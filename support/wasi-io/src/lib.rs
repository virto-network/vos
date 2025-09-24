use embedded_io_async::{ErrorType, Read, Write};
use std::{cell::OnceCell, io};
use wasi::{
    cli::stdin::get_stdin,
    cli::stdout::get_stdout,
    io::streams::{InputStream, OutputStream, StreamError},
};
use wasi_executor::wait_pollable;

pub fn stdio() -> StdIo {
    StdIo::new()
}

pub struct StdIo {
    stdin: InputStream,
    stdout: OutputStream,
    stdin_subscription: OnceCell<wasi::io::streams::Pollable>,
    stdout_subscription: OnceCell<wasi::io::streams::Pollable>,
}

impl StdIo {
    fn new() -> Self {
        Self {
            stdin: get_stdin(),
            stdout: get_stdout(),
            stdin_subscription: OnceCell::new(),
            stdout_subscription: OnceCell::new(),
        }
    }

    async fn stdin_readable(&self) -> Result<(), io::Error> {
        let subscription = self
            .stdin_subscription
            .get_or_init(|| self.stdin.subscribe());
        wait_pollable(subscription).await;
        Ok(())
    }

    async fn stdout_writable(&self) -> Result<(), io::Error> {
        let subscription = self
            .stdout_subscription
            .get_or_init(|| self.stdout.subscribe());
        wait_pollable(subscription).await;
        Ok(())
    }
}

impl Read for StdIo {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        loop {
            self.stdin_readable().await?;
            match self.stdin.read(buf.len() as u64) {
                Ok(data) if data.is_empty() => continue,
                Ok(data) => {
                    let len = data.len();
                    buf[0..len].copy_from_slice(&data);
                    return Ok(len);
                }
                Err(StreamError::Closed) => return Ok(0),
                Err(StreamError::LastOperationFailed(err)) => {
                    return Err(io::Error::other(err.to_debug_string()));
                }
            }
        }
    }
}

impl Write for StdIo {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        loop {
            match self.stdout.check_write() {
                Ok(0) => {
                    self.stdout_writable().await?;
                    continue;
                }
                Ok(available) => {
                    let writable = (available as usize).min(buf.len());
                    match self.stdout.write(&buf[0..writable]) {
                        Ok(()) => return Ok(writable),
                        Err(StreamError::Closed) => {
                            return Err(io::ErrorKind::BrokenPipe.into());
                        }
                        Err(StreamError::LastOperationFailed(err)) => {
                            return Err(io::Error::other(err.to_debug_string()));
                        }
                    }
                }
                Err(StreamError::Closed) => return Err(io::ErrorKind::BrokenPipe.into()),
                Err(StreamError::LastOperationFailed(err)) => {
                    return Err(io::Error::other(err.to_debug_string()));
                }
            }
        }
    }
}

impl ErrorType for StdIo {
    type Error = std::io::Error;
}

impl Drop for StdIo {
    fn drop(&mut self) {
        // Explicitly drop pollable subscriptions before parent resources
        // This ensures proper WASI resource cleanup order
        if let Some(pollable) = self.stdin_subscription.take() {
            drop(pollable);
        }
        if let Some(pollable) = self.stdout_subscription.take() {
            drop(pollable);
        }
    }
}
