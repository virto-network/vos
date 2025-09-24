pub use embedded_io_async::{Error, ErrorType, Read, Write};
use std::{cell::OnceCell, io};
use wasi::{
    cli::stderr::get_stderr,
    cli::stdin::get_stdin,
    cli::stdout::get_stdout,
    io::streams::{InputStream, OutputStream, StreamError},
};
use wasi_executor::wait_pollable;

#[cfg(feature = "net")]
pub mod net;

pub struct StdIn {
    stream: InputStream,
    subscription: OnceCell<wasi::io::streams::Pollable>,
}

pub struct StdOut {
    stream: OutputStream,
    subscription: OnceCell<wasi::io::streams::Pollable>,
}

pub struct Stderr {
    stream: OutputStream,
    subscription: OnceCell<wasi::io::streams::Pollable>,
}

impl StdIn {
    fn new() -> Self {
        Self {
            stream: get_stdin(),
            subscription: OnceCell::new(),
        }
    }

    async fn readable(&self) -> Result<(), io::Error> {
        let subscription = self.subscription.get_or_init(|| self.stream.subscribe());
        wait_pollable(subscription).await;
        Ok(())
    }
}

impl StdOut {
    fn new() -> Self {
        Self {
            stream: get_stdout(),
            subscription: OnceCell::new(),
        }
    }

    async fn writable(&self) -> Result<(), io::Error> {
        let subscription = self.subscription.get_or_init(|| self.stream.subscribe());
        wait_pollable(subscription).await;
        Ok(())
    }
}

impl Stderr {
    fn new() -> Self {
        Self {
            stream: get_stderr(),
            subscription: OnceCell::new(),
        }
    }

    async fn writable(&self) -> Result<(), io::Error> {
        let subscription = self.subscription.get_or_init(|| self.stream.subscribe());
        wait_pollable(subscription).await;
        Ok(())
    }
}

impl Read for StdIn {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        loop {
            self.readable().await?;
            match self.stream.read(buf.len() as u64) {
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

impl Write for StdOut {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        loop {
            match self.stream.check_write() {
                Ok(0) => {
                    self.writable().await?;
                    continue;
                }
                Ok(available) => {
                    let writable = (available as usize).min(buf.len());
                    match self.stream.write(&buf[0..writable]) {
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

impl Write for Stderr {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        loop {
            match self.stream.check_write() {
                Ok(0) => {
                    self.writable().await?;
                    continue;
                }
                Ok(available) => {
                    let writable = (available as usize).min(buf.len());
                    match self.stream.write(&buf[0..writable]) {
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

impl ErrorType for StdIn {
    type Error = std::io::Error;
}

impl ErrorType for StdOut {
    type Error = std::io::Error;
}

impl ErrorType for Stderr {
    type Error = std::io::Error;
}

impl Drop for StdIn {
    fn drop(&mut self) {
        if let Some(pollable) = self.subscription.take() {
            drop(pollable);
        }
    }
}

impl Drop for StdOut {
    fn drop(&mut self) {
        if let Some(pollable) = self.subscription.take() {
            drop(pollable);
        }
    }
}

impl Drop for Stderr {
    fn drop(&mut self) {
        if let Some(pollable) = self.subscription.take() {
            drop(pollable);
        }
    }
}

// Convenience functions
pub fn stdin() -> StdIn {
    StdIn::new()
}

pub fn stdout() -> StdOut {
    StdOut::new()
}

pub fn stderr() -> Stderr {
    Stderr::new()
}

pub fn stdio() -> Combined<StdIn, StdOut> {
    combine(stdin(), stdout())
}

// Utility types for split/combine functionality

/// Split a type that implements both Read and Write into separate reader and writer halves
pub fn split<T: Read + Write + 'static>(stream: T) -> (ReadHalf<T>, WriteHalf<T>) {
    let shared = std::rc::Rc::new(std::cell::RefCell::new(stream));
    let read_half = ReadHalf {
        inner: shared.clone(),
    };
    let write_half = WriteHalf { inner: shared };
    (read_half, write_half)
}

/// Combine separate Read and Write implementations into a single type that implements both
pub fn combine<R: Read, W: Write<Error = R::Error>>(reader: R, writer: W) -> Combined<R, W> {
    Combined { reader, writer }
}

pub struct ReadHalf<T> {
    inner: std::rc::Rc<std::cell::RefCell<T>>,
}

pub struct WriteHalf<T> {
    inner: std::rc::Rc<std::cell::RefCell<T>>,
}

pub struct Combined<R, W> {
    reader: R,
    writer: W,
}

impl<T: Read + Write> Read for ReadHalf<T> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.inner.borrow_mut().read(buf).await
    }
}

impl<T: Read + Write> Write for WriteHalf<T> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.inner.borrow_mut().write(buf).await
    }
}

impl<T: Read + Write> ErrorType for ReadHalf<T> {
    type Error = T::Error;
}

impl<T: Read + Write> ErrorType for WriteHalf<T> {
    type Error = T::Error;
}

impl<R: Read, W: Write<Error = R::Error>> Read for Combined<R, W> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.reader.read(buf).await
    }
}

impl<R: Read, W: Write<Error = R::Error>> Write for Combined<R, W> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.writer.write(buf).await
    }
}

impl<R: Read, W: Write<Error = R::Error>> ErrorType for Combined<R, W> {
    type Error = R::Error;
}
