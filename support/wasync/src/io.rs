use crate::{block_on, wait_pollable};
pub use embedded_io_async::{Error, ErrorType, Read, Seek, SeekFrom, Write};
use std::{cell::OnceCell, fmt, io};
use wasi::{
    cli::stderr::get_stderr,
    cli::stdin::get_stdin,
    cli::stdout::get_stdout,
    io::streams::{InputStream, OutputStream, StreamError},
};

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

/// Copy data from a reader to a writer.
pub async fn copy<R: Read, W: Write<Error = R::Error>>(
    reader: &mut R,
    writer: &mut W,
) -> Result<u64, R::Error> {
    let mut buf_reader = BufReader::<_, DEFAULT_BUF_LEN>::new(reader);
    let mut total_copied = 0u64;

    loop {
        let buf = buf_reader.fill_buf().await?;
        if buf.is_empty() {
            break; // EOF reached
        }

        let mut remaining = buf;
        while !remaining.is_empty() {
            let bytes_written = writer.write(remaining).await?;
            remaining = &remaining[bytes_written..];
        }

        let consumed = buf.len();
        buf_reader.consume(consumed);
        total_copied += consumed as u64;
    }

    Ok(total_copied)
}

pub const DEFAULT_BUF_LEN: usize = 8192;

pub struct BufReader<R: Read, const N: usize = DEFAULT_BUF_LEN> {
    inner: R,
    buf: [u8; N],
    pos: usize,
    cap: usize,
}

impl<R: Read, const N: usize> BufReader<R, N> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: [0; N],
            pos: 0,
            cap: 0,
        }
    }

    pub async fn fill_buf(&mut self) -> Result<&[u8], R::Error> {
        if self.pos >= self.cap {
            self.cap = self.inner.read(&mut self.buf).await?;
            self.pos = 0;
        }
        Ok(&self.buf[self.pos..self.cap])
    }

    pub fn consume(&mut self, amt: usize) {
        self.pos = (self.pos + amt).min(self.cap);
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read, const N: usize> Read for BufReader<R, N> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let available = self.fill_buf().await?;
        let to_copy = available.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&available[..to_copy]);
        self.consume(to_copy);
        Ok(to_copy)
    }
}

impl<R: Read, const N: usize> ErrorType for BufReader<R, N> {
    type Error = R::Error;
}

pub struct BufWriter<W: Write, const N: usize = DEFAULT_BUF_LEN> {
    inner: W,
    buf: [u8; N],
    pos: usize,
}

impl<W: Write, const N: usize> BufWriter<W, N> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            buf: [0; N],
            pos: 0,
        }
    }

    pub fn with_capacity(inner: W) -> Self {
        Self::new(inner)
    }

    pub async fn flush(&mut self) -> Result<(), W::Error> {
        if self.pos > 0 {
            let pos = self.pos;
            self.pos = 0; // Reset position before async operation
            let mut buf = &self.buf[..pos];
            while !buf.is_empty() {
                let written = self.inner.write(buf).await?;
                buf = &buf[written..];
            }
        }
        Ok(())
    }

    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    pub async fn into_inner(mut self) -> Result<W, W::Error> {
        self.flush().await?;
        let inner = unsafe { std::ptr::read(&self.inner) };
        std::mem::forget(self);
        Ok(inner)
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    pub fn capacity(&self) -> usize {
        N
    }
}

impl<W: Write, const N: usize> Write for BufWriter<W, N> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        // If the buffer would overflow
        if self.pos + buf.len() > N {
            // Flush the existing buffer first
            if self.pos > 0 {
                let pos = self.pos;
                self.pos = 0; // Reset position before async operation
                let mut flush_buf = &self.buf[..pos];
                while !flush_buf.is_empty() {
                    let written = self.inner.write(flush_buf).await?;
                    flush_buf = &flush_buf[written..];
                }
            }

            // If the new data is larger than our buffer, write it directly
            if buf.len() >= N {
                return self.inner.write(buf).await;
            }
        }

        // Copy data to our buffer
        let to_copy = buf.len().min(N - self.pos);
        self.buf[self.pos..self.pos + to_copy].copy_from_slice(&buf[..to_copy]);
        self.pos += to_copy;

        Ok(to_copy)
    }
}

impl<W: Write, const N: usize> ErrorType for BufWriter<W, N> {
    type Error = W::Error;
}

impl<W: Write, const N: usize> Drop for BufWriter<W, N> {
    fn drop(&mut self) {
        block_on(async {
            let _ = self.flush().await;
        })
    }
}

impl<W: Write, const N: usize> std::fmt::Write for BufWriter<W, N> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        block_on(async {
            let mut remaining = s.as_bytes();
            while !remaining.is_empty() {
                let written = self.write(s.as_bytes()).await.map_err(|_| fmt::Error)?;
                remaining = &remaining[written..];
            }
            self.flush().await.map_err(|_| fmt::Error)
        })
    }
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
