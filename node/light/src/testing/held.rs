//! A stream that holds its writes until flushed, as Tor's do: the testing
//! world's streams, and the Tor client's tests' (which include this file).

/// A stream that holds what is written until it is flushed, as a Tor
/// stream does at either end: the gateway's onion service and the phone's
/// client.
pub struct Held<S> {
    stream: S,
    held: Vec<u8>,
}

impl<S> Held<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            held: Vec::new(),
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Held<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Held<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.held.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = &mut *self;
        while !this.held.is_empty() {
            let written =
                std::task::ready!(std::pin::Pin::new(&mut this.stream).poll_write(cx, &this.held))?;
            this.held.drain(..written);
        }
        std::pin::Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
