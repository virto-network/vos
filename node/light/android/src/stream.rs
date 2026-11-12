// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A byte stream the facility opens for the client and serves into one end
//! of a Unix socket pair, the client holding the other as it would a TCP
//! socket: s4's own SSH runs over it. Not a loopback port, which any app on
//! the phone could reach. The stream comes from a [`Dialer`]: any byte
//! stream serves, a TCP connection's or an onion service's.

use std::io;
use std::os::unix::net::UnixStream;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::StreamTarget;
use crate::source::BoxFuture;

/// A byte stream both ways.
pub trait Duplex: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Duplex for T {}

/// What opens a stream to a target.
pub trait Dialer: Send + Sync + 'static {
    fn dial(&self, target: &StreamTarget) -> BoxFuture<'_, io::Result<Box<dyn Duplex>>>;
}

/// A TCP connection to the target, given up after [`CONNECT`].
pub struct Tcp;

/// How long a connection may take.
pub const CONNECT: std::time::Duration = std::time::Duration::from_secs(30);

impl Dialer for Tcp {
    fn dial(&self, target: &StreamTarget) -> BoxFuture<'_, io::Result<Box<dyn Duplex>>> {
        let (host, port) = (target.host.clone(), target.port);
        Box::pin(async move {
            let stream = tokio::time::timeout(
                CONNECT,
                tokio::net::TcpStream::connect((host.as_str(), port)),
            )
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as Box<dyn Duplex>)
        })
    }
}

/// A socket pair whose first end serves `stream` on the current runtime
/// until either side closes: the second end, the client's.
pub fn serve(stream: Box<dyn Duplex>) -> io::Result<UnixStream> {
    let (ours, theirs) = UnixStream::pair()?;
    ours.set_nonblocking(true)?;
    let ours = tokio::net::UnixStream::from_std(ours)?;
    tokio::spawn(pump(ours, stream));
    Ok(theirs)
}

/// Bytes both ways between the pair's end and the stream; each side's close
/// passed on as a shutdown of its writes.
async fn pump(mut ours: tokio::net::UnixStream, mut stream: Box<dyn Duplex>) {
    let _ = tokio::io::copy_bidirectional(&mut ours, &mut stream).await;
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    /// Bytes written to the client's end reach the target and its answer
    /// comes back; the target's close reaches the client as the end of its
    /// stream.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_clients_end_is_a_stream_to_the_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut line = [0u8; 5];
            socket.read_exact(&mut line).await.unwrap();
            socket
                .write_all(&line.map(|b| b.to_ascii_uppercase()))
                .await
                .unwrap();
        });
        let target = StreamTarget {
            host: "127.0.0.1".into(),
            port,
        };
        let stream = Tcp.dial(&target).await.unwrap();
        let mut client = serve(stream).unwrap();
        let read = tokio::task::spawn_blocking(move || {
            client.write_all(b"hello").unwrap();
            let mut answer = Vec::new();
            client.read_to_end(&mut answer).unwrap();
            answer
        });
        echo.await.unwrap();
        assert_eq!(read.await.unwrap(), b"HELLO");
    }

    #[tokio::test]
    async fn a_target_that_does_not_answer_is_an_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let target = StreamTarget {
            host: "127.0.0.1".into(),
            port,
        };
        assert!(Tcp.dial(&target).await.is_err());
    }
}
