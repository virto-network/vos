// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A byte stream the facility carries for the client: an onion service's,
//! over Tor, pumped into the client's end of a Unix socket pair, which the
//! client holds as it would a TCP socket: s4's own SSH runs over it. Not a
//! loopback port, which any app on the phone could reach.

use std::io;
use std::os::fd::OwnedFd;

use tokio::io::{AsyncRead, AsyncWrite};

/// A byte stream both ways.
pub trait Duplex: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Duplex for T {}

/// `stream` carried into `end` (the facility's end of the client's socket
/// pair) on the current runtime until either side closes.
pub fn carry(end: OwnedFd, stream: Box<dyn Duplex>) -> io::Result<()> {
    let ours = std::os::unix::net::UnixStream::from(end);
    ours.set_nonblocking(true)?;
    let ours = tokio::net::UnixStream::from_std(ours)?;
    tokio::spawn(pump(ours, stream));
    Ok(())
}

/// Bytes both ways between the pair's end and the stream; each side's close
/// passed on as a shutdown of its writes. A stream that fails (its circuit
/// lost) closes the pair's end as a close would: a socket pair carries no
/// error, and the client's SSH tells a server's end (its channel closed
/// first) from a carrier's.
async fn pump(mut ours: tokio::net::UnixStream, mut stream: Box<dyn Duplex>) {
    let _ = tokio::io::copy_bidirectional(&mut ours, &mut stream).await;
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    /// Bytes written to the client's end reach the stream and its answer
    /// comes back; the stream's close reaches the client as the end of its
    /// stream.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_clients_end_is_the_stream() {
        let (mut target, theirs) = tokio::io::duplex(64);
        let echo = tokio::spawn(async move {
            let mut line = [0u8; 5];
            target.read_exact(&mut line).await.unwrap();
            target
                .write_all(&line.map(|b| b.to_ascii_uppercase()))
                .await
                .unwrap();
        });
        let (mut client, end) = std::os::unix::net::UnixStream::pair().unwrap();
        carry(OwnedFd::from(end), Box::new(theirs)).unwrap();
        let read = tokio::task::spawn_blocking(move || {
            client.write_all(b"hello").unwrap();
            let mut answer = Vec::new();
            client.read_to_end(&mut answer).unwrap();
            answer
        });
        echo.await.unwrap();
        assert_eq!(read.await.unwrap(), b"HELLO");
    }
}
