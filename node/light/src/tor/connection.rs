//! One SSH connection to a gateway and its `vos-api` channel: the host key
//! pinned, the client authenticated by an ed25519 key drawn for this
//! connection alone, the node API's frames multiplexed over the channel.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Instant;

use russh::client;
use russh::keys::{PublicKeyOrCertificate, ssh_key};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use vos_api::client::{Answer, Multiplexed};
use zeroize::Zeroize;

use super::dial::Stream;

/// The gateway's `vos-api` subsystem.
pub const SUBSYSTEM: &str = "vos-api";
/// The SSH user: the gateway admits any key as no one in particular.
const USER: &str = "vos";

/// Accepts only the pinned host key.
pub(crate) struct Pinned {
    host_key: [u8; 32],
}

impl client::Handler for Pinned {
    type Error = russh::Error;

    /// A bare key only: a certificate is not the key pinned.
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(matches!(key, PublicKeyOrCertificate::PublicKey { key, .. }
            if key.key_data().ed25519().is_some_and(|key| key.0 == self.host_key)))
    }
}

/// `stream`, each write flushed before it counts as written. A Tor stream
/// holds what is written until it is flushed, and russh writes its version
/// line without flushing it, then waits for the gateway's: unflushed, the
/// line never leaves, and the gateway drops the connection at its handshake
/// deadline.
///
/// A write whose flush is pending holds the count of the bytes the stream
/// took across polls, so it must be polled again with the same bytes until
/// it is ready, never dropped for another write: the bytes left already,
/// and another write's would be counted as theirs.
struct Flushed<S = Stream> {
    stream: S,
    /// The bytes of a write taken but not yet flushed.
    unflushed: Option<usize>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Flushed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Flushed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = match self.unflushed {
            Some(written) => written,
            None => {
                let written = ready!(Pin::new(&mut self.stream).poll_write(cx, buf))?;
                self.unflushed = Some(written);
                written
            }
        };
        let flushed = ready!(Pin::new(&mut self.stream).poll_flush(cx));
        // Done with this write, flushed or failed: the next write is its own.
        self.unflushed = None;
        flushed?;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Why a connection did not open.
#[derive(Debug)]
pub(crate) enum OpenError {
    Ssh(russh::Error),
    /// The gateway refused the key or the subsystem.
    Refused,
    /// The operating system had no randomness to give.
    Randomness,
}

/// An open connection.
pub(crate) struct Connection {
    api: Multiplexed,
    _handle: client::Handle<Pinned>,
    /// When its last request was made or answered.
    last: Mutex<Instant>,
    /// The `vos-api` channel's reading and writing.
    task: JoinHandle<()>,
    /// Set once the client closes it: requests in flight end at once.
    closed: tokio::sync::watch::Sender<bool>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Connection {
    /// SSH over `stream`, the gateway's host key `host_key`, under a key
    /// drawn now, and its `vos-api` channel.
    pub async fn open(stream: Stream, host_key: [u8; 32]) -> Result<Self, OpenError> {
        let config = Arc::new(client::Config {
            // The client's deadlines end a connection, not russh's timers.
            inactivity_timeout: None,
            ..client::Config::default()
        });
        let stream = Flushed {
            stream,
            unflushed: None,
        };
        let mut handle = client::connect_stream(config, stream, Pinned { host_key })
            .await
            .map_err(OpenError::Ssh)?;
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| OpenError::Randomness)?;
        let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&seed));
        seed.zeroize();
        let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
        if !handle
            .authenticate_publickey(USER, key)
            .await
            .map_err(OpenError::Ssh)?
            .success()
        {
            return Err(OpenError::Refused);
        }
        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(OpenError::Ssh)?;
        channel
            .request_subsystem(true, SUBSYSTEM)
            .await
            .map_err(OpenError::Ssh)?;
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Success) => break,
                Some(russh::ChannelMsg::WindowAdjusted { .. }) => continue,
                _ => return Err(OpenError::Refused),
            }
        }
        let (reader, writer) = tokio::io::split(channel.into_stream());
        let (api, task) = vos_api::client::multiplexed(reader.compat(), writer.compat_write());
        Ok(Self {
            api,
            _handle: handle,
            last: Mutex::new(Instant::now()),
            task: tokio::spawn(task),
            closed: tokio::sync::watch::Sender::new(false),
        })
    }

    /// Send a request of `kind` holding `body`: its answer, or `Closed`
    /// once the stream ends or the client closes the connection.
    pub async fn request(&self, kind: u16, body: &[u8]) -> Result<Answer, vos_api::client::Closed> {
        self.touch();
        let mut closed = self.closed.subscribe();
        let answer = tokio::select! {
            answer = self.api.request(kind, vos_api::Mark::Unmarked, body) => answer,
            _ = closed.wait_for(|closed| *closed) => Err(vos_api::client::Closed::Ended),
        };
        self.touch();
        answer
    }

    fn touch(&self) {
        *self.last.lock().expect("the last request's time") = Instant::now();
    }

    /// Close it: nothing more is written or read, and every request in
    /// flight ends.
    pub fn close(&self) {
        self.closed.send_replace(true);
        self.task.abort();
    }

    /// Whether it can carry no request: its stream ended, or it was closed.
    pub fn is_closed(&self) -> bool {
        *self.closed.borrow() || self.api.is_closed() || self.task.is_finished()
    }

    /// When its last request was made or answered.
    pub fn last(&self) -> Instant {
        *self.last.lock().expect("the last request's time")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer whose first `pending` flushes are pending, holding what it
    /// took, and failing its next flush when told.
    #[derive(Default)]
    struct Slow {
        taken: Vec<u8>,
        pending: usize,
        fail: bool,
    }

    impl AsyncWrite for Slow {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.taken.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.pending > 0 {
                self.pending -= 1;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if std::mem::take(&mut self.fail) {
                return Poll::Ready(Err(io::Error::other("the stream broke")));
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn write(flushed: &mut Flushed<Slow>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        Pin::new(flushed).poll_write(&mut cx, bytes)
    }

    /// A write whose first flush is pending is counted once, when its flush
    /// is done, and its bytes are taken once.
    #[test]
    fn a_pending_flush_counts_its_write_once() {
        let mut flushed = Flushed {
            stream: Slow {
                pending: 1,
                ..Slow::default()
            },
            unflushed: None,
        };
        assert!(write(&mut flushed, b"SSH-2.0-vos\r\n").is_pending());
        let Poll::Ready(Ok(written)) = write(&mut flushed, b"SSH-2.0-vos\r\n") else {
            panic!("the flush is done");
        };
        assert_eq!(written, 13);
        assert_eq!(flushed.stream.taken, b"SSH-2.0-vos\r\n");
        assert_eq!(flushed.unflushed, None);
    }

    /// A flush that fails ends its write: the next write is taken anew.
    #[test]
    fn a_failed_flush_ends_its_write() {
        let mut flushed = Flushed {
            stream: Slow {
                fail: true,
                ..Slow::default()
            },
            unflushed: None,
        };
        assert!(matches!(write(&mut flushed, b"one"), Poll::Ready(Err(_))));
        assert_eq!(flushed.unflushed, None);
        let Poll::Ready(Ok(written)) = write(&mut flushed, b"other") else {
            panic!("the next write is taken");
        };
        assert_eq!(written, 5);
        assert_eq!(flushed.stream.taken, b"oneother");
    }
}
