//! The onion's streams (`light-node.md` §6.1, §6.6): each arrives on a
//! rendezvous circuit, from no address, for a virtual port: 22, SSH, and
//! nothing else. A circuit counts as
//! one address for the limits per address: its own address, in a range of
//! the unique local IPv6 addresses no client holds, and each stream on it
//! a port of that address, so a connection's caps count it alone.
//!
//! Its streams go to the onion's own SSH server, each handed over with its
//! address, so the server counts the circuit and marks onion what it
//! serves.
//!
//! The streams come from arti in process (the `onion` module, with the
//! `tor` feature).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The onion's virtual port, SSH's.
pub const SSH: u16 = 22;

/// The leading 32 bits of every circuit's address: a unique local IPv6
/// range (`fd76:6f73::/32`), held by no client.
const PREFIX: u128 = 0xfd76_6f73 << 96;

/// Circuit `circuit`'s address: its number in the 32 bits after the
/// prefix, so the /64 the limits count is the circuit's alone.
pub fn address(circuit: u32) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(PREFIX | (u128::from(circuit) << 64)))
}

/// Any stream, as tokio reads and writes it.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// What the onion's circuits may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerCircuit {
    /// Streams open at once on one circuit: past them, a stream is closed
    /// as it arrives.
    pub streams: usize,
    /// Circuits holding a stream, or waiting for their first, at once:
    /// past them, a rendezvous is not answered.
    pub circuits: usize,
}

impl Default for PerCircuit {
    fn default() -> Self {
        Self {
            streams: 8,
            circuits: 1024,
        }
    }
}

/// What the onion's streams and circuits counted so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Circuits taken.
    pub circuits: u64,
    /// Rendezvous not answered, past [`PerCircuit::circuits`].
    pub circuits_refused: u64,
    /// Streams served, SSH and HTTP.
    pub streams: u64,
    /// Streams closed as they arrived, past [`PerCircuit::streams`] or
    /// for another port.
    pub streams_refused: u64,
}

/// The onion's circuits and the streams open on each.
pub struct Circuits {
    per: PerCircuit,
    open: Mutex<HashMap<u32, Open>>,
    circuits: Mutex<usize>,
    counts: [AtomicU64; 4],
}

/// A circuit's open streams: the ports of its address they hold, and the
/// next port to try.
#[derive(Default)]
struct Open {
    ports: Vec<u16>,
    next: u16,
}

/// A circuit's place among the onion's, given back when it closes.
pub struct CircuitPlace(Arc<Circuits>);

impl Drop for CircuitPlace {
    fn drop(&mut self) {
        *self.0.circuits.lock().expect("the circuits") -= 1;
    }
}

/// A stream's place among its circuit's, given back when it ends.
pub struct StreamPlace {
    circuits: Arc<Circuits>,
    circuit: u32,
    /// The stream's address: its circuit's, and a port of its own.
    pub peer: SocketAddr,
}

impl Drop for StreamPlace {
    fn drop(&mut self) {
        let mut open = self.circuits.open.lock().expect("the open streams");
        let Some(streams) = open.get_mut(&self.circuit) else {
            return;
        };
        streams.ports.retain(|port| *port != self.peer.port());
        if streams.ports.is_empty() {
            open.remove(&self.circuit);
        }
    }
}

impl Circuits {
    pub fn new(per: PerCircuit) -> Arc<Self> {
        Arc::new(Self {
            per,
            open: Mutex::new(HashMap::new()),
            circuits: Mutex::new(0),
            counts: Default::default(),
        })
    }

    fn count(&self, at: usize) {
        self.counts[at].fetch_add(1, Ordering::Relaxed);
    }

    /// A place for a circuit, while fewer than the onion's limit hold one.
    pub fn circuit(self: &Arc<Self>) -> Option<CircuitPlace> {
        let mut held = self.circuits.lock().expect("the circuits");
        if *held >= self.per.circuits {
            drop(held);
            self.count(1);
            return None;
        }
        *held += 1;
        drop(held);
        self.count(0);
        Some(CircuitPlace(Arc::clone(self)))
    }

    /// A place for a stream on `circuit`, whose own task holds its place
    /// among the onion's, while it holds fewer than its limit.
    pub fn stream(self: &Arc<Self>, circuit: u32) -> Option<StreamPlace> {
        let mut open = self.open.lock().expect("the open streams");
        let streams = open.entry(circuit).or_default();
        if streams.ports.len() >= self.per.streams {
            drop(open);
            self.count(3);
            return None;
        }
        // A port no live stream of the circuit holds.
        let mut port = streams.next;
        while streams.ports.contains(&port) {
            port = port.wrapping_add(1);
        }
        streams.next = port.wrapping_add(1);
        streams.ports.push(port);
        drop(open);
        self.count(2);
        Some(StreamPlace {
            circuits: Arc::clone(self),
            circuit,
            peer: SocketAddr::new(address(circuit), port),
        })
    }

    /// The streams open on `circuit` now.
    pub fn streams(&self, circuit: u32) -> usize {
        self.open
            .lock()
            .expect("the open streams")
            .get(&circuit)
            .map_or(0, |streams| streams.ports.len())
    }

    /// A stream refused as it arrived, for a port the onion does not serve.
    pub fn refused(&self) {
        self.count(3);
    }

    /// What was counted so far.
    pub fn counts(&self) -> Counts {
        let count = |at: usize| self.counts[at].load(Ordering::Relaxed);
        Counts {
            circuits: count(0),
            circuits_refused: count(1),
            streams: count(2),
            streams_refused: count(3),
        }
    }
}

/// A stream holding its place on its circuit until it ends, each write
/// flushed before it counts as written: an onion stream holds what is
/// written until it is flushed, and russh writes the server's version line
/// without flushing it, which a client that waits for the server's line
/// first (as RFC 4253 lets it) would never read. A write whose flush is
/// pending holds its count across polls: it is polled again with the same
/// bytes, never dropped for another write.
struct Placed<S> {
    stream: S,
    _place: StreamPlace,
    /// The bytes of a write taken but not yet flushed.
    unflushed: Option<usize>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Placed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Placed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let written = match self.unflushed {
            Some(written) => written,
            None => {
                let written = ready!(Pin::new(&mut self.stream).poll_write(cx, buf))?;
                self.unflushed = Some(written);
                written
            }
        };
        let flushed = ready!(Pin::new(&mut self.stream).poll_flush(cx));
        self.unflushed = None;
        flushed?;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// A stream from the onion, with its address.
type Accepted = (Box<dyn Io>, SocketAddr);

/// The onion's streams, as its SSH server takes them.
pub struct OnionListener(tokio::sync::mpsc::Receiver<Accepted>);

impl OnionListener {
    /// The next stream and its address; `None` once the onion is gone.
    pub async fn next(&mut self) -> Option<Accepted> {
        self.0.recv().await
    }
}

/// Streams the onion's SSH server waits to take, at most.
const WAITING: usize = 64;

/// Where the onion's streams go: its SSH server.
pub struct Onion {
    pub circuits: Arc<Circuits>,
    ssh: tokio::sync::mpsc::Sender<Accepted>,
}

impl Onion {
    /// The onion over `circuits`, and the listener its streams arrive on.
    pub fn new(circuits: Arc<Circuits>) -> (Arc<Self>, OnionListener) {
        let (ssh, accepted) = tokio::sync::mpsc::channel(WAITING);
        (Arc::new(Self { circuits, ssh }), OnionListener(accepted))
    }

    /// Whether a stream to virtual port `port` would be served: SSH's
    /// alone.
    pub fn serves(&self, port: u16) -> bool {
        port == SSH
    }

    /// Hand `stream`, a stream on `circuit` to virtual port `port`, to the
    /// SSH server, holding its place on the circuit until it ends: closed
    /// at once past its circuit's streams, or for a port the onion does
    /// not serve. The circuit's own task holds its place.
    pub async fn serve(&self, stream: impl Io, circuit: u32, port: u16) {
        if !self.serves(port) {
            self.circuits.refused();
            return;
        }
        let place = self.circuits.stream(circuit);
        let Some(place) = place else {
            return;
        };
        let peer = place.peer;
        let stream = Placed {
            stream,
            _place: place,
            unflushed: None,
        };
        let _ = self.ssh.send((Box::new(stream), peer)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::counted;

    #[test]
    fn a_circuit_is_one_address_and_each_stream_a_port_of_it() {
        assert_eq!(counted(address(7)), address(7));
        assert_ne!(counted(address(7)), counted(address(8)));
        assert_eq!(address(1).to_string(), "fd76:6f73:0:1::");
        let circuits = Circuits::new(PerCircuit {
            streams: 2,
            circuits: 1,
        });
        let circuit = circuits.circuit().unwrap();
        assert!(circuits.circuit().is_none(), "the onion's circuits");
        let first = circuits.stream(3).unwrap();
        let second = circuits.stream(3).unwrap();
        assert!(circuits.stream(3).is_none(), "the circuit's streams");
        assert!(circuits.stream(4).is_some(), "another circuit's own");
        assert_eq!(first.peer.ip(), address(3));
        assert_ne!(first.peer, second.peer);
        assert_eq!(circuits.streams(3), 2);
        drop(first);
        assert!(circuits.stream(3).is_some());
        drop(circuit);
        assert!(circuits.circuit().is_some());
        assert_eq!(
            circuits.counts(),
            Counts {
                circuits: 2,
                circuits_refused: 1,
                streams: 4,
                streams_refused: 1,
            }
        );
    }

    /// An SSH stream reaches the SSH server with its circuit's address
    /// and a port of its own, holding its place on the circuit until it
    /// ends; a stream to another port, HTTP's among them, is closed.
    #[tokio::test]
    async fn streams_go_to_ssh_alone() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let circuits = Circuits::new(PerCircuit::default());
        let (onion, mut ssh) = Onion::new(Arc::clone(&circuits));
        let (mut client, served) = tokio::io::duplex(64);
        onion.serve(served, 6, SSH).await;
        let (mut stream, peer) = ssh.next().await.unwrap();
        assert_eq!(peer.ip(), address(6));
        assert_eq!(circuits.streams(6), 1, "its place held");
        client.write_all(b"ssh").await.unwrap();
        let mut read = [0u8; 3];
        stream.read_exact(&mut read).await.unwrap();
        assert_eq!(&read, b"ssh");
        drop(stream);
        assert_eq!(circuits.streams(6), 0, "given back once it ends");
        // Another port: closed, counted.
        for (circuit, port) in [(5, 80), (7, 443)] {
            let (_client, served) = tokio::io::duplex(64);
            onion.serve(served, circuit, port).await;
        }
        assert_eq!(circuits.counts().streams_refused, 2);
        assert!(!onion.serves(80));
    }
}
