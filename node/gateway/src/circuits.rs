//! The onion's streams (`light-node.md` §6.1, §6.6): each arrives on a
//! rendezvous circuit, from no address, for a virtual port, 22 (SSH) or 80
//! (HTTP), the clearnet's protocols and nothing else. A circuit counts as
//! one address for the limits per address: its own address, in a range of
//! the unique local IPv6 addresses no client holds, and each stream on it
//! a port of that address, so a connection's caps count it alone.
//!
//! HTTP streams go to the onion's own HTTP server, its requests marked
//! onion. An SSH stream is carried to the onion's own SSH port on a
//! loopback listener (s4-server serves a listener, not a stream): the
//! carrier's loopback address names the stream, so the port's subsystem
//! counts the circuit, and a loopback connection that no stream carries is
//! served no channel.
//!
//! The streams come from arti in process ([`crate::onion`]) or from a C tor
//! beside the gateway ([`sidecar`]), whose `HiddenServiceExportCircuitID
//! haproxy` names each stream's circuit.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

/// The onion's virtual port for SSH.
pub const SSH: u16 = 22;
/// The onion's virtual port for HTTP.
pub const HTTP: u16 = 80;

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
    open: Mutex<HashMap<u32, usize>>,
    circuits: Mutex<usize>,
    /// The SSH streams carried to the onion's SSH port, by the carrier's
    /// loopback port: the stream's address.
    carried: Mutex<HashMap<u16, SocketAddr>>,
    next: AtomicU16,
    counts: [AtomicU64; 4],
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
        if let Some(count) = open.get_mut(&self.circuit) {
            *count -= 1;
            if *count == 0 {
                open.remove(&self.circuit);
            }
        }
    }
}

impl Circuits {
    pub fn new(per: PerCircuit) -> Arc<Self> {
        Arc::new(Self {
            per,
            open: Mutex::new(HashMap::new()),
            circuits: Mutex::new(0),
            carried: Mutex::new(HashMap::new()),
            next: AtomicU16::new(0),
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

    /// A place for a stream on `circuit`, while it holds fewer than its
    /// limit.
    pub fn stream(self: &Arc<Self>, circuit: u32) -> Option<StreamPlace> {
        let mut open = self.open.lock().expect("the open streams");
        let count = open.entry(circuit).or_insert(0);
        if *count >= self.per.streams {
            drop(open);
            self.count(3);
            return None;
        }
        *count += 1;
        drop(open);
        self.count(2);
        let port = self.next.fetch_add(1, Ordering::Relaxed);
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
            .copied()
            .unwrap_or(0)
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

    /// The address of the stream the SSH connection from `peer` carries,
    /// if one does: the onion's SSH port serves channels to no other.
    pub fn carried(&self, peer: SocketAddr) -> Option<SocketAddr> {
        if !peer.ip().is_loopback() {
            return None;
        }
        self.carried
            .lock()
            .expect("the carried streams")
            .get(&peer.port())
            .copied()
    }
}

/// A stream holding its place on its circuit until it ends.
struct Placed<S> {
    stream: S,
    _place: StreamPlace,
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
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// An HTTP stream from the onion, with its address.
type Accepted = (Box<dyn Io>, SocketAddr);

/// The onion's HTTP streams as a listener of the gateway's HTTP server.
pub struct OnionListener(tokio::sync::mpsc::Receiver<Accepted>);

impl vos_http::Listener for OnionListener {
    type Stream = Compat<Box<dyn Io>>;

    async fn accept(&mut self) -> std::io::Result<(Self::Stream, SocketAddr)> {
        match self.0.recv().await {
            Some((stream, peer)) => Ok((stream.compat(), peer)),
            None => Err(std::io::ErrorKind::BrokenPipe.into()),
        }
    }
}

/// Where the onion's streams go: its HTTP server's listener, and its SSH
/// port's loopback address.
pub struct Onion {
    pub circuits: Arc<Circuits>,
    http: tokio::sync::mpsc::Sender<Accepted>,
    ssh: Option<SocketAddr>,
}

impl Onion {
    /// The onion over `circuits`, its SSH streams carried to `ssh`, if it
    /// serves SSH; and the listener its HTTP streams arrive on.
    pub fn new(circuits: Arc<Circuits>, ssh: Option<SocketAddr>) -> (Arc<Self>, OnionListener) {
        let (http, accepted) = tokio::sync::mpsc::channel(64);
        (
            Arc::new(Self {
                circuits,
                http,
                ssh,
            }),
            OnionListener(accepted),
        )
    }

    /// Whether a stream to virtual port `port` would be served: SSH, if
    /// the onion serves it, and HTTP.
    pub fn serves(&self, port: u16) -> bool {
        port == HTTP || (port == SSH && self.ssh.is_some())
    }

    /// Serve `stream`, a stream on `circuit` to virtual port `port`, until
    /// it ends: closed at once past its circuit's streams, or for a port
    /// the onion does not serve.
    pub async fn serve(&self, stream: impl Io, circuit: u32, port: u16) {
        if !self.serves(port) {
            self.circuits.refused();
            return;
        }
        let Some(place) = self.circuits.stream(circuit) else {
            return;
        };
        let peer = place.peer;
        let stream = Placed {
            stream,
            _place: place,
        };
        match (port, self.ssh) {
            (SSH, Some(ssh)) => self.carry(stream, peer, ssh).await,
            _ => {
                let _ = self.http.send((Box::new(stream), peer)).await;
            }
        }
    }

    /// Carry an SSH stream to the onion's SSH port, the carrier's loopback
    /// port naming it while it is open.
    async fn carry(&self, mut stream: impl Io, peer: SocketAddr, ssh: SocketAddr) {
        let Ok(mut carrier) = tokio::net::TcpStream::connect(ssh).await else {
            return;
        };
        let Ok(local) = carrier.local_addr() else {
            return;
        };
        let _ = carrier.set_nodelay(true);
        self.circuits
            .carried
            .lock()
            .expect("the carried streams")
            .insert(local.port(), peer);
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut carrier).await;
        self.circuits
            .carried
            .lock()
            .expect("the carried streams")
            .remove(&local.port());
    }
}

/// A C tor beside the gateway (`docs/operations.md`, "The onion service"):
/// its `HiddenServicePort`s forward to loopback listeners, and its
/// `HiddenServiceExportCircuitID haproxy` writes each stream's circuit
/// first, in a PROXY line whose source address's last 32 bits are tor's
/// circuit number. A connection without one is closed.
pub mod sidecar {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// A PROXY line's most bytes, its `\r\n` included.
    const LINE: usize = 107;
    /// How long a connection may take to write its PROXY line.
    const DEADLINE: Duration = Duration::from_secs(10);

    /// The circuit a PROXY line names: the last 32 bits of its source
    /// address, a `TCP6` one.
    pub fn circuit(line: &str) -> Option<u32> {
        let mut fields = line.strip_suffix("\r\n")?.split(' ');
        let ("PROXY", "TCP6", Some(source)) = (fields.next()?, fields.next()?, fields.next())
        else {
            return None;
        };
        let source: Ipv6Addr = source.parse().ok()?;
        Some(u128::from(source) as u32)
    }

    /// The PROXY line at `stream`'s start, read a byte at a time so no
    /// byte past it is taken.
    async fn line(stream: &mut tokio::net::TcpStream) -> Option<String> {
        let mut line = Vec::with_capacity(LINE);
        while !line.ends_with(b"\r\n") {
            if line.len() == LINE {
                return None;
            }
            line.push(stream.read_u8().await.ok()?);
        }
        String::from_utf8(line).ok()
    }

    /// Serve the connections C tor forwards on `listener` for virtual port
    /// `port`, each on the circuit its PROXY line names, until the listener
    /// fails.
    pub async fn serve(onion: Arc<Onion>, listener: tokio::net::TcpListener, port: u16) {
        while let Ok((mut stream, peer)) = listener.accept().await {
            if !peer.ip().is_loopback() {
                continue;
            }
            let onion = Arc::clone(&onion);
            tokio::spawn(async move {
                let named = tokio::time::timeout(DEADLINE, line(&mut stream)).await;
                let Some(circuit) = named.ok().flatten().as_deref().and_then(circuit) else {
                    return;
                };
                let _ = stream.set_nodelay(true);
                onion.serve(stream, circuit, port).await;
            });
        }
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

    #[test]
    fn a_proxy_line_names_tors_circuit() {
        assert_eq!(
            sidecar::circuit("PROXY TCP6 fc00:dead:beef:4dad::ffff:ffff ::1 65535 42\r\n"),
            Some(u32::MAX)
        );
        assert_eq!(
            sidecar::circuit("PROXY TCP6 fc00:dead:beef:4dad::1:2 ::1 65535 22\r\n"),
            Some(0x1_0002)
        );
        for refused in [
            "PROXY TCP4 10.0.0.1 10.0.0.2 1 2\r\n",
            "PROXY TCP6 fc00:dead:beef:4dad::1 ::1 1 2\n",
            "SSH-2.0-OpenSSH\r\n",
            "PROXY TCP6 nowhere ::1 1 2\r\n",
        ] {
            assert_eq!(sidecar::circuit(refused), None, "{refused}");
        }
    }

    /// An HTTP stream reaches the listener with its circuit's address, and
    /// an SSH stream is carried to the SSH port, its carrier naming it while
    /// it is open; a stream to another port is closed.
    #[tokio::test]
    async fn streams_go_by_their_port() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let ssh = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let circuits = Circuits::new(PerCircuit::default());
        let (onion, mut http) = Onion::new(Arc::clone(&circuits), Some(ssh.local_addr().unwrap()));
        let (mut client, served) = tokio::io::duplex(64);
        let serving = {
            let onion = Arc::clone(&onion);
            tokio::spawn(async move { onion.serve(served, 5, HTTP).await })
        };
        let (mut stream, peer) = vos_http::Listener::accept(&mut http).await.unwrap();
        assert_eq!(peer.ip(), address(5));
        client.write_all(b"ping").await.unwrap();
        let mut read = [0u8; 4];
        futures::AsyncReadExt::read_exact(&mut stream, &mut read)
            .await
            .unwrap();
        assert_eq!(&read, b"ping");
        serving.await.unwrap();
        // SSH: carried, the carrier's port naming the stream.
        let (mut client, served) = tokio::io::duplex(64);
        let carrying = {
            let onion = Arc::clone(&onion);
            tokio::spawn(async move { onion.serve(served, 6, SSH).await })
        };
        let (mut carried, from) = ssh.accept().await.unwrap();
        let mut named = None;
        for _ in 0..100 {
            named = circuits.carried(from);
            if named.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let named = named.expect("the carrier names it");
        assert_eq!(named.ip(), address(6));
        assert_eq!(circuits.carried("10.0.0.1:1".parse().unwrap()), None);
        client.write_all(b"ssh").await.unwrap();
        let mut read = [0u8; 3];
        carried.read_exact(&mut read).await.unwrap();
        assert_eq!(&read, b"ssh");
        drop(client);
        drop(carried);
        carrying.await.unwrap();
        assert_eq!(circuits.carried(from), None, "forgotten once it ends");
        // Another port: closed, counted.
        let (_client, served) = tokio::io::duplex(64);
        onion.serve(served, 7, 443).await;
        assert_eq!(circuits.counts().streams_refused, 1);
    }
}
