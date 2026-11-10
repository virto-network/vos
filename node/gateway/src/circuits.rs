//! The onion's streams (`light-node.md` §6.1, §6.6): each arrives on a
//! rendezvous circuit, from no address, for a virtual port, 22 (SSH) or 80
//! (HTTP), the clearnet's protocols and nothing else. A circuit counts as
//! one address for the limits per address: its own address, in a range of
//! the unique local IPv6 addresses no client holds, and each stream on it
//! a port of that address, so a connection's caps count it alone.
//!
//! HTTP streams go to the onion's own HTTP server, SSH streams to the
//! onion's own SSH server, each stream handed over with its address, so
//! both count the circuit and mark onion what they serve.
//!
//! The streams come from arti in process (the `onion` module, the `tor` feature) or from a C tor
//! beside the gateway ([`sidecar`]), whose `HiddenServiceExportCircuitID
//! haproxy` names each stream's circuit.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
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
    open: Mutex<HashMap<u32, Open>>,
    circuits: Mutex<usize>,
    counts: [AtomicU64; 4],
}

/// A circuit's open streams: the ports of its address they hold, the next
/// port to try, and the circuit's place when its streams hold it.
#[derive(Default)]
struct Open {
    ports: Vec<u16>,
    next: u16,
    /// Held while the circuit's streams are open, given back with the
    /// entry.
    _place: Option<CircuitPlace>,
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
        let closed = {
            let mut open = self.circuits.open.lock().expect("the open streams");
            let Some(streams) = open.get_mut(&self.circuit) else {
                return;
            };
            streams.ports.retain(|port| *port != self.peer.port());
            if streams.ports.is_empty() {
                open.remove(&self.circuit)
            } else {
                None
            }
        };
        // The circuit's place, if its streams held it, goes outside the lock.
        drop(closed);
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

    /// A place for a stream on `circuit`, while it holds fewer than its
    /// limit: on a circuit whose own task holds its place (arti's).
    pub fn stream(self: &Arc<Self>, circuit: u32) -> Option<StreamPlace> {
        self.open_stream(circuit, false)
    }

    /// A place for a stream on `circuit`, its first stream taking the
    /// circuit's place among the onion's and its last giving it back: a
    /// circuit that only its streams show (C tor's).
    pub fn stream_placing(self: &Arc<Self>, circuit: u32) -> Option<StreamPlace> {
        self.open_stream(circuit, true)
    }

    fn open_stream(self: &Arc<Self>, circuit: u32, placing: bool) -> Option<StreamPlace> {
        let mut open = self.open.lock().expect("the open streams");
        if placing && !open.contains_key(&circuit) {
            let place = self.circuit()?;
            open.insert(
                circuit,
                Open {
                    _place: Some(place),
                    ..Open::default()
                },
            );
        }
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

/// A stream from the onion, with its address.
type Accepted = (Box<dyn Io>, SocketAddr);

/// The onion's streams to one of its ports, as that port's server takes
/// them: the HTTP server's listener, or the SSH server's.
pub struct OnionListener(tokio::sync::mpsc::Receiver<Accepted>);

impl OnionListener {
    /// The next stream and its address; `None` once the onion is gone.
    pub async fn next(&mut self) -> Option<Accepted> {
        self.0.recv().await
    }
}

impl vos_http::Listener for OnionListener {
    type Stream = Compat<Box<dyn Io>>;

    async fn accept(&mut self) -> std::io::Result<(Self::Stream, SocketAddr)> {
        match self.next().await {
            Some((stream, peer)) => Ok((stream.compat(), peer)),
            None => Err(std::io::ErrorKind::BrokenPipe.into()),
        }
    }
}

/// Streams the onion's servers wait to take, a port's at most.
const WAITING: usize = 64;

/// Where the onion's streams go: its HTTP server and, if it serves SSH,
/// its SSH server.
pub struct Onion {
    pub circuits: Arc<Circuits>,
    http: tokio::sync::mpsc::Sender<Accepted>,
    ssh: Option<tokio::sync::mpsc::Sender<Accepted>>,
}

impl Onion {
    /// The onion over `circuits`; and the listeners its HTTP streams and,
    /// if it serves `ssh`, its SSH streams arrive on.
    pub fn new(
        circuits: Arc<Circuits>,
        ssh: bool,
    ) -> (Arc<Self>, OnionListener, Option<OnionListener>) {
        let (http, accepted) = tokio::sync::mpsc::channel(WAITING);
        let (ssh, ssh_accepted) = match ssh {
            true => {
                let (ssh, accepted) = tokio::sync::mpsc::channel(WAITING);
                (Some(ssh), Some(OnionListener(accepted)))
            }
            false => (None, None),
        };
        (
            Arc::new(Self {
                circuits,
                http,
                ssh,
            }),
            OnionListener(accepted),
            ssh_accepted,
        )
    }

    /// Whether a stream to virtual port `port` would be served: SSH, if
    /// the onion serves it, and HTTP.
    pub fn serves(&self, port: u16) -> bool {
        port == HTTP || (port == SSH && self.ssh.is_some())
    }

    /// Serve `stream`, a stream on `circuit` to virtual port `port`, until
    /// it ends: closed at once past its circuit's streams, or for a port
    /// the onion does not serve. The circuit's own task holds its place.
    pub async fn serve(&self, stream: impl Io, circuit: u32, port: u16) {
        self.serve_placed(stream, circuit, port, false).await
    }

    /// [`Onion::serve`], the circuit's streams holding its place when
    /// `placing`: closed at once past the onion's circuits too.
    async fn serve_placed(&self, stream: impl Io, circuit: u32, port: u16, placing: bool) {
        if !self.serves(port) {
            self.circuits.refused();
            return;
        }
        let place = match placing {
            true => self.circuits.stream_placing(circuit),
            false => self.circuits.stream(circuit),
        };
        let Some(place) = place else {
            return;
        };
        let peer = place.peer;
        let stream = Placed {
            stream,
            _place: place,
        };
        let server = match (port, &self.ssh) {
            (SSH, Some(ssh)) => ssh,
            _ => &self.http,
        };
        let _ = server.send((Box::new(stream), peer)).await;
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

    /// The source range C tor writes a circuit's number into.
    const EXPORTED: u128 = 0xfc00_dead_beef_4dad << 64;
    /// PROXY lines read at once: past them, a connection waits its turn.
    const READING: usize = 256;

    /// The circuit a PROXY line names: the last 32 bits of its source
    /// address, a `TCP6` one in C tor's `fc00:dead:beef:4dad::/64`.
    pub fn circuit(line: &str) -> Option<u32> {
        let mut fields = line.strip_suffix("\r\n")?.split(' ');
        let ("PROXY", "TCP6", Some(source)) = (fields.next()?, fields.next()?, fields.next())
        else {
            return None;
        };
        let source = u128::from(source.parse::<Ipv6Addr>().ok()?);
        (source >> 64 == EXPORTED >> 64).then_some(source as u32)
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
    /// `port`, each on the circuit its PROXY line names, its first stream
    /// taking the circuit's place among the onion's. The listener's trust
    /// boundary is the host: a local process may name any circuit, as it
    /// may reach the gateway's loopback ports.
    pub async fn serve(onion: Arc<Onion>, listener: tokio::net::TcpListener, port: u16) {
        let reading = Arc::new(tokio::sync::Semaphore::new(READING));
        loop {
            let (mut stream, peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(%error, "C tor's listener: an accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            if !peer.ip().is_loopback() {
                continue;
            }
            let Ok(turn) = Arc::clone(&reading).acquire_owned().await else {
                return;
            };
            let onion = Arc::clone(&onion);
            tokio::spawn(async move {
                let named = tokio::time::timeout(DEADLINE, line(&mut stream)).await;
                drop(turn);
                let Some(circuit) = named.ok().flatten().as_deref().and_then(circuit) else {
                    return;
                };
                let _ = stream.set_nodelay(true);
                onion.serve_placed(stream, circuit, port, true).await;
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

    /// A circuit only its streams show takes its place with its first
    /// stream and gives it back with its last; a live stream's port is
    /// never another's on its circuit.
    #[test]
    fn a_placing_circuit_is_held_by_its_streams() {
        let circuits = Circuits::new(PerCircuit {
            streams: 2,
            circuits: 1,
        });
        let first = circuits.stream_placing(9).unwrap();
        let second = circuits.stream_placing(9).unwrap();
        assert!(
            circuits.stream_placing(10).is_none(),
            "the onion's circuits"
        );
        assert_ne!(first.peer, second.peer);
        drop(first);
        assert!(
            circuits.stream_placing(10).is_none(),
            "held while one is open"
        );
        let third = circuits.stream_placing(9).unwrap();
        assert_ne!(third.peer, second.peer);
        drop((second, third));
        assert!(
            circuits.stream_placing(10).is_some(),
            "given back with the last"
        );
    }

    /// C tor's connection: its PROXY line read and its stream served on
    /// the circuit the line names; one without a line closed.
    #[tokio::test]
    async fn c_tors_streams_are_served_on_their_circuits() {
        use tokio::io::AsyncWriteExt;
        let circuits = Circuits::new(PerCircuit::default());
        let (onion, mut http, _) = Onion::new(Arc::clone(&circuits), false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(sidecar::serve(onion, listener, HTTP));
        let mut bare = tokio::net::TcpStream::connect(address).await.unwrap();
        bare.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut tor = tokio::net::TcpStream::connect(address).await.unwrap();
        tor.write_all(b"PROXY TCP6 fc00:dead:beef:4dad::12 ::1 65535 80\r\nping")
            .await
            .unwrap();
        let (mut stream, peer) = vos_http::Listener::accept(&mut http).await.unwrap();
        assert_eq!(peer.ip(), address_of(0x12));
        let mut read = [0u8; 4];
        futures::AsyncReadExt::read_exact(&mut stream, &mut read)
            .await
            .unwrap();
        assert_eq!(&read, b"ping", "nothing past the line taken");
        assert_eq!(circuits.counts().circuits, 1, "its circuit placed");
    }

    fn address_of(circuit: u32) -> IpAddr {
        address(circuit)
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
            "PROXY TCP6 fd00::1 ::1 1 2\r\n",
        ] {
            assert_eq!(sidecar::circuit(refused), None, "{refused}");
        }
    }

    /// An HTTP stream reaches the HTTP listener and an SSH stream the SSH
    /// one, each with its circuit's address and a port of its own, holding
    /// its place on the circuit until it ends; a stream to another port is
    /// closed.
    #[tokio::test]
    async fn streams_go_by_their_port() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let circuits = Circuits::new(PerCircuit::default());
        let (onion, mut http, ssh) = Onion::new(Arc::clone(&circuits), true);
        let mut ssh = ssh.expect("the onion serves SSH");
        let (mut client, served) = tokio::io::duplex(64);
        onion.serve(served, 5, HTTP).await;
        let (mut stream, peer) = vos_http::Listener::accept(&mut http).await.unwrap();
        assert_eq!(peer.ip(), address(5));
        client.write_all(b"ping").await.unwrap();
        let mut read = [0u8; 4];
        futures::AsyncReadExt::read_exact(&mut stream, &mut read)
            .await
            .unwrap();
        assert_eq!(&read, b"ping");
        // SSH: to the SSH server, on its circuit.
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
        let (_client, served) = tokio::io::duplex(64);
        onion.serve(served, 7, 443).await;
        assert_eq!(circuits.counts().streams_refused, 1);
        // Without SSH, port 22 is another port.
        let (onion, _http, none) = Onion::new(Arc::clone(&circuits), false);
        assert!(none.is_none() && !onion.serves(SSH));
    }
}
