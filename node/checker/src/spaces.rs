//! Spaces of nodes in one process, the free ports a space's nodes, in
//! one process or not, take, and the hold on a port while its node is
//! down.

use std::collections::BTreeSet;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use vos_node::{Config, Node, Space, SpaceNode};
use vos_wire::peer::NodeNumber;

use crate::Random;

/// How long a test of nodes in one process waits for them to settle.
pub(crate) const IN_PROCESS_WAIT: Duration = Duration::from_secs(20);

/// Wait until `done`, as long as a test of nodes in one process waits for
/// them to settle.
#[track_caller]
pub fn wait_in_process(what: &str, done: impl FnMut() -> bool) {
    crate::wait_until(what, IN_PROCESS_WAIT, done);
}

/// The key a node's first open at `dir` makes.
fn node_key(dir: &Path, agent: &[u8]) -> [u8; 32] {
    let node = Node::open(dir, Config::new(agent.to_vec())).unwrap();
    let key = node.id().0;
    node.shutdown();
    key
}

/// The space of the nodes whose data directories are `dirs`, numbered
/// from 1: each node's key is the one a first open of its directory makes,
/// its peer address a free UDP port, and its ingress the one `ingress`
/// names.
pub fn space<P: AsRef<Path>>(
    agent: &[u8],
    dirs: &[P],
    ingress: impl Fn(NodeNumber) -> String,
) -> Space {
    let nodes = dirs
        .iter()
        .zip(1..)
        .map(|(dir, number)| SpaceNode {
            number,
            key: node_key(dir.as_ref(), agent),
            peer: SocketAddr::from(([127, 0, 0, 1], free_udp_port())),
            ingress: ingress(number),
        })
        .collect();
    Space::new(nodes).unwrap()
}

/// Node `number` opened at `dir`, on a config `config` makes for each try:
/// a restarted node binds its peer address again once its last run has
/// let it go.
pub fn open_node(number: NodeNumber, dir: &Path, mut config: impl FnMut() -> Config) -> Node {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match Node::open(dir, config()) {
            Ok(node) => return node,
            Err(vos_node::Error::Data(error))
                if Instant::now() < until && error.contains("in use") =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("node {number}: {error:?}"),
        }
    }
}

/// A free local TCP port, below the range the system gives out for
/// outgoing connections: a node restarted takes its ports again, and a
/// connection made meanwhile must not have taken one.
pub fn free_tcp_port() -> u16 {
    free_port(
        |port| TcpListener::bind(("127.0.0.1", port)).is_ok(),
        || TcpListener::bind("127.0.0.1:0").unwrap().local_addr(),
    )
}

/// A free local UDP port, below the range the system gives out for
/// outgoing connections, as [`free_tcp_port`].
pub fn free_udp_port() -> u16 {
    free_port(
        |port| UdpSocket::bind(("127.0.0.1", port)).is_ok(),
        || UdpSocket::bind("127.0.0.1:0").unwrap().local_addr(),
    )
}

/// A port below the outgoing range that `free` says is free, or else the
/// one `any` takes; never one this process handed out before, which a
/// node down may be about to take again.
fn free_port(free: impl Fn(u16) -> bool, any: impl Fn() -> std::io::Result<SocketAddr>) -> u16 {
    // The generator's state, shared by the threads of this process.
    static STATE: AtomicU64 = AtomicU64::new(0);
    static HANDED_OUT: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());
    let claim = |port: u16| HANDED_OUT.lock().unwrap().insert(port);
    let lowest_ephemeral = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|range| range.split_whitespace().next()?.parse::<u16>().ok())
        .unwrap_or(32_768);
    // Never a privileged port.
    let (low, high) = ((lowest_ephemeral / 2).max(1024), lowest_ephemeral);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |since| since.as_nanos() as u64)
        ^ u64::from(std::process::id()) << 32;
    for _ in 0..if high > low { 1000 } else { 0 } {
        // One step of the generator, taken whole: no two threads draw the
        // same port.
        let mut drawn = 0;
        STATE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |state| {
                let mut random = Random(if state == 0 { seed | 1 } else { state });
                drawn = random.draw();
                Some(drawn)
            })
            .expect("a step");
        let port = low + (drawn % u64::from(high - low)) as u16;
        if claim(port) && free(port) {
            return port;
        }
    }
    // No room below that range: any port the system gives.
    (0..1000)
        .map(|_| any().unwrap().port())
        .find(|port| claim(*port))
        .expect("a port not handed out before")
}

/// A local port held while the node that binds it is down, so that no
/// other socket, of this process or another, takes it before the node
/// comes back. Dropping it lets the port go, as a node's start does just
/// before the node binds it.
pub struct HeldPort(Holding);

enum Holding {
    /// A listener, polled until `stop` by the thread that resets what
    /// connects.
    Tcp {
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    },
    Udp {
        _socket: UdpSocket,
    },
}

/// How often a held TCP port's thread looks for connections, and for its
/// stop.
const HELD_POLL: Duration = Duration::from_millis(2);

impl HeldPort {
    /// TCP `address`, held by a listener. It binds with `SO_REUSEADDR`, as
    /// a node's own listener does: without it, the node's connections left
    /// in TIME_WAIT would keep it off the port. It listens, since a bound
    /// socket that does not keeps no other `SO_REUSEADDR` bind off. What
    /// connects is reset at once, so a client fails as soon as at a port
    /// nothing serves.
    #[track_caller]
    pub fn tcp(address: SocketAddr) -> Self {
        Self::once_free(address, |address| {
            use socket2::{Domain, Protocol, SockRef, Socket, Type};
            let socket = Socket::new(
                Domain::for_address(address),
                Type::STREAM,
                Some(Protocol::TCP),
            )?;
            socket.set_reuse_address(true)?;
            socket.bind(&address.into())?;
            socket.listen(128)?;
            socket.set_nonblocking(true)?;
            let listener = TcpListener::from(socket);
            let stop = Arc::new(AtomicBool::new(false));
            let stopped = Arc::clone(&stop);
            let thread = std::thread::Builder::new()
                .name(format!("held {address}"))
                .spawn(move || {
                    while !stopped.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                let _ = SockRef::from(&stream).set_linger(Some(Duration::ZERO));
                            }
                            Err(_) => std::thread::sleep(HELD_POLL),
                        }
                    }
                })?;
            Ok(Holding::Tcp {
                stop,
                thread: Some(thread),
            })
        })
    }

    /// UDP `address`, held by a socket bound to it that never reads: what
    /// arrives is lost, as at a node that is down.
    #[track_caller]
    pub fn udp(address: SocketAddr) -> Self {
        Self::once_free(address, |address| {
            UdpSocket::bind(address).map(|socket| Holding::Udp { _socket: socket })
        })
    }

    /// `address` held as `hold` holds it, once a moment's bind elsewhere,
    /// such as another process's probe for a free port, lets it go.
    #[track_caller]
    fn once_free(
        address: SocketAddr,
        hold: impl Fn(SocketAddr) -> std::io::Result<Holding>,
    ) -> Self {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            match hold(address) {
                Ok(holding) => return Self(holding),
                Err(_) if Instant::now() < until => std::thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{address} could not be held: {error}"),
            }
        }
    }
}

impl Drop for HeldPort {
    fn drop(&mut self) {
        if let Holding::Tcp { stop, thread } = &mut self.0 {
            stop.store(true, Ordering::SeqCst);
            if let Some(thread) = thread.take() {
                let _ = thread.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    use super::*;

    #[test]
    fn no_port_is_handed_out_twice() {
        let ports: Vec<u16> = (0..200).map(|_| free_tcp_port()).collect();
        let distinct: BTreeSet<u16> = ports.iter().copied().collect();
        assert_eq!(distinct.len(), ports.len());
    }

    /// A TCP port is held past its last listener's connections left in
    /// TIME_WAIT; while held, it takes no other listener, and what
    /// connects is reset at once; let go of, it binds again.
    #[test]
    fn a_held_tcp_port_takes_no_listener_and_resets_what_connects() {
        let address = SocketAddr::from(([127, 0, 0, 1], free_tcp_port()));
        let listener = TcpListener::bind(address).unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        // Closed from the port's side first: that side waits in TIME_WAIT.
        drop(listener.accept().unwrap());
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
        drop((client, listener));
        let held = HeldPort::tcp(address);
        assert!(TcpListener::bind(address).is_err());
        let started = Instant::now();
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let _ = stream.write_all(b"GET / HTTP/1.1\r\n\r\n");
        let mut answer = Vec::new();
        assert!(!matches!(stream.read_to_end(&mut answer), Ok(length) if length > 0));
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(held);
        TcpListener::bind(address).unwrap();
    }

    /// While held, a UDP port takes no other socket; let go of, it binds
    /// again.
    #[test]
    fn a_held_udp_port_takes_no_other_socket() {
        let address = SocketAddr::from(([127, 0, 0, 1], free_udp_port()));
        let held = HeldPort::udp(address);
        assert!(UdpSocket::bind(address).is_err());
        drop(held);
        UdpSocket::bind(address).unwrap();
    }
}
