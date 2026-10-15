//! Spaces of nodes in one process, and the free ports a space's nodes,
//! in one process or not, take.

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
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
/// one `any` takes.
fn free_port(free: impl Fn(u16) -> bool, any: impl Fn() -> std::io::Result<SocketAddr>) -> u16 {
    // The generator's state, shared by the threads of this process.
    static STATE: AtomicU64 = AtomicU64::new(0);
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
        if free(port) {
            return port;
        }
    }
    // No room below that range: any port the system gives.
    any().unwrap().port()
}
