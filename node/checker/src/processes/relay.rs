//! A UDP relay between node processes, as their network: each node binds
//! its peer endpoint apart (`--peer-bind`), and the space lists the
//! relay's address for it instead. Datagrams pass through, and the test
//! cuts, thins or delays them.
//!
//! vos-net runs one QUIC connection per direction of dialing, so two kinds
//! of fault:
//! - a *connection* cut loses every datagram of the connection one node
//!   dialed to another, both ways: one-way message loss, as the other
//!   direction's connection goes on;
//! - a *link* fault touches the datagrams one node sends another, of both
//!   connections: lost in part, delayed, or all lost. A link cut cuts the
//!   acknowledgements of the other direction's connection too, so it is a
//!   partition both ways.

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::Random;

/// The largest datagram taken: QUIC may probe large ones on loopback.
const DATAGRAM: usize = 64 * 1024;
/// How long a blocking receive waits before it checks for the stop.
const POLL: Duration = Duration::from_millis(50);

/// A directed link's faults.
#[derive(Clone, Copy, Debug, Default)]
pub struct Link {
    /// Datagrams lost, out of a million.
    pub loss: u32,
    pub delay: Duration,
}

struct Faults {
    /// Connections cut, by (dialer, peer).
    cut_connections: HashSet<(usize, usize)>,
    /// Links cut, by (from, to).
    cut_links: HashSet<(usize, usize)>,
    links: HashMap<(usize, usize), Link>,
    random: Random,
}

impl Faults {
    /// Whether a datagram from node `from` to node `to`, of the connection
    /// `dialer` dialed to `peer`, is lost, and how long it waits if not.
    fn fate(
        &mut self,
        (from, to): (usize, usize),
        (dialer, peer): (usize, usize),
    ) -> Option<Duration> {
        if self.cut_connections.contains(&(dialer, peer)) || self.cut_links.contains(&(from, to)) {
            return None;
        }
        let link = self.links.get(&(from, to)).copied().unwrap_or_default();
        if link.loss > 0 && self.random.below(1_000_000) < u64::from(link.loss) {
            return None;
        }
        Some(link.delay)
    }
}

/// A datagram waiting out its delay.
struct Delayed {
    due: Instant,
    socket: Arc<UdpSocket>,
    to: SocketAddr,
    bytes: Vec<u8>,
}

impl PartialEq for Delayed {
    fn eq(&self, other: &Self) -> bool {
        self.due == other.due
    }
}
impl Eq for Delayed {}
impl PartialOrd for Delayed {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Delayed {
    /// Reversed, so the max-heap `BinaryHeap` pops the earliest due first.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.due.cmp(&self.due)
    }
}

struct Shared {
    faults: Mutex<Faults>,
    delayed: Mutex<BinaryHeap<Delayed>>,
    due: Condvar,
    stop: AtomicBool,
    /// Datagrams the relay itself failed to send on: not faults it was
    /// asked for.
    own_drops: AtomicU64,
}

impl Shared {
    fn pass(&self, socket: &Arc<UdpSocket>, to: SocketAddr, bytes: &[u8], wait: Duration) {
        if wait.is_zero() {
            if socket.send_to(bytes, to).is_err() {
                self.own_drops.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        self.delayed.lock().unwrap().push(Delayed {
            due: Instant::now() + wait,
            socket: Arc::clone(socket),
            to,
            bytes: bytes.to_vec(),
        });
        self.due.notify_one();
    }
}

/// The relay for `count` nodes, numbered from 1.
pub struct Relay {
    /// The address the space lists for each node.
    listed: Vec<SocketAddr>,
    /// The port of every socket of the relay's.
    ports: Vec<u16>,
    shared: Arc<Shared>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

fn socket(at: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_recv_buffer_size(4 << 20)?;
    socket.set_send_buffer_size(4 << 20)?;
    socket.bind(&at.into())?;
    let socket: UdpSocket = socket.into();
    socket.set_read_timeout(Some(POLL))?;
    Ok(socket)
}

impl Relay {
    /// A relay for nodes bound at `bound` (node `n` at `bound[n - 1]`):
    /// its listed addresses are where peers must dial them.
    pub fn start(bound: &[SocketAddr]) -> std::io::Result<Relay> {
        let count = bound.len();
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listening: Vec<Arc<UdpSocket>> = (0..count)
            .map(|_| socket(local).map(Arc::new))
            .collect::<Result<_, _>>()?;
        let listed: Vec<SocketAddr> = listening
            .iter()
            .map(|socket| socket.local_addr())
            .collect::<Result<_, _>>()?;
        // One socket for each sender toward each node, kept for the run.
        let mut proxies: HashMap<(usize, usize), Arc<UdpSocket>> = HashMap::new();
        for dialer in 1..=count {
            for peer in (1..=count).filter(|peer| *peer != dialer) {
                proxies.insert((dialer, peer), Arc::new(socket(local)?));
            }
        }
        let ports = listening
            .iter()
            .chain(proxies.values())
            .map(|socket| socket.local_addr().map(|address| address.port()))
            .collect::<Result<_, _>>()?;
        let shared = Arc::new(Shared {
            faults: Mutex::new(Faults {
                cut_connections: HashSet::new(),
                cut_links: HashSet::new(),
                links: HashMap::new(),
                random: Random(0x2545_f491_4f6c_dd1d),
            }),
            delayed: Mutex::new(BinaryHeap::new()),
            due: Condvar::new(),
            stop: AtomicBool::new(false),
            own_drops: AtomicU64::new(0),
        });
        let mut threads = Vec::new();
        // At a node's listed address: datagrams of connections others
        // dialed to it, on to the node through the dialer's own socket.
        for (at, listen) in listening.iter().enumerate() {
            let peer = at + 1;
            let listen = Arc::clone(listen);
            let shared = Arc::clone(&shared);
            let proxies = proxies.clone();
            let bound = bound.to_vec();
            let senders: HashMap<SocketAddr, usize> =
                (1..=count).map(|node| (bound[node - 1], node)).collect();
            threads.push(std::thread::spawn(move || {
                let mut buffer = vec![0; DATAGRAM];
                while !shared.stop.load(Ordering::Relaxed) {
                    let Ok((length, from)) = listen.recv_from(&mut buffer) else {
                        continue;
                    };
                    let Some(&dialer) = senders.get(&from) else {
                        continue;
                    };
                    let Some(proxy) = proxies.get(&(dialer, peer)) else {
                        continue;
                    };
                    let fate = shared
                        .faults
                        .lock()
                        .unwrap()
                        .fate((dialer, peer), (dialer, peer));
                    if let Some(wait) = fate {
                        shared.pass(proxy, bound[peer - 1], &buffer[..length], wait);
                    }
                }
            }));
        }
        // At a dialer's socket toward a node: the node's answers, back to
        // the dialer from the address it dialed.
        for (&(dialer, peer), proxy) in &proxies {
            let proxy = Arc::clone(proxy);
            let back = Arc::clone(&listening[peer - 1]);
            let shared = Arc::clone(&shared);
            let to = bound[dialer - 1];
            threads.push(std::thread::spawn(move || {
                let mut buffer = vec![0; DATAGRAM];
                while !shared.stop.load(Ordering::Relaxed) {
                    let Ok((length, _)) = proxy.recv_from(&mut buffer) else {
                        continue;
                    };
                    let fate = shared
                        .faults
                        .lock()
                        .unwrap()
                        .fate((peer, dialer), (dialer, peer));
                    if let Some(wait) = fate {
                        shared.pass(&back, to, &buffer[..length], wait);
                    }
                }
            }));
        }
        // The delayed datagrams, in order of their due time.
        {
            let shared = Arc::clone(&shared);
            threads.push(std::thread::spawn(move || {
                let mut delayed = shared.delayed.lock().unwrap();
                while !shared.stop.load(Ordering::Relaxed) {
                    let now = Instant::now();
                    match delayed.peek() {
                        Some(next) if next.due <= now => {
                            let next = delayed.pop().unwrap();
                            if next.socket.send_to(&next.bytes, next.to).is_err() {
                                shared.own_drops.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Some(next) => {
                            let wait = next.due - now;
                            delayed = shared.due.wait_timeout(delayed, wait.min(POLL)).unwrap().0;
                        }
                        None => {
                            delayed = shared.due.wait_timeout(delayed, POLL).unwrap().0;
                        }
                    }
                }
            }));
        }
        Ok(Relay {
            listed,
            ports,
            shared,
            threads,
        })
    }

    fn faults(&self) -> std::sync::MutexGuard<'_, Faults> {
        self.shared.faults.lock().unwrap()
    }

    /// The address peers dial node `number` at.
    pub fn listed(&self, number: usize) -> SocketAddr {
        self.listed[number - 1]
    }

    /// Lose every datagram of the connection `dialer` dialed to `peer`,
    /// both ways.
    pub fn cut_connection(&self, dialer: usize, peer: usize) {
        self.faults().cut_connections.insert((dialer, peer));
    }

    /// Lose every datagram node `from` sends node `to`.
    pub fn cut_link(&self, from: usize, to: usize) {
        self.faults().cut_links.insert((from, to));
    }

    /// Cut node `number` off from every other, both ways.
    pub fn isolate(&self, number: usize) {
        for other in (1..=self.listed.len()).filter(|other| *other != number) {
            self.cut_link(number, other);
            self.cut_link(other, number);
        }
    }

    /// Thin or delay what node `from` sends node `to`.
    pub fn set_link(&self, from: usize, to: usize, link: Link) {
        self.faults().links.insert((from, to), link);
    }

    /// Every link and connection restored.
    pub fn heal(&self) {
        let mut faults = self.faults();
        faults.cut_connections.clear();
        faults.cut_links.clear();
        faults.links.clear();
    }

    /// Datagrams the relay lost of itself: sends that failed, and those
    /// the system dropped with a socket's receive queue full.
    pub fn own_drops(&self) -> u64 {
        self.shared.own_drops.load(Ordering::Relaxed) + self.received_drops()
    }

    /// Datagrams dropped on arrival at the relay's sockets, as
    /// `/proc/net/udp` counts them (its last column).
    fn received_drops(&self) -> u64 {
        let Ok(table) = std::fs::read_to_string("/proc/net/udp") else {
            return 0;
        };
        table
            .lines()
            .skip(1)
            .filter_map(|line| {
                let columns: Vec<&str> = line.split_whitespace().collect();
                // 127.0.0.1, as the kernel prints it.
                let (address, port) = columns.get(1)?.split_once(':')?;
                let port = u16::from_str_radix(port, 16).ok()?;
                (address == "0100007F" && self.ports.contains(&port))
                    .then(|| columns.last()?.parse::<u64>().ok())?
            })
            .sum()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        self.shared.due.notify_all();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}
