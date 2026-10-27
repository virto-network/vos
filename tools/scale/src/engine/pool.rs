//! Kept connections to one node, plain or in TLS: at most the driver's cap,
//! one request on each at a time; past the cap a request waits for one.
//! No timer runs per request: a reaper shuts the socket of a request past
//! its deadline. Or, over the node API, one QUIC connection, a stream a
//! request, each within its deadline, the node's stream limit holding
//! the rest back.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use futures_rustls::TlsConnector;
use rustls::pki_types::ServerName;
use smol::Timer;
use smol::channel::{Receiver, Sender};
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::TcpStream;
use vos_node::client::Target;
use vos_wire::Decode;
use vos_wire::ingress::Response;

use crate::histogram::Histogram;

/// How long a connection may take to open, its handshake included.
const CONNECT: Duration = Duration::from_secs(10);
/// A kept connection is used again only if idle less than this long, well
/// within the node's idle limit.
const REUSE: Duration = Duration::from_secs(20);
/// The most a read takes at once: an answer is a few hundred bytes.
const READ_CHUNK: usize = 4 << 10;

/// A connection's stream, plain or in TLS.
enum Stream {
    Plain(TcpStream),
    Tls(Box<futures_rustls::client::TlsStream<TcpStream>>),
}

struct Conn {
    stream: Stream,
    /// Its socket, which the reaper shuts when a request on it is late.
    socket: TcpStream,
    /// Bytes read past the last answer.
    buffer: Vec<u8>,
    /// When its last answer came: one idle past [`REUSE`] is closed, not
    /// used, as the node may have closed it.
    used: Instant,
}

impl Conn {
    async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match &mut self.stream {
            Stream::Plain(stream) => {
                stream.write_all(bytes).await?;
                stream.flush().await
            }
            Stream::Tls(stream) => {
                stream.write_all(bytes).await?;
                stream.flush().await
            }
        }
    }

    /// Read what has arrived onto the buffer's end: how much.
    async fn read_more(&mut self) -> std::io::Result<usize> {
        let at = self.buffer.len();
        self.buffer.resize(at + READ_CHUNK, 0);
        let read = match &mut self.stream {
            Stream::Plain(stream) => stream.read(&mut self.buffer[at..]).await,
            Stream::Tls(stream) => stream.read(&mut self.buffer[at..]).await,
        };
        self.buffer.truncate(at + *read.as_ref().unwrap_or(&0));
        read
    }

    /// The next answer: its status, its body, and whether the node closes
    /// the connection after it.
    async fn answer(&mut self) -> std::io::Result<(u16, Vec<u8>, bool)> {
        let invalid =
            |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, why.to_string());
        loop {
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut answer = httparse::Response::new(&mut headers);
            match answer.parse(&self.buffer) {
                Ok(httparse::Status::Complete(head)) => {
                    let status = answer.code.unwrap_or(0);
                    let header = |name: &str| {
                        answer
                            .headers
                            .iter()
                            .find(|header| header.name.eq_ignore_ascii_case(name))
                            .map(|header| header.value)
                    };
                    let length: usize = header("content-length")
                        .and_then(|value| std::str::from_utf8(value).ok()?.trim().parse().ok())
                        .ok_or_else(|| invalid("an answer without a length"))?;
                    if length > 16 << 20 {
                        return Err(invalid("an answer larger than any the node gives"));
                    }
                    let close = header("connection")
                        .is_some_and(|value| value.eq_ignore_ascii_case(b"close"));
                    while self.buffer.len() < head + length {
                        if self.read_more().await? == 0 {
                            return Err(invalid("the answer ended early"));
                        }
                    }
                    let body = self.buffer[head..head + length].to_vec();
                    self.buffer.drain(..head + length);
                    return Ok((status, body, close));
                }
                Ok(httparse::Status::Partial) => {
                    if self.buffer.len() > 64 << 10 {
                        return Err(invalid("an answer's head too large"));
                    }
                    if self.read_more().await? == 0 {
                        return Err(invalid("the connection closed"));
                    }
                }
                Err(_) => return Err(invalid("an answer that is not HTTP")),
            }
        }
    }
}

/// What a pool saw over an interval: the requests that waited for a
/// connection, how long, and the most connections in use at once.
#[derive(Clone, Default)]
pub struct PoolStats {
    pub waits: u64,
    pub wait: Histogram,
    pub in_use_max: usize,
}

impl PoolStats {
    pub fn absorb(&mut self, other: &PoolStats) {
        self.waits += other.waits;
        self.wait.add(&other.wait);
        self.in_use_max = self.in_use_max.max(other.in_use_max);
    }
}

/// The node API over QUIC: its address, the node's key it pins, the
/// driver's key it presents, and the connection once dialed.
struct Quic {
    authority: String,
    node: [u8; 32],
    client: [u8; 32],
    dialed: smol::lock::Mutex<Option<(quinn::Endpoint, quinn::Connection)>>,
}

/// Kept connections to one node.
pub struct Pool {
    /// The node API over QUIC, in place of HTTP's connections.
    quic: Option<Quic>,
    addresses: Vec<SocketAddr>,
    tls: Option<(TlsConnector, ServerName<'static>)>,
    pub authority: String,
    /// The most connections it keeps.
    cap: usize,
    /// Kept connections, the last used on top: a few stay busy, and the
    /// rest age out unused.
    idle: RefCell<Vec<Conn>>,
    open: Cell<usize>,
    in_use: Cell<usize>,
    waiting: RefCell<VecDeque<Sender<Option<Conn>>>>,
    /// Requests on their connections, by number: each one's deadline, and
    /// its socket, which the reaper shuts past it.
    asked: RefCell<HashMap<u64, (Instant, TcpStream)>>,
    next: Cell<u64>,
    stats: RefCell<PoolStats>,
}

impl Pool {
    pub fn new(target: &Target, cap: usize) -> Result<Self, String> {
        let addresses: Vec<SocketAddr> = target
            .authority()
            .to_socket_addrs()
            .map_err(|error| format!("{}: {error}", target.authority()))?
            .collect();
        Ok(Self {
            quic: None,
            addresses,
            tls: target
                .tls()
                .map(|(config, name)| (TlsConnector::from(config), name)),
            authority: target.authority().to_string(),
            cap: cap.max(1),
            idle: RefCell::new(Vec::new()),
            open: Cell::new(0),
            in_use: Cell::new(0),
            waiting: RefCell::new(VecDeque::new()),
            asked: RefCell::new(HashMap::new()),
            next: Cell::new(0),
            stats: RefCell::new(PoolStats::default()),
        })
    }

    /// The node API at `url` (`quic://host:port`) over QUIC, pinned to the
    /// node's key `node`, as the driver's key `client`.
    pub fn quic(url: &str, node: [u8; 32], client: [u8; 32]) -> Result<Self, String> {
        let authority = url
            .strip_prefix("quic://")
            .ok_or_else(|| format!("{url}: not a quic:// address"))?
            .to_string();
        Ok(Self {
            quic: Some(Quic {
                authority: authority.clone(),
                node,
                client,
                dialed: smol::lock::Mutex::new(None),
            }),
            addresses: Vec::new(),
            tls: None,
            authority,
            cap: 1,
            idle: RefCell::new(Vec::new()),
            open: Cell::new(0),
            in_use: Cell::new(0),
            waiting: RefCell::new(VecDeque::new()),
            asked: RefCell::new(HashMap::new()),
            next: Cell::new(0),
            stats: RefCell::new(PoolStats::default()),
        })
    }

    /// The QUIC connection, dialed if none is open.
    async fn connection(quic: &Quic) -> Result<quinn::Connection, String> {
        let mut dialed = quic.dialed.lock().await;
        if let Some((_, connection)) = dialed.as_ref()
            && connection.close_reason().is_none()
        {
            return Ok(connection.clone());
        }
        let address = quic
            .authority
            .to_socket_addrs()
            .map_err(|error| error.to_string())?
            .next()
            .ok_or("the node has no address")?;
        let bind: SocketAddr = if address.is_ipv4() {
            "0.0.0.0:0".parse().expect("an address")
        } else {
            "[::]:0".parse().expect("an address")
        };
        let socket = std::net::UdpSocket::bind(bind).map_err(|error| error.to_string())?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            std::sync::Arc::new(quinn::SmolRuntime),
        )
        .map_err(|error| error.to_string())?;
        let config = vos_net::api::client_config(
            &quic.client,
            quic.node,
            std::sync::Arc::new(quinn::TransportConfig::default()),
        );
        let connecting = endpoint
            .connect_with(config, address, "node.vos")
            .map_err(|error| error.to_string())?;
        let late = async {
            Timer::after(CONNECT).await;
            Err(quinn::ConnectionError::TimedOut)
        };
        let connection = smol::future::or(connecting, late)
            .await
            .map_err(|error| error.to_string())?;
        *dialed = Some((endpoint, connection.clone()));
        Ok(connection)
    }

    /// POST `body` to `path` over the node API, as the route table
    /// translates it: the node's answer, within `within`.
    async fn post_quic(
        &self,
        quic: &Quic,
        path: &str,
        body: &[u8],
        within: Duration,
    ) -> Result<Response, String> {
        let request = vos_http::Request {
            method: "POST".into(),
            path: path.into(),
            headers: Vec::new(),
            body: body.to_vec(),
            peer: None,
            large: None,
        };
        let vos_http::routes::Routed::Request { kind, body } = vos_http::routes::route(&request)
        else {
            return Err(format!("{path}: not a request the node API takes"));
        };
        let asked = async {
            let connection = Self::connection(quic).await?;
            self.in_use.set(self.in_use.get() + 1);
            {
                let mut stats = self.stats.borrow_mut();
                stats.in_use_max = stats.in_use_max.max(self.in_use.get());
            }
            let answered = vos_api::quic::request(&connection, kind as u16, &body).await;
            self.in_use.set(self.in_use.get() - 1);
            answered.map_err(|error| error.to_string())
        };
        let late = async {
            Timer::after(within).await;
            Err("timed out".to_string())
        };
        let (answered, bytes) = smol::future::or(asked, late).await?;
        let answer = vos_http::routes::answer(answered, &bytes);
        Response::decode(&answer.body)
            .map(|(response, _)| response)
            .map_err(|_| format!("an answer it cannot read (status {})", answer.status))
    }

    /// The connections open, and those idle.
    #[cfg(test)]
    fn counts(&self) -> (usize, usize) {
        (self.open.get(), self.idle.borrow().len())
    }

    /// What it saw since the last time asked.
    pub fn take_stats(&self) -> PoolStats {
        std::mem::take(&mut *self.stats.borrow_mut())
    }

    async fn connect(&self) -> std::io::Result<Conn> {
        let opening = async {
            let mut last = None;
            for address in &self.addresses {
                match TcpStream::connect(*address).await {
                    Ok(tcp) => return self.handshake(tcp).await,
                    Err(error) => last = Some(error),
                }
            }
            Err(last.unwrap_or_else(|| std::io::Error::other("the node has no address")))
        };
        let late = async {
            Timer::after(CONNECT).await;
            Err(std::io::ErrorKind::TimedOut.into())
        };
        smol::future::or(opening, late).await
    }

    async fn handshake(&self, tcp: TcpStream) -> std::io::Result<Conn> {
        tcp.set_nodelay(true)?;
        let socket = tcp.clone();
        let stream = match &self.tls {
            Some((connector, name)) => {
                Stream::Tls(Box::new(connector.connect(name.clone(), tcp).await?))
            }
            None => Stream::Plain(tcp),
        };
        Ok(Conn {
            stream,
            socket,
            buffer: Vec::new(),
            used: Instant::now(),
        })
    }

    /// A kept connection, a new one while fewer than the cap are open, or
    /// the next one given back, within `within`; `held` once it holds a
    /// place among them.
    async fn take(&self, held: &Held<'_>, within: Duration) -> std::io::Result<Conn> {
        let kept = self.idle.borrow_mut().pop();
        if let Some(conn) = kept {
            held.0.set(true);
            if conn.used.elapsed() < REUSE {
                return Ok(conn);
            }
            // Stale: closed, its place taken by this request.
            drop(conn);
            return self.connect().await;
        }
        if self.open.get() >= self.cap {
            let asked = Instant::now();
            let (sender, receiver) = smol::channel::bounded(1);
            self.waiting.borrow_mut().push_back(sender);
            let mut waiting = Waiting(self, Some(receiver));
            let given = {
                let Some(receiver) = &waiting.1 else {
                    unreachable!("waiting")
                };
                let given = async { Some(receiver.recv().await) };
                let late = async {
                    Timer::after(within).await;
                    None
                };
                smol::future::or(given, late).await
            };
            {
                let mut stats = self.stats.borrow_mut();
                stats.waits += 1;
                stats.wait.record(asked.elapsed().as_micros() as u64);
            }
            let Some(given) = given else {
                // Dropping `waiting` gives back anything sent meanwhile.
                return Err(std::io::ErrorKind::TimedOut.into());
            };
            waiting.1 = None;
            return match given {
                Ok(Some(conn)) => {
                    held.0.set(true);
                    Ok(conn)
                }
                // A connection closed, its place given to this request.
                Ok(None) => {
                    held.0.set(true);
                    self.connect().await
                }
                Err(_) => Err(std::io::Error::other("the pool closed")),
            };
        }
        self.open.set(self.open.get() + 1);
        held.0.set(true);
        self.connect().await
    }

    /// A connection back, or `None` for one that closed: its place goes to
    /// the next request waiting.
    fn give(&self, conn: Option<Conn>) {
        match conn {
            Some(mut conn) => {
                conn.used = Instant::now();
                // The longest idle, at the bottom, are closed before the node
                // closes them, not found stale when a burst needs them.
                let stale = {
                    let mut idle = self.idle.borrow_mut();
                    let stale = idle
                        .iter()
                        .take_while(|kept| kept.used.elapsed() >= REUSE)
                        .count();
                    idle.drain(..stale).count()
                };
                self.open.set(self.open.get() - stale);
                loop {
                    let Some(waiter) = self.waiting.borrow_mut().pop_front() else {
                        break;
                    };
                    match waiter.try_send(Some(conn)) {
                        Ok(()) => return,
                        Err(error) => conn = error.into_inner().expect("the connection"),
                    }
                }
                self.idle.borrow_mut().push(conn);
            }
            None => {
                loop {
                    let Some(waiter) = self.waiting.borrow_mut().pop_front() else {
                        break;
                    };
                    if waiter.try_send(None).is_ok() {
                        return;
                    }
                }
                self.open.set(self.open.get() - 1);
            }
        }
    }

    /// Open a connection and keep it: a handshake done before the load
    /// starts.
    pub async fn warm(&self) {
        if let Some(quic) = &self.quic {
            let _ = Self::connection(quic).await;
            return;
        }
        if self.open.get() >= self.cap {
            return;
        }
        self.open.set(self.open.get() + 1);
        match self.connect().await {
            Ok(conn) => self.give(Some(conn)),
            Err(_) => self.give(None),
        }
    }

    /// POST `body` to `path`: the node's answer, within `within`. An error
    /// is the transport's: no answer came.
    pub async fn post(
        &self,
        path: &str,
        body: &[u8],
        within: Duration,
    ) -> Result<Response, String> {
        if let Some(quic) = &self.quic {
            return self.post_quic(quic, path, body, within).await;
        }
        let held = Held(Cell::new(false), self);
        let mut conn = match self.take(&held, within).await {
            Ok(conn) => conn,
            Err(error) => return Err(error.kind().to_string()),
        };
        self.in_use.set(self.in_use.get() + 1);
        {
            let mut stats = self.stats.borrow_mut();
            stats.in_use_max = stats.in_use_max.max(self.in_use.get());
        }
        let mut request = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
            self.authority,
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        let id = self.next.get();
        self.next.set(id + 1);
        self.asked
            .borrow_mut()
            .insert(id, (Instant::now() + within, conn.socket.clone()));
        let answered = match conn.write_all(&request).await {
            Ok(()) => conn.answer().await,
            Err(error) => Err(error),
        };
        let reaped = self.asked.borrow_mut().remove(&id).is_none();
        self.in_use.set(self.in_use.get() - 1);
        held.0.set(false);
        match answered {
            Ok((status, answer, close)) => {
                self.give((!close).then_some(conn));
                Response::decode(&answer)
                    .map(|(response, _)| response)
                    .map_err(|_| format!("an answer it cannot read (status {status})"))
            }
            Err(_) if reaped => {
                self.give(None);
                Err("timed out".into())
            }
            Err(error) => {
                self.give(None);
                Err(error.kind().to_string())
            }
        }
    }

    /// Shut the connections whose requests are past their deadlines: each
    /// request then fails, timed out.
    pub fn reap(&self) {
        let now = Instant::now();
        self.asked.borrow_mut().retain(|_, (deadline, socket)| {
            let late = *deadline <= now;
            if late {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            }
            !late
        });
    }
}

/// A request's place among a pool's connections: given back as closed if
/// the request is dropped holding it.
struct Held<'a>(Cell<bool>, &'a Pool);

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if self.0.get() {
            self.1.give(None);
        }
    }
}

/// A request waiting for a connection: if it ends first, what it was
/// given goes back.
struct Waiting<'a>(&'a Pool, Option<Receiver<Option<Conn>>>);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if let Some(Ok(given)) = self.1.as_ref().map(Receiver::try_recv) {
            self.0.give(given);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Pool;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::{Duration, Instant};
    use vos_node::client::Target;
    use vos_wire::Encode;
    use vos_wire::ingress::Response;

    /// A node stand-in on loopback: every request answered `Busy` after
    /// `delay`, its connection kept.
    fn stand_in(delay: Duration) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                std::thread::spawn(move || {
                    let body = Response::Busy.encode();
                    let mut buffer = [0u8; 4096];
                    while let Ok(read) = stream.read(&mut buffer) {
                        if read == 0 {
                            return;
                        }
                        std::thread::sleep(delay);
                        let head = format!(
                            "HTTP/1.1 503 Busy\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        );
                        if stream.write_all(head.as_bytes()).is_err()
                            || stream.write_all(&body).is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        port
    }

    fn pool(port: u16, cap: usize) -> Pool {
        let target = Target::loopback(&format!("http://127.0.0.1:{port}")).unwrap();
        Pool::new(&target, cap).unwrap()
    }

    #[test]
    fn requests_past_the_cap_wait_for_a_connection_and_reuse_it() {
        let pool = pool(stand_in(Duration::from_millis(50)), 2);
        let answers = smol::block_on(async {
            let posts = (0..6).map(|_| pool.post("/", b"x", Duration::from_secs(5)));
            futures_join(posts.collect()).await
        });
        assert!(answers.iter().all(|answer| *answer == Ok(Response::Busy)));
        // Two opened and kept; four waited, at most two at once in use.
        assert_eq!(pool.counts(), (2, 2));
        let stats = pool.take_stats();
        assert_eq!((stats.waits, stats.in_use_max), (4, 2));
    }

    #[test]
    fn a_dead_node_fails_at_once_and_holds_no_place() {
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let pool = pool(port, 4);
        let asked = Instant::now();
        let answer = smol::block_on(pool.post("/", b"x", Duration::from_secs(5)));
        assert!(answer.is_err(), "{answer:?}");
        assert!(asked.elapsed() < Duration::from_secs(2));
        assert_eq!(pool.counts(), (0, 0));
    }

    #[test]
    fn a_request_past_its_deadline_is_reaped_and_its_place_freed() {
        let pool = pool(stand_in(Duration::from_secs(3)), 1);
        let answer = smol::block_on(async {
            let reaper = async {
                loop {
                    smol::Timer::after(Duration::from_millis(50)).await;
                    pool.reap();
                }
            };
            smol::future::or(pool.post("/", b"x", Duration::from_millis(200)), reaper).await
        });
        assert_eq!(answer, Err("timed out".into()));
        assert_eq!(pool.counts(), (0, 0));
    }

    /// A node's API over QUIC, as a driver's pool reaches it: one
    /// connection, its requests' answers each the node's.
    #[test]
    fn a_pool_over_quic_reaches_the_nodes_api() {
        use vos_wire::ingress::Rejection;
        let programs = vos_checker::programs::Programs::load();
        let dir = tempfile::tempdir().unwrap();
        let driver = [17u8; 32];
        let node = vos_node::Node::open(dir.path(), vos_node::Config::new(programs.agent.clone()))
            .unwrap();
        let listed = ed25519_dalek::SigningKey::from_bytes(&driver)
            .verifying_key()
            .to_bytes();
        let address = node
            .serve_quic("127.0.0.1:0".parse().unwrap(), vec![listed])
            .unwrap();
        let agent = node.create_agent().unwrap();
        let pool = Pool::quic(&format!("quic://{address}"), node.id().0, driver).unwrap();
        let answers = smol::block_on(async {
            pool.warm().await;
            let within = Duration::from_secs(10);
            let malformed = pool
                .post(&format!("/agents/{}/queries", agent.0), b"x", within)
                .await;
            let absent = pool.post("/agents/99/calls", b"x", within).await;
            (malformed, absent)
        });
        assert_eq!(answers.0, Ok(Response::Rejected(Rejection::Malformed)));
        assert_eq!(answers.1, Ok(Response::Rejected(Rejection::Malformed)));
        assert_eq!(pool.take_stats().in_use_max, 1);
        // Another key is refused at the handshake.
        let stranger = Pool::quic(&format!("quic://{address}"), node.id().0, [18; 32]).unwrap();
        let refused = smol::block_on(stranger.post(
            &format!("/agents/{}/queries", agent.0),
            b"x",
            Duration::from_secs(10),
        ));
        assert!(refused.is_err(), "{refused:?}");
    }

    /// Every future of `futures`, run together on this thread.
    async fn futures_join<F: std::future::Future>(futures: Vec<F>) -> Vec<F::Output> {
        let ex = smol::LocalExecutor::new();
        let tasks: Vec<_> = futures.into_iter().map(|future| ex.spawn(future)).collect();
        ex.run(async {
            let mut outputs = Vec::new();
            for task in tasks {
                outputs.push(task.await);
            }
            outputs
        })
        .await
    }
}
