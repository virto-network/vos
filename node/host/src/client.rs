//! A blocking client of a node's ingress: a client key's sessions, signed
//! calls and queries, and the operator's commands.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use rustls::pki_types::ServerName;
use vos_wire::abi::refusal;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use vos_wire::ingress::{
    AgentInfo, Answer, Call, Contact, Create, Grant, Install, NodeId, QueryCall, Rejection,
    call_message, query_message,
};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode};

use crate::tls::{self, Trust};

#[derive(Debug)]
pub enum ClientError {
    Http(String),
    /// The node answered something this client cannot read.
    Undecodable(u16),
    /// The node knows no agent of that id.
    NoAgent,
    /// The node's record of the agent is not the one this client kept.
    OtherAgent,
    /// The node names itself by a key other than the one its TLS showed.
    NotTheNode,
}

/// A node's ingress, and how this client trusts it.
#[derive(Clone)]
pub struct Target {
    /// The `host:port` to connect to, which is also the `Host` header.
    authority: String,
    /// Where a plain target connects: loopback addresses, never a name a
    /// resolver could answer for.
    loopback: Option<Vec<SocketAddr>>,
    tls: Option<(Arc<rustls::ClientConfig>, ServerName<'static>)>,
    /// The node's key, when pinned.
    key: Option<[u8; 32]>,
    /// How the client trusts it, which the nodes it is sent on to inherit.
    trust: Trust,
}

impl Target {
    /// The node at `url` (`http://` or `https://`, then a host and an
    /// optional port), trusted as `trust` says. Plain HTTP reaches
    /// loopback addresses only, and HTTPS needs a key or a CA to trust.
    pub fn new(url: &str, trust: Trust) -> Result<Self, ClientError> {
        let invalid = |why: &str| ClientError::Http(format!("{url}: {why}"));
        let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(invalid("not an http:// or https:// address"));
        };
        let (host, port) = host_and_port(rest, secure).map_err(invalid)?;
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let mut loopback = None;
        let tls = match (secure, &trust) {
            (false, Trust::Loopback) => {
                let addresses: Vec<IpAddr> = if bare == "localhost" {
                    vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()]
                } else {
                    match bare.parse::<IpAddr>() {
                        Ok(address) if address.is_loopback() => vec![address],
                        _ => return Err(invalid("plain HTTP reaches loopback addresses only")),
                    }
                };
                loopback = Some(
                    addresses
                        .into_iter()
                        .map(|address| SocketAddr::new(address, port))
                        .collect(),
                );
                None
            }
            (false, _) => return Err(invalid("a key or a CA to trust needs https://")),
            (true, Trust::Loopback) => {
                return Err(invalid("https:// needs a key or a CA to trust"));
            }
            (true, trust) => {
                let config = tls::client_config(trust)
                    .map_err(ClientError::Http)?
                    .expect("TLS for a key or a CA");
                let name = match (ServerName::try_from(bare.to_string()), trust) {
                    (Ok(name), _) => name,
                    // A pinned key does not need the name, which only
                    // goes in the handshake.
                    (Err(_), Trust::NodeKey(_)) => ServerName::try_from("node.vos")
                        .expect("a host name")
                        .to_owned(),
                    (Err(_), _) => return Err(invalid("not a host name or an address")),
                };
                Some((config, name))
            }
        };
        Ok(Self {
            authority: format!("{host}:{port}"),
            loopback,
            tls,
            key: match trust {
                Trust::NodeKey(key) => Some(key),
                _ => None,
            },
            trust,
        })
    }

    /// The node at `url`, over plain HTTP on a loopback address.
    pub fn loopback(url: &str) -> Result<Self, ClientError> {
        Self::new(url, Trust::Loopback)
    }
}

/// The host and port of an address's authority (`rest`, after its
/// scheme), the scheme's port when it gives none.
fn host_and_port(rest: &str, secure: bool) -> Result<(&str, u16), &'static str> {
    let authority = rest.trim_end_matches('/');
    if authority.is_empty() || authority.contains('/') {
        return Err("a host and a port, with no path");
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.contains(']') => {
            Ok((host, port.parse::<u16>().map_err(|_| "not a port")?))
        }
        _ => Ok((authority, if secure { 443 } else { 80 })),
    }
}

/// `host:port` for an `http://` or `https://` address, as a target holds
/// it.
fn authority(url: &str) -> Option<String> {
    let (secure, rest) = match url.split_once("://")? {
        ("https", rest) => (true, rest),
        ("http", rest) => (false, rest),
        _ => return None,
    };
    let (host, port) = host_and_port(rest, secure).ok()?;
    Some(format!("{host}:{port}"))
}

/// A connection is used again only if it was idle less than this long,
/// well within the node's idle limit.
const REUSE: Duration = Duration::from_secs(20);
const CONNECT: Duration = Duration::from_secs(10);
/// A request's answer may take this long: an install prepares a program.
const ANSWER: Duration = Duration::from_secs(300);
/// The largest answer taken: a schema, a reply, a refusal.
const MAX_ANSWER: usize = 16 << 20;

trait Stream: Read + Write + Send {}

impl<T: Read + Write + Send> Stream for T {}

struct Connection {
    stream: Box<dyn Stream>,
    /// Bytes read past the last answer.
    buffer: Vec<u8>,
    used: Instant,
}

/// Idle connections kept open to one node.
const IDLE_CONNECTIONS: usize = 4;

/// HTTP/1.1 to one node, keeping connections open between requests.
/// Requests may go at once, each on a connection of its own.
struct Http {
    target: Target,
    idle: Mutex<Vec<Connection>>,
}

impl Http {
    fn new(target: &Target) -> Self {
        Self {
            target: target.clone(),
            idle: Mutex::new(Vec::new()),
        }
    }

    /// An idle connection still fresh enough, or a new one, and whether
    /// it was kept.
    fn connection(&self) -> std::io::Result<(Connection, bool)> {
        let fresh = {
            let mut idle = self.idle.lock().expect("the idle connections");
            idle.retain(|connection| connection.used.elapsed() < REUSE);
            idle.pop()
        };
        match fresh {
            Some(connection) => Ok((connection, true)),
            None => Ok((self.connect()?, false)),
        }
    }

    fn keep(&self, mut connection: Connection) {
        connection.used = Instant::now();
        let mut idle = self.idle.lock().expect("the idle connections");
        if idle.len() < IDLE_CONNECTIONS {
            idle.push(connection);
        }
    }

    fn connect(&self) -> std::io::Result<Connection> {
        let addresses: Vec<SocketAddr> = match &self.target.loopback {
            Some(addresses) => addresses.clone(),
            None => self.target.authority.to_socket_addrs()?.collect(),
        };
        let mut last = None;
        let mut tcp = None;
        for address in addresses {
            match TcpStream::connect_timeout(&address, CONNECT) {
                Ok(stream) => {
                    tcp = Some(stream);
                    break;
                }
                Err(error) => last = Some(error),
            }
        }
        let tcp = tcp.ok_or_else(|| {
            last.unwrap_or_else(|| std::io::Error::other("the host has no address"))
        })?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(CONNECT))?;
        tcp.set_write_timeout(Some(CONNECT))?;
        let stream: Box<dyn Stream> = match &self.target.tls {
            Some((config, name)) => {
                let tls = rustls::ClientConnection::new(Arc::clone(config), name.clone())
                    .map_err(std::io::Error::other)?;
                let mut stream = rustls::StreamOwned::new(tls, tcp);
                // Handshake now, within the connect timeout, so a wrong key
                // or a stalled node fails here, not mid-request.
                while stream.conn.is_handshaking() {
                    stream.conn.complete_io(&mut stream.sock)?;
                }
                stream.sock.set_read_timeout(Some(ANSWER))?;
                stream.sock.set_write_timeout(Some(ANSWER))?;
                Box::new(stream)
            }
            None => {
                tcp.set_read_timeout(Some(ANSWER))?;
                tcp.set_write_timeout(Some(ANSWER))?;
                Box::new(tcp)
            }
        };
        Ok(Connection {
            stream,
            buffer: Vec::new(),
            used: Instant::now(),
        })
    }

    /// Send a request and read its answer. `repeatable` says the node
    /// takes it twice as once (a read, or a signed call or query, which
    /// the node deduplicates): such a request that fails on a kept
    /// connection before any answer arrives is sent once more on a new
    /// one. The node likely restarted, so no kept connection is used.
    fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: &[u8],
        repeatable: bool,
    ) -> Result<(u16, Vec<u8>), ClientError> {
        let failed = |error: std::io::Error| ClientError::Http(error.to_string());
        let authorization = token.map_or(String::new(), |token| {
            format!("Authorization: Bearer {token}\r\n")
        });
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n{authorization}\r\n",
            self.target.authority,
            body.len(),
        );
        let (mut connection, kept) = self.connection().map_err(failed)?;
        let (status, body, close) = match exchange(&mut connection, head.as_bytes(), body) {
            Ok(answer) => answer,
            Err((_, false)) if kept && repeatable => {
                self.idle.lock().expect("the idle connections").clear();
                connection = self.connect().map_err(failed)?;
                exchange(&mut connection, head.as_bytes(), body)
                    .map_err(|(error, _)| failed(error))?
            }
            Err((error, _)) => return Err(failed(error)),
        };
        if !close {
            self.keep(connection);
        }
        Ok((status, body))
    }

    fn get(&self, path: &str) -> Result<(u16, Vec<u8>), ClientError> {
        self.request("GET", path, None, &[], true)
    }

    fn post(
        &self,
        path: &str,
        token: Option<&str>,
        body: &[u8],
        repeatable: bool,
    ) -> Result<(u16, Vec<u8>), ClientError> {
        self.request("POST", path, token, body, repeatable)
    }
}

/// Write a request and read its answer: the status, the body, and whether
/// the node closes the connection after it. On failure, whether any of
/// the answer had arrived.
fn exchange(
    connection: &mut Connection,
    head: &[u8],
    body: &[u8],
) -> Result<(u16, Vec<u8>, bool), (std::io::Error, bool)> {
    connection
        .stream
        .write_all(head)
        .and_then(|()| connection.stream.write_all(body))
        .and_then(|()| connection.stream.flush())
        .map_err(|error| (error, false))?;
    read_answer(connection).map_err(|error| {
        let answered = !connection.buffer.is_empty();
        (error, answered)
    })
}

/// The next answer on `connection`: its status, its body, and whether the
/// node closes the connection after it.
fn read_answer(connection: &mut Connection) -> std::io::Result<(u16, Vec<u8>, bool)> {
    let invalid = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, why.to_string());
    let mut chunk = [0u8; 8192];
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut answer = httparse::Response::new(&mut headers);
        match answer.parse(&connection.buffer) {
            Ok(httparse::Status::Complete(head)) => {
                let status = answer.code.unwrap_or(0);
                let header = |name: &str| {
                    answer
                        .headers
                        .iter()
                        .find(|header| header.name.eq_ignore_ascii_case(name))
                        .map(|header| header.value)
                };
                let length = header("content-length")
                    .and_then(|value| std::str::from_utf8(value).ok())
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .ok_or_else(|| invalid("an answer without a length"))?;
                if length > MAX_ANSWER {
                    return Err(invalid("an answer larger than any the node gives"));
                }
                let close =
                    header("connection").is_some_and(|value| value.eq_ignore_ascii_case(b"close"));
                while connection.buffer.len() < head + length {
                    let read = connection.stream.read(&mut chunk)?;
                    if read == 0 {
                        return Err(invalid("the answer ended early"));
                    }
                    connection.buffer.extend_from_slice(&chunk[..read]);
                }
                let body = connection.buffer[head..head + length].to_vec();
                connection.buffer.drain(..head + length);
                return Ok((status, body, close));
            }
            Ok(httparse::Status::Partial) => {
                if connection.buffer.len() > 16 << 10 {
                    return Err(invalid("an answer's head too large"));
                }
                let read = connection.stream.read(&mut chunk)?;
                if read == 0 {
                    return Err(invalid("the connection closed"));
                }
                connection.buffer.extend_from_slice(&chunk[..read]);
            }
            Err(_) => return Err(invalid("an answer that is not HTTP")),
        }
    }
}

fn answer(status: u16, body: &[u8]) -> Result<Answer, ClientError> {
    Answer::decode(body)
        .map(|(answer, _)| answer)
        .map_err(|_| ClientError::Undecodable(status))
}

/// POST `body` to `path`: the status and body answered. For requests this
/// client does not otherwise make, as a test of the ingress does.
pub fn post(target: &Target, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), ClientError> {
    Http::new(target).post(path, None, body, false)
}

/// The node's identity, its key, which its TLS presents. A pinned node
/// must name itself by the key it was pinned by.
pub fn node_id(target: &Target) -> Result<NodeId, ClientError> {
    fetch_node_id(&Http::new(target))
}

fn fetch_node_id(http: &Http) -> Result<NodeId, ClientError> {
    let (status, body) = http.get("/")?;
    let id = NodeId::decode(&body)
        .map(|(id, _)| id)
        .map_err(|_| ClientError::Undecodable(status))?;
    match http.target.key {
        Some(key) if key != id.0 => Err(ClientError::NotTheNode),
        _ => Ok(id),
    }
}

/// Agent `agent`'s creation record and replicas, as the node knows them:
/// `None` when it knows no such agent.
pub fn agent_info(target: &Target, agent: AgentId) -> Result<Option<AgentInfo>, ClientError> {
    agent_info_from(&Http::new(target), agent)
}

fn agent_info_from(http: &Http, agent: AgentId) -> Result<Option<AgentInfo>, ClientError> {
    let (status, body) = http.get(&format!("/agents/{}", agent.0))?;
    if status == 404 {
        return Ok(None);
    }
    match AgentInfo::decode(&body) {
        Ok((info, _)) if info.record.agent == agent => Ok(Some(info)),
        _ => Err(ClientError::Undecodable(status)),
    }
}

/// One agent's session as its client keeps it: the session's name and
/// creation time, and the next sequence to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kept {
    pub name: [u8; 16],
    pub t0: u64,
    pub next: u64,
}

/// Redirects a call follows before it answers what the last node said.
const REDIRECTS: usize = 4;
/// Times a call goes to another replica, after a failure, before it
/// answers the last.
const FAILOVERS: usize = 6;
/// The first wait after `Busy`, doubled each time up to [`MAX_BUSY`].
const BUSY: Duration = Duration::from_millis(50);
const MAX_BUSY: Duration = Duration::from_secs(1);
/// New sessions a call starts before it answers the refusal: one when the
/// agent refuses a session for good, and one more when the client's clock
/// is off the agent's time.
const RENEWALS: usize = 2;

/// A client key, calling each agent in a session of its own.
///
/// A session goes on until the agent refuses it for good (expired, or
/// started too far from the agent's time): only then does the client start
/// another. After an error the call may have run or not: call again with
/// the same request, which goes with the same sequence, and the agent runs
/// it once.
pub struct Client {
    http: Http,
    key: SigningKey,
    sessions: Mutex<HashMap<AgentId, Kept>>,
    identities: Mutex<HashMap<AgentId, [u8; 32]>>,
    /// Each agent's replicas, learned with its identity.
    replicas: Mutex<HashMap<AgentId, Vec<Contact>>>,
    /// Agents whose next call repeats one whose fate is unknown.
    unknown: Mutex<std::collections::HashSet<AgentId>>,
    /// How far the agents' time is ahead of this client's clock, as a
    /// node last reported it: a new session starts at that time.
    offset: Mutex<i64>,
}

impl Client {
    /// A client for `key` calling the node at `target`.
    pub fn new(target: &Target, key: SigningKey) -> Self {
        Self::resume(target, key, HashMap::new(), HashMap::new())
    }

    /// A client going on with the sessions it kept, and the agents'
    /// identities it learned.
    pub fn resume(
        target: &Target,
        key: SigningKey,
        sessions: HashMap<AgentId, Kept>,
        identities: HashMap<AgentId, [u8; 32]>,
    ) -> Self {
        Self {
            http: Http::new(target),
            key,
            sessions: Mutex::new(sessions),
            identities: Mutex::new(identities),
            replicas: Mutex::new(HashMap::new()),
            unknown: Mutex::new(std::collections::HashSet::new()),
            offset: Mutex::new(0),
        }
    }

    /// Each agent's session, to keep.
    pub fn sessions(&self) -> HashMap<AgentId, Kept> {
        self.sessions.lock().expect("the sessions").clone()
    }

    /// Each agent's identity learned, to keep.
    pub fn identities(&self) -> HashMap<AgentId, [u8; 32]> {
        self.identities.lock().expect("the identities").clone()
    }

    /// Say that the next call to `agent` repeats one whose fate is unknown,
    /// made lately, as a process that kept it pending can: a refusal saying
    /// it never ran then proves nothing, while copies of the earlier one
    /// may still be on their way.
    pub fn repeats_unknown(&self, agent: AgentId) {
        self.unknown
            .lock()
            .expect("the unknown calls")
            .insert(agent);
    }

    /// The node this client calls: the one it was given, or the last a
    /// redirect named.
    pub fn target(&self) -> &Target {
        &self.http.target
    }

    pub fn principal(&self) -> Principal {
        Principal::Client(self.key.verifying_key().to_bytes())
    }

    /// The session this client calls `agent` in, started if there is none.
    pub fn session(&self, agent: AgentId) -> Session {
        let kept = *self
            .sessions
            .lock()
            .expect("the sessions")
            .entry(agent)
            .or_insert_with(|| self.start());
        self.whole(kept)
    }

    /// Start another session for `agent`: the one before is done with.
    pub fn renew(&self, agent: AgentId) {
        let kept = self.start();
        self.sessions
            .lock()
            .expect("the sessions")
            .insert(agent, kept);
    }

    fn start(&self) -> Kept {
        let mut name = [0u8; 16];
        getrandom::getrandom(&mut name).expect("the operating system's randomness");
        let offset = *self.offset.lock().expect("the offset");
        let t0 = crate::wall_clock().saturating_add_signed(offset);
        Kept { name, t0, next: 1 }
    }

    fn whole(&self, kept: Kept) -> Session {
        Session {
            key: self.key.verifying_key().to_bytes(),
            name: kept.name,
            t0: kept.t0,
        }
    }

    /// The identity of `agent`, which calls to it are signed for: the hash
    /// of its creation record, fetched from the node once, with the agent's
    /// replicas.
    pub fn identity(&self, agent: AgentId) -> Result<[u8; 32], ClientError> {
        if let Some(identity) = self.identities.lock().expect("the identities").get(&agent) {
            return Ok(*identity);
        }
        self.learn(agent)
    }

    /// Fetch `agent`'s record and replicas from the node. An identity kept
    /// from before stands: a node that names another is refused.
    fn learn(&self, agent: AgentId) -> Result<[u8; 32], ClientError> {
        let info = agent_info_from(&self.http, agent)?.ok_or(ClientError::NoAgent)?;
        let identity = crate::identity(&info.record);
        let kept = *self
            .identities
            .lock()
            .expect("the identities")
            .entry(agent)
            .or_insert(identity);
        if kept != identity {
            return Err(ClientError::OtherAgent);
        }
        self.replicas
            .lock()
            .expect("the replicas")
            .insert(agent, info.replicas);
        Ok(identity)
    }

    /// Call the replica of `agent` after the one this client calls: false
    /// when it knows no other.
    fn fail_over(&mut self, agent: AgentId) -> Result<bool, ClientError> {
        // An identity kept from before comes without the replicas.
        if !self
            .replicas
            .lock()
            .expect("the replicas")
            .contains_key(&agent)
        {
            let _ = self.learn(agent);
        }
        let replicas = self
            .replicas
            .lock()
            .expect("the replicas")
            .get(&agent)
            .cloned()
            .unwrap_or_default();
        let current = Some(self.http.target.authority.clone());
        let at = replicas
            .iter()
            .position(|replica| authority(&replica.address) == current);
        let next = match at {
            Some(at) if replicas.len() > 1 => &replicas[(at + 1) % replicas.len()],
            None if !replicas.is_empty() => &replicas[0],
            _ => return Ok(false),
        };
        self.follow(&next.clone())?;
        Ok(true)
    }

    /// Call `method` on `agent`'s `instance`, at the session's next
    /// sequence for that agent, which moves on only once consumed.
    ///
    /// Any replica takes the call. On a failure, or an answer that leaves
    /// it unknown whether the call ran, the call goes to the next replica
    /// with the same sequence; on `Busy`, again after a wait. Redirects are
    /// followed, and a new session is started when the agent refuses this
    /// one for good.
    pub fn call(
        &mut self,
        agent: AgentId,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Answer, ClientError> {
        // Learn the replicas first: the node may be gone when a failover
        // needs them.
        if !self
            .replicas
            .lock()
            .expect("the replicas")
            .contains_key(&agent)
        {
            let _ = self.learn(agent);
        }
        let mut redirects = 0;
        let mut renewals = 0;
        let mut failovers = 0;
        let mut busy = BUSY;
        // An attempt that may have run, or may yet: later refusals that
        // say it never ran no longer prove it for the call.
        let mut inconclusive = self
            .unknown
            .lock()
            .expect("the unknown calls")
            .remove(&agent);
        loop {
            self.session(agent);
            let sequence = self.sessions.lock().expect("the sessions")[&agent].next;
            let answer = match self.call_at(agent, sequence, instance, method, arguments) {
                Ok(answer) => answer,
                Err(error) => {
                    inconclusive = true;
                    if failovers < FAILOVERS && self.fail_over(agent).unwrap_or(false) {
                        failovers += 1;
                        continue;
                    }
                    return Err(error);
                }
            };
            match &answer {
                Answer::Ran { .. } => {
                    if let Some(kept) = self.sessions.lock().expect("the sessions").get_mut(&agent)
                    {
                        kept.next = sequence + 1;
                    }
                    return Ok(answer);
                }
                Answer::NotLeader {
                    leader: Some(leader),
                } if redirects < REDIRECTS => {
                    redirects += 1;
                    self.follow(leader)?;
                }
                Answer::Elsewhere { replicas } if redirects < REDIRECTS && !replicas.is_empty() => {
                    redirects += 1;
                    self.follow(&replicas[(redirects - 1) % replicas.len()])?;
                }
                // An earlier attempt may still run in this session, at a
                // replica forwarding it: a new session could run it twice.
                Answer::Rejected(Rejection::StaleSession { .. }) if inconclusive => {
                    return Ok(Answer::TimedOut);
                }
                // Not consumed: the same request goes again in a new session.
                Answer::Rejected(Rejection::StaleSession { now }) if renewals < RENEWALS => {
                    renewals += 1;
                    let offset = i128::from(*now) - i128::from(crate::wall_clock());
                    *self.offset.lock().expect("the offset") =
                        offset.clamp(i64::MIN.into(), i64::MAX.into()) as i64;
                    self.renew(agent);
                }
                Answer::Refused(refusal::EXPIRED | refusal::STALE_SESSION)
                    if renewals < RENEWALS =>
                {
                    renewals += 1;
                    self.renew(agent);
                }
                Answer::Stopped
                | Answer::Unavailable
                | Answer::TimedOut
                | Answer::NotLeader { leader: None }
                    if failovers < FAILOVERS =>
                {
                    inconclusive = true;
                    failovers += 1;
                    let _ = self.fail_over(agent);
                }
                // Every replica forwards to the same leader: wait.
                Answer::Busy if failovers < FAILOVERS => {
                    failovers += 1;
                    std::thread::sleep(busy);
                    busy = (busy * 2).min(MAX_BUSY);
                }
                // Busy, or a failure of this attempt, says nothing of an
                // earlier one.
                Answer::Busy | Answer::NotConsumed if inconclusive => {
                    return Ok(Answer::TimedOut);
                }
                _ => return Ok(answer),
            }
        }
    }

    /// Call the node `contact` names from now on, trusted as this client
    /// trusts nodes: by the same CAs, or pinned by the key the redirecting
    /// node gave, as this client already trusts what that node says.
    fn follow(&mut self, contact: &Contact) -> Result<(), ClientError> {
        let trust = match &self.http.target.trust {
            Trust::Ca(roots) => Trust::Ca(roots.clone()),
            Trust::NodeKey(_) | Trust::Loopback if contact.address.starts_with("https://") => {
                Trust::NodeKey(contact.node.0)
            }
            Trust::NodeKey(_) | Trust::Loopback => Trust::Loopback,
        };
        self.http = Http::new(&Target::new(&contact.address, trust)?);
        Ok(())
    }

    /// Call with an explicit `sequence` in the agent's session: to resend
    /// one, or to test.
    pub fn call_at(
        &self,
        agent: AgentId,
        sequence: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Answer, ClientError> {
        let body = self.call_body(agent, sequence, instance, method, arguments)?;
        let path = format!("/agents/{}/calls", agent.0);
        let (status, body) = self.http.post(&path, None, &body, true)?;
        answer(status, &body)
    }

    /// A signed call's body in the agent's session, to send by other means.
    pub fn call_body(
        &self,
        agent: AgentId,
        sequence: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let identity = self.identity(agent)?;
        let session = self.session(agent);
        let message = call_message(&identity, &session, sequence, instance, method, arguments);
        Ok(Call {
            session,
            sequence,
            instance,
            method,
            arguments: arguments.to_vec(),
            signature: self.key.sign(&message).to_bytes(),
        }
        .encode())
    }

    /// Run query `method` on `agent`'s `instance`, good until `not_after`.
    pub fn query(
        &self,
        agent: AgentId,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
        not_after: u64,
    ) -> Result<Answer, ClientError> {
        let identity = self.identity(agent)?;
        let key = self.key.verifying_key().to_bytes();
        let message = query_message(&identity, &key, not_after, instance, method, arguments);
        let query = QueryCall {
            key,
            not_after,
            instance,
            method,
            arguments: arguments.to_vec(),
            signature: self.key.sign(&message).to_bytes(),
        };
        let path = format!("/agents/{}/queries", agent.0);
        let (status, body) = self.http.post(&path, None, &query.encode(), true)?;
        answer(status, &body)
    }

    /// The schema installed as `agent`'s `instance`.
    pub fn schema(
        &self,
        agent: AgentId,
        instance: InstanceId,
    ) -> Result<Option<Schema>, ClientError> {
        schema_from(&self.http, agent, instance)
    }
}

/// The schema installed as `agent`'s `instance`, if any.
pub fn schema(
    target: &Target,
    agent: AgentId,
    instance: InstanceId,
) -> Result<Option<Schema>, ClientError> {
    schema_from(&Http::new(target), agent, instance)
}

fn schema_from(
    http: &Http,
    agent: AgentId,
    instance: InstanceId,
) -> Result<Option<Schema>, ClientError> {
    let path = format!("/agents/{}/instances/{}/schema", agent.0, instance.0);
    let (status, body) = http.get(&path)?;
    if status == 404 {
        return Ok(None);
    }
    Schema::decode(&body)
        .map(|(schema, _)| Some(schema))
        .map_err(|_| ClientError::Undecodable(status))
}

/// The node's operator, by its admin token.
pub struct Operator {
    token: String,
    http: Http,
}

impl Operator {
    pub fn new(target: &Target, token: &str) -> Self {
        Self {
            token: token.trim().to_string(),
            http: Http::new(target),
        }
    }

    fn post(&self, path: &str, body: &[u8]) -> Result<Answer, ClientError> {
        // An operator's command may not be idempotent: never sent twice.
        let (status, body) = self.http.post(path, Some(&self.token), body, false)?;
        answer(status, &body)
    }

    /// Create an agent replicated on `replicas` (the node alone when
    /// empty).
    pub fn create_agent(&self, replicas: Vec<u8>) -> Result<Answer, ClientError> {
        if replicas.is_empty() {
            return self.post("/agents", &[]);
        }
        self.post("/agents", &Create { replicas }.encode())
    }

    pub fn install(&self, agent: AgentId, install: &Install) -> Result<Answer, ClientError> {
        self.post(&format!("/agents/{}/install", agent.0), &install.encode())
    }

    pub fn grant(
        &self,
        agent: AgentId,
        principal: Principal,
        role: Option<u8>,
    ) -> Result<Answer, ClientError> {
        let grant = Grant { principal, role };
        self.post(&format!("/agents/{}/roles", agent.0), &grant.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::authority;

    /// A replica's address matches the target made from it, the scheme's
    /// port written or not.
    #[test]
    fn an_address_s_authority_is_its_host_and_port() {
        assert_eq!(
            authority("https://n1.example").as_deref(),
            Some("n1.example:443")
        );
        assert_eq!(
            authority("https://n1.example/").as_deref(),
            Some("n1.example:443")
        );
        assert_eq!(
            authority("http://127.0.0.1:7700").as_deref(),
            Some("127.0.0.1:7700")
        );
        assert_eq!(authority("http://[::1]").as_deref(), Some("[::1]:80"));
        assert_eq!(authority("ftp://n1.example"), None);
        assert_eq!(authority("https://n1.example/path"), None);
    }
}
