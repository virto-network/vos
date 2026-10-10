//! A blocking client of a node's ingress: a client key's session, signed
//! calls and queries, and the operator's commands.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use rustls::pki_types::ServerName;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, SessionId};
use vos_wire::ingress::{
    Answer, Call, Create, Grant, Install, NodeId, Open, Opened, QueryCall, call_message,
    open_message, query_message,
};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode};

use crate::tls::{self, Trust};

#[derive(Debug)]
pub enum ClientError {
    Http(String),
    /// The node answered something this client cannot read.
    Undecodable(u16),
    /// The node did not open the session.
    Refused(Answer),
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
        let authority = rest.trim_end_matches('/');
        if authority.is_empty() || authority.contains('/') {
            return Err(invalid("a host and a port, with no path"));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !port.contains(']') => (
                host,
                port.parse::<u16>().map_err(|_| invalid("not a port"))?,
            ),
            _ => (authority, if secure { 443 } else { 80 }),
        };
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
        })
    }

    /// The node at `url`, over plain HTTP on a loopback address.
    pub fn loopback(url: &str) -> Result<Self, ClientError> {
        Self::new(url, Trust::Loopback)
    }
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

/// The node's identity, its key, which its clients sign for. A pinned
/// node must name itself by the key it was pinned by.
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

/// A client key's session on one node.
pub struct Client {
    http: Http,
    key: SigningKey,
    node: NodeId,
    session: SessionId,
    next: HashMap<AgentId, u64>,
}

impl Client {
    /// Open a session for `key` on the node at `base`, signed at `time`
    /// (milliseconds since the Unix epoch, near the node's clock).
    pub fn open(target: &Target, key: SigningKey, time: u64) -> Result<Self, ClientError> {
        let http = Http::new(target);
        let node = fetch_node_id(&http)?;
        let public = key.verifying_key().to_bytes();
        let open = Open {
            key: public,
            time,
            signature: key.sign(&open_message(&node, &public, time)).to_bytes(),
        };
        // Never sent twice: the node refuses an open it has seen.
        let (status, body) = http.post("/sessions", None, &open.encode(), false)?;
        let opened = match Opened::decode(&body) {
            Ok((opened, used)) if status == 200 && used == body.len() => opened,
            _ => return Err(ClientError::Refused(answer(status, &body)?)),
        };
        Ok(Self {
            http,
            key,
            node,
            session: opened.session,
            next: HashMap::new(),
        })
    }

    /// Go on with a session opened before: its node, id, and each agent's
    /// next sequence.
    pub fn resume(
        target: &Target,
        key: SigningKey,
        node: NodeId,
        session: SessionId,
        next: HashMap<AgentId, u64>,
    ) -> Self {
        Self {
            http: Http::new(target),
            key,
            node,
            session,
            next,
        }
    }

    pub fn session(&self) -> SessionId {
        self.session
    }

    pub fn node(&self) -> NodeId {
        self.node
    }

    /// Each agent's next sequence in this session.
    pub fn next(&self) -> &HashMap<AgentId, u64> {
        &self.next
    }

    pub fn principal(&self) -> Principal {
        Principal::Client(self.key.verifying_key().to_bytes())
    }

    /// Call `method` on `agent`'s `instance` with the session's next
    /// sequence for that agent, which moves on only once consumed.
    pub fn call(
        &mut self,
        agent: AgentId,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Answer, ClientError> {
        let sequence = self.next.get(&agent).copied().unwrap_or(1);
        let answer = self.call_at(agent, sequence, instance, method, arguments)?;
        if matches!(answer, Answer::Ran(_)) {
            self.next.insert(agent, sequence + 1);
        }
        Ok(answer)
    }

    /// Call with an explicit `sequence`: to resend one, or to test.
    pub fn call_at(
        &self,
        agent: AgentId,
        sequence: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Answer, ClientError> {
        let body = self.call_body(agent, sequence, instance, method, arguments);
        let path = format!("/agents/{}/calls", agent.0);
        let (status, body) = self.http.post(&path, None, &body, true)?;
        answer(status, &body)
    }

    /// A signed call's body, to send by other means.
    pub fn call_body(
        &self,
        agent: AgentId,
        sequence: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Vec<u8> {
        let message = call_message(
            &self.node,
            agent,
            self.session,
            sequence,
            instance,
            method,
            arguments,
        );
        Call {
            session: self.session,
            sequence,
            instance,
            method,
            arguments: arguments.to_vec(),
            signature: self.key.sign(&message).to_bytes(),
        }
        .encode()
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
        let message = query_message(
            &self.node,
            agent,
            self.session,
            not_after,
            instance,
            method,
            arguments,
        );
        let query = QueryCall {
            session: self.session,
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
