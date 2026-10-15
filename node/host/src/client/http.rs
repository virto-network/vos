//! HTTP/1.1 to one node, over kept connections, plain or in TLS.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{ClientError, Target};
use crate::http::{MAX_HEAD, content_length};
use crate::lock;

/// A connection is used again only if it was idle less than this long,
/// well within the node's idle limit.
const REUSE: Duration = Duration::from_secs(20);
const CONNECT: Duration = Duration::from_secs(10);
/// A request's answer may take this long: an install prepares a program.
const ANSWER: Duration = Duration::from_secs(300);
/// The largest answer taken: a schema, a reply, a refusal.
const MAX_ANSWER: usize = 16 << 20;
/// The largest request body sent in one write with its head.
const ONE_WRITE: usize = 64 << 10;

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
pub(super) struct Http {
    pub(super) target: Target,
    idle: Mutex<Vec<Connection>>,
    /// How long a request's answer may take.
    answer: Duration,
}

impl Http {
    pub(super) fn new(target: &Target) -> Self {
        Self::within(target, ANSWER)
    }

    /// One whose requests are answered within `answer`, connecting within
    /// it too.
    pub(super) fn within(target: &Target, answer: Duration) -> Self {
        Self {
            target: target.clone(),
            idle: Mutex::new(Vec::new()),
            answer,
        }
    }

    /// An idle connection still fresh enough, or a new one, and whether
    /// it was kept.
    fn connection(&self) -> std::io::Result<(Connection, bool)> {
        let fresh = {
            let mut idle = lock(&self.idle);
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
        let mut idle = lock(&self.idle);
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
        let connect = CONNECT.min(self.answer);
        for address in addresses {
            match TcpStream::connect_timeout(&address, connect) {
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
        tcp.set_read_timeout(Some(connect))?;
        tcp.set_write_timeout(Some(connect))?;
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
                stream.sock.set_read_timeout(Some(self.answer))?;
                stream.sock.set_write_timeout(Some(self.answer))?;
                Box::new(stream)
            }
            None => {
                tcp.set_read_timeout(Some(self.answer))?;
                tcp.set_write_timeout(Some(self.answer))?;
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
                lock(&self.idle).clear();
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

    /// A read, by the operator when `token` is theirs.
    pub(super) fn get(
        &self,
        path: &str,
        token: Option<&str>,
    ) -> Result<(u16, Vec<u8>), ClientError> {
        self.request("GET", path, token, &[], true)
    }

    /// A request the node may not take twice as once: never sent again.
    pub(super) fn post_once(
        &self,
        path: &str,
        token: Option<&str>,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), ClientError> {
        self.request("POST", path, token, body, false)
    }

    /// A request the node takes twice as once: a signed call or read.
    pub(super) fn post_repeatable(
        &self,
        path: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), ClientError> {
        self.request("POST", path, None, body, true)
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
    // A small request in one write, so it wakes the node once; a large one
    // (an install) is not copied for it.
    let written = if body.len() <= ONE_WRITE {
        let mut request = Vec::with_capacity(head.len() + body.len());
        request.extend_from_slice(head);
        request.extend_from_slice(body);
        connection.stream.write_all(&request)
    } else {
        connection
            .stream
            .write_all(head)
            .and_then(|()| connection.stream.write_all(body))
    };
    written
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
                    .and_then(content_length)
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
                if connection.buffer.len() > MAX_HEAD {
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
