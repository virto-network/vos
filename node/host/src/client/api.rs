//! The node API as a blocking client's transport: HTTP's requests
//! translated by the gateway's route table into frames, over the node's
//! unix socket or QUIC, and the answers translated back. A client then
//! speaks one interface, whichever transport its target names.

use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use vos_api::{Framing, MAX_ANSWER, Operated, frame};
use vos_http::routes::{self, Authorization, Routed};
use vos_wire::Encode;

use super::target::Api as Way;
use super::{ClientError, Target};
use crate::lock;

/// Idle socket connections kept to one node.
const IDLE_CONNECTIONS: usize = 4;
const CONNECT: Duration = Duration::from_secs(10);

/// A node API's QUIC connection, and the endpoint it runs on.
struct Dialed {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

/// The node API, reached as a target says.
pub(super) struct Api {
    pub(super) target: Target,
    way: ApiWay,
    /// How long a request's answer may take.
    answer: Duration,
    next: AtomicU64,
}

enum ApiWay {
    Socket {
        path: PathBuf,
        idle: Mutex<Vec<UnixStream>>,
    },
    Quic {
        client: [u8; 32],
        dialed: Mutex<Option<Dialed>>,
    },
}

impl Api {
    pub(super) fn new(target: &Target, answer: Duration) -> Self {
        let way = match target.api.as_ref().expect("an API target") {
            Way::Socket(path) => ApiWay::Socket {
                path: path.clone(),
                idle: Mutex::new(Vec::new()),
            },
            Way::Quic { client } => ApiWay::Quic {
                client: *client,
                dialed: Mutex::new(None),
            },
        };
        Self {
            target: target.clone(),
            way,
            answer,
            next: AtomicU64::new(1),
        }
    }

    /// An HTTP request as the gateway translates it: its status and body.
    /// A route the table answers with no node is answered here.
    pub(super) fn request(
        &self,
        method: &str,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
        repeatable: bool,
    ) -> Result<(u16, Vec<u8>), ClientError> {
        let request = vos_http::Request {
            method: method.to_string(),
            path: path.to_string(),
            headers: authorization
                .map(|value| ("authorization".to_string(), value.as_bytes().to_vec()))
                .into_iter()
                .collect(),
            body: body.to_vec(),
            peer: None,
            large: None,
        };
        let (kind, body) = match routes::route(&request) {
            Routed::Answer(answer) => return Ok((answer.status, answer.body)),
            Routed::Request { kind, body } => (kind, body),
            Routed::Operator {
                authorization,
                kind,
                inner,
            } => {
                let Authorization::Operated(credentials) = authorization else {
                    return Err(ClientError::Http(
                        "the node API takes a signed operator request, not a token".into(),
                    ));
                };
                match inner {
                    Ok(inner) => (
                        kind,
                        Operated::with_credentials(&credentials, inner).encode(),
                    ),
                    Err(answer) => return Ok((answer.status, answer.body)),
                }
            }
        };
        let (answered, bytes) = self.exchange(kind as u16, &body, repeatable)?;
        let answer = routes::answer(answered, &bytes);
        Ok((answer.status, answer.body))
    }

    /// A frame of `kind` holding `body`, and its answer frame's kind and
    /// body. A request the node takes twice as once is sent once more on a
    /// new connection when the kept one failed before any answer.
    fn exchange(
        &self,
        kind: u16,
        body: &[u8],
        repeatable: bool,
    ) -> Result<(u16, Vec<u8>), ClientError> {
        let failed = |error: std::io::Error| ClientError::Http(error.to_string());
        match &self.way {
            ApiWay::Socket { path, idle } => {
                let kept = lock(idle).pop();
                let (mut stream, was_kept) = match kept {
                    Some(stream) => (stream, true),
                    None => (self.connect(path).map_err(failed)?, false),
                };
                let id = self.next.fetch_add(1, Ordering::Relaxed);
                let answered = match socket_exchange(&mut stream, kind, id, body) {
                    Ok(answered) => answered,
                    Err((_, false)) if was_kept && repeatable => {
                        lock(idle).clear();
                        stream = self.connect(path).map_err(failed)?;
                        socket_exchange(&mut stream, kind, id, body)
                            .map_err(|(error, _)| failed(error))?
                    }
                    Err((error, _)) => return Err(failed(error)),
                };
                let mut idle = lock(idle);
                if idle.len() < IDLE_CONNECTIONS {
                    idle.push(stream);
                }
                Ok(answered)
            }
            ApiWay::Quic { client, dialed } => {
                let first = self.quic_exchange(client, dialed, kind, body);
                match first {
                    Err(_) if repeatable => {
                        *lock(dialed) = None;
                        self.quic_exchange(client, dialed, kind, body)
                    }
                    answered => answered,
                }
            }
        }
    }

    fn connect(&self, path: &PathBuf) -> std::io::Result<UnixStream> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(self.answer))?;
        stream.set_write_timeout(Some(self.answer))?;
        Ok(stream)
    }

    fn quic_exchange(
        &self,
        client: &[u8; 32],
        dialed: &Mutex<Option<Dialed>>,
        kind: u16,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), ClientError> {
        let connection = {
            let mut dialed = lock(dialed);
            match dialed.as_ref() {
                Some(kept) if kept.connection.close_reason().is_none() => kept.connection.clone(),
                _ => {
                    let fresh = self.dial(client)?;
                    let connection = fresh.connection.clone();
                    *dialed = Some(fresh);
                    connection
                }
            }
        };
        let asked = vos_api::quic::request(&connection, kind, body);
        match smol::block_on(crate::timeout(self.answer, asked)) {
            Some(Ok(answered)) => Ok(answered),
            Some(Err(error)) => Err(ClientError::Http(error.to_string())),
            None => Err(ClientError::Http("no answer in time".into())),
        }
    }

    fn dial(&self, client: &[u8; 32]) -> Result<Dialed, ClientError> {
        let failed = |why: String| ClientError::Http(format!("{}: {why}", self.target.authority));
        let crate::tls::Trust::NodeKey(node) = self.target.trust else {
            return Err(failed("a QUIC target pins its node's key".into()));
        };
        let address: SocketAddr = self
            .target
            .authority
            .to_socket_addrs()
            .map_err(|error| failed(error.to_string()))?
            .next()
            .ok_or_else(|| failed("no address".into()))?;
        let bind: SocketAddr = if address.is_ipv4() {
            "0.0.0.0:0".parse().expect("an address")
        } else {
            "[::]:0".parse().expect("an address")
        };
        let socket = UdpSocket::bind(bind).map_err(|error| failed(error.to_string()))?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::SmolRuntime),
        )
        .map_err(|error| failed(error.to_string()))?;
        let config =
            vos_net::api::client_config(client, node, Arc::new(quinn::TransportConfig::default()));
        let connecting = endpoint
            .connect_with(config, address, "node.vos")
            .map_err(|error| failed(error.to_string()))?;
        let connection = match smol::block_on(crate::timeout(CONNECT.min(self.answer), connecting))
        {
            Some(Ok(connection)) => connection,
            Some(Err(error)) => return Err(failed(error.to_string())),
            None => return Err(failed("no handshake in time".into())),
        };
        Ok(Dialed {
            _endpoint: endpoint,
            connection,
        })
    }
}

/// Write a frame and read its answer: the answer's kind and body. On
/// failure, whether any of the answer had arrived.
fn socket_exchange(
    stream: &mut UnixStream,
    kind: u16,
    id: u64,
    body: &[u8],
) -> Result<(u16, Vec<u8>), (std::io::Error, bool)> {
    stream
        .write_all(&frame(Framing::Stream, kind, id, body))
        .map_err(|error| (error, false))?;
    let invalid = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, why.to_string());
    let mut header = [0u8; 14];
    stream
        .read_exact(&mut header)
        .map_err(|error| (error, false))?;
    let length = u32::from_le_bytes(header[..4].try_into().expect("four bytes"));
    let answered = u16::from_le_bytes(header[4..6].try_into().expect("two bytes"));
    let answer_id = u64::from_le_bytes(header[6..].try_into().expect("eight bytes"));
    let Some(body_length) = length
        .checked_sub(10)
        .filter(|length| *length <= MAX_ANSWER)
    else {
        return Err((invalid("an answer larger than any the node gives"), true));
    };
    if answer_id != id {
        return Err((invalid("an answer to another request"), true));
    }
    let mut answer = vec![0u8; body_length as usize];
    stream
        .read_exact(&mut answer)
        .map_err(|error| (error, true))?;
    Ok((answered, answer))
}
