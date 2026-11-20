//! A test gateway's SSH server: `vos-api` over SSH on one end of an
//! in-memory stream, as a gateway's onion serves it, each connection's
//! SSH key and end recorded and each request answered by its gateway.

use std::collections::HashMap;
use std::sync::Arc;

use russh::keys::ssh_key;
use russh::server::{Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use vos_api::{Event, Framing, Reader, Requests, frame};

use super::held::Held;
use crate::tor::{Circuit, Target};

/// What one connection carried.
#[derive(Clone, Debug)]
pub struct Seen {
    pub target: Target,
    pub circuit: Circuit,
    /// The ed25519 key it authenticated with.
    pub key: Option<[u8; 32]>,
    /// Each request's kind and the agent it named (0: none).
    pub requests: Vec<(u16, u32)>,
    /// Its stream ended: its SSH session, or its `vos-api` channel.
    pub ended: bool,
}

impl Seen {
    /// A connection dialed to `target` on `circuit`, nothing carried yet.
    pub fn new(target: &Target, circuit: Circuit) -> Self {
        Self {
            target: target.clone(),
            circuit,
            key: None,
            requests: Vec::new(),
            ended: false,
        }
    }

    /// Its requests' kinds.
    pub fn kinds(&self) -> Vec<u16> {
        self.requests.iter().map(|(kind, _)| *kind).collect()
    }

    /// `kind` with `body` carried.
    pub fn carried(&mut self, kind: u16, body: &[u8]) {
        let agent = body
            .get(..4)
            .map_or(0, |bytes| u32::from_le_bytes(bytes.try_into().unwrap()));
        self.requests.push((kind, agent));
    }
}

/// What becomes of a request.
pub enum Answer {
    /// Its answer's body, framed back.
    Body(Vec<u8>),
    /// No answer; the connection stays.
    Silent,
    /// No answer, and the connection cut.
    Cut,
}

/// One connection as its gateway keeps it.
pub trait Connection: Send + Sync + 'static {
    /// `f` over this connection's record.
    fn seen(&self, f: impl FnOnce(&mut Seen));

    /// A request's fate, on a thread of its own (a gateway's answer may
    /// run the interpreter); the gateway records it or not.
    fn answer(&self, kind: u16, body: &[u8]) -> Answer;
}

/// An SSH server under `host_key` for `connection` on one end of a stream
/// that holds its writes until flushed: the other end, the client's.
pub fn dialed(
    host_key: &ssh_key::PrivateKey,
    connection: impl Connection,
) -> tokio::io::DuplexStream {
    let (ours, theirs) = tokio::io::duplex(1 << 20);
    serve(host_key, connection, Held::new(theirs));
    ours
}

/// An SSH server under `host_key` for `connection` on `stream`.
pub fn serve(
    host_key: &ssh_key::PrivateKey,
    connection: impl Connection,
    stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
) {
    let config = Arc::new(russh::server::Config {
        keys: vec![host_key.clone()],
        ..russh::server::Config::default()
    });
    let connection = Arc::new(connection);
    let handler = Handler {
        connection: Arc::clone(&connection),
        channels: HashMap::new(),
    };
    tokio::spawn(async move {
        if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
            let _ = session.await;
        }
        connection.seen(|seen| seen.ended = true);
    });
}

struct Handler<C> {
    connection: Arc<C>,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl<C: Connection> russh::server::Handler for Handler<C> {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        verified: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        let key = verified.public_key.key_data().ed25519().unwrap().0;
        self.connection.seen(|seen| seen.key = Some(key));
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(channel) = self.channels.remove(&id) else {
            return Ok(());
        };
        if name != "vos-api" {
            session.channel_failure(id)?;
            return Ok(());
        }
        session.channel_success(id)?;
        tokio::spawn(subsystem(
            channel.into_stream(),
            Arc::clone(&self.connection),
        ));
        Ok(())
    }
}

/// The `vos-api` subsystem: each frame answered by the connection's
/// gateway.
async fn subsystem(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    connection: Arc<impl Connection>,
) {
    let mut reader = Reader::requests(Framing::Stream, Requests::All);
    let mut chunk = vec![0u8; 64 << 10];
    'stream: loop {
        let read = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        reader.push(&chunk[..read]);
        while let Some(Event::Frame(request)) = reader.event() {
            let answering = Arc::clone(&connection);
            let (kind, body) = (request.kind, request.body);
            let answer = tokio::task::spawn_blocking(move || answering.answer(kind, &body))
                .await
                .expect("the gateway answered");
            let body = match answer {
                Answer::Body(body) => body,
                Answer::Silent => continue,
                Answer::Cut => break 'stream,
            };
            let bytes = frame(Framing::Stream, request.kind, request.id, &body);
            if stream.write_all(&bytes).await.is_err() {
                break 'stream;
            }
        }
    }
    connection.seen(|seen| seen.ended = true);
}
