//! The SSH port: s4's screens and the `vos-api` subsystem, under any key,
//! a fresh ephemeral one expected. The subsystem is a byte stream of the
//! node API's frames, with ids: the gateway reads each header, refuses a
//! kind outside the relay set (`NotRelayed`) before reading its body or
//! asking any node, checks its limit, then relays it to a node and writes
//! the answer back under the client's id. At most [`IN_FLIGHT`] requests a
//! channel, each frame within [`DEADLINE`] of its first byte.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use s4_server::rui::{App, Cx, Id, View, ViewContext, view};
use s4_server::{Credential, Identity, Server, SubsystemChannel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vos_api::{Event, Framing, Kind, Reader, Requests, error_frame, frame};

use crate::Gateway;
use crate::limits::Limits;

/// The subsystem's name [decided, S49].
pub const SUBSYSTEM: &str = "vos-api";
/// Requests in flight on one channel: past them, the gateway reads no
/// further until one ends.
pub const IN_FLIGHT: usize = 16;
/// How long a frame may take to arrive from its first byte.
pub const DEADLINE: Duration = Duration::from_secs(60);

/// The SSH port's screen until the demo's are built.
struct Screen;

impl App for Screen {
    type Message = ();

    fn view(&self, _context: &ViewContext) -> View<()> {
        View::new(view::text_at(
            Id::raw(1),
            "vos-gateway: its vos-api subsystem relays the node API's reads",
        ))
    }

    fn update(&mut self, _message: (), cx: &mut Cx<()>) {
        cx.skip_redraw();
    }
}

/// The SSH server, on `listener`, relaying through `gateway`, past each
/// address's rate refusing its channels.
pub fn server(
    host_key: russh::keys::PrivateKey,
    gateway: Arc<Gateway>,
    limits: Arc<Limits>,
) -> Server {
    Server::new("vos.gateway", || Screen)
        .host_key(host_key)
        // Any key: the subsystem's clients are no one in particular, and
        // the node checks every signature and proof.
        .authenticator_fn(|authentication| async move {
            match authentication.credential {
                Credential::PublicKey(key) => {
                    let fingerprint = key.fingerprint(Default::default());
                    Identity::new(format!("key:{fingerprint}"))
                        .map(Some)
                        .map_err(|error| s4_server::AuthError::new(error.to_string()))
                }
                _ => Ok(None),
            }
        })
        .subsystem_fn(SUBSYSTEM, move |channel| {
            let (gateway, limits) = (Arc::clone(&gateway), Arc::clone(&limits));
            async move {
                let admitted = channel
                    .peer()
                    .map(|peer: SocketAddr| peer.ip())
                    .is_none_or(|address: IpAddr| limits.request(address));
                if admitted {
                    relay(gateway, channel).await;
                }
            }
        })
}

/// The SSH port the file names, served on the runtime until it ends: its
/// host key made if missing.
pub async fn start(
    config: &crate::config::Config,
    gateway: Arc<Gateway>,
    limits: Arc<Limits>,
) -> Result<Option<tokio::task::JoinHandle<()>>, String> {
    let Some(address) = config.ssh else {
        return Ok(None);
    };
    let path = config
        .ssh_host_key
        .clone()
        .ok_or("an SSH port needs ssh_host_key")?;
    let host_key = s4_server::load_or_create_host_key(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|error| format!("{address}: {error}"))?;
    let server = server(host_key, gateway, limits);
    Ok(Some(tokio::spawn(async move {
        if let Err(error) = server.serve_on(listener).await {
            tracing::warn!(%error, "the SSH port ended");
        }
    })))
}

/// Relay one channel's frames until it ends, or a frame error closes it.
pub async fn relay(gateway: Arc<Gateway>, channel: SubsystemChannel) {
    let (mut reading, writer) = channel.into_split();
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    let slots = Arc::new(tokio::sync::Semaphore::new(IN_FLIGHT));
    let mut reader = Reader::requests(Framing::Stream, Requests::Relayed);
    let mut chunk = vec![0u8; 64 << 10];
    let mut started: Option<Instant> = None;
    let mut requests = tokio::task::JoinSet::new();
    loop {
        let read = match started {
            Some(started) => {
                let left = (started + DEADLINE).saturating_duration_since(Instant::now());
                match tokio::time::timeout(left, reading.read(&mut chunk)).await {
                    Ok(read) => read,
                    Err(_) => return,
                }
            }
            None => reading.read(&mut chunk).await,
        };
        let read = match read {
            Ok(read) => read,
            Err(_) => return,
        };
        if read == 0 {
            while requests.join_next().await.is_some() {}
            if let Some(Event::Error { error, id }) = reader.finish() {
                let _ = writer
                    .lock()
                    .await
                    .write_all(&error_frame(Framing::Stream, id, error))
                    .await;
            }
            return;
        }
        reader.push(&chunk[..read]);
        while let Some(event) = reader.event() {
            match event {
                Event::Frame(request) => {
                    let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
                        return;
                    };
                    let kind = Kind::from_u16(request.kind).expect("the reader's kinds");
                    let (gateway, writer) = (Arc::clone(&gateway), Arc::clone(&writer));
                    requests.spawn(async move {
                        let (answered, body) = gateway.relay(kind, &request.body).await;
                        let bytes = frame(Framing::Stream, answered, request.id, &body);
                        // Whole: an answer never interleaves another.
                        let _ = writer.lock().await.write_all(&bytes).await;
                        drop(slot);
                    });
                }
                Event::Error { error, id } => {
                    let mut writer = writer.lock().await;
                    let _ = writer
                        .write_all(&error_frame(Framing::Stream, id, error))
                        .await;
                    let _ = writer.shutdown().await;
                    return;
                }
            }
        }
        while requests.try_join_next().is_some() {}
        started = match (reader.pending(), started) {
            (false, _) => None,
            (true, Some(started)) => Some(started),
            (true, None) => Some(Instant::now()),
        };
    }
}
