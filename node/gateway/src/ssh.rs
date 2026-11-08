//! The SSH port: s4's screens and the `vos-api` subsystem, under any key as
//! no one in particular (s4's anonymous policy: an identity for the
//! connection alone, no resumable session, no remembered grant), a fresh
//! ephemeral key expected. The screens are the demo's ([`crate::demo`]) when
//! the file names its agent. The subsystem is a byte stream of the
//! node API's frames, with ids: the gateway reads each header, refuses a
//! kind outside the relay set (`NotRelayed`) before reading its body or
//! asking any node, checks its limit, then relays it to a node and writes
//! the answer back under the client's id. At most [`IN_FLIGHT`] requests a
//! channel, each frame within [`DEADLINE`] of its first byte.
//!
//! A proven call's body, up to a device proof's 1.5 MiB, is read only once
//! it holds one of the places the gateway's SSH ports share
//! ([`crate::caps::PROVEN_BODIES`]): past them the channel reads no further until one
//! is given back, the frame's deadline running from then. Each call and
//! proven call then passes its port's caps ([`crate::caps`]), or is
//! answered `Busy` with no node asked.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use s4_server::rui::{App, Cx, Id, View, ViewContext, view};
use s4_server::{Server, SubsystemChannel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use vos_api::{Event, FrameError, Framing, Kind, Mark, Reader, Requests, error_frame, frame};

use crate::Gateway;
use crate::caps::{Caps, busy};
use crate::circuits::Circuits;
use crate::limits::Limits;

/// The subsystem's name.
pub const SUBSYSTEM: &str = "vos-api";
/// Requests in flight on one channel: past them, the gateway reads no
/// further until one ends.
pub const IN_FLIGHT: usize = 16;
/// How long a frame may take to arrive from its first byte.
pub const DEADLINE: Duration = Duration::from_secs(60);

/// Whose channels a port serves, and how it counts them.
#[derive(Clone)]
pub enum Peers {
    /// A TCP port's: each by its peer's address.
    Addresses,
    /// The onion's: each by the stream its loopback carrier names, a port
    /// of its circuit's address; a connection no stream carries is served
    /// no channel.
    Carried(Arc<Circuits>),
}

/// What a port's relay counts and caps: the transport it marks, its limits
/// per address (or circuit), its caps on calls, and the proven calls'
/// bodies it shares with the gateway's other ports.
#[derive(Clone)]
pub struct Port {
    pub mark: Mark,
    pub limits: Arc<Limits>,
    pub caps: Arc<Caps>,
    pub bodies: Arc<Semaphore>,
    pub peers: Peers,
}

impl Port {
    /// A TCP port marking `mark`, its limits and caps as given, and the
    /// bodies it shares.
    pub fn tcp(mark: Mark, limits: Arc<Limits>, caps: Arc<Caps>, bodies: Arc<Semaphore>) -> Self {
        Self {
            mark,
            limits,
            caps,
            bodies,
            peers: Peers::Addresses,
        }
    }

    /// The address a channel from `peer` counts as, or `None` when the
    /// port serves it no channel.
    fn connection(&self, peer: Option<SocketAddr>) -> Option<Option<SocketAddr>> {
        match &self.peers {
            Peers::Addresses => Some(peer),
            Peers::Carried(circuits) => peer.and_then(|peer| circuits.carried(peer)).map(Some),
        }
    }
}

/// The SSH port's screen when the file names no demo.
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

/// The SSH server, relaying through `gateway` as `port` counts and caps
/// its channels, marked with its transport; with `demo`, its screens,
/// whose claims go as the app's key.
pub fn server(
    host_key: russh::keys::PrivateKey,
    gateway: Arc<Gateway>,
    port: Port,
    demo: Option<(crate::demo::Demo, Arc<crate::app::AppClient>)>,
) -> Server {
    let mark = port.mark;
    let server = match demo {
        Some((demo, app)) => {
            let service = Arc::new(crate::demo::Service::new(
                demo.clone(),
                Arc::clone(&gateway),
                mark,
                app,
            ));
            Server::new(crate::demo::APPLICATION, move || {
                crate::demo::Screens::new(demo.clone())
            })
            .facility(crate::demo::FACILITY, 1)
            .host_service_fn(crate::demo::SERVICE, move |request| {
                Arc::clone(&service).serve(request)
            })
        }
        None => Server::new(crate::demo::APPLICATION, || Screen),
    };
    server
        .host_key(host_key)
        // Any key, as no one in particular: authority is what a request
        // proves, and the node checks every signature and proof.
        .anonymous()
        .subsystem_fn(SUBSYSTEM, move |channel| {
            let (gateway, port) = (Arc::clone(&gateway), port.clone());
            async move {
                let Some(connection) = port.connection(channel.peer()) else {
                    return;
                };
                // A channel holds a place among its address's, as an HTTP
                // connection does.
                let place = match connection {
                    Some(connection) => match port.limits.connect(connection.ip()) {
                        Some(place) => Some(place),
                        None => return,
                    },
                    None => None,
                };
                relay(gateway, channel, &port, connection).await;
                drop(place);
            }
        })
}

/// The SSH port the file names, served on the runtime until it ends: its
/// host key made if missing, counted and capped as `port`.
pub async fn start(
    config: &crate::config::Config,
    gateway: Arc<Gateway>,
    port: Port,
    app: Option<Arc<crate::app::AppClient>>,
) -> Result<Option<tokio::task::JoinHandle<()>>, String> {
    let Some(address) = config.ssh else {
        return Ok(None);
    };
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|error| format!("{address}: {error}"))?;
    serve(config, gateway, port, app, listener).map(Some)
}

/// The SSH server the file names on `listener`, its host key made if
/// missing, counted and capped as `port`, served on the runtime until it
/// ends.
pub fn serve(
    config: &crate::config::Config,
    gateway: Arc<Gateway>,
    port: Port,
    app: Option<Arc<crate::app::AppClient>>,
    listener: tokio::net::TcpListener,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let path = config
        .ssh_host_key
        .clone()
        .ok_or("an SSH port needs ssh_host_key")?;
    let host_key = s4_server::load_or_create_host_key(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let demo = match (config.demo.clone(), app) {
        (Some(demo), Some(app)) => Some((demo, app)),
        (Some(_), None) => return Err("the demo's screens need app_key".into()),
        (None, _) => None,
    };
    let server = server(host_key, gateway, port, demo);
    Ok(tokio::spawn(async move {
        if let Err(error) = server.serve_on(listener).await {
            tracing::warn!(%error, "an SSH port ended");
        }
    }))
}

/// Whether a frame of `kind` with a body of `body` bytes is a proven
/// call's large body.
fn large(kind: u16, body: u32) -> bool {
    kind == Kind::Credentialed as u16 && body > Kind::Call.limit()
}

/// Relay one channel's frames until it ends, or a frame error closes it,
/// each marked with `port`'s transport, whatever the client marked it.
/// From `connection`, each frame takes a token of its address's rate (past
/// it, the channel closes) and, while in flight, a place among its
/// address's (past them, it is answered `Unavailable`); each call and
/// proven call passes the port's caps or is answered `Busy`.
pub async fn relay(
    gateway: Arc<Gateway>,
    channel: SubsystemChannel,
    port: &Port,
    connection: Option<SocketAddr>,
) {
    let mark = port.mark;
    let (mut reading, writer) = channel.into_split();
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    let slots = Arc::new(Semaphore::new(IN_FLIGHT));
    let mut reader = Reader::requests(Framing::Stream, Requests::Relayed);
    let mut chunk = vec![0u8; 64 << 10];
    let mut started: Option<Instant> = None;
    // The frame part read's place among the proven bodies, if it is large.
    let mut body = None;
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
                    // A whole frame read: the next one's deadline runs from
                    // its own first byte.
                    started = None;
                    let body = match body.take() {
                        None if large(request.kind, request.body.len() as u32) => {
                            let Ok(place) = Arc::clone(&port.bodies).acquire_owned().await else {
                                return;
                            };
                            Some(place)
                        }
                        held => held,
                    };
                    let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
                        return;
                    };
                    let mut place = None;
                    if let Some(connection) = connection {
                        if !port.limits.request(connection.ip()) {
                            return;
                        }
                        place = port.limits.connect(connection.ip());
                        if place.is_none() {
                            let bytes =
                                error_frame(Framing::Stream, request.id, FrameError::Unavailable);
                            let _ = writer.lock().await.write_all(&bytes).await;
                            continue;
                        }
                    }
                    let kind = Kind::from_u16(request.kind).expect("the reader's kinds");
                    let held = match port.caps.admit(kind, &request.body, connection) {
                        Ok(held) => held,
                        Err(()) => {
                            let (answered, answer) = busy(kind);
                            let bytes = frame(Framing::Stream, answered, request.id, &answer);
                            let _ = writer.lock().await.write_all(&bytes).await;
                            continue;
                        }
                    };
                    let (gateway, writer) = (Arc::clone(&gateway), Arc::clone(&writer));
                    requests.spawn(async move {
                        let (_place, _body, _held) = (place, body, held);
                        let (answered, answer) = gateway.relay(kind, mark, &request.body).await;
                        let bytes = frame(Framing::Stream, answered, request.id, &answer);
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
        // A large body is read only once it holds a place; its deadline
        // runs from then, as the wait is the gateway's.
        if body.is_none()
            && let Some(header) = reader.header()
            && header
                .body(Framing::Stream)
                .is_some_and(|length| large(header.kind, length))
        {
            let Ok(place) = Arc::clone(&port.bodies).acquire_owned().await else {
                return;
            };
            body = Some(place);
            started = Some(Instant::now());
        }
    }
}
