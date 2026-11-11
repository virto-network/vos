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
//! it holds its places: on a capped port (the onion's) its port's,
//! connection's and circuit's ([`crate::caps`]), the channel reading
//! nothing while it waits for the port's and closed past the others; on
//! an uncapped one a place among the port's own proven bodies
//! ([`crate::caps::PROVEN_BODIES`]). The body must then arrive within
//! [`LARGE_DEADLINE`]. Each call and proven call passes its port's caps,
//! or is answered `Busy` with no node asked.

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
use crate::limits::Limits;

/// The subsystem's name.
pub const SUBSYSTEM: &str = "vos-api";
/// Requests in flight on one channel: past them, the gateway reads no
/// further until one ends.
pub const IN_FLIGHT: usize = 16;
/// How long a frame may take to arrive from its first byte.
pub const DEADLINE: Duration = Duration::from_secs(60);
/// How long a proven call's large body may take to arrive once it holds
/// its places: a device proof over an onion circuit at its slowest
/// measured rate (`light-node.md` §6.3), with room.
pub const LARGE_DEADLINE: Duration = Duration::from_secs(30);

/// Host-service calls in flight from one of the onion's screen sessions:
/// with a circuit's connections and an anonymous connection's sessions
/// (s4-server's four), what bounds the screens' own calls from one circuit,
/// whose requests name no peer to count them by.
pub const ONION_HOST_CALLS: usize = 4;

/// What a port's relay counts and caps: the transport it marks, its limits
/// per address (an onion's: per circuit, each stream a port of its
/// circuit's address, [`crate::circuits`]), its caps on calls, and the
/// proven calls' bodies it shares with the gateway's other ports.
#[derive(Clone)]
pub struct Port {
    pub mark: Mark,
    pub limits: Arc<Limits>,
    pub caps: Arc<Caps>,
    pub bodies: Arc<Semaphore>,
}

impl Port {
    /// A port marking `mark`, its limits and caps as given, and the bodies
    /// it shares.
    pub fn new(mark: Mark, limits: Arc<Limits>, caps: Arc<Caps>, bodies: Arc<Semaphore>) -> Self {
        Self {
            mark,
            limits,
            caps,
            bodies,
        }
    }
}

/// The onion's SSH streams as the SSH server's connections, each from its
/// stream's address.
impl s4_server::Listener for crate::circuits::OnionListener {
    type Stream = Box<dyn crate::circuits::Io>;

    async fn accept(&mut self) -> std::io::Result<(Self::Stream, Option<SocketAddr>)> {
        match self.next().await {
            Some((stream, peer)) => Ok((stream, Some(peer))),
            None => Err(std::io::ErrorKind::BrokenPipe.into()),
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
            // An onion's port 22 presents this key; with no Ed25519 host
            // key the enrollment pins no onion.
            let ssh_host_key = host_key.public_key().key_data().ed25519().map(|key| key.0);
            let service = Arc::new(crate::demo::Service::new(
                demo.clone(),
                ssh_host_key,
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
    let limits = match mark {
        Mark::Onion => s4_server::ServerLimits {
            host_services: s4_server::HostServiceLimits {
                max_active_per_session: ONION_HOST_CALLS,
                ..Default::default()
            },
            ..Default::default()
        },
        _ => s4_server::ServerLimits::default(),
    };
    server
        .host_key(host_key)
        .limits(limits)
        // Any key, as no one in particular: authority is what a request
        // proves, and the node checks every signature and proof.
        .anonymous()
        .subsystem_fn(SUBSYSTEM, move |channel| {
            let (gateway, port) = (Arc::clone(&gateway), port.clone());
            async move {
                let connection = channel.peer();
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
    listener: impl s4_server::Listener + 'static,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let path = config
        .ssh_host_key
        .clone()
        .ok_or("an SSH port needs ssh_host_key")?;
    let host_key = s4_server::load_or_create_host_key(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let demo = match (config.demo.clone(), app) {
        (Some(mut demo), Some(app)) => {
            // The enrollment pins the onion the gateway serves in process.
            if let Some(path) = config.onion.as_ref().and_then(|onion| onion.key.as_ref()) {
                let seed = crate::config::seed(path)?;
                demo.onions = vec![
                    ed25519_dalek::SigningKey::from_bytes(&seed)
                        .verifying_key()
                        .to_bytes(),
                ];
            }
            Some((demo, app))
        }
        (Some(_), None) => return Err("the demo's screens need app_key".into()),
        (None, _) => None,
    };
    let mark = port.mark;
    let server = server(host_key, gateway, port, demo);
    Ok(tokio::spawn(async move {
        if let Err(error) = server.serve_on(listener).await {
            tracing::warn!(%error, ?mark, "an SSH port ended");
        }
    }))
}

/// Whether a frame of `kind` with a body of `body` bytes is a proven
/// call's large body.
fn large(kind: u16, body: u32) -> bool {
    kind == Kind::Credentialed as u16 && body > Kind::Call.limit()
}

/// The places a proven call's large body holds from its header on.
#[derive(Default)]
struct Placed {
    held: Option<crate::caps::Held>,
    body: Option<tokio::sync::OwnedSemaphorePermit>,
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
    // When the frame part read must have arrived by.
    let mut due: Option<Instant> = None;
    // The places the frame part read holds, if it is a large body.
    let mut placed: Option<Placed> = None;
    let mut requests = tokio::task::JoinSet::new();
    loop {
        let read = match due {
            Some(due) => {
                let left = due.saturating_duration_since(Instant::now());
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
                    due = None;
                    let placed = placed.take().unwrap_or_default();
                    let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
                        return;
                    };
                    let mut place = None;
                    if let Some(connection) = connection {
                        if !port.limits.request(connection.ip()) {
                            tracing::debug!(
                                ?connection,
                                ?mark,
                                "a channel past its address's rate, closed"
                            );
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
                    let admitted = match placed.held {
                        // Its places taken at its header: its agent's rate
                        // is left.
                        Some(held) => port
                            .caps
                            .agent(kind, &request.body, connection)
                            .then_some(Some(held))
                            .ok_or(crate::caps::Capped),
                        None => port.caps.admit(kind, &request.body, connection),
                    };
                    let Ok(held) = admitted else {
                        let (answered, answer) = busy(kind);
                        let bytes = frame(Framing::Stream, answered, request.id, &answer);
                        let _ = writer.lock().await.write_all(&bytes).await;
                        continue;
                    };
                    let body = placed.body;
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
        if !reader.pending() {
            due = None;
        } else if due.is_none() {
            due = Some(Instant::now() + DEADLINE);
        }
        // A large body is read only once it holds its places; its deadline
        // runs from then, as the wait is the gateway's.
        if placed.is_none()
            && let Some(header) = reader.header()
            && header
                .body(Framing::Stream)
                .is_some_and(|length| large(header.kind, length))
        {
            let taken = if port.caps.caps() {
                match tokio::time::timeout(DEADLINE, port.caps.proven_wait(connection)).await {
                    Ok(Ok(held)) => Some(Placed { held, body: None }),
                    _ => None,
                }
            } else {
                Arc::clone(&port.bodies)
                    .acquire_owned()
                    .await
                    .ok()
                    .map(|body| Placed {
                        held: None,
                        body: Some(body),
                    })
            };
            let Some(taken) = taken else {
                // Past its connection's or circuit's proven calls: the
                // body is not read, so the channel's framing ends here.
                let (answered, answer) = busy(Kind::Credentialed);
                let bytes = frame(Framing::Stream, answered, header.id, &answer);
                let mut writer = writer.lock().await;
                let _ = writer.write_all(&bytes).await;
                let _ = writer.shutdown().await;
                return;
            };
            placed = Some(taken);
            due = Some(Instant::now() + LARGE_DEADLINE);
        }
    }
}
