//! The SSH port: s4's screens and the `vos-api` subsystem, under any key as
//! no one in particular (s4's anonymous policy: an identity for the
//! connection alone, no resumable session, no remembered grant), a fresh
//! ephemeral key expected. The screens are an [`App`]'s: an application
//! built on this library brings its own, and `vos-gateway` serves a
//! placeholder ([`Placeholder`]). The subsystem is a byte stream of the
//! node API's frames, with ids: the gateway reads each header, refuses a
//! kind outside the relay set (`NotRelayed`) before reading its body or
//! asking any node, checks its limit, then relays it to a node and writes
//! the answer back under the client's id. At most [`IN_FLIGHT`] requests a
//! channel, each frame within [`DEADLINE`] of its first byte.
//!
//! A proven call's body, up to a device proof's 1.5 MiB, is read only once
//! it holds its places ([`crate::caps`]): on a capped port (the onion's)
//! its connection's and circuit's, then its port's, the channel reading
//! nothing while it waits for the port's and closed past the others; on
//! an uncapped one a place among the port's proven bodies
//! ([`crate::caps::PROVEN_BODIES`]). Its header takes its address's rate
//! token. The body must then arrive within [`PROGRESS`] plus its length at
//! [`SLOWEST_RATE`], at most [`LARGE_DEADLINE`], at a pace ([`Pace`]):
//! after a first [`PROGRESS`], as much of it as that share of its time, so
//! a header whose body never comes, or comes a byte at a time, holds its
//! places about [`PROGRESS`], and a small body kept at its pace little
//! longer. Each call and proven call
//! passes its port's caps, or is answered `Busy` with no node asked.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use s4_server::rui::{Cx, Id, View, ViewContext, view};
use s4_server::{Server, SubsystemChannel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use vos_api::{Event, FrameError, Framing, Kind, Mark, Reader, Requests, error_frame, frame};

use crate::Gateway;
use crate::caps::{Caps, busy};
use crate::limits::Limits;

/// The subsystem's name.
pub const SUBSYSTEM: &str = "vos-api";
/// The application identity the screens are served as.
pub const APPLICATION: &str = "vos.gateway";
/// Requests in flight on one channel: past them, the gateway reads no
/// further until one ends.
pub const IN_FLIGHT: usize = 16;
/// How long a frame may take to arrive from its first byte.
pub const DEADLINE: Duration = Duration::from_secs(60);
/// The most a proven call's large body may take to arrive once it holds
/// its places: a device proof over an onion circuit at its slowest
/// measured rate (`light-node.md` §6.3), with room.
pub const LARGE_DEADLINE: Duration = Duration::from_secs(30);
/// The slack a proven call's large body has over its pace once it holds
/// its places: a Tor circuit delivers its cells seconds apart at worst.
pub const PROGRESS: Duration = Duration::from_secs(5);
/// The slowest rate, in bytes a second, a large body's pace allows past
/// [`PROGRESS`]: a 1 MiB upload's slowest measured, 26 s through a bridge
/// (`light-node.md` §6.3), about 40 KiB/s. A body has [`PROGRESS`] plus its
/// length at this rate, at most [`LARGE_DEADLINE`], so a small one holds
/// its places only as long as its length needs.
pub const SLOWEST_RATE: u64 = 40 << 10;

/// A large body's pace from when it took its places: of its `length`
/// bytes, `read` so far, each due by [`PROGRESS`] plus its share of the
/// whole body's time ([`Pace::whole`]), the whole by then.
struct Pace {
    from: Instant,
    length: u64,
    read: u64,
}

impl Pace {
    /// The whole body's time: [`PROGRESS`] and its length at
    /// [`SLOWEST_RATE`], at most [`LARGE_DEADLINE`].
    fn whole(&self) -> Duration {
        (PROGRESS + Duration::from_secs_f64(self.length as f64 / SLOWEST_RATE as f64))
            .min(LARGE_DEADLINE)
    }

    /// When its next byte is due.
    fn due(&self) -> Instant {
        let whole = self.whole();
        let share = whole.mul_f64(self.read as f64 / self.length.max(1) as f64);
        (self.from + PROGRESS + share).min(self.from + whole)
    }
}

/// How long the onion's SSH connections may take to authenticate: the
/// light node's own handshake deadline over Tor.
pub const ONION_HANDSHAKE: Duration = Duration::from_secs(30);

/// Host-service calls in flight from one of the onion's screen sessions:
/// with a circuit's connections and an anonymous connection's sessions
/// (s4-server's four), what bounds the screens' own calls from one circuit,
/// whose requests name no peer to count them by.
pub const ONION_HOST_CALLS: usize = 4;

/// What a port's relay counts and caps: the transport it marks, its limits
/// per address (an onion's: per circuit, each stream a port of its
/// circuit's address, [`crate::circuits`]), and its caps on calls.
#[derive(Clone)]
pub struct Port {
    pub mark: Mark,
    pub limits: Arc<Limits>,
    pub caps: Arc<Caps>,
    /// The SSH server's connections at once, the handshake included:
    /// s4-server's default unless set.
    pub connections: Option<usize>,
}

impl Port {
    /// A port marking `mark`, its limits and caps as given.
    pub fn new(mark: Mark, limits: Arc<Limits>, caps: Arc<Caps>) -> Self {
        Self {
            mark,
            limits,
            caps,
            connections: None,
        }
    }

    /// The same, its SSH server taking at most `connections` at once.
    pub fn with_connections(self, connections: Option<usize>) -> Self {
        Self {
            connections,
            ..self
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

/// What an SSH port serves as its screens: for the port marked `mark`,
/// relaying through `gateway`, whose host key's Ed25519 half is
/// `host_key` (what an onion's port 22 presents), the s4 server of an
/// application's screens and host services. The port adds its host key,
/// its limits, the anonymous policy and the `vos-api` subsystem. Asked
/// once a port.
pub trait App: Send + Sync {
    fn server(&self, gateway: &Arc<Gateway>, mark: Mark, host_key: Option<[u8; 32]>) -> Server;
}

/// `vos-gateway`'s screens: one line saying what the port relays.
pub struct Placeholder;

impl App for Placeholder {
    fn server(&self, _: &Arc<Gateway>, _: Mark, _: Option<[u8; 32]>) -> Server {
        Server::new(APPLICATION, || Screen)
    }
}

/// [`Placeholder`]'s screen.
struct Screen;

impl s4_server::rui::App for Screen {
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
/// its channels, marked with its transport, serving `app`'s screens.
pub fn server(
    host_key: russh::keys::PrivateKey,
    gateway: Arc<Gateway>,
    port: Port,
    app: &dyn App,
) -> Server {
    let mark = port.mark;
    let ed25519 = host_key.public_key().key_data().ed25519().map(|key| key.0);
    let server = app.server(&gateway, mark, ed25519);
    let defaults = s4_server::ServerLimits::default();
    let mut limits = match mark {
        Mark::Onion => s4_server::ServerLimits {
            auth_timeout: ONION_HANDSHAKE,
            host_services: s4_server::HostServiceLimits {
                max_active_per_session: ONION_HOST_CALLS,
                ..Default::default()
            },
            ..defaults
        },
        _ => defaults,
    };
    if let Some(connections) = port.connections {
        limits.max_connections = connections;
    }
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

/// The SSH port the file names, serving `app`'s screens on the runtime
/// until it ends: its host key made if missing, counted and capped as
/// `port`.
pub async fn start(
    config: &crate::config::Config,
    gateway: Arc<Gateway>,
    port: Port,
    app: &dyn App,
) -> Result<Option<tokio::task::JoinHandle<()>>, String> {
    let Some(address) = config.ssh else {
        return Ok(None);
    };
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|error| format!("{address}: {error}"))?;
    serve(config, gateway, port, app, listener).map(Some)
}

/// The SSH server the file names on `listener`, serving `app`'s screens,
/// its host key made if missing, counted and capped as `port`, served on
/// the runtime until it ends.
pub fn serve(
    config: &crate::config::Config,
    gateway: Arc<Gateway>,
    port: Port,
    app: &dyn App,
    listener: impl s4_server::Listener + 'static,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let path = config
        .ssh_host_key
        .clone()
        .ok_or("an SSH port needs ssh_host_key")?;
    let host_key = s4_server::load_or_create_host_key(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let mark = port.mark;
    let server = server(host_key, gateway, port, app);
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

/// Whether a frame from `connection` passes its address's rate on `port`:
/// past it, the channel closes.
fn rated(port: &Port, connection: SocketAddr) -> bool {
    let passes = port.limits.request(connection.ip());
    if !passes {
        tracing::debug!(?connection, mark = ?port.mark, "a channel past its address's rate, closed");
    }
    passes
}

/// Write `bytes` whole to the channel, an answer never interleaving
/// another; then end the channel's side if `close`.
async fn write<W: tokio::io::AsyncWrite + Unpin>(
    writer: &tokio::sync::Mutex<W>,
    bytes: &[u8],
    close: bool,
) {
    let mut writer = writer.lock().await;
    let _ = writer.write_all(bytes).await;
    if close {
        let _ = writer.shutdown().await;
    }
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
    // A large body's pace, once it holds its places.
    let mut pace: Option<Pace> = None;
    // The places the frame part read holds, if it is a large body.
    let mut placed: Option<crate::caps::Held> = None;
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
                write(&writer, &error_frame(Framing::Stream, id, error), false).await;
            }
            return;
        }
        reader.push(&chunk[..read]);
        // A large body read on: its next bytes at its pace.
        if let Some(pace) = pace.as_mut() {
            pace.read += read as u64;
            due = Some(pace.due());
        }
        while let Some(event) = reader.event() {
            match event {
                Event::Frame(request) => {
                    // A whole frame read: the next one's deadline runs from
                    // its own first byte.
                    due = None;
                    pace = None;
                    let placed = placed.take();
                    // A large body's token was taken at its header.
                    let charged = placed.is_some();
                    let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
                        return;
                    };
                    let mut place = None;
                    if let Some(connection) = connection {
                        if !charged && !rated(port, connection) {
                            return;
                        }
                        place = port.limits.in_flight(connection.ip());
                        if place.is_none() {
                            let bytes =
                                error_frame(Framing::Stream, request.id, FrameError::Unavailable);
                            write(&writer, &bytes, false).await;
                            continue;
                        }
                    }
                    let kind = Kind::from_u16(request.kind).expect("the reader's kinds");
                    let Ok(held) = port
                        .caps
                        .admit_held(kind, &request.body, connection, placed)
                    else {
                        let (answered, answer) = busy(kind);
                        let bytes = frame(Framing::Stream, answered, request.id, &answer);
                        write(&writer, &bytes, false).await;
                        continue;
                    };
                    let (gateway, writer) = (Arc::clone(&gateway), Arc::clone(&writer));
                    requests.spawn(async move {
                        let (_place, _held) = (place, held);
                        let (answered, answer) = gateway.relay(kind, mark, &request.body).await;
                        let bytes = frame(Framing::Stream, answered, request.id, &answer);
                        // Whole: an answer never interleaves another.
                        write(&writer, &bytes, false).await;
                        drop(slot);
                    });
                }
                Event::Error { error, id } => {
                    write(&writer, &error_frame(Framing::Stream, id, error), true).await;
                    return;
                }
            }
        }
        while requests.try_join_next().is_some() {}
        if !reader.pending() {
            due = None;
            pace = None;
        } else if due.is_none() {
            due = Some(Instant::now() + DEADLINE);
        }
        // A large body is read only once it holds its places; its deadline
        // runs from then, as the wait is the gateway's.
        if placed.is_none()
            && let Some(header) = reader.header()
            && let Some(length) = header.body(Framing::Stream)
            && large(header.kind, length)
        {
            // Its header takes its address's token: a header whose body
            // never comes costs one, as a whole frame does.
            if let Some(connection) = connection
                && !rated(port, connection)
            {
                return;
            }
            let Ok(Ok(taken)) =
                tokio::time::timeout(DEADLINE, port.caps.proven_wait(connection)).await
            else {
                // Past its connection's or circuit's proven calls: the
                // body is not read, so the channel's framing ends here.
                let (answered, answer) = busy(Kind::Credentialed);
                let bytes = frame(Framing::Stream, answered, header.id, &answer);
                write(&writer, &bytes, true).await;
                return;
            };
            placed = Some(taken);
            let started = Pace {
                from: Instant::now(),
                length: u64::from(length),
                read: 0,
            };
            due = Some(started.due());
            pace = Some(started);
        }
    }
}
