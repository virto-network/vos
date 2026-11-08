//! The client: spaces, their routes, a connection a purpose, the spare,
//! dormancy, s4's screens and the onion set's refresh.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::task::JoinHandle;
use vos_api::Kind;
use vos_api::client::Answer;
use vos_wire::credentials::{MAX_ONIONS, Onion};

use super::connection::{Connection, OpenError};
use super::dial::{Circuit, Dial, Target};
use super::{Config, SSH_PORT, onion_address};
use crate::route::{Purpose, Refused, Route, Routes};
use crate::{DeviceError, wire};

/// A space, by its handle.
pub type SpaceId = [u8; 32];

/// The space's credential actor, whose registrar serves its onion set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registrar {
    pub agent: u32,
    pub instance: u32,
    /// The agent's identity, which a query's signature covers.
    pub identity: [u8; 32],
}

/// Why a request got no answer.
#[derive(Debug)]
pub enum Error {
    /// The policy sent nothing.
    Refused(Refused),
    /// The client is dormant: nothing leaves until it is woken.
    Dormant,
    /// No connection opened within its attempts: the last one's failure.
    Unreachable(String),
    /// The connection was lost, or missed the request's deadline, before
    /// the answer: it is closed.
    Lost,
    /// The request is not a node-API request: no kind leads it.
    Malformed,
    /// The registrar's answer to the onion set's refresh.
    Answer(DeviceError),
    /// The registrar served an empty set, or one past [`MAX_ONIONS`] or
    /// naming an onion twice: the pinned set is kept.
    Onions,
}

impl From<Refused> for Error {
    fn from(refused: Refused) -> Self {
        Error::Refused(refused)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Refused(refused) => refused.fmt(f),
            Error::Dormant => f.write_str("Tor is dormant"),
            Error::Unreachable(why) => write!(f, "the space's gateways do not answer: {why}"),
            Error::Lost => f.write_str("the connection was lost"),
            Error::Malformed => f.write_str("not a node-API request"),
            Error::Answer(error) => write!(f, "the onion set: {error:?}"),
            Error::Onions => f.write_str("the registrar served no usable onion set"),
        }
    }
}

impl std::error::Error for Error {}

/// A kept-open purpose's connection in a space.
type Group = (Purpose, SpaceId);

/// A slot for a group's connection, held while it opens, so a group opens
/// one at a time.
type Slot = Arc<tokio::sync::Mutex<Option<Arc<Connection>>>>;

/// What the client holds.
#[derive(Default)]
struct State {
    spaces: HashMap<SpaceId, Routes>,
    groups: HashMap<Group, Slot>,
    /// The space the spare is kept for, and the spare once built.
    spare_for: Option<SpaceId>,
    spare: Option<Arc<Connection>>,
    /// The task building the spare.
    building: Option<JoinHandle<()>>,
    /// The task closing idle connections.
    reaper: Option<JoinHandle<()>>,
    /// s4's screen session's carrying task.
    screens: Option<JoinHandle<()>>,
    dormant: bool,
}

/// The light node's client of its spaces' gateways. Cloned, it shares
/// them. Its tasks run on the current tokio runtime.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

struct Inner {
    dial: Arc<dyn Dial>,
    config: Config,
    state: Mutex<State>,
    /// Moved at each dormancy: a connection opened across one is dropped.
    epoch: AtomicU64,
    /// Where the next connection's onion is taken from in a pinned set.
    next: AtomicU64,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let state = self.state.get_mut().expect("the client's state");
        for task in [
            state.building.take(),
            state.reaper.take(),
            state.screens.take(),
        ]
        .into_iter()
        .flatten()
        {
            task.abort();
        }
    }
}

/// s4's screen session, carried.
pub struct Screens {
    /// The SSH host key the gateway's port presents, for s4 to pin.
    pub ssh_host_key: [u8; 32],
    /// The route it took.
    pub route: Route,
}

impl Client {
    /// A client dialing through `dial` (the process's [`super::Tor`]),
    /// awake.
    pub fn new(dial: Arc<dyn Dial>, config: Config) -> Self {
        let client = Self {
            inner: Arc::new(Inner {
                dial,
                config,
                state: Mutex::new(State::default()),
                epoch: AtomicU64::new(0),
                next: AtomicU64::new(rand_u64()),
            }),
        };
        client.start_reaper();
        client
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner.state.lock().expect("the client's state")
    }

    /// Set `space`'s routes; its connections close if its routes changed.
    pub fn set_space(&self, space: SpaceId, routes: Routes) {
        let mut state = self.state();
        if state.spaces.get(&space) == Some(&routes) {
            return;
        }
        state.spaces.insert(space, routes);
        state.groups.retain(|(_, of), _| *of != space);
        if state.spare_for == Some(space) {
            state.spare = None;
        }
        drop(state);
        self.refill();
    }

    /// `space`'s routes.
    pub fn routes(&self, space: &SpaceId) -> Option<Routes> {
        self.state().spaces.get(space).cloned()
    }

    /// Keep a spare connection built ahead to `space` for its next proven
    /// call, or none.
    pub fn keep_spare(&self, space: Option<SpaceId>) {
        let mut state = self.state();
        if state.spare_for != space {
            state.spare = None;
            state.spare_for = space;
        }
        drop(state);
        self.refill();
    }

    /// Whether the spare is built and open.
    pub fn spare_ready(&self) -> bool {
        self.state()
            .spare
            .as_ref()
            .is_some_and(|spare| !spare.is_closed())
    }

    /// Dormant, or awake: dormant closes every connection, drops the spare
    /// and the screens, stops every timer and tells arti; awake starts them
    /// again and builds the spare.
    pub fn set_dormant(&self, dormant: bool) {
        let mut state = self.state();
        if state.dormant == dormant {
            return;
        }
        state.dormant = dormant;
        self.inner.epoch.fetch_add(1, Ordering::SeqCst);
        if dormant {
            state.groups.clear();
            state.spare = None;
            for task in [
                state.building.take(),
                state.reaper.take(),
                state.screens.take(),
            ]
            .into_iter()
            .flatten()
            {
                task.abort();
            }
        }
        drop(state);
        self.inner.dial.set_dormant(dormant);
        if !dormant {
            self.start_reaper();
            self.refill();
        }
    }

    /// Whether the client is dormant.
    pub fn is_dormant(&self) -> bool {
        self.state().dormant
    }

    /// Send `request` (its kind's two little-endian bytes, then its body,
    /// as [`crate::wire`] makes them) to `space` under `purpose`: its
    /// answer's kind and body. The policy decides first; a proven call
    /// takes the spare when one is built for the space.
    pub async fn request(
        &self,
        space: SpaceId,
        purpose: Purpose,
        request: &[u8],
    ) -> Result<Answer, Error> {
        let (kind, body) = request.split_at_checked(2).ok_or(Error::Malformed)?;
        let kind =
            Kind::from_u16(u16::from_le_bytes([kind[0], kind[1]])).ok_or(Error::Malformed)?;
        if !purpose.admits(kind) {
            return Err(Refused::Kind.into());
        }
        let routes = self.space(&space)?;
        let route = routes.route(purpose)?;
        let deadline = if kind == Kind::Credentialed {
            self.inner.config.proven
        } else {
            self.inner.config.request
        };
        if purpose.one_shot() {
            let connection = match self.take_spare(space, purpose, route) {
                Some(spare) => spare,
                None => Arc::new(self.open(&routes, route).await?),
            };
            let answered =
                tokio::time::timeout(deadline, connection.request(kind as u16, body)).await;
            drop(connection);
            if purpose == Purpose::Proven {
                self.refill();
            }
            return answered.map_err(|_| Error::Lost)?.map_err(|_| Error::Lost);
        }
        let slot = self.slot((purpose, space))?;
        let connection = {
            let mut held = slot.lock().await;
            match held.as_ref() {
                Some(connection) if !connection.is_closed() => Arc::clone(connection),
                _ => {
                    let connection = Arc::new(self.open(&routes, route).await?);
                    *held = Some(Arc::clone(&connection));
                    connection
                }
            }
        };
        match tokio::time::timeout(deadline, connection.request(kind as u16, body)).await {
            Ok(Ok(answer)) => Ok(answer),
            _ => {
                // Lost, or past its deadline: the connection goes.
                let mut held = slot.lock().await;
                if held
                    .as_ref()
                    .is_some_and(|held| Arc::ptr_eq(held, &connection))
                {
                    *held = None;
                }
                Err(Error::Lost)
            }
        }
    }

    /// Carry s4's screen session between `stream` and `space`'s gateway,
    /// on a circuit of its own (one session at a time: a new one ends the
    /// last). s4 speaks SSH over it itself, pinning the host key returned.
    pub async fn screens<S>(&self, space: SpaceId, stream: S) -> Result<Screens, Error>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let routes = self.space(&space)?;
        let route = routes.route(Purpose::Screens)?;
        let (mut gateway, ssh_host_key) = self.connect(&routes, route).await?;
        let task = tokio::spawn(async move {
            let mut stream = stream;
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut gateway).await;
        });
        let mut state = self.state();
        if state.dormant {
            task.abort();
            return Err(Error::Dormant);
        }
        if let Some(last) = state.screens.replace(task) {
            last.abort();
        }
        Ok(Screens {
            ssh_host_key,
            route,
        })
    }

    /// [`Client::screens`] over a descriptor s4 hands over: one end of a
    /// socketpair (Android's `ParcelFileDescriptor`, detached).
    #[cfg(unix)]
    pub async fn screens_fd(
        &self,
        space: SpaceId,
        descriptor: std::os::fd::OwnedFd,
    ) -> Result<Screens, Error> {
        let stream = std::os::unix::net::UnixStream::from(descriptor);
        stream
            .set_nonblocking(true)
            .map_err(|error| Error::Unreachable(error.to_string()))?;
        let stream = tokio::net::UnixStream::from_std(stream)
            .map_err(|error| Error::Unreachable(error.to_string()))?;
        self.screens(space, stream).await
    }

    /// Whether s4's screen session is being carried.
    pub fn screens_open(&self) -> bool {
        self.state()
            .screens
            .as_ref()
            .is_some_and(|task| !task.is_finished())
    }

    /// Read `space`'s onion set from its registrar, through the pinned set,
    /// as a fetch of its own; a usable set replaces the pinned one and is
    /// returned, for the app to keep.
    pub async fn refresh_onions(
        &self,
        space: SpaceId,
        registrar: &Registrar,
    ) -> Result<Vec<Onion>, Error> {
        let (_, time) = self
            .request(space, Purpose::Fetch, &wire::time_request())
            .await?;
        let now = wire::time_answer(&time).map_err(Error::Answer)?;
        let query = wire::query_request(
            registrar.agent,
            &registrar.identity,
            registrar.instance,
            "onions",
            Vec::new(),
            now + 60_000,
        )
        .map_err(Error::Answer)?;
        let (_, answer) = self.request(space, Purpose::Fetch, &query).await?;
        let onions: Vec<Onion> = wire::query_answer(&answer).map_err(Error::Answer)?;
        let repeated = onions
            .iter()
            .enumerate()
            .any(|(at, onion)| onions[..at].iter().any(|seen| seen.key == onion.key));
        if onions.is_empty() || onions.len() > MAX_ONIONS || repeated {
            return Err(Error::Onions);
        }
        let mut state = self.state();
        let routes = state.spaces.get_mut(&space).ok_or(Refused::UnknownSpace)?;
        if routes.onions != onions {
            routes.onions = onions.clone();
            state.groups.retain(|(_, of), _| *of != space);
            if state.spare_for == Some(space) {
                state.spare = None;
            }
            drop(state);
            self.refill();
        }
        Ok(onions)
    }

    fn space(&self, space: &SpaceId) -> Result<Routes, Error> {
        let state = self.state();
        if state.dormant {
            return Err(Error::Dormant);
        }
        Ok(state
            .spaces
            .get(space)
            .cloned()
            .ok_or(Refused::UnknownSpace)?)
    }

    fn slot(&self, group: Group) -> Result<Slot, Error> {
        let mut state = self.state();
        if state.dormant {
            return Err(Error::Dormant);
        }
        Ok(Arc::clone(state.groups.entry(group).or_default()))
    }

    /// The spare, for a proven call to `space` on the onion, if it is built
    /// and still open.
    fn take_spare(
        &self,
        space: SpaceId,
        purpose: Purpose,
        route: Route,
    ) -> Option<Arc<Connection>> {
        if purpose != Purpose::Proven || route != Route::Onion {
            return None;
        }
        let mut state = self.state();
        if state.spare_for != Some(space) {
            return None;
        }
        state.spare.take().filter(|spare| !spare.is_closed())
    }

    /// Build the spare if one is wanted and none is built or building.
    fn refill(&self) {
        let mut state = self.state();
        let Some(space) = state.spare_for else {
            return;
        };
        let building = state
            .building
            .as_ref()
            .is_some_and(|task| !task.is_finished());
        let built = state.spare.as_ref().is_some_and(|spare| !spare.is_closed());
        if state.dormant || building || built {
            return;
        }
        let Some(routes) = state.spaces.get(&space).cloned() else {
            return;
        };
        if routes.route(Purpose::Proven) != Ok(Route::Onion) {
            return;
        }
        let client = Arc::downgrade(&self.inner);
        state.building = Some(tokio::spawn(async move {
            let Some(inner) = client.upgrade() else {
                return;
            };
            let client = Client { inner };
            let epoch = client.inner.epoch.load(Ordering::SeqCst);
            let Ok(spare) = client.open(&routes, Route::Onion).await else {
                return;
            };
            let mut state = client.state();
            if client.inner.epoch.load(Ordering::SeqCst) == epoch
                && state.spare_for == Some(space)
                && state.spaces.get(&space) == Some(&routes)
            {
                state.spare = Some(Arc::new(spare));
            }
        }));
    }

    /// Close kept-open connections idle past their time, each half of it.
    fn start_reaper(&self) {
        let client = Arc::downgrade(&self.inner);
        let idle = self.inner.config.idle;
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(idle / 2).await;
                let Some(inner) = client.upgrade() else {
                    return;
                };
                let slots: Vec<Slot> = {
                    let state = inner.state.lock().expect("the client's state");
                    state.groups.values().cloned().collect()
                };
                for slot in slots {
                    let Ok(mut held) = slot.try_lock() else {
                        continue;
                    };
                    let stale = held
                        .as_ref()
                        .is_some_and(|held| held.is_closed() || held.last().elapsed() >= idle);
                    if stale {
                        *held = None;
                    }
                }
            }
        });
        if let Some(last) = self.state().reaper.replace(task) {
            last.abort();
        }
    }

    /// A new connection to the space on `route`, its `vos-api` channel
    /// open; each failed attempt retried on a new circuit, through the
    /// next pinned onion.
    async fn open(&self, routes: &Routes, route: Route) -> Result<Connection, Error> {
        let config = self.inner.config;
        let epoch = self.inner.epoch.load(Ordering::SeqCst);
        let mut last = String::from("no attempt");
        let turn = self
            .inner
            .next
            .fetch_add(config.attempts as u64, Ordering::Relaxed);
        for attempt in 0..config.attempts.max(1) as u64 {
            let (target, host_key) = Self::target(routes, route, turn + attempt)?;
            let circuit = Circuit::new();
            let opened = async {
                let stream =
                    tokio::time::timeout(config.connect, self.inner.dial.dial(&target, circuit))
                        .await
                        .map_err(|_| "the connection's deadline passed".to_string())?
                        .map_err(|error| error.to_string())?;
                tokio::time::timeout(config.handshake, Connection::open(stream, host_key))
                    .await
                    .map_err(|_| "the SSH handshake's deadline passed".to_string())?
                    .map_err(|error| match error {
                        OpenError::Ssh(error) => error.to_string(),
                        OpenError::Refused => "the gateway refused the SSH session".into(),
                        OpenError::Randomness => "no randomness".into(),
                    })
            };
            match opened.await {
                Ok(connection) => {
                    if self.inner.epoch.load(Ordering::SeqCst) != epoch {
                        return Err(Error::Dormant);
                    }
                    return Ok(connection);
                }
                Err(why) => last = why,
            }
            if self.inner.epoch.load(Ordering::SeqCst) != epoch {
                return Err(Error::Dormant);
            }
        }
        Err(Error::Unreachable(last))
    }

    /// A raw stream to the space on `route`, for s4's own SSH, retried on
    /// a new circuit as [`Client::open`]'s: the stream and the host key
    /// to pin.
    async fn connect(
        &self,
        routes: &Routes,
        route: Route,
    ) -> Result<(super::Stream, [u8; 32]), Error> {
        let config = self.inner.config;
        let mut last = io::Error::other("no attempt");
        let turn = self
            .inner
            .next
            .fetch_add(config.attempts as u64, Ordering::Relaxed);
        for attempt in 0..config.attempts.max(1) as u64 {
            let (target, host_key) = Self::target(routes, route, turn + attempt)?;
            match tokio::time::timeout(
                config.connect,
                self.inner.dial.dial(&target, Circuit::new()),
            )
            .await
            {
                Ok(Ok(stream)) => return Ok((stream, host_key)),
                Ok(Err(error)) => last = error,
                Err(_) => last = io::Error::other("the connection's deadline passed"),
            }
        }
        Err(Error::Unreachable(last.to_string()))
    }

    /// Where the `turn`th connection goes: the pinned set's onion that
    /// turn names, so each attempt takes the next; or the clearnet port.
    fn target(routes: &Routes, route: Route, turn: u64) -> Result<(Target, [u8; 32]), Error> {
        match route {
            Route::Onion => {
                let count = routes.onions.len() as u64;
                if count == 0 {
                    return Err(Refused::OnionOnly.into());
                }
                let onion = routes.onions[(turn % count) as usize];
                Ok((
                    Target::Onion {
                        address: onion_address(&onion.key),
                        port: SSH_PORT,
                    },
                    onion.ssh_host_key,
                ))
            }
            Route::Clearnet => {
                let clearnet = routes.clearnet.as_ref().ok_or(Refused::NoClearnet)?;
                Ok((
                    Target::Clearnet {
                        host: clearnet.host.clone(),
                        port: clearnet.port,
                    },
                    clearnet.ssh_host_key,
                ))
            }
        }
    }
}

/// A random 64-bit number, or zero without randomness: where a pinned
/// set's rotation starts.
fn rand_u64() -> u64 {
    let mut bytes = [0u8; 8];
    let _ = getrandom::getrandom(&mut bytes);
    u64::from_le_bytes(bytes)
}
