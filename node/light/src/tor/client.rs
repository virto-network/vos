//! The client: spaces, their routes, a connection a purpose, the spares,
//! dormancy, s4's screens and the onion set's refresh.
//!
//! Every connection is made under a [`Version`]: the space's routes as
//! they were and the awake period it opened in. A connection is used only
//! under the version it was made in, and a change of the space's routes or
//! a dormancy closes every connection of the old one, requests in flight
//! included, so none outlives the route it was chosen for.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;
use vos_api::Kind;
use vos_api::client::Answer;
use vos_wire::credentials::{MAX_ONIONS, Onion};

use super::connection::{Connection, OpenError};
use super::dial::{Circuit, Dial, Target, Unpublished};
use super::tally::{self, Dialed, Hour, Tally};
use super::{Config, SSH_PORT, onion_address};
use crate::route::{Purpose, Refused, Route, Routes};
use crate::{DeviceError, TreeKeeper, wire};

/// How long a feed query is good for, by the node's clock.
const FEED_TIME: Duration = Duration::from_secs(60);

/// The most pages one [`Client::read_tree`] reads, about 12 MiB: the
/// feed's length is the gateway's word, so a read ends however long it
/// says the feed is.
pub const FEED_PAGES: usize = 256;

/// A space, by its handle.
pub type SpaceId = [u8; 32];

/// The space's credential actor, whose registrar serves its onion set and
/// whose feed serves its tree.
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
    /// The connection was lost, missed the request's deadline, or was
    /// closed by a change of the space's routes, before the answer.
    Lost,
    /// The request is not a node-API request: no kind leads it.
    Malformed,
    /// A descriptor handed over could not be used.
    Local(String),
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
            Error::Local(why) => write!(f, "the descriptor: {why}"),
            Error::Answer(error) => write!(f, "the onion set: {error}"),
            Error::Onions => f.write_str("the registrar served no usable onion set"),
        }
    }
}

impl std::error::Error for Error {}

/// The routes and the awake period a connection was made under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Version {
    awake: u64,
    routes: u64,
}

/// A connection, and the version it was made under.
struct Held {
    version: Version,
    connection: Arc<Connection>,
}

/// A spare, and when it is closed unused.
struct Spare {
    held: Held,
    until: Instant,
}

impl Spare {
    /// Open, and not past its life.
    fn usable(&self, now: Instant) -> bool {
        !self.held.connection.is_closed() && now < self.until
    }
}

/// A kept-open group's connection, and when its last open failed.
#[derive(Default)]
struct Kept {
    held: Option<Held>,
    failed: Option<Instant>,
}

/// A kept-open purpose's connection in a space.
type Group = (Purpose, SpaceId);

/// A slot for a group's connection, held while it opens, so a group opens
/// one at a time.
type Slot = Arc<tokio::sync::Mutex<Kept>>;

/// What the client holds.
#[derive(Default)]
struct State {
    /// Each space's routes and their version.
    spaces: HashMap<SpaceId, (Routes, u64)>,
    /// The last routes' version given.
    versions: u64,
    groups: HashMap<Group, Slot>,
    /// Every open connection, by its space, closed when its routes change
    /// or the client goes dormant.
    live: Vec<(SpaceId, Weak<Connection>)>,
    /// The space spares are kept for, and the purposes kept one.
    spare_for: Option<SpaceId>,
    spare_purposes: Vec<Purpose>,
    /// Each purpose's spare once built.
    spares: HashMap<Purpose, Spare>,
    /// Moved each time spares are kept anew: a spare is kept, and taken,
    /// only under the keeping it was built for.
    spare_epoch: u64,
    /// The task building the spares, one at a time, and closing each at
    /// its life's end.
    building: Option<JoinHandle<()>>,
    /// That task waits for a life's end alone: a spare wanted meanwhile
    /// starts it anew.
    waiting: bool,
    /// The task closing idle connections.
    reaper: Option<JoinHandle<()>>,
    /// s4's screen session's space and carrying task.
    screens: Option<(SpaceId, JoinHandle<()>)>,
    dormant: bool,
    /// The app is in the foreground: spares are built only then.
    foreground: bool,
    /// Moved at each dormancy and each waking.
    awake: u64,
}

impl State {
    /// Close every connection of `space`, or of every space, its spare and
    /// its screens.
    fn close(&mut self, space: Option<SpaceId>) {
        let of = |other: &SpaceId| space.is_none_or(|space| space == *other);
        self.live.retain(|(other, connection)| {
            if !of(other) {
                return connection.strong_count() > 0;
            }
            if let Some(connection) = connection.upgrade() {
                connection.close();
            }
            false
        });
        self.groups.retain(|(_, other), _| !of(other));
        if self.spare_for.is_some_and(|spare| of(&spare)) {
            self.drop_spares();
        }
        if self.screens.as_ref().is_some_and(|(other, _)| of(other)) {
            let (_, task) = self.screens.take().expect("the screens");
            task.abort();
        }
    }

    /// Close every spare.
    fn drop_spares(&mut self) {
        for (_, spare) in self.spares.drain() {
            spare.held.connection.close();
        }
    }

    /// The space and the purpose the next spare is built for, if one is
    /// wanted: none while dormant or in the background.
    fn wanted(&self) -> Option<(SpaceId, Purpose)> {
        if self.dormant || !self.foreground {
            return None;
        }
        let space = self.spare_for?;
        let now = Instant::now();
        self.spare_purposes
            .iter()
            .copied()
            .find(|purpose| {
                !self
                    .spares
                    .get(purpose)
                    .is_some_and(|spare| spare.usable(now))
            })
            .map(|purpose| (space, purpose))
    }
}

/// The light node's client of its spaces' gateways. Cloned, it shares
/// them. Made and used on a tokio runtime, whose tasks it spawns.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

struct Inner {
    dial: Arc<dyn Dial>,
    config: Config,
    state: Mutex<State>,
    /// Where the next connection's onion is taken from in a pinned set.
    next: AtomicU64,
    /// What it opened, each hour.
    tally: Mutex<Tally>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let state = self.state.get_mut().expect("the client's state");
        state.close(None);
        for task in [state.building.take(), state.reaper.take()]
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
                next: AtomicU64::new(rand_u64()),
                tally: Mutex::new(Tally::default()),
            }),
        };
        client.start_reaper();
        client
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner.state.lock().expect("the client's state")
    }

    /// Set `space`'s routes; if they changed, its connections, spare and
    /// screens close, requests in flight on them included.
    pub fn set_space(&self, space: SpaceId, routes: Routes) {
        self.replace_routes(space, |current| *current = routes);
    }

    /// Change `space`'s routes by `change` (a new space starts from
    /// none), closing what the old ones opened if they changed.
    fn replace_routes(&self, space: SpaceId, change: impl FnOnce(&mut Routes)) {
        let mut state = self.state();
        let mut routes = state
            .spaces
            .get(&space)
            .map(|(routes, _)| routes.clone())
            .unwrap_or_default();
        let before = state.spaces.contains_key(&space).then(|| routes.clone());
        change(&mut routes);
        if before.as_ref() == Some(&routes) {
            return;
        }
        state.versions += 1;
        let version = state.versions;
        state.spaces.insert(space, (routes, version));
        state.close(Some(space));
        drop(state);
        self.refill();
    }

    /// `space`'s routes.
    pub fn routes(&self, space: &SpaceId) -> Option<Routes> {
        self.state()
            .spaces
            .get(space)
            .map(|(routes, _)| routes.clone())
    }

    /// Keep a spare connection built ahead to `space` for the next request
    /// of each of the one-shot `purposes`, or none, for a new keeper: the
    /// spares kept before, and any being built, are closed. The keeping's
    /// number, which [`Client::request_with`] takes a spare under.
    pub fn keep_spares(&self, space: Option<SpaceId>, purposes: &[Purpose]) -> u64 {
        let mut state = self.state();
        state.drop_spares();
        if let Some(task) = state.building.take() {
            task.abort();
        }
        state.spare_epoch += 1;
        state.spare_for = space;
        state.spare_purposes = match space {
            Some(_) => purposes
                .iter()
                .copied()
                .filter(|purpose| purpose.one_shot())
                .collect(),
            None => Vec::new(),
        };
        let epoch = state.spare_epoch;
        drop(state);
        self.refill();
        epoch
    }

    /// Whether `purpose`'s spare is built and open.
    pub fn spare_ready(&self, purpose: Purpose) -> bool {
        self.state()
            .spares
            .get(&purpose)
            .is_some_and(|spare| spare.usable(Instant::now()))
    }

    /// Dormant, or awake: dormant closes every connection (requests in
    /// flight end), the spares and the screens, stops every timer and tells
    /// arti; awake starts them again and builds the spares.
    pub fn set_dormant(&self, dormant: bool) {
        let mut state = self.state();
        if state.dormant == dormant {
            return;
        }
        state.dormant = dormant;
        state.awake += 1;
        if dormant {
            state.close(None);
            for task in [state.building.take(), state.reaper.take()]
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

    /// The app came to the foreground, or left it: what the client opens
    /// from now on is counted as the foreground's, or the background's.
    /// Spares are built only in the foreground: leaving it closes them.
    pub fn set_foreground(&self, foreground: bool) {
        self.tally().set_foreground(foreground);
        let mut state = self.state();
        if state.foreground == foreground {
            return;
        }
        state.foreground = foreground;
        if !foreground {
            state.drop_spares();
            if let Some(task) = state.building.take() {
                task.abort();
            }
        }
        drop(state);
        self.refill();
    }

    /// Whether the app is in the foreground, as last told.
    pub fn is_foreground(&self) -> bool {
        self.state().foreground
    }

    /// What the client opened, each of the last [`super::HOURS`] hours in
    /// which it opened anything, the newest last.
    pub fn opened(&self) -> Vec<Hour> {
        self.tally().hours()
    }

    /// Count in the hours a process before this one kept (its
    /// [`Client::opened`], encoded and kept by the app).
    pub fn restore_opened(&self, hours: &[Hour]) {
        self.tally().restore(hours);
    }

    fn tally(&self) -> std::sync::MutexGuard<'_, Tally> {
        self.inner.tally.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Count a connection to `target` for `purpose`, opened or failed.
    fn dialed(&self, target: &Target, purpose: Purpose, failed: bool) {
        let dialed = match target {
            Target::Onion { .. } => Dialed::Onion { purpose, failed },
            Target::Clearnet { .. } => Dialed::Clearnet,
        };
        self.tally().record(tally::now(), dialed);
    }

    /// Send `request` (its kind's two little-endian bytes, then its body,
    /// as [`crate::wire`] makes them) to `space` under `purpose`: its
    /// answer's kind and body. The policy decides first; a one-shot
    /// purpose's request takes its spare when one is built for the space,
    /// and the next is built after a drawn delay.
    pub async fn request(
        &self,
        space: SpaceId,
        purpose: Purpose,
        request: &[u8],
    ) -> Result<Answer, Error> {
        let epoch = self.state().spare_epoch;
        self.request_with(space, purpose, request, Some(epoch))
            .await
    }

    /// [`Client::request`], a spare taken only if one is kept under the
    /// keeping `spare` ([`Client::keep_spares`]'s number): a caller's
    /// requests take its own spares alone.
    pub async fn request_with(
        &self,
        space: SpaceId,
        purpose: Purpose,
        request: &[u8],
        spare: Option<u64>,
    ) -> Result<Answer, Error> {
        let (kind, body) = request.split_at_checked(2).ok_or(Error::Malformed)?;
        let kind =
            Kind::from_u16(u16::from_le_bytes([kind[0], kind[1]])).ok_or(Error::Malformed)?;
        if !purpose.admits(kind) {
            return Err(Refused::Kind.into());
        }
        let deadline = if kind == Kind::Credentialed {
            self.inner.config.proven
        } else {
            self.inner.config.request
        };
        let connection = if purpose.one_shot() {
            let (routes, route, version) = self.current(space, purpose)?;
            let spare = spare.and_then(|epoch| self.take_spare(space, purpose, version, epoch));
            self.refill();
            match spare {
                Some(spare) => spare,
                None => self.open(space, purpose, &routes, route, version).await?,
            }
        } else {
            self.kept((purpose, space)).await?
        };
        let answered = tokio::time::timeout(deadline, connection.request(kind as u16, body)).await;
        match answered {
            Ok(Ok(answer)) => {
                if purpose.one_shot() {
                    connection.close();
                }
                Ok(answer)
            }
            _ => {
                connection.close();
                Err(Error::Lost)
            }
        }
    }

    /// A kept-open group's connection, open under the space's current
    /// routes: the one held, or a new one. A request that waited while
    /// another's open failed fails with it, rather than trying again.
    async fn kept(&self, group: Group) -> Result<Arc<Connection>, Error> {
        let (purpose, space) = group;
        let slot = {
            let mut state = self.state();
            if state.dormant {
                return Err(Error::Dormant);
            }
            Arc::clone(state.groups.entry(group).or_default())
        };
        let waited = Instant::now();
        let mut kept = slot.lock().await;
        // The routes as they are now, after the wait.
        let (routes, route, version) = self.current(space, purpose)?;
        if let Some(held) = &kept.held
            && held.version == version
            && !held.connection.is_closed()
        {
            return Ok(Arc::clone(&held.connection));
        }
        if kept.failed.is_some_and(|failed| failed > waited) {
            return Err(Error::Unreachable(
                "the connection another request opened failed".into(),
            ));
        }
        match self.open(space, purpose, &routes, route, version).await {
            Ok(connection) => {
                kept.held = Some(Held {
                    version,
                    connection: Arc::clone(&connection),
                });
                kept.failed = None;
                Ok(connection)
            }
            Err(error) => {
                kept.failed = Some(Instant::now());
                Err(error)
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
        let (routes, route, version) = self.current(space, Purpose::Screens)?;
        let (mut gateway, ssh_host_key) = self.connect(&routes, route).await?;
        let mut state = self.state();
        Self::still(&state, space, version)?;
        let task = tokio::spawn(async move {
            let mut stream = stream;
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut gateway).await;
        });
        if let Some((_, last)) = state.screens.replace((space, task)) {
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
            .map_err(|error| Error::Local(error.to_string()))?;
        let stream = tokio::net::UnixStream::from_std(stream)
            .map_err(|error| Error::Local(error.to_string()))?;
        self.screens(space, stream).await
    }

    /// Whether s4's screen session is being carried.
    pub fn screens_open(&self) -> bool {
        self.state()
            .screens
            .as_ref()
            .is_some_and(|(_, task)| !task.is_finished())
    }

    /// Read `space`'s onion set from its registrar, through the pinned set,
    /// as fetches of their own, no spare among them; a usable set replaces
    /// the pinned one and is returned, for the app to keep.
    pub async fn refresh_onions(
        &self,
        space: SpaceId,
        registrar: &Registrar,
    ) -> Result<Vec<Onion>, Error> {
        let (_, time) = self
            .request_with(space, Purpose::Fetch, &wire::time_request(), None)
            .await?;
        let now = wire::time_answer(&time).map_err(Error::Answer)?;
        let query = wire::query_request(
            registrar.agent,
            &registrar.identity,
            registrar.instance,
            vos_wire::credentials::method::ONIONS,
            Vec::new(),
            now + 60_000,
        )
        .map_err(Error::Answer)?;
        let (_, answer) = self
            .request_with(space, Purpose::Fetch, &query, None)
            .await?;
        let onions: Vec<Onion> = wire::query_answer(&answer).map_err(Error::Answer)?;
        let repeated = onions
            .iter()
            .enumerate()
            .any(|(at, onion)| onions[..at].iter().any(|seen| seen.key == onion.key));
        if onions.is_empty() || onions.len() > MAX_ONIONS || repeated {
            return Err(Error::Onions);
        }
        if !self.state().spaces.contains_key(&space) {
            return Err(Refused::UnknownSpace.into());
        }
        let fresh = onions.clone();
        self.replace_routes(space, move |routes| routes.onions = fresh);
        Ok(onions)
    }

    /// Read `space`'s credential tree into `keeper` from the feed of its
    /// credential actor (`credentials`), on the space's feed connection:
    /// the node's time, for the queries' life, then each page from the
    /// keeper's place until the feed holds no more, or [`FEED_PAGES`] pages
    /// (the keeper then due at once), the time read again for a page past
    /// half a query's life. The keeper's timer runs on this device's clock
    /// (`now_ms`, milliseconds). The changes applied; a page refused leaves
    /// the tree as the pages before it left it. The caller reads it when
    /// [`TreeKeeper::due`] says, never because a proof is about to be made.
    pub async fn read_tree(
        &self,
        space: SpaceId,
        credentials: &Registrar,
        keeper: &mut TreeKeeper,
        now_ms: impl Fn() -> u64,
    ) -> Result<u64, Error> {
        let mut applied = 0;
        let mut time: Option<(u64, Instant)> = None;
        for _ in 0..FEED_PAGES {
            let node = match time {
                Some((node, at)) if at.elapsed() < FEED_TIME / 2 => node,
                _ => {
                    let (_, answer) = self
                        .request(space, Purpose::Feed, &wire::time_request())
                        .await?;
                    let node = wire::time_answer(&answer).map_err(Error::Answer)?;
                    time = Some((node, Instant::now()));
                    node
                }
            };
            let query = keeper
                .request(
                    credentials.agent,
                    &credentials.identity,
                    credentials.instance,
                    node + FEED_TIME.as_millis() as u64,
                )
                .map_err(Error::Answer)?;
            let (_, answer) = self.request(space, Purpose::Feed, &query).await?;
            let read = keeper.ingest(&answer, now_ms()).map_err(Error::Answer)?;
            applied += read.applied;
            if !read.more {
                break;
            }
        }
        Ok(applied)
    }

    /// `space`'s routes, the route `purpose` takes there, and the version
    /// a connection for it is made under.
    fn current(&self, space: SpaceId, purpose: Purpose) -> Result<(Routes, Route, Version), Error> {
        let state = self.state();
        if state.dormant {
            return Err(Error::Dormant);
        }
        let (routes, version) = state.spaces.get(&space).ok_or(Refused::UnknownSpace)?;
        let route = routes.route(purpose)?;
        Ok((
            routes.clone(),
            route,
            Version {
                awake: state.awake,
                routes: *version,
            },
        ))
    }

    /// Whether `version` is still `space`'s: refused when the client went
    /// dormant, or the routes changed, since.
    fn still(state: &State, space: SpaceId, version: Version) -> Result<(), Error> {
        if state.dormant {
            return Err(Error::Dormant);
        }
        let routes = state.spaces.get(&space).map(|(_, version)| *version);
        if state.awake != version.awake || routes != Some(version.routes) {
            return Err(Error::Lost);
        }
        Ok(())
    }

    /// `purpose`'s spare, for a request to `space` under `version` by the
    /// keeping `epoch`, if it is built and still open: taken, so it carries
    /// this request alone.
    fn take_spare(
        &self,
        space: SpaceId,
        purpose: Purpose,
        version: Version,
        epoch: u64,
    ) -> Option<Arc<Connection>> {
        let mut state = self.state();
        if state.spare_for != Some(space) || state.spare_epoch != epoch {
            return None;
        }
        let spare = state.spares.remove(&purpose)?;
        if spare.held.version == version && spare.usable(Instant::now()) {
            return Some(spare.held.connection);
        }
        spare.held.connection.close();
        None
    }

    /// Keep the spares: build each wanted, one at a time, each after a
    /// delay drawn below [`Config::spare_gap`]; close each at the end of its
    /// own drawn life, and build it anew. Unless a builder runs.
    fn refill(&self) {
        let mut state = self.state();
        let building = state
            .building
            .as_ref()
            .is_some_and(|task| !task.is_finished());
        let wanted = state.wanted().is_some();
        if building && !(state.waiting && wanted) {
            return;
        }
        if let Some(task) = state.building.take() {
            task.abort();
        }
        state.waiting = false;
        if !wanted && state.spares.is_empty() {
            return;
        }
        let (client, config) = (Arc::downgrade(&self.inner), self.inner.config);
        state.building = Some(tokio::spawn(async move {
            loop {
                let next = {
                    let Some(inner) = client.upgrade() else {
                        return;
                    };
                    let mut state = inner.state.lock().expect("the client's state");
                    let next = match state.wanted() {
                        Some(wanted) => Ok(wanted),
                        None => Err(state.spares.values().map(|spare| spare.until).min()),
                    };
                    state.waiting = next.is_err();
                    next
                };
                let (space, purpose) = match next {
                    Ok(wanted) => wanted,
                    Err(None) => return,
                    Err(Some(until)) => {
                        // The next spare's life ends: closed then, at its
                        // own drawn time, and built anew.
                        tokio::time::sleep_until(until.into()).await;
                        let Some(inner) = client.upgrade() else {
                            return;
                        };
                        let mut state = inner.state.lock().expect("the client's state");
                        let now = Instant::now();
                        state.spares.retain(|_, spare| {
                            let usable = spare.usable(now);
                            if !usable {
                                spare.held.connection.close();
                            }
                            usable
                        });
                        continue;
                    }
                };
                tokio::time::sleep(below(config.spare_gap)).await;
                let Some(inner) = client.upgrade() else {
                    return;
                };
                let client = Client { inner };
                let (wanted, epoch) = {
                    let state = client.state();
                    (state.wanted(), state.spare_epoch)
                };
                if wanted != Some((space, purpose)) {
                    continue;
                }
                let Ok((routes, Route::Onion, version)) = client.current(space, purpose) else {
                    return;
                };
                let Ok(connection) = client
                    .open(space, purpose, &routes, Route::Onion, version)
                    .await
                else {
                    return;
                };
                let mut state = client.state();
                // Kept for whom it was opened for alone: not for a keeper
                // that came since.
                let wanted = state.wanted() == Some((space, purpose))
                    && state.spare_epoch == epoch
                    && Self::still(&state, space, version).is_ok();
                if !wanted {
                    connection.close();
                    continue;
                }
                let life = config.spare_idle / 2 + below(config.spare_idle);
                state.spares.insert(
                    purpose,
                    Spare {
                        held: Held {
                            version,
                            connection,
                        },
                        until: Instant::now() + life,
                    },
                );
            }
        }));
    }

    /// Close kept-open connections idle past their time, each half of it;
    /// a spare whose build failed is tried again then.
    fn start_reaper(&self) {
        let client = Arc::downgrade(&self.inner);
        let idle = self.inner.config.idle;
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep((idle / 2).max(Duration::from_millis(100))).await;
                let Some(inner) = client.upgrade() else {
                    return;
                };
                Client {
                    inner: Arc::clone(&inner),
                }
                .refill();
                let slots: Vec<Slot> = {
                    let state = inner.state.lock().expect("the client's state");
                    state.groups.values().cloned().collect()
                };
                for slot in slots {
                    // A slot held is in use, or opening.
                    let Ok(mut kept) = slot.try_lock() else {
                        continue;
                    };
                    let stale = kept.held.as_ref().is_some_and(|held| {
                        held.connection.is_closed() || held.connection.last().elapsed() >= idle
                    });
                    if stale && let Some(held) = kept.held.take() {
                        held.connection.close();
                    }
                }
            }
        });
        if let Some(last) = self.state().reaper.replace(task) {
            last.abort();
        }
    }

    /// A new connection to `space` on `route` under `version`, its
    /// `vos-api` channel open; each failed attempt retried on a new
    /// circuit, through the next pinned onion. Refused, and closed, if the
    /// version is no longer the space's once it opened.
    async fn open(
        &self,
        space: SpaceId,
        purpose: Purpose,
        routes: &Routes,
        route: Route,
        version: Version,
    ) -> Result<Arc<Connection>, Error> {
        let config = self.inner.config;
        let mut last = String::from("no attempt");
        let mut unpublished = true;
        let attempts = config.attempts.max(1) as u64;
        let turn = self.inner.next.fetch_add(attempts + 1, Ordering::Relaxed);
        for attempt in 0..=attempts {
            if attempt == attempts {
                // Every attempt found the service unpublished: once more,
                // after a pause.
                if !unpublished {
                    break;
                }
                tokio::time::sleep(config.again).await;
                if self.is_dormant() {
                    return Err(Error::Dormant);
                }
            }
            let (target, host_key) = Self::target(routes, route, turn + attempt)?;
            let circuit = Circuit::new();
            let opened = async {
                let stream =
                    tokio::time::timeout(config.connect, self.inner.dial.dial(&target, circuit))
                        .await
                        .map_err(|_| ("the connection's deadline passed".to_string(), false))?
                        .map_err(|error| (error.to_string(), Unpublished::is(&error)))?;
                tokio::time::timeout(config.handshake, Connection::open(stream, host_key))
                    .await
                    .map_err(|_| "the SSH handshake's deadline passed".to_string())
                    .and_then(|opened| {
                        opened.map_err(|error| match error {
                            OpenError::Ssh(error) => error.to_string(),
                            OpenError::Refused => "the gateway refused the SSH session".into(),
                            OpenError::Randomness => "no randomness".into(),
                        })
                    })
                    .map_err(|why| (why, false))
            };
            let opened = opened.await;
            self.dialed(&target, purpose, opened.is_err());
            let mut state = self.state();
            Self::still(&state, space, version)?;
            match opened {
                Ok(connection) => {
                    let connection = Arc::new(connection);
                    state.live.retain(|(_, live)| live.strong_count() > 0);
                    state.live.push((space, Arc::downgrade(&connection)));
                    return Ok(connection);
                }
                Err((why, was)) => {
                    last = why;
                    unpublished &= was;
                }
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
        let mut unpublished = true;
        let attempts = config.attempts.max(1) as u64;
        let turn = self.inner.next.fetch_add(attempts + 1, Ordering::Relaxed);
        for attempt in 0..=attempts {
            if attempt == attempts {
                if !unpublished {
                    break;
                }
                tokio::time::sleep(config.again).await;
            }
            if self.is_dormant() {
                return Err(Error::Dormant);
            }
            let (target, host_key) = Self::target(routes, route, turn + attempt)?;
            let dialed = tokio::time::timeout(
                config.connect,
                self.inner.dial.dial(&target, Circuit::new()),
            )
            .await;
            self.dialed(&target, Purpose::Screens, !matches!(dialed, Ok(Ok(_))));
            match dialed {
                Ok(Ok(stream)) => return Ok((stream, host_key)),
                Ok(Err(error)) => {
                    unpublished &= Unpublished::is(&error);
                    last = error;
                }
                Err(_) => {
                    unpublished = false;
                    last = io::Error::other("the connection's deadline passed");
                }
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
                    return Err(Refused::NoOnion.into());
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
/// set's rotation starts, and the spares' draws.
fn rand_u64() -> u64 {
    let mut bytes = [0u8; 8];
    let _ = getrandom::getrandom(&mut bytes);
    u64::from_le_bytes(bytes)
}

/// A uniform draw below `period`.
fn below(period: Duration) -> Duration {
    Duration::from_micros(rand_u64() % (period.as_micros() as u64).max(1))
}
