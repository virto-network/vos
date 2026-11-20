// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! How the facility reaches its spaces (VOS's `light-node.md` §6.2, §6.5):
//! one `vos_light::tor::Client` for the process, every request under its
//! purpose, its own circuit and SSH key.
//!
//! - **Tor for every space** [E22]: each space's routes are its pinned
//!   onions, the clearnet port of the gateway it was enrolled through (if
//!   it pinned that port's host key) and whether it declared itself
//!   onion-only. Only key-signed calls may take the clearnet, and only for
//!   a space the user opted out of Tor after the plain warning
//!   ([`OPT_OUT_WARNING`]); a proof, a read that prepares one, the
//!   personal agent's and `Homes`' traffic never do (`vos_light::route`).
//! - **What is kept**, rows of the facility's database ([`crate::kept`]):
//!   each space's onion set as its registrar last served it, the user's
//!   opt-out ([`ROUTES`]), and the bridges pasted in the chrome
//!   ([`BRIDGES`]). A space's enrollment pins its first set; a refresh's
//!   replaces it. A database this build does not read leaves each space
//!   its pinned routes (Tor) and refuses every change, so nothing in it
//!   is written over.
//! - **One arti a process** ([`Arti`]): its state in the app's private
//!   files, its bridges replaced by building it anew.
//! - **What a run read and wrote** ([`Count`]): every stream of the
//!   client's dial counts its bytes, so the background job's runs say what
//!   they cost whatever carried them.
//! - **A gateway spelled another way** ([`Net::onion_pinned`]): a host key
//!   a space pinned to its onion is that space's gateway however its name
//!   is written, so s4 never reaches it over the clearnet itself.
//! - **The rendezvous an hour** ([`RENDEZVOUS`]): the client's tally of
//!   the onion connections it opened, in the foreground and in the
//!   background, written beside the enrollments for the bound on
//!   rendezvous an hour and counted in again when the process starts anew.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use vos_abi::{Decode, Encode};
use vos_light::route::{Clearnet, Purpose, Refused, Routes};
use vos_light::tor::{BootstrapError, Circuit, Client, Config, Dial, Dialing, Registrar, Target};
use vos_light::tor::{Hour, Tor, TorConfig};
use vos_wire::credentials::Onion;

use crate::enrollment::write_private;
use crate::kept::Kept;

pub use vos_light::route::OPT_OUT_WARNING;
pub use vos_light::tor::SpaceId;

/// Each space's routes' row: this prefix, then the space's id.
pub const ROUTES: &[u8] = b"routes/";

/// The bridges' row.
pub const BRIDGES: &[u8] = b"bridges";

/// The client's rendezvous, an hour a line, beside the enrollments.
pub const RENDEZVOUS: &str = "rendezvous.txt";

/// The same hours encoded, counted in again when the process starts anew.
const RENDEZVOUS_KEPT: &str = "rendezvous.state";

/// A space's routes as kept: its onion set, and the user's opt-out.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
struct Route {
    onions: Vec<Onion>,
    opted_out: bool,
    /// When the registrar's set was last read, by the device's clock.
    onions_ms: u64,
}

/// How often a space's onion set is read again from its registrar.
pub const ONIONS_EVERY_MS: u64 = 24 * 60 * 60 * 1000;

/// What the routes' rows hold, read at the start: by the space's id.
#[derive(Debug, Default)]
struct State {
    spaces: BTreeMap<SpaceId, Route>,
    bridges: Vec<String>,
}

fn route_key(space: &SpaceId) -> Vec<u8> {
    [ROUTES, space.as_slice()].concat()
}

/// What `kept` holds of the routes.
fn read(kept: &Kept) -> Result<State, String> {
    let mut spaces = BTreeMap::new();
    for (key, route) in kept.under::<Route>(ROUTES)? {
        let space = SpaceId::try_from(&key[ROUTES.len()..])
            .map_err(|_| "the facility's database needs repair: a route's key is not a space's")?;
        spaces.insert(space, route);
    }
    let bridges = kept.get(BRIDGES)?.unwrap_or_default();
    Ok(State { spaces, bridges })
}

/// What a space pins: its onions, the gateway's clearnet port with its
/// host key if enrollment pinned one, and whether it is onion-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pinned {
    pub onions: Vec<Onion>,
    pub clearnet: Option<Clearnet>,
    pub onion_only: bool,
}

pub use crate::enrollment::onions;

/// The bytes the client's streams read and wrote.
#[derive(Clone, Default)]
pub struct Count {
    down: Arc<AtomicU64>,
    up: Arc<AtomicU64>,
}

impl Count {
    /// The bytes read, and written, so far.
    pub fn bytes(&self) -> (u64, u64) {
        (
            self.down.load(Ordering::Relaxed),
            self.up.load(Ordering::Relaxed),
        )
    }
}

/// A dial whose every stream counts its bytes into one [`Count`].
struct Counted {
    dial: Arc<dyn Dial>,
    count: Count,
}

impl Dial for Counted {
    fn dial(&self, target: &Target, circuit: Circuit) -> Dialing {
        let (dialing, count) = (self.dial.dial(target, circuit), self.count.clone());
        Box::pin(async move {
            let stream = dialing.await?;
            Ok(Box::new(Counting { stream, count }) as vos_light::tor::Stream)
        })
    }

    fn set_dormant(&self, dormant: bool) {
        self.dial.set_dormant(dormant);
    }
}

struct Counting {
    stream: vos_light::tor::Stream,
    count: Count,
}

impl AsyncRead for Counting {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.stream).poll_read(cx, buf);
        let read = (buf.filled().len() - before) as u64;
        self.count.down.fetch_add(read, Ordering::Relaxed);
        polled
    }
}

impl AsyncWrite for Counting {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = polled {
            self.count.up.fetch_add(written as u64, Ordering::Relaxed);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// The process's arti, built anew when the bridges change: every dial
/// goes through the one built last.
pub struct Arti {
    directory: PathBuf,
    tor: RwLock<Option<Tor>>,
    /// Whether the client is dormant, for an arti built anew.
    dormant: std::sync::atomic::AtomicBool,
    /// What its last bootstrap found, and why it failed.
    state: Mutex<(crate::personal::Tor, String)>,
}

impl Arti {
    /// Arti with its state and cache under `directory` (made `0700`),
    /// through `bridges` if any: built, not yet bootstrapped. On the
    /// runtime the client runs on.
    pub fn new(directory: PathBuf, bridges: &[String]) -> Result<Arc<Self>, BootstrapError> {
        let arti = Arc::new(Self {
            directory,
            tor: RwLock::new(None),
            dormant: Default::default(),
            state: Mutex::default(),
        });
        arti.rebuild(bridges)?;
        Ok(arti)
    }

    fn rebuild(&self, bridges: &[String]) -> Result<(), BootstrapError> {
        let tor = self.build(bridges)?;
        *self.tor.write().unwrap_or_else(|e| e.into_inner()) = Some(tor);
        Ok(())
    }

    fn build(&self, bridges: &[String]) -> Result<Tor, BootstrapError> {
        let mut config = TorConfig::new(&self.directory);
        config.bridges = bridges.to_vec();
        let tor = Tor::new(&config)?;
        // One built while the app is in the background starts dormant.
        tor.set_dormant(self.dormant.load(Ordering::SeqCst));
        Ok(tor)
    }

    /// An arti through `bridges`, bootstrapped, then the one every dial
    /// goes through; on a failure the one built before stays.
    async fn replace(&self, bridges: &[String]) -> Result<(), BootstrapError> {
        let candidate = self.build(bridges)?;
        self.found(candidate.bootstrap().await)?;
        *self.tor.write().unwrap_or_else(|e| e.into_inner()) = Some(candidate);
        Ok(())
    }

    fn current(&self) -> Option<Tor> {
        self.tor.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Bootstrap the arti built last: its failure named (a wrong clock, a
    /// bridge that does not answer, a network that blocks Tor).
    pub async fn bootstrap(&self) -> Result<(), BootstrapError> {
        let bootstrapped = match self.current() {
            Some(tor) => tor.bootstrap().await,
            None => Err(BootstrapError::Tor("not built".into())),
        };
        self.found(bootstrapped)
    }

    /// A bootstrap's outcome kept as Tor's state.
    fn found(&self, bootstrapped: Result<(), BootstrapError>) -> Result<(), BootstrapError> {
        use crate::personal::Tor as State;
        *crate::lock(&self.state) = match &bootstrapped {
            Ok(()) => (State::Connected, String::new()),
            Err(error) => (State::Blocked, error.to_string()),
        };
        bootstrapped
    }

    /// Tor held back for `why`: no bootstrap is tried until the user asks.
    pub fn hold(&self, why: String) {
        *crate::lock(&self.state) = (crate::personal::Tor::Blocked, why);
    }

    /// Tor's state as its last bootstrap found it, and why it is blocked.
    pub fn state(&self) -> (crate::personal::Tor, String) {
        crate::lock(&self.state).clone()
    }
}

impl Dial for Arti {
    fn dial(&self, target: &Target, circuit: Circuit) -> Dialing {
        match self.current() {
            Some(tor) => tor.dial(target, circuit),
            None => Box::pin(async { Err(io::Error::other("Tor is not built")) }),
        }
    }

    fn set_dormant(&self, dormant: bool) {
        self.dormant.store(dormant, Ordering::SeqCst);
        if let Some(tor) = self.current() {
            tor.set_dormant(dormant);
        }
    }
}

/// The facility's client of its spaces, and what it keeps of their routes.
pub struct Net {
    client: Client,
    /// What the client dials through, for a stream of the client's own.
    dial: Arc<dyn Dial>,
    /// The space spare connections are kept for, the session (a facility
    /// session's number) they are kept for, and the client's number for
    /// that keeping.
    spare: Mutex<Option<(SpaceId, u64, u64)>>,
    count: Count,
    directory: PathBuf,
    /// The facility's database, and the routes read from it; or why it
    /// cannot be read, every change then refused.
    kept: Result<Kept, String>,
    state: Mutex<State>,
    arti: Option<Arc<Arti>>,
    /// Every space whose routes were pinned.
    pinned: Mutex<std::collections::BTreeSet<SpaceId>>,
}

/// Why a request got no answer, as the chrome is told.
pub type NetError = String;

impl Net {
    /// The client dialling through `dial`, its routes kept under
    /// `directory`. Made on the runtime it runs on.
    pub fn new(dial: Arc<dyn Dial>, directory: &Path) -> Self {
        Self::with(dial, directory, None)
    }

    /// The client over `arti`.
    pub fn over(arti: Arc<Arti>, directory: &Path) -> Self {
        Self::with(Arc::clone(&arti) as Arc<dyn Dial>, directory, Some(arti))
    }

    fn with(dial: Arc<dyn Dial>, directory: &Path, arti: Option<Arc<Arti>>) -> Self {
        let count = Count::default();
        let counted = Arc::new(Counted {
            dial,
            count: count.clone(),
        });
        let (kept, state) = match Kept::open(directory).and_then(|kept| Ok((read(&kept)?, kept))) {
            Ok((state, kept)) => (Ok(kept), state),
            Err(error) => (Err(error), State::default()),
        };
        let client = Client::new(Arc::clone(&counted) as Arc<dyn Dial>, Config::default());
        let opened = std::fs::read(directory.join(RENDEZVOUS_KEPT)).ok();
        if let Some(hours) = opened.and_then(|bytes| Vec::<Hour>::decode_exact(&bytes)) {
            client.restore_opened(&hours);
        }
        Self {
            client,
            dial: counted,
            spare: Mutex::new(None),
            count,
            directory: directory.to_path_buf(),
            kept,
            state: Mutex::new(state),
            arti,
            pinned: Mutex::default(),
        }
    }

    /// The bridges kept, which the process's arti is built with; why they
    /// cannot be read, when the database is refused or the row does not
    /// decode.
    pub fn bridges_kept(directory: &Path) -> Result<Vec<String>, String> {
        Ok(Kept::open(directory)?.get(BRIDGES)?.unwrap_or_default())
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        crate::lock(&self.state)
    }

    /// `space`'s routes as `state` holds them, kept.
    fn keep(&self, state: &State, space: &SpaceId) -> Result<(), NetError> {
        let kept = self.kept.as_ref().map_err(Clone::clone)?;
        match state.spaces.get(space) {
            Some(route) => kept.put(&route_key(space), route),
            None => kept.remove(&route_key(space)),
        }
    }

    /// A stream to the onion service at `address`, `port`, on a circuit of
    /// its own: the s4 session's, to a gateway's onion.
    pub async fn onion_stream(
        &self,
        address: &str,
        port: u16,
    ) -> io::Result<vos_light::tor::Stream> {
        if vos_light::tor::onion_key(address).is_none() {
            return Err(io::Error::other("not an onion service's address"));
        }
        let target = Target::Onion {
            address: address.to_ascii_lowercase(),
            port,
        };
        self.dial.dial(&target, Circuit::new()).await
    }

    /// The client, for the requests the light node's flows make.
    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn count(&self) -> &Count {
        &self.count
    }

    /// `space`'s routes from what it pins, the onion set a refresh kept in
    /// place of the pinned one, and the user's opt-out re-applied.
    pub fn pin(&self, space: SpaceId, pinned: Pinned) {
        let kept = self.state().spaces.get(&space).cloned();
        let mut routes = Routes::new(pinned.onions, pinned.clearnet, pinned.onion_only);
        if let Some(kept) = kept {
            if !kept.onions.is_empty() {
                routes.onions = kept.onions;
            }
            if kept.opted_out {
                // Refused for an onion-only space or one with no clearnet
                // port: Tor then stays.
                let _ = routes.opt_out();
            }
        }
        self.client.set_space(space, routes);
        crate::lock(&self.pinned).insert(space);
    }

    /// A space whose routes take its onion and which pinned `host_key` for
    /// its gateway, at an onion's port 22 or at the clearnet port it was
    /// enrolled through: s4's own connection to a gateway presenting that
    /// key, however its name or port is spelled, would carry over the
    /// clearnet what the space's routes keep on Tor.
    pub fn onion_pinned(&self, host_key: &[u8; 32]) -> Option<SpaceId> {
        let pinned = crate::lock(&self.pinned).clone();
        pinned.into_iter().find(|space| {
            self.client.routes(space).is_some_and(|routes| {
                !routes.opted_out()
                    && !routes.onions.is_empty()
                    && (routes
                        .onions
                        .iter()
                        .any(|onion| onion.ssh_host_key == *host_key)
                        || routes
                            .clearnet
                            .as_ref()
                            .is_some_and(|clearnet| clearnet.ssh_host_key == *host_key))
            })
        })
    }

    /// The app came to the foreground, or left it: the client counts what
    /// it opens from now on as the foreground's, or the background's, and
    /// keeps spares only in the foreground.
    pub fn set_foreground(&self, foreground: bool) {
        self.client.set_foreground(foreground);
    }

    /// The client's tally, an hour a line, written to [`RENDEZVOUS`].
    pub fn keep_rendezvous(&self) {
        let directory = &self.directory;
        let hours = self.client.opened();
        let lines: String = hours.iter().map(|hour| format!("{hour}\n")).collect();
        let _ = write_private(&directory.join(RENDEZVOUS_KEPT), &hours.encode());
        let _ = write_private(&directory.join(RENDEZVOUS), lines.as_bytes());
    }

    /// Send `request` to `space` under `purpose`: its answer's body. No
    /// spare carries it.
    pub async fn request(
        &self,
        space: SpaceId,
        purpose: Purpose,
        request: &[u8],
    ) -> Result<Vec<u8>, NetError> {
        self.request_for(space, purpose, request, None).await
    }

    /// The same for the facility session `session`: the spares kept for it,
    /// and only those, may carry it.
    pub async fn request_for(
        &self,
        space: SpaceId,
        purpose: Purpose,
        request: &[u8],
        session: Option<u64>,
    ) -> Result<Vec<u8>, NetError> {
        // The client takes a spare only under the keeping named, so a
        // session kept spares since takes this one's none.
        let spare = session.and_then(|session| {
            crate::lock(&self.spare)
                .filter(|(kept, by, _)| (*kept, *by) == (space, session))
                .map(|(_, _, epoch)| epoch)
        });
        self.client
            .request_with(space, purpose, request, spare)
            .await
            .map(|(_, body)| body)
            .map_err(|error| error.to_string())
    }

    /// Opt `space`'s key-signed calls out of Tor, the chrome having shown
    /// [`OPT_OUT_WARNING`]; or back on Tor. Kept.
    pub fn opt_out(&self, space: SpaceId, out: bool) -> Result<(), Refused> {
        let mut routes = self.client.routes(&space).ok_or(Refused::UnknownSpace)?;
        if out {
            routes.opt_out()?;
        } else {
            routes.opt_in();
        }
        let opted_out = routes.opted_out();
        self.client.set_space(space, routes);
        let mut state = self.state();
        state.spaces.entry(space).or_default().opted_out = opted_out;
        let _ = self.keep(&state, &space);
        Ok(())
    }

    /// Whether the user opted `space` out of Tor.
    pub fn opted_out(&self, space: &SpaceId) -> bool {
        self.client
            .routes(space)
            .is_some_and(|routes| routes.opted_out())
    }

    /// The registrar's current onion set for `space`, read through its
    /// pinned set, kept in place of the pinned one.
    pub async fn refresh_onions(
        &self,
        space: SpaceId,
        registrar: &Registrar,
    ) -> Result<Vec<Onion>, NetError> {
        let onions = self
            .client
            .refresh_onions(space, registrar)
            .await
            .map_err(|error| error.to_string())?;
        let mut state = self.state();
        let kept = state.spaces.entry(space).or_default();
        kept.onions = onions.clone();
        kept.onions_ms = crate::job::now_ms();
        self.keep(&state, &space)?;
        Ok(onions)
    }

    /// The same once a day: whether it was read.
    pub async fn refresh_onions_due(
        &self,
        space: SpaceId,
        registrar: &Registrar,
        now_ms: u64,
    ) -> Result<bool, NetError> {
        let last = self
            .state()
            .spaces
            .get(&space)
            .map_or(0, |kept| kept.onions_ms);
        if now_ms.saturating_sub(last) < ONIONS_EVERY_MS {
            return Ok(false);
        }
        self.refresh_onions(space, registrar).await.map(|_| true)
    }

    /// Dormant (the app in the background, no job running) or awake.
    pub fn set_dormant(&self, dormant: bool) {
        self.client.set_dormant(dormant);
    }

    /// Keep spare connections for `space`'s next proven call and next
    /// fetch, for the session `session` alone: the spares another session
    /// was kept are closed, so no connection opened in one session's time
    /// carries another's request (`light-node.md` §6.2).
    pub fn keep_spare(&self, space: SpaceId, session: u64) {
        let mut spare = crate::lock(&self.spare);
        if spare.is_some_and(|(kept, by, _)| (kept, by) == (space, session)) {
            return;
        }
        let epoch = self
            .client
            .keep_spares(Some(space), &[Purpose::Proven, Purpose::Fetch]);
        *spare = Some((space, session, epoch));
    }

    /// No spares for `session` any more: it closed. Spares kept for
    /// another session stay.
    pub fn drop_spare(&self, space: SpaceId, session: u64) {
        let mut spare = crate::lock(&self.spare);
        if spare.is_some_and(|(kept, by, _)| (kept, by) == (space, session)) {
            *spare = None;
            self.client.keep_spares(None, &[]);
        }
    }

    /// Whether the app is in the foreground, as last told.
    pub fn foreground(&self) -> bool {
        self.client.is_foreground()
    }

    /// The bridges pasted in the chrome: arti built anew through them
    /// (none: the public relays), bootstrapped, and kept once it is.
    pub async fn bridges(&self, lines: Vec<String>) -> Result<(), String> {
        for line in &lines {
            vos_light::tor::bridge(line).map_err(|error| error.to_string())?;
        }
        let arti = self.arti.as_ref().ok_or("this facility does not run Tor")?;
        arti.replace(&lines)
            .await
            .map_err(|error| error.to_string())?;
        let kept = self.kept.as_ref().map_err(Clone::clone)?;
        kept.put(BRIDGES, &lines)?;
        self.state().bridges = lines;
        Ok(())
    }

    /// Why the facility's database does not read, if it does not: every
    /// route then its pinned one, every change refused.
    pub fn repair(&self) -> Option<String> {
        self.kept.as_ref().err().cloned()
    }

    /// Tor's state, and why it is blocked: connected for a client that
    /// runs no arti (an in-process dial).
    pub fn tor(&self) -> (crate::personal::Tor, String) {
        match &self.arti {
            Some(arti) => arti.state(),
            None => (crate::personal::Tor::Connected, String::new()),
        }
    }

    /// Bootstrap the process's arti, if it runs one.
    pub async fn bootstrap(&self) -> Result<(), String> {
        match &self.arti {
            Some(arti) => arti.bootstrap().await.map_err(|error| error.to_string()),
            None => Ok(()),
        }
    }
}
