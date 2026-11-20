//! The facility, one connection's use of it, and each enrollment's
//! credential tree, kept for the process apart from every connection that
//! proves.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use vos_light::release::Release;
use vos_light::route::{Clearnet, Purpose};
use vos_light::tor::Registrar;
use vos_light::wire;
use vos_light::{
    AuthWitness, Call, DeviceError, DeviceProgram, DeviceSecret, Digest, PEAK_BYTES, Proven,
    Prover, ProverConfig, TreeKeeper,
};
use vos_wire::ingress::DeviceWindow;

use crate::chrome::{Answer, Chrome, Field, Form, short};
use crate::enrollment::{Agent, Enrollment, Guard, Method, Origin, Store, write_private};
use crate::job::now_ms;
use crate::net::{Net, Pinned};
use crate::source::{Kind, Reference, Source, SourceError};
use crate::warm::{self, Programs, Warming};
use crate::{
    Code, Enroll, Enrolled, EnrolledSpace, Gateway, Operation, Outcome, Paid, Pay, Refusal, SignIn,
    SignedIn, StreamTarget, Synced, refused,
};
use s4_credential_contract::{TRANSFER, account};

/// How far past the node's time a proof's expiry is set: within VOS's
/// `CREDENTIAL_HORIZON_MS`, which ingress allows, room for the proof and
/// the trip.
const EXPIRY_MS: u64 = 60_000;
const _: () = assert!(EXPIRY_MS < vos_wire::defaults::CREDENTIAL_HORIZON_MS);
/// How often a refresher asks its keeper whether the feed is due: the
/// keeper's own jittered timer decides.
const TICK: Duration = Duration::from_secs(1);
/// The wait after a failed read before the next.
const RETRY: Duration = Duration::from_secs(5);
/// How long a sign-in whose root the node refused waits for the keeper's
/// next read before it answers that refusal: the read falls due within
/// `TreeKeeper::UNKNOWN_SPREAD_MS`, and takes a page or two over Tor.
const ROOT_RETRY: Duration = Duration::from_secs(30);
/// How often that wait looks at the keeper.
const ROOT_POLL: Duration = Duration::from_millis(250);
/// The spread of the wait after that read before the proof is made again
/// (`TreeKeeper::UNKNOWN_SPREAD_MS`'s).
const ROOT_SPREAD: Duration = Duration::from_millis(TreeKeeper::UNKNOWN_SPREAD_MS);
/// A space that no longer admits the device format this app proves in.
const UPDATE: &str = "the space no longer admits this app's proofs: update the app";
/// A space whose window admits none of this app's programs: the app or the
/// space is behind the other.
const WINDOW: &str =
    "the space admits none of this app's programs: the app or the space must update";
/// A window a space's node could not compute whole yet.
const UNAVAILABLE: &str = "the space's node cannot read its device window yet: try again";
/// A space's handle, an agent and an instance there: whose device window.
type WindowKey = ([u8; 32], u32, u32);
/// How long a space's device window is taken as read.
const WINDOW_TTL: Duration = Duration::from_secs(600);
/// A window this old is read again by the tree's refresher, so a sign-in
/// or a payment never waits for it.
const WINDOW_RENEW: Duration = Duration::from_secs(400);
/// The furthest the node's time may be from the device's: past it, a relay
/// that lies about the time could keep a confirmed proof for later.
const CLOCK_SKEW_MS: u64 = 300_000;
/// How long a session uses its reading of the node's clock. A reading
/// is an offset from the device's clock, which drifts a few milliseconds
/// in that time; what makes it wrong is a step of the device's clock,
/// which [`CLOCK_STEP_MS`] catches. The bound is on rendezvous an hour
/// (at most 30 in the foreground): each reading is a fetch, a rendezvous,
/// so a session reads again every 4 to 12 minutes ([`CLOCK_EVERY`]), about
/// seven an hour.
const CLOCK_LIFE: Duration = Duration::from_secs(15 * 60);
/// How often a session reads the node's clock again, about: each reading
/// draws its renewal between half and one and a half of it.
const CLOCK_EVERY: Duration = Duration::from_secs(8 * 60);
/// The most the device's clock may move apart from its monotonic clock
/// while a reading is used: past it the clock was set, or the device
/// slept, and the node's clock is read again.
const CLOCK_STEP_MS: u64 = 2_000;
/// The spread of a session's first reading after its grant.
const CLOCK_SPREAD: Duration = Duration::from_secs(2);
/// How often a session's clock task looks at its reading.
const CLOCK_TICK: Duration = Duration::from_secs(5);
/// Each session's number, which its spares are kept under.
static SESSIONS: AtomicU64 = AtomicU64::new(1);
/// The least time between two `refresh` requests the facility honours, and
/// the spread of the read one schedules.
const REFRESH_EVERY: Duration = Duration::from_secs(30);
const REFRESH_SPREAD: Duration = Duration::from_secs(5);

/// The release artifacts of VOS's stock kernels, each an encoded
/// `vos_light::release::Release`: the programs the device proves sign-ins
/// and payments with, never one a server sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stock {
    pub auth: Vec<u8>,
    pub owner: Vec<u8>,
}

/// A stock kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kernel {
    Auth,
    Owner,
}

impl Stock {
    /// `kernel`'s release artifact.
    pub(crate) fn artifact(&self, kernel: Kernel) -> &[u8] {
        match kernel {
            Kernel::Auth => &self.auth,
            Kernel::Owner => &self.owner,
        }
    }

    /// The artifacts this crate embeds, built from this tree's credential
    /// actor (`just facility-release`).
    pub fn embedded() -> Self {
        Self {
            auth: include_bytes!("../release/auth.device").to_vec(),
            owner: include_bytes!("../release/owner.device").to_vec(),
        }
    }
}

/// The `vos.credential` facility of one device: its enrollments, its secret
/// source, its prover, and each enrollment's tree.
#[derive(Clone)]
pub struct Facility {
    inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub(crate) store: Store,
    pub(crate) source: Arc<dyn Source>,
    pub(crate) stock: Stock,
    prover: Mutex<Option<Arc<Prover>>>,
    /// The enrolled kernels' programs, by release artifact.
    programs: Programs,
    /// Held for a proof: two at once would hold a proof's memory twice.
    device_proof: Mutex<()>,
    tick: Duration,
    /// The one client every request to a space goes through.
    pub(crate) net: Arc<Net>,
    /// Each enrollment's tree and its refresher, by origin, for the
    /// process's life: no connection that proves starts or steers it.
    trees: Mutex<HashMap<(String, String), Arc<Tree>>>,
    /// The device's personal space, while it runs.
    personal: Mutex<Option<std::sync::Weak<dyn PersonalLink>>>,
    /// Each space's device window for its credential actor, as its node answered it
    /// last, and when: read before a proof, and kept for [`WINDOW_TTL`]
    /// while it admits this app's programs.
    windows: Mutex<HashMap<WindowKey, (Instant, DeviceWindow)>>,
    /// Held while a space's window is read, so a call waits for the read
    /// its session's grant started rather than making another.
    window_reads: Mutex<HashMap<WindowKey, Arc<tokio::sync::Mutex<()>>>>,
}

/// What an enrollment asks of the device's personal space.
pub(crate) trait PersonalLink: Send + Sync {
    /// The source this device's handle in the space `handle` was derived
    /// from at a pairing, while its confirmation there is owed: the device
    /// that paired it enrolled that handle, so this one enrolls with it.
    fn owed_source(&self, handle: &[u8; 32]) -> Result<Option<Reference>, String>;
    /// An enrollment made: the credential book records it.
    fn enrolled(&self);
    /// The home the device's agent is at: its handle, its space and its
    /// onion set.
    fn home(&self) -> Option<([u8; 32], [u8; 32], Vec<vos_wire::credentials::Onion>)>;
}

/// One enrollment's credential tree, its refresher while a session holds
/// it, and its last payment.
struct Tree {
    /// The key its space's routes are kept under in the client.
    space: [u8; 32],
    keeper: tokio::sync::Mutex<TreeKeeper>,
    /// Where the keeper is kept, beside the enrollment.
    file: PathBuf,
    /// When a `refresh` request makes the feed due, at a drawn delay.
    unknown_at: Mutex<Option<Instant>>,
    last_refresh: Mutex<Option<Instant>>,
    /// The last payment made: its confirmed values and its request, sent
    /// again as it is for the same values while it may still run.
    payment: Mutex<Option<Payment>>,
    refresher: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// The sessions holding it: its refresher stops with the last.
    sessions: AtomicUsize,
    /// The feed's reads made: a sign-in whose root was refused waits for
    /// the next.
    reads: AtomicUsize,
    /// The member's path at the newest root the keeper holds, as its last
    /// read left it: a sign-in takes it without waiting for a read in
    /// flight.
    witness: Mutex<Option<AuthWitness>>,
}

#[derive(Clone)]
struct Payment {
    values: (String, u64),
    expires_ms: u64,
    request: Vec<u8>,
}

impl Tree {
    /// The keeper told its root is unknown to the node, and the witness
    /// kept as the keeper now has it.
    fn unknown(&self, keeper: &mut TreeKeeper) {
        keeper.unknown(now_ms());
        *self.witness.lock().expect("witness poisoned") = keeper.witness();
    }

    fn stop(&self) {
        if let Some(refresher) = self.refresher.lock().expect("refresher poisoned").take() {
            refresher.abort();
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A gateway's host as two spellings of one name compare: lowercase, no
/// trailing dot.
fn host(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// What `enrollment` pins of its space's routes.
pub(crate) fn pinned(enrollment: &Enrollment) -> Pinned {
    Pinned {
        onions: enrollment.onions.clone(),
        // A session over an onion names no clearnet: its host would go to
        // the system's resolver.
        clearnet: enrollment
            .host_key
            .filter(|_| !enrollment.host.to_ascii_lowercase().ends_with(".onion"))
            .map(|key| Clearnet {
                host: enrollment.host.clone(),
                port: enrollment.port,
                ssh_host_key: key,
            }),
        onion_only: enrollment.onion_only,
    }
}

/// `enrollment`'s credential actor, whose feed serves its tree.
fn registrar(enrollment: &Enrollment) -> Result<Registrar, String> {
    let location = enrollment.credentials;
    let identity = enrollment
        .agent(location.agent)
        .ok_or("the credential actor's agent was not pinned")?
        .identity;
    Ok(Registrar {
        agent: location.agent,
        instance: location.instance,
        identity,
    })
}

impl Facility {
    /// The facility over `store`, its secret sources `source`, every
    /// request to a space through `net`.
    pub fn new(store: Store, source: Arc<dyn Source>, net: Arc<Net>) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                source,
                stock: Stock::embedded(),
                prover: Mutex::new(None),
                programs: Programs::default(),
                device_proof: Mutex::new(()),
                tick: TICK,
                net,
                trees: Mutex::new(HashMap::new()),
                personal: Mutex::new(None),
                windows: Mutex::new(HashMap::new()),
                window_reads: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The device's personal space, which enrollments ask.
    pub(crate) fn lend_personal(&self, personal: std::sync::Weak<dyn PersonalLink>) {
        *crate::lock(&self.inner.personal) = Some(personal);
    }

    fn inner_mut(&mut self) -> &mut Inner {
        Arc::get_mut(&mut self.inner).expect("a facility not yet shared")
    }

    /// The same, proving with the stock kernels' artifacts `stock`: a
    /// client of a VOS tree whose credential actor is built apart (tests).
    pub fn with_stock(mut self, stock: Stock) -> Self {
        self.inner_mut().stock = stock;
        self
    }

    /// The same, its refreshers asking their keepers every `tick` (tests).
    pub fn with_tick(mut self, tick: Duration) -> Self {
        self.inner_mut().tick = tick;
        self
    }

    pub(crate) fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }

    /// The client every request goes through.
    pub fn net(&self) -> &Arc<Net> {
        &self.inner.net
    }

    /// Whether the device has a secret source, or a key one already made
    /// for an enrollment: without either the client does not offer the
    /// facility.
    pub fn supported(&self) -> bool {
        !self.inner.source.kinds().is_empty() || self.inner.store.any()
    }

    /// Compute the enrolled kernels' programs in the background at a low
    /// priority: `None` when nothing is enrolled.
    pub fn warm(&self) -> Option<Warming> {
        let kernels = self.inner.enrolled_kernels();
        Inner::warm(&self.inner, kernels)
    }

    /// Every enrollment's space told to the client, its routes as pinned.
    pub fn pin_all(&self) {
        for enrollment in self.inner.store.all().unwrap_or_default() {
            self.inner.net.pin(enrollment.routes(), pinned(&enrollment));
        }
    }

    /// One pass of the facility's sync, apart from every proof: each
    /// enrollment's tree read from its feed if due, over Tor. What it
    /// keeps is the process's: a pass cut short leaves the store as it was.
    pub async fn sync(&self) -> Result<Synced, Refusal> {
        let all = self.inner.store.all().map_err(store_error)?;
        let mut synced = Synced {
            enrollments: all.len() as u32,
            ..Synced::default()
        };
        let mut failures = Vec::new();
        for enrollment in all {
            self.inner.net.pin(enrollment.routes(), pinned(&enrollment));
            let Some(tree) = self.inner.tree_of(&enrollment) else {
                synced.failed += 1;
                failures.push("an enrollment's tree is not kept".to_owned());
                continue;
            };
            match read_once(&self.inner.net, &tree, &enrollment).await {
                Ok(()) => synced.synced += 1,
                Err(error) => {
                    synced.failed += 1;
                    failures.push(format!("a space's tree: {error}"));
                }
            }
            // The registrar's onion set, once a day: a space whose onions
            // rotate stays reachable. A failure keeps the set pinned.
            if let Ok(registrar) = registrar(&enrollment) {
                let _ = self
                    .inner
                    .net
                    .refresh_onions_due(enrollment.routes(), &registrar, now_ms())
                    .await;
            }
        }
        synced.failures = failures.join("; ");
        Ok(synced)
    }

    /// The enrollments kept, as the app's own screens list them.
    pub fn enrollments(&self) -> Result<Vec<EnrolledSpace>, Refusal> {
        Ok(self
            .inner
            .store
            .all()
            .map_err(store_error)?
            .into_iter()
            .map(|enrollment| EnrolledSpace {
                space: enrollment.space,
                handle: enrollment.handle,
                member: enrollment.member,
                opted_out: self.inner.net.opted_out(&enrollment.routes()),
                host: enrollment.host,
                port: enrollment.port,
            })
            .collect())
    }

    /// The space whose routes pin the onion service `host` names, if one
    /// does: s4's screens to it are that space's, with the key it pinned.
    pub fn onion_space(&self, host: &str) -> Result<Option<crate::net::SpaceId>, Refusal> {
        let Some(key) = vos_light::tor::onion_key(host.trim_end_matches('.')) else {
            return Ok(None);
        };
        let net = &self.inner.net;
        for enrollment in self.inner.store.all().map_err(store_error)? {
            self.inner.pin_missing(&enrollment);
            let pins = net
                .client()
                .routes(&enrollment.routes())
                .is_some_and(|routes| routes.onions.iter().any(|onion| onion.key == key));
            if pins {
                return Ok(Some(enrollment.routes()));
            }
        }
        Ok(None)
    }

    /// The space whose screens the gateway `gateway` names serves: one
    /// enrolled through that gateway whose routes take its onion, before
    /// one the user opted out to its clearnet port, before one whose
    /// routes take neither (which its routes then refuse). `NotEnrolled`
    /// only when no space was enrolled through it.
    pub fn screens_space(&self, gateway: &StreamTarget) -> Result<crate::net::SpaceId, Refusal> {
        let net = &self.inner.net;
        let (mut opted_out, mut unrouted) = (None, None);
        for enrollment in self.inner.store.all().map_err(store_error)? {
            if enrollment.port != gateway.port || host(&enrollment.host) != host(&gateway.host) {
                continue;
            }
            self.inner.pin_missing(&enrollment);
            let routes = net.client().routes(&enrollment.routes());
            match routes {
                Some(routes) if routes.opted_out() => {
                    opted_out.get_or_insert(enrollment.routes());
                }
                Some(routes) if !routes.onions.is_empty() => return Ok(enrollment.routes()),
                _ => {
                    unrouted.get_or_insert(enrollment.routes());
                }
            }
        }
        opted_out.or(unrouted).ok_or_else(|| {
            refused(
                Code::NotEnrolled,
                "no space was enrolled through this gateway",
            )
        })
    }

    /// Refused when `host_key`, the key a gateway presented to s4's own
    /// connection, is one a space pinned to its onion (at the onion's port
    /// 22, or at the clearnet port it was enrolled through) while its
    /// routes take the onion: that gateway is the space's, however its
    /// name or its port is spelled, and s4 does not reach it over the
    /// clearnet itself. A space the user opted out of Tor refuses nothing.
    pub fn clearnet_refused(&self, host_key: &[u8; 32]) -> Result<(), Refusal> {
        let all = self.inner.store.all().map_err(store_error)?;
        for enrollment in &all {
            self.inner.pin_missing(enrollment);
        }
        match self.inner.net.onion_pinned(host_key) {
            None => Ok(()),
            Some(space) => {
                let through = all
                    .into_iter()
                    .find(|enrollment| enrollment.routes() == space)
                    .map(|enrollment| {
                        format!(
                            ", as the gateway it was enrolled through ({}:{})",
                            enrollment.host, enrollment.port
                        )
                    })
                    .unwrap_or_default();
                Err(refused(
                    Code::Refused,
                    format!(
                        "this gateway serves a space this device reaches over Tor alone: s4 \
                         reaches it over its onion{through}"
                    ),
                ))
            }
        }
    }

    /// The facility for one connection to `gateway`, whose `ServerHello`
    /// named its application.
    pub fn session(&self, gateway: Gateway) -> Session {
        Session {
            id: SESSIONS.fetch_add(1, Ordering::Relaxed),
            clock: Arc::default(),
            inner: Arc::clone(&self.inner),
            origin: Origin {
                host: gateway.fingerprint.clone(),
                application: gateway.application.clone(),
            },
            gateway,
            held: Mutex::new(None),
            learned: Mutex::new(Learned::Nothing),
        }
    }
}

impl Inner {
    /// `enrollment`'s space told to the client, its routes as pinned, if
    /// the client holds none for it.
    fn pin_missing(&self, enrollment: &Enrollment) {
        if self.net.client().routes(&enrollment.routes()).is_none() {
            self.net.pin(enrollment.routes(), pinned(enrollment));
        }
    }

    fn personal(&self) -> Option<Arc<dyn PersonalLink>> {
        crate::lock(&self.personal).as_ref().and_then(Weak::upgrade)
    }

    /// The source a pairing derived this device's handle `handle` from,
    /// while its confirmation is owed. Unread, the enrollment is refused:
    /// a new key there would never prove.
    async fn owed_source(&self, handle: [u8; 32]) -> Result<Option<Reference>, Refusal> {
        let Some(personal) = self.personal() else {
            return Ok(None);
        };
        tokio::task::spawn_blocking(move || personal.owed_source(&handle))
            .await
            .map_err(|_| refused(Code::Failed, "the personal space stopped"))?
            .map_err(|error| refused(Code::Store, format!("the personal space's store: {error}")))
    }

    /// An enrollment made, told to the personal space off the runtime,
    /// unawaited: a flow holding it delays the record, not the enrollment.
    fn enrolled(&self) {
        if let Some(personal) = self.personal() {
            drop(tokio::task::spawn_blocking(move || personal.enrolled()));
        }
    }

    /// The stock kernels `enrollment`'s guards prove with.
    fn kernels<'a>(&'a self, enrollment: &'a Enrollment) -> impl Iterator<Item = &'a [u8]> {
        enrollment.methods.iter().map(|method| match &method.guard {
            Guard::Auth { .. } => self.stock.auth.as_slice(),
            Guard::Owner => self.stock.owner.as_slice(),
        })
    }

    /// Whether the space admits the stock `kernel`'s program, as the device
    /// window of `enrollment`'s credential actor, whose method a stock
    /// kernel is, says (`light-node.md` §4.4): read before anything is
    /// asked or proved, so a space behind the app, or ahead of it, is
    /// refused with the window's words and not a proof's.
    pub(crate) async fn admits(
        &self,
        enrollment: &Enrollment,
        kernel: Kernel,
    ) -> Result<(), Refusal> {
        let shipped = <Release as vos_abi::Decode>::decode_exact(self.stock.artifact(kernel))
            .ok_or_else(|| refused(Code::Prove, "a stock kernel's artifact does not decode"))?;
        let window = self.window(enrollment, WINDOW_TTL).await?;
        // A window that admits none of them is read again next time: the
        // space, or the app, may have moved meanwhile.
        let chosen = vos_light::choose(std::slice::from_ref(&shipped), &window, shipped.method);
        if chosen.is_err() {
            self.forget_window(enrollment);
        }
        match chosen {
            Ok(_) => Ok(()),
            Err(DeviceError::Unavailable) => Err(refused(Code::Api, UNAVAILABLE)),
            Err(_) => Err(refused(Code::Refused, WINDOW)),
        }
    }

    /// `enrollment`'s device window, as read within `fresh`, or read now on
    /// the space's feed connection: the window names nothing of the member's
    /// and enters no request's bytes (it only gates which program is
    /// proved), so the connection every member reads the same feed on
    /// carries it, and it costs no rendezvous.
    async fn window(
        &self,
        enrollment: &Enrollment,
        fresh: Duration,
    ) -> Result<DeviceWindow, Refusal> {
        let actor = enrollment.credentials;
        let key = (enrollment.handle, actor.agent, actor.instance);
        let held = || {
            self.windows
                .lock()
                .expect("windows poisoned")
                .get(&key)
                .filter(|(at, _)| at.elapsed() < fresh)
                .map(|(_, window)| window.clone())
        };
        if let Some(window) = held() {
            return Ok(window);
        }
        let lock = Arc::clone(
            self.window_reads
                .lock()
                .expect("windows poisoned")
                .entry(key)
                .or_default(),
        );
        let _reading = lock.lock().await;
        if let Some(window) = held() {
            return Ok(window);
        }
        let answer = self
            .net
            .request(
                enrollment.routes(),
                Purpose::Feed,
                &wire::devices_request(actor.agent, actor.instance),
            )
            .await
            .map_err(|error| refused(Code::Api, format!("the space's device window: {error}")))?;
        let window = wire::devices_answer(&answer)
            .map_err(|error| refused(Code::Api, format!("the space's device window: {error}")))?
            .ok_or_else(|| refused(Code::Refused, "the space holds no such instance"))?;
        self.windows
            .lock()
            .expect("windows poisoned")
            .insert(key, (Instant::now(), window.clone()));
        Ok(window)
    }

    /// `enrollment`'s window read again at the next call.
    fn forget_window(&self, enrollment: &Enrollment) {
        let actor = enrollment.credentials;
        let key = (enrollment.handle, actor.agent, actor.instance);
        self.windows.lock().expect("windows poisoned").remove(&key);
    }

    /// Every enrolled kernel, the programs of others dropped.
    fn enrolled_kernels(&self) -> Vec<Vec<u8>> {
        let Ok(all) = self.store.all() else {
            return Vec::new();
        };
        let mut kernels = HashMap::new();
        for enrollment in &all {
            for kernel in self.kernels(enrollment) {
                kernels.insert(warm::key(kernel), kernel.to_vec());
            }
        }
        self.programs
            .retain(&kernels.keys().copied().collect::<HashSet<_>>());
        kernels.into_values().collect()
    }

    /// The program of the release artifact `kernel`, computed once while an
    /// enrolled guard proves with it.
    pub(crate) fn program(&self, kernel: &[u8]) -> Result<Arc<DeviceProgram>, DeviceError> {
        self.programs.get(warm::key(kernel), || {
            <Release as vos_abi::Decode>::decode_exact(kernel)
                .ok_or(DeviceError::Prove)
                .and_then(|device| {
                    DeviceProgram::from_release(&device).map_err(DeviceError::Program)
                })
        })
    }

    /// The prover, allowed a proof's memory.
    pub(crate) fn prover(&self) -> Result<Arc<Prover>, DeviceError> {
        let mut prover = self.prover.lock().expect("prover poisoned");
        if let Some(prover) = &*prover {
            return Ok(Arc::clone(prover));
        }
        let made = Arc::new(Prover::new(ProverConfig {
            max_memory: PEAK_BYTES,
            ..ProverConfig::default()
        })?);
        *prover = Some(Arc::clone(&made));
        Ok(made)
    }

    /// One proof at a time, its heap handed back after: `prove` of `call`
    /// on a blocking thread, given the program of `kernel`; the call's
    /// credentialed request.
    pub(crate) async fn prove(
        this: &Arc<Self>,
        kernel: Kernel,
        call: Call,
        prove: impl FnOnce(&Prover, &DeviceProgram, &Call) -> Result<Proven, DeviceError>
        + Send
        + 'static,
    ) -> Result<Vec<u8>, Refusal> {
        let prover = this
            .prover()
            .map_err(|error| refused(Code::Prove, error.to_string()))?;
        let inner = Arc::clone(this);
        tokio::task::spawn_blocking(move || {
            let proof = inner
                .program(inner.stock.artifact(kernel))
                .and_then(|program| {
                    let _one = crate::lock(&inner.device_proof);
                    prove(&prover, &program, &call).map(|proof| wire::credentialed(&call, &proof))
                });
            // A proof's half a gigabyte handed back, whether it was made or
            // failed.
            warm::release_heap();
            proof
        })
        .await
        .map_err(|_| refused(Code::Prove, "the prover stopped"))?
        .map_err(|error| match error {
            // The space admits none of this app's programs.
            DeviceError::Window => refused(Code::Refused, UPDATE),
            error => refused(Code::Prove, error.to_string()),
        })
    }

    /// The tree kept for `enrollment`, restored from its file if one is
    /// kept; `None` for a member digest that is none.
    fn tree_of(&self, enrollment: &Enrollment) -> Option<Arc<Tree>> {
        let member = Digest::from_bytes(&enrollment.member)?;
        let origin = Origin {
            host: enrollment.fingerprint.clone(),
            application: enrollment.application.clone(),
        };
        let mut all = self.trees.lock().expect("trees poisoned");
        let key = (origin.host.clone(), origin.application.clone());
        Some(Arc::clone(all.entry(key).or_insert_with(|| {
            let file = self.store.tree_path(&origin);
            let keeper = std::fs::read(&file)
                .ok()
                .and_then(|bytes| TreeKeeper::restore(member, &bytes).ok())
                .unwrap_or_else(|| TreeKeeper::new(member));
            let witness = Mutex::new(keeper.witness());
            Arc::new(Tree {
                space: enrollment.routes(),
                keeper: tokio::sync::Mutex::new(keeper),
                file,
                unknown_at: Mutex::new(None),
                last_refresh: Mutex::new(None),
                payment: Mutex::new(None),
                refresher: Mutex::new(None),
                sessions: AtomicUsize::new(0),
                reads: AtomicUsize::new(0),
                witness,
            })
        })))
    }

    /// `kernels`' programs computed on a thread of their own.
    fn warm(this: &Arc<Self>, kernels: Vec<Vec<u8>>) -> Option<Warming> {
        if kernels.is_empty() {
            return None;
        }
        let inner = Arc::downgrade(this);
        Warming::spawn(move |cancelled| {
            for kernel in &kernels {
                let Some(inner) = live(&inner, cancelled) else {
                    return;
                };
                drop(inner.program(kernel));
            }
        })
    }
}

/// The facility, unless it is gone or the warm-up `cancelled`.
fn live(inner: &Weak<Inner>, cancelled: &AtomicBool) -> Option<Arc<Inner>> {
    if cancelled.load(Ordering::SeqCst) {
        return None;
    }
    inner.upgrade()
}

/// The node's clock as a session read it: its offset from the device's
/// clock, and when it was read, by the device's clock and its monotonic
/// one.
#[derive(Clone, Copy, Debug)]
struct Clock {
    offset_ms: i64,
    wall_ms: u64,
    at: Instant,
    /// When the session reads it again.
    renew: Duration,
}

impl Clock {
    /// The node's time now: its time at the reading, moved on by the
    /// monotonic clock, which a step of the device's clock does not move;
    /// none past [`CLOCK_LIFE`], or once the device's clock moved apart from
    /// the monotonic one (it was set, or the device slept, which the
    /// monotonic clock does not count).
    fn now(&self) -> Option<u64> {
        let elapsed = self.at.elapsed();
        if elapsed >= CLOCK_LIFE {
            return None;
        }
        let elapsed_ms = elapsed.as_millis() as u64;
        let moved = now_ms() as i64 - self.wall_ms as i64;
        if moved.abs_diff(elapsed_ms as i64) > CLOCK_STEP_MS {
            return None;
        }
        self.wall_ms
            .checked_add_signed(self.offset_ms)?
            .checked_add(elapsed_ms)
    }

    fn due(&self) -> bool {
        self.now().is_none() || self.at.elapsed() >= self.renew
    }
}

/// A session's reading of the node's clock, its own: the time a gateway
/// answered reaches every expiry set from it, so a reading is shared only
/// among the calls of the one session that asked them, which its server
/// joins anyway (`light-node.md` §6.2).
#[derive(Default)]
struct SessionClock {
    reading: Mutex<Option<Clock>>,
    /// Held while the clock is read, so a call waits for a read in flight
    /// rather than making another.
    read: tokio::sync::Mutex<()>,
    /// The task reading it again while the session is open.
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// A read made while a form is read.
    meanwhile: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl SessionClock {
    fn current(&self) -> Option<u64> {
        self.reading
            .lock()
            .expect("clock poisoned")
            .as_ref()
            .and_then(Clock::now)
    }

    /// The node's time now: this session's reading, or one read now.
    async fn now(&self, net: &Net, space: [u8; 32], session: u64) -> Result<u64, String> {
        if let Some(now) = self.current() {
            return Ok(now);
        }
        self.renew(net, space, session).await?;
        self.current()
            .ok_or_else(|| "the device's clock moved while the node's time was read".into())
    }

    /// The clock read again, if its reading is due.
    async fn renew(&self, net: &Net, space: [u8; 32], session: u64) -> Result<(), String> {
        let _reading = self.read.lock().await;
        let due = self
            .reading
            .lock()
            .expect("clock poisoned")
            .as_ref()
            .is_none_or(Clock::due);
        if due {
            let clock = read_clock(net, space, session).await?;
            *self.reading.lock().expect("clock poisoned") = Some(clock);
        }
        Ok(())
    }

    fn stop(&self) {
        for task in [&self.task, &self.meanwhile] {
            if let Some(task) = task.lock().expect("clock poisoned").take() {
                task.abort();
            }
        }
    }
}

/// The node's clock, read on a fetch of its own (the session's fetch spare
/// if one is built), refused when it is further from the device's than
/// [`CLOCK_SKEW_MS`]. The device's clock is taken as the answer arrives, so
/// the reading errs early by the trip and an expiry set from it never
/// later than the node's time says.
async fn read_clock(net: &Net, space: [u8; 32], session: u64) -> Result<Clock, String> {
    let answer = net
        .request_for(space, Purpose::Fetch, &wire::time_request(), Some(session))
        .await?;
    let (wall_ms, at) = (now_ms(), Instant::now());
    let node = wire::time_answer(&answer).map_err(|error| error.to_string())?;
    if node.abs_diff(wall_ms) > CLOCK_SKEW_MS {
        return Err("the node's time is minutes off this device's".into());
    }
    Ok(Clock {
        offset_ms: node as i64 - wall_ms as i64,
        wall_ms,
        at,
        renew: jittered(CLOCK_EVERY),
    })
}

/// The facility on one connection.
pub struct Session {
    /// Its number, which its spares are kept under.
    id: u64,
    /// Its reading of the node's clock.
    clock: Arc<SessionClock>,
    inner: Arc<Inner>,
    origin: Origin,
    gateway: Gateway,
    /// The tree this session holds since its grant.
    held: Mutex<Option<Arc<Tree>>>,
    /// What the session's server learned of the device: its digests (an
    /// enrollment's answer) or its account (a payment's owner proof), or
    /// a sign-in's pseudonym. One session never carries both, so its
    /// server cannot join an anonymous sign-in to the member it named.
    learned: Mutex<Learned>,
}

/// What a session's server learned of the device.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Learned {
    #[default]
    Nothing,
    /// The device's member or owner digest.
    Named,
    /// A sign-in's pseudonym.
    SignedIn,
}

impl Drop for Session {
    /// Its clock's task stops and its spares close; the last session
    /// holding a tree stops its refresher.
    fn drop(&mut self) {
        self.clock.stop();
        let Some(tree) = self.held.lock().expect("held poisoned").take() else {
            return;
        };
        self.inner.net.drop_spare(tree.space, self.id);
        if tree.sessions.fetch_sub(1, Ordering::SeqCst) == 1 {
            tree.stop();
        }
    }
}

fn declined() -> Refusal {
    refused(Code::Declined, "the user declined")
}

/// The store's failure as the server is told it: its own message names the
/// enrollments' files and quotes what it could not read, another origin's
/// enrollment among them, so it stays on the device.
pub(crate) fn store_error(_: String) -> Refusal {
    refused(
        Code::Store,
        "this device's enrollments could not be read or kept",
    )
}

pub(crate) fn source_error(error: SourceError) -> Refusal {
    match error {
        SourceError::Declined => declined(),
        SourceError::Failed(message) => refused(Code::Source, message),
    }
}

impl Session {
    /// The user granted the facility for this session. The enrolled
    /// member's tree is kept from then on, while a session holds it: its
    /// refresher starts at a drawn delay, on the space's feed connection,
    /// reading the space's device window first, and later sessions do not
    /// restart it; the session reads the node's clock at a drawn delay and
    /// keeps it read; spare connections are kept for the session's next
    /// proof and next fetch. So a sign-in or a payment asked a few seconds
    /// on reads nothing before its form, and sends one request after its
    /// confirm. Nothing is read before a grant.
    pub fn granted(&self) {
        if let Ok(Some(enrollment)) = self.inner.store.get(&self.origin) {
            self.keep(enrollment);
        }
    }

    /// Compute this origin's kernels' programs: the earliest moment its
    /// sign-in is known to be near is the user's grant.
    pub fn warm(&self) -> Option<Warming> {
        self.inner.enrolled_kernels();
        let kernels = match self.inner.store.get(&self.origin) {
            Ok(Some(enrollment)) => self
                .inner
                .kernels(&enrollment)
                .map(<[u8]>::to_vec)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect(),
            _ => Vec::new(),
        };
        Inner::warm(&self.inner, kernels)
    }

    /// One call of `operation`, confirmed in `chrome`.
    pub async fn call(
        &self,
        operation: Operation,
        chrome: &dyn Chrome,
    ) -> Result<Outcome, Refusal> {
        Ok(match operation {
            Operation::Enroll(request) => Outcome::Enrolled(self.enroll(request, chrome).await?),
            Operation::SignIn(request) => Outcome::SignedIn(self.sign_in(request, chrome).await?),
            Operation::Pay(request) => Outcome::Paid(self.pay(request, chrome).await?),
            Operation::Refresh => {
                self.refreshed();
                Outcome::Refreshed
            }
        })
    }

    /// The server says the node did not hold the proof's root: at a drawn
    /// delay the feed is due again, so a server cannot time this member's
    /// reads by asking; honoured at most once in [`REFRESH_EVERY`],
    /// whoever asks.
    pub fn refreshed(&self) {
        let Some(tree) = self.tree() else {
            return;
        };
        let recent = tree
            .last_refresh
            .lock()
            .expect("refresh poisoned")
            .is_some_and(|last| last.elapsed() < REFRESH_EVERY);
        if recent {
            return;
        }
        tree.unknown_at
            .lock()
            .expect("refresh poisoned")
            .get_or_insert_with(|| Instant::now() + below(REFRESH_SPREAD));
    }

    fn tree(&self) -> Option<Arc<Tree>> {
        let enrollment = self.inner.store.get(&self.origin).ok()??;
        self.inner.tree_of(&enrollment)
    }

    fn enrolled(&self) -> Result<Enrollment, Refusal> {
        self.inner
            .store
            .get(&self.origin)
            .map_err(store_error)?
            .ok_or_else(|| refused(Code::NotEnrolled, "this device is not enrolled here"))
    }

    /// The member's secret, derived again from the source's output for the
    /// space's handle, after the user's consent at the source; the output
    /// zeroized once copied. On the heap, so the prover's task takes it as a
    /// pointer and no freed task keeps its words.
    async fn secret(&self, enrollment: &Enrollment) -> Result<Arc<DeviceSecret>, Refusal> {
        secret_of(&*self.inner.source, enrollment).await
    }

    /// Refused, before any prompt, a proof for a session the facility does
    /// not carry, unless the user opted the space out of Tor: its server
    /// would join the device's network address to it. After an
    /// enrollment, s4 connects again, carried.
    fn carried(&self, enrollment: &Enrollment) -> Result<(), Refusal> {
        if self.gateway.carried || self.inner.net.opted_out(&enrollment.routes()) {
            return Ok(());
        }
        Err(refused(
            Code::Refused,
            "this session is not carried over Tor: reconnect, and s4 reaches this gateway over \
             Tor",
        ))
    }

    /// Refused, before any prompt, what would join a sign-in to the member
    /// in this session: a sign-in after the device was named in it (`to`
    /// [`Learned::SignedIn`]), or naming it after a sign-in. Otherwise the
    /// session is taken as `to` at once, in the same step, so two calls
    /// racing on one session cannot both pass.
    fn apart(&self, to: Learned) -> Result<(), Refusal> {
        let mut learned = self.learned.lock().expect("learned poisoned");
        let joined = match to {
            Learned::SignedIn => *learned == Learned::Named,
            Learned::Named => *learned == Learned::SignedIn,
            Learned::Nothing => false,
        };
        if !joined {
            *learned = to;
            return Ok(());
        }
        Err(refused(
            Code::Refused,
            match to {
                Learned::SignedIn => {
                    "this session was shown this device's digests or account: sign in from a new \
                     session, so the sign-in is not joined to them"
                }
                _ => {
                    "this session holds a sign-in: show the digests or pay from a new session, \
                     so the sign-in is not joined to them"
                }
            },
        ))
    }

    fn origin_line(&self) -> String {
        format!(
            "{} at {}:{} asks",
            self.origin.application, self.gateway.host, self.gateway.port
        )
    }
    /// `enroll`: this device enrolled in the request's space, the digests
    /// shown in the chrome and answered.
    pub async fn enroll(&self, request: Enroll, chrome: &dyn Chrome) -> Result<Enrolled, Refusal> {
        self.apart(Learned::Named)?;
        let store = &self.inner.store;
        let existing = store.get(&self.origin).map_err(store_error)?;
        if existing
            .as_ref()
            .is_some_and(|existing| !existing.pins(&request))
        {
            return Err(refused(
                Code::NotPinned,
                "this device is enrolled here for another space, agents or methods",
            ));
        }
        // Another server asking for a space this device is enrolled in
        // elsewhere could relay its proofs: refused.
        let elsewhere = store.others(&self.origin).map_err(store_error)?;
        if elsewhere
            .iter()
            .any(|other| other.handle == request.handle || other.space == request.space)
        {
            return Err(refused(
                Code::NotPinned,
                "this space is enrolled on this device through another server",
            ));
        }
        // A server naming this device's home could take the personal
        // agent's traffic, were their routes one: they are apart, and an
        // enrollment naming the home is refused unless it names the home's
        // own onion set (a home in a space the user belongs to).
        if let Some((handle, space, home_onions)) = self.inner.personal().and_then(|p| p.home()) {
            let named = crate::enrollment::onions(&request.onions);
            let same = |a: &[vos_wire::credentials::Onion], b: &[vos_wire::credentials::Onion]| {
                a.iter().all(|onion| b.contains(onion)) && b.iter().all(|onion| a.contains(onion))
            };
            if (request.handle == handle || request.space == space) && !same(&named, &home_onions) {
                return Err(refused(
                    Code::NotPinned,
                    "this server names this device's home, through onions other than the home's",
                ));
            }
        }
        let kinds = self.inner.source.kinds();
        // A handle a pairing gave this device here is enrolled already, by
        // the device that paired it: this device enrolls with the source
        // it derived that handle from, not a new key.
        let paired = match &existing {
            Some(_) => None,
            None => self.inner.owed_source(request.handle).await?,
        };
        let mut rows = vec![
            ("Space handle".to_owned(), short(&request.handle)),
            ("Space".to_owned(), short(&request.space)),
        ];
        rows.extend(
            request
                .agents
                .iter()
                .map(|agent| (format!("Agent {}", agent.agent), short(&agent.identity))),
        );
        rows.extend(
            request
                .methods
                .iter()
                .map(Method::from)
                .map(|method| describe(&method)),
        );
        rows.push((
            "Onions".to_owned(),
            format!(
                "{}{}",
                request.onions.len(),
                if request.onion_only {
                    ", onion-only"
                } else {
                    ""
                }
            ),
        ));
        let form = Form {
            title: if existing.is_some() {
                "Show this device's digests".into()
            } else {
                "Enroll this device".into()
            },
            detail: format!(
                "{} to enroll this device in a space, for these methods only. \
                 Check the space with its operator before you confirm.",
                self.origin_line()
            ),
            rows,
            fields: Vec::new(),
            notice: None,
            choices: match (&existing, &paired) {
                (Some(_), _) => vec!["Show".into()],
                (None, Some(paired)) => vec![choice(paired.kind()).into()],
                (None, None) => kinds.iter().map(|kind| choice(*kind).into()).collect(),
            },
        };
        let Answer::Confirmed { choice, .. } = chrome.confirm(form).await else {
            return Err(declined());
        };
        let reference = match (&existing, paired) {
            (Some(existing), _) => existing.source.clone(),
            (None, Some(paired)) => paired,
            (None, None) => {
                let kind = *kinds.get(choice).ok_or_else(declined)?;
                self.inner.source.create(kind).await.map_err(source_error)?
            }
        };
        let output = self
            .inner
            .source
            .evaluate(&reference, vos_light::source_input(&request.handle))
            .await
            .map_err(source_error)?;
        let (member, owner) = digests(&output, &request.handle);
        drop(output);
        let enrollment = Enrollment {
            handle: request.handle,
            space: request.space,
            agents: request.agents.iter().map(Agent::from).collect(),
            methods: request.methods.iter().map(Method::from).collect(),
            credentials: request.credentials.into(),
            source: reference,
            member: member.to_bytes(),
            owner: owner.to_bytes(),
            host: self.gateway.host.clone(),
            port: self.gateway.port,
            fingerprint: self.origin.host.clone(),
            application: self.origin.application.clone(),
            host_key: self.gateway.host_key,
            onions: crate::enrollment::onions(&request.onions),
            onion_only: request.onion_only,
        };
        if existing
            .as_ref()
            .is_some_and(|existing| existing.member != enrollment.member)
        {
            return Err(refused(
                Code::Source,
                "the source no longer gives this device's secret: revoke and enroll again",
            ));
        }
        store.put(&self.origin, &enrollment).map_err(store_error)?;
        self.keep(enrollment);
        self.inner.enrolled();
        // Its sign-in is near: its kernels' programs made meanwhile.
        drop(self.warm());
        // The digests the operator invites, shown here: a server's document
        // could show its own in their place.
        chrome
            .confirm(Form {
                title: "This device's digests".into(),
                detail: "Read these to the space's operator from this screen, never from \
                         the server's, so no one else's are invited in their place."
                    .into(),
                rows: vec![
                    ("Member".into(), hex::encode(member.to_bytes())),
                    ("Owner".into(), hex::encode(owner.to_bytes())),
                ],
                fields: Vec::new(),
                notice: None,
                choices: vec!["Done".into()],
            })
            .await;
        Ok(Enrolled {
            member: member.to_bytes(),
            owner: owner.to_bytes(),
        })
    }

    /// The pinned method `name`, which `wanted` accepts.
    fn pinned<'a>(
        enrollment: &'a Enrollment,
        agent: u32,
        instance: u32,
        name: &str,
        wanted: impl Fn(&Method) -> bool,
    ) -> Result<&'a Method, Refusal> {
        enrollment
            .method(agent, instance, name)
            .filter(|method| wanted(method))
            .ok_or_else(|| {
                refused(
                    Code::NotPinned,
                    format!("`{name}` at agent {agent}, instance {instance} was not pinned here"),
                )
            })
    }

    /// The member's path at the newest root its tree holds, as its last
    /// read left it.
    fn witness(&self) -> Option<AuthWitness> {
        self.tree()?
            .witness
            .lock()
            .expect("witness poisoned")
            .clone()
    }

    /// The node's time now, by this session's reading of its clock, or
    /// read now on a fetch of its own.
    async fn node_now(&self, enrollment: &Enrollment) -> Result<u64, Refusal> {
        self.clock
            .now(&self.inner.net, enrollment.routes(), self.id)
            .await
            .map_err(|error| refused(Code::Api, error))
    }

    /// The node's clock read while the user reads the form, if this
    /// session holds no reading: the call after the confirm then waits for
    /// that read, not a new one.
    fn read_clock_meanwhile(&self, enrollment: &Enrollment) {
        if self.clock.current().is_some() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let (clock, net, space, id) = (
            Arc::clone(&self.clock),
            Arc::clone(&self.inner.net),
            enrollment.routes(),
            self.id,
        );
        let task = runtime.spawn({
            let clock = Arc::clone(&clock);
            async move {
                let _ = clock.renew(&net, space, id).await;
            }
        });
        if let Some(last) = clock
            .meanwhile
            .lock()
            .expect("clock poisoned")
            .replace(task)
        {
            last.abort();
        }
    }

    /// Why the member has no path: its tree read to the feed's end holds
    /// no leaf of its (its invitation not claimed yet, or claimed since
    /// that read: the tree's own timer reads it again within a minute, no
    /// read made now, so none follows the sign-in); or the tree is not read
    /// to its end yet.
    async fn pathless(&self) -> Refusal {
        let leafless = match self.tree() {
            Some(tree) => {
                let keeper = tree.keeper.lock().await;
                keeper.caught_up() && keeper.slot().is_none()
            }
            None => false,
        };
        if leafless {
            refused(
                Code::Unclaimed,
                "claim your invitation first: the space's tree holds no leaf of this device's \
                 member (claimed just now? the device reads the tree again within a minute)",
            )
        } else {
            refused(
                Code::NoPath,
                "the device is still reading its space's tree: try again in a few seconds",
            )
        }
    }

    /// `sign_in`: a pinned auth-guarded call, proved.
    pub async fn sign_in(&self, request: SignIn, chrome: &dyn Chrome) -> Result<SignedIn, Refusal> {
        let enrollment = self.enrolled()?;
        let method = Self::pinned(
            &enrollment,
            request.agent,
            request.instance,
            &request.method,
            |method| matches!(method.guard, Guard::Auth { .. }),
        )?;
        self.carried(&enrollment)?;
        let Guard::Auth { scope, once } = &method.guard else {
            unreachable!("an auth guard, filtered above")
        };
        // What a `once` call spends its admission on must be what the user
        // sees: until the chrome reads a method's arguments from its schema,
        // a `once` call takes none.
        if *once && !request.arguments.is_empty() {
            return Err(refused(
                Code::Arguments,
                "a once-guarded call is proved with no arguments the chrome cannot show",
            ));
        }
        self.inner.admits(&enrollment, Kernel::Auth).await?;
        let Some(witness) = self.witness() else {
            return Err(self.pathless().await);
        };
        self.apart(Learned::SignedIn)?;
        self.read_clock_meanwhile(&enrollment);
        let form = Form {
            title: if *once {
                format!("Spend your one {}?", method.name)
            } else {
                format!("Prove membership: {}", method.name)
            },
            detail: format!(
                "{} this device to prove it is a member, without saying which.",
                self.origin_line()
            ),
            rows: vec![
                ("Space handle".into(), short(&enrollment.handle)),
                ("Method".into(), describe(method).1),
                ("Agent".into(), method.agent.to_string()),
                (
                    "Arguments".into(),
                    if request.arguments.is_empty() {
                        "none".into()
                    } else {
                        format!(
                            "{} bytes: {}",
                            request.arguments.len(),
                            hex::encode(&request.arguments[..request.arguments.len().min(32)])
                        )
                    },
                ),
            ],
            fields: Vec::new(),
            notice: once.then(|| {
                format!(
                    "This call spends your one admission in the scope “{scope}”: \
                     the space admits each member there once, for good."
                )
            }),
            choices: vec![if *once {
                "Spend it".into()
            } else {
                "Prove".into()
            }],
        };
        if !matches!(chrome.confirm(form).await, Answer::Confirmed { .. }) {
            return Err(declined());
        }
        // The secret is held until the node took a proof or refused it
        // for good: a root it no longer judges current is proved against
        // again, once, with no second prompt. The call is made before the
        // source is asked, so a node out of reach asks nothing.
        let arguments = request.arguments;
        let call = self
            .call_for(&enrollment, method, arguments.clone())
            .await?;
        let refused_root = witness.root;
        let secret = self.secret(&enrollment).await?;
        let started = Instant::now();
        let request = self.prove_sign_in(call, scope, &secret, witness).await?;
        let mut proving_ms = started.elapsed().as_millis() as u64;
        let mut answer = self.send(&enrollment, &request).await?;
        let again = match root_refused(&answer) {
            Some(stale) => self.next_witness(&enrollment, refused_root, stale).await,
            None => None,
        };
        if let Some(again) = again {
            let call = self.call_for(&enrollment, method, arguments).await?;
            let started = Instant::now();
            let request = self.prove_sign_in(call, scope, &secret, again).await?;
            proving_ms += started.elapsed().as_millis() as u64;
            drop(secret);
            answer = self.send(&enrollment, &request).await?;
        }
        Ok(SignedIn { answer, proving_ms })
    }

    /// `call` proved under `secret` on `witness`'s path in `scope`: the
    /// credentialed request.
    async fn prove_sign_in(
        &self,
        call: Call,
        scope: &str,
        secret: &Arc<DeviceSecret>,
        witness: AuthWitness,
    ) -> Result<Vec<u8>, Refusal> {
        let (secret, name) = (Arc::clone(secret), scope.to_owned());
        Inner::prove(
            &self.inner,
            Kernel::Auth,
            call,
            move |prover, program, call| {
                // The stock kernel's program, as the space's ingress
                // computes it from the installed kernel: the warm-up's if
                // it made it, waited for if it is making it.
                let proof = prover.prove_auth(&secret, &witness, name.as_bytes(), call, program);
                drop(secret);
                proof
            },
        )
        .await
    }

    /// After a proof on `refused`, a root, was answered as one the node
    /// does not hold (or, `stale`, as one superseded past its grace): the
    /// member's path to prove on again, once the keeper's next read is
    /// made on its own timer (the read that answer made due, at a drawn
    /// delay, never at once), and a further drawn delay has passed, so
    /// the proof does not follow the feed's read by a fixed time. `None`
    /// when no read is made in [`ROOT_RETRY`], the keeper holds no path
    /// after it, or a stale root is still the one it holds.
    async fn next_witness(
        &self,
        enrollment: &Enrollment,
        refused: Digest,
        stale: bool,
    ) -> Option<AuthWitness> {
        let tree = self.inner.tree_of(enrollment)?;
        let read = tree.reads.load(Ordering::Acquire);
        let deadline = Instant::now() + ROOT_RETRY;
        while tree.reads.load(Ordering::Acquire) == read {
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(ROOT_POLL).await;
        }
        tokio::time::sleep(below(ROOT_SPREAD)).await;
        tree.keeper
            .lock()
            .await
            .witness()
            .filter(|witness| !stale || witness.root != refused)
    }

    /// A proved request sent over Tor as a proven call, the spare's if one
    /// is built: the node's answer. One that names the root unknown or
    /// stale makes the feed due; one that no longer admits this app's
    /// device format is refused: the app needs updating.
    async fn send(&self, enrollment: &Enrollment, request: &[u8]) -> Result<Vec<u8>, Refusal> {
        let answer = self
            .inner
            .net
            .request_for(enrollment.routes(), Purpose::Proven, request, Some(self.id))
            .await
            .map_err(|error| refused(Code::Api, error))?;
        if root_refused(&answer).is_some()
            && let Some(tree) = self.inner.tree_of(enrollment)
        {
            tree.unknown(&mut *tree.keeper.lock().await);
        }
        if let Err(refusal) = update_refused(&answer) {
            // The window that admitted this format is the space's no more.
            self.inner.forget_window(enrollment);
            return Err(refusal);
        }
        Ok(answer)
    }

    /// `pay`: a transfer from this device's account, as the user confirmed
    /// it, proved.
    pub async fn pay(&self, request: Pay, chrome: &dyn Chrome) -> Result<Paid, Refusal> {
        let enrollment = self.enrolled()?;
        let method = Self::pinned(
            &enrollment,
            request.agent,
            request.instance,
            &request.method,
            |method| method.guard == Guard::Owner && method.name == TRANSFER,
        )?;
        self.carried(&enrollment)?;
        self.inner.admits(&enrollment, Kernel::Owner).await?;
        self.apart(Learned::Named)?;
        self.read_clock_meanwhile(&enrollment);
        let (mut payee, mut amount) = (request.payee.clone(), request.amount.to_string());
        let mut notice = None;
        let (payee, amount) = loop {
            let form = Form {
                title: "Confirm the payment".into(),
                detail: format!(
                    "{} this device to pay from its account. What you confirm here is \
                     what is paid.",
                    self.origin_line()
                ),
                rows: vec![
                    ("Space handle".into(), short(&enrollment.handle)),
                    ("Method".into(), describe(method).1),
                    ("From".into(), "this device's account".into()),
                ],
                fields: vec![
                    Field {
                        label: "To account".into(),
                        value: payee.clone(),
                    },
                    Field {
                        label: "Amount".into(),
                        value: amount.clone(),
                    },
                ],
                notice: notice.take(),
                choices: vec!["Pay".into()],
            };
            let Answer::Confirmed { values, .. } = chrome.confirm(form).await else {
                return Err(declined());
            };
            let [to, how_much] = values.as_slice() else {
                return Err(refused(Code::Arguments, "the form answered other fields"));
            };
            (payee, amount) = (to.trim().to_owned(), how_much.trim().to_owned());
            match (account(&payee), amount.parse::<u64>()) {
                (Ok(to), Ok(how_much)) if how_much > 0 => break (to, how_much),
                (Err(_), _) => {
                    notice = Some(
                        "An account's name is 1 to 32 ASCII letters, digits, `.`, `_` or `-`."
                            .into(),
                    )
                }
                _ => notice = Some("The amount is a whole number above zero.".into()),
            }
        };
        let values = (payee.clone(), amount);
        let answer = |answer: Vec<u8>, proving_ms: u64| Paid {
            answer,
            proving_ms,
            payee: values.0.clone(),
            amount: values.1,
        };
        // The same payment asked again while its last proof may still run
        // (a relay that withheld it, then asked anew) is that proof again:
        // its binding runs once.
        let now = self.node_now(&enrollment).await?;
        let tree = self.tree();
        let again = tree.as_ref().and_then(|tree| {
            tree.payment
                .lock()
                .expect("payment poisoned")
                .clone()
                .filter(|last| last.values == values && now + 5_000 < last.expires_ms)
        });
        if let Some(again) = again {
            return Ok(answer(self.send(&enrollment, &again.request).await?, 0));
        }
        let arguments = vos_light::transfer_arguments(&values.0, amount);
        let call = self.call_at(&enrollment, method, arguments, now)?;
        let secret = self.secret(&enrollment).await?;
        let started = Instant::now();
        let expires_ms = call.expires_ms;
        let bytes = Inner::prove(
            &self.inner,
            Kernel::Owner,
            call,
            move |prover, program, call| {
                let proof = prover.prove_owner(&secret, call, program);
                drop(secret);
                proof
            },
        )
        .await?;
        let proving_ms = started.elapsed().as_millis() as u64;
        if let Some(tree) = tree {
            *tree.payment.lock().expect("payment poisoned") = Some(Payment {
                values: values.clone(),
                expires_ms,
                request: bytes.clone(),
            });
        }
        Ok(answer(self.send(&enrollment, &bytes).await?, proving_ms))
    }

    /// A call of `method` with `arguments`, its expiry from the node's time
    /// by this session's reading of its clock.
    async fn call_for(
        &self,
        enrollment: &Enrollment,
        method: &Method,
        arguments: Vec<u8>,
    ) -> Result<Call, Refusal> {
        let now = self.node_now(enrollment).await?;
        self.call_at(enrollment, method, arguments, now)
    }

    fn call_at(
        &self,
        enrollment: &Enrollment,
        method: &Method,
        arguments: Vec<u8>,
        now: u64,
    ) -> Result<Call, Refusal> {
        Call::new(
            enrollment.space,
            method.agent,
            method.instance,
            vos_light::method_id(&method.name),
            arguments,
            now + EXPIRY_MS,
        )
        .map_err(|error| refused(Code::Prove, error.to_string()))
    }

    /// Hold `enrollment`'s tree for this session, its refresher started
    /// if none runs, the session's clock kept read, and spares kept for its
    /// proofs and fetches.
    fn keep(&self, enrollment: Enrollment) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Some(tree) = self.inner.tree_of(&enrollment) else {
            return;
        };
        self.inner.net.pin(enrollment.routes(), pinned(&enrollment));
        {
            let mut held = self.held.lock().expect("held poisoned");
            if held.is_none() {
                tree.sessions.fetch_add(1, Ordering::SeqCst);
                *held = Some(Arc::clone(&tree));
            }
        }
        self.inner.net.keep_spare(enrollment.routes(), self.id);
        self.keep_clock(&runtime, enrollment.routes());
        let mut refresher = tree.refresher.lock().expect("refresher poisoned");
        if refresher.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        let (weak, facility, tick, net) = (
            Arc::downgrade(&tree),
            Arc::downgrade(&self.inner),
            self.inner.tick,
            Arc::clone(&self.inner.net),
        );
        *refresher = Some(runtime.spawn(async move {
            // The first read at a drawn delay, not at the grant.
            tokio::time::sleep(below(tick)).await;
            let mut window_due = Instant::now();
            loop {
                let Some(tree) = weak.upgrade() else {
                    return;
                };
                // The window read again before a call would find it old,
                // and no more often, whatever a call made of it.
                if Instant::now() >= window_due
                    && let Some(facility) = facility.upgrade()
                {
                    let read = facility.window(&enrollment, WINDOW_RENEW).await;
                    window_due = Instant::now() + if read.is_ok() { WINDOW_RENEW } else { RETRY };
                }
                let wait = match read_once(&net, &tree, &enrollment).await {
                    Ok(()) => jittered(tick),
                    Err(_) => RETRY,
                };
                drop(tree);
                tokio::time::sleep(wait).await;
            }
        }));
    }

    /// The session's clock read at a drawn delay after its grant, and again
    /// as each reading falls due, while the app is in the foreground: the
    /// reads are fetches, each its own connection (its fetch spare's when
    /// one is built).
    fn keep_clock(&self, runtime: &tokio::runtime::Handle, space: [u8; 32]) {
        let mut task = self.clock.task.lock().expect("clock poisoned");
        if task.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        let (clock, net, id) = (
            Arc::clone(&self.clock),
            Arc::clone(&self.inner.net),
            self.id,
        );
        *task = Some(runtime.spawn(async move {
            tokio::time::sleep(below(CLOCK_SPREAD)).await;
            loop {
                let wait = match net.foreground() {
                    false => CLOCK_TICK,
                    true => match clock.renew(&net, space, id).await {
                        Ok(()) => jittered(CLOCK_TICK),
                        Err(_) => RETRY,
                    },
                };
                tokio::time::sleep(wait).await;
            }
        }));
    }
}

/// The feed read into `tree` if its keeper says so, on the space's feed
/// connection, and the keeper kept if the read changed it (a change
/// applied, or the tree dropped to start over from the feed's start); a
/// `refresh` asked for and due makes it so first.
async fn read_once(net: &Net, tree: &Tree, enrollment: &Enrollment) -> Result<(), String> {
    let registrar = registrar(enrollment)?;
    let mut keeper = tree.keeper.lock().await;
    {
        let mut unknown = tree.unknown_at.lock().expect("refresh poisoned");
        if unknown.is_some_and(|at| Instant::now() >= at) {
            *unknown = None;
            tree.unknown(&mut keeper);
            *tree.last_refresh.lock().expect("refresh poisoned") = Some(Instant::now());
        }
    }
    if !keeper.due(now_ms()) {
        return Ok(());
    }
    let before = keeper.encode();
    net.client()
        .read_tree(tree.space, &registrar, &mut keeper, now_ms)
        .await
        .map_err(|error| error.to_string())?;
    let after = keeper.encode();
    if after != before {
        write_private(&tree.file, &after)?;
    }
    *tree.witness.lock().expect("witness poisoned") = keeper.witness();
    tree.reads.fetch_add(1, Ordering::Release);
    Ok(())
}

/// The member's secret of `enrollment`, from its source's output after the
/// user's consent there.
pub(crate) async fn secret_of(
    source: &dyn Source,
    enrollment: &Enrollment,
) -> Result<Arc<DeviceSecret>, Refusal> {
    let output = source
        .evaluate(
            &enrollment.source,
            vos_light::source_input(&enrollment.handle),
        )
        .await
        .map_err(source_error)?;
    Ok(Arc::new(vos_light::derive_secret(
        &output,
        &enrollment.handle,
    )))
}

/// The member and owner digests of the secret `output` gives for `handle`.
/// The secret is derived and dropped here, on this call's stack: held in an
/// async function, it would sit in its future's state, which `drop` copies
/// out of and zeroizes only the copy of.
fn digests(output: &[u8; 32], handle: &[u8; 32]) -> (Digest, Digest) {
    let secret = vos_light::derive_secret(output, handle);
    (vos_light::member(&secret), vos_light::owner(&secret))
}

/// A uniform draw below `period`.
fn below(period: Duration) -> Duration {
    let mut bytes = [0; 8];
    let draw = match getrandom::getrandom(&mut bytes) {
        Ok(()) => u64::from_le_bytes(bytes),
        Err(_) => 0,
    };
    Duration::from_millis(draw % (period.as_millis() as u64).max(1))
}

/// `period`, moved uniformly by up to half of it either way.
fn jittered(period: Duration) -> Duration {
    period / 2 + below(period)
}

/// The button that enrolls with `kind`.
fn choice(kind: Kind) -> &'static str {
    match kind {
        Kind::Keystore | Kind::Admin => "Use this phone's lock",
        Kind::SecurityKey | Kind::Kit => "Use a security key",
    }
}

/// A pinned method as the chrome lists it: its use, and its place.
fn describe(method: &Method) -> (String, String) {
    match &method.guard {
        Guard::Auth { scope, once: false } => (
            "Sign in".into(),
            format!("{} (scope “{scope}”)", method.name),
        ),
        Guard::Auth { scope, once: true } => (
            "Once".into(),
            format!("{} (once in scope “{scope}”)", method.name),
        ),
        Guard::Owner => (
            "Pay".into(),
            format!("{} (from this device's account)", method.name),
        ),
    }
}

/// Whether the node answered a proof as one on a root it does not judge
/// current: `Some(false)` for one its ring does not hold (`RootUnknown`),
/// `Some(true)` for one superseded past its grace, at ingress
/// (`RootStale`) or at apply (`StaleRoot`).
fn root_refused(answer: &[u8]) -> Option<bool> {
    use vos_abi::abi::Refusal as Refused;
    use vos_wire::ingress::Response;
    match wire::credentialed_answer(answer) {
        Ok(wire::Answer::RootUnknown) => Some(false),
        Ok(wire::Answer::RootStale) => Some(true),
        Ok(wire::Answer::Other(body)) => matches!(
            <Response as vos_abi::Decode>::decode_exact(&body),
            Some(Response::Refused(Refused::StaleRoot))
        )
        .then_some(true),
        _ => None,
    }
}

/// Refused, as an app to update, when the node refused a proof for its
/// device format: one its ingress does not admit, or one the release or
/// the agent's log retired by the batch's time.
pub(crate) fn update_refused(answer: &[u8]) -> Result<(), Refusal> {
    match format_refused(answer) {
        true => Err(refused(Code::Refused, UPDATE)),
        false => Ok(()),
    }
}

fn format_refused(answer: &[u8]) -> bool {
    use vos_abi::abi::Refusal as Refused;
    use vos_wire::ingress::{CredentialRefusal, Response};
    match wire::credentialed_answer(answer) {
        Ok(wire::Answer::Refused(CredentialRefusal::Format)) => true,
        Ok(wire::Answer::Other(body)) => matches!(
            <Response as vos_abi::Decode>::decode_exact(&body),
            Some(Response::Refused(Refused::Format))
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::source::{BoxFuture, Output, Reference};

    struct NoSource;

    impl Source for NoSource {
        fn kinds(&self) -> Vec<Kind> {
            Vec::new()
        }

        fn create(&self, _: Kind) -> BoxFuture<'_, Result<Reference, SourceError>> {
            Box::pin(async { Err(SourceError::Declined) })
        }

        fn evaluate<'a>(
            &'a self,
            _: &'a Reference,
            _: [u8; 32],
        ) -> BoxFuture<'a, Result<Output, SourceError>> {
            Box::pin(async { Err(SourceError::Declined) })
        }
    }

    fn enrollment(guard: Guard) -> Enrollment {
        Enrollment {
            fingerprint: origin().host,
            application: origin().application,
            ..crate::enrollment::fixture(vec![Method {
                agent: 7,
                instance: 4,
                name: "login".into(),
                guard,
            }])
        }
    }

    /// A dial that reaches nothing.
    struct Nowhere;

    impl vos_light::tor::Dial for Nowhere {
        fn dial(
            &self,
            _: &vos_light::tor::Target,
            _: vos_light::tor::Circuit,
        ) -> vos_light::tor::Dialing {
            Box::pin(async { Err(std::io::Error::other("no network")) })
        }
    }

    /// A facility under `directory` that reaches no gateway, on `runtime`.
    fn unreachable(
        runtime: &tokio::runtime::Runtime,
        store: Store,
        directory: &std::path::Path,
    ) -> Facility {
        let _entered = runtime.enter();
        Facility::new(
            store,
            Arc::new(NoSource),
            Arc::new(Net::new(Arc::new(Nowhere), directory)),
        )
    }

    fn origin() -> Origin {
        Origin {
            host: "SHA256:abc".into(),
            application: "vos.test".into(),
        }
    }

    /// A guard's stock kernel's program is computed by the warm-up once,
    /// the sign-in's ask a hit, and dropped once no enrollment proves with
    /// it.
    #[test]
    fn a_stock_kernels_program_is_kept_while_a_guard_proves_with_it() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path());
        let login = Guard::Auth {
            scope: "login".into(),
            once: false,
        };
        store.put(&origin(), &enrollment(login)).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let facility = unreachable(&runtime, store.clone(), directory.path());
        let inner = &facility.inner;
        let (auth, owner) = (warm::key(&inner.stock.auth), warm::key(&inner.stock.owner));
        assert!(!inner.programs.holds(&auth));

        facility.warm().unwrap().join();
        assert!(inner.programs.holds(&auth));
        assert!(!inner.programs.holds(&owner));
        let program = inner.program(&inner.stock.auth).unwrap();
        facility.warm().unwrap().join();
        assert!(Arc::ptr_eq(
            &program,
            &inner.program(&inner.stock.auth).unwrap()
        ));
        // Nothing proved: the prover was not even made.
        assert!(inner.prover.lock().unwrap().is_none());

        store.put(&origin(), &enrollment(Guard::Owner)).unwrap();
        facility.warm().unwrap().join();
        assert!(!inner.programs.holds(&auth));
        assert!(inner.programs.holds(&owner));
    }

    /// The embedded stock artifacts are programs of the device format, and
    /// an artifact whose id is not its program's proves nothing.
    #[test]
    fn the_stock_artifacts_are_programs() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let facility = unreachable(&runtime, Store::new(directory.path()), directory.path());
        let stock = Stock::embedded();
        for artifact in [&stock.auth, &stock.owner] {
            facility.inner.program(artifact).unwrap();
        }
        let mut renamed = <Release as vos_abi::Decode>::decode_exact(&stock.owner).unwrap();
        renamed.id[0] ^= 1;
        let renamed = vos_abi::Encode::encode(&renamed);
        assert_eq!(
            facility.inner.program(&renamed).map(drop),
            Err(DeviceError::Program(vos_light::ProgramError::IdMismatch))
        );
    }
}
