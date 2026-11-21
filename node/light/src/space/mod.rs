//! The device's personal space (`light-node.md` §3): the light node with
//! its local actors, the device group at the personal agent, and the flows
//! a UI drives, over the [`Host`]'s network, its prompts the user's
//! ([`Prompts`]).
//!
//! - **What the device keeps** is the light node's store alone (under
//!   [`LIGHT`]): beside its group, claim and pairing rows, the home and the
//!   agent it claimed or joined, the secret source's key it proves there
//!   with, its admin key's public half (the key is the UI's, behind a
//!   strong biometric), its label (`rows`). Each change is one batch: the
//!   home and agent are written in the batch of the claim, the pairing's
//!   group or the restore's split that makes them the device's, so a crash
//!   leaves the device before the step or after it. A store of another
//!   layout is refused and kept as it is, the personal space named in need
//!   of repair.
//! - **What a flow keeps before its step at the agent**: each key the
//!   moment it is made; a flow called again resumes what the store shows
//!   held, and the pass finishes what needs no prompt (an acknowledgement,
//!   the credential book).
//! - **The flows** ([`Personal`]'s methods): the claim at a home-only space
//!   with a phrase or a security-key kit; pairing, as the device that shows
//!   the code ([`Personal::pair_offer`], [`Personal::pair_await`]) and as the
//!   one that scans it ([`Personal::pair_join`], which also pairs again a
//!   device that holds another personal space, or a removed one, leaving it
//!   first); the memberships a pairing leaves; the device set's
//!   operations; a restore from the kit; a move home.
//! - **Forgetting** (`Personal::forget`): a device gives up the personal
//!   space it holds with no call to its agent: its light node's store made
//!   anew, as at a fresh install. A move home is a leave of this kind and a
//!   claim at the new home, a device paired again after a move or a regroup
//!   one and a pairing: nothing is carried, since the personal space holds
//!   the credential book and the device book alone, which each device
//!   writes again from what it holds ([`Artifacts`]).
//! - **Leaving** ([`Personal::leave`]): the device's own removal, signed by
//!   its admin key and read through to `Out`, then the space forgotten; the
//!   other devices commit the removal.
//! - **The prompts are the user's**: a kit shown or entered, a secret
//!   source's output, a security key's `hmac-secret`, the admin key's
//!   signature over bytes prepared here; none is asked outside a flow the
//!   user started.
//! - **The pass** ([`Personal::pass`]): the background job's, on the
//!   `Background` isolation group, a flow's on `Personal`; the personal
//!   agent's traffic never shares a circuit with a proof.

mod claim;
mod error;
mod files;
mod host;
mod kit;
pub mod link;
mod members;
mod pairing;
mod restore;
mod rows;
mod set;
mod status;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_abi::ids::InstanceId;
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode};
use vos_wire::credentials::Onion;
use vos_wire::personal::{KitKind, NewDevice, NewKit};
use zeroize::Zeroizing;

use crate::group::{Alarm, DeviceGroup};
use crate::home::Home;
use crate::kit::{KitKey, KitSecret, SecurityKey};
use crate::route::Purpose;
use crate::{Config, Light, memberships, wire};
use files::create_private;
use link::{Agent, AgentLink, Signer};

pub use error::Error;
pub(crate) use error::{answered, failed, logged, store_failed, unreached};
pub use host::{AdminKey, Approval, Card, Enrolled, Host, Prompts, Proof, Stage};
pub use kit::KitView;
pub use pairing::PairCode;
pub use set::{AdminOffer, Device};
pub use status::{Phase, Status};

/// The light node's store, under the personal space's directory: the
/// directory of the first store, and the prefix of each later one's, which
/// a leave makes anew (`light_dir`); the device's is the newest whose
/// first batch made it so.
pub const LIGHT: &str = "light";
pub use vos_wire::personal::PERSONAL;
/// The local actors: the credential book and the device book.
pub const CREDENTIAL_BOOK: InstanceId = InstanceId(1);
pub const DEVICE_BOOK: InstanceId = InstanceId(2);

/// The light node's artifacts: the default agent's program, and the local
/// actors' packages. The local actors are the credential book and the
/// device book, which each device writes again from what it holds: so a
/// leave, a move home among them, carries nothing (`Personal::forget`). A
/// local actor holding what no device writes again needs the move to carry
/// its scope first.
#[derive(Clone)]
pub struct Artifacts {
    pub agent: Vec<u8>,
    pub books: Vec<(InstanceId, Vec<u8>)>,
}

/// A home as kept: where it is, and its onions.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Kept {
    pub home: Home,
    pub onions: Vec<Onion>,
}

impl State {
    /// The onions of the home whose handle is `handle` that its last read
    /// no longer named, while they stay pinned at `now`.
    fn previous(&self, handle: &[u8; 32], now: u64) -> Vec<Onion> {
        self.onions
            .as_ref()
            .filter(|refreshed| refreshed.handle == *handle && now < refreshed.until)
            .map(|refreshed| refreshed.previous.clone())
            .unwrap_or_default()
    }
}

impl Kept {
    /// A home known by its handle and onions alone, as a pairing code
    /// names it: the rest comes in the opener's offer.
    fn reached(handle: [u8; 32], onions: Vec<Onion>) -> Self {
        Kept {
            home: Home {
                space: [0; 32],
                handle,
                agent: 0,
                identity: [0; 32],
                homes: InstanceId(0),
                credentials: InstanceId(0),
            },
            onions,
        }
    }

    /// Its card, shown with a kit.
    fn card(&self) -> Card {
        Card {
            handle: self.home.handle,
            onions: self.onions.clone(),
        }
    }
}

/// A claim at `home` with a new kit of `kit`, this device named `label` to
/// the user's other devices: what a restore and a move home take too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub home: Kept,
    pub kit: KitKind,
    pub label: String,
}

/// A claim's (a restore's, a move's) result: the agent, and this device's
/// id in its set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claimed {
    pub agent: u32,
    pub device: u32,
}

/// A pairing's result: the new device's id, and the memberships it is to
/// be enrolled in (the opener's) or to confirm (the joiner's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Paired {
    pub device: u32,
    pub memberships: u32,
}

/// An admin call the agent took: its log index and batch time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Posted {
    pub index: u64,
    pub at: u64,
}

pub use members::{Membership, Owed};

/// What the device keeps of its personal space, as its rows hold it
/// (`rows`).
#[derive(Clone, Default)]
struct State {
    /// The home its agent is at.
    home: Option<Kept>,
    /// The agent and its identity.
    agent: Option<(u32, [u8; 32])>,
    /// The secret source's key the device proves with at its homes and
    /// derives its handles in offered spaces from.
    source: Option<Vec<u8>>,
    /// The admin key's public half and its attestation, as its key in the
    /// UI's keystore answered them.
    admin: Option<AdminKey>,
    label: String,
    /// The admin keys offered to replace this device's, the newest last,
    /// until the set shows one of them.
    next_admin: Vec<AdminKey>,
    /// A restore opened, from before its call until it matures.
    restoring: Option<Restoring>,
    /// A joiner's acknowledgement of its pairing's handover, kept before
    /// it is put in the slot, until it is.
    acked: Option<Acked>,
    /// The kit's calls on the device set as signed, kept before they leave
    /// until their evidence is posted.
    kit_calls: Vec<KitCall>,
    /// The home's onion set's last read from its registrar.
    onions: Option<Refreshed>,
}

/// The home's onion set as last read from its registrar (the current set
/// is the kept home's): when, and the onions it no longer named, still
/// pinned beside it until `until`, so one forged answer cannot leave the
/// device without a way home. Of the home whose handle it names alone.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
struct Refreshed {
    handle: [u8; 32],
    at: u64,
    previous: Vec<Onion>,
    until: u64,
}

/// How often the home's onion set is read again, as an enrolled space's
/// is: once a day.
pub const ONIONS_EVERY_MS: u64 = 24 * 60 * 60 * 1000;
/// How long the onions a read no longer names stay pinned.
pub const ONIONS_KEPT_MS: u64 = 7 * ONIONS_EVERY_MS;
/// How soon a read of the home's onion set that failed is tried again.
const ONIONS_RETRY_MS: u64 = 60 * 60 * 1000;

/// Whether two onion sets name the same onions, in any order.
fn same_onions(a: &[Onion], b: &[Onion]) -> bool {
    a.len() == b.len() && a.iter().all(|onion| b.contains(onion))
}

/// A kit's call on the device set at the agent `identity`, as signed.
#[derive(Clone, Encode, Decode)]
struct KitCall {
    identity: [u8; 32],
    message: Vec<u8>,
    signature: [u8; 64],
}

/// The directory of the light node's store of `generation` under
/// `directory`.
fn light_dir(directory: &Path, generation: u32) -> PathBuf {
    match generation {
        0 => directory.join(LIGHT),
        n => directory.join(format!("{LIGHT}.{n}")),
    }
}

/// The device's store under `directory`, and its generation: the
/// newest, each one there made whole before it is named ([`fresh`]); none
/// at all, a fresh install, made now. One this build does not read, or
/// one its first batch did not make the device's, is refused, and left as
/// it is.
fn store(directory: &Path, artifacts: &Artifacts) -> Result<(u32, Light), Error> {
    let generations = generations(directory)?;
    let Some(generation) = generations.iter().copied().max() else {
        return Ok((0, fresh(directory, artifacts, 0, &State::default())?));
    };
    let light = Light::open(
        &light_dir(directory, generation),
        &artifacts.agent,
        Config::default(),
    )
    .map_err(|error| Error::NeedsRepair(format!("its store: {error}")))?;
    if !rows::ready(light.store())? {
        return Err(Error::NeedsRepair(
            "its store was not made the device's".into(),
        ));
    }
    Ok((generation, light))
}

/// Where a store of `generation` is made before it is named.
fn partial(directory: &Path, generation: u32) -> PathBuf {
    let mut dir = light_dir(directory, generation).into_os_string();
    dir.push(".partial");
    PathBuf::from(dir)
}

/// A store made anew as generation `generation`, its local actors
/// installed, made the device's by its first batch, which writes `state`:
/// all of it under a partial directory, renamed to the generation's once
/// written, so a store cut short is never one the next open takes. A
/// generation already there is refused: nothing named is written over.
fn fresh(
    directory: &Path,
    artifacts: &Artifacts,
    generation: u32,
    state: &State,
) -> Result<Light, Error> {
    let dir = light_dir(directory, generation);
    if dir.exists() {
        return Err(Error::NeedsRepair(format!(
            "its store of generation {generation} is there already"
        )));
    }
    let making = partial(directory, generation);
    if making.exists() {
        std::fs::remove_dir_all(&making).map_err(store_failed)?;
    }
    create_private(&making).map_err(store_failed)?;
    {
        let light =
            Light::open(&making, &artifacts.agent, Config::default()).map_err(store_failed)?;
        install(&light, &artifacts.books)?;
        light
            .store()
            .write_group_rows(state.first_rows())
            .map_err(store_failed)?;
    }
    std::fs::rename(&making, &dir).map_err(store_failed)?;
    std::fs::File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(store_failed)?;
    Light::open(&dir, &artifacts.agent, Config::default()).map_err(store_failed)
}

/// The generations of the stores under `directory` (a partial one is
/// none).
fn generations(directory: &Path) -> Result<Vec<u32>, Error> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(store_failed(error)),
    };
    let mut generations = Vec::new();
    for entry in entries {
        let entry = entry.map_err(store_failed)?;
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let generation = match name.strip_prefix(LIGHT) {
            Some("") => Some(0),
            Some(rest) => rest.strip_prefix('.').and_then(|rest| rest.parse().ok()),
            None => None,
        };
        generations.extend(generation);
    }
    Ok(generations)
}

/// The stores of generations other than `generation` under `directory`,
/// deleted: a leave's old store, or the new one a leave cut short before
/// it was the device's.
fn drop_stores(directory: &Path, generation: u32) {
    let current = light_dir(directory, generation);
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let ours = name == LIGHT
            || name
                .strip_prefix(LIGHT)
                .is_some_and(|rest| rest.starts_with('.'));
        if ours && path != current && path.is_dir() {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

/// A restore opened at the agent of `home`: the next kit's key and its
/// `R`'s hash; the call's arguments (this device, the kit split for it);
/// the `R2` its evidence carries, until it is posted; and the kit-signed
/// call as signed, before it was sent.
#[derive(Clone, Encode, Decode)]
struct Restoring {
    next: KitKey,
    r_hash: [u8; 32],
    arguments: Vec<u8>,
    r2: Option<[u8; 32]>,
    signed: Option<(Vec<u8>, [u8; 64])>,
    /// When it matures uncontested, once the agent's log showed it.
    matures: u64,
}

impl Restoring {
    /// A restore of `device` with `kit`, split for the next kit `next`.
    fn new(device: &NewDevice, kit: &NewKit, next: KitKey, r2: [u8; 32]) -> Self {
        Self {
            next,
            r_hash: kit.r_hash,
            arguments: (device.clone(), kit.clone()).encode(),
            r2: Some(r2),
            signed: None,
            matures: 0,
        }
    }
}

/// A joiner's acknowledgement, and what its put in the slot takes of the
/// code scanned: the home's handle and onions, the agent, the slot key's
/// seed and the slot's expiry (ms). Nothing else of the code is kept.
#[derive(Clone, Encode, Decode)]
struct Acked {
    handle: [u8; 32],
    onions: Vec<Onion>,
    agent: (u32, [u8; 32]),
    slot: [u8; 32],
    expires: u64,
    ack: Vec<u8>,
}

impl State {
    /// The offered admin key `key`, if it is one.
    fn next_admin(&self, key: &[u8; 32]) -> Option<AdminKey> {
        self.next_admin
            .iter()
            .find(|next| next.key == *key)
            .copied()
    }

    /// `next` offered too: any key offered may be the one signed in, so
    /// the last few are kept.
    fn set_next_admin(&mut self, next: AdminKey) {
        const KEPT: usize = 4;
        self.next_admin.push(next);
        if self.next_admin.len() > KEPT {
            self.next_admin.remove(0);
        }
    }
}

/// Each local actor in `books` installed, or upgraded in place: one not
/// installed, or installed at a release before the package's, as the store
/// records it. Whether one was.
fn install(light: &Light, books: &[(InstanceId, Vec<u8>)]) -> Result<bool, Error> {
    let mut changed = false;
    for (instance, package) in books {
        let package = crate::release::Package::decode_exact(package)
            .ok_or_else(|| store_failed("a local actor's package does not decode"))?;
        let at = light.release(*instance).map_err(store_failed)?;
        if at.is_some_and(|at| at >= package.release) {
            continue;
        }
        match light.install(*instance, &package, Vec::new()) {
            Ok(Outcome::Done(_)) => changed = true,
            Ok(other) => {
                return Err(store_failed(format!(
                    "a local actor's install answered {other:?}"
                )));
            }
            Err(error) => return Err(store_failed(error)),
        }
    }
    Ok(changed)
}

/// What a flow holds while it runs: the light node, its device group, the
/// keys' sessions, and a pairing under way.
struct Held {
    light: Light,
    group: Option<DeviceGroup>,
    state: State,
    sync: Signer,
    admin: Signer,
    pairing: Option<pairing::Pairing>,
    /// The store's generation: its directory (`light_dir`).
    generation: u32,
}

/// Whether a pairing waits on its slot, and whether the user cancelled
/// it: kept apart from the held state, so a cancel never waits for the
/// pairing it stops, which reads it between two reads of the slot.
#[derive(Default)]
struct Waiting {
    waiting: AtomicBool,
    cancelled: AtomicBool,
}

impl Waiting {
    fn start(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
        self.waiting.store(true, Ordering::SeqCst);
    }

    fn end(&self) {
        self.waiting.store(false, Ordering::SeqCst);
        self.cancelled.store(false, Ordering::SeqCst);
    }

    fn cancel(&self) {
        if self.waiting.load(Ordering::SeqCst) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// How long a flow waits for the agent to take a claim (ms), and between
/// reads of a slot or a log.
pub const WAIT_MS: u64 = 120_000;
const POLL: Duration = Duration::from_millis(500);
/// A proven call's expiry past the node's time.
const EXPIRY_MS: u64 = 60_000;

/// The device's personal space, its flows run over `H`.
pub struct Personal<H: Host> {
    host: H,
    held: Mutex<Held>,
    waiting: Waiting,
    /// How long a flow waits for the agent (ms): [`WAIT_MS`] unless set.
    wait: AtomicU64,
    /// The follows a flow left for after it returned.
    behind: AtomicUsize,
    /// The node's time each kept-open purpose read last, which a flow's
    /// links count on.
    clocks: link::Clocks,
    /// The state as [`Personal::status`] last read it.
    last: Mutex<Option<Status>>,
    /// The light node's store and the source kept, as an enrollment asks
    /// them while a flow holds the rest.
    owed: (Mutex<crate::Store>, Mutex<Option<Vec<u8>>>),
    /// The home kept, as an enrollment asks it while a flow holds the rest.
    home: Mutex<Option<Kept>>,
    /// When the home's onion set was last asked for, read or not.
    onions_tried: AtomicU64,
    /// The personal space's directory, and the artifacts a store made anew
    /// installs (`Personal::forget`).
    directory: PathBuf,
    artifacts: Artifacts,
}

/// What one pass found: the device set's notices, the group's alarms
/// among them, each device's last call the agent took, and why it stopped
/// short, if it did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Passed {
    pub notices: Vec<crate::job::Notice>,
    pub alarms: Vec<Alarm>,
    pub seen: Vec<(u32, u64)>,
    pub stopped: Option<String>,
}

impl<H: Host> Personal<H> {
    /// The personal space under `directory`, its light node opened from
    /// `artifacts`, its local actors installed or upgraded, what a flow
    /// left done in the store made the device's, its homes' routes told to
    /// the host. A store this build does not read, or a row of it, is
    /// refused as in need of repair, and left as it is.
    pub fn open(directory: &Path, artifacts: &Artifacts, host: H) -> Result<Self, Error> {
        let (generation, light) = store(directory, artifacts)?;
        drop_stores(directory, generation);
        let mut state = State::read(light.store())?;
        install(&light, &artifacts.books)?;
        let group = DeviceGroup::open(light.store())
            .map_err(|error| Error::NeedsRepair(format!("its device group: {error}")))?;
        let expired = state
            .acked
            .as_ref()
            .is_some_and(|acked| acked.expires < host.now());
        if expired {
            state.acked = None;
        }
        let sync = Signer::new(light.sync_key().verifying_key().to_bytes());
        let admin = Signer::new(state.admin.map(|admin| admin.key).unwrap_or_default());
        let owed = (
            Mutex::new(light.store().clone()),
            Mutex::new(state.source.clone()),
        );
        let home = Mutex::new(state.home.clone());
        let space = Self {
            host,
            held: Mutex::new(Held {
                light,
                group,
                state,
                sync,
                admin,
                pairing: None,
                generation,
            }),
            waiting: Waiting::default(),
            wait: AtomicU64::new(WAIT_MS),
            behind: AtomicUsize::new(0),
            clocks: link::Clocks::default(),
            last: Mutex::new(None),
            owed,
            home,
            onions_tried: AtomicU64::new(0),
            directory: directory.to_path_buf(),
            artifacts: artifacts.clone(),
        };
        let held = space.held();
        if expired {
            space.keep(&held.light, &held.state)?;
        }
        if let Some(kept) = &held.state.home {
            space.pin_with(
                kept,
                &held.state.previous(&kept.home.handle, space.host.now()),
            );
        }
        drop(held);
        Ok(space)
    }

    fn held(&self) -> MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The host the flows run over.
    pub fn host(&self) -> &H {
        &self.host
    }

    /// A home's routes: its onions, onion-only (E17), under the home's
    /// own key ([`crate::route::home`]).
    /// A card's or a code's set for the device's own home joins the set
    /// it holds, refreshed, so a kit call or a pairing never narrows it.
    fn pin(&self, kept: &Kept) {
        let held = self
            .home()
            .filter(|mine| mine.home.handle == kept.home.handle)
            .map(|mine| mine.onions)
            .unwrap_or_default();
        self.pin_with(kept, &held);
    }

    /// The same, the onions a read no longer names beside them.
    fn pin_with(&self, kept: &Kept, previous: &[Onion]) {
        let mut onions = kept.onions.clone();
        for onion in previous {
            if !onions.iter().any(|kept| kept.key == onion.key) {
                onions.push(*onion);
            }
        }
        self.host
            .pin(&crate::route::home(&kept.home.handle), &onions);
    }

    /// The home's onion set read again from its registrar, once a day
    /// ([`ONIONS_EVERY_MS`]), through the set pinned: a usable set (1 to
    /// [`vos_wire::credentials::MAX_ONIONS`] distinct onions) becomes the
    /// kept home's, the onions it no longer names pinned beside it for
    /// [`ONIONS_KEPT_MS`]. The answer is the gateway's word.
    fn refresh_onions(&self, held: &mut Held, now: u64) -> Result<(), Error> {
        let Some(kept) = held.state.home.clone() else {
            return Ok(());
        };
        let handle = kept.home.handle;
        let last = held
            .state
            .onions
            .as_ref()
            .filter(|refreshed| refreshed.handle == handle)
            .map_or(0, |refreshed| refreshed.at);
        let tried = self.onions_tried.load(Ordering::Relaxed);
        if now.saturating_sub(last) < ONIONS_EVERY_MS || now.saturating_sub(tried) < ONIONS_RETRY_MS
        {
            return Ok(());
        }
        self.onions_tried.store(now, Ordering::Relaxed);
        // The node's time and the query on one fetch of their own.
        let home = &kept.home;
        let answer = self
            .host
            .fetch_timed(&To::Home(home.handle).routes(), &mut |now| {
                wire::query_request(
                    home.agent,
                    &home.identity,
                    home.credentials.0,
                    vos_wire::credentials::method::ONIONS,
                    Vec::new(),
                    now + EXPIRY_MS,
                )
                .map_err(|error| error.to_string())
            })
            .map_err(Error::Unreachable)?;
        let onions: Vec<Onion> = wire::query_answer(&answer).map_err(failed)?;
        if !crate::route::usable_onions(&onions) {
            return Err(failed("the home's registrar served an unusable onion set"));
        }
        let mut previous: Vec<Onion> = Vec::new();
        for onion in held
            .state
            .previous(&handle, now)
            .into_iter()
            .chain(kept.onions.iter().copied())
        {
            let known = previous
                .iter()
                .chain(&onions)
                .any(|seen| seen.key == onion.key);
            if !known {
                previous.push(onion);
            }
        }
        previous.truncate(vos_wire::credentials::MAX_ONIONS);
        let until = match previous.is_empty() {
            true => 0,
            false if same_onions(&onions, &kept.onions) => held
                .state
                .onions
                .as_ref()
                .map_or(0, |refreshed| refreshed.until),
            false => now.saturating_add(ONIONS_KEPT_MS),
        };
        let kept = Kept { onions, ..kept };
        held.state.home = Some(kept.clone());
        held.state.onions = Some(Refreshed {
            handle,
            at: now,
            previous: previous.clone(),
            until,
        });
        self.keep(&held.light, &held.state)?;
        self.pin_with(&kept, &previous);
        Ok(())
    }

    /// What `state` keeps written to `light`'s store, in one batch.
    fn keep(&self, light: &Light, state: &State) -> Result<(), Error> {
        light
            .store()
            .write_group_rows(state.rows())
            .map_err(store_failed)?;
        self.mirror(state);
        Ok(())
    }

    /// `next` the device's state, its rows written in a flow's batch.
    fn adopt(&self, held: &mut Held, next: State) {
        self.mirror(&next);
        held.state = next;
    }

    /// What an enrollment reads while a flow holds the rest, as `state`
    /// keeps it.
    fn mirror(&self, state: &State) {
        *self.owed.1.lock().unwrap_or_else(|e| e.into_inner()) = state.source.clone();
        *self.home.lock().unwrap_or_else(|e| e.into_inner()) = state.home.clone();
    }

    /// Whether the device holds a personal space's group.
    pub fn grouped(&self) -> bool {
        self.held().group.is_some()
    }

    /// Forget the personal space this device holds, for good, with no call
    /// to its agent: a store made anew under the next generation's
    /// directory, its local actors installed there, then made the device's
    /// by its first batch, which keeps the source and the label and drops
    /// the home, the agent, the admin key and every flow's state; the old
    /// store's directory deleted after. The device then holds no personal
    /// space, as at a fresh install: it claims, or pairs, with new sync and
    /// admin keys. Cut short before the new store is named, the old space
    /// stands; after, the old directory goes at the next open.
    fn forget(&self, held: &mut Held) -> Result<(), Error> {
        let generation = held.generation + 1;
        let state = State {
            source: held.state.source.clone(),
            label: held.state.label.clone(),
            ..State::default()
        };
        let light = fresh(&self.directory, &self.artifacts, generation, &state)?;
        *self.owed.0.lock().unwrap_or_else(|e| e.into_inner()) = light.store().clone();
        held.sync = Signer::new(light.sync_key().verifying_key().to_bytes());
        held.admin = Signer::new([0; 32]);
        held.group = None;
        held.pairing = None;
        self.adopt(held, state);
        held.light = light;
        held.generation = generation;
        drop_stores(&self.directory, generation);
        Ok(())
    }

    /// How long a flow waits for the agent (ms), [`WAIT_MS`] unless set:
    /// tests shorten it.
    #[doc(hidden)]
    pub fn set_wait(&self, ms: u64) {
        self.wait.store(ms, Ordering::Relaxed);
    }

    fn wait(&self) -> Duration {
        Duration::from_millis(self.wait.load(Ordering::Relaxed))
    }

    fn wait_ms(&self) -> u64 {
        self.wait.load(Ordering::Relaxed)
    }

    /// The data key of the scope `name` names at the confirmed epoch.
    pub fn scope_key(&self, name: &[u8]) -> Result<[u8; 32], Error> {
        let mut held = self.held();
        let group = held.group.as_mut().ok_or(Error::NoSpace)?;
        let scope = group.archive().scope(name);
        group.key(scope).map_err(failed)
    }

    /// How many spaces the credential book records `device`'s handle in,
    /// as this device's light node reads the book: what reached it.
    #[doc(hidden)]
    pub fn recorded(&self, device: u32) -> usize {
        memberships::handles_of(&self.held().light, CREDENTIAL_BOOK, device)
            .map_or(0, |handles| handles.len())
    }

    /// The light node's sync key's public half: the device's author.
    pub fn sync_key(&self) -> [u8; 32] {
        self.held().light.sync_key().verifying_key().to_bytes()
    }

    /// The background job's pass at the device's time `now`, on its own
    /// isolation group: a joiner's acknowledgement left by a process that
    /// died first put in its slot, the light node's job, and the
    /// credential book's records of this device's enrollments.
    pub fn pass(&self, now: u64) -> Result<Passed, Error> {
        let mut held = self.held();
        let mut failures = Vec::new();
        if let Err(error) = self.acknowledge(&mut held) {
            failures.push(format!("the pairing's acknowledgement: {error}"));
        }
        let Held {
            light,
            group,
            state,
            sync,
            ..
        } = &mut *held;
        let (Some(group), Some(home), Some(agent)) = (group.as_mut(), &state.home, state.agent)
        else {
            return Err(Error::NoSpace);
        };
        let key = light.sync_key().clone();
        let mut link = self.link(home, Purpose::Background, agent, &key, sync);
        // The log is followed and `alive` posted even when the scopes
        // cannot be read.
        let instances = light.instances().unwrap_or_else(|error| {
            failures.push(format!("the local actors: {error}"));
            Vec::new()
        });
        let pass = match crate::job::run(light, group, &mut link, &instances, now) {
            Ok(pass) => pass,
            Err(stopped) => {
                failures.push(stopped.error.to_string());
                *stopped.pass
            }
        };
        if let Some(device) = group.id() {
            self.book(light, device);
        }
        if let Err(error) = self.refresh_onions(&mut held, now) {
            failures.push(format!("the home's onions: {error}"));
        }
        Ok(Passed {
            notices: pass.notices(),
            alarms: pass.alarms.clone(),
            seen: pass.seen.clone(),
            stopped: (!failures.is_empty()).then(|| failures.join("; ")),
        })
    }

    /// The device group's `alarms`, raised by a pass, are kept by the app:
    /// the group raises them no more.
    pub fn acknowledge_alarms(&self, alarms: &[Alarm]) -> Result<(), Error> {
        let mut held = self.held();
        let group = held.group.as_mut().ok_or(Error::NoSpace)?;
        group.acknowledge(alarms).map_err(failed)
    }

    /// The source this device's handle in the space `handle` was derived
    /// from at a pairing, while its confirmation there is owed: the device
    /// that paired it enrolled that handle, so this one enrolls with it.
    /// Read while a flow holds the rest.
    pub fn owed_source(&self, handle: &[u8; 32]) -> Result<Option<Vec<u8>>, Error> {
        let store = self
            .owed
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let owed = memberships::confirmations(&store).map_err(store_failed)?;
        if !owed.iter().any(|membership| membership.handle == *handle) {
            return Ok(None);
        }
        let source = self
            .owed
            .1
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        source
            .map(Some)
            .ok_or_else(|| failed("a confirmation is owed with no source kept"))
    }

    /// The home the device's agent is at, as kept: its handle and its
    /// onion set. Read while a flow holds the rest.
    pub fn home(&self) -> Option<Kept> {
        self.home.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// An enrollment made: the credential book records it.
    pub fn enrolled(&self) {
        let held = self.held();
        if let Some(device) = held.group.as_ref().and_then(DeviceGroup::id) {
            self.book(&held.light, device);
        }
    }

    // ----- what every flow shares -----

    /// The device's secret source's key: the one kept, or one made now and
    /// kept at once, so a flow cut short proves with it again.
    fn source(&self, prompts: &dyn Prompts, held: &mut Held) -> Result<Vec<u8>, Error> {
        if let Some(source) = &held.state.source {
            return Ok(source.clone());
        }
        let source = prompts.create_source()?;
        held.state.source = Some(source.clone());
        self.keep(&held.light, &held.state)?;
        Ok(source)
    }

    /// `request` sent `to` a home or a space, under `purpose`.
    fn ask(&self, to: To, purpose: Purpose, request: &[u8]) -> Result<Vec<u8>, Error> {
        self.host
            .request(&to.routes(), purpose, request)
            .map_err(Error::Unreachable)
    }

    /// The node's time at `to`, under `purpose`: a kept-open purpose's
    /// reading counted on while young ([`link::Clocks`]), a one-shot
    /// purpose's read on a connection of its own.
    fn time(&self, to: To, purpose: Purpose) -> Result<u64, Error> {
        if let Some(now) = self.clocks.now(&to.routes(), purpose) {
            return Ok(now);
        }
        let node =
            wire::time_answer(&self.ask(to, purpose, &wire::time_request())?).map_err(failed)?;
        self.clocks
            .read(&to.routes(), purpose, node, std::time::Instant::now());
        Ok(node)
    }

    /// A link to the agent the device's group is at.
    fn with_link<T>(
        &self,
        held: &mut Held,
        purpose: Purpose,
        f: impl FnOnce(&mut AgentLink<'_, H>, &mut Held) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let (Some(kept), Some(agent)) = (held.state.home.clone(), held.state.agent) else {
            return Err(Error::NoSpace);
        };
        let key = held.light.sync_key().clone();
        // Taken out while the link holds it: a nested link starts a session
        // of its own rather than a sequence this one uses.
        let mut sync =
            std::mem::replace(&mut held.sync, Signer::new(key.verifying_key().to_bytes()));
        let mut link = self.link(&kept, purpose, agent, &key, &mut sync);
        let done = f(&mut link, held);
        held.sync = sync;
        done
    }

    /// A link of `purpose` to the agent `agent` at `home`, its sync key's
    /// session `signer`, counting on the node's time the flow's links read
    /// ([`link::Clocks`]).
    fn link<'a>(
        &'a self,
        home: &Kept,
        purpose: Purpose,
        agent: (u32, [u8; 32]),
        sync: &'a SigningKey,
        signer: &'a mut Signer,
    ) -> AgentLink<'a, H> {
        AgentLink::new(
            &self.host,
            To::Home(home.home.handle).routes(),
            purpose,
            Agent {
                agent: agent.0,
                identity: agent.1,
                instance: PERSONAL,
            },
            sync,
            signer,
        )
        .with_clocks(&self.clocks)
    }

    /// One pass of the light node's job in the foreground: the log
    /// followed and every vote, evidence and `alive` posted, the scopes
    /// pushed and read. Whether it left the device with nothing a flow
    /// waits for ([`crate::job::complete`]).
    fn follow(&self, held: &mut Held) -> Result<bool, Error> {
        let now = self.host.now();
        self.with_link(held, Purpose::Personal, |link, held| {
            let Held { light, group, .. } = held;
            let group = group.as_mut().ok_or(Error::NoSpace)?;
            let instances = light.instances().map_err(store_failed)?;
            crate::job::run(light, group, link, &instances, now)
                .map(|pass| crate::job::complete(group, &pass))
                .map_err(|stopped| unreached(stopped.error))
        })
    }

    /// Up to `follows` follows, until one leaves the device complete
    /// ([`crate::job::complete`]): the follows made.
    fn follow_until_complete(&self, held: &mut Held, follows: usize) -> Result<usize, Error> {
        for made in 1..=follows {
            if self.follow(held)? {
                return Ok(made);
            }
        }
        Ok(follows)
    }

    /// `follows` left for after the flow holding `held` returns
    /// ([`Personal::follow_behind`]), and the state it leaves kept for the
    /// status read while they run.
    fn leave_behind(&self, held: &Held, follows: usize) {
        if let Ok(status) = status::read(held) {
            *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(status);
        }
        self.behind.store(follows, Ordering::SeqCst);
    }

    /// Whether a flow returned with follows left for after it.
    pub fn behind(&self) -> bool {
        self.behind.load(Ordering::SeqCst) > 0
    }

    /// The follows a flow left for after it returned, each holding the
    /// space for itself alone, so a flow or a read the user starts
    /// meanwhile waits for one follow at most. One that fails leaves the
    /// rest to the next pass.
    pub fn follow_behind(&self) -> Result<(), Error> {
        while self.behind() {
            let followed = self.follow(&mut self.held());
            match followed {
                Ok(_) => {
                    let _ = self
                        .behind
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                            Some(left.saturating_sub(1))
                        });
                }
                Err(error) => {
                    self.behind.store(0, Ordering::SeqCst);
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// The follows left for after a flow dropped: the next pass makes
    /// them.
    pub fn drop_behind(&self) {
        self.behind.store(0, Ordering::SeqCst);
    }

    /// The device's keys at `home`: its sync key, its admin key (made now
    /// unless kept), its "home" nullifier from `secret`, its label.
    fn device(
        &self,
        held: &mut Held,
        prompts: &dyn Prompts,
        home: &Home,
        secret: &crate::DeviceSecret,
        label: &str,
    ) -> Result<NewDevice, Error> {
        let admin = match held.state.admin {
            Some(admin) => admin,
            None => {
                let made = prompts.create_admin()?;
                held.state.admin = Some(made);
                held.admin = Signer::new(made.key);
                self.keep(&held.light, &held.state)?;
                made
            }
        };
        Ok(NewDevice {
            sync: held.light.sync_key().verifying_key().to_bytes(),
            admin: admin.key,
            class: admin.class(),
            attestation: vos_wire::personal::Attestation {
                hardware: admin.hardware,
                verified_boot: admin.verified_boot,
            },
            nullifier: home.nullifier(secret),
            label: label.as_bytes().to_vec(),
        })
    }
}

/// Where a flow's request goes: the home whose handle it names, or the
/// space an enrollment names; their routes are kept apart.
#[derive(Clone, Copy, Debug)]
pub(super) enum To {
    Home([u8; 32]),
    Space([u8; 32]),
}

impl To {
    /// The key of the routes it takes.
    fn routes(self) -> [u8; 32] {
        match self {
            To::Home(handle) => crate::route::home(&handle),
            To::Space(handle) => crate::route::space(&handle),
        }
    }
}

/// The secret for the space whose handle is `handle`, from `source` at its
/// prompt.
fn secret(
    prompts: &dyn Prompts,
    source: &[u8],
    handle: &[u8; 32],
) -> Result<Box<crate::DeviceSecret>, Error> {
    let output = prompts.evaluate_source(source, &crate::source_input(handle))?;
    Ok(Box::new(crate::derive_secret(&output, handle)))
}

/// A security key's `hmac-secret` through the user's prompt: its
/// credential `id` (empty: the key's discoverable credential).
struct Touched<'a> {
    prompts: &'a dyn Prompts,
    id: Vec<u8>,
}

impl SecurityKey for Touched<'_> {
    type Error = Error;

    fn hmac_secret(&mut self, salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
        self.prompts.kit_secret(&self.id, salt)
    }
}

/// A new kit of `kind` for the home `kept`: a phrase shown once beside
/// its card, or a security key's, its discoverable credential made at its
/// prompt, then its card; `void`, why it replaces one shown before.
fn new_kit(
    prompts: &dyn Prompts,
    kind: KitKind,
    kept: &Kept,
    void: Option<&str>,
) -> Result<KitSecret, Error> {
    match kind {
        KitKind::Phrase => {
            let secret = KitSecret::phrase().ok_or_else(|| failed("no randomness"))?;
            let words = secret.words().ok_or_else(|| failed("a phrase has words"))?;
            if !prompts.show_phrase(&words, &kept.card(), void) {
                return Err(Error::Declined);
            }
            Ok(secret)
        }
        KitKind::SecurityKey => {
            let id = prompts.create_kit_key()?;
            let secret = KitSecret::security_key(&mut Touched { prompts, id })?;
            if !prompts.show_card(&kept.card(), void) {
                return Err(Error::Declined);
            }
            Ok(secret)
        }
    }
}

/// The kit the user has: its words entered, or its security key touched
/// (its discoverable credential).
fn entered_kit(prompts: &dyn Prompts, kind: KitKind) -> Result<KitSecret, Error> {
    match kind {
        KitKind::Phrase => {
            let words = prompts.enter_phrase().ok_or(Error::Declined)?;
            KitSecret::from_words(words.trim()).ok_or(Error::NotAKit)
        }
        KitKind::SecurityKey => KitSecret::security_key(&mut Touched {
            prompts,
            id: Vec::new(),
        }),
    }
}

/// A signer of messages by the admin key `key`, at its prompt.
fn admin_sign<'a>(
    prompts: &'a dyn Prompts,
    key: [u8; 32],
) -> impl Fn(&[u8]) -> Result<[u8; 64], String> + 'a {
    move |message: &[u8]| {
        prompts
            .sign_admin(&key, message)
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests;
