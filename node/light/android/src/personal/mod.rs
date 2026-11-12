// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The device's personal space (VOS's `light-node.md` §3): the light node
//! with its local actors, the device group at the personal agent, and the
//! flows the chrome drives, each the light node's own, over Tor alone.
//!
//! - **What the device keeps** ([`FILE`], and the light node's store under
//!   [`LIGHT`]): the home and the agent it claimed or joined, the secret
//!   source's key it proves there with, its admin key's public half (the
//!   key is the UI's, behind a strong biometric), its label. Every group,
//!   claim, move and pairing row is the light node's, each change one
//!   batch. The file is versioned ([`STATE_VERSION`]): one this build does
//!   not read is refused and kept as it is, the personal space named in
//!   need of repair, sign-in and payments unaffected.
//! - **What a flow keeps before its step at the agent**: each key the
//!   moment it is made, and the home and agent the flow takes the group to
//!   before the call that makes it so; a restart finishes what the store
//!   shows done ([`Space::open`]), a flow called again resumes what it
//!   shows held, and the pass finishes what needs no prompt (a carry, an
//!   acknowledgement, the credential book).
//! - **The flows** ([`Space`]'s methods): the claim at a home-only space
//!   with a phrase or a security-key kit; pairing, as the device that shows
//!   the code ([`Space::pair_offer`], [`Space::pair_await`]) and as the one
//!   that scans it ([`Space::pair_join`], which also re-pairs after a move);
//!   the memberships a pairing leaves; the device set's operations; the
//!   yearly re-proof; a restore from the kit; a move home.
//! - **The prompts are the UI's**: a form, a secret source's output, a
//!   security key's `hmac-secret`, the admin key's signature over bytes
//!   prepared here; none is asked outside a flow the user started.
//! - **The pass** ([`crate::job::Personal`]): the background job's, on the
//!   `Background` isolation group, a flow's on `Personal`; the personal
//!   agent's traffic never shares a circuit with a proof.

pub mod link;
mod ops;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use ed25519_dalek::SigningKey;
use vos_light::group::DeviceGroup;
use vos_light::home::Home as HomeSpace;
use vos_light::kit::KitKey;
use vos_light::memberships;
use vos_light::route::Purpose;
use vos_light::{Config, Light};
use vos_wire::credentials::Onion;
use vos_wire::ids::InstanceId;
use vos_wire::personal::{NewDevice, NewKit};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

use crate::enrollment::{create_private, write_private};
use crate::job::{Passed, Personal};
use crate::net::{Net, Pinned};
use crate::node::Prompts;
use crate::source::Reference;
use crate::{Code, Facility, Refusal, Seen, refused};
use link::{Agent, AgentLink, Signer};

pub use ops::{AdminOffer, Removal};

impl Held {
    /// [`State::arrived`] by the group held.
    fn arrived(&mut self) -> bool {
        let Held { state, group, .. } = self;
        state.arrived(group.as_ref())
    }
}

/// The personal space's file, beside the enrollments: [`MAGIC`], its
/// version (u16, little-endian), then what the device keeps.
pub const FILE: &str = "personal.state";
/// The file's first bytes.
const MAGIC: &[u8; 8] = b"vos/pst\0";
/// The version of what the file keeps, which this build writes. A file of
/// another version, or of none (an earlier build's), is refused and its
/// bytes kept ([`read_state`]); a later version that reads an earlier one
/// converts it there.
pub const STATE_VERSION: u16 = 1;
/// The light node's store, under the facility's directory.
pub const LIGHT: &str = "light";
/// `Personal`'s instance in every personal agent.
pub const PERSONAL: InstanceId = InstanceId(5);
/// The local actors: the credential book and the device book.
pub const CREDENTIAL_BOOK: InstanceId = InstanceId(1);
pub const DEVICE_BOOK: InstanceId = InstanceId(2);

/// The light node's artifacts this crate embeds (`just vos-release`): the
/// default agent's program, and the local actors' packages.
pub struct Artifacts {
    pub agent: Vec<u8>,
    pub books: Vec<(InstanceId, Vec<u8>)>,
}

impl Artifacts {
    pub fn embedded() -> Self {
        Self {
            agent: include_bytes!("../../release/agent.program").to_vec(),
            books: vec![
                (
                    CREDENTIAL_BOOK,
                    include_bytes!("../../release/credential-book.package").to_vec(),
                ),
                (
                    DEVICE_BOOK,
                    include_bytes!("../../release/device-book.package").to_vec(),
                ),
            ],
        }
    }
}

/// A home as kept: where it is, and its onions.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Kept {
    pub home: HomeSpace,
    pub onions: Vec<Onion>,
}

/// What the device keeps of its personal space.
#[derive(Clone, Default, Encode, Decode)]
struct State {
    /// The home its agent is at.
    home: Option<Kept>,
    /// The agent and its identity.
    agent: Option<(u32, [u8; 32])>,
    /// The secret source's key the device proves with at its homes and
    /// derives its handles in offered spaces from (`Reference::to_bytes`).
    source: Option<Vec<u8>>,
    /// The admin key's public half and its attestation, as its key in the
    /// UI's keystore answered them.
    admin: Option<([u8; 32], bool, bool)>,
    label: String,
    /// The home and agent a claim, a pairing or a move takes the group
    /// to, kept before the step that makes it so at the agent, until the
    /// store's group is there.
    bound: Option<Bound>,
    /// The admin keys offered to replace this device's, the newest last,
    /// until the set shows one of them.
    next_admin: Vec<([u8; 32], bool, bool)>,
    /// A restore opened, from before its call until it matures.
    restoring: Option<Restoring>,
    /// A joiner's open claim at its home, which the background job makes
    /// once its drawn time comes.
    claim_due: Option<ClaimDue>,
    /// This device's handover to another device's matured regroup, until
    /// its new group is confirmed.
    handover: Option<ops::regroup::Handed>,
    /// A joiner's acknowledgement of its pairing's handover, kept before
    /// it is put in the slot, until it is.
    acked: Option<Acked>,
    /// Each local actor's instance and the release installed there.
    books: Vec<(u32, u32)>,
}

/// Where a flow takes the device's group: the home, and the agent there.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct Bound {
    home: Kept,
    agent: (u32, [u8; 32]),
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

/// What `bytes`, `personal.state`'s, keep, or why this build does not read
/// them.
fn read_state(bytes: &[u8]) -> Result<State, String> {
    let body = bytes
        .strip_prefix(MAGIC.as_slice())
        .ok_or("names no version")?;
    let (version, body) = body.split_first_chunk::<2>().ok_or("is cut short")?;
    match u16::from_le_bytes(*version) {
        STATE_VERSION => State::decode_exact(body).ok_or_else(|| "does not decode".into()),
        other => Err(format!(
            "is of version {other}, and this build reads {STATE_VERSION}"
        )),
    }
}

/// `state` as `personal.state` keeps it.
fn state_bytes(state: &State) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&STATE_VERSION.to_le_bytes());
    state.encode_to(&mut bytes);
    bytes
}

impl State {
    /// A pairing's what the store shows it never joined dropped: the
    /// home and agent it was to take the group to, the open claim owed
    /// there, its acknowledgement. Whether it changed.
    fn unjoined(
        &mut self,
        store: &vos_light::Store,
        group: Option<&DeviceGroup>,
    ) -> Result<bool, Refusal> {
        let Some(bound) = &self.bound else {
            return Ok(false);
        };
        let there = group.is_some_and(|group| group.agent().identity == bound.agent.1);
        let held = vos_light::home::Claim::pending(store)
            .map_err(store_failed)?
            .is_some()
            || vos_light::moving::moving(store).map_err(store_failed)?;
        if there || held {
            return Ok(false);
        }
        let handle = bound.home.home.handle;
        if self
            .claim_due
            .as_ref()
            .is_some_and(|due| due.home.handle == handle)
        {
            self.claim_due = None;
        }
        self.bound = None;
        self.acked = None;
        Ok(true)
    }

    /// The home and agent a flow took the group to are the device's once
    /// the store's group is at that agent: a claim, a pairing or a move
    /// whose last step the process did not live to see. Whether it
    /// changed.
    fn arrived(&mut self, group: Option<&DeviceGroup>) -> bool {
        let at = |bound: &Bound| group.is_some_and(|group| group.agent().identity == bound.agent.1);
        match self.bound.take() {
            Some(bound) if at(&bound) => {
                self.home = Some(bound.home);
                self.agent = Some(bound.agent);
                true
            }
            other => {
                self.bound = other;
                false
            }
        }
    }
}

/// The personal space in need of repair: what does not read, kept as it
/// is.
fn needs_repair(why: impl std::fmt::Display) -> Refusal {
    refused(
        Code::Store,
        format!(
            "the personal space needs repair: {why}. Nothing was changed; sign-in and payments \
             are not affected"
        ),
    )
}

/// Each local actor in `books` installed, or upgraded in place: one not
/// installed, or installed at a release before the package's. `kept`
/// holds each instance's release installed; whether it changed.
fn install(
    light: &Light,
    books: &[(InstanceId, Vec<u8>)],
    kept: &mut Vec<(u32, u32)>,
) -> Result<bool, Refusal> {
    let installed = light.instances().map_err(store_failed)?;
    let mut changed = false;
    for (instance, package) in books {
        let package = vos_light::release::Package::decode_exact(package)
            .ok_or_else(|| store_failed("a local actor's package does not decode"))?;
        let at = kept
            .iter()
            .find(|(id, _)| *id == instance.0)
            .map(|(_, release)| *release);
        if installed.contains(instance) && at.is_some_and(|at| at >= package.release) {
            continue;
        }
        let release = match light.install(*instance, &package, Vec::new()) {
            Ok(Outcome::Done(_)) => package.release,
            Ok(other) => {
                return Err(store_failed(format!(
                    "a local actor's install answered {other:?}"
                )));
            }
            // Installed already at a later release than this build's.
            Err(vos_light::Error::Release { installed }) if installed > package.release => {
                installed
            }
            Err(error) => return Err(store_failed(error)),
        };
        kept.retain(|(id, _)| *id != instance.0);
        kept.push((instance.0, release));
        changed = true;
    }
    Ok(changed)
}

/// A joiner's open claim, owed at `home` for `member` from `due` (ms),
/// and the attempts the home refused so far (one not reached is not
/// counted).
#[derive(Clone, Debug, Encode, Decode)]
struct ClaimDue {
    home: HomeSpace,
    member: [u8; 32],
    due: u64,
    refused: u32,
}

/// The joiner's open claim's delay after its pairing, drawn uniformly
/// over this range (ms): the home's operators do not link the new member
/// to the agent by its time (`light-node.md` L5).
pub const CLAIM_DELAY: std::ops::Range<u64> = 3_600_000..6 * 3_600_000;

/// The joiner's open claim, refused, is tried again after this (ms),
/// doubled at each of the home's refusals up to [`CLAIM_RETRY_MAX`]; each
/// wait drawn uniformly from its upper half, so the attempts do not form a
/// sequence the home's operators could link.
pub const CLAIM_RETRY: u64 = 60_000;
/// The longest wait between two attempts at an open claim (ms).
pub const CLAIM_RETRY_MAX: u64 = 6 * 3_600_000;

/// The longest wait before the next attempt at an open claim the home
/// refused `refused` times, from a first wait of `base`.
fn retry_after(base: u64, refused: u32) -> u64 {
    base.saturating_mul(1 << refused.saturating_sub(1).min(32))
        .min(CLAIM_RETRY_MAX.max(base))
}

/// What a flow holds while it runs: the light node, its device group, the
/// keys' sessions, and a pairing under way.
struct Held {
    light: Light,
    group: Option<DeviceGroup>,
    state: State,
    sync: Signer,
    admin: Signer,
    pairing: Option<ops::Pairing>,
}

/// The device's personal space.
pub struct Space {
    facility: Facility,
    runtime: tokio::runtime::Handle,
    file: PathBuf,
    held: Mutex<Held>,
    waiting: Waiting,
    claim_delay: Mutex<std::ops::Range<u64>>,
    claim_retry: AtomicU64,
    /// How long a flow waits for the agent (ms): [`ops::WAIT`] unless set.
    wait: AtomicU64,
    /// The light node's store and the source kept, as an enrollment asks
    /// them while a flow holds the rest.
    owed: (vos_light::Store, Mutex<Option<Vec<u8>>>),
}

/// Whether a pairing waits on its slot, and whether the chrome cancelled
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

fn store_failed(error: impl std::fmt::Display) -> Refusal {
    refused(Code::Store, format!("the personal space's store: {error}"))
}

pub(crate) fn failed(error: impl std::fmt::Display) -> Refusal {
    refused(Code::Failed, error.to_string())
}

pub(crate) fn unreached(error: impl std::fmt::Display) -> Refusal {
    refused(Code::Api, error.to_string())
}

impl Space {
    /// The personal space under `directory` (the facility's), its light
    /// node opened from `artifacts`, its local actors installed or
    /// upgraded, what a flow left done in the store made the device's, its
    /// homes' routes told to the facility's client. A state file or a
    /// store this build does not read is refused as in need of repair, and
    /// left as it is.
    pub fn open(
        directory: &Path,
        artifacts: &Artifacts,
        facility: Facility,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self, Refusal> {
        let file = directory.join(FILE);
        let mut state = match std::fs::read(&file) {
            Ok(bytes) => {
                read_state(&bytes).map_err(|why| needs_repair(format!("its file {why}")))?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(error) => return Err(needs_repair(format!("its file does not read: {error}"))),
        };
        let dir = directory.join(LIGHT);
        create_private(&dir).map_err(store_failed)?;
        let light = Light::open(&dir, &artifacts.agent, Config::default())
            .map_err(|error| needs_repair(format!("its store: {error}")))?;
        let mut changed = install(&light, &artifacts.books, &mut state.books)?;
        let group = DeviceGroup::open(light.store())
            .map_err(|error| needs_repair(format!("its device group: {error}")))?;
        changed |= state.arrived(group.as_ref());
        changed |= state.unjoined(light.store(), group.as_ref())?;
        if state
            .acked
            .as_ref()
            .is_some_and(|acked| acked.expires < crate::job::now_ms())
        {
            state.acked = None;
            changed = true;
        }
        let sync = Signer::new(light.sync_key().verifying_key().to_bytes());
        let admin = Signer::new(state.admin.map(|(key, ..)| key).unwrap_or_default());
        let owed = (light.store().clone(), Mutex::new(state.source.clone()));
        let space = Self {
            facility,
            runtime,
            file,
            held: Mutex::new(Held {
                light,
                group,
                state,
                sync,
                admin,
                pairing: None,
            }),
            waiting: Waiting::default(),
            claim_delay: Mutex::new(CLAIM_DELAY),
            claim_retry: AtomicU64::new(CLAIM_RETRY),
            wait: AtomicU64::new(ops::WAIT_MS),
            owed,
        };
        let held = space.held();
        if changed {
            space.keep(&held.state)?;
        }
        let bound = held.state.bound.as_ref().map(|bound| &bound.home);
        for kept in [held.state.home.as_ref(), bound].into_iter().flatten() {
            space.pin(kept);
        }
        drop(held);
        Ok(space)
    }

    fn held(&self) -> MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn net(&self) -> &Net {
        self.facility.net()
    }

    /// A home's routes: its onions, onion-only (E17).
    fn pin(&self, kept: &Kept) {
        self.net().pin(
            kept.home.handle,
            Pinned {
                onions: kept.onions.clone(),
                clearnet: None,
                onion_only: true,
            },
        );
    }

    fn keep(&self, state: &State) -> Result<(), Refusal> {
        write_private(&self.file, &state_bytes(state)).map_err(store_failed)?;
        *self.owed.1.lock().unwrap_or_else(|e| e.into_inner()) = state.source.clone();
        Ok(())
    }

    /// Whether the device holds a personal space's group.
    pub fn grouped(&self) -> bool {
        self.held().group.is_some()
    }

    /// The joiner's open claim's delay range (ms), [`CLAIM_DELAY`] unless
    /// set: tests shorten it, which no product caller does (L5).
    #[doc(hidden)]
    pub fn set_claim_delay(&self, delay: std::ops::Range<u64>) {
        *self.claim_delay.lock().unwrap_or_else(|e| e.into_inner()) = delay;
    }

    /// How long a flow waits for the agent (ms), [`ops::WAIT`] unless
    /// set: tests shorten it.
    #[doc(hidden)]
    pub fn set_wait(&self, ms: u64) {
        self.wait.store(ms, Ordering::Relaxed);
    }

    fn wait(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.wait.load(Ordering::Relaxed))
    }

    /// The first wait after a refused open claim (ms), [`CLAIM_RETRY`]
    /// unless set: tests shorten it.
    #[doc(hidden)]
    pub fn set_claim_retry(&self, base: u64) {
        self.claim_retry.store(base, Ordering::Relaxed);
    }

    /// The wait before the next attempt at an open claim refused
    /// `refused` times: drawn uniformly from the upper half of its bound.
    fn claim_retry(&self, refused: u32) -> Result<u64, Refusal> {
        let bound = retry_after(self.claim_retry.load(Ordering::Relaxed), refused);
        let half = bound / 2;
        let mut bytes = [0; 8];
        getrandom::getrandom(&mut bytes).map_err(failed)?;
        Ok(half + u64::from_le_bytes(bytes) % (bound - half + 1))
    }

    /// A delay drawn uniformly over the claim delay's range.
    fn draw_claim_delay(&self) -> Result<u64, Refusal> {
        let range = self
            .claim_delay
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let span = range.end.saturating_sub(range.start);
        if span == 0 {
            return Ok(range.start);
        }
        let mut bytes = [0; 8];
        getrandom::getrandom(&mut bytes).map_err(failed)?;
        Ok(range.start + u64::from_le_bytes(bytes) % span)
    }

    /// When the joiner's open claim is due (ms), while it is owed.
    pub fn claim_due(&self) -> Option<u64> {
        self.held().state.claim_due.as_ref().map(|due| due.due)
    }

    /// The data key of the scope `name` names at the confirmed epoch.
    pub fn scope_key(&self, name: &[u8]) -> Result<[u8; 32], Refusal> {
        let mut held = self.held();
        let group = held
            .group
            .as_mut()
            .ok_or_else(|| refused(Code::NotEnrolled, "this device holds no personal space"))?;
        let scope = group.archive().scope(name);
        group.key(scope).map_err(failed)
    }

    /// The light node's sync key's public half: the device's author.
    pub fn sync_key(&self) -> [u8; 32] {
        self.held().light.sync_key().verifying_key().to_bytes()
    }
}

/// A link of `purpose` to the agent `agent` at `home`, its sync key's
/// session `signer`.
fn link<'a>(
    net: &'a Net,
    runtime: &'a tokio::runtime::Handle,
    home: &Kept,
    purpose: Purpose,
    agent: (u32, [u8; 32]),
    sync: &'a SigningKey,
    signer: &'a mut Signer,
) -> AgentLink<'a> {
    AgentLink::new(
        net,
        runtime,
        home.home.handle,
        purpose,
        Agent {
            agent: agent.0,
            identity: agent.1,
            instance: PERSONAL,
        },
        sync,
        signer,
    )
}

impl Personal for Space {
    /// The background job's pass, on its own isolation group: a joiner's
    /// acknowledgement left by a process that died first put in its slot,
    /// the light node's job, a kept device's handover, a carry an
    /// interrupted move left, the credential book's records of this
    /// device's enrollments, and the joiner's open claim once due.
    fn pass(&self, now: u64, runtime: &tokio::runtime::Handle) -> Result<Passed, String> {
        let mut held = self.held();
        let mut failures = Vec::new();
        if let Err(refusal) = self.acknowledge(&mut held) {
            failures.push(format!(
                "the pairing's acknowledgement: {}",
                refusal.message
            ));
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
            return Err("no personal space".into());
        };
        let key = light.sync_key().clone();
        let mut link = link(
            self.net(),
            runtime,
            home,
            Purpose::Background,
            agent,
            &key,
            sync,
        );
        let instances = light.instances().map_err(|error| error.to_string())?;
        let pass = match vos_light::job::run(light, group, &mut link, &instances, now) {
            Ok(pass) => pass,
            Err(stopped) => {
                failures.push(stopped.error.to_string());
                *stopped.pass
            }
        };
        // A kept device's handover to another device's matured regroup.
        let before = state.handover.clone();
        let mut handed = ops::regroup::hand_over(&mut link, group, state, &key).map(drop);
        if state.handover != before
            && let Err(refusal) = self.keep(state)
        {
            // Not kept: the next pass draws its package again.
            state.handover = before;
            handed = Err(refusal.message);
        }
        if let Err(error) = handed {
            failures.push(format!("the regroup's handover: {error}"));
        }
        match ops::carry(light, group, &mut link) {
            Ok(Some(_)) => {}
            Ok(None) => failures.push("the move's carry is not whole yet".into()),
            Err(refusal) => failures.push(format!("the move's carry: {}", refusal.message)),
        }
        if let Some(device) = group.id() {
            self.book(light, device);
        }
        if let Err(refusal) = self.claim_if_due(state, now) {
            failures.push(format!("the open claim at the home: {}", refusal.message));
        }
        Ok(Passed {
            notices: pass.notices().into_iter().map(crate::job::notice).collect(),
            seen: pass
                .seen
                .iter()
                .map(|(device, at)| Seen {
                    device: *device,
                    at: *at,
                })
                .collect(),
            stopped: (!failures.is_empty()).then(|| failures.join("; ")),
        })
    }
}

impl crate::session::Paired for Space {
    fn owed_source(&self, handle: &[u8; 32]) -> Result<Option<Reference>, String> {
        let owed = memberships::confirmations(&self.owed.0).map_err(|error| error.to_string())?;
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
            .as_deref()
            .and_then(Reference::from_bytes)
            .map(Some)
            .ok_or_else(|| "a confirmation is owed with no source kept".into())
    }

    fn enrolled(&self) {
        let held = self.held();
        if let Some(device) = held.group.as_ref().and_then(DeviceGroup::id) {
            self.book(&held.light, device);
        }
    }
}

/// The source reference kept, or none.
fn reference(state: &State) -> Option<Reference> {
    Reference::from_bytes(state.source.as_deref()?)
}

/// The prompts a flow is lent.
pub type Lent<'a> = &'a dyn Prompts;

/// A shared space, as the node holds it.
pub type Shared = Arc<Space>;

#[cfg(test)]
mod tests {
    use super::*;
    use vos_wire::personal::{AdminClass, Attestation, KitKind};

    /// A state with each field set, its values fixed.
    fn every_field() -> State {
        let home = Kept {
            home: HomeSpace {
                space: [1; 32],
                handle: [2; 32],
                agent: 3,
                identity: [4; 32],
                homes: InstanceId(5),
                credentials: InstanceId(6),
            },
            onions: vec![Onion {
                key: [7; 32],
                ssh_host_key: [8; 32],
            }],
        };
        let device = NewDevice {
            sync: [9; 32],
            admin: [10; 32],
            class: AdminClass::Strong,
            attestation: Attestation {
                hardware: true,
                verified_boot: false,
            },
            nullifier: [11; 32],
            label: b"phone".to_vec(),
        };
        let kit = NewKit {
            entries: vec![vos_wire::personal::KitEntry {
                kind: KitKind::SecurityKey,
                signing: [30; 32],
                sealing: [31; 32],
                sealed_r1: vec![32; 2],
            }],
            r2_hash: [12; 32],
            r_hash: [13; 32],
        };
        let next = KitKey {
            kind: KitKind::Phrase,
            signing: [14; 32],
            sealing: [15; 32],
        };
        let mut restoring = Restoring::new(&device, &kit, next, [16; 32]);
        restoring.signed = Some((vec![17; 3], [18; 64]));
        State {
            home: Some(home.clone()),
            agent: Some((19, [20; 32])),
            source: Some(b"\x01vos.device.1".to_vec()),
            admin: Some(([21; 32], true, true)),
            label: "phone".into(),
            bound: Some(Bound {
                home: home.clone(),
                agent: (22, [23; 32]),
            }),
            next_admin: vec![([24; 32], false, true)],
            restoring: Some(restoring),
            claim_due: Some(ClaimDue {
                home: home.home,
                member: [25; 32],
                due: 26,
                refused: 27,
            }),
            handover: None,
            acked: Some(Acked {
                handle: [28; 32],
                onions: Vec::new(),
                agent: (33, [34; 32]),
                slot: [35; 32],
                expires: 36,
                ack: vec![29; 4],
            }),
            books: vec![(1, 2), (2, 3)],
        }
    }

    /// The bytes of [`every_field`] in [`STATE_VERSION`]: a change to what
    /// the file keeps, or to how a type it holds encodes, fails here, and
    /// is a new version with its conversion in [`read_state`].
    const PINNED: &str = concat!(
        "766f732f70737400010001010101010101010101010101010101010101010101010101010101010101010102",
        "0202020202020202020202020202020202020202020202020202020202020203000000040404040404040404",
        "0404040404040404040404040404040404040404040404050000000600000001000000070707070707070707",
        "0707070707070707070707070707070707070707070707080808080808080808080808080808080808080808",
        "0808080808080808080808011300000014141414141414141414141414141414141414141414141414141414",
        "14141414010d00000001766f732e6465766963652e3101151515151515151515151515151515151515151515",
        "151515151515151515151501010500000070686f6e6501010101010101010101010101010101010101010101",
        "0101010101010101010101020202020202020202020202020202020202020202020202020202020202020203",
        "0000000404040404040404040404040404040404040404040404040404040404040404050000000600000001",
        "0000000707070707070707070707070707070707070707070707070707070707070707080808080808080808",
        "0808080808080808080808080808080808080808080808160000001717171717171717171717171717171717",
        "1717171717171717171717171717170100000018181818181818181818181818181818181818181818181818",
        "18181818181818000101000e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0f",
        "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0d0d0d0d0d0d0d0d0d0d0d0d0d",
        "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0df7000000090909090909090909090909090909090909090909",
        "09090909090909090909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00",
        "01000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0500000070686f6e6501",
        "000000011e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1f1f1f1f1f1f1f1f",
        "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f0200000020200c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d",
        "0d0d0d0d0d0d0110101010101010101010101010101010101010101010101010101010101010100103000000",
        "1111111212121212121212121212121212121212121212121212121212121212121212121212121212121212",
        "1212121212121212121212121212121212121212121212010101010101010101010101010101010101010101",
        "0101010101010101010101010202020202020202020202020202020202020202020202020202020202020202",
        "0300000004040404040404040404040404040404040404040404040404040404040404040500000006000000",
        "19191919191919191919191919191919191919191919191919191919191919191a000000000000001b000000",
        "00011c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c00000000210000002222",
        "2222222222222222222222222222222222222222222222222222222222222323232323232323232323232323",
        "2323232323232323232323232323232323232400000000000000040000001d1d1d1d02000000010000000200",
        "00000200000003000000",
    );

    #[test]
    fn the_state_files_layout_is_pinned_to_its_version() {
        let bytes = state_bytes(&every_field());
        assert_eq!(hex::encode(&bytes), PINNED);
        let read = read_state(&bytes).unwrap();
        assert_eq!(state_bytes(&read), bytes);
    }

    #[test]
    fn a_state_file_of_another_version_or_none_is_refused() {
        let bytes = state_bytes(&every_field());
        let mut later = bytes.clone();
        later[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&(STATE_VERSION + 1).to_le_bytes());
        assert!(read_state(&later).err().unwrap().contains("version 2"));
        let unversioned = every_field().encode();
        assert!(
            read_state(&unversioned)
                .err()
                .unwrap()
                .contains("no version")
        );
        assert!(read_state(&bytes[..bytes.len() - 1]).is_err());
        assert!(read_state(&bytes[..MAGIC.len() + 1]).is_err());
        assert!(read_state(&[bytes.as_slice(), &[0]].concat()).is_err());
    }

    /// A local actor upgraded in place to a later release the app carries,
    /// never downgraded to an earlier one.
    #[test]
    fn a_local_actor_is_upgraded_in_place() {
        let directory = tempfile::tempdir().unwrap();
        let artifacts = Artifacts::embedded();
        let light = Light::open(directory.path(), &artifacts.agent, Config::default()).unwrap();
        let mut kept = Vec::new();
        assert!(install(&light, &artifacts.books, &mut kept).unwrap());
        assert!(!install(&light, &artifacts.books, &mut kept).unwrap());
        let (instance, package) = &artifacts.books[0];
        let first = vos_light::release::Package::decode_exact(package).unwrap();
        let next = vos_light::release::Package {
            release: first.release + 1,
            ..first.clone()
        };
        let books = vec![(*instance, next.encode())];
        assert!(install(&light, &books, &mut kept).unwrap());
        assert!(kept.contains(&(instance.0, first.release + 1)));
        // The upgrade stands: the earlier release is refused under it.
        assert!(matches!(
            light.install(*instance, &first, Vec::new()),
            Err(vos_light::Error::Release { installed }) if installed == first.release + 1
        ));
        assert!(!install(&light, &artifacts.books, &mut kept).unwrap());
        // A record lost: the installed release is learnt from the refusal.
        let mut lost = Vec::new();
        assert!(install(&light, &artifacts.books, &mut lost).unwrap());
        assert!(lost.contains(&(instance.0, first.release + 1)));
    }

    #[test]
    fn a_refused_claims_wait_doubles_to_its_bound() {
        assert_eq!(retry_after(CLAIM_RETRY, 0), CLAIM_RETRY);
        assert_eq!(retry_after(CLAIM_RETRY, 1), CLAIM_RETRY);
        assert_eq!(retry_after(CLAIM_RETRY, 2), 2 * CLAIM_RETRY);
        assert_eq!(retry_after(CLAIM_RETRY, 9), 256 * CLAIM_RETRY);
        assert_eq!(retry_after(CLAIM_RETRY, 10), CLAIM_RETRY_MAX);
        assert_eq!(retry_after(CLAIM_RETRY, u32::MAX), CLAIM_RETRY_MAX);
        assert_eq!(retry_after(u64::MAX, 40), u64::MAX);
    }
}
