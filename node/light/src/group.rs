//! The device group (`light-node.md` §3.4–§3.5): the user's devices as one
//! MLS group over `vos-mls`, its commits ordered by the personal agent.
//!
//! - **Commits are admin calls** ([`DeviceGroup::commit`]): a device's commit
//!   names its effect (the device it adds, every matured removal) and is
//!   held before the call that posts it; its signed message is posted as
//!   the call's evidence, with the Welcome, until the log holds it.
//! - **The log decides, each device checks:** [`DeviceGroup::follow`] reads
//!   the control log in order, its chain checked. A candidate is acted on
//!   only once its evidence verifies against the committer's admin key, its
//!   removals each a matured operation whose evidence verifies; it is
//!   processed on a copy at the log's batch time under its logged effect,
//!   and the device votes: `confirm(h)` signed by its sync key, or `nack`.
//!   Each vote of the logged confirming set is verified, against the
//!   candidate's place in this device's log; one `h` from every voice of
//!   the set confirms the epoch and the copy is swapped in, a nack, a
//!   second `h` or the window's end voids it.
//! - **Sleepers are deferred:** a device outside the set processes the
//!   confirmed candidate when it reads it; one it cannot process, or whose
//!   `h` is not the confirmed one, raises [`Alarm::CannotFollow`] naming the
//!   committer, and stops: it re-pairs, or regroups with no device to pair
//!   from.
//! - **Keys:** data keys are exported at the confirmed epoch alone
//!   ([`DeviceGroup::key`]), scope ids derive from the archive's naming
//!   secret, and the archive ([`archive`]) records every scope key of every
//!   confirmed epoch.
//!
//! Sans I/O: the caller makes the calls (the admin key signs commits behind
//! the owner's prompt, the sync key votes and evidence), reads the log and
//! hands its entries over.

pub mod archive;
mod follow;

use std::collections::BTreeMap;

use vos_mls::{Mls, Namespace};
use vos_wire::ids::{InstanceId, MethodId};
use vos_wire::personal::{DeviceId, Effect, NewDevice, Policy, Scope, Vote, welcome_hash};
use vos_wire::{Decode, Encode};

use crate::store::{Store, StoreError};

pub use archive::Archive;

/// The confirmation hash's domain.
pub const CONFIRM: &[u8] = b"vos/personal/confirm";

/// How long a device's leaf lasts before its yearly update is due: the
/// home's re-proof prompts for both.
pub const RENEW_AFTER_MS: u64 = 335 * vos_wire::personal::DAY_MS;

/// The group's rows in the store's group keyspace, beside `vos-mls`'s
/// namespace.
const STATE: &[u8] = b"g/state";

/// The calls a device remembers within the window.
const CALLS: usize = 32;
const MLS: &[u8] = b"mls/";

/// The personal agent a device group's commits go through: its identity,
/// which calls are signed for, `Personal`'s instance, and the methods an
/// admin call's evidence names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Agent {
    pub identity: [u8; 32],
    pub instance: InstanceId,
    pub commit: MethodId,
    pub remove: MethodId,
}

/// Why the device group cannot do something.
#[derive(Debug)]
pub enum GroupError {
    Mls(vos_mls::Error),
    Store(StoreError),
    /// A group row that does not read.
    Corrupt,
    /// The store has a device group already, or none.
    Grouped,
    NoGroup,
    /// The store's naming secret names scopes already: a device joins only
    /// from a fresh store.
    Scoped,
    /// A candidate is pending, or this device's own commit: commit after it
    /// is decided.
    Pending,
    /// The device cannot follow the confirmed epoch: it re-pairs or
    /// regroups.
    Stuck,
    /// The device has no voice: its removal matured, or a confirmed commit
    /// removed it.
    Out,
    /// No own commit is waiting for its call.
    NoCommit,
    /// The device a commit would add is in the group already.
    Known,
}

impl From<vos_mls::Error> for GroupError {
    fn from(error: vos_mls::Error) -> Self {
        GroupError::Mls(error)
    }
}

impl From<StoreError> for GroupError {
    fn from(error: StoreError) -> Self {
        GroupError::Store(error)
    }
}

impl From<fjall::Error> for GroupError {
    fn from(error: fjall::Error) -> Self {
        GroupError::Store(StoreError::Fjall(error))
    }
}

impl std::fmt::Display for GroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GroupError::Mls(error) => error.fmt(f),
            GroupError::Store(error) => error.fmt(f),
            GroupError::Corrupt => f.write_str("a device group row does not read"),
            GroupError::Grouped => f.write_str("the store has a device group already"),
            GroupError::NoGroup => f.write_str("the store has no device group"),
            GroupError::Scoped => f.write_str("the store's scopes are named already"),
            GroupError::Pending => f.write_str("a candidate is pending"),
            GroupError::Stuck => f.write_str("the device cannot follow the confirmed epoch"),
            GroupError::Out => f.write_str("the device is out of the group"),
            GroupError::NoCommit => f.write_str("no commit is waiting for its call"),
            GroupError::Known => f.write_str("the device is in the group already"),
        }
    }
}

impl std::error::Error for GroupError {}

/// What a device must do, or what it saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Vote on `epoch`'s candidate: sign `message` with the sync key and
    /// post `confirm(epoch, h, signature)` or `nack(epoch, signature)`.
    /// Given again until the log holds the vote.
    Vote {
        epoch: u64,
        vote: Vote,
        message: Vec<u8>,
    },
    /// Post the evidence of this device's admin call at `index`, under its
    /// sync key. Given again until the log holds it.
    Evidence {
        index: u64,
        message: Vec<u8>,
        signature: [u8; 64],
        welcome: Option<Vec<u8>>,
    },
    /// `epoch` confirmed: its keys are the data keys from now.
    Confirmed {
        epoch: u64,
    },
    /// `epoch`'s candidate void: its committer flagged.
    Voided {
        epoch: u64,
        committer: DeviceId,
        why: Why,
    },
    /// This device is out of the group: its removal matured, or a
    /// confirmed commit removed it.
    Removed,
    Alarm(Alarm),
}

/// Why a candidate was void, as this device counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A device of the set nacked it: the chrome names it.
    Nack(DeviceId),
    /// The set confirmed two different `h`.
    Split,
    /// The window passed without the set complete.
    Timeout,
    /// The agent voided it before this device's count decided it.
    Agent,
}

/// What a device raises to its user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alarm {
    /// The log does not chain from what this device saw at `index`: a
    /// rollback or a fork. The device reads no further.
    Log { index: u64 },
    /// A vote by `device`, of `epoch`'s logged set, does not verify against
    /// the candidate as this device's log holds it: the devices were shown
    /// two logs (a different confirming set), or the vote is forged.
    SplitLog { epoch: u64, device: DeviceId },
    /// The log names this device absent from `epoch`'s confirming set
    /// though it made a call within the window.
    NamedAbsent { epoch: u64, last_call: u64 },
    /// This device refused `epoch`'s candidate by `committer`: its evidence
    /// does not verify, its effect is not the matured operations', or its
    /// handshake does not process. It nacked, if it votes.
    Refused { epoch: u64, committer: DeviceId },
    /// `epoch` was confirmed and this device cannot follow it: it could not
    /// process `committer`'s commit, or its `h` is not the confirmed one.
    CannotFollow {
        epoch: u64,
        committer: DeviceId,
        remedy: Remedy,
    },
    /// The agent's verdict on `epoch` is not this device's count.
    Verdict { epoch: u64 },
    /// The log's entry at `index` asserts what no verified operation
    /// supports (a maturity with no signed removal): it is ignored.
    Unsigned { index: u64 },
    /// The device's clock and the agent's batch time disagree by `skew_ms`,
    /// more than an hour: the device acts as the log says.
    Clock { skew_ms: u64 },
}

/// What a device that cannot follow does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remedy {
    /// Pair again from another live device.
    RePair,
    /// No other live device to pair from: a regroup (§3.5).
    Regroup,
}

/// The clock alarm: the device's clock `local` against the agent's batch
/// time `agent`, both in milliseconds.
pub fn clock(local: u64, agent: u64) -> Option<Alarm> {
    let skew_ms = local.abs_diff(agent);
    (skew_ms > vos_wire::personal::HOUR_MS).then_some(Alarm::Clock { skew_ms })
}

/// A commit this device made, held: what its admin call carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    pub epoch: u64,
    pub effect: Effect,
    pub handshake: Vec<u8>,
    /// The Welcome for the device it adds, posted with the evidence.
    pub welcome: Option<Vec<u8>>,
}

impl Prepared {
    /// The commit call's arguments, as `Personal::commit` takes them.
    pub fn arguments(&self) -> Vec<u8> {
        let hash = self.welcome.as_deref().map(welcome_hash);
        (
            (self.epoch, self.effect.clone()),
            (self.handshake.clone(), hash),
        )
            .encode()
    }
}

/// A device the group knows: its keys, and whether it has a voice.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct Known {
    pub(crate) keys: NewDevice,
    /// When its probation ends, by the log's time: it signs no operation
    /// or commit before.
    pub(crate) active_from: u64,
    /// Its removal matured: it has no voice.
    pub(crate) matured: bool,
    /// A confirmed commit removed it from the group.
    pub(crate) out: bool,
}

/// What a check of an admin call's evidence found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub(crate) enum Check {
    #[codec(index = 0)]
    Missing = 0,
    #[codec(index = 1)]
    Valid = 1,
    #[codec(index = 2)]
    Invalid = 2,
}

/// A removal operation the log holds.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct Removal {
    pub(crate) index: u64,
    pub(crate) by: DeviceId,
    pub(crate) target: DeviceId,
    pub(crate) matures: u64,
    pub(crate) arguments: Vec<u8>,
    pub(crate) origin: [u8; 32],
    pub(crate) evidence: Check,
}

/// The pending candidate, as this device's log holds it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct Pending {
    pub(crate) index: u64,
    pub(crate) at: u64,
    pub(crate) epoch: u64,
    pub(crate) by: DeviceId,
    pub(crate) set: Vec<DeviceId>,
    /// The log's chain through the candidate's entry, which votes bind.
    pub(crate) chain: [u8; 32],
    pub(crate) added: Option<DeviceId>,
    pub(crate) effect: Effect,
    pub(crate) handshake: Vec<u8>,
    pub(crate) welcome_hash: Option<[u8; 32]>,
    pub(crate) origin: [u8; 32],
    pub(crate) arguments: Vec<u8>,
    pub(crate) evidence: Check,
    pub(crate) welcome: Option<Vec<u8>>,
    /// The votes logged and verified, each device's first.
    pub(crate) votes: Vec<(DeviceId, Vote)>,
    /// This device's vote, and whether the log holds it.
    pub(crate) mine: Option<Vote>,
    pub(crate) logged: bool,
}

/// This device's own commit, from its preparation until it is decided.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct Own {
    pub(crate) epoch: u64,
    pub(crate) welcome: Option<Vec<u8>>,
    /// Its call's arguments, by which the log's candidate is known as it.
    pub(crate) arguments: Vec<u8>,
    /// Its call's signed message and signature, written before the call
    /// is made.
    pub(crate) signed: Option<(Vec<u8>, [u8; 64])>,
    /// Its call's log index, once the agent took it.
    pub(crate) index: Option<u64>,
    /// The log holds its evidence.
    pub(crate) evidenced: bool,
}

/// Where the device is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Course {
    #[codec(index = 0)]
    Following,
    /// It cannot follow `epoch`, committed by `committer`.
    #[codec(index = 1)]
    Stuck { epoch: u64, committer: DeviceId },
    /// It is out of the group.
    #[codec(index = 2)]
    Out,
}

/// What the device keeps of the log: the agent, itself, its place in the
/// log, the devices and removals it verified, the pending candidate and
/// its own commit.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct State {
    pub(crate) agent: Agent,
    pub(crate) me: NewDevice,
    /// Its number in the device set, once its add is confirmed.
    pub(crate) id: Option<DeviceId>,
    /// The next log index to read, and the chain through the one before.
    pub(crate) next: u64,
    pub(crate) chain: [u8; 32],
    /// The latest batch time the log showed.
    pub(crate) time: u64,
    /// The batch times of this device's calls within the confirming
    /// window, the latest last.
    pub(crate) calls: Vec<u64>,
    pub(crate) confirmed: u64,
    /// When this device's leaf was last renewed: its add, or its last
    /// confirmed commit.
    pub(crate) renewed: u64,
    pub(crate) policy: Policy,
    pub(crate) devices: Vec<(DeviceId, Known)>,
    pub(crate) removals: Vec<Removal>,
    pub(crate) pending: Option<Pending>,
    pub(crate) own: Option<Own>,
    /// This device's last decision: an epoch, and whether it confirmed it.
    pub(crate) decided: Option<(u64, bool)>,
    pub(crate) course: Course,
}

impl State {
    pub(crate) fn known(&self, device: DeviceId) -> Option<&Known> {
        self.devices
            .iter()
            .find(|(id, _)| *id == device)
            .map(|(_, known)| known)
    }

    pub(crate) fn known_mut(&mut self, device: DeviceId) -> Option<&mut Known> {
        self.devices
            .iter_mut()
            .find(|(id, _)| *id == device)
            .map(|(_, known)| known)
    }

    /// A device in the group with a voice.
    pub(crate) fn voiced(&self, device: DeviceId) -> bool {
        self.known(device)
            .is_some_and(|known| !known.matured && !known.out)
    }

    /// A device with a voice past its probation at `at`: it may sign an
    /// operation or a commit.
    pub(crate) fn may_sign(&self, device: DeviceId, at: u64) -> bool {
        self.voiced(device)
            && self
                .known(device)
                .is_some_and(|known| at >= known.active_from)
    }

    /// The device's voice at `cutoff`: no matured removal, and none whose
    /// verified removal matures by then.
    pub(crate) fn voiced_at(&self, device: DeviceId, cutoff: u64) -> bool {
        self.voiced(device)
            && !self.removals.iter().any(|removal| {
                removal.target == device
                    && removal.evidence == Check::Valid
                    && removal.matures <= cutoff
            })
    }

    /// The matured removals with verified evidence no confirmed commit
    /// carried yet: what the next commit carries.
    pub(crate) fn owed(&self) -> Vec<DeviceId> {
        let mut owed: Vec<DeviceId> = self
            .removals
            .iter()
            .filter(|removal| {
                removal.evidence == Check::Valid
                    && self
                        .known(removal.target)
                        .is_some_and(|known| known.matured && !known.out)
            })
            .map(|removal| removal.target)
            .collect();
        owed.sort_unstable();
        owed.dedup();
        owed
    }
}

/// What a device that pairs another hands it over the pairing channel:
/// the agent, the device group's devices and removals as the pairing
/// device verified them, its place in the log, and the key archive.
#[derive(Clone, Debug, Encode, Decode)]
pub struct Pairing {
    agent: Agent,
    next: u64,
    chain: [u8; 32],
    time: u64,
    confirmed: u64,
    policy: Policy,
    devices: Vec<(DeviceId, Known)>,
    removals: Vec<Removal>,
    archive: Archive,
}

impl Pairing {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::decode_exact(bytes)
    }
}

/// A device's leaf credential: its sync key and its admin key.
pub fn credential(device: &NewDevice) -> Vec<u8> {
    [&device.sync[..], &device.admin[..]].concat()
}

/// A candidate processed on a copy, in memory: after a restart the logged
/// candidate is processed again.
pub(crate) enum Processed {
    /// Its copy, and its confirmation hash: none when it removes this
    /// device.
    Copy {
        candidate: Box<vos_mls::Candidate>,
        h: Option<[u8; 32]>,
    },
    /// Refused: its evidence, its effect or its handshake.
    Refused,
    /// This device cannot process it: its own commit, no longer held.
    Unable,
    /// Not for this device: a device not yet in the group seeing another's
    /// add.
    Ignored,
}

/// The device group of a light node's store.
pub struct DeviceGroup {
    store: Store,
    mls: Mls,
    state: State,
    archive: Archive,
    /// The pending candidate's processing, by its log index.
    processed: Option<(u64, Processed)>,
}

fn namespace(store: &Store) -> Namespace {
    Namespace::current(store.group_store(), MLS.to_vec())
}

impl DeviceGroup {
    /// The claiming device's group: this device alone, number 0, at epoch
    /// 0, following the log from its start; the store's archive, its
    /// naming secret drawn with the store, kept.
    pub fn create(
        store: &Store,
        agent: Agent,
        me: NewDevice,
        now: u64,
    ) -> Result<Self, GroupError> {
        if store.group_row(STATE)?.is_some() {
            return Err(GroupError::Grouped);
        }
        let archive = store.archive()?;
        let state = State {
            agent,
            me: me.clone(),
            id: Some(0),
            next: 0,
            chain: [0; 32],
            time: now,
            calls: vec![now],
            confirmed: 0,
            renewed: now,
            policy: Policy::DEFAULT,
            devices: vec![(
                0,
                Known {
                    keys: me.clone(),
                    active_from: now,
                    matured: false,
                    out: false,
                },
            )],
            removals: Vec::new(),
            pending: None,
            own: None,
            decided: None,
            course: Course::Following,
        };
        let mut mls = Mls::open(namespace(store), &credential(&me), BTreeMap::new())?;
        mls.create(now / 1000, rows(&state, None))?;
        Ok(Self {
            store: store.clone(),
            mls,
            state,
            archive,
            processed: None,
        })
    }

    /// A device about to be paired: its leaf's signing key drawn and a key
    /// package made, for the pairing device's add, at `now`.
    pub fn key_package(store: &Store, me: &NewDevice, now: u64) -> Result<Vec<u8>, GroupError> {
        if store.group_row(STATE)?.is_some() {
            return Err(GroupError::Grouped);
        }
        let mut mls = Mls::open(namespace(store), &credential(me), BTreeMap::new())?;
        Ok(mls.key_package(now / 1000, BTreeMap::new())?)
    }

    /// The paired device's group, from `pairing`: it follows the log from
    /// where the pairing device read it, and joins with the Welcome of the
    /// commit that adds it. Its store's archive becomes the pairing's; a
    /// store whose naming secret named a scope already is refused.
    pub fn join(store: &Store, me: NewDevice, pairing: Pairing) -> Result<Self, GroupError> {
        if store.group_row(STATE)?.is_some() {
            return Err(GroupError::Grouped);
        }
        if store.scoped()? {
            return Err(GroupError::Scoped);
        }
        let Pairing {
            agent,
            next,
            chain,
            time,
            confirmed,
            policy,
            devices,
            removals,
            archive,
        } = pairing;
        let state = State {
            agent,
            me: me.clone(),
            id: None,
            next,
            chain,
            time,
            calls: Vec::new(),
            confirmed,
            renewed: time,
            policy,
            devices,
            removals,
            pending: None,
            own: None,
            decided: None,
            course: Course::Following,
        };
        let mut mls = Mls::open(namespace(store), &credential(&me), BTreeMap::new())?;
        mls.write(rows(&state, Some(&archive)))?;
        Ok(Self {
            store: store.clone(),
            mls,
            state,
            archive,
            processed: None,
        })
    }

    /// The store's device group, if it has one.
    pub fn open(store: &Store) -> Result<Option<Self>, GroupError> {
        let Some(bytes) = store.group_row(STATE)? else {
            return Ok(None);
        };
        let state = State::decode_exact(&bytes).ok_or(GroupError::Corrupt)?;
        let mls = Mls::open(namespace(store), &credential(&state.me), BTreeMap::new())?;
        Ok(Some(Self {
            store: store.clone(),
            mls,
            archive: store.archive()?,
            state,
            processed: None,
        }))
    }

    /// The device's number in the device set, once its add is confirmed.
    pub fn id(&self) -> Option<DeviceId> {
        self.state.id
    }

    pub fn course(&self) -> Course {
        self.state.course
    }

    /// The confirmed epoch: the one data is sealed under.
    pub fn confirmed(&self) -> u64 {
        self.state.confirmed
    }

    /// The next log index to read.
    pub fn cursor(&self) -> u64 {
        self.state.next
    }

    /// The log's chain through the entry before the cursor: this device's
    /// view of the control log.
    pub fn view(&self) -> (u64, [u8; 32]) {
        (self.state.next, self.state.chain)
    }

    /// Whether a candidate is pending, or this device's own commit.
    pub fn pending(&self) -> bool {
        self.state.pending.is_some() || self.state.own.is_some()
    }

    pub fn archive(&self) -> &Archive {
        &self.archive
    }

    /// What the device group stores, in bytes: its MLS group state, what
    /// it keeps of the log, and the key archive.
    pub fn stored_bytes(&self) -> Result<(usize, usize, usize), GroupError> {
        let state = self.mls.state_bytes()?;
        let log = self.store.group_row(STATE)?.map_or(0, |row| row.len());
        let archive = self
            .store
            .group_row(crate::store::ARCHIVE_ROW)?
            .map_or(0, |row| row.len());
        Ok((state, log, archive))
    }

    /// The scope key of `scope` at the confirmed epoch, `k(scope, n) =
    /// MLS-Exporter("vos/personal/scope", scope, 32)`: tracked from now,
    /// so the archive records it at every confirmed epoch.
    pub fn key(&mut self, scope: Scope) -> Result<[u8; 32], GroupError> {
        let key = self.export(archive::SCOPE_LABEL, &scope)?;
        if !self.archive.scopes.contains(&scope)
            || !self
                .archive
                .keys(self.state.confirmed, &scope)
                .contains(&key)
        {
            self.archive.track(scope);
            self.archive.record(self.state.confirmed, scope, key);
            self.mls.write(rows(&self.state, Some(&self.archive)))?;
        }
        Ok(key)
    }

    /// The archive's key at the confirmed epoch.
    pub fn archive_key(&self) -> Result<[u8; 32], GroupError> {
        self.export(archive::ARCHIVE_LABEL, b"")
    }

    fn export(&self, label: &[u8], context: &[u8]) -> Result<[u8; 32], GroupError> {
        if !self.mls.grouped() {
            return Err(GroupError::NoGroup);
        }
        if self.mls.epoch()? != self.state.confirmed {
            return Err(GroupError::Stuck);
        }
        let key = self.mls.export(label, context, 32)?;
        key.try_into().map_err(|_| GroupError::Corrupt)
    }

    /// Merge `other` into this device's archive: a pairing's, or one
    /// opened from the agent.
    pub fn merge_archive(&mut self, other: &Archive) -> Result<(), GroupError> {
        self.archive.merge(other);
        self.mls.write(rows(&self.state, Some(&self.archive)))?;
        Ok(())
    }

    /// Record that this device made a call the agent answered at `at`:
    /// the log must count it seen.
    pub fn called(&mut self, at: u64) {
        let window = self.state.policy.confirm_window_ms;
        let calls = &mut self.state.calls;
        if calls.last().is_none_or(|last| *last < at) {
            calls.push(at);
        }
        calls.retain(|call| call.saturating_add(window) >= at);
        if calls.len() > CALLS {
            calls.drain(..calls.len() - CALLS);
        }
    }

    /// Whether this device's leaf is due its yearly update at `now`.
    pub fn update_due(&self, now: u64) -> bool {
        now >= self.state.renewed.saturating_add(RENEW_AFTER_MS)
    }

    fn ready(&self) -> Result<DeviceId, GroupError> {
        match self.state.course {
            Course::Following => {}
            Course::Stuck { .. } => return Err(GroupError::Stuck),
            Course::Out => return Err(GroupError::Out),
        }
        if self.pending() || self.processed.is_some() {
            return Err(GroupError::Pending);
        }
        self.state.id.ok_or(GroupError::NoGroup)
    }

    /// Commit at `now` for the epoch after the confirmed one: adding `add`
    /// (a device's keys and its key package), and carrying every matured
    /// removal; an update with neither. Held, with the record of it, before
    /// this returns: then make the admin call with
    /// [`Prepared::arguments`], and give its log index and signed message
    /// to [`DeviceGroup::called_commit`], or [`DeviceGroup::abandon`] it if
    /// the agent refused it.
    pub fn commit(
        &mut self,
        add: Option<(NewDevice, Vec<u8>)>,
        now: u64,
    ) -> Result<Prepared, GroupError> {
        self.ready()?;
        let remove = self.state.owed();
        let mut removes = Vec::new();
        for device in &remove {
            let known = self.state.known(*device).ok_or(GroupError::Corrupt)?;
            removes.push(credential(&known.keys));
        }
        let mut packages = Vec::new();
        if let Some((keys, package)) = &add {
            if self
                .state
                .devices
                .iter()
                .any(|(_, known)| known.keys.sync == keys.sync || known.keys.admin == keys.admin)
            {
                return Err(GroupError::Known);
            }
            packages.push(package.clone());
        }
        let effect = Effect {
            add: add.map(|(keys, _)| keys),
            remove,
        };
        let mut state = self.state.clone();
        let epoch = state.confirmed + 1;
        state.own = Some(Own {
            epoch,
            welcome: None,
            arguments: Vec::new(),
            signed: None,
            index: None,
            evidenced: false,
        });
        let commit = self.mls.commit(&packages, &removes, now / 1000, |commit| {
            if let Some(own) = &mut state.own {
                own.welcome = commit.welcome.clone();
                own.arguments = Prepared {
                    epoch: commit.epoch,
                    effect: effect.clone(),
                    handshake: commit.handshake.clone(),
                    welcome: commit.welcome.clone(),
                }
                .arguments();
            }
            rows(&state, None)
        })?;
        self.state = state;
        Ok(Prepared {
            epoch: commit.epoch,
            effect,
            handshake: commit.handshake,
            welcome: commit.welcome,
        })
    }

    /// Pair `device` at `now`: the commit adding it, and what the new
    /// device needs over the pairing channel.
    pub fn pair(
        &mut self,
        device: NewDevice,
        key_package: Vec<u8>,
        now: u64,
    ) -> Result<(Prepared, Pairing), GroupError> {
        let prepared = self.commit(Some((device, key_package)), now)?;
        let pairing = Pairing {
            agent: self.state.agent,
            next: self.state.next,
            chain: self.state.chain,
            time: self.state.time,
            confirmed: self.state.confirmed,
            policy: self.state.policy,
            devices: self.state.devices.clone(),
            removals: self.state.removals.clone(),
            archive: self.archive.clone(),
        };
        Ok((prepared, pairing))
    }

    /// The admin call of this device's held commit is signed, as
    /// `message` with `signature`: written before the call is made, so the
    /// evidence survives a crash between the call and its answer.
    pub fn signed_commit(
        &mut self,
        message: Vec<u8>,
        signature: [u8; 64],
    ) -> Result<(), GroupError> {
        let own = self.state.own.as_mut().ok_or(GroupError::NoCommit)?;
        own.signed = Some((message, signature));
        self.mls.write(rows(&self.state, None))?;
        Ok(())
    }

    /// The agent took this device's signed commit call at log index
    /// `index`: the evidence to post, which [`DeviceGroup::follow`] gives
    /// again until the log holds it (and finds by itself in the log after
    /// a crash).
    pub fn called_commit(&mut self, index: u64) -> Result<Event, GroupError> {
        let own = self.state.own.as_mut().ok_or(GroupError::NoCommit)?;
        let (message, signature) = own.signed.clone().ok_or(GroupError::NoCommit)?;
        own.index = Some(index);
        let welcome = own.welcome.clone();
        self.mls.write(rows(&self.state, None))?;
        Ok(Event::Evidence {
            index,
            message,
            signature,
            welcome,
        })
    }

    /// The agent refused this device's held commit's call (`EpochTaken`,
    /// `EpochGap`, a quota): the held commit is deleted; the device rereads
    /// the log and commits again if its intent still holds.
    pub fn abandon(&mut self) -> Result<(), GroupError> {
        if self
            .state
            .own
            .as_ref()
            .is_some_and(|own| own.index.is_some())
        {
            return Err(GroupError::Pending);
        }
        self.state.own = None;
        self.mls.void(rows(&self.state, None))?;
        Ok(())
    }
}

/// The group's rows: its state and, when it changed, the archive.
pub(crate) fn rows(state: &State, archive: Option<&Archive>) -> vos_mls::Writes {
    let mut rows = BTreeMap::new();
    rows.insert(STATE.to_vec(), Some(state.encode()));
    if let Some(archive) = archive {
        rows.insert(crate::store::ARCHIVE_ROW.to_vec(), Some(archive.encode()));
    }
    rows
}
