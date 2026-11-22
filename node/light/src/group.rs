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
//! - **The device set's operations are honoured behind their evidence:**
//!   each operation, veto, second signature and resolution is checked
//!   against its signer, and a maturity the log asserts takes effect only
//!   once the evidence supports it (its delay passed unvetoed, or a
//!   verified second signature or resolution), else [`Alarm::Unsigned`].
//!   A commit carries every removal this device honours; a matured
//!   regroup's first commit is its regrouper's new group of it alone
//!   ([`DeviceGroup::regroup`]), every other device removed and pairing
//!   again; a restore's device starts its own ([`DeviceGroup::restore`]).
//! - **Sleepers are deferred:** a device outside the set processes the
//!   confirmed candidate when it reads it; one it cannot process, or whose
//!   `h` is not the confirmed one, raises [`Alarm::CannotFollow`] naming the
//!   committer, and stops: it re-pairs, or regroups with no device to pair
//!   from.
//! - **Keys:** data keys are exported at the confirmed epoch alone
//!   ([`DeviceGroup::key`]), scope ids derive from the archive's naming
//!   secret, and the archive ([`archive`]) records every scope key of every
//!   confirmed epoch.
//! - **`R` rotates at every removal:** a commit carrying a removal draws a
//!   new `R`, its `R1` sealed to each of the kit's keys and its `R2` in the
//!   evidence ([`Effect::rekey`]); a kit rotation ([`DeviceGroup::rotate`])
//!   and a restore draw one too. The device that drew it holds it aside
//!   until the log makes it the kit's (the commit's verdict, the
//!   operation's verified maturity), then the other devices take it from
//!   an archive sealed under an epoch the removed device is not in, only
//!   when its hash is the one the admin call named.
//! - **A replaced admin key** takes the device's leaf with the device's
//!   next commit, which renews its credential; a call the new key signs
//!   while the replacement's evidence is still to come waits for it.
//!
//! Sans I/O: the caller makes the calls (the admin key signs commits behind
//! the owner's prompt, the sync key votes and evidence), reads the log and
//! hands its entries over. A call `Personal` refuses with `Settling` (more
//! fell due than one call settles) is made again after a `wake`.

mod alarm;
pub mod archive;
mod follow;
#[cfg(test)]
mod pins;
mod set;
mod state;

use std::collections::BTreeMap;

use vos_abi::ids::{InstanceId, MethodId};
use vos_abi::{Decode, Encode};
use vos_mls::{Mls, Namespace};
use vos_wire::ingress::CallMessage;
use vos_wire::personal::{
    Attached, DeviceId, DeviceView, Effect, NewDevice, Op, Place, Policy, Scope, Signer, Status,
    Vote, welcome_hash,
};
use zeroize::Zeroize;

use crate::kit::{KitKey, Split};
use crate::store::{Change, Store, StoreError};

pub use alarm::{Alarm, Remedy, Why, clock};
pub use archive::Archive;
pub use state::Course;
pub(crate) use state::{
    Act, Call, Check, Claim, Known, Made, Named, Own, Passing, Pending, Sent, Set, State, Support,
};

/// The confirmation hash's domain.
pub const CONFIRM: &[u8] = b"vos/personal/confirm";

/// The group's rows in the store's group keyspace, beside `vos-mls`'s
/// namespace.
const STATE: &[u8] = b"g/state";

/// The calls a device remembers within the window.
const CALLS: usize = 32;
/// The admin calls a device remembers until the log shows them, and the
/// writers' views past its cursor it keeps to check.
const MADE: usize = 16;
const VIEWS: usize = 16;
/// The admin calls a device holds whose evidence the log has yet to show.
const SENT: usize = 8;
/// The MLS state's rows.
const MLS: &[u8] = b"mls/";
/// The log's chain through each entry read, by the next index: the views
/// writers name are checked against it.
const CHAINS: &[u8] = b"g/chain/";
/// The alarms raised and not yet acknowledged, and how many are kept.
const ALARMS: &[u8] = b"g/alarms";
const KEPT_ALARMS: usize = 64;

fn chain_key(next: u64) -> Vec<u8> {
    [CHAINS, &next.to_be_bytes()[..]].concat()
}

/// The personal agent a device group's commits go through: its identity,
/// which calls are signed for, and `Personal`'s instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Agent {
    pub identity: [u8; 32],
    pub instance: InstanceId,
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
    /// A matured regroup's new group comes first: its regrouper's
    /// [`DeviceGroup::regroup`], no other commit.
    Regroup,
    /// No matured regroup of this device's waits for its new group.
    NoRegroup,
    /// The agent's device set as read does not name this device.
    Unnamed,
    /// The kit's keys do not seal: no key, one no agreement is
    /// contributory with, or no randomness.
    Kit,
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
            GroupError::Regroup => f.write_str("a regroup's new group comes first"),
            GroupError::NoRegroup => f.write_str("no regroup of this device's has matured"),
            GroupError::Unnamed => f.write_str("the device set does not name this device"),
            GroupError::Kit => f.write_str("the kit's keys do not seal"),
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
    /// sync key, with what rides beside it. Given again until the log holds
    /// it.
    Evidence {
        index: u64,
        message: Vec<u8>,
        signature: [u8; 64],
        attached: Attached,
    },
    /// Post `alive` under the sync key: a restore is pending, which
    /// asserts every device lost. Given again until the log cancels it.
    Alive,
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
    /// This device's own leave matured, after [`Event::Removed`]: it forgets
    /// the space.
    Left,
    Alarm(Alarm),
}

/// A commit this device made, held: what its admin call carries; its `R2`,
/// when it re-seals the kit, rides in the evidence.
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

/// What a device that pairs another hands it over the pairing channel:
/// the agent, the device group's devices and the device set's operations
/// as the pairing device verified them, its place in the log and the
/// index after the last admin call it read there, and the key archive.
#[derive(Clone, Debug, Encode, Decode)]
pub struct Pairing {
    agent: Agent,
    next: u64,
    chain: [u8; 32],
    floor: u64,
    time: u64,
    confirmed: u64,
    offset: u64,
    policy: Policy,
    devices: Vec<(DeviceId, Known)>,
    set: Set,
    recovery: Option<Named>,
    assigned: Option<u64>,
    archive: Archive,
}

/// What a device a restore added reads from the agent once the restore
/// matured, to start its new group: the log's head, the confirmed epoch,
/// the policy, and the device set; and what it knows itself, the kit it
/// carried and its `R`'s hash, the `R` it drew held in its store
/// ([`restoring`]). It has no earlier view to check the agent's against.
#[derive(Clone, Debug)]
pub struct Restored {
    pub next: u64,
    pub chain: [u8; 32],
    pub time: u64,
    pub confirmed: u64,
    pub policy: Policy,
    pub kit: Vec<KitKey>,
    pub r_hash: [u8; 32],
    pub devices: Vec<DeviceView>,
}

/// The policy the control log `entries` set, read from its start in
/// order, as a device following it takes it: the claim's
/// configuration (one before its assignment, or the one beside it) whole,
/// each later one over it ([`Policy::over`]), from [`Policy::DEFAULT`]. A
/// restored device starts from it, never from a policy of its own.
pub fn configured<'a>(
    entries: impl IntoIterator<Item = &'a (u64, vos_wire::personal::Entry)>,
) -> Policy {
    use vos_wire::personal::Body;
    let mut assigned = None;
    let mut policy = Policy::DEFAULT;
    for (index, entry) in entries {
        match &entry.body {
            Body::Assigned { device: 0, .. } if assigned.is_none() => assigned = Some(*index),
            Body::Configured(configured) => {
                policy = configure(assigned, *index, *configured, &policy)
            }
            _ => {}
        }
    }
    policy
}

/// A configuration `policy` at log index `index`, the claim's assignment
/// at `assigned` if read, over `held`: the claim's (one before the
/// assignment, or the one beside it) taken whole, a later one over
/// `held`.
pub(crate) fn configure(
    assigned: Option<u64>,
    index: u64,
    policy: Policy,
    held: &Policy,
) -> Policy {
    if assigned.is_none_or(|assigned| index == assigned + 1) {
        policy
    } else {
        policy.over(held)
    }
}

impl Pairing {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::decode_exact(bytes)
    }

    /// The personal agent it is of.
    pub fn agent(&self) -> Agent {
        self.agent
    }

    /// The key archive it hands over.
    pub fn archive(&self) -> &Archive {
        &self.archive
    }
}

/// Whether `store` has a device group.
pub(crate) fn grouped(store: &Store) -> Result<bool, StoreError> {
    Ok(store.group_row(STATE)?.is_some())
}

/// A store with no device group: refused `Grouped` otherwise.
fn ungrouped(store: &Store) -> Result<(), GroupError> {
    match grouped(store)? {
        true => Err(GroupError::Grouped),
        false => Ok(()),
    }
}

/// A device's leaf credential at its add: its sync key and its admin key.
pub fn credential(device: &NewDevice) -> Vec<u8> {
    [&device.sync[..], &device.admin[..]].concat()
}

/// A restore's split of `keys`, the kit it carries, at `agent`: its `R`
/// held in `store`'s archive until the restore matures and
/// [`DeviceGroup::restore`] makes it the kit's, and the rows `rows` makes
/// of the split written in the same batch: what the restore makes the
/// device's beside it. Only for a store with no device group.
pub fn restoring(
    store: &Store,
    keys: &[KitKey],
    agent: &Agent,
    rows: impl FnOnce(&Split) -> Vec<Change>,
) -> Result<Split, GroupError> {
    ungrouped(store)?;
    let split = Split::draw(keys, &agent.identity).ok_or(GroupError::Kit)?;
    let mut archive = store.archive()?;
    archive.draw(*split.r());
    let mut writes = vec![(crate::store::ARCHIVE_ROW.to_vec(), Some(archive.encode()))];
    writes.extend(rows(&split));
    store.write_group_rows(writes)?;
    Ok(split)
}

/// An open operation of the device set as this device verified it, for
/// the chrome: its index, signer and operation, when it matures, whether
/// it is contested, the devices whose vetoes verified, and whether its
/// own evidence did; and for a contest, whether this device cannot resolve
/// it (one of its targets, or not a seasoned strong device, as the agent
/// rules), and whether fewer than the two devices a resolution needs can,
/// so the kit alone resolves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Open {
    pub index: u64,
    pub by: Signer,
    pub op: Op,
    pub matures: u64,
    pub contested: bool,
    pub vetoes: Vec<DeviceId>,
    pub verified: bool,
    pub cannot_resolve: bool,
    pub kit_only: bool,
}

/// The devices an operation names as its target: those it removes, or
/// whose admin key it replaces.
fn targets(op: &Op) -> Vec<DeviceId> {
    match op {
        Op::Replace { device, .. } => vec![*device],
        _ => removes(op),
    }
}

/// The devices an operation removes.
fn removes(op: &Op) -> Vec<DeviceId> {
    match op {
        Op::Remove(target) => vec![*target],
        Op::Regroup(named) => named.clone(),
        _ => Vec::new(),
    }
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
    /// The log's chains read and not yet written, by the next index.
    chains: Vec<(u64, [u8; 32])>,
    /// The alarms raised and not yet written.
    raised: Vec<Alarm>,
}

/// The namespace `store`'s MLS state is in.
pub fn mls_namespace(store: &Store) -> Namespace {
    Namespace::current(store.group_store(), MLS.to_vec())
}

impl DeviceGroup {
    /// The claiming device's group: this device alone, number 0, at epoch
    /// 0, following the log from its start, its kit `kit`; the store's
    /// archive, its naming secret drawn with the store, kept. The claim's
    /// `R` is [`DeviceGroup::set_recovery`]'s.
    pub fn create(
        store: &Store,
        agent: Agent,
        me: NewDevice,
        kit: Vec<KitKey>,
        now: u64,
    ) -> Result<Self, GroupError> {
        ungrouped(store)?;
        let archive = store.archive()?;
        let state = State {
            agent,
            me: me.clone(),
            id: Some(0),
            next: 0,
            chain: [0; 32],
            floor: 0,
            time: 0,
            calls: vec![now],
            confirmed: 0,
            offset: 0,
            policy: Policy::DEFAULT,
            devices: vec![(0, Known::new(me.clone(), now))],
            set: Set {
                kit,
                ..Set::default()
            },
            pending: None,
            passing: None,
            own: None,
            decided: None,
            course: Course::Following,
            recovery: None,
            rekeyed: None,
            made: Vec::new(),
            sent: Vec::new(),
            reseal: false,
            views: Vec::new(),
            ahead: None,
            assigned: None,
            leaving: false,
        };
        let mut mls = Mls::open(mls_namespace(store), &credential(&me), BTreeMap::new())?;
        mls.create(now / 1000, rows(&state, None))?;
        Ok(Self {
            store: store.clone(),
            mls,
            state,
            archive,
            processed: None,
            chains: Vec::new(),
            raised: Vec::new(),
        })
    }

    /// A device about to be paired: its leaf's signing key drawn and a key
    /// package made, for the pairing device's add, at `now`. Refused for a
    /// store that has a group.
    pub fn key_package(store: &Store, me: &NewDevice, now: u64) -> Result<Vec<u8>, GroupError> {
        ungrouped(store)?;
        let mut mls = Mls::open(mls_namespace(store), &credential(me), BTreeMap::new())?;
        Ok(mls.key_package(now / 1000, BTreeMap::new())?)
    }

    /// The paired device's group, from `pairing`: it follows the log from
    /// where the pairing device read it, and joins with the Welcome of the
    /// commit that adds it, `rows` of the group keyspace written in the
    /// batch that makes the group: what the pairing makes the device's
    /// beside it. Its store's archive becomes the pairing's; a store whose
    /// naming secret named a scope already is refused.
    pub fn join(
        store: &Store,
        me: NewDevice,
        pairing: Pairing,
        rows: Vec<Change>,
    ) -> Result<Self, GroupError> {
        ungrouped(store)?;
        if store.scoped()? {
            return Err(GroupError::Scoped);
        }
        Self::joined(store, me, pairing, rows)
    }

    fn joined(
        store: &Store,
        me: NewDevice,
        pairing: Pairing,
        extra: Vec<Change>,
    ) -> Result<Self, GroupError> {
        let Pairing {
            agent,
            next,
            chain,
            floor,
            time,
            confirmed,
            offset,
            policy,
            devices,
            set,
            recovery,
            assigned,
            archive,
        } = pairing;
        let state = State {
            agent,
            me: me.clone(),
            id: None,
            next,
            chain,
            floor,
            time,
            calls: Vec::new(),
            confirmed,
            offset,
            policy,
            devices,
            set,
            pending: None,
            passing: None,
            own: None,
            decided: None,
            course: Course::Following,
            recovery,
            rekeyed: None,
            made: Vec::new(),
            sent: Vec::new(),
            reseal: false,
            views: Vec::new(),
            ahead: None,
            assigned,
            leaving: false,
        };
        let mut mls = Mls::open(mls_namespace(store), &credential(&me), BTreeMap::new())?;
        let mut writes = rows(&state, Some(&archive));
        writes.extend(extra);
        mls.write(writes)?;
        Ok(Self {
            store: store.clone(),
            mls,
            state,
            archive,
            processed: None,
            chains: Vec::new(),
            raised: Vec::new(),
        })
    }

    /// The group of the device a matured restore added alone, from what it
    /// read of the agent ([`Restored`]): a new group of this device alone at
    /// the confirmed epoch, following the log from its head; its first
    /// commit carries the removal of every device before it. The store's
    /// archive is kept, the `R` [`restoring`] drew the kit's.
    pub fn restore(
        store: &Store,
        agent: Agent,
        me: NewDevice,
        read: Restored,
    ) -> Result<Self, GroupError> {
        ungrouped(store)?;
        let id = read
            .devices
            .iter()
            .find(|view| view.device.keys.sync == me.sync && view.device.status == Status::Live)
            .map(|view| view.id)
            .ok_or(GroupError::Unnamed)?;
        // The restore's `R`, drawn for the kit it carries, is the kit's
        // from its maturity, before the log's head.
        let since = read.next.saturating_sub(1);
        let mut archive = store.archive()?;
        if !archive.name(since, &read.r_hash) {
            return Err(GroupError::Kit);
        }
        let mut devices = Vec::new();
        let mut owed = Vec::new();
        for view in &read.devices {
            let mut known = Known::new(view.device.keys.clone(), view.device.active_from);
            match view.device.status {
                Status::Live => {}
                Status::Removed { at } => {
                    known.matured = Some(at);
                    known.out = view
                        .removal
                        .is_some_and(|removal| removal.committed.is_some());
                    if !known.out {
                        owed.push(view.id);
                    }
                }
                Status::Dropped { .. } => known.out = true,
            }
            devices.push((view.id, known));
        }
        let state = State {
            agent,
            me: me.clone(),
            id: Some(id),
            next: read.next,
            chain: read.chain,
            floor: read.next,
            time: read.time,
            calls: vec![read.time],
            confirmed: read.confirmed,
            offset: read.confirmed,
            policy: read.policy,
            devices,
            set: Set {
                kit: read.kit,
                owed,
                ..Set::default()
            },
            pending: None,
            passing: None,
            own: None,
            decided: None,
            course: Course::Following,
            recovery: Some(Named {
                since,
                hash: read.r_hash,
                by_kit: false,
            }),
            rekeyed: None,
            made: Vec::new(),
            sent: Vec::new(),
            reseal: false,
            views: Vec::new(),
            ahead: None,
            assigned: Some(0),
            leaving: false,
        };
        let mut mls = Mls::open(mls_namespace(store), &credential(&me), BTreeMap::new())?;
        mls.create(read.time / 1000, rows(&state, Some(&archive)))?;
        Ok(Self {
            store: store.clone(),
            mls,
            state,
            archive,
            processed: None,
            chains: Vec::new(),
            raised: Vec::new(),
        })
    }

    /// The store's device group, if it has one.
    pub fn open(store: &Store) -> Result<Option<Self>, GroupError> {
        let Some(bytes) = store.group_row(STATE)? else {
            return Ok(None);
        };
        let state = State::decode_exact(&bytes).ok_or(GroupError::Corrupt)?;
        let mls = Mls::open(
            mls_namespace(store),
            &credential(&state.me),
            BTreeMap::new(),
        )?;
        Ok(Some(Self {
            store: store.clone(),
            mls,
            archive: store.archive()?,
            state,
            processed: None,
            chains: Vec::new(),
            raised: Vec::new(),
        }))
    }

    /// The device's number in the device set, once its add is confirmed.
    pub fn id(&self) -> Option<DeviceId> {
        self.state.id
    }

    pub fn course(&self) -> Course {
        self.state.course
    }

    /// Whether the device is out of the group by its own leave: its store
    /// is to be forgotten, by whichever pass finds it so.
    pub fn left(&self) -> bool {
        self.state.course == Course::Out && self.state.leaving
    }

    /// Whether the pending candidate adds a device: one whose add is
    /// undecided, which is no other live device yet.
    pub fn adding(&self) -> bool {
        self.state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.effect.add.is_some())
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

    /// Whether this device owes no vote: no commit of its own waits to be
    /// logged, and the candidate pending, if one is, holds its vote. The
    /// epoch may still wait for the other devices'.
    pub fn voted(&self) -> bool {
        let me = self.id();
        self.state.own.is_none()
            && self.state.pending.as_ref().is_none_or(|pending| {
                me.is_some_and(|me| pending.votes.iter().any(|(device, _)| *device == me))
            })
    }

    pub fn archive(&self) -> &Archive {
        &self.archive
    }

    /// The agent's policy, as the log configured it: its delays, windows
    /// and quotas (a pairing's items are its inbox items' size).
    pub fn policy(&self) -> Policy {
        self.state.policy
    }

    /// The personal agent its commits go through.
    pub fn agent(&self) -> Agent {
        self.state.agent
    }

    /// Hold `R`, the claim's at `since`, in the archive: the recovery
    /// envelopes are sealed under it. An `R` the log made the kit's later
    /// stands.
    pub fn set_recovery(&mut self, since: u64, r: [u8; 32]) -> Result<(), GroupError> {
        let mut theirs = self.archive.shareable();
        theirs.recovery = Some(archive::Recovery { since, r });
        self.merge_archive(&theirs)
    }

    /// Whether this device holds the `R` the log made the kit's last, and
    /// may let it travel: not while a removal it honours is owed (the
    /// removed device is still in the epoch), not while a confirmed
    /// commit's re-sealed kit waits on the agent's verdict confirming it
    /// (a verdict that does not leaves it unheld until the next commit
    /// re-seals the kit), and not while it cannot follow.
    pub fn holds_recovery(&self) -> bool {
        if self.state.rekeyed.is_some()
            || !self.state.set.owed.is_empty()
            || self.state.course != Course::Following
        {
            return false;
        }
        match (&self.state.recovery, &self.archive.recovery) {
            (Some(named), Some(held)) => held.since == named.since,
            (None, held) => held.is_some(),
            (Some(_), None) => false,
        }
    }

    /// The kit's keys, as this device verified them.
    pub fn kit(&self) -> &[KitKey] {
        &self.state.set.kit
    }

    /// A kit rotation to `keys`: a split at this device's agent, its `R`
    /// held aside until the rotation's verified maturity makes it the
    /// kit's. Make the admin call `rotate(kit)` and post its evidence with
    /// the split's `R2`.
    pub fn rotate(&mut self, keys: &[KitKey]) -> Result<Split, GroupError> {
        let split = Split::draw(keys, &self.state.agent.identity).ok_or(GroupError::Kit)?;
        self.archive.draw(*split.r());
        let writes = self.writes(true)?;
        self.mls.write(writes)?;
        Ok(split)
    }

    /// A recovered group's archive taken in: its naming secret one of the
    /// earlier groups' (their scopes keep their ids), its keys merged.
    pub fn inherit(&mut self, recovered: &Archive) -> Result<(), GroupError> {
        self.archive.inherit(&recovered.without_recovery());
        let writes = self.writes(true)?;
        self.mls.write(writes)?;
        Ok(())
    }

    /// An archive read from the agent merged, bounded by what any device
    /// of the epoch may bring: the keys of the epochs before the confirmed
    /// one (this device exports the confirmed epoch's itself, and no device
    /// holds a later one), and its `R` only when it is the one the log made
    /// the kit's, by its hash. Earlier groups' naming secrets and scopes
    /// are not taken: they come from this device's own restore and from a
    /// pairing alone. So no device, removed later, leaves a key behind that
    /// outlives its removal.
    pub fn merge_read(&mut self, read: &Archive) -> Result<(), GroupError> {
        let named = self.state.recovery;
        let confirmed = self.state.confirmed;
        let mut taken = read.shareable();
        let theirs = taken.recovery.take();
        if let (Some(named), Some(theirs)) = (named, theirs)
            && theirs.since == named.since
            && vos_wire::personal::r_hash(&theirs.r) == named.hash
        {
            taken.recovery = Some(theirs);
        }
        taken.previous.zeroize();
        taken.previous.clear();
        taken.scopes.clear();
        taken.keys.retain_mut(|((epoch, _), keys)| {
            let before = *epoch < confirmed;
            if !before {
                keys.zeroize();
            }
            before
        });
        self.merge_archive(&taken)
    }

    /// Whether the log asserted a maturity removing `device` that its
    /// evidence has not supported: one waiting for evidence never posted,
    /// or refused for want of it. Not a removal pending its delay.
    pub fn removal_unsupported(&self, device: DeviceId) -> bool {
        self.state.set.claims.iter().any(|claim| {
            matches!(claim.support, Support::Waiting | Support::Refused)
                && (claim.every || claim.removes.contains(&device))
        })
    }

    /// The device set's open operations, as this device verified them.
    pub fn operations(&self) -> Vec<Open> {
        let state = &self.state;
        state
            .set
            .operations
            .iter()
            .filter(|call| {
                call.evidence != Check::Invalid && !state.set.closed.contains(&call.index)
            })
            .filter_map(|call| {
                let Act::Op { op, matures } = &call.act else {
                    return None;
                };
                let vetoes = state
                    .set
                    .operations
                    .iter()
                    .filter(|veto| {
                        veto.act == Act::Veto(call.index) && veto.evidence == Check::Valid
                    })
                    .filter_map(|veto| match veto.by {
                        Signer::Device(device) => Some(device),
                        Signer::Kit(_) => None,
                    })
                    .collect::<Vec<_>>();
                let contested = call.rival.is_some() || !vetoes.is_empty();
                // As the agent rules: a resolution is two seasoned strong
                // devices', none of them a target of the operation (those
                // it names) or of its rival (those it removes).
                let mut named = targets(op);
                if let Some(Act::Op { op: rival, .. }) = call
                    .rival
                    .and_then(|rival| state.call_at(rival))
                    .map(|rival| &rival.act)
                {
                    named.extend(removes(rival));
                }
                let resolver = |id: DeviceId| {
                    !named.contains(&id)
                        && state.seasoned(id, state.time)
                        && state.known(id).is_some_and(|known| known.strong)
                };
                let resolvers = state.devices.iter().filter(|(id, _)| resolver(*id)).count();
                Some(Open {
                    index: call.index,
                    by: call.by,
                    op: op.clone(),
                    matures: *matures,
                    contested,
                    vetoes,
                    verified: call.evidence == Check::Valid && call.awaits.is_none(),
                    cannot_resolve: contested && !state.id.is_some_and(resolver),
                    kit_only: contested && resolvers < 2,
                })
            })
            .collect()
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
            let writes = self.writes(true)?;
            self.mls.write(writes)?;
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
        if self.mls.epoch()? + self.state.offset != self.state.confirmed {
            return Err(GroupError::Stuck);
        }
        let key = self.mls.export(label, context, 32)?;
        key.try_into().map_err(|_| GroupError::Corrupt)
    }

    /// Merge `other` into this device's archive: a pairing's, or one
    /// opened from the agent.
    pub fn merge_archive(&mut self, other: &Archive) -> Result<(), GroupError> {
        self.archive.merge(other);
        let writes = self.writes(true)?;
        self.mls.write(writes)?;
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

    /// This device's admin call signed as `message` with `signature`,
    /// held before it leaves, with the `R2` its evidence carries: from the
    /// agent's answer ([`DeviceGroup::made`]) or the call found in the log,
    /// [`DeviceGroup::follow`] gives its evidence to post until the log
    /// holds it, so an evidence post lost to a kill or the network is made
    /// again (an operation due without it is cancelled).
    pub fn sending(
        &mut self,
        message: Vec<u8>,
        signature: [u8; 64],
        r2: Option<[u8; 32]>,
    ) -> Result<(), GroupError> {
        let sent = &mut self.state.sent;
        sent.retain(|sent| sent.message != message);
        // A call never found in the log goes first.
        if sent.len() >= SENT {
            let oldest = sent
                .iter()
                .position(|sent| sent.index.is_none())
                .unwrap_or(0);
            sent.remove(oldest);
        }
        sent.push(Sent {
            message,
            signature,
            r2,
            index: None,
        });
        self.mls.write(rows(&self.state, None))?;
        Ok(())
    }

    /// The agent refused this device's admin call signed as `message`: it
    /// is held no more, unless the log holds it (a refusal the route made
    /// up), whose evidence is posted still.
    pub fn unsent(&mut self, message: &[u8]) -> Result<(), GroupError> {
        let before = self.state.sent.len();
        self.state
            .sent
            .retain(|sent| sent.message != message || sent.index.is_some());
        if self.state.sent.len() < before {
            self.mls.write(rows(&self.state, None))?;
        }
        Ok(())
    }

    /// This device's admin call of `method` with `arguments` (its place
    /// aside) that the log holds open with its evidence still to post: one
    /// whose answer was lost. Its log index, its batch time, and the
    /// message and signature its evidence carries.
    pub fn taken(
        &self,
        method: MethodId,
        arguments: &[u8],
    ) -> Option<(u64, u64, Vec<u8>, [u8; 64])> {
        self.state.sent.iter().find_map(|sent| {
            let index = sent.index?;
            let signed = CallMessage::parse(&sent.message)?;
            let (_, unplaced) = Place::split(&signed.arguments)?;
            let call = self.state.call_at(index)?;
            (signed.method == method && unplaced == arguments)
                .then(|| (index, call.at, sent.message.clone(), sent.signature))
        })
    }

    /// The agent refused the evidence posted for the call at `index`, past
    /// any retry: neither a held call's nor the held commit's is posted
    /// again.
    pub fn evidence_refused(&mut self, index: u64) -> Result<(), GroupError> {
        self.state.sent.retain(|sent| sent.index != Some(index));
        if let Some(own) = self.state.own.as_mut()
            && own.index == Some(index)
        {
            own.evidenced = true;
        }
        self.mls.write(rows(&self.state, None))?;
        Ok(())
    }

    /// Whether a commit is owed that re-seals the kit under a new `R`: the
    /// agent's verdict on the epoch whose commit re-sealed it did not
    /// confirm it, so the `R` before, a removed device's, stands until one
    /// does, and nothing is pushed to the recovery scope meanwhile.
    pub fn reseal_owed(&self) -> bool {
        self.state.reseal && self.state.rekeyed.is_some()
    }

    /// The matured removals the next commit must carry.
    pub fn owed(&self) -> Vec<DeviceId> {
        self.state.owed()
    }

    /// The agent took this device's admin call, signed as `message`, at
    /// log index `index`: the log must hold that call there, and a veto in
    /// it holds its operation back until it does ([`Alarm::Dropped`]); the
    /// call held ([`DeviceGroup::sending`]) has its evidence posted there.
    /// Given before the device follows the log past `index`.
    pub fn made(&mut self, index: u64, message: &[u8]) -> Result<(), GroupError> {
        let Some(signed) = CallMessage::parse(message) else {
            return Ok(());
        };
        if let Some(sent) = self
            .state
            .sent
            .iter_mut()
            .find(|sent| sent.message == message)
        {
            sent.index = Some(index);
        }
        if index < self.state.next {
            self.mls.write(rows(&self.state, None))?;
            return Ok(());
        }
        let made = &mut self.state.made;
        made.retain(|made| made.index != index);
        made.push(Made {
            index,
            origin: signed.session.key,
            method: signed.method.0,
            arguments: signed.arguments,
            dropped: false,
        });
        // A veto holding its operation back is kept past the bound: the
        // open operations bound them.
        if made.len() > MADE
            && let Some(oldest) = made.iter().position(|made| !made.vetoes_any())
        {
            made.remove(oldest);
        }
        let writes = self.writes(false)?;
        self.mls.write(writes)?;
        Ok(())
    }

    /// Check a writer's view of the control log, `(index, chain)`, against
    /// this device's: the chain it read through the entry before `index`.
    /// A view past the cursor is kept and checked as the device reads on,
    /// or at the agent's head ([`DeviceGroup::head`]); one before what this
    /// device read of the log passes.
    pub fn check_view(&mut self, index: u64, chain: [u8; 32]) -> Result<Option<Alarm>, GroupError> {
        let alarm = Some(Alarm::View { index });
        if index == 0 {
            return Ok(alarm.filter(|_| chain != [0; 32]));
        }
        if index == self.state.next {
            return Ok(alarm.filter(|_| chain != self.state.chain));
        }
        if index < self.state.next {
            return Ok(match self.store.group_row(&chain_key(index))? {
                Some(read) if read[..] != chain[..] => alarm,
                _ => None,
            });
        }
        let views = &mut self.state.views;
        if let Some((_, held)) = views.iter().find(|(at, _)| *at == index) {
            return Ok(alarm.filter(|_| *held != chain));
        }
        views.push((index, chain));
        views.sort_unstable();
        if views.len() > VIEWS {
            views.remove(0);
        }
        let writes = self.writes(false)?;
        self.mls.write(writes)?;
        Ok(None)
    }

    /// The agent's log head, `(next, chain)`, as it answers after this
    /// device read the log to its end: a head behind what this device read,
    /// or diverging at it, is a rollback. A head past it is kept, and the
    /// caller reads the log again and gives the head again: a kept head the
    /// log still does not reach is entries withheld ([`Alarm::Unserved`]).
    /// Wherever the log reaches no further than this device read, the
    /// writers' views past it ([`Alarm::View`]) and the admin calls the
    /// agent took past it ([`Alarm::Dropped`]) are unreached.
    pub fn head(&mut self, next: u64, chain: [u8; 32]) -> Result<Vec<Alarm>, GroupError> {
        let mut alarms = Vec::new();
        let cursor = self.state.next;
        if next < cursor || (next == cursor && chain != self.state.chain) {
            alarms.push(Alarm::Rollback { next });
        }
        let kept = self.state.ahead.take();
        match kept.filter(|claimed| *claimed > cursor) {
            Some(claimed) => alarms.push(Alarm::Unserved { next: claimed }),
            None if next > cursor => {
                self.state.ahead = Some(next);
                self.raised.extend(alarms.iter().copied());
                let writes = self.writes(false)?;
                self.mls.write(writes)?;
                return Ok(alarms);
            }
            None => {}
        }
        let views = std::mem::take(&mut self.state.views);
        alarms.extend(views.iter().map(|(index, _)| Alarm::View { index: *index }));
        // A call the agent said it took at an index its log does not reach.
        let mut changed = kept.is_some() || !views.is_empty() || !alarms.is_empty();
        for made in &mut self.state.made {
            if made.index >= cursor && !made.dropped {
                alarms.push(Alarm::Dropped { index: made.index });
                made.dropped = true;
                changed = true;
            }
        }
        self.state
            .made
            .retain(|made| !made.dropped || made.vetoes_any());
        if changed {
            self.raised.extend(alarms.iter().copied());
            let writes = self.writes(false)?;
            self.mls.write(writes)?;
        }
        Ok(alarms)
    }

    /// The device of the set whose sync key is `sync`, and whether it is
    /// removed: a node's author is one, and a removed one's nodes count
    /// only up to its frontier.
    pub fn author(&self, sync: &[u8; 32]) -> Option<(DeviceId, bool)> {
        self.state
            .devices
            .iter()
            .find(|(_, known)| known.keys.sync == *sync)
            .map(|(id, known)| (*id, known.matured.is_some() || known.out))
    }

    /// The sync keys of the set's devices, removed ones' included.
    pub fn sync_keys(&self) -> Vec<(DeviceId, [u8; 32])> {
        self.state
            .devices
            .iter()
            .map(|(id, known)| (*id, known.keys.sync))
            .collect()
    }

    fn ready(&self) -> Result<DeviceId, GroupError> {
        match self.state.course {
            Course::Following => {}
            Course::Stuck { .. } => return Err(GroupError::Stuck),
            Course::Out => return Err(GroupError::Out),
        }
        self.idle()
    }

    fn idle(&self) -> Result<DeviceId, GroupError> {
        if self.pending() || self.processed.is_some() {
            return Err(GroupError::Pending);
        }
        self.state.id.ok_or(GroupError::NoGroup)
    }

    /// This device's removals owed, as the next commit carries them: their
    /// numbers, and the leaf credentials of those in the MLS group.
    fn removals(&self) -> Result<(Vec<DeviceId>, Vec<Vec<u8>>), GroupError> {
        let remove = self.state.owed();
        let members: Vec<Vec<u8>> = self
            .mls
            .credentials()?
            .into_iter()
            .map(|(_, credential)| credential)
            .collect();
        let removes = remove
            .iter()
            .filter_map(|device| self.state.known(*device))
            .map(Known::credential)
            .filter(|credential| members.contains(credential))
            .collect();
        Ok((remove, removes))
    }

    /// The kit re-sealed for a commit carrying `remove`, while the log
    /// names an `R` this device does not hold (a kit rotation the kit
    /// signed, or one whose drawer never passed its `R` on), or while a
    /// confirmed re-sealing commit's `R` waits on a verdict that did not
    /// make it the kit's: a split of the kit's keys, its `R` held aside
    /// until the commit's verdict, and its `R2`.
    fn rekey(&mut self, remove: &[DeviceId]) -> Result<Option<(Split, [u8; 32])>, GroupError> {
        let unheld = (self.state.recovery.is_some() && !self.holds_recovery())
            || self.state.rekeyed.is_some();
        if remove.is_empty() && !unheld {
            return Ok(None);
        }
        let split =
            Split::draw(&self.state.set.kit, &self.state.agent.identity).ok_or(GroupError::Kit)?;
        self.archive.draw(*split.r());
        let r2 = *split.r2();
        Ok(Some((split, r2)))
    }

    /// This device's own commit, held with the record of it: its call's
    /// arguments, by which the log's candidate is known as it.
    fn hold(
        &mut self,
        effect: Effect,
        r2: Option<[u8; 32]>,
        make: impl FnOnce(
            &mut Mls,
            &mut dyn FnMut(&vos_mls::Commit) -> vos_mls::Writes,
        ) -> Result<vos_mls::Commit, vos_mls::Error>,
    ) -> Result<Prepared, GroupError> {
        let mut state = self.state.clone();
        let epoch = state.confirmed + 1;
        let mut rows_of = |commit: &vos_mls::Commit| {
            state.own = Some(Own {
                epoch,
                welcome: commit.welcome.clone(),
                arguments: Prepared {
                    epoch,
                    effect: effect.clone(),
                    handshake: commit.handshake.clone(),
                    welcome: commit.welcome.clone(),
                }
                .arguments(),
                signed: None,
                r2,
                index: None,
                evidenced: false,
            });
            rows(&state, Some(&self.archive))
        };
        let commit = make(&mut self.mls, &mut rows_of)?;
        self.state = state;
        Ok(Prepared {
            epoch,
            effect,
            handshake: commit.handshake,
            welcome: commit.welcome,
        })
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
        if self.state.set.fresh.is_some() {
            return Err(GroupError::Regroup);
        }
        let (remove, removes) = self.removals()?;
        let mut packages = Vec::new();
        if let Some((keys, package)) = &add {
            if self.state.devices.iter().any(|(_, known)| {
                known.keys.sync == keys.sync
                    || known.keys.admin == keys.admin
                    || known.admin == keys.admin
            }) {
                return Err(GroupError::Known);
            }
            packages.push(package.clone());
        }
        let rekey = self.rekey(&remove)?;
        let (rekey, r2) = rekey.map(|(split, r2)| (split.kit.clone(), r2)).unzip();
        let effect = Effect {
            add: add.map(|(keys, _)| keys),
            remove,
            rekey,
        };
        let renewal = self.state.id.and_then(|me| self.renewal_of(me));
        self.hold(effect, r2, |mls, rows| match &renewal {
            Some(credential) => mls.renew(credential, &packages, &removes, now / 1000, rows),
            None => mls.commit(&packages, &removes, now / 1000, rows),
        })
    }

    /// The device whose matured regroup's new group the set waits for: the
    /// next commit is its.
    pub fn regrouper(&self) -> Option<DeviceId> {
        self.state.set.fresh
    }

    /// This device's regroup matured: start its new group of it alone at
    /// `now`, the first commit after the confirmed epoch, carrying every
    /// matured removal (every other device's). Held as
    /// [`DeviceGroup::commit`]'s, and called the same way; a device that
    /// cannot follow regroups so.
    pub fn regroup(&mut self, now: u64) -> Result<Prepared, GroupError> {
        if self.state.course == Course::Out {
            return Err(GroupError::Out);
        }
        let me = self.idle()?;
        if self.state.set.fresh != Some(me) {
            return Err(GroupError::NoRegroup);
        }
        let remove = self.state.owed();
        let rekey = self.rekey(&remove)?;
        let (rekey, r2) = rekey.map(|(split, r2)| (split.kit.clone(), r2)).unzip();
        let effect = Effect {
            add: None,
            remove,
            rekey,
        };
        self.hold(effect, r2, |mls, rows| mls.restart(now / 1000, rows))
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
            floor: self.state.floor,
            time: self.state.time,
            confirmed: self.state.confirmed,
            offset: self.state.offset,
            policy: self.state.policy,
            devices: self.state.devices.clone(),
            set: self.state.set.clone(),
            recovery: self.state.recovery,
            assigned: self.state.assigned,
            archive: self.archive.shareable(),
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
        let attached = Attached {
            welcome: own.welcome.clone(),
            r2: own.r2,
        };
        self.mls.write(rows(&self.state, None))?;
        Ok(Event::Evidence {
            index,
            message,
            signature,
            attached,
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

impl DeviceGroup {
    /// The group's rows, as [`rows`] gives them, with the log's chains read
    /// since the last write and the alarms raised since, kept until they
    /// are acknowledged.
    pub(crate) fn writes(&mut self, archive: bool) -> Result<vos_mls::Writes, GroupError> {
        let mut writes = rows(&self.state, archive.then_some(&self.archive));
        for (next, chain) in self.chains.drain(..) {
            writes.insert(chain_key(next), Some(chain.to_vec()));
        }
        let raised = std::mem::take(&mut self.raised);
        if let Some((key, value)) = raised_row(&self.store, &raised)? {
            writes.insert(key, value);
        }
        Ok(writes)
    }

    /// Note the alarms among `events`: the next write keeps them.
    pub(crate) fn note(&mut self, events: &[Event]) {
        for event in events {
            if let Event::Alarm(alarm) = event
                && !self.raised.contains(alarm)
            {
                self.raised.push(*alarm);
            }
        }
    }

    /// The alarms raised and not yet acknowledged, the oldest first: every
    /// one the device group and sealed sync raised, each kept from the batch
    /// that consumed its evidence, so a pass killed or stopped after it
    /// loses none.
    pub fn alarms(&self) -> Result<Vec<Alarm>, GroupError> {
        Ok(stored_alarms(&self.store)?)
    }

    /// Keep `alarms`, raised outside the device group's own batches.
    pub fn keep(&mut self, alarms: &[Alarm]) -> Result<(), GroupError> {
        if let Some(row) = raised_row(&self.store, alarms)? {
            self.store.write_group_rows(vec![row])?;
        }
        Ok(())
    }

    /// The chrome showed `alarms` to the user: they are kept no more. One
    /// raised again after is kept again.
    pub fn acknowledge(&mut self, alarms: &[Alarm]) -> Result<(), GroupError> {
        let mut kept = stored_alarms(&self.store)?;
        let before = kept.len();
        kept.retain(|alarm| !alarms.contains(alarm));
        if kept.len() != before {
            self.store
                .write_group_rows(vec![(ALARMS.to_vec(), Some(kept.encode()))])?;
        }
        Ok(())
    }
}

/// A row written, or deleted when its value is none.
type Write = (Vec<u8>, Option<Vec<u8>>);

/// The alarms kept, the oldest first.
fn stored_alarms(store: &Store) -> Result<Vec<Alarm>, StoreError> {
    Ok(store
        .group_row(ALARMS)?
        .and_then(|bytes| Vec::<Alarm>::decode_exact(&bytes))
        .unwrap_or_default())
}

/// The row of the alarms kept with `raised` added, each once, a clock
/// alarm in the place of the one kept (its skew the latest); none when
/// `raised` adds nothing. Past [`KEPT_ALARMS`], the oldest of a kind of
/// which a later one is kept goes first, so a flood of one kind evicts no
/// other.
pub(crate) fn raised_row(store: &Store, raised: &[Alarm]) -> Result<Option<Write>, StoreError> {
    let mut kept = stored_alarms(store)?;
    let before = kept.clone();
    for alarm in raised {
        if !kept.contains(alarm) {
            if matches!(alarm, Alarm::Clock { .. }) {
                kept.retain(|kept| !matches!(kept, Alarm::Clock { .. }));
            }
            kept.push(*alarm);
        }
    }
    if kept == before {
        return Ok(None);
    }
    while kept.len() > KEPT_ALARMS {
        let kind = |alarm: &Alarm| core::mem::discriminant(alarm);
        let oldest = (0..kept.len())
            .find(|at| {
                kept[at + 1..]
                    .iter()
                    .any(|later| kind(later) == kind(&kept[*at]))
            })
            .unwrap_or(0);
        kept.remove(oldest);
    }
    Ok(Some((ALARMS.to_vec(), Some(kept.encode()))))
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
