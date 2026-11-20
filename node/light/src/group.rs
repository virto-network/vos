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

pub mod archive;
mod follow;
mod set;

use std::collections::BTreeMap;

use vos_abi::ids::InstanceId;
use vos_abi::{Decode, Encode};
use vos_mls::{Mls, Namespace};
use vos_wire::ingress::CallMessage;
use vos_wire::personal::{
    AdminCall, AdminClass, Attached, DeviceId, DeviceView, Effect, KitEntry, NewDevice, Op, Policy,
    Scope, Signer, Status, Vote, welcome_hash,
};
use zeroize::Zeroize;

use crate::kit::{KitKey, Split};
use crate::store::{Change, Store, StoreError};

pub use archive::Archive;

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
    /// A regroup or a restore matured: a new group starts.
    Regroup,
}

/// What a device raises to its user. Kept in the store from the batch
/// that consumes its evidence until the chrome acknowledges it
/// ([`DeviceGroup::alarms`], [`DeviceGroup::acknowledge`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Alarm {
    /// The log does not chain from what this device saw at `index`: a
    /// rollback or a fork. The device reads no further.
    #[codec(index = 0)]
    Log { index: u64 },
    /// A vote by `device`, of `epoch`'s logged set, does not verify against
    /// the candidate as this device's log holds it: the devices were shown
    /// two logs (a different confirming set), or the vote is forged.
    #[codec(index = 1)]
    SplitLog { epoch: u64, device: DeviceId },
    /// The log names this device absent from `epoch`'s confirming set
    /// though it made a call within the window.
    #[codec(index = 2)]
    NamedAbsent { epoch: u64, last_call: u64 },
    /// This device refused `epoch`'s candidate by `committer`: its evidence
    /// does not verify, its effect is not the matured operations', or its
    /// handshake does not process. It nacked, if it votes.
    #[codec(index = 3)]
    Refused { epoch: u64, committer: DeviceId },
    /// `epoch` was confirmed and this device cannot follow it: it could not
    /// process `committer`'s commit, or its `h` is not the confirmed one.
    #[codec(index = 4)]
    CannotFollow {
        epoch: u64,
        committer: DeviceId,
        remedy: Remedy,
    },
    /// The agent's verdict on `epoch` is not this device's count.
    #[codec(index = 5)]
    Verdict { epoch: u64 },
    /// The log's entry at `index` asserts a maturity its evidence does not
    /// support: no verified operation, or one whose delay had not passed
    /// with no verified second signature or resolution, or vetoed. It is
    /// ignored.
    #[codec(index = 6)]
    Unsigned { index: u64 },
    /// The device's clock and the agent's batch time disagree by `skew_ms`,
    /// more than an hour: the device acts as the log says.
    #[codec(index = 7)]
    Clock { skew_ms: u64 },
    /// The kit signed the operation at `index`: every device shows it for
    /// as long as it is open, and its user vetoes it or rotates the kit.
    #[codec(index = 8)]
    Kit { index: u64 },
    /// The agent's log head, `next`, is behind what this device read of
    /// it, or diverges from it there: a rollback.
    #[codec(index = 9)]
    Rollback { next: u64 },
    /// A writer's view of the log names `index` with a chain this device's
    /// log does not have there, or an index past what the agent serves this
    /// device: a split log.
    #[codec(index = 10)]
    View { index: u64 },
    /// An admin call of this device's that the agent took at `index` is not
    /// there: dropped, or replaced.
    #[codec(index = 11)]
    Dropped { index: u64 },
    /// A writer had read `scope` to `position`, and the agent serves this
    /// device less of it: a partition.
    #[codec(index = 12)]
    Partition { scope: Scope, position: u64 },
    /// The agent's page of `scope` skips `position`, which it numbered: an
    /// envelope withheld.
    #[codec(index = 13)]
    Withheld { scope: Scope, position: u64 },
    /// The envelope at `scope`'s `position` is sealed under an epoch before
    /// one the agent took earlier there: a push it should have refused.
    #[codec(index = 14)]
    Stale { scope: Scope, position: u64 },
    /// The node at `scope`'s `position` is not by a device of the set, or by
    /// a removed device past its frontier: refused.
    #[codec(index = 15)]
    Author { scope: Scope, position: u64 },
    /// This device's own envelope at `scope`'s `position` is gone: pushed
    /// again.
    #[codec(index = 16)]
    Deleted { scope: Scope, position: u64 },
    /// The agent named its log's head at `next` and, read again, served
    /// this device less of the log: entries withheld. The writers' views
    /// and this device's admin calls past what it was served count as
    /// unreached.
    #[codec(index = 18)]
    Unserved { next: u64 },
    /// The log's entry at `index` lowers a delay or a window of the device
    /// set's policy: refused, the policy's delays and windows kept. Only
    /// the claim's configuration sets them (`light-node.md` §3.5).
    #[codec(index = 19)]
    Policy { index: u64 },
}

/// What a device that cannot follow does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum Remedy {
    /// Pair again from another live device.
    #[codec(index = 0)]
    RePair = 0,
    /// No other live device to pair from: a regroup (§3.5).
    #[codec(index = 1)]
    Regroup = 1,
}

/// The clock alarm: the device's clock `local` against the agent's batch
/// time `agent`, both in milliseconds.
pub fn clock(local: u64, agent: u64) -> Option<Alarm> {
    let skew_ms = local.abs_diff(agent);
    (skew_ms > vos_wire::personal::HOUR_MS).then_some(Alarm::Clock { skew_ms })
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

/// A device the group knows: its keys at its add, its admin key as
/// replaced and the one its leaf carries, and whether it has a voice.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct Known {
    pub(crate) keys: NewDevice,
    pub(crate) admin: [u8; 32],
    /// The admin key its leaf's credential carries: its add's, until a
    /// commit of its renews the leaf to a replaced key.
    pub(crate) leaf: [u8; 32],
    pub(crate) strong: bool,
    /// When its probation ends, by the log's time: it signs no operation
    /// or commit before.
    pub(crate) active_from: u64,
    /// What was left of its probation when a removal against it opened:
    /// frozen until no removal against it is open.
    pub(crate) frozen: Option<u64>,
    /// When its removal matured: it has no voice from then.
    pub(crate) matured: Option<u64>,
    /// A confirmed commit removed it from the group.
    pub(crate) out: bool,
    /// The log index of its last logged `alive`, the agent's word.
    pub(crate) alive: u64,
}

impl Known {
    pub(crate) fn new(keys: NewDevice, active_from: u64) -> Self {
        Self {
            admin: keys.admin,
            leaf: keys.admin,
            strong: keys.class == AdminClass::Strong,
            keys,
            active_from,
            frozen: None,
            matured: None,
            out: false,
            alive: 0,
        }
    }

    /// Its leaf's credential.
    pub(crate) fn credential(&self) -> Vec<u8> {
        [&self.keys.sync[..], &self.leaf[..]].concat()
    }

    /// The credential its next commit renews its leaf to, its admin key
    /// replaced since its leaf was made.
    pub(crate) fn renewal(&self) -> Option<Vec<u8>> {
        (self.admin != self.leaf).then(|| [&self.keys.sync[..], &self.admin[..]].concat())
    }
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

/// What a device-set admin call does. An operation carries its `Op`
/// inline: a device keeps a few open calls, encoded in its state row.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Act {
    /// An operation, maturing at `matures` unless vetoed or contested.
    #[codec(index = 0)]
    Op { op: Op, matures: u64 },
    /// A veto of the operation at the index.
    #[codec(index = 1)]
    Veto(u64),
    /// The second signature making the operation at the index immediate.
    #[codec(index = 2)]
    Cosign(u64),
    /// A resolution of the contest of the operation at `op`.
    #[codec(index = 3)]
    Resolve { op: u64, upheld: bool },
}

/// A device-set admin call the log holds at `index`, as this device
/// checked it: its signer, origin, method and arguments, its evidence, and
/// for a removal, the removal it makes one contest with.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct Call {
    pub(crate) index: u64,
    pub(crate) at: u64,
    pub(crate) by: Signer,
    pub(crate) origin: [u8; 32],
    pub(crate) method: u32,
    pub(crate) arguments: Vec<u8>,
    pub(crate) act: Act,
    pub(crate) evidence: Check,
    pub(crate) rival: Option<u64>,
    /// The replacement whose new key signed it, while its maturity waits
    /// on its evidence: the call stands or falls with it.
    pub(crate) awaits: Option<u64>,
}

/// A candidate a device that cannot follow saw, which it does not take:
/// its epoch, its time, the device it added and its logged effect, kept
/// only to follow the device set through its verdict.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct Passing {
    pub(crate) epoch: u64,
    pub(crate) at: u64,
    pub(crate) added: Option<DeviceId>,
    pub(crate) effect: Effect,
}

/// Whether the evidence supports a maturity the log asserts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub(crate) enum Support {
    /// Evidence it needs is not in the log yet.
    #[codec(index = 0)]
    Waiting = 0,
    #[codec(index = 1)]
    Held = 1,
    #[codec(index = 2)]
    Refused = 2,
}

/// A maturity the log asserts in its entry at `entry`: the operation at
/// `op` matured at `at`, removing `removes` (or, a restore, `every`
/// device), and the removals the log logged for it while its support
/// waits.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct Claim {
    pub(crate) entry: u64,
    pub(crate) op: u64,
    /// The removal it was one contest with, when the log asserted it.
    pub(crate) rival: Option<u64>,
    pub(crate) at: u64,
    pub(crate) every: bool,
    pub(crate) removes: Vec<DeviceId>,
    pub(crate) removed: Vec<DeviceId>,
    pub(crate) support: Support,
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
    /// The replacement whose new key signed it, while its maturity waits
    /// on its evidence.
    pub(crate) awaits: Option<u64>,
    pub(crate) welcome: Option<Vec<u8>>,
    /// The votes logged and verified, each device's first.
    pub(crate) votes: Vec<(DeviceId, Vote)>,
    /// This device's vote, and whether the log holds it.
    pub(crate) mine: Option<Vote>,
    pub(crate) logged: bool,
}

/// This device's own commit, from its preparation until it is decided. Its
/// `Debug` shows no `R2`.
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
pub(crate) struct Own {
    pub(crate) epoch: u64,
    pub(crate) welcome: Option<Vec<u8>>,
    /// Its call's arguments, by which the log's candidate is known as it.
    pub(crate) arguments: Vec<u8>,
    /// Its call's signed message and signature, written before the call
    /// is made.
    pub(crate) signed: Option<(Vec<u8>, [u8; 64])>,
    /// The `R2` of the kit it re-seals, for its evidence.
    pub(crate) r2: Option<[u8; 32]>,
    /// Its call's log index, once the agent took it.
    pub(crate) index: Option<u64>,
    /// The log holds its evidence.
    pub(crate) evidenced: bool,
}

impl std::fmt::Debug for Own {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Own")
            .field("epoch", &self.epoch)
            .field("index", &self.index)
            .field("evidenced", &self.evidenced)
            .finish_non_exhaustive()
    }
}

/// An admin call of this device's that the agent took at `index`: what
/// the log must hold there.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct Made {
    pub(crate) index: u64,
    pub(crate) origin: [u8; 32],
    pub(crate) method: u32,
    pub(crate) arguments: Vec<u8>,
    /// The log holds another entry there: a veto, kept to hold its
    /// operation back.
    pub(crate) dropped: bool,
}

impl Made {
    /// Whether it is a veto of the operation at `op`.
    pub(crate) fn vetoes(&self, op: u64) -> bool {
        self.vetoes_any() && self.arguments == op.encode()
    }

    fn vetoes_any(&self) -> bool {
        self.method == vos_wire::personal::method::VETO.0
    }
}

/// An admin call of this device's, signed as `message`, held before it
/// leaves: its evidence (with `r2` beside it) is posted until the log holds
/// it, from the agent's answer or, after a crash, from the call found in
/// the log (`index`).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct Sent {
    pub(crate) message: Vec<u8>,
    pub(crate) signature: [u8; 64],
    pub(crate) r2: Option<[u8; 32]>,
    pub(crate) index: Option<u64>,
}

impl Sent {
    /// Whether `call` is this one's, as the log holds it.
    pub(crate) fn is(&self, call: &AdminCall) -> bool {
        CallMessage::parse(&self.message).is_some_and(|signed| {
            signed.session.key == call.origin
                && signed.method.0 == call.method
                && signed.arguments == call.arguments
        })
    }

    /// Whether it is the operation at `op`, or a veto, cosign or
    /// resolution of it: cancelled, its evidence decides nothing more.
    pub(crate) fn about(&self, op: u64) -> bool {
        use vos_wire::personal::method::{COSIGN, RESOLVE, VETO};
        self.index == Some(op)
            || CallMessage::parse(&self.message).is_some_and(|signed| {
                [VETO, COSIGN, RESOLVE].contains(&signed.method)
                    && signed.arguments.starts_with(&op.encode())
            })
    }
}

/// Where the device is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub enum Course {
    #[codec(index = 0)]
    #[default]
    Following,
    /// It cannot follow `epoch`, committed by `committer`.
    #[codec(index = 1)]
    Stuck { epoch: u64, committer: DeviceId },
    /// It is out of the group.
    #[codec(index = 2)]
    Out,
    /// The agent turns its key away, though its add was confirmed: its
    /// removal settled while it was off, or the home fails it. Nothing is
    /// dropped: a pass the agent serves again finds it following.
    #[codec(index = 3)]
    TurnedAway,
}

/// What a device keeps of the device set's operations.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub(crate) struct Set {
    /// The kit's keys, by entry: as the claim made them, or a verified
    /// rotation or restore brought them.
    pub(crate) kit: Vec<KitKey>,
    /// The admin calls of the operations open, and theirs.
    pub(crate) operations: Vec<Call>,
    pub(crate) claims: Vec<Claim>,
    /// The operations closed, their calls dropped once no claim waits.
    pub(crate) closed: Vec<u64>,
    /// The matured removals no confirmed commit carried yet.
    pub(crate) owed: Vec<DeviceId>,
    /// The matured adds no confirmed commit carried yet.
    pub(crate) adds: Vec<NewDevice>,
    /// The regrouper whose new group a matured regroup waits for.
    pub(crate) fresh: Option<DeviceId>,
}

/// The `R` the log made the kit's last: the entry that did, the hash its
/// admin call named it by, and whether the kit signed that call, so no
/// device drew it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct Named {
    pub(crate) since: u64,
    pub(crate) hash: [u8; 32],
    pub(crate) by_kit: bool,
}

/// What the device keeps of the log: the agent, itself, its place in the
/// log, the devices and the open operations it verified, the pending
/// candidate and its own commit, and the `R` the log names.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct State {
    pub(crate) agent: Agent,
    pub(crate) me: NewDevice,
    /// Its number in the device set, once its add is confirmed.
    pub(crate) id: Option<DeviceId>,
    /// The next log index to read, and the chain through the one before.
    pub(crate) next: u64,
    pub(crate) chain: [u8; 32],
    /// The latest batch time the log showed, which no entry after goes
    /// back on.
    pub(crate) time: u64,
    /// The batch times of this device's calls within the confirming
    /// window, the latest last.
    pub(crate) calls: Vec<u64>,
    pub(crate) confirmed: u64,
    /// The confirmed epoch less the MLS group's epoch: a new group's
    /// epochs count on from the agent's.
    pub(crate) offset: u64,
    pub(crate) policy: Policy,
    pub(crate) devices: Vec<(DeviceId, Known)>,
    pub(crate) set: Set,
    pub(crate) pending: Option<Pending>,
    pub(crate) passing: Option<Passing>,
    pub(crate) own: Option<Own>,
    /// This device's last decision: an epoch, and whether it confirmed it.
    pub(crate) decided: Option<(u64, bool)>,
    pub(crate) course: Course,
    pub(crate) recovery: Option<Named>,
    /// The epoch this device confirmed whose commit re-sealed the kit, and
    /// its `R`'s hash, until the agent's verdict makes it the kit's.
    pub(crate) rekeyed: Option<(u64, [u8; 32])>,
    /// The admin calls of this device's the log has yet to show.
    pub(crate) made: Vec<Made>,
    /// The admin calls of this device's whose evidence the log has yet to
    /// show.
    pub(crate) sent: Vec<Sent>,
    /// The agent's verdict on the epoch whose commit re-sealed the kit
    /// (`rekeyed`) did not confirm it: the `R` is unheld until a commit
    /// re-seals the kit again, which the device asks its user for.
    pub(crate) reseal: bool,
    /// Writers' views past the cursor, checked as the device reads on.
    pub(crate) views: Vec<(u64, [u8; 32])>,
    /// A head the agent named past the cursor, which the next reading of
    /// the log must reach ([`Alarm::Unserved`]).
    pub(crate) ahead: Option<u64>,
    /// The log index of the claim's assignment, once read: a configuration
    /// before it, or the one beside it, is the claim's and sets the
    /// policy's delays and windows; a later one lowers none of them
    /// ([`Alarm::Policy`]). A paired device's is its pairing device's; a
    /// restored device starts past it.
    pub(crate) assigned: Option<u64>,
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
            .is_some_and(|known| known.matured.is_none() && !known.out)
    }

    /// A device with a voice active for the policy's seasoning at `at`.
    pub(crate) fn seasoned(&self, device: DeviceId, at: u64) -> bool {
        self.may_sign(device, at)
            && self.known(device).is_some_and(|known| {
                known.active_from.saturating_add(self.policy.seasoning_ms) <= at
            })
    }

    /// The device-set admin call the log holds at `index`, while its
    /// operation is open.
    pub(crate) fn call_at(&self, index: u64) -> Option<&Call> {
        self.set.operations.iter().find(|call| call.index == index)
    }

    /// A device with a voice past its probation at `at`: it may sign an
    /// operation or a commit.
    pub(crate) fn may_sign(&self, device: DeviceId, at: u64) -> bool {
        self.voiced(device)
            && self
                .known(device)
                .is_some_and(|known| at >= known.active_from)
    }

    /// The matured removals no confirmed commit carried yet: what the next
    /// commit carries.
    pub(crate) fn owed(&self) -> Vec<DeviceId> {
        let mut owed = self.set.owed.clone();
        owed.sort_unstable();
        owed
    }

    /// Whether `entries` are the kit's keys, in order.
    pub(crate) fn kit_is(&self, entries: &[KitEntry]) -> bool {
        entries
            .iter()
            .map(KitKey::of)
            .eq(self.set.kit.iter().copied())
    }
}

/// What a device that pairs another hands it over the pairing channel:
/// the agent, the device group's devices and the device set's operations
/// as the pairing device verified them, its place in the log, and the key
/// archive.
#[derive(Clone, Debug, Encode, Decode)]
pub struct Pairing {
    agent: Agent,
    next: u64,
    chain: [u8; 32],
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

/// A device's leaf credential at its add: its sync key and its admin key.
pub fn credential(device: &NewDevice) -> Vec<u8> {
    [&device.sync[..], &device.admin[..]].concat()
}

/// A restore's split of `keys`, the kit it carries, at `agent`: its `R`
/// held in `store`'s archive until the restore matures and
/// [`DeviceGroup::restore`] makes it the kit's. Only for a store with no
/// device group.
pub fn restoring(store: &Store, keys: &[KitKey], agent: &Agent) -> Result<Split, GroupError> {
    restoring_with(store, keys, agent, |_| Vec::new())
}

/// [`restoring`], the rows `rows` makes of the split written in the same
/// batch: what the restore makes the device's beside it.
pub fn restoring_with(
    store: &Store,
    keys: &[KitKey],
    agent: &Agent,
    rows: impl FnOnce(&Split) -> Vec<Change>,
) -> Result<Split, GroupError> {
    if store.group_row(STATE)?.is_some() {
        return Err(GroupError::Grouped);
    }
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
        if store.group_row(STATE)?.is_some() {
            return Err(GroupError::Grouped);
        }
        let mut mls = Mls::open(mls_namespace(store), &credential(me), BTreeMap::new())?;
        Ok(mls.key_package(now / 1000, BTreeMap::new())?)
    }

    /// The paired device's group, from `pairing`: it follows the log from
    /// where the pairing device read it, and joins with the Welcome of the
    /// commit that adds it. Its store's archive becomes the pairing's; a
    /// store whose naming secret named a scope already is refused.
    pub fn join(store: &Store, me: NewDevice, pairing: Pairing) -> Result<Self, GroupError> {
        Self::join_with(store, me, pairing, Vec::new())
    }

    /// [`DeviceGroup::join`], `rows` of the group keyspace written in the
    /// batch that makes the group: what the pairing makes the device's
    /// beside it.
    pub fn join_with(
        store: &Store,
        me: NewDevice,
        pairing: Pairing,
        rows: Vec<Change>,
    ) -> Result<Self, GroupError> {
        if store.group_row(STATE)?.is_some() {
            return Err(GroupError::Grouped);
        }
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
        if store.group_row(STATE)?.is_some() {
            return Err(GroupError::Grouped);
        }
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
    /// is held no more.
    pub fn unsent(&mut self, message: &[u8]) -> Result<(), GroupError> {
        let before = self.state.sent.len();
        self.state.sent.retain(|sent| sent.message != message);
        if self.state.sent.len() < before {
            self.mls.write(rows(&self.state, None))?;
        }
        Ok(())
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

    /// Whether the agent turns this device's sync key away, as `admitted`
    /// says: once it was added and while it follows, a key the agent
    /// admits no more is one whose removal matured and was settled before
    /// the device read it (a removal by the kit or by another device while
    /// it was off, or a restore), the log no longer served to it; the
    /// operators could say as much of any device, as they could deny it
    /// service. Nothing is dropped, and a key admitted again follows on:
    /// whether the course changed.
    pub fn turned_away(&mut self, away: bool) -> Result<bool, GroupError> {
        let course = match (self.state.course, away) {
            (Course::Following, true) if self.state.id.is_some() => Course::TurnedAway,
            (Course::TurnedAway, false) => Course::Following,
            _ => return Ok(false),
        };
        self.state.course = course;
        self.mls.write(rows(&self.state, None))?;
        Ok(true)
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
            Course::Out | Course::TurnedAway => return Err(GroupError::Out),
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
