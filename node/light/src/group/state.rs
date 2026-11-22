//! What a device group keeps of the log: the devices it knows, the calls
//! and admin calls it holds, the device set, and its state as stored.

use vos_abi::{Decode, Encode};
use vos_wire::ingress::CallMessage;
use vos_wire::personal::{
    AdminCall, AdminClass, DeviceId, Effect, KitEntry, NewDevice, Op, Place, Policy, Signer, Vote,
};

use super::Agent;
use crate::kit::KitKey;

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
        self.vetoes_any()
            && Place::split(&self.arguments).is_some_and(|(_, vetoed)| vetoed == op.encode())
    }

    pub(super) fn vetoes_any(&self) -> bool {
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
                    && Place::split(&signed.arguments)
                        .is_some_and(|(_, named)| named.starts_with(&op.encode()))
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
    /// It is out of the group: its removal, as the log it verified says.
    #[codec(index = 2)]
    Out,
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
    /// The index after the last admin call read (its start, for a device
    /// that read none): no admin call it reads later names a place before
    /// it.
    pub(crate) floor: u64,
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
    /// the log must reach ([`Alarm::Unserved`](super::Alarm::Unserved)).
    pub(crate) ahead: Option<u64>,
    /// The log index of the claim's assignment, once read: a configuration
    /// before it, or the one beside it, is the claim's and sets the
    /// policy's delays and windows; a later one lowers none of them
    /// ([`Alarm::Policy`](super::Alarm::Policy)). A paired device's is its
    /// pairing device's; a restored device starts past it.
    pub(crate) assigned: Option<u64>,
    /// This device's own leave held: the removal of it the log asserts
    /// next is its leave, and the device out by it forgets its store.
    pub(crate) leaving: bool,
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
