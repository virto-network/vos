// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The facility's own interface's types (`IVosPersonal`, under the AAR's
//! `src/main/aidl`, package `team.virto.vos.personal`), each declared once
//! with s4's `parcel!` or `byte_enum!`: the background jobs' passes and what
//! they raise, and the personal space's flows' requests and results (VOS's
//! `light-node.md` §3.3–§3.9): the claim at a home with its recovery kit,
//! pairing, the memberships a pairing leaves, the device set, a restore
//! from the kit and a move home. [`REGISTRY`] lists them, held to the AIDL
//! in the tests; under the `jni` feature each is its parcelable.

use s4_credential_contract::{MAX_ONIONS, Onion, byte_enum, parcel};
use zeroize::Zeroizing;

use crate::{Code, Refusal};

/// The interface's AIDL source root, beside this crate.
pub const AIDL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/aar/src/main/aidl");

/// A device's label, at most this many bytes (`vos_wire::books::LABEL_BYTES`).
pub const MAX_LABEL: usize = 64;

byte_enum! {
    package "team.virto.vos.personal";
    /// What a local notification raises: a pending operation of the device
    /// set, a pending restore, this device's removal, or an alarm.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub enum Pending {
        /// A device added by a delayed admin.
        #[default]
        Add = 0 as ADD,
        Remove = 1 as REMOVE,
        /// A device's admin key replaced.
        Replace = 2 as REPLACE,
        /// The recovery kit replaced.
        Rotate = 3 as ROTATE,
        /// Every other device removed and a new group started by one alone.
        Regroup = 4 as REGROUP,
        /// Every device removed by the kit's restore, signed by the kit.
        Restore = 5 as RESTORE,
        /// A restore is pending: this device answered it with `alive`.
        Restoring = 6 as RESTORING,
        /// This device is out of its group.
        Removed = 7 as REMOVED,
        /// The personal space raised an alarm: its `alarm` names it.
        Alarm = 9 as ALARM,
        /// This device cannot follow its group: removed from another
        /// device, it pairs again; or it regroups.
        Stuck = 10 as STUCK,
        /// A commit is owed for the removals that matured: until one
        /// carries them, the removed devices hold the epoch's keys.
        Commit = 11 as COMMIT,
        /// A commit is owed that re-seals the kit under a new `R`: the
        /// agent's verdict left it sealed under one a removed device holds.
        Reseal = 12 as RESEAL,
    }
}

byte_enum! {
    package "team.virto.vos.personal";
    /// What a recovery kit is.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub enum KitKind {
        /// 24 words, shown once in the chrome and written down.
        #[default]
        Phrase = 1 as PHRASE,
        /// A FIDO2 security key's `hmac-secret`.
        SecurityKey = 2 as SECURITY_KEY,
    }
}

byte_enum! {
    package "team.virto.vos.personal";
    /// Where a flow is, said to the screen that runs it (`IVosWatcher.stage`):
    /// a kind alone, no secret and no value in it, in no order a flow keeps.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Stage {
        /// Reaching the home: its open claim, an agent from its pool.
        Reaching = 1 as REACHING,
        /// A proof made: the device's at its home, a sign-in's or a payment's.
        Proving = 2 as PROVING,
        /// The recovery kit written at the agent.
        WritingKit = 3 as WRITING_KIT,
        /// The device set's log followed: the group joined or caught up.
        Joining = 4 as JOINING,
        /// A pairing's code read by the new device.
        Scanned = 5 as SCANNED,
        /// A pairing's check confirmed.
        Checked = 6 as CHECKED,
        /// The device set's keys handed over to the new device.
        HandingOver = 7 as HANDING_OVER,
        /// The new device's add waiting for the opener's admin key.
        Approving = 8 as APPROVING,
        /// A proved call sent to its space.
        Sending = 9 as SENDING,
    }
}

byte_enum! {
    package "team.virto.vos.personal";
    /// What a membership waits for on this device.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Owed {
        /// Another device of the person to enroll there, by this device's
        /// owner proof: deferrable.
        Enroll = 0 as ENROLL,
        /// This device's own confirmation there, once its leaf is in.
        Confirm = 1 as CONFIRM,
    }
}

byte_enum! {
    package "team.virto.vos.personal";
    /// Where the device's personal space is (`PersonalStatus.phase`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub enum Phase {
        /// None: a claim, a pairing or a restore makes one.
        #[default]
        None = 0 as NONE,
        /// A claim under way: claiming at its home again finishes it.
        Claiming = 1 as CLAIMING,
        /// Paired, not yet added by the opener's confirmed commit.
        Joining = 2 as JOINING,
        /// The device holds the group and follows it.
        Held = 3 as HELD,
        /// A restore opened, maturing at `matures`; then `restored`.
        Restoring = 4 as RESTORING,
        /// Out of its group: it pairs again, or claims.
        Removed = 5 as REMOVED,
        /// It cannot follow its group: it pairs again, or regroups.
        Stuck = 6 as STUCK,
        /// What the device keeps of it is not this build's: `repair` says
        /// what; the app's data cleared, it claims or pairs again.
        NeedsRepair = 7 as NEEDS_REPAIR,
    }
}

byte_enum! {
    package "team.virto.vos.personal";
    /// Tor as the process's client last found it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub enum Tor {
        /// Bootstrapping, or not yet asked.
        #[default]
        Starting = 0 as STARTING,
        Connected = 1 as CONNECTED,
        /// Its bootstrap failed: `torWhy` names why.
        Blocked = 2 as BLOCKED,
    }
}

byte_enum! {
    package "team.virto.vos.personal";
    /// What alarm a notice raises (`vos_light::group::Alarm`'s kinds).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub enum Alarm {
        /// Not an alarm.
        #[default]
        None = 0 as NONE,
        /// The log does not chain from what this device saw: a rollback or
        /// a fork.
        Log = 1 as LOG,
        /// A vote does not verify against the candidate: two logs shown.
        SplitLog = 2 as SPLIT_LOG,
        /// The log names this device absent though it called.
        NamedAbsent = 3 as NAMED_ABSENT,
        /// This device refused a candidate commit.
        Refused = 4 as REFUSED,
        /// This device cannot follow a confirmed epoch: `remedy` says what.
        CannotFollow = 5 as CANNOT_FOLLOW,
        /// The agent's verdict is not this device's count.
        Verdict = 6 as VERDICT,
        /// A maturity the evidence does not support.
        Unsigned = 7 as UNSIGNED,
        /// The device's clock and the agent's disagree by over an hour.
        Clock = 8 as CLOCK,
        /// The kit signed an operation: veto it, or rotate the kit.
        Kit = 9 as KIT,
        /// The log's head went back: a rollback.
        Rollback = 10 as ROLLBACK,
        /// A writer's view of the log is not this device's: a split log.
        View = 11 as VIEW,
        /// An admin call of this device's the agent took is gone.
        Dropped = 12 as DROPPED,
        /// A scope served short of what a writer read: a partition.
        Partition = 13 as PARTITION,
        /// An envelope withheld.
        Withheld = 14 as WITHHELD,
        /// An envelope sealed under an older epoch.
        Stale = 15 as STALE,
        /// A node by no device of the set.
        Author = 16 as AUTHOR,
        /// This device's own envelope gone: pushed again.
        Deleted = 17 as DELETED,
        /// Log entries withheld.
        Unserved = 18 as UNSERVED,
        /// An entry lowering the policy's delays: refused.
        Policy = 19 as POLICY,
    }
}

byte_enum! {
    package "team.virto.vos.personal";
    /// What a device that cannot follow its group does.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub enum Remedy {
        #[default]
        None = 0 as NONE,
        /// Pair again from another live device.
        RePair = 1 as RE_PAIR,
        /// No other live device to pair from: regroup.
        Regroup = 2 as REGROUP,
    }
}

byte_enum! {
    package "team.virto.vos.personal";
    /// Why a personal operation was refused (`vos_light::space::Error`'s
    /// kinds, and the facility's own): what the screen acts on, the words
    /// its own (`Words.why`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub enum Why {
        /// Not refused: the operation answered.
        #[default]
        None = 0 as NONE,
        /// The device holds no personal space.
        NoSpace = 1 as NO_SPACE,
        /// It holds one already.
        AlreadyHeld = 2 as ALREADY_HELD,
        /// It holds a personal space's keys already: restore or pair.
        HoldsKeys = 3 as HOLDS_KEYS,
        /// A claim at another home is under way: claim there to finish it.
        ClaimElsewhere = 4 as CLAIM_ELSEWHERE,
        /// The personal space is at that home already.
        AtThatHome = 5 as AT_THAT_HOME,
        /// No restore is open.
        NoRestore = 6 as NO_RESTORE,
        /// No pairing is under way.
        NoPairing = 7 as NO_PAIRING,
        /// What the device keeps is not this build's: `detail` says what.
        NeedsRepair = 8 as NEEDS_REPAIR,
        /// The user declined.
        Declined = 9 as DECLINED,
        /// The flow was cancelled.
        Cancelled = 10 as CANCELLED,
        /// Not a recovery kit.
        NotAKit = 11 as NOT_A_KIT,
        /// The kit is not this agent's.
        WrongKit = 12 as WRONG_KIT,
        NotAPairingCode = 13 as NOT_A_PAIRING_CODE,
        NotAnOffer = 14 as NOT_AN_OFFER,
        /// The offer is stale: ask for a new one.
        StaleOffer = 15 as STALE_OFFER,
        /// This device's own key.
        OwnKey = 16 as OWN_KEY,
        /// The device is not in the set.
        NotInSet = 17 as NOT_IN_SET,
        /// The secret source failed.
        Source = 18 as SOURCE,
        /// The home serves no claim.
        NoOpenClaim = 19 as NO_OPEN_CLAIM,
        /// The home refused to open a claim.
        OpenClaimRefused = 20 as OPEN_CLAIM_REFUSED,
        /// The home has no agent to give.
        NoAgentToGive = 21 as NO_AGENT_TO_GIVE,
        /// No agent holds this kit at that home.
        NoAgentForKit = 22 as NO_AGENT_FOR_KIT,
        /// This device holds an agent at that home already.
        HoldsAgentThere = 23 as HOLDS_AGENT_THERE,
        /// The agent is not known at that home.
        UnknownAgent = 24 as UNKNOWN_AGENT,
        /// The space's tree is not read yet: try again.
        NoLeaf = 25 as NO_LEAF,
        /// The home refused: `detail` names its error.
        HomeRefused = 26 as HOME_REFUSED,
        /// The proof's format was retired: update the app.
        Update = 27 as UPDATE,
        /// The proof was rejected.
        Rejected = 28 as REJECTED,
        /// The personal agent refused: `detail` names its error.
        AgentRefused = 29 as AGENT_REFUSED,
        /// The agent has not taken it yet: try again.
        NotTakenYet = 30 as NOT_TAKEN_YET,
        /// Not yet joined: try again.
        NotJoinedYet = 31 as NOT_JOINED_YET,
        /// The commit awaits the devices' votes.
        AwaitsVotes = 32 as AWAITS_VOTES,
        /// The commit is undecided.
        Undecided = 33 as UNDECIDED,
        /// The commit was void: try again.
        CommitVoid = 34 as COMMIT_VOID,
        /// Another device committed meanwhile: try again.
        CommittedMeanwhile = 35 as COMMITTED_MEANWHILE,
        /// The pairing's slot expired.
        SlotExpired = 36 as SLOT_EXPIRED,
        /// The device is in that space already.
        InSetAlready = 37 as IN_SET_ALREADY,
        /// The agent's set does not hold this device.
        NotInAgentSet = 38 as NOT_IN_AGENT_SET,
        /// `device` regrouped: this device pairs again.
        Regrouped = 39 as REGROUPED,
        /// The device is not enrolled in that space.
        NotEnrolled = 40 as NOT_ENROLLED,
        /// Nothing is owed there.
        NothingOwed = 41 as NOTHING_OWED,
        /// The enrollment was spent.
        Spent = 42 as SPENT,
        /// The registrar refused: `detail` names its error.
        RegistrarRefused = 43 as REGISTRAR_REFUSED,
        /// The space was not reached over Tor: `detail` says how.
        Unreachable = 44 as UNREACHABLE,
        /// The proof failed.
        Prove = 45 as PROVE,
        /// The device's store failed.
        Store = 46 as STORE,
        /// The request's arguments are not the operation's.
        Arguments = 47 as ARGUMENTS,
        /// The facility failed: `detail` says how.
        Failed = 48 as FAILED,
        /// This device is a delayed admin: a pairing is opened on a strong
        /// admin's device.
        DelayedAdmin = 49 as DELAYED_ADMIN,
        /// The other device declined the pairing.
        PairingDeclined = 50 as PAIRING_DECLINED,
    }
}

parcel! {
    package "team.virto.vos.personal";
    registry REGISTRY with [Pending, KitKind, Stage, Owed, Phase, Tor, Alarm, Remedy, Why];

    /// One pass of the facility's sync, a background job's: of the
    /// enrollments kept, how many synced and how many failed (the personal
    /// space's pass counted with them); the bytes its connections read and
    /// wrote, its length; what the chrome raises; each of the person's
    /// devices' last call at the personal agent; and why each failure
    /// failed, `; ` between them, as the log says (no secret in it).
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Synced {
        pub enrollments: u32 => int,
        pub synced: u32 => int,
        pub failed: u32 => int,
        pub bytes_down: u64 => long,
        pub bytes_up: u64 => long,
        pub millis: u64 => long,
        pub notices: Vec<Notice> => Notice[],
        pub seen: Vec<Seen> => Seen[],
        pub failures: String => String,
    }

    /// One thing the chrome raises: an operation's at its log `index`,
    /// taken at `at` (the agent's time, 0 when this pass did not read it)
    /// and maturing at `matures` unless vetoed, signed by device `by` or by
    /// the kit (`by_kit`), `contested` by another (a contest this device
    /// cannot resolve when `cannot_resolve`, the kit alone when `kit_only`); a
    /// restore stopped, at its log `index`; or an alarm of its kind,
    /// `index` its place (its log index, epoch, position or skew) and its
    /// `remedy`. `fresh` when no pass raised it before, so its
    /// notification alerts.
    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    pub struct Notice {
        pub pending: Pending => enum Pending,
        pub index: u64 => long,
        pub at: u64 => long,
        pub matures: u64 => long,
        pub fresh: bool => boolean,
        pub by: u32 => long,
        pub by_kit: bool => boolean,
        pub contested: bool => boolean,
        pub alarm: Alarm => enum Alarm,
        pub remedy: Remedy => enum Remedy,
        pub cannot_resolve: bool => boolean,
        pub kit_only: bool => boolean,
    }

    /// The personal space's state, read without a request: its phase (a
    /// restore's maturing at `matures`), its home (none: zeros, no onion),
    /// agent and this device's id, Tor's state and why it is blocked, the
    /// memberships owed, the notices standing, what needs repair, the kind
    /// of kit a kit's call here enters (a restore's, else the device
    /// set's; known when `kit_known`), and why the last personal pass
    /// failed (empty when it did not), standing until a pass changes it.
    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    pub struct PersonalStatus {
        pub phase: Phase => enum Phase,
        pub matures: u64 => long,
        pub home: Home => Home,
        pub agent: u32 => long,
        pub device: u32 => long,
        pub tor: Tor => enum Tor,
        pub tor_why: String => String,
        pub owed: u32 => int,
        pub standing: Vec<Notice> => Notice[],
        pub repair: String => String,
        pub kit: KitKind => enum KitKind,
        pub kit_known: bool => boolean,
        pub failed: String => String,
    }

    /// Why a personal operation was refused: its kind, a device it names
    /// (the one that regrouped), and its detail (an agent's error's name, a
    /// store's failure): no prose the screen shows as it is.
    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    pub struct Refused {
        pub why: Why => enum Why,
        pub device: u32 => long,
        pub detail: String => String,
    }

    /// A device of the person's set, and its last call the personal agent
    /// took (its time, 0 before any).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Seen {
        pub device: u32 => long,
        pub at: u64 => long,
    }

    /// A home as the device reaches it: its space and handle, the agent
    /// holding its credential actor and `Homes`, with the identity calls to
    /// it are signed for, their instances, and its onions (a home is
    /// onion-only).
    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    pub struct Home {
        pub space: [u8; 32] => byte[],
        pub handle: [u8; 32] => byte[],
        pub agent: u32 => long,
        pub identity: [u8; 32] => byte[],
        pub homes: u32 => long,
        pub credentials: u32 => long,
        pub onions: Vec<Onion> => Onion[],
    }

    /// `claim`: a personal agent at `home` with a kit of `kit`, this device
    /// named `label` to the user's other devices. `restore` and `move_home`
    /// take the same: the home, the new kit.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Claim as ClaimRequest {
        pub home: Home => Home,
        pub kit: KitKind => enum KitKind,
        pub label: String => String,
    }

    /// A claim's (or a restore's, or a move's) result: the agent, and this
    /// device's id in its set.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Claimed {
        pub agent: u32 => long,
        pub device: u32 => long,
    }

    /// `pair_offer`'s result: the QR code's bytes, which hold the pairing's
    /// one-time code, and when the slot expires (the agent's time).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PairCode {
        pub code: Zeroizing<Vec<u8>> => byte[],
        pub expires_ms: u64 => long,
    }

    /// A pairing's result: the new device's id, and the memberships it is
    /// to be enrolled in (the opener's) or to confirm (the joiner's).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Paired {
        pub device: u32 => long,
        pub memberships: u32 => int,
    }

    /// A membership in a space other than the home: the space, its handle,
    /// its credential actor's agent and instance, and what is owed there.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Membership {
        pub space: [u8; 32] => byte[],
        pub handle: [u8; 32] => byte[],
        pub agent: u32 => long,
        pub instance: u32 => long,
        pub owed: Owed => enum Owed,
    }

    /// A device of the set, as the chrome lists it: its id and label,
    /// whether its admin is strong, its standing
    /// (`vos_wire::personal::Standing`'s index), its last call the agent
    /// took (0 before any), whether a removal of it matured, and whether it
    /// is this device.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Device {
        pub id: u32 => long,
        pub label: String => String,
        pub strong: bool => boolean,
        pub standing: u8 => byte,
        pub seen: u64 => long,
        pub removed: bool => boolean,
        pub me: bool => boolean,
    }

    /// The device set as the kit reads it at its home: each device, and
    /// the operations open, as the chrome raises them.
    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    pub struct KitView {
        pub devices: Vec<Device> => Device[],
        pub operations: Vec<Notice> => Notice[],
    }

    /// An admin call the agent took: its log index and batch time.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Posted {
        pub index: u64 => long,
        pub at: u64 => long,
    }
}

fn bad(message: impl Into<String>) -> Refusal {
    Refusal::new(Code::Arguments, message)
}

impl Home {
    /// Within its bounds: 1 to [`MAX_ONIONS`] distinct onions.
    pub fn check(self) -> Result<Self, Refusal> {
        if self.onions.is_empty() || self.onions.len() > MAX_ONIONS {
            return Err(bad(format!(
                "a home pins 1 to {MAX_ONIONS} onions: it is onion-only"
            )));
        }
        if self
            .onions
            .iter()
            .enumerate()
            .any(|(at, onion)| self.onions[..at].iter().any(|seen| seen.key == onion.key))
        {
            return Err(bad("an onion is pinned twice"));
        }
        Ok(self)
    }
}

/// A device's label: 1 to [`MAX_LABEL`] ASCII letters, digits, spaces,
/// `.`, `_` or `-`, so the other devices' chrome shows it as it reads.
pub fn label(text: &str) -> Result<(), Refusal> {
    let plain = text
        .split(' ')
        .all(|word| s4_credential_contract::plain(word, false));
    if (1..=MAX_LABEL).contains(&text.len()) && plain {
        Ok(())
    } else {
        Err(bad(format!(
            "a device's label is 1 to {MAX_LABEL} ASCII letters, digits, spaces, `.`, `_` or `-`"
        )))
    }
}

impl Claim {
    pub fn check(self) -> Result<Self, Refusal> {
        label(&self.label)?;
        Ok(Self {
            home: self.home.check()?,
            ..self
        })
    }
}

impl From<Refusal> for Refused {
    /// A refusal of the facility's own (an argument, a store, a personal
    /// space that does not open): its code's kind, its message the detail.
    fn from(refusal: Refusal) -> Self {
        let why = match refusal.code {
            Code::Arguments => Why::Arguments,
            Code::Declined => Why::Declined,
            Code::NotEnrolled => Why::NotEnrolled,
            Code::NoPath | Code::Unclaimed => Why::NoLeaf,
            Code::Source => Why::Source,
            Code::Api => Why::Unreachable,
            Code::Prove => Why::Prove,
            Code::Store if refusal.message.contains("needs repair") => Why::NeedsRepair,
            Code::Store => Why::Store,
            _ => Why::Failed,
        };
        Refused {
            why,
            detail: refusal.message,
            ..Refused::default()
        }
    }
}

impl From<Refused> for Refusal {
    /// A personal refusal where the facility's own operations answer s4's:
    /// its kind's code, its detail the message.
    fn from(refused: Refused) -> Self {
        let code = match refused.why {
            Why::NoSpace | Why::NotEnrolled => Code::NotEnrolled,
            Why::Declined | Why::Cancelled => Code::Declined,
            Why::Arguments => Code::Arguments,
            Why::Source => Code::Source,
            Why::NoLeaf => Code::NoPath,
            Why::Unreachable | Why::NotTakenYet | Why::NotJoinedYet => Code::Api,
            Why::Prove => Code::Prove,
            Why::Store | Why::NeedsRepair => Code::Store,
            Why::Failed | Why::UnknownAgent => Code::Failed,
            _ => Code::Refused,
        };
        // In need of repair, as `From<Refusal>` reads it back.
        let message = match (refused.why, refused.detail.is_empty()) {
            (Why::NeedsRepair, _) => format!("needs repair: {}", refused.detail),
            (why, true) => format!("{why:?}"),
            (why, false) => format!("{why:?}: {}", refused.detail),
        };
        Refusal::new(code, message)
    }
}

#[cfg(feature = "jni")]
impl Refused {
    /// Write `self` into an operation's `out Refused` parcelable `object`.
    pub fn write_into(
        &self,
        env: &mut jni::Env<'_>,
        object: &jni::objects::JObject<'_>,
    ) -> s4_credential_contract::java::Result<()> {
        use s4_credential_contract::java::{Fields, Value as _};
        let fields = Fields::of::<Self>(object)?;
        self.why.write(&fields, env, "why")?;
        self.device.write(&fields, env, "device")?;
        self.detail.write(&fields, env, "detail")
    }
}

#[cfg(feature = "jni")]
impl From<s4_credential_contract::java::JavaError> for Refused {
    fn from(error: s4_credential_contract::java::JavaError) -> Self {
        Refused::from(Refusal::from(error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A personal refusal in need of repair stays so across s4's refusal.
    #[test]
    fn a_refusal_in_need_of_repair_crosses_s4s_and_back() {
        let refused = Refused {
            why: Why::NeedsRepair,
            detail: "its store: layout 6".into(),
            ..Refused::default()
        };
        let back = Refused::from(Refusal::from(refused));
        assert_eq!(back.why, Why::NeedsRepair);
        assert!(back.detail.contains("its store: layout 6"));
    }
}
