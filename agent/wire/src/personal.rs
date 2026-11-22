//! The personal agent's wire types (`light-node.md` §3.3–§3.7): what its
//! actor, `Personal`, takes and answers, and what devices compute to talk
//! to it.
//!
//! The agent orders the device group's commits, stores the user's sealed
//! envelopes and holds an inbox. It never holds a key that opens the
//! user's data and verifies no signature: admin calls are client calls
//! signed by a device's admin key and verified at ingress, and their
//! evidence, stored beside each, is checked by devices alone.
//!
//! **Its layout is append-only across versions:** an install replaces the
//! program and touches no table, so a row's key and encoding never change;
//! a later version adds tables. Every type here stored in a row keeps its
//! encoding for good.

use alloc::vec::Vec;

use scale::{Decode, Encode};

/// `Personal`'s instance in every personal agent.
pub const PERSONAL: vos_abi::ids::InstanceId = vos_abi::ids::InstanceId(5);

/// `Personal`'s handlers.
pub mod method {
    methods! {
        CLAIM = "claim";
        RENEW = "renew";
        REMOVE = "remove";
        ADD = "add";
        REPLACE = "replace";
        ROTATE = "rotate";
        REGROUP = "regroup";
        RESTORE = "restore";
        VETO = "veto";
        COSIGN = "cosign";
        RESOLVE = "resolve";
        COMMIT = "commit";
        EVIDENCE = "evidence";
        CONFIRM = "confirm";
        NACK = "nack";
        ALIVE = "alive";
        PUSH = "push";
        ACKNOWLEDGE = "acknowledge";
        OPEN_SLOT = "open_slot";
        CLOSE_SLOT = "close_slot";
        PUT = "put";
        WAKE = "wake";
        VERSION = "version";
        OVERVIEW = "overview";
        DEVICES = "devices";
        OPERATIONS = "operations";
        OPERATION = "operation";
        RECOVERY = "recovery";
        LOG = "log";
        SINCE = "since";
        INBOX = "inbox";
        ACKNOWLEDGEMENTS = "acknowledgements";
        FRONTIER = "frontier";
    }

    /// The device-set calls, which name their place in the log first.
    pub const PLACED: [vos_abi::ids::MethodId; 9] = [
        ADD, REMOVE, REPLACE, ROTATE, REGROUP, RESTORE, VETO, COSIGN, RESOLVE,
    ];
}

/// A sealed scope's id: opaque to the agent, `BLAKE2b-128("vos/personal/
/// scope-id" ‖ naming ‖ name)` on devices.
pub type Scope = [u8; 16];

/// A device's number in the agent's device set, in the order of their
/// adds.
pub type DeviceId = u32;

/// The recovery scope: the epoch's scope keys sealed under `R` at every
/// confirmed epoch, the one scope the kit reads.
pub const RECOVERY: Scope = [0; 16];

/// An envelope's largest size, under the request and value caps.
pub const MAX_ENVELOPE: usize = 60 << 10;

/// The bytes of a `since` or `log` answer's items, beyond which it stops:
/// at least one item, whatever its size, and the answer under the reply
/// cap.
pub const ANSWER_BYTES: usize = 60 << 10;

/// One day of batch time, which the daily quotas count by.
pub const DAY_MS: u64 = 24 * HOUR_MS;

pub const HOUR_MS: u64 = 60 * 60 * 1000;

/// An envelope's clear header: its scope, its epoch, its nonce and its
/// padded length's class, the AAD of its sealed body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub scope: Scope,
    pub epoch: u64,
    pub nonce: [u8; 24],
    pub len_class: u8,
}

impl Header {
    /// The header's bytes: the scope, the epoch little-endian, the nonce
    /// and the class.
    pub const BYTES: usize = 16 + 8 + 24 + 1;

    /// The header an envelope starts with; `None` for one shorter than a
    /// header.
    pub fn parse(envelope: &[u8]) -> Option<Self> {
        let header = envelope.get(..Self::BYTES)?;
        Some(Self {
            scope: header[..16].try_into().ok()?,
            epoch: u64::from_le_bytes(header[16..24].try_into().ok()?),
            nonce: header[24..48].try_into().ok()?,
            len_class: header[48],
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0; Self::BYTES];
        bytes[..16].copy_from_slice(&self.scope);
        bytes[16..24].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[24..48].copy_from_slice(&self.nonce);
        bytes[48] = self.len_class;
        bytes
    }
}

fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    vos_pvm_precompiles::blake2b_hash::<32>(domain, parts)
}

/// An envelope's id, its hash: the agent deduplicates pushes by it.
pub fn envelope_id(envelope: &[u8]) -> [u8; 32] {
    hash(b"vos/personal/envelope", &[envelope])
}

/// A commit's id, its handshake's hash: a commit is a candidate once.
pub fn commit_id(handshake: &[u8]) -> [u8; 32] {
    hash(b"vos/personal/commit", &[handshake])
}

/// The hash a commit names its Welcome by, which its evidence carries.
pub fn welcome_hash(welcome: &[u8]) -> [u8; 32] {
    hash(b"vos/personal/welcome", &[welcome])
}

/// The hash a kit rotation or a restore names its `R2` by: `R2` rides in
/// the operation's evidence, kept by the agent and logged nowhere, so no
/// read serves it.
pub fn r2_hash(r2: &[u8; 32]) -> [u8; 32] {
    hash(b"vos/personal/r2", &[r2])
}

/// The hash a kit's `R` is named by in the admin call that drew it: a
/// device takes an `R` another device's archive brings only when it is the
/// one named.
pub fn r_hash(r: &[u8; 32]) -> [u8; 32] {
    hash(b"vos/personal/r", &[r])
}

/// The index `Homes` keeps a personal agent under for a recovery kit's
/// entry whose signing key is `signing`: `BLAKE2b-256("vos/personal/kit/
/// index" ‖ signing)`, so a kit finds its agent with no agent id.
pub fn kit_index(signing: &[u8; 32]) -> [u8; 32] {
    hash(b"vos/personal/kit/index", &[signing])
}

/// The control log's chain after the entry at `index`: over the chain
/// before it and the entry's time and body, encoded. The chain before the
/// first entry is zeros.
pub fn chain(before: &[u8; 32], index: u64, at: u64, body: &Body) -> [u8; 32] {
    hash(
        b"vos/personal/log",
        &[
            before,
            &index.to_le_bytes(),
            &at.to_le_bytes(),
            &body.encode(),
        ],
    )
}

/// What a device's sync key signs for its vote on `epoch`'s candidate,
/// logged at `candidate` with the log's chain `chain` through it, at the
/// agent whose identity is `identity`: the vote travels with the
/// signature, stored as data, and every device checks it. The candidate's
/// index binds it to that candidate alone, an epoch's number being free
/// again after a void; the chain binds it to the log the voter read, the
/// confirming set in it, so a vote shown to a device whose log differs
/// does not verify there.
pub fn vote_message(
    identity: &[u8; 32],
    epoch: u64,
    candidate: u64,
    chain: &[u8; 32],
    vote: &Vote,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"vos/personal/vote");
    message.extend_from_slice(identity);
    epoch.encode_to(&mut message);
    candidate.encode_to(&mut message);
    message.extend_from_slice(chain);
    vote.encode_to(&mut message);
    message
}

/// How a device's admin key is held (`light-node.md` §3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum AdminClass {
    /// A TEE key behind a strong biometric: its adds are immediate.
    #[codec(index = 0)]
    Strong = 0,
    /// Any other: every operation it signs waits.
    #[codec(index = 1)]
    Delayed = 1,
}

/// What the admin key's attestation showed, recorded and shown, never
/// changing the class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Attestation {
    /// A TEE key requiring a strong biometric.
    pub hardware: bool,
    /// The verified-boot state was verified.
    pub verified_boot: bool,
}

/// A device's keys and what the agent records of it at its add.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct NewDevice {
    /// Its client key at the agent: syncing, votes, evidence.
    pub sync: [u8; 32],
    /// Its admin calls' client key: device-set operations and commits.
    pub admin: [u8; 32],
    pub class: AdminClass,
    pub attestation: Attestation,
    /// Its nullifier in the home's "home" scope, for the yearly re-proof.
    pub nullifier: [u8; 32],
    /// Its label, sealed to the device group.
    pub label: Vec<u8>,
}

/// A device in the set.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Device {
    pub keys: NewDevice,
    /// The batch time of its add.
    pub added: u64,
    /// When its probation ends: its add's time for the claiming device, a
    /// restore's maturity for the device it adds. A probation frozen under
    /// a removal moves it on by the time frozen.
    pub active_from: u64,
    pub status: Status,
}

/// An admin key replacing a device's, and what its attestation showed.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct NewAdmin {
    pub key: [u8; 32],
    pub class: AdminClass,
    pub attestation: Attestation,
}

/// A device's lasting status, as the agent wrote it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Status {
    #[codec(index = 0)]
    Live,
    /// Its removal matured at `at`: it has no voice.
    #[codec(index = 1)]
    Removed { at: u64 },
    /// The candidate that added it was void, at `at`.
    #[codec(index = 2)]
    Dropped { at: u64 },
}

/// A device's standing at a batch time: its status, and its probation
/// and the removals pending against it read against the time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Standing {
    /// It may sync and vote, not sign operations, veto or commit.
    #[codec(index = 0)]
    Probation,
    #[codec(index = 1)]
    Active,
    #[codec(index = 2)]
    Removed,
    #[codec(index = 3)]
    Dropped,
}

/// A device's matured removal, until a confirmed commit carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Removal {
    /// The log index of the operation that removed it: a removal, a
    /// regroup or a restore.
    pub index: u64,
    /// When it matured.
    pub at: u64,
    /// The epoch whose confirmed commit carried it out of the group.
    pub committed: Option<u64>,
}

/// A device as the agent answers it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct DeviceView {
    pub id: DeviceId,
    pub device: Device,
    pub standing: Standing,
    /// Active for the policy's seasoning: one of two for the two-device
    /// rules, when its admin is strong.
    pub seasoned: bool,
    pub removal: Option<Removal>,
    /// The batch time of the device's last call the agent took: 0 before
    /// any. A device's last sync, as the chrome shows it.
    pub seen: u64,
}

/// What a key admitted at ingress is to the agent: the rows of its
/// `admitted` table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Holder {
    #[codec(index = 0)]
    Sync(DeviceId),
    #[codec(index = 1)]
    Admin(DeviceId),
    /// A recovery kit's signing key, by its entry.
    #[codec(index = 2)]
    Kit(u8),
    /// An open pairing slot's key, for that slot alone.
    #[codec(index = 3)]
    Slot(Scope),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum KitKind {
    #[codec(index = 0)]
    Phrase = 0,
    #[codec(index = 1)]
    SecurityKey = 1,
}

/// A recovery entry: a kit's keys and `R1` sealed to it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct KitEntry {
    pub kind: KitKind,
    /// Its ed25519 key: its client key at the agent.
    pub signing: [u8; 32],
    /// Its X25519 key, which `R1` is sealed to.
    pub sealing: [u8; 32],
    pub sealed_r1: Vec<u8>,
}

/// The recovery kit a claim brings: its entries and `R2`, which the agent
/// keeps and serves to no read.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Kit {
    pub entries: Vec<KitEntry>,
    pub r2: [u8; 32],
}

/// A kit an operation or a commit brings: its entries, its `R2` by
/// [`r2_hash`], `R2` itself in the call's evidence, and its `R` by
/// [`r_hash`], which the devices check.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct NewKit {
    pub entries: Vec<KitEntry>,
    pub r2_hash: [u8; 32],
    pub r_hash: [u8; 32],
}

/// The recovery kit as the agent answers it: its entries, each with `R1`
/// sealed to it; the recovery scope's position its envelopes start after,
/// those sealed under an earlier `R` before it; and, for the device a
/// matured restore added alone, the previous `R2` and the entries the
/// restore replaced, whose `R1` it opens with the kit it used.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct RecoveryView {
    pub entries: Vec<KitEntry>,
    pub from: u64,
    pub released: Option<[u8; 32]>,
    pub previous: Vec<KitEntry>,
}

/// Who signed an operation: a device's admin key, or a recovery entry's
/// signing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum Signer {
    #[codec(index = 0)]
    Device(DeviceId),
    #[codec(index = 1)]
    Kit(u8),
}

/// A device-set operation (`light-node.md` §3.5): each pending for its
/// signer's delay, then matured unless vetoed or contested.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Op {
    /// An add as an operation, a delayed admin's: a commit carries it once
    /// matured.
    #[codec(index = 0)]
    Add(NewDevice),
    #[codec(index = 1)]
    Remove(DeviceId),
    /// A device's admin key replaced, its seasoning kept: the wait is the
    /// new key's probation.
    #[codec(index = 2)]
    Replace { device: DeviceId, admin: NewAdmin },
    /// The kit replaced: its entries, `R2`, and the recovery envelopes
    /// re-sealed after it.
    #[codec(index = 3)]
    Rotate(NewKit),
    /// The devices named removed and a new group started with the rest:
    /// a device's restore, needing no `R2`.
    #[codec(index = 4)]
    Regroup(Vec<DeviceId>),
    /// Every device removed, `device` added alone and active, `kit`
    /// replacing the kit, and the previous `R2` released to `device`.
    #[codec(index = 5)]
    Restore { device: NewDevice, kit: NewKit },
}

/// Why an operation was cancelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum Cancel {
    /// A device vetoed the kit's operation.
    #[codec(index = 0)]
    Veto = 0,
    /// A device's `alive` while a restore was pending.
    #[codec(index = 1)]
    Alive = 1,
    /// Its signer's removal matured: it has no voice.
    #[codec(index = 2)]
    Signer = 2,
    /// The device it acts on left the set first.
    #[codec(index = 3)]
    Moot = 3,
    /// A resolution dropped it.
    #[codec(index = 4)]
    Resolved = 4,
    /// Its kit was replaced, by a rotation or a restore.
    #[codec(index = 5)]
    Retired = 5,
    /// It fell due without its evidence, or without the evidence
    /// carrying its `R2`.
    #[codec(index = 6)]
    Unevidenced = 6,
    /// A key it brings was admitted by its maturity.
    #[codec(index = 7)]
    KeyTaken = 7,
    /// A leave whose signer was the set's last live device by then.
    #[codec(index = 8)]
    Alone = 8,
}

/// Where an operation is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum OpState {
    /// Waiting for its maturity.
    #[codec(index = 0)]
    Pending,
    /// Vetoed by a device with a voice, or one of two removals aimed at
    /// each other: it does not mature until resolved.
    #[codec(index = 1)]
    Contested,
    #[codec(index = 2)]
    Matured { at: u64 },
    /// An add a confirmed commit carried.
    #[codec(index = 3)]
    Carried { epoch: u64 },
    #[codec(index = 4)]
    Cancelled { at: u64, why: Cancel },
}

/// A device-set operation as the agent holds it, by its log index.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Operation {
    pub by: Signer,
    pub op: Op,
    /// Its batch time, and when it matures uncontested.
    pub at: u64,
    pub matures: u64,
    pub state: OpState,
}

/// The space's policy for its personal agents: delays, windows and
/// quotas, minutes on a test home.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Policy {
    /// A device's operation's wait before it matures: a removal, a
    /// delayed admin's add, a kit rotation, a regroup.
    pub operation_delay_ms: u64,
    /// The kit's operations' wait.
    pub kit_delay_ms: u64,
    /// A paired device's probation, and a replaced admin key's.
    pub probation_ms: u64,
    /// How long a device is active before it is seasoned.
    pub seasoning_ms: u64,
    /// The confirming set's window of calls, and a candidate's wait for
    /// its set.
    pub confirm_window_ms: u64,
    /// The lease a re-proof renews.
    pub lease_ms: u64,
    /// The bytes held before the first re-proof, and after it.
    pub bytes_new: u64,
    pub bytes_full: u64,
    /// Envelopes and commits a day.
    pub envelopes_per_day: u32,
    pub commits_per_day: u32,
    /// The kit's operations a day: a veto or an `alive` that cancels one
    /// frees its place, so this bounds how often a leaked kit tries.
    pub kit_operations_per_day: u32,
    /// The inbox's items, each item's bytes and its longest life.
    pub inbox_items: u32,
    pub inbox_item_bytes: u32,
    pub inbox_ttl_ms: u64,
    /// A pairing slot's life.
    pub slot_ttl_ms: u64,
}

impl Policy {
    /// A home's policy unless it sets another.
    pub const DEFAULT: Self = Self {
        operation_delay_ms: 72 * HOUR_MS,
        kit_delay_ms: 7 * DAY_MS,
        probation_ms: 72 * HOUR_MS,
        seasoning_ms: 7 * DAY_MS,
        confirm_window_ms: 72 * HOUR_MS,
        lease_ms: 395 * DAY_MS,
        bytes_new: 8 << 20,
        bytes_full: 64 << 20,
        envelopes_per_day: 8192,
        commits_per_day: 32,
        kit_operations_per_day: 4,
        inbox_items: 64,
        inbox_item_bytes: 16 << 10,
        inbox_ttl_ms: 7 * DAY_MS,
        slot_ttl_ms: 10 * 60 * 1000,
    };

    /// This policy configured over `held`, the one the claim set: its
    /// quotas, lease and inbox, and each delay and window of the device
    /// set's rules no lower than `held`'s. Only the claim sets those: a
    /// later configuration is the operators' word, and a lowered delay
    /// would let an operation mature before its window to veto it.
    pub fn over(self, held: &Policy) -> Policy {
        Policy {
            operation_delay_ms: self.operation_delay_ms.max(held.operation_delay_ms),
            kit_delay_ms: self.kit_delay_ms.max(held.kit_delay_ms),
            probation_ms: self.probation_ms.max(held.probation_ms),
            seasoning_ms: self.seasoning_ms.max(held.seasoning_ms),
            confirm_window_ms: self.confirm_window_ms.max(held.confirm_window_ms),
            ..self
        }
    }
}

/// A commit's declared effect: the device it adds, inline for a strong
/// admin's add or a matured add operation's, the devices whose matured
/// removals it carries, and the kit re-sealed under a new `R`, which every
/// commit carrying a removal brings: the kit's entries as they are, each
/// with a new `R1` sealed to it, its `R2` in the evidence. An update with
/// none of these.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Effect {
    pub add: Option<NewDevice>,
    pub remove: Vec<DeviceId>,
    pub rekey: Option<NewKit>,
}

/// What an admin call's evidence carries beside it, bound by hash in the
/// call: a commit's Welcome, and the `R2` of a kit rotation, a restore or
/// a commit that re-seals the kit. `R2` is kept apart and logged nowhere;
/// its `Debug` shows only whether it is there.
#[derive(Clone, Default, PartialEq, Eq, Encode, Decode)]
pub struct Attached {
    pub welcome: Option<Vec<u8>>,
    pub r2: Option<[u8; 32]>,
}

impl core::fmt::Debug for Attached {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Attached")
            .field("welcome", &self.welcome.as_ref().map(Vec::len))
            .field("r2", &self.r2.is_some())
            .finish()
    }
}

/// Where a device-set admin call takes its place in the control log, the
/// first of its arguments: the log's head as the device read it when it
/// signed the call, the next index and the chain through the entry before
/// it. The agent and every device take the call only at a place at or
/// after the entry following the last admin call before it and at or
/// before the call's own entry, its chain the one the log had there
/// ([`PersonalError::StaleHead`]; the agent compares it before anything
/// the call's batch settles): a call logged again on a log a route forks
/// names a place before the call it copies, which every device that read
/// that call has passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Place {
    pub next: u64,
    pub chain: [u8; 32],
}

impl Place {
    /// The place `arguments` name first, and the arguments after it.
    pub fn split(arguments: &[u8]) -> Option<(Place, &[u8])> {
        let (place, used) = Place::decode(arguments).ok()?;
        Some((place, &arguments[used..]))
    }

    /// `arguments` placed here.
    pub fn arguments(&self, arguments: &[u8]) -> Vec<u8> {
        let mut placed = self.encode();
        placed.extend_from_slice(arguments);
        placed
    }
}

/// An admin call as the agent recorded it: its origin, its method and its
/// arguments, which its evidence's message must carry byte for byte.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AdminCall {
    pub origin: [u8; 32],
    pub method: u32,
    pub arguments: Vec<u8>,
}

/// A device's vote on a candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Vote {
    /// `h = BLAKE2b-256("vos/personal/confirm" ‖ agent ‖ epoch ‖
    /// epoch_authenticator)`.
    #[codec(index = 0)]
    Confirm([u8; 32]),
    #[codec(index = 1)]
    Nack,
}

/// Why a candidate was void.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum Void {
    /// A device of its set nacked it.
    #[codec(index = 0)]
    Nack = 0,
    /// Its set confirmed two different `h`.
    #[codec(index = 1)]
    Split = 1,
    /// Its window passed without its set complete.
    #[codec(index = 2)]
    Timeout = 2,
    /// A regroup or a restore started a new group.
    #[codec(index = 3)]
    Regroup = 3,
}

/// The agent's advisory verdict on a candidate: each device checks the
/// signed votes itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Verdict {
    #[codec(index = 0)]
    Confirmed([u8; 32]),
    #[codec(index = 1)]
    Void(Void),
}

/// A control-log entry's body.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Body {
    /// The claim's device, the first, and the kit's signing keys.
    #[codec(index = 0)]
    Assigned {
        device: DeviceId,
        kit: Vec<[u8; 32]>,
    },
    #[codec(index = 1)]
    Configured(Policy),
    /// A re-proof: the lease runs to `until`.
    #[codec(index = 2)]
    Renewed { until: u64 },
    /// An admin call making a device-set operation, maturing at
    /// `matures` unless vetoed or contested.
    #[codec(index = 3)]
    Operation {
        call: AdminCall,
        by: Signer,
        op: Op,
        matures: u64,
    },
    /// A removal matured: the device has no voice.
    #[codec(index = 4)]
    Matured { device: DeviceId },
    /// An admin call, `epoch`'s candidate, the device it added, and its
    /// confirming set.
    #[codec(index = 5)]
    Candidate {
        call: AdminCall,
        by: DeviceId,
        epoch: u64,
        added: Option<DeviceId>,
        set: Vec<DeviceId>,
    },
    /// A vote, signed by the device's sync key over [`vote_message`].
    #[codec(index = 6)]
    Vote {
        device: DeviceId,
        epoch: u64,
        /// The candidate's log index.
        candidate: u64,
        vote: Vote,
        signature: [u8; 64],
    },
    #[codec(index = 7)]
    Verdict { epoch: u64, verdict: Verdict },
    /// The admin call at `index`, as signed: the exact call message and
    /// its signature, and a commit's Welcome.
    #[codec(index = 8)]
    Evidence {
        index: u64,
        message: Vec<u8>,
        signature: [u8; 64],
        welcome: Option<Vec<u8>>,
    },
    /// A device's liveness.
    #[codec(index = 9)]
    Alive { device: DeviceId },
    /// An admin call vetoing the operation at `op`.
    #[codec(index = 10)]
    Veto {
        call: AdminCall,
        by: DeviceId,
        op: u64,
    },
    /// An admin call adding the second signature that makes the operation
    /// at `op` immediate.
    #[codec(index = 11)]
    Cosign {
        call: AdminCall,
        by: Signer,
        op: u64,
    },
    /// An admin call resolving the contest of the operation at `op`:
    /// `upheld`, it matures and its rival is dropped; else the reverse.
    #[codec(index = 12)]
    Resolve {
        call: AdminCall,
        by: Signer,
        op: u64,
        upheld: bool,
    },
    /// The operation at `op` reached `state`.
    #[codec(index = 13)]
    Settled { op: u64, state: OpState },
}

/// A control-log entry: its batch time, its body and the chain through it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Entry {
    pub at: u64,
    pub body: Body,
    pub chain: [u8; 32],
}

/// A stored envelope as `since` answers it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Envelope {
    pub position: u64,
    pub id: [u8; 32],
    pub bytes: Vec<u8>,
}

impl Envelope {
    /// Its encoding's bytes beyond the envelope's.
    pub const FRAMING: usize = 8 + 32 + 4;
}

/// Whom an inbox item is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Recipient {
    /// The user's devices, sealed to the device group.
    #[codec(index = 0)]
    Devices,
    /// A pairing slot's two parties, sealed to the slot's key.
    #[codec(index = 1)]
    Slot(Scope),
}

/// Who wrote an inbox item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Author {
    #[codec(index = 0)]
    Device(DeviceId),
    #[codec(index = 1)]
    Slot(Scope),
}

/// An inbox item, keyed by its expiry and its writer's id.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Item {
    pub to: Recipient,
    pub from: Author,
    pub bytes: Vec<u8>,
}

/// An inbox item as a read answers it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct InboxItem {
    pub expires: u64,
    pub id: [u8; 16],
    pub item: Item,
}

/// A device's acknowledgement of a checkpoint at a scope's position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Acknowledged {
    pub position: u64,
    pub device: DeviceId,
    pub hash: [u8; 32],
}

/// The pending candidate.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Pending {
    pub epoch: u64,
    /// Its log entry.
    pub index: u64,
    pub set: Vec<DeviceId>,
}

/// The agent at a batch time.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Overview {
    pub at: u64,
    pub confirmed: u64,
    pub candidate: Option<Pending>,
    /// The log's next index and its chain so far.
    pub next: u64,
    pub chain: [u8; 32],
    pub lease_until: u64,
    pub lapsed: bool,
}

/// A commit taken as its epoch's candidate.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Candidacy {
    pub at: u64,
    pub index: u64,
    pub set: Vec<DeviceId>,
}

/// An envelope stored, or found stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Pushed {
    pub at: u64,
    pub position: u64,
    pub id: [u8; 32],
}

/// A call the log recorded at `index`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Recorded {
    pub at: u64,
    pub index: u64,
}

/// A `wake`: its batch time, and whether it settled everything due.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Woken {
    pub at: u64,
    pub settled: bool,
}

/// A vote recorded, and the verdict it reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Voted {
    pub at: u64,
    pub index: u64,
    pub verdict: Option<Verdict>,
}

/// Why `Personal` refused a call or a read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum PersonalError {
    /// No claim assigned the agent yet.
    #[codec(index = 0)]
    Unassigned,
    #[codec(index = 1)]
    Assigned,
    /// The caller is not a key the agent admits for this.
    #[codec(index = 2)]
    NotAdmitted,
    /// An admin call from a device's sync key.
    #[codec(index = 3)]
    SyncKey,
    /// The device is in probation: it signs no operation or commit but its
    /// own removal.
    #[codec(index = 4)]
    Probation,
    /// The device's removal matured: it has no voice.
    #[codec(index = 5)]
    Removed,
    /// A delayed admin's add waits as an operation first.
    #[codec(index = 6)]
    Delayed,
    /// A candidate is pending.
    #[codec(index = 7)]
    EpochTaken,
    /// Not the confirmed epoch plus one.
    #[codec(index = 8)]
    EpochGap { confirmed: u64 },
    /// The commit was a candidate already.
    #[codec(index = 9)]
    Decided,
    /// A matured removal the commit does not carry.
    #[codec(index = 10)]
    MissingRemoval(DeviceId),
    /// A device the commit removes whose removal has not matured, or was
    /// carried already.
    #[codec(index = 11)]
    NotMatured(DeviceId),
    #[codec(index = 12)]
    UnknownDevice,
    /// A key the agent admits already.
    #[codec(index = 13)]
    KeyTaken,
    /// The lease lapsed: in its grace, no push and no commit but one
    /// carrying a removal.
    #[codec(index = 14)]
    Lapsed,
    /// Not the confirmed epoch: seal again under it.
    #[codec(index = 15)]
    StaleEpoch { confirmed: u64 },
    #[codec(index = 16)]
    TooLarge,
    #[codec(index = 17)]
    Malformed,
    #[codec(index = 18)]
    Quota,
    /// No candidate is pending for the epoch.
    #[codec(index = 19)]
    NoCandidate,
    /// The device is not in the candidate's confirming set.
    #[codec(index = 20)]
    NotConfirming,
    #[codec(index = 21)]
    Voted,
    /// The log entry is not an admin call.
    #[codec(index = 22)]
    NotAdminCall,
    /// The admin call is another device's.
    #[codec(index = 23)]
    NotYours,
    /// Its evidence is stored.
    #[codec(index = 24)]
    Evidenced,
    /// The evidence's message is not the call recorded.
    #[codec(index = 25)]
    Mismatch,
    /// What rides beside the evidence, a commit's Welcome or an `R2`, is
    /// missing, unexpected, or not the one named.
    #[codec(index = 26)]
    Welcome,
    /// An operation of the kind is open already, for the device or for
    /// the agent.
    #[codec(index = 27)]
    Pending,
    /// No envelope at that position.
    #[codec(index = 28)]
    NoPosition,
    #[codec(index = 29)]
    InboxFull,
    /// An expiry past now and within the item's longest life.
    #[codec(index = 30)]
    Expiry,
    /// The slot id is open, its opener holds another, or the agent holds
    /// as many as it opens at once.
    #[codec(index = 31)]
    SlotTaken,
    #[codec(index = 32)]
    NoSlot,
    /// Another item holds the inbox key.
    #[codec(index = 33)]
    ItemTaken,
    /// No open operation at the index.
    #[codec(index = 34)]
    NoOperation,
    /// The device vetoed the operation already.
    #[codec(index = 35)]
    Vetoed,
    /// The kit vetoes nothing.
    #[codec(index = 36)]
    KitVeto,
    /// Not a seasoned device whose admin is strong, as the two-device
    /// rules and a replacement need.
    #[codec(index = 37)]
    Unseasoned,
    /// A device the operation acts on signs no resolution or second
    /// signature of it, nor the operation itself but its own removal.
    #[codec(index = 38)]
    Targeted,
    /// The signer holds as many open operations as it may.
    #[codec(index = 39)]
    Operations,
    /// The operation is not contested.
    #[codec(index = 40)]
    Uncontested,
    /// The operation is not one this signer makes, or signs a second time.
    #[codec(index = 41)]
    NotSigner,
    /// Operations fell due that `wake` settles first.
    #[codec(index = 42)]
    Settling,
    /// The set holds as many live devices as it may.
    #[codec(index = 43)]
    Devices,
    /// A commit carrying a removal without the kit re-sealed, or a kit
    /// re-sealed that is not the agent's kit.
    #[codec(index = 44)]
    Rekey,
    /// The operation a cosign or a resolution would make mature has no
    /// evidence yet (or no `R2` where it carries one): post it first.
    #[codec(index = 45)]
    Unevidenced,
    /// The place the admin call names is behind the last admin call
    /// logged, past the head, or a chain the log never had: read the log
    /// again and sign the call at its head.
    #[codec(index = 46)]
    StaleHead,
    /// A device's own removal, its leave: it matures with its evidence, no
    /// one vetoes or cosigns it, and it is never contested.
    #[codec(index = 47)]
    Leaving,
    /// The set's last live device leaves nothing to commit its leave: a
    /// restore with the kit replaces it instead. A device whose add the
    /// pending candidate makes is not yet another live device.
    #[codec(index = 48)]
    Alone,
    /// The device's add is the pending candidate's, not yet confirmed: it
    /// signs nothing, its own leave included, until the verdict.
    #[codec(index = 49)]
    Undecided,
}
