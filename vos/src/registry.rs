//! Space-registry protocol — the wire types, constants, and canonical
//! signing-byte encodings shared by the `space-registry` PVM actor
//! (verifier), the `vosx` CLI (signer/reader), and the daemon's
//! read-only ingress author binding.
//!
//! The actor re-exports these definitions, keeping one source of truth for
//! consensus-critical byte layouts without creating a crate dependency cycle.
//!
//! Everything here is `no_std` + `alloc` only — the row types must
//! compile for the actor's `service`/`wasm` builds. The verifier-side
//! `verify_op_sig` (ed25519) deliberately STAYS in the actor so its
//! `ed25519-dalek` dependency never reaches `vos`; it consumes
//! [`ed25519_pubkey_from_peer_id`] from here.

use crate::service::{ActorId, AgentId, InstallationId};
use alloc::string::String;
use alloc::vec::Vec;

// ── Clean-break protocol identity ────────────────────────────────

/// Wire/state protocol generation for the typed registry cutover.
///
/// Version 2 is deliberately not wire-compatible with the former
/// `ProgramRow { name, hash, crdt }` catalog. The schema hash commits to
/// the row families and mutation semantics, while the version makes operator
/// diagnostics human-readable.
pub const REGISTRY_SCHEMA_VERSION: u32 = 2;

/// Canonical semantic schema preimage. Keep the human-readable contract in
/// executable bytes so changing a wire/state rule cannot leave a doc-only
/// digest recipe behind.
pub const REGISTRY_SCHEMA_PREIMAGE: &[u8] = b"vos.space-registry.schema/v2;versioned-genesis-root-wire;space-bound-registry-mutation-auth;authenticated-register-remote;typed-program-kind;service-agent-row;system-actor-row;publication-cas-burn-losers-exact-retry;installation-tombstones-burn-structural-losers;installation-revision-cas;distinct-read-verbs;fail-closed-schema-gates;retained-program-blob-authorization;canonical-slugs;shared-instance-namespace;exact-space-anchor;canonical-auth-peer-and-role-shapes;lossless-u16-prefix-queries;host-lifecycle-required-system-and-service-upgrade;service-install-bootstrap";

/// BLAKE2b-256 of [`REGISTRY_SCHEMA_PREIMAGE`].
pub const REGISTRY_SCHEMA_HASH: [u8; 32] = [
    0x88, 0x45, 0xdb, 0x30, 0xda, 0x48, 0x54, 0xbb, 0x6d, 0xbf, 0x1d, 0x0b, 0xaf, 0x87, 0x0e, 0x37,
    0x22, 0x78, 0xaa, 0x63, 0x5e, 0xa2, 0xf9, 0x23, 0x85, 0xb2, 0x63, 0x8a, 0x6b, 0xae, 0xae, 0xaf,
];

/// Exact registry protocol descriptor returned by [`RegistryRef::protocol`].
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct RegistryProtocol {
    pub version: u32,
    pub schema_hash: [u8; 32],
}

impl RegistryProtocol {
    pub const CURRENT: Self = Self {
        version: REGISTRY_SCHEMA_VERSION,
        schema_hash: REGISTRY_SCHEMA_HASH,
    };

    /// Fail-closed response used when a new actor opens state whose genesis
    /// root predates the v2 schema envelope.
    pub const UNSUPPORTED: Self = Self {
        version: 0,
        schema_hash: [0; 32],
    };

    pub fn is_current(self) -> bool {
        self.version == REGISTRY_SCHEMA_VERSION && self.schema_hash == REGISTRY_SCHEMA_HASH
    }
}

/// Return whether `name` is the canonical identifier form shared by registry
/// programs, service instances, Local system actors, and extension/remote
/// instance mappings.
///
/// A registry slug is 1–63 ASCII bytes, begins and ends with a lowercase
/// letter or decimal digit, and contains only lowercase letters, decimal
/// digits, or `-` in between. This byte-level definition rejects Unicode and
/// alternate spellings at every signer/verifier boundary.
pub fn is_canonical_registry_slug(name: &str) -> bool {
    let bytes = name.as_bytes();
    if !(1..=63).contains(&bytes.len()) {
        return false;
    }
    let endpoint = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    endpoint(bytes[0])
        && endpoint(bytes[bytes.len() - 1])
        && bytes.iter().all(|byte| endpoint(*byte) || *byte == b'-')
}

// ── Programs ──────────────────────────────────────────────────────

/// Immutable execution class of a catalogued package.
///
/// The class is archived as an enum and selected by distinct publish verbs;
/// it is never inferred from metadata or a boolean supplied to an install.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub enum ProgramKind {
    /// A conventional service actor. `crdt` is the immutable signed
    /// replication capability formerly carried as an untyped row field.
    Service { crdt: bool },
    /// An actor package admitted only to the Local system Agent Host.
    AgentActor,
}

impl ProgramKind {
    pub const fn service_crdt(&self) -> Option<bool> {
        match self {
            Self::Service { crdt } => Some(*crdt),
            Self::AgentActor => None,
        }
    }

    pub const fn is_agent_actor(&self) -> bool {
        matches!(self, Self::AgentActor)
    }
}

/// Unique identity of one successful movement of a named catalog tag.
/// It supplies the generation component of the compare-and-swap contract,
/// preventing an A -> B -> A hash cycle from reviving an old signed update.
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[rkyv(crate = rkyv)]
#[repr(transparent)]
pub struct PublicationId([u8; 32]);

impl PublicationId {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for PublicationId {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<PublicationId> for [u8; 32] {
    fn from(value: PublicationId) -> Self {
        value.0
    }
}

/// The exact current generation of a catalog name, used by signed CAS ops.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct ProgramTag {
    pub publication_id: PublicationId,
    pub hash: [u8; 32],
}

/// One strongly-discriminated row in the program catalog.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct ProgramRow {
    pub name: String,
    pub hash: [u8; 32],
    pub publication_id: PublicationId,
    pub kind: ProgramKind,
}

impl ProgramRow {
    pub const fn tag(&self) -> ProgramTag {
        ProgramTag {
            publication_id: self.publication_id,
            hash: self.hash,
        }
    }
}

/// Typed point-lookup response. Unlike the legacy tagged `Option<ProgramRow>`
/// wire, this response carries the exact protocol identity as well as the
/// discriminated row.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct ProgramLookup {
    pub protocol: RegistryProtocol,
    pub row: Option<ProgramRow>,
}

/// Typed authorization decision for serving one immutable program blob.
/// Once a content hash has been published it remains authorized so durable
/// installed state, replay inputs, and proofs can recover that exact program
/// after the mutable catalog name moves elsewhere.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct ProgramBlobAuthorization {
    pub protocol: RegistryProtocol,
    pub authorized: bool,
}

/// One page of [`RegistryRef::programs`]. The catalog is returned in
/// name order and every scanned row is emitted (no
/// filtering), so — unlike [`AuthGrantPage`] — the cursor is just the
/// last row's name; `more` is the terminator. Start with an empty name and
/// continue while `more` is set.
/// Use [`RegistryRef::programs_all`] to drain the whole catalog.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct ProgramPage {
    pub protocol: RegistryProtocol,
    pub rows: Vec<ProgramRow>,
    pub more: bool,
}

/// One row in the agent (installed-instance) table.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct AgentRow {
    pub instance_name: String,
    /// Opaque install-operation identity. It is burned forever when the row
    /// is first admitted and forms part of every uninstall/upgrade CAS base.
    pub installation_id: InstallationId,
    /// Monotonic generation of this live installation. Every successful
    /// upgrade increments it, so an old A -> B signature cannot replay after
    /// a later B -> A transition within the same installation.
    pub revision: u64,
    /// Pinned at install time so a program retag never silently
    /// changes the code an agent runs.
    pub program_hash: [u8; 32],
    /// Display-only references to the program catalog. Agents
    /// resolve code via `program_hash`; these are for
    /// `space agents` listings and manifest export.
    pub program_name: String,
    /// Exact catalog generation installed, in addition to the immutable hash.
    pub program_publication_id: PublicationId,
    pub replication_id: [u8; 32],
    /// 0 = Ephemeral, 1 = Local, 2 = Crdt, 3 = Raft. Mirrors
    /// `vos::node::Consistency` discriminants.
    pub consistency: u8,
    /// Opt this node-confined (`Local`/`Ephemeral`) agent OUT of the
    /// device-confinement gate so remote peers can reach it — for the
    /// network-served bridges (`clerk-bridge`, `space-bridge`). `false`
    /// (confined, device-private) by default; `Crdt`/`Raft` agents are never
    /// confined and ignore it. See
    /// [`vos::node::AgentConfig::network_reachable`].
    pub network_reachable: bool,
    /// Serving-side sync floor: who this replica's state (`FetchHeads`/
    /// `FetchNode`) is served to, and the default spawn set a node
    /// derives from its own role. `Public` serves any connected peer,
    /// `Member` and `Private` require a space read grant. `Private` also
    /// excludes enrolled nodes that do not hold that grant. See [`SyncFloor`].
    pub sync_role: SyncFloor,
}

/// One actor installed inside the Local system Agent Host. It has no service
/// replication or caller-selected runtime identity; the host derives the
/// actual `ActorId` after validating the installation receipt.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct SystemActorRow {
    pub instance_name: String,
    pub installation_id: InstallationId,
    /// Monotonic generation of this live Host installation (see
    /// [`AgentRow::revision`]).
    pub revision: u64,
    /// Actual identities returned by the trusted Local Agent Host. They are
    /// carried inside an authority-attested receipt, never accepted as loose
    /// caller-selected mutation arguments.
    pub system_agent_id: AgentId,
    pub actor_id: ActorId,
    pub program_hash: [u8; 32],
    pub program_name: String,
    pub program_publication_id: PublicationId,
    /// Hash of the complete opaque host receipt retained by the registry op.
    pub host_receipt_hash: [u8; 32],
}

/// Registry projection of a completed Local Agent Host installation. The
/// public mutation accepts this single encoded receipt and a root signature
/// over its exact bytes; it has no loose `AgentId`/`ActorId` parameters.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct SystemActorInstallReceipt {
    pub protocol: RegistryProtocol,
    pub installation_id: InstallationId,
    pub system_agent_id: AgentId,
    pub actor_id: ActorId,
    pub instance_name: String,
    pub program_name: String,
    pub program_hash: [u8; 32],
    pub program_publication_id: PublicationId,
    /// Canonical Host/guest authority evidence. The typed registry currently
    /// treats it as opaque and commits its hash; the root signature on the
    /// full encoded receipt is the recording authority boundary.
    pub host_receipt: Vec<u8>,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct AgentLookup {
    pub protocol: RegistryProtocol,
    pub row: Option<AgentRow>,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct SystemActorLookup {
    pub protocol: RegistryProtocol,
    pub row: Option<SystemActorRow>,
}

/// One page of [`RegistryRef::agents`]. The roster is returned in
/// `instance_name` order with every scanned row emitted, so the cursor is
/// the last row's `instance_name` and `more` is the terminator. Start with
/// an empty `after_name` and continue while `more` is set. Use
/// [`RegistryRef::agents_all`] to drain the whole roster.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct AgentPage {
    pub protocol: RegistryProtocol,
    pub rows: Vec<AgentRow>,
    pub more: bool,
}

/// One page of the Local system Agent Host installation table.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct SystemActorPage {
    pub protocol: RegistryProtocol,
    pub rows: Vec<SystemActorRow>,
    pub more: bool,
}

/// One page of [`RegistryRef::agent_names`] — the names-only projection of
/// [`AgentPage`], for callers (e.g. HTTP ingress rendering `/__schema`) that
/// want the instance-name list without the `AgentRow` rkyv decode. Same
/// `instance_name`-ordered cursor + `more` terminator. Use
/// [`RegistryRef::agent_names_all`] to drain.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct AgentNamePage {
    pub protocol: RegistryProtocol,
    pub names: Vec<String>,
    pub more: bool,
}

/// Serving-side sync floor for a replica — who its state (`FetchHeads`/
/// `FetchNode`) is served to, and the default spawn set a node derives
/// from its own role. Three user-facing levels (`sync = "public" |
/// "member" | "private"` in manifests/`install`), ordered from most
/// open to most restricted, so `<` means "more open".
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[rkyv(crate = rkyv)]
#[repr(u8)]
pub enum SyncFloor {
    /// Served to any connected peer; every node spawns it.
    Public = 0,
    /// Served to a caller holding a space read grant
    /// (`>= AUTH_ROLE_READONLY`); the default for new installs.
    Member = 1,
    /// Served only to a caller holding a space read grant
    /// (`>= AUTH_ROLE_READONLY`). Node enrollment alone is insufficient.
    Private = 2,
}

impl SyncFloor {
    /// Decode a floor byte (the wire/rkyv discriminant). `None` for an
    /// unknown byte.
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Public),
            1 => Some(Self::Member),
            2 => Some(Self::Private),
            _ => None,
        }
    }

    /// The user-facing manifest/CLI spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Member => "member",
            Self::Private => "private",
        }
    }

    /// Parse the user-facing spelling (`public` / `member` / `private`),
    /// case-insensitively. `None` for anything else.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("public") {
            Some(Self::Public)
        } else if s.eq_ignore_ascii_case("member") {
            Some(Self::Member)
        } else if s.eq_ignore_ascii_case("private") {
            Some(Self::Private)
        } else {
            None
        }
    }
}

/// New installs default to `Member` — served to space members, not the
/// world. The pre-onboarding behaviour (everything served publicly) is
/// now an explicit `Public` opt-in.
impl Default for SyncFloor {
    fn default() -> Self {
        Self::Member
    }
}

impl core::fmt::Display for SyncFloor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Members ──────────────────────────────────────────────────────

/// Member kind discriminant.
pub const MEMBER_KIND_NODE: u8 = 0;
pub const MEMBER_KIND_IDENTITY: u8 = 1;

/// Node role discriminant (only meaningful when `kind = Node`).
pub const NODE_ROLE_VOTER: u8 = 0;
pub const NODE_ROLE_OBSERVER: u8 = 1;

/// Identity proof-kind discriminant (only meaningful when
/// `kind = Identity`).
pub const PROOF_KIND_MERKLE_INCLUSION: u8 = 0;
pub const PROOF_KIND_ZK: u8 = 1;

/// One row in the member table — discriminated union over
/// `Node` and `Identity` shapes flattened into a single record
/// so the wire format stays a single `Vec<MemberRow>` query.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct MemberRow {
    /// `MEMBER_KIND_NODE` or `MEMBER_KIND_IDENTITY`.
    pub kind: u8,
    /// `peer_id` bytes (Node) or `public_key` bytes (Identity).
    pub key: Vec<u8>,
    /// Node prefix; 0 when `kind = Identity`.
    pub prefix: u16,
    /// `NODE_ROLE_*` value; 0 when `kind = Identity`.
    pub role: u8,
    /// `PROOF_KIND_*` value; 0 when `kind = Node`.
    pub proof_kind: u8,
    /// Serialized proof bytes; empty when `kind = Node`.
    pub proof_data: Vec<u8>,
}

// ── Auth grants ───────────────────────────────────────────────────
//
// Hierarchy: `ADMIN > DEVELOPER > READONLY > NONE`. Unenrolled peers
// default to `NONE`. The dispatch-layer gate in
// `vos::node::dispatch_invoke` compares the *required* role for a
// handler against the caller's *granted* role.

pub const AUTH_ROLE_NONE: u8 = 0;
pub const AUTH_ROLE_READONLY: u8 = 1;
pub const AUTH_ROLE_DEVELOPER: u8 = 2;
pub const AUTH_ROLE_ADMIN: u8 = 3;

/// Whether a byte is one of the registry's defined space-role discriminants.
pub const fn is_defined_auth_role(role: u8) -> bool {
    matches!(
        role,
        AUTH_ROLE_NONE | AUTH_ROLE_READONLY | AUTH_ROLE_DEVELOPER | AUTH_ROLE_ADMIN
    )
}

/// Whether a role may be written by `grant_role`.
///
/// `NONE` is deliberately not a grant: callers revoke an existing role with
/// the separately authenticated `revoke_role` operation.
pub const fn is_grantable_auth_role(role: u8) -> bool {
    matches!(
        role,
        AUTH_ROLE_READONLY | AUTH_ROLE_DEVELOPER | AUTH_ROLE_ADMIN
    )
}

/// Whether a role may be carried by an offline invite credential.
/// Administrator enrollment remains an online authority decision.
pub const fn is_offline_invite_role(role: u8) -> bool {
    matches!(role, AUTH_ROLE_READONLY | AUTH_ROLE_DEVELOPER)
}

/// Canonical invite evidence signed by the granting administrator.
///
/// The authority identity is part of every invite. It prevents either a
/// joining client or a lagging peer from turning an authority-bound bearer
/// into registry-only evidence.
pub fn invite_signed_bytes(
    space_id: &[u8; 32],
    role: u8,
    expires_at: u64,
    token_pub: &[u8; 32],
    authority_replication_id: &[u8; 32],
) -> Vec<u8> {
    let expires_at = expires_at.to_le_bytes();
    registry_mutation_signed_bytes(
        space_id,
        "invite",
        &[&[role], &expires_at, token_pub, authority_replication_id],
    )
}

/// Total ordering shared by the registry and canonical service authority for the
/// single grant retained per subject.
///
/// Root evidence dominates delegated evidence regardless of epoch. Otherwise
/// the greater epoch wins, with the exact grantor PeerId and then the role
/// byte providing the same deterministic equal-epoch tie-break in both
/// stores. Lower role wins the final tie so concurrent grant/downgrade
/// evidence is fail-closed as well as total.
pub fn role_grant_supersedes(
    new_epoch: u64,
    new_grantor: &[u8],
    new_role: u8,
    cur_epoch: u64,
    cur_grantor: &[u8],
    cur_role: u8,
    root: &[u8],
) -> bool {
    let new_root = !root.is_empty() && new_grantor == root;
    let cur_root = !root.is_empty() && cur_grantor == root;
    if new_root != cur_root {
        return new_root;
    }
    if new_epoch != cur_epoch {
        return new_epoch > cur_epoch;
    }
    if new_grantor != cur_grantor {
        return new_grantor < cur_grantor;
    }
    new_role < cur_role
}

/// Per-PeerId auth grant. `peer_id` is the libp2p PeerId in
/// multihash bytes (same encoding as `MemberRow.key` when
/// `kind = Node`); `role` is one of the `AUTH_ROLE_*` constants.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct AuthGrantRow {
    pub peer_id: Vec<u8>,
    pub role: u8,
    /// Monotonic grant epoch. A grant only takes effect while its
    /// epoch is strictly above the peer's `revoke_epochs` high-water,
    /// so a replayed (stale-epoch) grant can never resurrect a revoked
    /// role and a fresh re-grant must carry a higher epoch (the CLI
    /// reads the peer's epoch and signs `epoch + 1`).
    pub epoch: u64,
    /// PeerId of the op's signer — the delegator. Authority is resolved
    /// on demand by the actor's `effective_role`: this grant counts only
    /// if `grantor` is itself the genesis root or a transitively-effective
    /// admin, so revoking a delegator voids its whole subtree regardless
    /// of replay order.
    pub grantor: Vec<u8>,
}

/// One page of [`RegistryRef::auth_grants`]. The registry keeps one grant
/// row per peer and drops revoked/ineffective ones from `grants`, so a
/// natural-key cursor over the returned rows would skip past scanned-but-
/// dropped peers — `next` instead carries the last *scanned* `peer_id`
/// (empty when the scan reached the end), which the caller round-trips as
/// `after_peer` to continue.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct AuthGrantPage {
    pub grants: Vec<AuthGrantRow>,
    pub next: Vec<u8>,
}

/// One page of [`RegistryRef::members`]. Members are two key spaces —
/// nodes (by `prefix`) then identities (by hashed key) — stitched into
/// one ordered stream. The cursor names the phase to resume (`next_kind`)
/// and the resume-after key within it (`next_key`: a node's 2-byte prefix
/// or an identity's hashed 32-byte map key; empty = that phase's start).
/// The identity cursor is the *hashed* key, never the original
/// `public_key`, so it can't be empty and can't collide with the
/// phase-start sentinel. `more` is the terminator — `next_kind` alone
/// can't be, since `MEMBER_KIND_NODE` is `0`. Round-trip the cursor
/// opaquely. Use [`RegistryRef::members_all`] to drain the whole stream.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct MemberPage {
    pub members: Vec<MemberRow>,
    pub next_kind: u8,
    pub next_key: Vec<u8>,
    pub more: bool,
}

// ── Invites ───────────────────────────────────────────────────────
//
// An invite is a delegated-grant credential: an admin signs the invite
// canonical (`space_id, role, expires, token_pub`) with its operator
// key; a joiner's daemon proves possession of the token secret by
// signing its own node peer-id, then remotely invokes `redeem_invite`.
// The registry verifies admin→token→node offline and records the grant.
// One row per `token_pub`; `redeemed_by` accumulates (sorted, deduped)
// every peer that redeemed the token so a double-redemption is
// *detected* (not silently prevented), and `revoked` is a grow-only
// flag mirroring the `revoke_epochs` monotonicity discipline.

/// One row in the invites table, keyed by `token_pub`.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct InviteRow {
    /// The invite token's ed25519 public key (raw 32 bytes) — the row's
    /// identity and the key `redeem_sig` verifies under.
    pub token_pub: [u8; 32],
    /// `AUTH_ROLE_*` the token grants. Only offline tiers
    /// (`READONLY`/`DEVELOPER`) are redeemable; `admin` is refused.
    pub role: u8,
    /// Admin-committed expiry (unix seconds). Bound into the signed
    /// invite canonical, but never compared to a clock in the handler
    /// (expiry is checked once, host-side, at admission).
    pub expires_at: u64,
    /// Every node peer-id that has redeemed this token, sorted +
    /// deduped so the set converges identically on every replica. More
    /// than one entry flags a double-redemption for `space members`.
    pub redeemed_by: Vec<Vec<u8>>,
    /// Grow-only: once an admin `revoke_invite`s the token, no replayed
    /// redeem may clear it.
    pub revoked: bool,
}

/// One page of [`RegistryRef::invites`]. Cursor is the last-scanned
/// `token_pub` (empty when the scan reached the end), round-tripped as
/// `after`.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct InvitePage {
    pub invites: Vec<InviteRow>,
    pub next: Vec<u8>,
}

// ── Result codes ─────────────────────────────────────────────────

/// Status returned by a mutation handler. `Ok` is always `0`.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
#[repr(u8)]
pub enum Status {
    /// Handler succeeded.
    Ok = 0,
    /// A catalog name is already bound to different content.
    CatalogConflict = 1,
    /// The referenced row doesn't exist.
    NotFound = 2,
    /// A program can't be unpublished while an agent still references it.
    InUse = 3,
    /// The referenced program isn't in the catalog.
    ProgramNotFound = 4,
    /// An agent with this `instance_name` is already installed.
    InstanceExists = 5,
    /// A byte field wasn't the expected fixed length.
    BadHash = 6,
    /// The caller's PeerId doesn't carry the auth role required for this
    /// handler. Distinct from `NotFound` so clients can surface
    /// "permission denied" specifically.
    Forbidden = 7,
    /// Hyperspace `register_remote`: the supplied `host_prefix` doesn't
    /// match any registered node prefix.
    BadPrefix = 8,
    /// Monotone-locality guard: `install` refused to (re)create an
    /// instance at a *wider* consistency tier than the narrowest one the
    /// same `instance_name` was ever installed at.
    ConsistencyWidenDenied = 9,
    /// Anti-replay guard: `install` refused because its `replication_id`
    /// was already consumed by a prior install.
    ReplicationIdReused = 10,
    /// Compare-and-swap guard: `upgrade` refused because the instance's
    /// live program hash no longer matches the `from_hash` the op was
    /// authored against.
    StaleUpgrade = 11,
    /// CRDT consistency was requested for a catalog entry whose signed
    /// publication does not declare `#[actor(crdt)]`.
    CrdtOptInRequired = 12,
    /// Actor metadata is missing or malformed.
    BadMetadata = 13,
    /// The signed compare-and-swap base no longer names the current catalog
    /// generation (including an absent/present mismatch).
    StaleCatalog = 14,
    /// A verb for one program/install class was applied to the other class.
    ProgramKindMismatch = 15,
    /// The opaque installation identity has already been burned by a prior
    /// successful install, even if that row was later uninstalled.
    InstallationIdReused = 16,
    /// The live row has a different installation identity or pinned program
    /// generation from the signed mutation's observed base.
    StaleInstallation = 17,
    /// Persisted genesis/state is not anchored to this exact clean-break
    /// registry protocol.
    ProtocolMismatch = 18,
    /// A catalog generation identity was already consumed by a prior
    /// successful tag movement.
    PublicationIdReused = 19,
    /// The operation must be completed through the production Host-backed
    /// reservation/receipt protocol, which is not the loose registry wire.
    HostLifecycleRequired = 20,
}

impl Status {
    /// Decode a status byte (the over-the-wire discriminant) back into a
    /// `Status`. `None` for an unknown byte.
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Ok),
            1 => Some(Self::CatalogConflict),
            2 => Some(Self::NotFound),
            3 => Some(Self::InUse),
            4 => Some(Self::ProgramNotFound),
            5 => Some(Self::InstanceExists),
            6 => Some(Self::BadHash),
            7 => Some(Self::Forbidden),
            8 => Some(Self::BadPrefix),
            9 => Some(Self::ConsistencyWidenDenied),
            10 => Some(Self::ReplicationIdReused),
            11 => Some(Self::StaleUpgrade),
            12 => Some(Self::CrdtOptInRequired),
            13 => Some(Self::BadMetadata),
            14 => Some(Self::StaleCatalog),
            15 => Some(Self::ProgramKindMismatch),
            16 => Some(Self::InstallationIdReused),
            17 => Some(Self::StaleInstallation),
            18 => Some(Self::ProtocolMismatch),
            19 => Some(Self::PublicationIdReused),
            20 => Some(Self::HostLifecycleRequired),
            _ => None,
        }
    }
}

impl core::fmt::Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Status::Ok => "ok",
            Status::CatalogConflict => "catalog conflict",
            Status::NotFound => "not found",
            Status::InUse => "in use",
            Status::ProgramNotFound => "program not found",
            Status::InstanceExists => "instance exists",
            Status::BadHash => "bad hash",
            Status::Forbidden => "forbidden",
            Status::BadPrefix => "bad prefix",
            Status::ConsistencyWidenDenied => "consistency widen denied",
            Status::ReplicationIdReused => "replication id reused",
            Status::StaleUpgrade => "stale upgrade",
            Status::CrdtOptInRequired => "CRDT consistency requires #[actor(crdt)]",
            Status::BadMetadata => "bad metadata",
            Status::StaleCatalog => "stale catalog tag",
            Status::ProgramKindMismatch => "program kind mismatch",
            Status::InstallationIdReused => "installation id reused",
            Status::StaleInstallation => "stale installation",
            Status::ProtocolMismatch => "registry protocol mismatch",
            Status::PublicationIdReused => "publication id reused",
            Status::HostLifecycleRequired => "production Agent Host lifecycle required",
        })
    }
}

// ── Signing-byte builders (consensus-critical: byte-exact) ─────────

/// Domain tag for space-bound registry mutation signatures.
pub const REGISTRY_MUTATION_DOMAIN: &[u8] = b"vos-registry-mutation/v2";

/// ed25519 signature length.
pub const OP_SIG_LEN: usize = 64;

/// Canonical authorization for replacing one Raft voter with an
/// already-promoted identity. The active configuration index is the operation
/// epoch: an authorization minted for one steady membership cannot be replayed
/// after the old identity is later re-enrolled by another configuration.
pub fn raft_voter_replacement_signed_bytes(
    space_id: &[u8; 32],
    replication_id: &[u8; 32],
    old_prefix: u16,
    old_peer: &[u8],
    replacement_prefix: u16,
    replacement_peer: &[u8],
    operation_epoch: u64,
) -> Vec<u8> {
    registry_mutation_signed_bytes(
        space_id,
        "replace_raft_voter",
        &[
            replication_id,
            &old_prefix.to_le_bytes(),
            old_peer,
            &replacement_prefix.to_le_bytes(),
            replacement_peer,
            &operation_epoch.to_le_bytes(),
        ],
    )
}

/// Root-signed binding between a registry and its role authority.
pub fn role_authority_signed_bytes(
    space_id: &[u8; 32],
    authority_replication_id: &[u8; 32],
) -> Vec<u8> {
    registry_mutation_signed_bytes(space_id, "set_role_authority", &[authority_replication_id])
}

/// Root-host attestation emitted only after the canonical authority has
/// durably accepted this exact invite redemption. The complete redemption
/// fields are length-framed by [`registry_mutation_signed_bytes`], so no signature can be
/// transplanted to another token, holder, role, deadline, or authority.
#[allow(clippy::too_many_arguments)]
pub fn role_authority_invite_attestation_signed_bytes(
    space_id: &[u8; 32],
    authority_replication_id: &[u8; 32],
    token_pub: &[u8],
    role: u8,
    expires_at: u64,
    admin_peer_id: &[u8],
    admin_sig: &[u8],
    peer_id: &[u8],
    redeem_sig: &[u8],
    node_sig: &[u8],
) -> Vec<u8> {
    registry_mutation_signed_bytes(
        space_id,
        "attest_role_authority_invite",
        &[
            authority_replication_id,
            token_pub,
            &[role],
            &expires_at.to_le_bytes(),
            admin_peer_id,
            admin_sig,
            peer_id,
            redeem_sig,
            node_sig,
        ],
    )
}

/// Canonical byte string a registry mutation's author signs. Layout:
/// `domain || schema_version || schema_hash || space_id || u16(op.len) || op
/// || (u32(field.len) || field)*`.
/// The signer (CLI/daemon) and the verifier (actor) build these from the
/// same logical args, so the bytes match exactly without re-encoding the
/// wire `Msg`. The actor supplies `space_id` only from its exact durable,
/// nonzero anchor; it is never accepted from the mutation message itself.
pub fn registry_mutation_signed_bytes(space_id: &[u8; 32], op: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(REGISTRY_MUTATION_DOMAIN);
    out.extend_from_slice(&REGISTRY_SCHEMA_VERSION.to_le_bytes());
    out.extend_from_slice(&REGISTRY_SCHEMA_HASH);
    out.extend_from_slice(space_id);
    out.extend_from_slice(&(op.len() as u16).to_le_bytes());
    out.extend_from_slice(op.as_bytes());
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// Canonical bytes for a CAS publication of a service-actor package.
#[allow(clippy::too_many_arguments)]
pub fn publish_service_program_signed_bytes(
    space_id: &[u8; 32],
    name: &str,
    hash: &[u8],
    crdt: bool,
    publication_id: &[u8],
    expected_publication_id: &[u8],
    expected_hash: &[u8],
) -> Vec<u8> {
    registry_mutation_signed_bytes(
        space_id,
        "publish_service_program",
        &[
            name.as_bytes(),
            hash,
            &[crdt as u8],
            publication_id,
            expected_publication_id,
            expected_hash,
        ],
    )
}

/// Canonical bytes for a CAS publication of an AgentActor package.
pub fn publish_agent_actor_program_signed_bytes(
    space_id: &[u8; 32],
    name: &str,
    hash: &[u8],
    publication_id: &[u8],
    expected_publication_id: &[u8],
    expected_hash: &[u8],
) -> Vec<u8> {
    registry_mutation_signed_bytes(
        space_id,
        "publish_agent_actor_program",
        &[
            name.as_bytes(),
            hash,
            publication_id,
            expected_publication_id,
            expected_hash,
        ],
    )
}

/// Canonical bytes for removing an exact service-program tag generation.
pub fn unpublish_service_program_signed_bytes(
    space_id: &[u8; 32],
    name: &str,
    expected_publication_id: &[u8],
    expected_hash: &[u8],
) -> Vec<u8> {
    registry_mutation_signed_bytes(
        space_id,
        "unpublish_service_program",
        &[name.as_bytes(), expected_publication_id, expected_hash],
    )
}

/// Canonical bytes for removing an exact AgentActor tag generation.
pub fn unpublish_agent_actor_program_signed_bytes(
    space_id: &[u8; 32],
    name: &str,
    expected_publication_id: &[u8],
    expected_hash: &[u8],
) -> Vec<u8> {
    registry_mutation_signed_bytes(
        space_id,
        "unpublish_agent_actor_program",
        &[name.as_bytes(), expected_publication_id, expected_hash],
    )
}

/// Canonical bytes for admitting one service-actor installation.
#[allow(clippy::too_many_arguments)]
pub fn install_service_actor_signed_bytes(
    space_id: &[u8; 32],
    instance_name: &str,
    program_name: &str,
    program_hash: &[u8],
    program_publication_id: &[u8],
    installation_id: &[u8],
    replication_id: &[u8],
    consistency: u8,
    network_reachable: bool,
    sync_role: u8,
) -> Vec<u8> {
    registry_mutation_signed_bytes(
        space_id,
        "install_service_actor",
        &[
            instance_name.as_bytes(),
            program_name.as_bytes(),
            program_hash,
            program_publication_id,
            installation_id,
            replication_id,
            &[consistency],
            &[network_reachable as u8],
            &[sync_role],
        ],
    )
}

/// Canonical bytes for recording one authority-attested Local system Agent
/// Host installation receipt.
pub fn install_system_actor_signed_bytes(space_id: &[u8; 32], receipt: &[u8]) -> Vec<u8> {
    registry_mutation_signed_bytes(space_id, "install_system_actor", &[receipt])
}

/// Canonical bytes for retiring an exact live service installation.
pub fn uninstall_service_actor_signed_bytes(
    space_id: &[u8; 32],
    instance_name: &str,
    installation_id: &[u8],
    expected_revision: u64,
    expected_program_hash: &[u8],
    expected_program_publication_id: &[u8],
) -> Vec<u8> {
    let expected_revision = expected_revision.to_le_bytes();
    registry_mutation_signed_bytes(
        space_id,
        "uninstall_service_actor",
        &[
            instance_name.as_bytes(),
            installation_id,
            &expected_revision,
            expected_program_hash,
            expected_program_publication_id,
        ],
    )
}

/// Canonical bytes for retiring an exact live system-actor installation.
pub fn uninstall_system_actor_signed_bytes(
    space_id: &[u8; 32],
    instance_name: &str,
    installation_id: &[u8],
    expected_revision: u64,
    expected_program_hash: &[u8],
    expected_program_publication_id: &[u8],
) -> Vec<u8> {
    let expected_revision = expected_revision.to_le_bytes();
    registry_mutation_signed_bytes(
        space_id,
        "uninstall_system_actor",
        &[
            instance_name.as_bytes(),
            installation_id,
            &expected_revision,
            expected_program_hash,
            expected_program_publication_id,
        ],
    )
}

/// Canonical bytes for an exact service installation upgrade.
#[allow(clippy::too_many_arguments)]
pub fn upgrade_service_actor_signed_bytes(
    space_id: &[u8; 32],
    instance_name: &str,
    installation_id: &[u8],
    expected_revision: u64,
    from_program_hash: &[u8],
    from_program_publication_id: &[u8],
    new_program_name: &str,
    new_program_hash: &[u8],
    new_program_publication_id: &[u8],
) -> Vec<u8> {
    let expected_revision = expected_revision.to_le_bytes();
    registry_mutation_signed_bytes(
        space_id,
        "upgrade_service_actor",
        &[
            instance_name.as_bytes(),
            installation_id,
            &expected_revision,
            from_program_hash,
            from_program_publication_id,
            new_program_name.as_bytes(),
            new_program_hash,
            new_program_publication_id,
        ],
    )
}

/// Canonical bytes for an exact Local system Agent Host actor upgrade.
#[allow(clippy::too_many_arguments)]
pub fn upgrade_system_actor_signed_bytes(
    space_id: &[u8; 32],
    instance_name: &str,
    installation_id: &[u8],
    expected_revision: u64,
    from_program_hash: &[u8],
    from_program_publication_id: &[u8],
    new_program_name: &str,
    new_program_hash: &[u8],
    new_program_publication_id: &[u8],
) -> Vec<u8> {
    let expected_revision = expected_revision.to_le_bytes();
    registry_mutation_signed_bytes(
        space_id,
        "upgrade_system_actor",
        &[
            instance_name.as_bytes(),
            installation_id,
            &expected_revision,
            from_program_hash,
            from_program_publication_id,
            new_program_name.as_bytes(),
            new_program_hash,
            new_program_publication_id,
        ],
    )
}

/// Pack an authorization blob: `signer_peer_id || signature(64)`.
/// `signer_peer_id` is libp2p multihash bytes (same encoding as
/// [`AuthGrantRow::peer_id`]); the verifier splits at `len - 64`.
pub fn pack_auth(signer_peer_id: &[u8], sig: &[u8; OP_SIG_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(signer_peer_id.len() + OP_SIG_LEN);
    out.extend_from_slice(signer_peer_id);
    out.extend_from_slice(sig);
    out
}

/// Extract the raw 32-byte ed25519 public key embedded in a libp2p
/// PeerId. For ed25519, a PeerId is the identity-multihash of the
/// protobuf-encoded public key, a fixed 38-byte shape:
///
/// ```text
/// 00 24 08 01 12 20 <32-byte ed25519 key>
/// │  │  └──────────┴ protobuf PublicKey { KeyType::Ed25519=1, key[32] }
/// │  └ multihash length 0x24 = 36
/// └ multihash code 0x00 = identity
/// ```
///
/// Returns `None` for any other shape. Verifier-side `verify_op_sig`
/// (in the actor, where the ed25519 dep lives) consumes this.
pub fn ed25519_pubkey_from_peer_id(peer_id: &[u8]) -> Option<[u8; 32]> {
    const PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    if peer_id.len() != 38 || peer_id[..6] != PREFIX {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&peer_id[6..]);
    Some(key)
}

// ── Service-id derivation ─────────────────────────────────────────

/// Domain tag for `space_id` derivation. The host computes
/// `space_id = blake2b("vos-space-id" || genesis_dag_root)`.
pub const SPACE_ID_DOMAIN_TAG: &[u8] = b"vos-space-id";

/// Deterministic per-node `ServiceId` (raw u32) for an installed
/// instance. The low 16 bits are `blake2b(instance_name)` folded into
/// `[0x100, 0x7FFF]` so they can't collide with `ServiceId::REGISTRY`
/// (= 0) or any reserved low system id; the high 16 bits carry the
/// node `prefix`. Stable across restarts of the same node so each
/// instance's redb path persists.
///
/// Cross-target by design — the actor's `resolve` handler and the host
/// (the vosx CLI, the daemon's feeder / reconcile) both call this with
/// the same bytes coming out. On riscv64 the blake2b dispatches to the
/// host ECALL precompile; on every other target it runs through
/// [`crate::crypto::blake2b_hash`] → `blake2b_simd`.
pub fn instance_service_id(instance_name: &str, prefix: u16) -> u32 {
    let raw_bytes: [u8; 2] =
        crate::crypto::blake2b_hash(b"vos-instance-svc-id", &[&[0u8], instance_name.as_bytes()]);
    let raw = u16::from_le_bytes(raw_bytes);
    let local = (raw & 0x7FFF).max(0x100);
    ((prefix as u32) << 16) | (local as u32)
}

// ── Catalog ingress authentication (host/daemon side) ────────────────
//
// Catalog mutators are signed by their actual author before dispatch and
// re-verified by the registry actor on every replica's replay. The network
// host only peeks at the embedded signer so it can bind that author to the
// Noise-authenticated ingress peer (or an authenticated Raft origin). It
// never decodes and re-encodes the payload.
use crate::actors::codec::Encode;
use crate::value::{Msg, TAG_DYNAMIC, Value};
#[cfg(feature = "std")]
use alloc::sync::Arc;

/// Host-held operator signature callback. Catalog mutation threads do not
/// receive it; the node service retains it solely for root-host attestations
/// produced after a canonical authority decision.
#[cfg(feature = "std")]
pub(crate) type OperatorSigner = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

#[cfg(feature = "std")]
fn is_catalog_mutation(method: &str) -> bool {
    matches!(
        method,
        "publish_service_program"
            | "publish_agent_actor_program"
            | "unpublish_service_program"
            | "unpublish_agent_actor_program"
            | "install_service_actor"
            | "install_system_actor"
            | "uninstall_service_actor"
            | "uninstall_system_actor"
            | "upgrade_service_actor"
            | "upgrade_system_actor"
            | "register_meta"
            | "register_extension_meta"
    )
}

/// Read the unique embedded author from a dynamic catalog mutation without
/// changing its bytes.
///
/// `Ok(None)` means the payload is not dynamic, or is a well-formed dynamic
/// message that does not name a catalog mutation. `Err(())` means a dynamic
/// payload is malformed, or names a catalog mutation without one unique,
/// structurally valid Ed25519 `auth = signer_peer_id || signature(64)`
/// argument. Keeping those outcomes distinct lets network ingress leave
/// unrelated methods generic while failing closed before malformed dynamic
/// bytes or a malformed mutation reach the registry guest.
#[cfg(feature = "std")]
pub(crate) fn catalog_op_auth_signer(payload: &[u8]) -> Result<Option<Vec<u8>>, ()> {
    if !payload.starts_with(&[TAG_DYNAMIC]) {
        return Ok(None);
    }
    let msg = <Msg as crate::Decode>::try_decode(&payload[1..]).ok_or(())?;
    if !is_catalog_mutation(&msg.name) {
        return Ok(None);
    }
    let mut auth_args = msg
        .args
        .0
        .iter()
        .filter_map(|(name, value)| (name == "auth").then_some(value));
    let auth = auth_args.next().ok_or(())?;
    if auth_args.next().is_some() {
        return Err(());
    }
    let Value::Bytes(auth) = auth else {
        return Err(());
    };
    let signer_length = auth
        .len()
        .checked_sub(OP_SIG_LEN)
        .filter(|length| *length > 0)
        .ok_or(())?;
    let signer = &auth[..signer_length];
    ed25519_pubkey_from_peer_id(signer).ok_or(())?;
    Ok(Some(signer.to_vec()))
}

// ── Dynamic registry client ───────────────────────────────────────
//
// [`RegistryRef`] is a hand-written typed reference over the registry's
// dynamic-dispatch wire, replacing the macro-generated `SpaceRegistryRef`
// from the `space-registry` actor crate. A host consumer (the vosx CLI,
// the daemon's in-process feeder / reconcile) talks to the registry
// through it without depending on the actor crate. Every method builds a
// `Msg` whose name is the handler's name and whose arg keys are the
// handler's param names, frames it `TAG_DYNAMIC`, invokes, and decodes
// the reply `Value` into the row/status types above — byte-identical to
// the registry guest consumes. Generic over `RegistryInvoker`, so the
// same code drives a network invoke (CLI → daemon, arriving as
// `Caller::Peer`) and a local in-process control-plane invoke.

use crate::abi::service::ServiceId;
use crate::actors::client::ClientError;

/// Route-oriented invocation reserved for the built-in registry control plane.
/// Application actor references use `ActorId` through `actors::Invoker`.
pub trait RegistryInvoker {
    fn invoke_registry(
        &mut self,
        target: ServiceId,
        payload: Vec<u8>,
    ) -> impl core::future::Future<Output = Result<Value, ClientError>> + '_;
}

impl<A: crate::Actor> RegistryInvoker for crate::Context<A> {
    async fn invoke_registry(
        &mut self,
        target: ServiceId,
        payload: Vec<u8>,
    ) -> Result<Value, ClientError> {
        self.ask_raw(target, &payload)
            .await
            .map_err(ClientError::from)
    }
}

#[cfg(feature = "std")]
impl RegistryInvoker for &crate::node::VosNode {
    async fn invoke_registry(
        &mut self,
        target: ServiceId,
        payload: Vec<u8>,
    ) -> Result<Value, ClientError> {
        decode_node_registry_reply(crate::node::VosNode::invoke(self, target, payload))
    }
}

/// Decode the daemon's outer actor-value reply without ever constructing an
/// archived `Value` through unchecked access. A corrupt or ABI-mismatched
/// guest reply is untrusted input at this boundary, just like an inner typed
/// page, and must fail closed instead of reaching rkyv's unchecked decoder.
#[cfg(feature = "std")]
fn decode_node_registry_reply(reply: Option<Vec<u8>>) -> Result<Value, ClientError> {
    match reply {
        Some(bytes)
            if bytes.len() == 5
                && bytes[0] == crate::STATUS_FORBIDDEN
                && bytes[1..] == [0, 0, 0, 0] =>
        {
            Err(ClientError::Forbidden)
        }
        Some(bytes) if bytes.is_empty() => Ok(Value::Unit),
        Some(bytes) => <Value as crate::Decode>::try_decode(&bytes).ok_or(ClientError::Decode),
        None => Err(ClientError::Unreachable),
    }
}

/// Decode a `Value::Bytes` rkyv reply into `T` (checked access), mapping
/// a wrong-shape or undecodable reply to the matching `ClientError` —
/// mirrors the generated client's reply decode.
fn decode_rkyv<T: crate::Decode>(value: Value) -> Result<T, ClientError> {
    match value {
        Value::Bytes(b) => T::try_decode(&b).ok_or(ClientError::Decode),
        other => Err(ClientError::UnexpectedReply(alloc::format!("{other:?}"))),
    }
}

/// Decode a raw `Vec<u8>` reply (a byte-buffer return like
/// `meta_for_instance` / `root`).
fn decode_bytes(value: Value) -> Result<Vec<u8>, ClientError> {
    match value {
        Value::Bytes(b) => Ok(b),
        other => Err(ClientError::UnexpectedReply(alloc::format!("{other:?}"))),
    }
}

fn require_current_protocol(protocol: RegistryProtocol) -> Result<(), ClientError> {
    if protocol.is_current() {
        Ok(())
    } else {
        Err(ClientError::UnexpectedReply(alloc::format!(
            "registry protocol mismatch: version {}, schema {:02x?}",
            protocol.version,
            protocol.schema_hash,
        )))
    }
}

fn program_tag_wire(tag: Option<ProgramTag>) -> (Vec<u8>, Vec<u8>) {
    match tag {
        Some(tag) => (tag.publication_id.as_bytes().to_vec(), tag.hash.to_vec()),
        None => (Vec::new(), Vec::new()),
    }
}

// Whole-table convenience drains are deliberately finite. The actor caps a
// page at 128 rows, but a corrupt peer can otherwise feed a client an endless
// sequence of individually valid, advancing pages and grow memory without a
// bound. Manual paging remains available when a legitimate administrative
// table exceeds these convenience-view ceilings.
pub(crate) const REGISTRY_DRAIN_MAX_PAGES: usize = 64;
pub(crate) const REGISTRY_DRAIN_MAX_ROWS: usize = 8_192;
pub(crate) const REGISTRY_DRAIN_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Shared aggregate budget for every registry whole-table convenience drain.
/// `encoded_bytes` is the canonical encoded size of the decoded page, which
/// bounds retained row payload without trusting any peer-supplied length.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RegistryDrainBudget {
    pages: usize,
    rows: usize,
    bytes: usize,
    max_pages: usize,
    max_rows: usize,
    max_bytes: usize,
}

impl Default for RegistryDrainBudget {
    fn default() -> Self {
        Self::with_limits(
            REGISTRY_DRAIN_MAX_PAGES,
            REGISTRY_DRAIN_MAX_ROWS,
            REGISTRY_DRAIN_MAX_BYTES,
        )
    }
}

impl RegistryDrainBudget {
    pub(crate) const fn with_limits(max_pages: usize, max_rows: usize, max_bytes: usize) -> Self {
        Self {
            pages: 0,
            rows: 0,
            bytes: 0,
            max_pages,
            max_rows,
            max_bytes,
        }
    }

    /// Charge a decoded page before retaining any of its rows. Arithmetic
    /// overflow and every exceeded dimension fail closed without mutating the
    /// budget, so callers cannot accidentally resume from an invalid page.
    pub(crate) fn record_page(&mut self, rows: usize, encoded_bytes: usize) -> bool {
        let Some(pages) = self.pages.checked_add(1) else {
            return false;
        };
        let Some(rows) = self.rows.checked_add(rows) else {
            return false;
        };
        let Some(bytes) = self.bytes.checked_add(encoded_bytes) else {
            return false;
        };
        if pages > self.max_pages || rows > self.max_rows || bytes > self.max_bytes {
            return false;
        }
        self.pages = pages;
        self.rows = rows;
        self.bytes = bytes;
        true
    }
}

fn valid_member_cursor(kind: u8, key: &[u8]) -> bool {
    match kind {
        MEMBER_KIND_NODE => key.is_empty() || key.len() == 2,
        MEMBER_KIND_IDENTITY => key.is_empty() || key.len() == 32,
        _ => false,
    }
}

fn identity_member_cursor(key: &[u8]) -> [u8; 32] {
    crate::crypto::blake2b_hash::<32>(b"space-registry/identity-key", &[key])
}

fn valid_member_row(row: &MemberRow) -> bool {
    match row.kind {
        MEMBER_KIND_NODE => {
            !row.key.is_empty()
                && matches!(row.role, NODE_ROLE_VOTER | NODE_ROLE_OBSERVER)
                && row.proof_kind == 0
                && row.proof_data.is_empty()
        }
        MEMBER_KIND_IDENTITY => {
            !row.key.is_empty()
                && row.prefix == 0
                && row.role == 0
                && matches!(row.proof_kind, PROOF_KIND_MERKLE_INCLUSION | PROOF_KIND_ZK)
        }
        _ => false,
    }
}

/// Validate the exact cursor and row-order contract of a member page. This is
/// shared by the typed client and the SSH host view so neither can loop on, or
/// render, a malformed registry response.
pub(crate) fn member_page_advances(after_kind: u8, after_key: &[u8], page: &MemberPage) -> bool {
    if !valid_member_cursor(after_kind, after_key)
        || page.members.iter().any(|row| !valid_member_row(row))
        || (page.more && page.members.is_empty())
        || (!page.more && (page.next_kind != MEMBER_KIND_NODE || !page.next_key.is_empty()))
    {
        return false;
    }
    let Some(first) = page.members.first() else {
        return true;
    };
    if page.members.iter().any(|row| row.kind != first.kind) {
        return false;
    }

    match first.kind {
        MEMBER_KIND_NODE => {
            if after_kind != MEMBER_KIND_NODE
                || page.members.first().is_some_and(|row| {
                    after_key.len() == 2
                        && row.prefix <= u16::from_be_bytes([after_key[0], after_key[1]])
                })
                || page
                    .members
                    .windows(2)
                    .any(|pair| pair[0].prefix >= pair[1].prefix)
            {
                return false;
            }
            // A non-empty node page always either continues with its last
            // prefix or explicitly hands off to the identity phase.
            if !page.more {
                return false;
            }
            match page.next_kind {
                MEMBER_KIND_NODE => {
                    page.next_key
                        == page
                            .members
                            .last()
                            .expect("non-empty page")
                            .prefix
                            .to_be_bytes()
                }
                MEMBER_KIND_IDENTITY => page.next_key.is_empty(),
                _ => false,
            }
        }
        MEMBER_KIND_IDENTITY => {
            let mut previous = if after_kind == MEMBER_KIND_IDENTITY && after_key.len() == 32 {
                let mut cursor = [0_u8; 32];
                cursor.copy_from_slice(after_key);
                Some(cursor)
            } else {
                None
            };
            for row in &page.members {
                let cursor = identity_member_cursor(&row.key);
                if previous.is_some_and(|prior| cursor <= prior) {
                    return false;
                }
                previous = Some(cursor);
            }
            !page.more
                || (page.next_kind == MEMBER_KIND_IDENTITY
                    && page.next_key.as_slice() == previous.expect("non-empty page").as_slice())
        }
        _ => false,
    }
}

fn invite_page_advances(after: &[u8], page: &InvitePage) -> bool {
    if (!after.is_empty() && after.len() != 32)
        || (!page.next.is_empty() && page.next.len() != 32)
        || (!page.next.is_empty() && page.invites.is_empty())
        || page
            .invites
            .first()
            .is_some_and(|row| after.len() == 32 && row.token_pub.as_slice() <= after)
        || page
            .invites
            .windows(2)
            .any(|pair| pair[0].token_pub >= pair[1].token_pub)
        || page.invites.iter().any(|row| {
            row.redeemed_by.iter().any(Vec::is_empty)
                || row.redeemed_by.windows(2).any(|pair| pair[0] >= pair[1])
        })
    {
        return false;
    }
    page.next.is_empty()
        || page.next.as_slice()
            == page
                .invites
                .last()
                .expect("non-empty advancing page")
                .token_pub
}

/// Typed reference to a space registry, addressed by `ServiceId`.
#[derive(Copy, Clone)]
pub struct RegistryRef {
    target: ServiceId,
}

impl RegistryRef {
    /// Bind to an explicit registry `ServiceId`. Cheap; copy freely.
    pub const fn at(target: ServiceId) -> Self {
        Self { target }
    }

    /// The `ServiceId` this ref points at.
    pub const fn id(&self) -> ServiceId {
        self.target
    }

    /// Frame `msg` as `[TAG_DYNAMIC][rkyv Msg]` and invoke, returning the
    /// decoded reply `Value`. The single funnel every method goes through.
    async fn call<I: RegistryInvoker>(&self, inv: &mut I, msg: Msg) -> Result<Value, ClientError> {
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        inv.invoke_registry(self.target, payload).await
    }

    /// Probe the exact clean-break registry wire/state generation.
    pub async fn protocol<I: RegistryInvoker>(
        &self,
        inv: &mut I,
    ) -> Result<RegistryProtocol, ClientError> {
        let protocol = decode_rkyv(self.call(inv, Msg::new("protocol")).await?)?;
        require_current_protocol(protocol)?;
        Ok(protocol)
    }

    // ── Catalog reads ─────────────────────────────────────────────

    /// One page of the program catalog in name order. Pass
    /// an empty name to start; continue from the
    /// last returned row's name while the page's `more` flag
    /// is set. `budget` caps the page (0 = the registry's max). Prefer
    /// [`programs_all`](Self::programs_all) unless paging by hand.
    pub async fn programs<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        after_name: String,
        budget: u32,
    ) -> Result<ProgramPage, ClientError> {
        let page: ProgramPage = decode_rkyv(
            self.call(
                inv,
                Msg::new("catalog_programs")
                    .with("after_name", after_name)
                    .with("budget", budget),
            )
            .await?,
        )?;
        require_current_protocol(page.protocol)?;
        Ok(page)
    }

    /// Drain the whole program catalog into one `Vec` (name order).
    /// Callers that need the full set — `space programs`, `space info`,
    /// manifest export — use this.
    pub async fn programs_all<I: RegistryInvoker>(
        &self,
        inv: &mut I,
    ) -> Result<Vec<ProgramRow>, ClientError> {
        let mut out: Vec<ProgramRow> = Vec::new();
        let mut drain = RegistryDrainBudget::default();
        loop {
            let after_name = out.last().map(|p| p.name.clone()).unwrap_or_default();
            let page = self.programs(inv, after_name.clone(), 0).await?;
            let page_bytes = page.encode().len();
            if !drain.record_page(page.rows.len(), page_bytes)
                || page
                    .rows
                    .iter()
                    .any(|row| !is_canonical_registry_slug(&row.name))
                || page
                    .rows
                    .first()
                    .is_some_and(|row| !after_name.is_empty() && row.name <= after_name)
                || page
                    .rows
                    .windows(2)
                    .any(|pair| pair[0].name >= pair[1].name)
                || (page.more && page.rows.is_empty())
            {
                return Err(ClientError::Decode);
            }
            let more = page.more;
            out.extend(page.rows);
            if !more {
                break;
            }
        }
        Ok(out)
    }

    pub async fn program<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        name: String,
    ) -> Result<Option<ProgramRow>, ClientError> {
        let expected_name = name.clone();
        let lookup: ProgramLookup = decode_rkyv(
            self.call(inv, Msg::new("catalog_program").with("name", name))
                .await?,
        )?;
        require_current_protocol(lookup.protocol)?;
        if lookup
            .row
            .as_ref()
            .is_some_and(|row| row.name != expected_name || !is_canonical_registry_slug(&row.name))
        {
            return Err(ClientError::Decode);
        }
        Ok(lookup.row)
    }

    /// The catalogued program (if any) whose `hash` matches — a targeted
    /// lookup so a hash-membership check needn't drain the whole catalog.
    pub async fn program_by_hash<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        hash: Vec<u8>,
    ) -> Result<Option<ProgramRow>, ClientError> {
        let expected_hash = hash.clone();
        let lookup: ProgramLookup = decode_rkyv(
            self.call(inv, Msg::new("catalog_program_by_hash").with("hash", hash))
                .await?,
        )?;
        require_current_protocol(lookup.protocol)?;
        if lookup.row.as_ref().is_some_and(|row| {
            row.hash.as_slice() != expected_hash.as_slice()
                || !is_canonical_registry_slug(&row.name)
        }) {
            return Err(ClientError::Decode);
        }
        Ok(lookup.row)
    }

    /// Whether the hash was ever admitted by a successful typed publication.
    /// This is intentionally broader than the mutable current-name catalog:
    /// displaced generations remain fetchable for deterministic recovery.
    pub async fn program_blob_authorized<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        hash: Vec<u8>,
    ) -> Result<bool, ClientError> {
        let decision: ProgramBlobAuthorization = decode_rkyv(
            self.call(inv, Msg::new("program_blob_authorized").with("hash", hash))
                .await?,
        )?;
        require_current_protocol(decision.protocol)?;
        Ok(decision.authorized)
    }

    /// One page of the installed-agent roster, in `instance_name` order.
    /// Pass an empty `after_name` to start; continue from the last returned
    /// row's `instance_name` while `more` is set. `budget` caps the page
    /// (0 = the registry's max). Prefer [`agents_all`](Self::agents_all)
    /// unless paging by hand.
    pub async fn agents<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        after_name: String,
        budget: u32,
    ) -> Result<AgentPage, ClientError> {
        let page: AgentPage = decode_rkyv(
            self.call(
                inv,
                Msg::new("service_actors")
                    .with("after_name", after_name)
                    .with("budget", budget),
            )
            .await?,
        )?;
        require_current_protocol(page.protocol)?;
        Ok(page)
    }

    /// Drain the whole installed-agent roster into one `Vec`
    /// (`instance_name` order).
    pub async fn agents_all<I: RegistryInvoker>(
        &self,
        inv: &mut I,
    ) -> Result<Vec<AgentRow>, ClientError> {
        let mut out: Vec<AgentRow> = Vec::new();
        let mut drain = RegistryDrainBudget::default();
        loop {
            let after = out
                .last()
                .map(|a| a.instance_name.clone())
                .unwrap_or_default();
            let page = self.agents(inv, after.clone(), 0).await?;
            let page_bytes = page.encode().len();
            if !drain.record_page(page.rows.len(), page_bytes)
                || page.rows.iter().any(|row| {
                    !is_canonical_registry_slug(&row.instance_name)
                        || !is_canonical_registry_slug(&row.program_name)
                })
                || page
                    .rows
                    .first()
                    .is_some_and(|row| !after.is_empty() && row.instance_name <= after)
                || page
                    .rows
                    .windows(2)
                    .any(|pair| pair[0].instance_name >= pair[1].instance_name)
                || (page.more && page.rows.is_empty())
            {
                return Err(ClientError::Decode);
            }
            let more = page.more;
            out.extend(page.rows);
            if !more {
                break;
            }
        }
        Ok(out)
    }

    pub async fn agent<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        instance_name: String,
    ) -> Result<Option<AgentRow>, ClientError> {
        let expected_name = instance_name.clone();
        let lookup: AgentLookup = decode_rkyv(
            self.call(
                inv,
                Msg::new("service_actor").with("instance_name", instance_name),
            )
            .await?,
        )?;
        require_current_protocol(lookup.protocol)?;
        if lookup.row.as_ref().is_some_and(|row| {
            row.instance_name != expected_name
                || !is_canonical_registry_slug(&row.instance_name)
                || !is_canonical_registry_slug(&row.program_name)
        }) {
            return Err(ClientError::Decode);
        }
        Ok(lookup.row)
    }

    /// One page of actors installed in the Local system Agent Host.
    pub async fn system_actors<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        after_name: String,
        budget: u32,
    ) -> Result<SystemActorPage, ClientError> {
        let page: SystemActorPage = decode_rkyv(
            self.call(
                inv,
                Msg::new("system_actors")
                    .with("after_name", after_name)
                    .with("budget", budget),
            )
            .await?,
        )?;
        require_current_protocol(page.protocol)?;
        Ok(page)
    }

    /// Drain the Local system Agent Host actor table in name order.
    pub async fn system_actors_all<I: RegistryInvoker>(
        &self,
        inv: &mut I,
    ) -> Result<Vec<SystemActorRow>, ClientError> {
        let mut out: Vec<SystemActorRow> = Vec::new();
        let mut drain = RegistryDrainBudget::default();
        loop {
            let after = out
                .last()
                .map(|row| row.instance_name.clone())
                .unwrap_or_default();
            let page = self.system_actors(inv, after.clone(), 0).await?;
            let page_bytes = page.encode().len();
            if !drain.record_page(page.rows.len(), page_bytes)
                || page.rows.iter().any(|row| {
                    !is_canonical_registry_slug(&row.instance_name)
                        || !is_canonical_registry_slug(&row.program_name)
                })
                || page
                    .rows
                    .first()
                    .is_some_and(|row| !after.is_empty() && row.instance_name <= after)
                || page
                    .rows
                    .windows(2)
                    .any(|pair| pair[0].instance_name >= pair[1].instance_name)
                || (page.more && page.rows.is_empty())
            {
                return Err(ClientError::Decode);
            }
            let more = page.more;
            out.extend(page.rows);
            if !more {
                return Ok(out);
            }
        }
    }

    pub async fn system_actor<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        instance_name: String,
    ) -> Result<Option<SystemActorRow>, ClientError> {
        let expected_name = instance_name.clone();
        let lookup: SystemActorLookup = decode_rkyv(
            self.call(
                inv,
                Msg::new("system_actor").with("instance_name", instance_name),
            )
            .await?,
        )?;
        require_current_protocol(lookup.protocol)?;
        if lookup.row.as_ref().is_some_and(|row| {
            row.instance_name != expected_name
                || !is_canonical_registry_slug(&row.instance_name)
                || !is_canonical_registry_slug(&row.program_name)
        }) {
            return Err(ClientError::Decode);
        }
        Ok(lookup.row)
    }

    /// The first installed agent (in `instance_name` order) whose name
    /// starts with `prefix` and ends with `suffix` — a template lookup so a
    /// caller cloning a channel's program rows needn't drain the roster.
    pub async fn agent_by_pattern<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        prefix: String,
        suffix: String,
    ) -> Result<Option<AgentRow>, ClientError> {
        let expected_prefix = prefix.clone();
        let expected_suffix = suffix.clone();
        let lookup: AgentLookup = decode_rkyv(
            self.call(
                inv,
                Msg::new("service_actor_by_pattern")
                    .with("prefix", prefix)
                    .with("suffix", suffix),
            )
            .await?,
        )?;
        require_current_protocol(lookup.protocol)?;
        if lookup.row.as_ref().is_some_and(|row| {
            !row.instance_name.starts_with(&expected_prefix)
                || !row.instance_name.ends_with(&expected_suffix)
                || !is_canonical_registry_slug(&row.instance_name)
                || !is_canonical_registry_slug(&row.program_name)
        }) {
            return Err(ClientError::Decode);
        }
        Ok(lookup.row)
    }

    /// One page of installed-agent names (names only), in `instance_name`
    /// order. Same cursor/`more` contract as [`agents`](Self::agents).
    /// Prefer [`agent_names_all`](Self::agent_names_all) unless paging by
    /// hand.
    pub async fn agent_names<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        after_name: String,
        budget: u32,
    ) -> Result<AgentNamePage, ClientError> {
        let page: AgentNamePage = decode_rkyv(
            self.call(
                inv,
                Msg::new("service_actor_names")
                    .with("after_name", after_name)
                    .with("budget", budget),
            )
            .await?,
        )?;
        require_current_protocol(page.protocol)?;
        Ok(page)
    }

    /// Drain every installed-agent name into one `Vec<String>`
    /// (`instance_name` order).
    pub async fn agent_names_all<I: RegistryInvoker>(
        &self,
        inv: &mut I,
    ) -> Result<Vec<String>, ClientError> {
        let mut out: Vec<String> = Vec::new();
        let mut drain = RegistryDrainBudget::default();
        loop {
            let after = out.last().cloned().unwrap_or_default();
            let page = self.agent_names(inv, after.clone(), 0).await?;
            let page_bytes = page.encode().len();
            if !drain.record_page(page.names.len(), page_bytes)
                || page
                    .names
                    .iter()
                    .any(|name| !is_canonical_registry_slug(name))
                || page
                    .names
                    .first()
                    .is_some_and(|name| !after.is_empty() && name <= &after)
                || page.names.windows(2).any(|pair| pair[0] >= pair[1])
                || (page.more && page.names.is_empty())
            {
                return Err(ClientError::Decode);
            }
            let more = page.more;
            out.extend(page.names);
            if !more {
                break;
            }
        }
        Ok(out)
    }

    pub async fn meta_for_instance<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        name: String,
    ) -> Result<Vec<u8>, ClientError> {
        decode_bytes(
            self.call(inv, Msg::new("meta_for_instance").with("name", name))
                .await?,
        )
    }

    /// One page of the member roster (nodes then identities). Prefer
    /// [`members_all`](Self::members_all) unless you are paging by hand;
    /// pass `(0, [])` to start and continue from the returned page's
    /// `(next_kind, next_key)` while `more` is true. `budget` caps the page.
    pub async fn members<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        after_kind: u8,
        after_key: Vec<u8>,
        budget: u32,
    ) -> Result<MemberPage, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("members")
                    .with("after_kind", after_kind)
                    .with("after_key", after_key)
                    .with("budget", budget),
            )
            .await?,
        )
    }

    /// Drain the whole member roster into one `Vec` (nodes then
    /// identities). Callers that need the full set — voter-set
    /// derivation, `space members`, catalog export — use this.
    pub async fn members_all<I: RegistryInvoker>(
        &self,
        inv: &mut I,
    ) -> Result<Vec<MemberRow>, ClientError> {
        let mut out = Vec::new();
        let mut kind = 0u8;
        let mut key: Vec<u8> = Vec::new();
        let mut drain = RegistryDrainBudget::default();
        loop {
            let page = self.members(inv, kind, key.clone(), 0).await?;
            let page_bytes = page.encode().len();
            if !drain.record_page(page.members.len(), page_bytes)
                || !member_page_advances(kind, &key, &page)
            {
                return Err(ClientError::Decode);
            }
            let more = page.more;
            kind = page.next_kind;
            key = page.next_key;
            out.extend(page.members);
            if !more {
                break;
            }
        }
        Ok(out)
    }

    pub async fn root<I: RegistryInvoker>(&self, inv: &mut I) -> Result<Vec<u8>, ClientError> {
        decode_bytes(self.call(inv, Msg::new("root")).await?)
    }

    // ── Auth reads ────────────────────────────────────────────────

    pub async fn peer_role<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        peer_id: Vec<u8>,
    ) -> Result<u8, ClientError> {
        let v = self
            .call(inv, Msg::new("peer_role").with("peer_id", peer_id))
            .await?;
        v.as_u8()
            .ok_or_else(|| ClientError::UnexpectedReply(alloc::format!("{v:?}")))
    }

    pub async fn peer_epoch<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        peer_id: Vec<u8>,
    ) -> Result<u64, ClientError> {
        let v = self
            .call(inv, Msg::new("peer_epoch").with("peer_id", peer_id))
            .await?;
        v.as_u64()
            .ok_or_else(|| ClientError::UnexpectedReply(alloc::format!("{v:?}")))
    }

    /// A node prefix's enrollment: `0` if not enrolled, otherwise
    /// `role + 1` (so voter/observer both read as `> 0`). Ungated —
    /// enrollment is non-secret membership metadata. Used to decide
    /// whether this node is a space member before spawning agents
    /// whose sync floor requires membership.
    pub async fn node_role<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        prefix: u64,
    ) -> Result<u8, ClientError> {
        let v = self
            .call(inv, Msg::new("node_role").with("prefix", prefix))
            .await?;
        v.as_u8()
            .ok_or_else(|| ClientError::UnexpectedReply(alloc::format!("{v:?}")))
    }

    /// One page of the effective space-level grants. Pass an empty
    /// `after_peer` to start; continue from the returned [`AuthGrantPage::next`]
    /// until it comes back empty. `budget` caps the page (0 = the
    /// registry's max).
    pub async fn auth_grants<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        after_peer: Vec<u8>,
        budget: u32,
    ) -> Result<AuthGrantPage, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("auth_grants")
                    .with("after_peer", after_peer)
                    .with("budget", budget),
            )
            .await?,
        )
    }

    // ── Genesis / catalog mutators ────────────────────────────────

    pub async fn set_root<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        root: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("set_root")
                    .with("root", root)
                    .with("schema_version", REGISTRY_SCHEMA_VERSION)
                    .with("schema_hash", REGISTRY_SCHEMA_HASH.to_vec()),
            )
            .await?,
        )
    }

    /// Anchor this space's `space_id` (first-write-wins). The daemon
    /// calls this once at boot with the id it already validated against
    /// the genesis; it lets `redeem_invite` bind the invite canonical to
    /// THIS space so an invite can't be replayed at another space the
    /// same operator runs (the genesis root alone can't distinguish them).
    pub async fn set_space_id<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        space_id: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(inv, Msg::new("set_space_id").with("space_id", space_id))
                .await?,
        )
    }

    /// This space's anchored `space_id`, or empty if never set.
    pub async fn space_id<I: RegistryInvoker>(&self, inv: &mut I) -> Result<Vec<u8>, ClientError> {
        decode_bytes(self.call(inv, Msg::new("space_id")).await?)
    }

    /// Durable guest-owned role-authority binding.
    pub async fn role_authority<I: RegistryInvoker>(
        &self,
        inv: &mut I,
    ) -> Result<Vec<u8>, ClientError> {
        decode_bytes(self.call(inv, Msg::new("role_authority")).await?)
    }

    pub async fn set_role_authority<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        authority_replication_id: Vec<u8>,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("set_role_authority")
                    .with("authority_replication_id", authority_replication_id)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn publish_service_program<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        name: String,
        hash: [u8; 32],
        crdt: bool,
        publication_id: PublicationId,
        expected_current: Option<ProgramTag>,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        let (expected_publication_id, expected_hash) = program_tag_wire(expected_current);
        decode_rkyv(
            self.call(
                inv,
                Msg::new("publish_service_program")
                    .with("name", name)
                    .with("hash", hash.to_vec())
                    .with("crdt", crdt)
                    .with("publication_id", publication_id.as_bytes().to_vec())
                    .with("expected_publication_id", expected_publication_id)
                    .with("expected_hash", expected_hash)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn publish_agent_actor_program<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        name: String,
        hash: [u8; 32],
        publication_id: PublicationId,
        expected_current: Option<ProgramTag>,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        let (expected_publication_id, expected_hash) = program_tag_wire(expected_current);
        decode_rkyv(
            self.call(
                inv,
                Msg::new("publish_agent_actor_program")
                    .with("name", name)
                    .with("hash", hash.to_vec())
                    .with("publication_id", publication_id.as_bytes().to_vec())
                    .with("expected_publication_id", expected_publication_id)
                    .with("expected_hash", expected_hash)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn register_meta<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        program_hash: Vec<u8>,
        blob: Vec<u8>,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("register_meta")
                    .with("program_hash", program_hash)
                    .with("blob", blob)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn register_extension_meta<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        instance_name: String,
        blob: Vec<u8>,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("register_extension_meta")
                    .with("instance_name", instance_name)
                    .with("blob", blob)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn unpublish_service_program<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        name: String,
        expected_current: ProgramTag,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("unpublish_service_program")
                    .with("name", name)
                    .with(
                        "expected_publication_id",
                        expected_current.publication_id.as_bytes().to_vec(),
                    )
                    .with("expected_hash", expected_current.hash.to_vec())
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn unpublish_agent_actor_program<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        name: String,
        expected_current: ProgramTag,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("unpublish_agent_actor_program")
                    .with("name", name)
                    .with(
                        "expected_publication_id",
                        expected_current.publication_id.as_bytes().to_vec(),
                    )
                    .with("expected_hash", expected_current.hash.to_vec())
                    .with("auth", auth),
            )
            .await?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn install_service_actor<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        instance_name: String,
        program_name: String,
        program: ProgramTag,
        installation_id: InstallationId,
        replication_id: [u8; 32],
        consistency: u8,
        network_reachable: bool,
        sync_role: SyncFloor,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("install_service_actor")
                    .with("instance_name", instance_name)
                    .with("program_name", program_name)
                    .with("program_hash", program.hash.to_vec())
                    .with(
                        "program_publication_id",
                        program.publication_id.as_bytes().to_vec(),
                    )
                    .with("installation_id", installation_id.as_bytes().to_vec())
                    .with("replication_id", replication_id.to_vec())
                    .with("consistency", consistency)
                    .with("network_reachable", network_reachable)
                    .with("sync_role", sync_role as u8)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    /// Record a root-attested receipt returned by the Local Agent Host. The
    /// public wire carries no loose caller-selected `AgentId` or `ActorId`.
    pub async fn install_system_actor<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        receipt: SystemActorInstallReceipt,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        let receipt = receipt.encode();
        decode_rkyv(
            self.call(
                inv,
                Msg::new("install_system_actor")
                    .with("receipt", receipt)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_service_actor<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        instance_name: String,
        installation_id: InstallationId,
        expected_revision: u64,
        from_program: ProgramTag,
        new_program_name: String,
        new_program: ProgramTag,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("upgrade_service_actor")
                    .with("instance_name", instance_name)
                    .with("installation_id", installation_id.as_bytes().to_vec())
                    .with("expected_revision", expected_revision)
                    .with("from_program_hash", from_program.hash.to_vec())
                    .with(
                        "from_program_publication_id",
                        from_program.publication_id.as_bytes().to_vec(),
                    )
                    .with("new_program_name", new_program_name)
                    .with("new_program_hash", new_program.hash.to_vec())
                    .with(
                        "new_program_publication_id",
                        new_program.publication_id.as_bytes().to_vec(),
                    )
                    .with("auth", auth),
            )
            .await?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_system_actor<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        instance_name: String,
        installation_id: InstallationId,
        expected_revision: u64,
        from_program: ProgramTag,
        new_program_name: String,
        new_program: ProgramTag,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("upgrade_system_actor")
                    .with("instance_name", instance_name)
                    .with("installation_id", installation_id.as_bytes().to_vec())
                    .with("expected_revision", expected_revision)
                    .with("from_program_hash", from_program.hash.to_vec())
                    .with(
                        "from_program_publication_id",
                        from_program.publication_id.as_bytes().to_vec(),
                    )
                    .with("new_program_name", new_program_name)
                    .with("new_program_hash", new_program.hash.to_vec())
                    .with(
                        "new_program_publication_id",
                        new_program.publication_id.as_bytes().to_vec(),
                    )
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn uninstall_service_actor<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        instance_name: String,
        installation_id: InstallationId,
        expected_revision: u64,
        expected_program: ProgramTag,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("uninstall_service_actor")
                    .with("instance_name", instance_name)
                    .with("installation_id", installation_id.as_bytes().to_vec())
                    .with("expected_revision", expected_revision)
                    .with("expected_program_hash", expected_program.hash.to_vec())
                    .with(
                        "expected_program_publication_id",
                        expected_program.publication_id.as_bytes().to_vec(),
                    )
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn uninstall_system_actor<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        instance_name: String,
        installation_id: InstallationId,
        expected_revision: u64,
        expected_program: ProgramTag,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("uninstall_system_actor")
                    .with("instance_name", instance_name)
                    .with("installation_id", installation_id.as_bytes().to_vec())
                    .with("expected_revision", expected_revision)
                    .with("expected_program_hash", expected_program.hash.to_vec())
                    .with(
                        "expected_program_publication_id",
                        expected_program.publication_id.as_bytes().to_vec(),
                    )
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn add_node<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        prefix: u32,
        peer_id: Vec<u8>,
        role: u8,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("add_node")
                    .with("prefix", prefix)
                    .with("peer_id", peer_id)
                    .with("role", role)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn remove_node<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        prefix: u32,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("remove_node")
                    .with("prefix", prefix)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn add_identity<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        public_key: Vec<u8>,
        proof_kind: u8,
        proof_data: Vec<u8>,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("add_identity")
                    .with("public_key", public_key)
                    .with("proof_kind", proof_kind)
                    .with("proof_data", proof_data)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn remove_identity<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        public_key: Vec<u8>,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("remove_identity")
                    .with("public_key", public_key)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn grant_role<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        peer_id: Vec<u8>,
        role: u8,
        epoch: u64,
        authority_replication_id: Vec<u8>,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("grant_role")
                    .with("peer_id", peer_id)
                    .with("role", role)
                    .with("epoch", epoch)
                    .with("authority_replication_id", authority_replication_id)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn revoke_role<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        peer_id: Vec<u8>,
        epoch: u64,
        authority_replication_id: Vec<u8>,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("revoke_role")
                    .with("peer_id", peer_id)
                    .with("epoch", epoch)
                    .with("authority_replication_id", authority_replication_id)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn register_remote<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        instance_name: String,
        host_prefix: u32,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("register_remote")
                    .with("instance_name", instance_name)
                    .with("host_prefix", host_prefix)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    // ── Invites ───────────────────────────────────────────────────

    /// Redeem an invite token: grant `role` to `peer_id`. Deliberately
    /// unauthenticated — the carried signatures ARE the auth. The handler
    /// verifies `admin_sig` over the invite canonical (`invite`,
    /// `[space_id, [role], expires_le, token_pub]`) under `admin_peer_id`
    /// (a current-epoch effective admin), `redeem_sig` (token possession)
    /// under `token_pub`, and `node_sig` (peer-id control) under
    /// `peer_id` — both over (`redeem_invite`, `[token_pub, peer_id]`).
    /// The invite canonical binds the actor's own anchored `space_id`
    /// (set via `set_space_id`), not a caller-supplied value. No expiry
    /// check happens here (checked host-side at admission).
    #[allow(clippy::too_many_arguments)]
    pub async fn redeem_invite<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        token_pub: Vec<u8>,
        role: u8,
        expires_at: u64,
        authority_replication_id: Vec<u8>,
        admin_peer_id: Vec<u8>,
        admin_sig: Vec<u8>,
        peer_id: Vec<u8>,
        redeem_sig: Vec<u8>,
        node_sig: Vec<u8>,
        authority_attestation: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("redeem_invite")
                    .with("token_pub", token_pub)
                    .with("role", role)
                    .with("expires_at", expires_at)
                    .with("authority_replication_id", authority_replication_id)
                    .with("admin_peer_id", admin_peer_id)
                    .with("admin_sig", admin_sig)
                    .with("peer_id", peer_id)
                    .with("redeem_sig", redeem_sig)
                    .with("node_sig", node_sig)
                    .with("authority_attestation", authority_attestation),
            )
            .await?,
        )
    }

    /// Revoke an invite token (admin-signed). Grow-only: flips the
    /// token's `revoked` flag so no future redemption succeeds and no
    /// replayed redeem can clear it. Idempotent.
    pub async fn revoke_invite<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        token_pub: Vec<u8>,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("revoke_invite")
                    .with("token_pub", token_pub)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    /// One page of the invites table. Pass an empty `after` to start;
    /// continue from the returned [`InvitePage::next`] until it comes
    /// back empty. `budget` caps the page (0 = the registry's max).
    pub async fn invites<I: RegistryInvoker>(
        &self,
        inv: &mut I,
        after: Vec<u8>,
        budget: u32,
    ) -> Result<InvitePage, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("invites")
                    .with("after", after)
                    .with("budget", budget),
            )
            .await?,
        )
    }

    /// Drain the complete invite table while enforcing its natural-key cursor
    /// contract and the same finite whole-table bounds as other administrative
    /// registry views.
    pub async fn invites_all<I: RegistryInvoker>(
        &self,
        inv: &mut I,
    ) -> Result<Vec<InviteRow>, ClientError> {
        let mut out = Vec::new();
        let mut after = Vec::new();
        let mut drain = RegistryDrainBudget::default();
        loop {
            let page = self.invites(inv, after.clone(), 0).await?;
            let page_bytes = page.encode().len();
            if !drain.record_page(page.invites.len(), page_bytes)
                || !invite_page_advances(&after, &page)
            {
                return Err(ClientError::Decode);
            }
            let next = page.next;
            out.extend(page.invites);
            if next.is_empty() {
                return Ok(out);
            }
            after = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decode as _;

    #[test]
    fn registry_schema_hash_is_reproducible_from_semantic_preimage() {
        assert_eq!(
            crate::crypto::blake2b_hash::<32>(REGISTRY_SCHEMA_PREIMAGE, &[]),
            REGISTRY_SCHEMA_HASH,
        );
        let preimage = core::str::from_utf8(REGISTRY_SCHEMA_PREIMAGE).expect("ASCII preimage");
        for required in [
            "versioned-genesis-root-wire",
            "space-bound-registry-mutation-auth",
            "authenticated-register-remote",
            "canonical-slugs",
            "shared-instance-namespace",
            "exact-space-anchor",
            "canonical-auth-peer-and-role-shapes",
            "lossless-u16-prefix-queries",
            "host-lifecycle-required",
        ] {
            assert!(
                preimage.contains(required),
                "schema preimage must commit to {required}",
            );
        }
    }

    #[test]
    fn auth_role_shape_predicates_are_fail_closed() {
        for role in [
            AUTH_ROLE_NONE,
            AUTH_ROLE_READONLY,
            AUTH_ROLE_DEVELOPER,
            AUTH_ROLE_ADMIN,
        ] {
            assert!(is_defined_auth_role(role));
        }
        for role in [AUTH_ROLE_ADMIN + 1, u8::MAX] {
            assert!(!is_defined_auth_role(role));
            assert!(!is_grantable_auth_role(role));
            assert!(!is_offline_invite_role(role));
        }

        assert!(!is_grantable_auth_role(AUTH_ROLE_NONE));
        for role in [AUTH_ROLE_READONLY, AUTH_ROLE_DEVELOPER, AUTH_ROLE_ADMIN] {
            assert!(is_grantable_auth_role(role));
        }

        assert!(!is_offline_invite_role(AUTH_ROLE_NONE));
        assert!(is_offline_invite_role(AUTH_ROLE_READONLY));
        assert!(is_offline_invite_role(AUTH_ROLE_DEVELOPER));
        assert!(!is_offline_invite_role(AUTH_ROLE_ADMIN));
    }

    #[test]
    fn canonical_registry_slug_has_one_byte_level_definition() {
        for valid in ["a", "0", "agent-01", "a--b"] {
            assert!(is_canonical_registry_slug(valid));
        }
        for invalid in ["", "-agent", "agent-", "Agent", "agent_actor", "é"] {
            assert!(!is_canonical_registry_slug(invalid));
        }
        assert!(is_canonical_registry_slug(&"a".repeat(63)));
        assert!(!is_canonical_registry_slug(&"a".repeat(64)));
    }

    struct ReplyQueue {
        replies: Vec<Value>,
    }

    impl ReplyQueue {
        fn pages(replies: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                replies: replies.into_iter().map(Value::Bytes).collect::<Vec<_>>(),
            }
        }
    }

    impl RegistryInvoker for ReplyQueue {
        async fn invoke_registry(
            &mut self,
            target: ServiceId,
            payload: Vec<u8>,
        ) -> Result<Value, ClientError> {
            assert_eq!(target, ServiceId::REGISTRY);
            assert_eq!(payload.first(), Some(&TAG_DYNAMIC));
            assert!(
                !self.replies.is_empty(),
                "registry client over-drained replies"
            );
            Ok(self.replies.remove(0))
        }
    }

    fn stale_protocol() -> RegistryProtocol {
        RegistryProtocol {
            version: REGISTRY_SCHEMA_VERSION,
            schema_hash: [0xFF; 32],
        }
    }

    fn dynamic_payload(message: Msg) -> Vec<u8> {
        let mut payload = alloc::vec![TAG_DYNAMIC];
        payload.extend_from_slice(&message.encode());
        payload
    }

    fn test_peer() -> Vec<u8> {
        let mut peer = alloc::vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
        peer.extend_from_slice(&[42; 32]);
        peer
    }

    #[test]
    fn catalog_ingress_extracts_one_embedded_signer_without_reencoding() {
        let peer = test_peer();
        let auth = pack_auth(&peer, &[0xAB; OP_SIG_LEN]);
        for method in [
            "publish_service_program",
            "publish_agent_actor_program",
            "unpublish_service_program",
            "unpublish_agent_actor_program",
            "install_service_actor",
            "install_system_actor",
            "uninstall_service_actor",
            "uninstall_system_actor",
            "upgrade_service_actor",
            "upgrade_system_actor",
            "register_meta",
            "register_extension_meta",
        ] {
            let payload = dynamic_payload(Msg::new(method).with("auth", auth.clone()));
            let unchanged = payload.clone();
            assert_eq!(catalog_op_auth_signer(&payload), Ok(Some(peer.clone())));
            assert_eq!(payload, unchanged, "ingress peek must preserve exact bytes");
        }
    }

    #[test]
    fn catalog_ingress_rejects_missing_duplicate_or_malformed_auth() {
        let peer = test_peer();
        let valid = pack_auth(&peer, &[0xAB; OP_SIG_LEN]);
        let cases = [
            Msg::new("publish_service_program"),
            Msg::new("publish_service_program").with("auth", Vec::<u8>::new()),
            Msg::new("publish_service_program").with("auth", "not bytes"),
            Msg::new("publish_service_program").with("auth", alloc::vec![0u8; OP_SIG_LEN + 1]),
            Msg::new("publish_service_program")
                .with("auth", valid.clone())
                .with("auth", valid),
        ];
        for message in cases {
            assert_eq!(catalog_op_auth_signer(&dynamic_payload(message)), Err(()));
        }
    }

    #[test]
    fn catalog_ingress_ignores_only_well_formed_non_catalog_payloads() {
        assert_eq!(
            catalog_op_auth_signer(&dynamic_payload(Msg::new("agents"))),
            Ok(None),
        );
        assert_eq!(catalog_op_auth_signer(&[1, 2, 3]), Ok(None));
        assert_eq!(catalog_op_auth_signer(&[TAG_DYNAMIC]), Err(()));
        assert_eq!(catalog_op_auth_signer(&[TAG_DYNAMIC, 1, 2, 3]), Err(()));
        for removed in ["publish", "unpublish", "install", "uninstall", "upgrade"] {
            assert_eq!(
                catalog_op_auth_signer(&dynamic_payload(Msg::new(removed))),
                Ok(None),
                "removed v1 verbs are not reinterpreted as v2 mutations",
            );
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn node_registry_reply_uses_checked_outer_value_decoding() {
        assert!(matches!(
            decode_node_registry_reply(Some(vec![1, 2, 3])),
            Err(ClientError::Decode)
        ));
        assert!(matches!(
            decode_node_registry_reply(Some(vec![crate::STATUS_FORBIDDEN, 0, 0, 0, 0])),
            Err(ClientError::Forbidden)
        ));
        assert!(matches!(
            decode_node_registry_reply(None),
            Err(ClientError::Unreachable)
        ));
        assert_eq!(
            decode_node_registry_reply(Some(Value::U64(7).encode())).unwrap(),
            Value::U64(7),
        );
    }

    #[test]
    fn ed25519_pubkey_extracts_from_valid_peer_id() {
        let mut pid = alloc::vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
        pid.extend_from_slice(&[42u8; 32]);
        assert_eq!(ed25519_pubkey_from_peer_id(&pid), Some([42u8; 32]));
        assert!(ed25519_pubkey_from_peer_id(&[0u8; 10]).is_none());
    }

    #[test]
    fn canonical_ops_bind_protocol_and_distinct_program_kinds() {
        let space_id = [0xa1; 32];
        let service = publish_service_program_signed_bytes(
            &space_id,
            "worker",
            &[1; 32],
            false,
            &[2; 32],
            &[],
            &[],
        );
        let agent = publish_agent_actor_program_signed_bytes(
            &space_id,
            "worker",
            &[1; 32],
            &[2; 32],
            &[],
            &[],
        );
        assert_ne!(
            service, agent,
            "kind-specific verbs must not share signatures"
        );
        assert!(service.starts_with(REGISTRY_MUTATION_DOMAIN));
        let version_offset = REGISTRY_MUTATION_DOMAIN.len();
        assert_eq!(
            &service[version_offset..version_offset + 4],
            &REGISTRY_SCHEMA_VERSION.to_le_bytes(),
        );
        assert_eq!(
            &service[version_offset + 4..version_offset + 36],
            &REGISTRY_SCHEMA_HASH,
        );
        assert_eq!(
            &service[version_offset + 36..version_offset + 68],
            &space_id,
        );

        let invite = invite_signed_bytes(&space_id, 1, 7, &[4; 32], &[5; 32]);
        assert!(invite.starts_with(REGISTRY_MUTATION_DOMAIN));
        assert_eq!(
            &invite[version_offset + 4..version_offset + 36],
            &REGISTRY_SCHEMA_HASH,
            "invite credentials are pinned to the registry schema",
        );

        let upgrade_revision_0 = upgrade_service_actor_signed_bytes(
            &space_id,
            "worker",
            &[6; 32],
            0,
            &[7; 32],
            &[8; 32],
            "worker-v2",
            &[9; 32],
            &[10; 32],
        );
        let upgrade_revision_2 = upgrade_service_actor_signed_bytes(
            &space_id,
            "worker",
            &[6; 32],
            2,
            &[7; 32],
            &[8; 32],
            "worker-v2",
            &[9; 32],
            &[10; 32],
        );
        assert_ne!(
            upgrade_revision_0, upgrade_revision_2,
            "upgrade signatures bind the exact live installation revision",
        );

        let sibling = publish_service_program_signed_bytes(
            &[0xb2; 32],
            "worker",
            &[1; 32],
            false,
            &[2; 32],
            &[],
            &[],
        );
        assert_ne!(
            service, sibling,
            "otherwise identical mutation preimages must differ across spaces",
        );
    }

    #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    #[rkyv(crate = rkyv)]
    struct V1ProgramRow {
        name: String,
        hash: [u8; 32],
        crdt: bool,
    }

    #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    #[rkyv(crate = rkyv)]
    struct V1ProgramPage {
        rows: Vec<V1ProgramRow>,
        more: bool,
    }

    #[test]
    fn v1_program_wire_does_not_decode_as_typed_v2_wire() {
        let old_row = V1ProgramRow {
            name: "legacy".into(),
            hash: [7; 32],
            crdt: true,
        };
        assert!(ProgramRow::try_decode(&old_row.encode()).is_none());
        let old_lookup = Some(old_row).encode();
        assert!(ProgramLookup::try_decode(&old_lookup).is_none());

        let old_page = V1ProgramPage {
            rows: Vec::new(),
            more: false,
        }
        .encode();
        assert!(ProgramPage::try_decode(&old_page).is_none());

        let current_lookup = ProgramLookup {
            protocol: RegistryProtocol::CURRENT,
            row: Some(ProgramRow {
                name: "current".into(),
                hash: [8; 32],
                publication_id: PublicationId::new([9; 32]),
                kind: ProgramKind::AgentActor,
            }),
        };
        assert!(Option::<V1ProgramRow>::try_decode(&current_lookup.encode()).is_none());
        // rkyv intentionally permits some older prefix-shaped structs to
        // ignore newer trailing fields. The actor therefore exposes this
        // page only on the new `catalog_programs` verb; its v1 `programs`
        // verb is absent, rather than relying on a decoder accident.
    }

    #[test]
    fn typed_id_and_row_round_trip_without_runtime_id_aliasing() {
        let installation = InstallationId::new([0x11; 32]);
        let agent = AgentId::new([0x12; 32]);
        let actor = ActorId::top_level(agent, "worker");
        assert_ne!(installation.as_bytes(), agent.as_bytes());
        assert_ne!(installation.as_bytes(), actor.as_bytes());
        let receipt = SystemActorInstallReceipt {
            protocol: RegistryProtocol::CURRENT,
            installation_id: installation,
            system_agent_id: agent,
            actor_id: actor,
            instance_name: "worker".into(),
            program_name: "program".into(),
            program_hash: [0x13; 32],
            program_publication_id: PublicationId::new([0x14; 32]),
            host_receipt: vec![0x15, 0x16],
        };
        assert_eq!(
            SystemActorInstallReceipt::try_decode(&receipt.encode()),
            Some(receipt),
        );
    }

    #[test]
    fn typed_registry_drains_reject_stale_protocol_pages() {
        let registry = RegistryRef::at(ServiceId::REGISTRY);

        let mut programs = ReplyQueue::pages([ProgramPage {
            protocol: stale_protocol(),
            rows: Vec::new(),
            more: false,
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.programs_all(&mut programs)),
            Err(ClientError::UnexpectedReply(_))
        ));

        let mut agents = ReplyQueue::pages([AgentPage {
            protocol: stale_protocol(),
            rows: Vec::new(),
            more: false,
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.agents_all(&mut agents)),
            Err(ClientError::UnexpectedReply(_))
        ));

        let mut system_actors = ReplyQueue::pages([SystemActorPage {
            protocol: stale_protocol(),
            rows: Vec::new(),
            more: false,
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.system_actors_all(&mut system_actors)),
            Err(ClientError::UnexpectedReply(_))
        ));

        let mut names = ReplyQueue::pages([AgentNamePage {
            protocol: stale_protocol(),
            names: Vec::new(),
            more: false,
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.agent_names_all(&mut names)),
            Err(ClientError::UnexpectedReply(_))
        ));
    }

    #[test]
    fn registry_protocol_handshake_accepts_only_the_exact_schema() {
        let registry = RegistryRef::at(ServiceId::REGISTRY);
        let mut current = ReplyQueue::pages([RegistryProtocol::CURRENT.encode()]);
        assert_eq!(
            crate::block_on(registry.protocol(&mut current)).unwrap(),
            RegistryProtocol::CURRENT,
        );

        let mut stale = ReplyQueue::pages([stale_protocol().encode()]);
        assert!(matches!(
            crate::block_on(registry.protocol(&mut stale)),
            Err(ClientError::UnexpectedReply(_))
        ));
    }

    #[test]
    fn typed_registry_drains_reject_empty_advancing_pages() {
        let registry = RegistryRef::at(ServiceId::REGISTRY);

        let mut programs = ReplyQueue::pages([ProgramPage {
            protocol: RegistryProtocol::CURRENT,
            rows: Vec::new(),
            more: true,
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.programs_all(&mut programs)),
            Err(ClientError::Decode)
        ));

        let mut agents = ReplyQueue::pages([AgentPage {
            protocol: RegistryProtocol::CURRENT,
            rows: Vec::new(),
            more: true,
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.agents_all(&mut agents)),
            Err(ClientError::Decode)
        ));

        let mut system_actors = ReplyQueue::pages([SystemActorPage {
            protocol: RegistryProtocol::CURRENT,
            rows: Vec::new(),
            more: true,
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.system_actors_all(&mut system_actors)),
            Err(ClientError::Decode)
        ));

        let mut names = ReplyQueue::pages([AgentNamePage {
            protocol: RegistryProtocol::CURRENT,
            names: Vec::new(),
            more: true,
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.agent_names_all(&mut names)),
            Err(ClientError::Decode)
        ));
    }

    #[test]
    fn typed_registry_drains_reject_malformed_page_replies() {
        let registry = RegistryRef::at(ServiceId::REGISTRY);

        let mut programs = ReplyQueue {
            replies: vec![Value::Unit],
        };
        assert!(matches!(
            crate::block_on(registry.programs_all(&mut programs)),
            Err(ClientError::UnexpectedReply(_))
        ));

        let mut agents = ReplyQueue::pages([vec![1, 2, 3]]);
        assert!(matches!(
            crate::block_on(registry.agents_all(&mut agents)),
            Err(ClientError::Decode)
        ));

        let mut system_actors = ReplyQueue {
            replies: vec![Value::Str("not a page".into())],
        };
        assert!(matches!(
            crate::block_on(registry.system_actors_all(&mut system_actors)),
            Err(ClientError::UnexpectedReply(_))
        ));

        let mut names = ReplyQueue::pages([Vec::new()]);
        assert!(matches!(
            crate::block_on(registry.agent_names_all(&mut names)),
            Err(ClientError::Decode)
        ));
    }

    #[test]
    fn registry_name_drain_rejects_a_repeated_cursor() {
        let registry = RegistryRef::at(ServiceId::REGISTRY);
        let mut replies = ReplyQueue::pages([
            AgentNamePage {
                protocol: RegistryProtocol::CURRENT,
                names: vec!["alpha".into()],
                more: true,
            }
            .encode(),
            AgentNamePage {
                protocol: RegistryProtocol::CURRENT,
                names: vec!["alpha".into()],
                more: false,
            }
            .encode(),
        ]);
        assert!(matches!(
            crate::block_on(registry.agent_names_all(&mut replies)),
            Err(ClientError::Decode)
        ));
    }

    #[test]
    fn typed_registry_drains_reject_nonadvancing_or_unsorted_rows() {
        let registry = RegistryRef::at(ServiceId::REGISTRY);

        let program = |name: &str, byte: u8| ProgramRow {
            name: name.into(),
            hash: [byte; 32],
            publication_id: PublicationId::new([byte.wrapping_add(1); 32]),
            kind: ProgramKind::Service { crdt: false },
        };
        let mut programs = ReplyQueue::pages([
            ProgramPage {
                protocol: RegistryProtocol::CURRENT,
                rows: vec![program("alpha", 1)],
                more: true,
            }
            .encode(),
            ProgramPage {
                protocol: RegistryProtocol::CURRENT,
                rows: vec![program("alpha", 2)],
                more: false,
            }
            .encode(),
        ]);
        assert!(matches!(
            crate::block_on(registry.programs_all(&mut programs)),
            Err(ClientError::Decode)
        ));

        let agent = |name: &str, byte: u8| AgentRow {
            instance_name: name.into(),
            installation_id: InstallationId::new([byte; 32]),
            revision: 0,
            program_hash: [byte.wrapping_add(1); 32],
            program_name: "worker-program".into(),
            program_publication_id: PublicationId::new([byte.wrapping_add(2); 32]),
            replication_id: [byte.wrapping_add(3); 32],
            consistency: 1,
            network_reachable: false,
            sync_role: SyncFloor::Member,
        };
        let mut agents = ReplyQueue::pages([AgentPage {
            protocol: RegistryProtocol::CURRENT,
            rows: vec![agent("beta", 3), agent("alpha", 4)],
            more: false,
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.agents_all(&mut agents)),
            Err(ClientError::Decode)
        ));

        let system_actor = |name: &str, byte: u8| SystemActorRow {
            instance_name: name.into(),
            installation_id: InstallationId::new([byte; 32]),
            revision: 0,
            system_agent_id: AgentId::new([byte.wrapping_add(1); 32]),
            actor_id: ActorId::new([byte.wrapping_add(2); 32]),
            program_hash: [byte.wrapping_add(3); 32],
            program_name: "worker-program".into(),
            program_publication_id: PublicationId::new([byte.wrapping_add(4); 32]),
            host_receipt_hash: [byte.wrapping_add(5); 32],
        };
        let mut system_actors = ReplyQueue::pages([
            SystemActorPage {
                protocol: RegistryProtocol::CURRENT,
                rows: vec![system_actor("alpha", 5)],
                more: true,
            }
            .encode(),
            SystemActorPage {
                protocol: RegistryProtocol::CURRENT,
                rows: vec![system_actor("alpha", 6)],
                more: false,
            }
            .encode(),
        ]);
        assert!(matches!(
            crate::block_on(registry.system_actors_all(&mut system_actors)),
            Err(ClientError::Decode)
        ));
    }

    #[test]
    fn typed_registry_drains_reject_noncanonical_row_names() {
        let registry = RegistryRef::at(ServiceId::REGISTRY);
        let mut programs = ReplyQueue::pages([ProgramPage {
            protocol: RegistryProtocol::CURRENT,
            rows: vec![ProgramRow {
                name: "Bad_Name".into(),
                hash: [1; 32],
                publication_id: PublicationId::new([2; 32]),
                kind: ProgramKind::Service { crdt: false },
            }],
            more: false,
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.programs_all(&mut programs)),
            Err(ClientError::Decode)
        ));

        let service_row = |instance_name: &str, program_name: &str| AgentRow {
            instance_name: instance_name.into(),
            installation_id: InstallationId::new([3; 32]),
            revision: 0,
            program_hash: [4; 32],
            program_name: program_name.into(),
            program_publication_id: PublicationId::new([5; 32]),
            replication_id: [6; 32],
            consistency: 1,
            network_reachable: false,
            sync_role: SyncFloor::Member,
        };
        let mut agents = ReplyQueue::pages([AgentPage {
            protocol: RegistryProtocol::CURRENT,
            rows: vec![service_row("worker", "BadProgram")],
            more: false,
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.agents_all(&mut agents)),
            Err(ClientError::Decode)
        ));

        let mut system_actors = ReplyQueue::pages([SystemActorPage {
            protocol: RegistryProtocol::CURRENT,
            rows: vec![SystemActorRow {
                instance_name: "bad/name".into(),
                installation_id: InstallationId::new([7; 32]),
                revision: 0,
                system_agent_id: AgentId::new([8; 32]),
                actor_id: ActorId::new([9; 32]),
                program_hash: [10; 32],
                program_name: "worker-program".into(),
                program_publication_id: PublicationId::new([11; 32]),
                host_receipt_hash: [12; 32],
            }],
            more: false,
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.system_actors_all(&mut system_actors)),
            Err(ClientError::Decode)
        ));

        let mut names = ReplyQueue::pages([AgentNamePage {
            protocol: RegistryProtocol::CURRENT,
            names: vec!["é".into()],
            more: false,
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.agent_names_all(&mut names)),
            Err(ClientError::Decode)
        ));
    }

    #[test]
    fn point_lookups_reject_rows_with_the_wrong_natural_key_or_name_shape() {
        let registry = RegistryRef::at(ServiceId::REGISTRY);
        let program = |name: &str, hash: [u8; 32]| ProgramRow {
            name: name.into(),
            hash,
            publication_id: PublicationId::new([0x21; 32]),
            kind: ProgramKind::Service { crdt: false },
        };
        let agent = |instance_name: &str, program_name: &str| AgentRow {
            instance_name: instance_name.into(),
            installation_id: InstallationId::new([0x31; 32]),
            revision: 0,
            program_hash: [0x32; 32],
            program_name: program_name.into(),
            program_publication_id: PublicationId::new([0x33; 32]),
            replication_id: [0x34; 32],
            consistency: 1,
            network_reachable: false,
            sync_role: SyncFloor::Member,
        };

        let mut wrong_program_name = ReplyQueue::pages([ProgramLookup {
            protocol: RegistryProtocol::CURRENT,
            row: Some(program("beta", [0x11; 32])),
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.program(&mut wrong_program_name, "alpha".into())),
            Err(ClientError::Decode)
        ));

        let mut wrong_program_hash = ReplyQueue::pages([ProgramLookup {
            protocol: RegistryProtocol::CURRENT,
            row: Some(program("alpha", [0x12; 32])),
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.program_by_hash(&mut wrong_program_hash, vec![0x11; 32],)),
            Err(ClientError::Decode)
        ));

        let mut wrong_agent_name = ReplyQueue::pages([AgentLookup {
            protocol: RegistryProtocol::CURRENT,
            row: Some(agent("other", "worker-program")),
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.agent(&mut wrong_agent_name, "worker".into())),
            Err(ClientError::Decode)
        ));

        let mut bad_agent_program = ReplyQueue::pages([AgentLookup {
            protocol: RegistryProtocol::CURRENT,
            row: Some(agent("worker", "Bad_Program")),
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.agent(&mut bad_agent_program, "worker".into())),
            Err(ClientError::Decode)
        ));

        let system_row = SystemActorRow {
            instance_name: "other".into(),
            installation_id: InstallationId::new([0x41; 32]),
            revision: 0,
            system_agent_id: AgentId::new([0x42; 32]),
            actor_id: ActorId::new([0x43; 32]),
            program_hash: [0x44; 32],
            program_name: "worker-program".into(),
            program_publication_id: PublicationId::new([0x45; 32]),
            host_receipt_hash: [0x46; 32],
        };
        let mut wrong_system_name = ReplyQueue::pages([SystemActorLookup {
            protocol: RegistryProtocol::CURRENT,
            row: Some(system_row),
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.system_actor(&mut wrong_system_name, "worker".into())),
            Err(ClientError::Decode)
        ));

        let mut wrong_pattern = ReplyQueue::pages([AgentLookup {
            protocol: RegistryProtocol::CURRENT,
            row: Some(agent("worker", "worker-program")),
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.agent_by_pattern(
                &mut wrong_pattern,
                "prefix-".into(),
                "-suffix".into(),
            )),
            Err(ClientError::Decode)
        ));
    }

    fn node_member(prefix: u16) -> MemberRow {
        MemberRow {
            kind: MEMBER_KIND_NODE,
            key: vec![prefix as u8 + 1],
            prefix,
            role: NODE_ROLE_VOTER,
            proof_kind: 0,
            proof_data: Vec::new(),
        }
    }

    fn identity_member(key: u8) -> MemberRow {
        MemberRow {
            kind: MEMBER_KIND_IDENTITY,
            key: vec![key],
            prefix: 0,
            role: 0,
            proof_kind: PROOF_KIND_MERKLE_INCLUSION,
            proof_data: vec![0xA5],
        }
    }

    #[test]
    fn member_drain_accepts_the_exact_two_phase_cursor_contract() {
        let registry = RegistryRef::at(ServiceId::REGISTRY);
        let mut identities = vec![identity_member(1), identity_member(2)];
        identities.sort_by_key(|row| identity_member_cursor(&row.key));
        let expected_identities = identities.clone();
        let mut replies = ReplyQueue::pages([
            MemberPage {
                members: vec![node_member(1), node_member(2)],
                next_kind: MEMBER_KIND_IDENTITY,
                next_key: Vec::new(),
                more: true,
            }
            .encode(),
            MemberPage {
                members: identities,
                next_kind: MEMBER_KIND_NODE,
                next_key: Vec::new(),
                more: false,
            }
            .encode(),
        ]);
        let drained = crate::block_on(registry.members_all(&mut replies)).unwrap();
        assert_eq!(&drained[..2], &[node_member(1), node_member(2)]);
        assert_eq!(&drained[2..], expected_identities.as_slice());
    }

    #[test]
    fn member_drain_rejects_empty_more_repeated_unsorted_and_malformed_pages() {
        let registry = RegistryRef::at(ServiceId::REGISTRY);

        let mut empty_more = ReplyQueue::pages([MemberPage {
            members: Vec::new(),
            next_kind: MEMBER_KIND_IDENTITY,
            next_key: Vec::new(),
            more: true,
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.members_all(&mut empty_more)),
            Err(ClientError::Decode)
        ));

        let mut repeated = ReplyQueue::pages([
            MemberPage {
                members: vec![node_member(1)],
                next_kind: MEMBER_KIND_NODE,
                next_key: 1_u16.to_be_bytes().to_vec(),
                more: true,
            }
            .encode(),
            MemberPage {
                members: vec![node_member(1)],
                next_kind: MEMBER_KIND_IDENTITY,
                next_key: Vec::new(),
                more: true,
            }
            .encode(),
        ]);
        assert!(matches!(
            crate::block_on(registry.members_all(&mut repeated)),
            Err(ClientError::Decode)
        ));

        let mut identities = vec![identity_member(1), identity_member(2)];
        identities.sort_by_key(|row| core::cmp::Reverse(identity_member_cursor(&row.key)));
        assert!(!member_page_advances(
            MEMBER_KIND_IDENTITY,
            &[],
            &MemberPage {
                members: identities,
                next_kind: MEMBER_KIND_NODE,
                next_key: Vec::new(),
                more: false,
            },
        ));

        let mut malformed = ReplyQueue::pages([vec![1, 2, 3]]);
        assert!(matches!(
            crate::block_on(registry.members_all(&mut malformed)),
            Err(ClientError::Decode)
        ));
    }

    fn invite(token: u8) -> InviteRow {
        InviteRow {
            token_pub: [token; 32],
            role: AUTH_ROLE_READONLY,
            expires_at: 42,
            redeemed_by: vec![vec![token]],
            revoked: false,
        }
    }

    #[test]
    fn invite_drain_enforces_natural_key_progress_order_and_empty_more() {
        let registry = RegistryRef::at(ServiceId::REGISTRY);
        let mut valid = ReplyQueue::pages([
            InvitePage {
                invites: vec![invite(1)],
                next: vec![1; 32],
            }
            .encode(),
            InvitePage {
                invites: vec![invite(2)],
                next: Vec::new(),
            }
            .encode(),
        ]);
        assert_eq!(
            crate::block_on(registry.invites_all(&mut valid)).unwrap(),
            vec![invite(1), invite(2)],
        );

        let mut empty_more = ReplyQueue::pages([InvitePage {
            invites: Vec::new(),
            next: vec![1; 32],
        }
        .encode()]);
        assert!(matches!(
            crate::block_on(registry.invites_all(&mut empty_more)),
            Err(ClientError::Decode)
        ));

        let mut repeated = ReplyQueue::pages([
            InvitePage {
                invites: vec![invite(1)],
                next: vec![1; 32],
            }
            .encode(),
            InvitePage {
                invites: vec![invite(1)],
                next: Vec::new(),
            }
            .encode(),
        ]);
        assert!(matches!(
            crate::block_on(registry.invites_all(&mut repeated)),
            Err(ClientError::Decode)
        ));

        assert!(!invite_page_advances(
            &[],
            &InvitePage {
                invites: vec![invite(2), invite(1)],
                next: Vec::new(),
            },
        ));

        let mut malformed = ReplyQueue::pages([vec![1, 2, 3]]);
        assert!(matches!(
            crate::block_on(registry.invites_all(&mut malformed)),
            Err(ClientError::Decode)
        ));
    }

    #[test]
    fn whole_table_registry_budget_checks_pages_rows_bytes_and_overflow() {
        assert_eq!(REGISTRY_DRAIN_MAX_PAGES * 128, REGISTRY_DRAIN_MAX_ROWS);
        assert_eq!(REGISTRY_DRAIN_MAX_BYTES, 8 * 1024 * 1024);

        let mut exact = RegistryDrainBudget::with_limits(2, 3, 5);
        assert!(exact.record_page(2, 3));
        assert!(exact.record_page(1, 2));
        assert!(!exact.record_page(0, 0));

        let mut rows = RegistryDrainBudget::with_limits(2, 1, 8);
        assert!(!rows.record_page(2, 1));
        assert!(rows.record_page(1, 1));
        let mut bytes = RegistryDrainBudget::with_limits(2, 8, 1);
        assert!(!bytes.record_page(1, 2));
        assert!(bytes.record_page(1, 1));
        let mut overflow = RegistryDrainBudget::with_limits(usize::MAX, usize::MAX, usize::MAX);
        assert!(overflow.record_page(usize::MAX, usize::MAX));
        assert!(!overflow.record_page(1, 1));
    }

    fn full_page_names(prefix: char, page: usize) -> Vec<String> {
        (0..128)
            .map(|offset| alloc::format!("{prefix}{:05}", page * 128 + offset))
            .collect()
    }

    #[test]
    fn every_typed_whole_table_drain_rejects_an_endless_full_page_stream() {
        let registry = RegistryRef::at(ServiceId::REGISTRY);

        let mut programs = ReplyQueue::pages((0..=REGISTRY_DRAIN_MAX_PAGES).map(|page| {
            ProgramPage {
                protocol: RegistryProtocol::CURRENT,
                rows: full_page_names('p', page)
                    .into_iter()
                    .map(|name| ProgramRow {
                        name,
                        hash: [0x11; 32],
                        publication_id: PublicationId::new([0x12; 32]),
                        kind: ProgramKind::Service { crdt: false },
                    })
                    .collect(),
                more: true,
            }
            .encode()
        }));
        assert!(matches!(
            crate::block_on(registry.programs_all(&mut programs)),
            Err(ClientError::Decode)
        ));

        let mut agents = ReplyQueue::pages((0..=REGISTRY_DRAIN_MAX_PAGES).map(|page| {
            AgentPage {
                protocol: RegistryProtocol::CURRENT,
                rows: full_page_names('a', page)
                    .into_iter()
                    .map(|instance_name| AgentRow {
                        instance_name,
                        installation_id: InstallationId::new([0x21; 32]),
                        revision: 0,
                        program_hash: [0x22; 32],
                        program_name: "worker-program".into(),
                        program_publication_id: PublicationId::new([0x23; 32]),
                        replication_id: [0x24; 32],
                        consistency: 1,
                        network_reachable: false,
                        sync_role: SyncFloor::Member,
                    })
                    .collect(),
                more: true,
            }
            .encode()
        }));
        assert!(matches!(
            crate::block_on(registry.agents_all(&mut agents)),
            Err(ClientError::Decode)
        ));

        let mut system_actors = ReplyQueue::pages((0..=REGISTRY_DRAIN_MAX_PAGES).map(|page| {
            SystemActorPage {
                protocol: RegistryProtocol::CURRENT,
                rows: full_page_names('s', page)
                    .into_iter()
                    .map(|instance_name| SystemActorRow {
                        instance_name,
                        installation_id: InstallationId::new([0x31; 32]),
                        revision: 0,
                        system_agent_id: AgentId::new([0x32; 32]),
                        actor_id: ActorId::new([0x33; 32]),
                        program_hash: [0x34; 32],
                        program_name: "worker-program".into(),
                        program_publication_id: PublicationId::new([0x35; 32]),
                        host_receipt_hash: [0x36; 32],
                    })
                    .collect(),
                more: true,
            }
            .encode()
        }));
        assert!(matches!(
            crate::block_on(registry.system_actors_all(&mut system_actors)),
            Err(ClientError::Decode)
        ));

        let mut names = ReplyQueue::pages((0..=REGISTRY_DRAIN_MAX_PAGES).map(|page| {
            AgentNamePage {
                protocol: RegistryProtocol::CURRENT,
                names: full_page_names('n', page),
                more: true,
            }
            .encode()
        }));
        assert!(matches!(
            crate::block_on(registry.agent_names_all(&mut names)),
            Err(ClientError::Decode)
        ));
    }
}
