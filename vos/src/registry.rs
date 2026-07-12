//! Space-registry protocol — the wire types, constants, and canonical
//! signing-byte encodings shared by the `space-registry` PVM actor
//! (verifier), the `vosx` CLI (signer/reader), and the daemon's
//! sign-on-relay path.
//!
//! These used to live in the `space-registry` actor crate, which forced
//! a mirror here (`registry_canon`) because `vos` can't depend on an
//! actor crate that already depends on `vos`. Hoisting the protocol into
//! `vos` ends that cycle: the actor now `pub use`s these back, so there
//! is one source of truth for the consensus-critical byte layouts and
//! the drift-pin cross-check test is no longer needed.
//!
//! Everything here is `no_std` + `alloc` only — the row types must
//! compile for the actor's `service`/`wasm` builds. The verifier-side
//! `verify_op_sig` (ed25519) deliberately STAYS in the actor so its
//! `ed25519-dalek` dependency never reaches `vos`; it consumes
//! [`ed25519_pubkey_from_peer_id`] from here.

use alloc::string::String;
use alloc::vec::Vec;

// ── Programs ──────────────────────────────────────────────────────

/// One row in the program catalog.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct ProgramRow {
    pub name: String,
    pub version: String,
    pub hash: [u8; 32],
}

/// One row in the agent (installed-instance) table.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct AgentRow {
    pub instance_name: String,
    /// Pinned at install time so a program retag never silently
    /// changes the code an agent runs.
    pub program_hash: [u8; 32],
    /// Display-only references to the program catalog. Agents
    /// resolve code via `program_hash`; these are for
    /// `space agents` listings and manifest export.
    pub program_name: String,
    pub program_version: String,
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
    /// `Member` requires a space read grant, `Private` requires a
    /// per-actor grant (the generalized `msg-*` private semantics). See
    /// [`SyncFloor`].
    pub sync_role: SyncFloor,
    /// rkyv-encoded `vos::init::InitArgs` captured at install
    /// time. New replicas use this to bootstrap their copy of
    /// the agent before its first message arrives. Empty when
    /// the agent was installed without init args.
    pub install_args: Vec<u8>,
    /// Optional one-shot messages to dispatch when the agent
    /// is first cold-started. rkyv-encoded `Vec<Vec<u8>>`
    /// where each inner `Vec<u8>` is a `[TAG_DYNAMIC] + rkyv(Msg)`
    /// payload. Reconciled from the manifest's `on_start = [{msg=…}]`
    /// list. Empty when the agent has no on_start.
    pub install_payloads: Vec<u8>,
}

/// Serving-side sync floor for a replica — who its state (`FetchHeads`/
/// `FetchNode`) is served to, and the default spawn set a node derives
/// from its own role. Three user-facing levels (`sync = "public" |
/// "member" | "private"` in manifests/`install`), ordered from most
/// open to most restricted, so `<` means "more open".
#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq,
    PartialOrd, Ord, Hash,
)]
#[rkyv(crate = rkyv)]
#[repr(u8)]
pub enum SyncFloor {
    /// Served to any connected peer; every node spawns it.
    Public = 0,
    /// Served to a caller holding a space read grant
    /// (`>= AUTH_ROLE_READONLY`); the default for new installs.
    Member = 1,
    /// Served only to a caller holding a per-actor grant on this replica
    /// (`>= AUTH_ROLE_READONLY`) — the generalized `msg-*` semantics.
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

/// Per-(PeerId, agent_name) ACL row — the actor-local override table.
/// Lookup precedence in the dispatch path is `actor_acls` keyed on
/// `(peer_id, agent_name)`, falling back to `auth_grants` keyed on
/// `peer_id` (space-level). `role` discriminants are interpreted in the
/// *target actor's* `Role` enum; the registry stores them opaquely.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct ActorAclRow {
    pub peer_id: Vec<u8>,
    pub agent_name: String,
    pub role: u8,
    /// Monotonic grant epoch — see [`AuthGrantRow::epoch`]. Compared
    /// against the matching per-actor revoke high-water.
    pub epoch: u64,
    /// PeerId of the delegator. The actor-local grant counts only if the
    /// grantor is a transitively-effective *space* admin.
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

/// One page of [`RegistryRef::actor_acls`]. Same filtered-cursor shape as
/// [`AuthGrantPage`], but the actor-local key is `(peer_id, agent_name)`,
/// so the continuation cursor is the last *scanned* pair (both empty when
/// the scan reached the end).
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct ActorAclPage {
    pub acls: Vec<ActorAclRow>,
    pub next_peer: Vec<u8>,
    pub next_agent: String,
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
#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[rkyv(crate = rkyv)]
#[repr(u8)]
pub enum Status {
    /// Handler succeeded.
    Ok = 0,
    /// A `(name, version)` tag already exists bound to a different hash.
    TagConflict = 1,
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
}

impl Status {
    /// Decode a status byte (the over-the-wire discriminant) back into a
    /// `Status`. `None` for an unknown byte.
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Ok),
            1 => Some(Self::TagConflict),
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
            _ => None,
        }
    }
}

impl core::fmt::Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Status::Ok => "ok",
            Status::TagConflict => "tag conflict",
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
        })
    }
}

// ── Signing-byte builders (consensus-critical: byte-exact) ─────────

/// Domain tag for registry-op author signatures.
pub const REGISTRY_OP_DOMAIN: &[u8] = b"vos-registry-op/v1";

/// ed25519 signature length.
pub const OP_SIG_LEN: usize = 64;

/// Canonical byte string a mutation's author signs. Layout:
/// `domain || u16(op.len) || op || (u32(field.len) || field)*`.
/// The signer (CLI/daemon) and the verifier (actor) build these from the
/// same logical args, so the bytes match exactly without re-encoding the
/// wire `Msg`.
pub fn canonical_op_bytes(op: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(REGISTRY_OP_DOMAIN);
    out.extend_from_slice(&(op.len() as u16).to_le_bytes());
    out.extend_from_slice(op.as_bytes());
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
    out
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

/// Domain tag for the MLS identity-binding signature (the messenger's
/// `vos-msg/identity-binding/v1`). Separate from [`REGISTRY_OP_DOMAIN`]
/// so a registry-op signature can never be replayed as a binding cert.
pub const BINDING_DOMAIN: &[u8] = b"vos-msg/identity-binding/v1";

/// Canonical bytes the operator's identity key signs to bind an MLS
/// signature key to a space PeerId: `domain || u16(mls_pubkey.len) ||
/// mls_pubkey || u16(peer_id.len) || peer_id || space_id`. Shared so the
/// messenger actor (which verifies the cert on every leaf) and the CLI
/// (which produces it) build identical bytes from one source.
pub fn binding_signed_bytes(mls_pubkey: &[u8], peer_id: &[u8], space_id: &[u8; 32]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(BINDING_DOMAIN.len() + 4 + mls_pubkey.len() + peer_id.len() + 32);
    out.extend_from_slice(BINDING_DOMAIN);
    out.extend_from_slice(&(mls_pubkey.len() as u16).to_le_bytes());
    out.extend_from_slice(mls_pubkey);
    out.extend_from_slice(&(peer_id.len() as u16).to_le_bytes());
    out.extend_from_slice(peer_id);
    out.extend_from_slice(space_id);
    out
}

// ── Service-id derivation ─────────────────────────────────────────

/// Domain tag for `space_id` derivation. The host computes
/// `space_id = blake2b("vos-space-id/v1" || genesis_dag_root)`.
pub const SPACE_ID_DOMAIN_TAG: &[u8] = b"vos-space-id/v1";

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
    let raw_bytes: [u8; 2] = crate::crypto::blake2b_hash(
        b"vos-instance-svc-id/v1",
        &[&[0u8], instance_name.as_bytes()],
    );
    let raw = u16::from_le_bytes(raw_bytes);
    let local = (raw & 0x7FFF).max(0x100);
    ((prefix as u32) << 16) | (local as u32)
}

// ── Sign-on-relay (host/daemon side) ──────────────────────────────
//
// Folded in from the former `registry_canon` module. The catalog
// mutators (`install`/`publish`/…) are author-signed and re-verified on
// every replica's replay. A keyless PVM agent (the messenger cloning a
// channel's actor pair) and the daemon's own manifest reconcile can't
// carry a CLI signature, so the daemon signs these ops as they reach the
// registry — at `handle_invoke_request`, the one funnel every invoke
// converges on — with the operator key it loaded at boot. It rebuilds
// the exact bytes the registry verifies via [`canonical_op_bytes`].

// `Msg`/`Value`/`TAG_DYNAMIC`/`Encode` are shared with the always-
// available `RegistryRef` below; the `Arc`-backed signer + relay signing
// are host-only (they run in the daemon), so they carry a `std` gate —
// `alloc::sync` is configured out on the atomic-free riscv actor target.
use crate::actors::codec::Encode;
use crate::value::{Msg, TAG_DYNAMIC, Value};
#[cfg(feature = "std")]
use alloc::sync::Arc;

/// Signs the canonical bytes of a registry op and returns the packed
/// `auth` blob (`signer_peer_id || sig(64)`), or `None` if signing
/// fails. Built by the daemon at boot from the operator's libp2p
/// identity and held by the space-registry agent thread.
#[cfg(feature = "std")]
pub(crate) type CatalogOpSigner = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// If `msg` is one of the signed catalog mutators, rebuild the exact
/// canonical bytes its author signs — the same fields, in the same order
/// and encoding the registry handler passes to [`canonical_op_bytes`].
/// `None` for any other method or if a required arg is missing or
/// ill-typed (fail closed). `register_remote` is deliberately absent — it
/// is the hyperspace surface with a separate trust model.
#[cfg(feature = "std")]
fn catalog_op_canonical(msg: &Msg) -> Option<Vec<u8>> {
    let a = &msg.args;
    let canon = match msg.name.as_str() {
        "publish" => {
            let name = a.get_str("name")?;
            let version = a.get_str("version")?;
            let hash = a.get_bytes("hash")?;
            canonical_op_bytes("publish", &[name.as_bytes(), version.as_bytes(), &hash])
        }
        "unpublish" => {
            let name = a.get_str("name")?;
            let version = a.get_str("version")?;
            canonical_op_bytes("unpublish", &[name.as_bytes(), version.as_bytes()])
        }
        "install" => {
            let instance_name = a.get_str("instance_name")?;
            let program_name = a.get_str("program_name")?;
            let program_version = a.get_str("program_version")?;
            let program_hash = a.get_bytes("program_hash")?;
            let replication_id = a.get_bytes("replication_id")?;
            let consistency = a.get_u8("consistency")?;
            let install_args = a.get_bytes("install_args")?;
            let install_payloads = a.get_bytes("install_payloads")?;
            // Absent field (e.g. an older client) defaults to false (confined),
            // matching the mutator's decode of a missing bool param.
            let network_reachable = a.get_bool("network_reachable").unwrap_or(false);
            // Absent floor defaults to `Member`, matching the mutator's
            // `SyncFloor::from_u8(...).unwrap_or_default()` decode.
            let sync_role = a.get_u8("sync_role").unwrap_or(SyncFloor::Member as u8);
            canonical_op_bytes(
                "install",
                &[
                    instance_name.as_bytes(),
                    program_name.as_bytes(),
                    program_version.as_bytes(),
                    &program_hash,
                    &replication_id,
                    &[consistency],
                    &install_args,
                    &install_payloads,
                    &[network_reachable as u8],
                    &[sync_role],
                ],
            )
        }
        "uninstall" => {
            let instance_name = a.get_str("instance_name")?;
            canonical_op_bytes("uninstall", &[instance_name.as_bytes()])
        }
        "upgrade" => {
            let instance_name = a.get_str("instance_name")?;
            let new_program_name = a.get_str("new_program_name")?;
            let new_program_version = a.get_str("new_program_version")?;
            let new_program_hash = a.get_bytes("new_program_hash")?;
            let from_hash = a.get_bytes("from_hash")?;
            canonical_op_bytes(
                "upgrade",
                &[
                    instance_name.as_bytes(),
                    new_program_name.as_bytes(),
                    new_program_version.as_bytes(),
                    &new_program_hash,
                    &from_hash,
                ],
            )
        }
        "register_meta" => {
            let program_hash = a.get_bytes("program_hash")?;
            let blob = a.get_bytes("blob")?;
            canonical_op_bytes("register_meta", &[&program_hash, &blob])
        }
        "register_extension_meta" => {
            let instance_name = a.get_str("instance_name")?;
            let blob = a.get_bytes("blob")?;
            canonical_op_bytes("register_extension_meta", &[instance_name.as_bytes(), &blob])
        }
        _ => return None,
    };
    Some(canon)
}

/// Implements the sign-on-relay step: if `payload` (`[TAG_DYNAMIC][rkyv Msg]`)
/// targets a signed catalog mutator, rebuild its canonical bytes, sign
/// them with `signer`, and return a re-encoded payload carrying the
/// operator's `auth` blob (replacing any caller-supplied placeholder).
/// `None` leaves the original payload untouched.
#[cfg(feature = "std")]
pub(crate) fn sign_catalog_op_on_relay(
    payload: &[u8],
    signer: &CatalogOpSigner,
) -> Option<Vec<u8>> {
    if !payload.starts_with(&[TAG_DYNAMIC]) {
        return None;
    }
    let mut msg = <Msg as crate::Decode>::try_decode(&payload[1..])?;
    let canonical = catalog_op_canonical(&msg)?;
    let auth = signer(&canonical)?;
    // The registry reads the first `auth` arg; drop any caller-supplied
    // placeholder so the operator's signature is the one it sees.
    msg.args.0.retain(|(k, _)| k != "auth");
    msg.args.0.push((String::from("auth"), Value::Bytes(auth)));
    let encoded = msg.encode();
    let mut out = Vec::with_capacity(1 + encoded.len());
    out.push(TAG_DYNAMIC);
    out.extend_from_slice(&encoded);
    Some(out)
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
// the wire the generated ref emitted, so the daemon's sign-on-relay and
// the actor's verifier are unaffected. Generic over `Invoker`, so the
// same code drives a network invoke (CLI → daemon, arriving as
// `Caller::Peer`) and a local in-process invoke (daemon → its own
// registry, arriving as `Caller::System`).

use crate::abi::service::ServiceId;
use crate::actors::client::{ClientError, Invoker};

/// Decode a `Value::Bytes` rkyv reply into `T` (checked access), mapping
/// a wrong-shape or undecodable reply to the matching `ClientError` —
/// mirrors the generated client's reply decode.
fn decode_rkyv<T: crate::Decode>(value: Value) -> Result<T, ClientError> {
    match value {
        Value::Bytes(b) => T::try_decode(&b).ok_or(ClientError::Decode),
        other => Err(ClientError::UnexpectedReply(alloc::format!("{other:?}"))),
    }
}

/// Decode an `Option<T>` reply: `Unit` / empty `Bytes` → `None`, a
/// populated `Bytes` → rkyv-decoded `Some`.
fn decode_opt<T: crate::Decode>(value: Value) -> Result<Option<T>, ClientError> {
    match value {
        Value::Unit => Ok(None),
        Value::Bytes(b) if b.is_empty() => Ok(None),
        Value::Bytes(b) => T::try_decode(&b).map(Some).ok_or(ClientError::Decode),
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
    async fn call<I: Invoker>(&self, inv: &mut I, msg: Msg) -> Result<Value, ClientError> {
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        inv.invoke(self.target, payload).await
    }

    // ── Catalog reads ─────────────────────────────────────────────

    pub async fn programs<I: Invoker>(&self, inv: &mut I) -> Result<Vec<ProgramRow>, ClientError> {
        decode_rkyv(self.call(inv, Msg::new("programs")).await?)
    }

    pub async fn program<I: Invoker>(
        &self,
        inv: &mut I,
        name: String,
        version: String,
    ) -> Result<Option<ProgramRow>, ClientError> {
        decode_opt(
            self.call(inv, Msg::new("program").with("name", name).with("version", version))
                .await?,
        )
    }

    pub async fn agents<I: Invoker>(&self, inv: &mut I) -> Result<Vec<AgentRow>, ClientError> {
        decode_rkyv(self.call(inv, Msg::new("agents")).await?)
    }

    pub async fn agent<I: Invoker>(
        &self,
        inv: &mut I,
        instance_name: String,
    ) -> Result<Option<AgentRow>, ClientError> {
        decode_opt(
            self.call(inv, Msg::new("agent").with("instance_name", instance_name))
                .await?,
        )
    }

    pub async fn meta_for_instance<I: Invoker>(
        &self,
        inv: &mut I,
        name: String,
    ) -> Result<Vec<u8>, ClientError> {
        decode_bytes(self.call(inv, Msg::new("meta_for_instance").with("name", name)).await?)
    }

    /// One page of the member roster (nodes then identities). Prefer
    /// [`members_all`](Self::members_all) unless you are paging by hand;
    /// pass `(0, [])` to start and continue from the returned page's
    /// `(next_kind, next_key)` while `more` is true. `budget` caps the page.
    pub async fn members<I: Invoker>(
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
    pub async fn members_all<I: Invoker>(
        &self,
        inv: &mut I,
    ) -> Result<Vec<MemberRow>, ClientError> {
        let mut out = Vec::new();
        let mut kind = 0u8;
        let mut key: Vec<u8> = Vec::new();
        loop {
            let page = self.members(inv, kind, key, 0).await?;
            out.extend(page.members);
            if !page.more {
                break;
            }
            kind = page.next_kind;
            key = page.next_key;
        }
        Ok(out)
    }

    pub async fn root<I: Invoker>(&self, inv: &mut I) -> Result<Vec<u8>, ClientError> {
        decode_bytes(self.call(inv, Msg::new("root")).await?)
    }

    // ── Auth reads ────────────────────────────────────────────────

    pub async fn peer_role<I: Invoker>(
        &self,
        inv: &mut I,
        peer_id: Vec<u8>,
    ) -> Result<u8, ClientError> {
        let v = self.call(inv, Msg::new("peer_role").with("peer_id", peer_id)).await?;
        v.as_u8()
            .ok_or_else(|| ClientError::UnexpectedReply(alloc::format!("{v:?}")))
    }

    pub async fn peer_epoch<I: Invoker>(
        &self,
        inv: &mut I,
        peer_id: Vec<u8>,
    ) -> Result<u64, ClientError> {
        let v = self.call(inv, Msg::new("peer_epoch").with("peer_id", peer_id)).await?;
        v.as_u64()
            .ok_or_else(|| ClientError::UnexpectedReply(alloc::format!("{v:?}")))
    }

    pub async fn actor_epoch<I: Invoker>(
        &self,
        inv: &mut I,
        peer_id: Vec<u8>,
        agent_name: String,
    ) -> Result<u64, ClientError> {
        let v = self
            .call(
                inv,
                Msg::new("actor_epoch")
                    .with("peer_id", peer_id)
                    .with("agent_name", agent_name),
            )
            .await?;
        v.as_u64()
            .ok_or_else(|| ClientError::UnexpectedReply(alloc::format!("{v:?}")))
    }

    /// One page of the effective space-level grants. Pass an empty
    /// `after_peer` to start; continue from the returned [`AuthGrantPage::next`]
    /// until it comes back empty. `budget` caps the page (0 = the
    /// registry's max).
    pub async fn auth_grants<I: Invoker>(
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

    /// One page of the effective actor-local ACLs. Continue from the
    /// returned [`ActorAclPage::next_peer`]/`next_agent` until both come
    /// back empty. `budget` caps the page (0 = the registry's max).
    pub async fn actor_acls<I: Invoker>(
        &self,
        inv: &mut I,
        after_peer: Vec<u8>,
        after_agent: String,
        budget: u32,
    ) -> Result<ActorAclPage, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("actor_acls")
                    .with("after_peer", after_peer)
                    .with("after_agent", after_agent)
                    .with("budget", budget),
            )
            .await?,
        )
    }

    // ── Genesis / catalog mutators ────────────────────────────────

    pub async fn set_root<I: Invoker>(
        &self,
        inv: &mut I,
        root: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(self.call(inv, Msg::new("set_root").with("root", root)).await?)
    }

    pub async fn publish<I: Invoker>(
        &self,
        inv: &mut I,
        name: String,
        version: String,
        hash: Vec<u8>,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("publish")
                    .with("name", name)
                    .with("version", version)
                    .with("hash", hash)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn register_meta<I: Invoker>(
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

    pub async fn register_extension_meta<I: Invoker>(
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

    pub async fn unpublish<I: Invoker>(
        &self,
        inv: &mut I,
        name: String,
        version: String,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("unpublish")
                    .with("name", name)
                    .with("version", version)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn install<I: Invoker>(
        &self,
        inv: &mut I,
        instance_name: String,
        program_name: String,
        program_version: String,
        program_hash: Vec<u8>,
        replication_id: Vec<u8>,
        consistency: u8,
        install_args: Vec<u8>,
        install_payloads: Vec<u8>,
        network_reachable: bool,
        sync_role: SyncFloor,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("install")
                    .with("instance_name", instance_name)
                    .with("program_name", program_name)
                    .with("program_version", program_version)
                    .with("program_hash", program_hash)
                    .with("replication_id", replication_id)
                    .with("consistency", consistency)
                    .with("install_args", install_args)
                    .with("install_payloads", install_payloads)
                    .with("network_reachable", network_reachable)
                    .with("sync_role", sync_role as u8)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade<I: Invoker>(
        &self,
        inv: &mut I,
        instance_name: String,
        new_program_name: String,
        new_program_version: String,
        new_program_hash: Vec<u8>,
        from_hash: Vec<u8>,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("upgrade")
                    .with("instance_name", instance_name)
                    .with("new_program_name", new_program_name)
                    .with("new_program_version", new_program_version)
                    .with("new_program_hash", new_program_hash)
                    .with("from_hash", from_hash)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn uninstall<I: Invoker>(
        &self,
        inv: &mut I,
        instance_name: String,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("uninstall")
                    .with("instance_name", instance_name)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn add_node<I: Invoker>(
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

    pub async fn remove_node<I: Invoker>(
        &self,
        inv: &mut I,
        prefix: u32,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("remove_node").with("prefix", prefix).with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn add_identity<I: Invoker>(
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

    pub async fn remove_identity<I: Invoker>(
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

    pub async fn grant_role<I: Invoker>(
        &self,
        inv: &mut I,
        peer_id: Vec<u8>,
        role: u8,
        epoch: u64,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("grant_role")
                    .with("peer_id", peer_id)
                    .with("role", role)
                    .with("epoch", epoch)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn revoke_role<I: Invoker>(
        &self,
        inv: &mut I,
        peer_id: Vec<u8>,
        epoch: u64,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("revoke_role")
                    .with("peer_id", peer_id)
                    .with("epoch", epoch)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn grant_actor_role<I: Invoker>(
        &self,
        inv: &mut I,
        peer_id: Vec<u8>,
        agent_name: String,
        role: u8,
        epoch: u64,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("grant_actor_role")
                    .with("peer_id", peer_id)
                    .with("agent_name", agent_name)
                    .with("role", role)
                    .with("epoch", epoch)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn revoke_actor_role<I: Invoker>(
        &self,
        inv: &mut I,
        peer_id: Vec<u8>,
        agent_name: String,
        epoch: u64,
        auth: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("revoke_actor_role")
                    .with("peer_id", peer_id)
                    .with("agent_name", agent_name)
                    .with("epoch", epoch)
                    .with("auth", auth),
            )
            .await?,
        )
    }

    pub async fn register_remote<I: Invoker>(
        &self,
        inv: &mut I,
        instance_name: String,
        host_prefix: u32,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("register_remote")
                    .with("instance_name", instance_name)
                    .with("host_prefix", host_prefix),
            )
            .await?,
        )
    }

    // ── Invites ───────────────────────────────────────────────────

    /// Redeem an invite token: grant `role` to `peer_id`. Deliberately
    /// unauthenticated — the two carried signatures ARE the auth. The
    /// handler verifies `admin_sig` over the invite canonical
    /// (`invite`, `[space_id, [role], expires_le, token_pub]`) under
    /// `admin_peer_id` (which must be a current-epoch effective admin),
    /// and `redeem_sig` over (`redeem_invite`, `[token_pub, peer_id]`)
    /// under `token_pub`. No expiry check happens here (checked
    /// host-side at admission).
    #[allow(clippy::too_many_arguments)]
    pub async fn redeem_invite<I: Invoker>(
        &self,
        inv: &mut I,
        space_id: Vec<u8>,
        token_pub: Vec<u8>,
        role: u8,
        expires_at: u64,
        admin_peer_id: Vec<u8>,
        admin_sig: Vec<u8>,
        peer_id: Vec<u8>,
        redeem_sig: Vec<u8>,
    ) -> Result<Status, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("redeem_invite")
                    .with("space_id", space_id)
                    .with("token_pub", token_pub)
                    .with("role", role)
                    .with("expires_at", expires_at)
                    .with("admin_peer_id", admin_peer_id)
                    .with("admin_sig", admin_sig)
                    .with("peer_id", peer_id)
                    .with("redeem_sig", redeem_sig),
            )
            .await?,
        )
    }

    /// Revoke an invite token (admin-signed). Grow-only: flips the
    /// token's `revoked` flag so no future redemption succeeds and no
    /// replayed redeem can clear it. Idempotent.
    pub async fn revoke_invite<I: Invoker>(
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
    pub async fn invites<I: Invoker>(
        &self,
        inv: &mut I,
        after: Vec<u8>,
        budget: u32,
    ) -> Result<InvitePage, ClientError> {
        decode_rkyv(
            self.call(
                inv,
                Msg::new("invites").with("after", after).with("budget", budget),
            )
            .await?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the per-method field ordering `catalog_op_canonical` feeds
    /// into `canonical_op_bytes` — the consensus-critical layout the
    /// signer and the actor verifier must agree on. (This is the
    /// successor to the old `registry_canon` drift-pin: with one source
    /// of truth, it asserts the canonical builder itself, not a mirror.)
    #[test]
    fn catalog_op_canonical_matches_canonical_bytes_for_every_op() {
        let m = Msg::new("install")
            .with("instance_name", "msg-x-log")
            .with("program_name", "p")
            .with("program_version", "1")
            .with("program_hash", alloc::vec![7u8; 32])
            .with("replication_id", alloc::vec![9u8; 32])
            .with("consistency", 2u64)
            .with("install_args", alloc::vec![1u8, 2, 3])
            .with("install_payloads", Vec::<u8>::new())
            .with("network_reachable", true)
            .with("sync_role", SyncFloor::Private as u64);
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            canonical_op_bytes(
                "install",
                &[
                    b"msg-x-log",
                    b"p",
                    b"1",
                    &[7u8; 32],
                    &[9u8; 32],
                    &[2u8],
                    &[1u8, 2, 3],
                    &[],
                    &[1u8],
                    &[2u8],
                ],
            ),
        );

        let m = Msg::new("publish")
            .with("name", "p")
            .with("version", "1")
            .with("hash", alloc::vec![7u8; 32]);
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            canonical_op_bytes("publish", &[b"p", b"1", &[7u8; 32]]),
        );

        let m = Msg::new("unpublish").with("name", "p").with("version", "1");
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            canonical_op_bytes("unpublish", &[b"p", b"1"]),
        );

        let m = Msg::new("uninstall").with("instance_name", "msg-x-log");
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            canonical_op_bytes("uninstall", &[b"msg-x-log"]),
        );

        let m = Msg::new("register_meta")
            .with("program_hash", alloc::vec![7u8; 32])
            .with("blob", alloc::vec![1u8, 2, 3]);
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            canonical_op_bytes("register_meta", &[&[7u8; 32], &[1u8, 2, 3]]),
        );

        let m = Msg::new("register_extension_meta")
            .with("instance_name", "gateway")
            .with("blob", alloc::vec![9u8, 8]);
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            canonical_op_bytes("register_extension_meta", &[b"gateway", &[9u8, 8]]),
        );

        let m = Msg::new("upgrade")
            .with("instance_name", "msg-x-log")
            .with("new_program_name", "p")
            .with("new_program_version", "2")
            .with("new_program_hash", alloc::vec![5u8; 32])
            .with("from_hash", alloc::vec![7u8; 32]);
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            canonical_op_bytes("upgrade", &[b"msg-x-log", b"p", b"2", &[5u8; 32], &[7u8; 32]]),
        );
    }

    #[test]
    fn non_catalog_method_is_not_signed() {
        assert!(catalog_op_canonical(&Msg::new("agents")).is_none());
        let grant = Msg::new("grant_role")
            .with("peer_id", alloc::vec![1u8; 38])
            .with("role", 3u8);
        assert!(catalog_op_canonical(&grant).is_none());
        // register_remote is out of scope (hyperspace trust model).
        let rr = Msg::new("register_remote")
            .with("instance_name", "x")
            .with("host_prefix", 5u32);
        assert!(catalog_op_canonical(&rr).is_none());
    }

    #[test]
    fn sign_on_relay_injects_single_auth_over_the_canonical() {
        let captured: Arc<std::sync::Mutex<Vec<u8>>> = Default::default();
        let seen = captured.clone();
        let signer: CatalogOpSigner = Arc::new(move |canon: &[u8]| {
            *seen.lock().unwrap() = canon.to_vec();
            Some(alloc::vec![0xABu8; 70])
        });

        // typed-wrapper style: carries an empty `auth` placeholder.
        let m = Msg::new("uninstall")
            .with("instance_name", "x")
            .with("auth", Vec::<u8>::new());
        let mut payload = alloc::vec![TAG_DYNAMIC];
        payload.extend_from_slice(&m.encode());

        let signed = sign_catalog_op_on_relay(&payload, &signer).expect("catalog op signed");
        assert_eq!(
            *captured.lock().unwrap(),
            canonical_op_bytes("uninstall", &[b"x"]),
        );
        let decoded = <Msg as crate::Decode>::try_decode(&signed[1..]).unwrap();
        let auths = decoded.args.0.iter().filter(|(k, _)| k == "auth").count();
        assert_eq!(auths, 1, "exactly one auth arg after signing");
        assert_eq!(decoded.args.get_bytes("auth").unwrap(), alloc::vec![0xABu8; 70]);
    }

    #[test]
    fn non_dynamic_payload_is_left_untouched() {
        let signer: CatalogOpSigner = Arc::new(|_| Some(alloc::vec![0u8; 70]));
        assert!(sign_catalog_op_on_relay(&[0x01, 0x02, 0x03], &signer).is_none());
    }

    #[test]
    fn ed25519_pubkey_extracts_from_valid_peer_id() {
        let mut pid = alloc::vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
        pid.extend_from_slice(&[42u8; 32]);
        assert_eq!(ed25519_pubkey_from_peer_id(&pid), Some([42u8; 32]));
        assert!(ed25519_pubkey_from_peer_id(&[0u8; 10]).is_none());
    }
}
