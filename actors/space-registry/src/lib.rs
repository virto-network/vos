//! Space registry — the per-space source of truth.
//!
//! Holds three tables, all replicated via the registry actor's
//! own consistency strategy (Raft today, BFT-swappable later):
//!
//! 1. **Programs** — published PVM blobs identified by
//!    `(name, version)`. Tags are immutable: republishing a
//!    `(name, version)` pair with a different hash errors.
//! 2. **Agents** — installed *instances* of programs, each with
//!    its own `instance_name`, `replication_id`, consistency,
//!    and state. Multiple agents can share one program.
//! 3. **Members** — Nodes (libp2p peers, may vote in consensus)
//!    and Identities (people / bots, author signed messages
//!    with a Merkle-inclusion or ZK proof of set membership).
//!
//! Init args for an installed agent are NOT stored in the
//! Agents table; they live in the registry's own DAG as the
//! genesis effect of the `install` operation. Auditable via
//! the DAG; not part of the queryable schema.
//!
//! Hashes (`program_hash`, `replication_id`, `peer_id`) cross
//! message boundaries as `Vec<u8>` because the dynamic-`Msg`
//! arg system handles a small fixed set of primitive types.
//! The actor validates lengths internally and stores `[u8; 32]`
//! in the rkyv-archived rows.
//!
//! ## Schema evolution
//!
//! Adding a field to `SpaceRegistry` (or any of its rkyv-archived
//! rows) changes the on-disk layout. Persisted state from prior
//! versions fails `try_decode` validation and the actor falls
//! back to `create()` — i.e. every space hosting an older
//! registry blob loses its full agents/programs/members tables
//! on first restart. This is the operating model while the
//! project is pre-release; once we ship a stable shape, additions
//! will need an explicit migration step (versioned blob header,
//! rkyv archive upgrade path, or similar).

//! ── Wire types ─────────────────────────────────────────────────────

/// Reserved ServiceId for the space registry. Mirrors
/// `vos::abi::service::ServiceId::REGISTRY` so the host can route
/// without first looking us up.
pub const SERVICE_ID_RAW: u32 = 0;

/// Domain tag for `space_id` derivation. Host computes
/// `blake2b("vos-space-id/v1" || genesis_dag_root)`.
pub const SPACE_ID_DOMAIN_TAG: &[u8] = b"vos-space-id/v1";

// ── Programs ──────────────────────────────────────────────────────

/// One row in the program catalog.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ProgramRow {
    pub name: String,
    pub version: String,
    pub hash: [u8; 32],
}

/// One row in the metadata table — opaque schema bytes attached to a
/// program hash. The wire payload is the raw `.vos_meta` ELF section
/// (binary format defined by `vos::actors::metadata`); the registry
/// itself doesn't decode it, so no schema lock-in across versions.
/// All agents installed from the same program share one entry; the
/// `meta_for_instance` lookup composes the agent → program_hash join
/// internally.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct MetaRow {
    pub program_hash: [u8; 32],
    pub blob: Vec<u8>,
}

/// One row in the extension-metadata table — meta bytes for a native
/// extension `.so`, keyed by its manifest `instance_name`. Service-
/// mode extensions don't have a program-hash identity the way PVM
/// blobs do (the host loads them straight from a path; the same
/// .so can produce a different meta blob across rebuilds), so the
/// natural key is the operator-chosen name. `meta_for_instance` falls
/// through to this table when an extension instance shares a name
/// with no installed agent — `vosx <ext> <cmd>` reads it to extend
/// clap with the extension's CLI surface.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ExtensionMetaRow {
    pub instance_name: String,
    pub blob: Vec<u8>,
}

/// Raw PVM blob stored in the registry's per-space content-
/// addressed object store. Hashed with the empty-domain blake2b
/// that vosx's host-side `blob_store::BlobHash::of` uses, so a
/// `ProgramRow.hash` looked up via `program(name, version)` is
/// directly usable as a key into both the registry's blob table
/// and the operator's `~/.cache/vosx/blobs/` cache.
///
/// Capacity caveat: blobs replicate via the registry's CRDT/Raft
/// stream, so every peer in the space carries every blob's bytes.
/// Fine for the program-distribution use case (small PVM ELFs at
/// publish time) but unsuitable for bulk data — push that through
/// a dedicated blob-distribution agent.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct BlobRow {
    pub hash: [u8; 32],
    pub bytes: Vec<u8>,
}

// ── Agents ────────────────────────────────────────────────────────

/// One row in the agent (instance) catalog.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
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

/// Monotone-locality floor: the narrowest consistency tier (by
/// shareability) an `instance_name` was ever installed at. Retained
/// across `uninstall` — unlike the `AgentRow`, which is removed — so
/// that reusing a name to *widen* it (e.g. re-installing a
/// formerly-`Local` channel as `Crdt`) is refused. The load-bearing
/// enforcement lives host-side in `vos::node` (the registry is
/// replicated and not trusted); this catalog-level row keeps honest
/// replicas from ever *recording* a widening.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ConsistencyFloorRow {
    pub instance_name: String,
    /// `vos::node::Consistency` discriminant, same encoding as
    /// `AgentRow.consistency`.
    pub consistency: u8,
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
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
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

// ── Auth grants (Sprint 2) ────────────────────────────────────────
//
// Separate table from `MemberRow` because the existing `role`
// field is a Raft-consensus concern (`NODE_ROLE_VOTER` /
// `OBSERVER`), independent from auth roles. A PeerId can hold
// any combination of (consensus role, auth role) — they're
// orthogonal axes.
//
// Hierarchy: `ADMIN > DEVELOPER > READONLY > NONE`. Unenrolled
// peers default to `NONE`. The dispatch-layer gate in
// `vos::node::dispatch_invoke` compares the *required* role
// for a handler against the caller's *granted* role.
//
// `READONLY` is the default for `members` lookups so a peer can
// see who's enrolled without an explicit grant.

pub const AUTH_ROLE_NONE: u8 = 0;
pub const AUTH_ROLE_READONLY: u8 = 1;
pub const AUTH_ROLE_DEVELOPER: u8 = 2;
pub const AUTH_ROLE_ADMIN: u8 = 3;

/// The space-registry actor's own role hierarchy. Discriminants
/// match the AUTH_ROLE_* constants above so a space-level grant
/// (stored as a SpaceRole byte) can be reinterpreted in this
/// enum's vocabulary via [`SPACE_ROLE_MAP`](SpaceRegistry::SPACE_ROLE_MAP).
///
/// Each #[msg(role = SpaceRegistryRole::Admin)] handler runs the
/// M6 macro-emitted check against the caller's effective role
/// before the handler body executes; the M5 host dispatch
/// populates the caller's bytes from `peer_role` and
/// `actor_role`.
#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum SpaceRegistryRole {
    None = 0,
    Reader = 1,
    Developer = 2,
    Admin = 3,
}

impl vos::RoleByte for SpaceRegistryRole {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::Reader),
            2 => Some(Self::Developer),
            3 => Some(Self::Admin),
            _ => None,
        }
    }
    fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Per-PeerId auth grant. `peer_id` is the libp2p PeerId in
/// multihash bytes (same encoding as `MemberRow.key` when
/// `kind = Node`); `role` is one of the `AUTH_ROLE_*`
/// constants above.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct AuthGrantRow {
    pub peer_id: Vec<u8>,
    pub role: u8,
}

/// Per-(PeerId, agent_name) ACL row — the M4 actor-local override
/// table. Lookup precedence in the dispatch path is:
///
/// 1. `actor_acls` keyed on `(peer_id, agent_name)`.
/// 2. Fall back to `auth_grants` keyed on `peer_id` (space-level).
///
/// `role` discriminants are interpreted in the *target actor's*
/// `Role` enum, not [`SpaceRole`](vos::SpaceRole). The registry
/// stores them opaquely; the host plumbs them through and the
/// actor decodes via `RoleByte::from_byte`. Sorting key is the
/// pair `(peer_id_bytes, agent_name_bytes)` for binary lookup.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ActorAclRow {
    pub peer_id: Vec<u8>,
    pub agent_name: String,
    pub role: u8,
}

// ── Host mappings (hyperspace addressing) ───────────────────────
//
// In a space-local registry, every node hosts every agent so the
// `resolve` formula `instance_service_id(name, caller_prefix)` lands
// the caller on its own local replica. In a hyperspace registry that
// breaks: peer-space agents have non-overlapping replica sets, so
// the caller's prefix is the wrong host. `HostMapping` tracks where
// each agent actually lives so cross-space resolve returns a
// ServiceId that routes through libp2p to the right node.

/// A single (instance_name → host node_prefix) mapping. Recorded
/// in the hyperspace registry by `register_remote`; consulted by
/// `resolve` to override `caller_prefix` when the agent isn't
/// hosted on the asking node.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct HostMapping {
    pub instance_name: String,
    /// libp2p-derived 16-bit node prefix of the node hosting this
    /// agent. Cross-space callers route to (host_prefix, derived_local).
    pub host_prefix: u16,
}

// ── Result codes ─────────────────────────────────────────────────
//
// Mutation messages return a single u8 status. 0 always = ok.

pub const STATUS_OK: u8 = 0;
pub const STATUS_TAG_CONFLICT: u8 = 1;
pub const STATUS_NOT_FOUND: u8 = 2;
pub const STATUS_IN_USE: u8 = 3;
pub const STATUS_PROGRAM_NOT_FOUND: u8 = 4;
pub const STATUS_INSTANCE_EXISTS: u8 = 5;
pub const STATUS_BAD_HASH: u8 = 6;
/// Sprint 2: the caller's PeerId doesn't carry the auth role
/// required for this handler. Distinct from `STATUS_NOT_FOUND`
/// so clients can surface "permission denied" specifically.
pub const STATUS_FORBIDDEN: u8 = 7;
/// Hyperspace `register_remote`: the supplied `host_prefix`
/// doesn't match any registered node prefix. Distinct from
/// `STATUS_NOT_FOUND` so callers can distinguish "instance
/// not found" from "host node not enrolled".
pub const STATUS_BAD_PREFIX: u8 = 8;
/// Monotone-locality guard: `install` refused to (re)create an
/// instance at a *wider* consistency tier than the narrowest one
/// the same `instance_name` was ever installed at. Confined tiers
/// (`Ephemeral`/`Local`) may never be widened into replication by
/// reusing a name — widening requires a fresh name. This is the
/// defense-in-depth half of the immutable-local seal; the
/// load-bearing enforcement is host-side in `vos::node`.
pub const STATUS_CONSISTENCY_WIDEN_DENIED: u8 = 9;

// ── Actor ─────────────────────────────────────────────────────────

use vos::prelude::*;

/// Per-actor SpaceRole map (M7) — declared as a `pub const` so
/// it survives the `#[actor(space_role_map = ...)]` expansion.
/// Maps the four space-level tiers onto this registry's local
/// roles:
///
///   space Admin     → registry Admin     (full control)
///   space Developer → registry Developer (reserved — no
///                                         handlers gate on
///                                         Developer today, but
///                                         the tier is wired so
///                                         M8/M9 operators can
///                                         delegate via local
///                                         grants)
///   space Member    → registry Reader    (read-only handlers)
///   space Guest     → None               (deny mutations)
pub const SPACE_REGISTRY_SPACE_ROLE_MAP: vos::SpaceRoleMap<SpaceRegistryRole> = vos::SpaceRoleMap {
    admin: Some(SpaceRegistryRole::Admin),
    developer: Some(SpaceRegistryRole::Developer),
    member: Some(SpaceRegistryRole::Reader),
    guest: None,
};

#[actor(
    role = SpaceRegistryRole,
    default_role = SpaceRegistryRole::Reader,
    space_role_map = SPACE_REGISTRY_SPACE_ROLE_MAP
)]
pub struct SpaceRegistry {
    /// Sorted by `(name, version)` for fast lookup.
    programs: Vec<ProgramRow>,
    /// Sorted by `instance_name`.
    agents: Vec<AgentRow>,
    /// Members; nodes sorted by `prefix` first, then identities
    /// sorted by `key`.
    members: Vec<MemberRow>,
    /// Opaque metadata blobs keyed by program hash. Stored as raw
    /// `.vos_meta` section bytes so the registry stays agnostic
    /// about the schema format (lives in `vos::metadata` on the
    /// consumer side).
    metas: Vec<MetaRow>,
    /// Opaque metadata blobs for native `.so` extensions, keyed by
    /// the manifest `instance_name`. Service-mode extensions have
    /// no program-hash identity in this catalog (the host loads
    /// them off a filesystem path), so we key by the operator-
    /// visible name. `meta_for_instance` falls through here when
    /// the name doesn't match an installed PVM agent.
    extension_metas: Vec<ExtensionMetaRow>,
    /// PVM blob bytes, keyed by their `BlobHash::of` hash. Sorted
    /// by hash for binary search. Populated by
    /// `upload_blob` — typically the dev extension's
    /// `publish` flow uploads here before calling `publish` so
    /// peers can resolve `ProgramRow.hash` without a separate
    /// fetch dance.
    blobs: Vec<BlobRow>,
    /// Sprint 2 — per-PeerId auth grants. Sorted by `peer_id`
    /// (lexicographic bytes) for binary lookup. Pre-Sprint-2
    /// state archives don't have this field; the actor's
    /// fall-back-to-fresh behaviour on archive decode failure
    /// (see "Schema evolution" in this file's module doc) lets
    /// upgrades resync from the DAG.
    auth_grants: Vec<AuthGrantRow>,
    /// M4 — per-(peer, agent) actor-local ACL overrides. Sorted
    /// by `(peer_id, agent_name)` for binary lookup. Empty until
    /// an operator calls `grant_actor_role`. Falls through to
    /// `auth_grants` (space-level) when no actor-local grant
    /// exists for `(peer, target_agent)`.
    actor_acls: Vec<ActorAclRow>,
    /// Sorted by `instance_name`. Populated on the hyperspace
    /// registry replica only — the local space-registry leaves
    /// this empty so its `resolve` keeps the in-space behaviour
    /// (caller_prefix == host).
    host_mappings: Vec<HostMapping>,
    /// Monotone-locality floors, sorted by `instance_name`. The
    /// narrowest consistency tier each name was ever installed at;
    /// retained across `uninstall` so `install` can refuse to widen
    /// a reused name (see [`ConsistencyFloorRow`]). Pre-existing
    /// state archives don't have this field; the actor's
    /// fall-back-to-fresh behaviour on archive decode failure lets
    /// upgrades resync from the DAG.
    consistency_floors: Vec<ConsistencyFloorRow>,
    /// Genesis root authority: the operator PeerId baked at
    /// `space new` via the first [`set_root`](SpaceRegistry::set_root)
    /// op. Empty until set. [`authorize_op`](SpaceRegistry::authorize_op)
    /// treats the root as the supreme signer of any mutation; every
    /// other admin's authority delegates from it through `auth_grants`.
    /// Pinned into `space_id` (it rides the genesis DAG), so a joiner
    /// verifies it via the same `space new`/`space verify` root recompute.
    root: Vec<u8>,
}

#[messages]
impl SpaceRegistry {
    fn new() -> Self {
        Self {
            programs: Vec::new(),
            agents: Vec::new(),
            members: Vec::new(),
            metas: Vec::new(),
            extension_metas: Vec::new(),
            blobs: Vec::new(),
            auth_grants: Vec::new(),
            actor_acls: Vec::new(),
            host_mappings: Vec::new(),
            consistency_floors: Vec::new(),
            root: Vec::new(),
        }
    }

    // ── Genesis root authority ──────────────────────────────────

    /// Establish the genesis root — the operator PeerId whose
    /// signature anchors every signed registry mutation. First-write-
    /// wins: valid only while no root is set, so the genesis `set_root`
    /// `space new` emits (and pins into `space_id`) is the one true
    /// root, and a later forged `set_root` merged via CRDT is refused.
    /// This op carries no `auth` of its own — it *is* the anchor;
    /// its integrity comes from being part of the immutable genesis
    /// commit that `space verify` recomputes against the advertised
    /// `space_id`.
    #[msg]
    async fn set_root(&mut self, root: Vec<u8>) -> u8 {
        if root.is_empty() {
            return STATUS_BAD_HASH;
        }
        if !self.root.is_empty() {
            return STATUS_FORBIDDEN;
        }
        self.root = root;
        STATUS_OK
    }

    /// The genesis root PeerId, or empty if none is set. Read surface
    /// for diagnostics and joiner verification.
    #[msg]
    async fn root(&self) -> Vec<u8> {
        self.root.clone()
    }

    // ── Programs catalog ────────────────────────────────────────

    /// Add a program to the catalog. Tags are immutable — if
    /// `(name, version)` already exists, returns
    /// `STATUS_TAG_CONFLICT` unless the existing hash matches
    /// (idempotent re-publish).
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn publish(&mut self, name: String, version: String, hash: Vec<u8>, auth: Vec<u8>) -> u8 {
        if !self.authorize_op(
            &canonical_op_bytes("publish", &[name.as_bytes(), version.as_bytes(), &hash]),
            &auth,
        ) {
            return STATUS_FORBIDDEN;
        }
        let Some(hash) = bytes_to_32(&hash) else {
            return STATUS_BAD_HASH;
        };
        let mut idx = 0usize;
        while idx < self.programs.len() {
            let cur = &self.programs[idx];
            let cmp = compare_program(&cur.name, &cur.version, &name, &version);
            if cmp == 0 {
                if cur.hash == hash {
                    return STATUS_OK;
                }
                return STATUS_TAG_CONFLICT;
            }
            if cmp > 0 {
                break;
            }
            idx += 1;
        }
        self.programs.insert(
            idx,
            ProgramRow {
                name,
                version,
                hash,
            },
        );
        STATUS_OK
    }

    /// Remove a program from the catalog. Errors with
    /// `STATUS_IN_USE` if any agent still references the version.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn unpublish(&mut self, name: String, version: String, auth: Vec<u8>) -> u8 {
        if !self.authorize_op(
            &canonical_op_bytes("unpublish", &[name.as_bytes(), version.as_bytes()]),
            &auth,
        ) {
            return STATUS_FORBIDDEN;
        }
        let mut idx = 0usize;
        while idx < self.programs.len() {
            let cur = &self.programs[idx];
            if cur.name == name && cur.version == version {
                let hash = cur.hash;
                let mut ai = 0usize;
                while ai < self.agents.len() {
                    if self.agents[ai].program_hash == hash {
                        return STATUS_IN_USE;
                    }
                    ai += 1;
                }
                self.programs.remove(idx);
                return STATUS_OK;
            }
            idx += 1;
        }
        STATUS_NOT_FOUND
    }

    /// Look up a single program by `(name, version)`.
    #[msg]
    async fn program(&self, name: String, version: String) -> Option<ProgramRow> {
        let mut idx = 0usize;
        while idx < self.programs.len() {
            if self.programs[idx].name == name && self.programs[idx].version == version {
                return Some(self.programs[idx].clone());
            }
            idx += 1;
        }
        None
    }

    /// Snapshot the full catalog. Pagination can come later.
    #[msg]
    async fn programs(&self) -> Vec<ProgramRow> {
        self.programs.clone()
    }

    // ── Metadata blobs ──────────────────────────────────────────

    /// Record (or replace) the metadata blob for a program hash.
    /// Idempotent: re-registering the same hash overwrites the
    /// existing blob (lets a manifest re-deploy refresh schema).
    /// Returns `STATUS_BAD_HASH` if the hash isn't 32 bytes;
    /// otherwise `STATUS_OK`. The hash doesn't need to match an
    /// existing `ProgramRow` — schema can be registered before
    /// the program is published if the orchestrator prefers
    /// that order.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn register_meta(&mut self, program_hash: Vec<u8>, blob: Vec<u8>) -> u8 {
        let Some(program_hash) = bytes_to_32(&program_hash) else {
            return STATUS_BAD_HASH;
        };
        let mut idx = 0usize;
        while idx < self.metas.len() {
            if self.metas[idx].program_hash == program_hash {
                self.metas[idx].blob = blob;
                return STATUS_OK;
            }
            idx += 1;
        }
        self.metas.push(MetaRow { program_hash, blob });
        STATUS_OK
    }

    /// Look up the metadata blob for a program hash. Returns an
    /// empty vector when no entry exists — callers treat that as
    /// "schema unknown" and fall back to whatever heuristic they
    /// were using before.
    #[msg]
    async fn meta_for_program(&self, program_hash: Vec<u8>) -> Vec<u8> {
        let Some(program_hash) = bytes_to_32(&program_hash) else {
            return Vec::new();
        };
        let mut idx = 0usize;
        while idx < self.metas.len() {
            if self.metas[idx].program_hash == program_hash {
                return self.metas[idx].blob.clone();
            }
            idx += 1;
        }
        Vec::new()
    }

    /// Convenience join: find an installed agent by name, then
    /// return its program's metadata blob. Saves the caller a
    /// round trip in the common case (gateway resolving a
    /// per-method schema). Empty vector when the agent is
    /// unknown or has no meta registered.
    ///
    /// Falls through to the extension-meta table when no agent
    /// matches — extensions share the same instance-name
    /// namespace from the manifest, and `vosx <ext> <cmd>` needs
    /// a single lookup that doesn't care whether the target is a
    /// PVM agent or a native `.so`. Agents win on collision; an
    /// extension with the same name as an installed agent is
    /// shadowed. The manifest reconciler is the right place to
    /// reject the collision up-front, but doesn't today.
    #[msg]
    async fn meta_for_instance(&self, name: String) -> Vec<u8> {
        let mut ai = 0usize;
        while ai < self.agents.len() {
            if self.agents[ai].instance_name == name {
                let hash = self.agents[ai].program_hash;
                let mut mi = 0usize;
                while mi < self.metas.len() {
                    if self.metas[mi].program_hash == hash {
                        return self.metas[mi].blob.clone();
                    }
                    mi += 1;
                }
                return Vec::new();
            }
            ai += 1;
        }
        let mut ei = 0usize;
        while ei < self.extension_metas.len() {
            if self.extension_metas[ei].instance_name == name {
                return self.extension_metas[ei].blob.clone();
            }
            ei += 1;
        }
        Vec::new()
    }

    /// Record (or replace) the metadata blob for a native
    /// extension instance. Keyed by `instance_name` (not a
    /// program hash — see `ExtensionMetaRow` comment).
    ///
    /// An empty `blob` removes the row outright rather than
    /// storing an empty entry. That keeps "no schema registered"
    /// distinguishable from "schema registered but trivially
    /// empty" if the producer ever has reason to publish a
    /// zero-method surface — and lets a re-deploy genuinely roll
    /// back a previously-published surface rather than leaving
    /// behind a stale row.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn register_extension_meta(&mut self, instance_name: String, blob: Vec<u8>) -> u8 {
        let mut idx = 0usize;
        while idx < self.extension_metas.len() {
            if self.extension_metas[idx].instance_name == instance_name {
                if blob.is_empty() {
                    self.extension_metas.remove(idx);
                } else {
                    self.extension_metas[idx].blob = blob;
                }
                return STATUS_OK;
            }
            idx += 1;
        }
        if !blob.is_empty() {
            self.extension_metas.push(ExtensionMetaRow {
                instance_name,
                blob,
            });
        }
        STATUS_OK
    }

    // ── Agents (instances) ──────────────────────────────────────

    /// Instantiate a program as an agent. The caller resolves
    /// `(program_name, program_version)` to a hash and passes
    /// the hash so the install pins to a specific blob.
    /// Init args are NOT stored here — they're applied host-side
    /// when the agent is spawned and recorded in the registry's
    /// DAG node for this `install` call.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn install(
        &mut self,
        instance_name: String,
        program_name: String,
        program_version: String,
        program_hash: Vec<u8>,
        replication_id: Vec<u8>,
        consistency: u8,
        install_args: Vec<u8>,
        install_payloads: Vec<u8>,
        auth: Vec<u8>,
    ) -> u8 {
        if !self.authorize_op(
            &canonical_op_bytes(
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
                ],
            ),
            &auth,
        ) {
            return STATUS_FORBIDDEN;
        }
        let Some(program_hash) = bytes_to_32(&program_hash) else {
            return STATUS_BAD_HASH;
        };
        let Some(replication_id) = bytes_to_32(&replication_id) else {
            return STATUS_BAD_HASH;
        };

        // Verify program exists with the claimed hash.
        let mut found = false;
        let mut pi = 0usize;
        while pi < self.programs.len() {
            let p = &self.programs[pi];
            if p.name == program_name && p.version == program_version && p.hash == program_hash {
                found = true;
                break;
            }
            pi += 1;
        }
        if !found {
            return STATUS_PROGRAM_NOT_FOUND;
        }

        let mut idx = 0usize;
        while idx < self.agents.len() {
            let cur = &self.agents[idx];
            if cur.instance_name == instance_name {
                return STATUS_INSTANCE_EXISTS;
            }
            if cur.instance_name.as_str() > instance_name.as_str() {
                break;
            }
            idx += 1;
        }

        // Monotone-locality guard (defense-in-depth): if this name was
        // ever installed before, its shareability may only narrow. A
        // reused name can't be *widened* into replication — that needs a
        // fresh name (and a fresh `replication_id`), so private-era state
        // is never folded into a now-shared DAG. The floor outlives the
        // row, so this fires on the uninstall→reinstall-wider path; a live
        // row already returned `STATUS_INSTANCE_EXISTS` above.
        if let Some(floor) = consistency_floor(&self.consistency_floors, &instance_name) {
            if !may_transition_to(floor, consistency) {
                return STATUS_CONSISTENCY_WIDEN_DENIED;
            }
        }
        record_consistency_floor(
            &mut self.consistency_floors,
            instance_name.clone(),
            consistency,
        );

        self.agents.insert(
            idx,
            AgentRow {
                instance_name,
                program_hash,
                program_name,
                program_version,
                replication_id,
                consistency,
                install_args,
                install_payloads,
            },
        );
        STATUS_OK
    }

    /// Tombstone an agent. Local data on each replica moves to
    /// trash on the host side; the registry just removes the row.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn uninstall(&mut self, instance_name: String, auth: Vec<u8>) -> u8 {
        if !self.authorize_op(
            &canonical_op_bytes("uninstall", &[instance_name.as_bytes()]),
            &auth,
        ) {
            return STATUS_FORBIDDEN;
        }
        let mut idx = 0usize;
        while idx < self.agents.len() {
            if self.agents[idx].instance_name == instance_name {
                self.agents.remove(idx);
                return STATUS_OK;
            }
            idx += 1;
        }
        STATUS_NOT_FOUND
    }

    /// Repoint an agent at a different program version. State
    /// is preserved (same `replication_id`, same redb); replicas
    /// restart their agent thread on the next sync.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn upgrade(
        &mut self,
        instance_name: String,
        new_program_name: String,
        new_program_version: String,
        new_program_hash: Vec<u8>,
        auth: Vec<u8>,
    ) -> u8 {
        if !self.authorize_op(
            &canonical_op_bytes(
                "upgrade",
                &[
                    instance_name.as_bytes(),
                    new_program_name.as_bytes(),
                    new_program_version.as_bytes(),
                    &new_program_hash,
                ],
            ),
            &auth,
        ) {
            return STATUS_FORBIDDEN;
        }
        let Some(new_program_hash) = bytes_to_32(&new_program_hash) else {
            return STATUS_BAD_HASH;
        };

        // Verify the target program exists.
        let mut found = false;
        let mut pi = 0usize;
        while pi < self.programs.len() {
            let p = &self.programs[pi];
            if p.name == new_program_name
                && p.version == new_program_version
                && p.hash == new_program_hash
            {
                found = true;
                break;
            }
            pi += 1;
        }
        if !found {
            return STATUS_PROGRAM_NOT_FOUND;
        }

        let mut idx = 0usize;
        while idx < self.agents.len() {
            if self.agents[idx].instance_name == instance_name {
                self.agents[idx].program_name = new_program_name;
                self.agents[idx].program_version = new_program_version;
                self.agents[idx].program_hash = new_program_hash;
                return STATUS_OK;
            }
            idx += 1;
        }
        STATUS_NOT_FOUND
    }

    #[msg]
    async fn agent(&self, instance_name: String) -> Option<AgentRow> {
        let mut idx = 0usize;
        while idx < self.agents.len() {
            if self.agents[idx].instance_name == instance_name {
                return Some(self.agents[idx].clone());
            }
            idx += 1;
        }
        None
    }

    #[msg]
    async fn agents(&self) -> Vec<AgentRow> {
        self.agents.clone()
    }

    /// Lightweight enumeration of installed agent names.
    /// Returns `Vec<String>` so cross-actor callers without
    /// `AgentRow` schema knowledge (e.g. the gateway rendering
    /// `/__schema`) can pull the list without an rkyv dance.
    /// Same ordering as `agents()` — sorted by `instance_name`.
    #[msg]
    async fn agent_names(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(self.agents.len());
        let mut idx = 0usize;
        while idx < self.agents.len() {
            out.push(self.agents[idx].instance_name.clone());
            idx += 1;
        }
        out
    }

    /// Resolve an installed agent's name to the `ServiceId` it
    /// occupies. Packed as a u32.
    ///
    /// Lookup order:
    ///
    /// 1. **Local catalog**: if the name is in `agents`, return
    ///    `instance_service_id(name, caller_prefix)` so the caller
    ///    lands on its own local replica — the in-space default.
    /// 2. **Host mapping**: if the name has a recorded `HostMapping`
    ///    (only populated on the hyperspace registry replica),
    ///    return `instance_service_id(name, host_prefix)` so the
    ///    caller's envelope routes through libp2p to the actual
    ///    host node.
    /// 3. Otherwise return 0.
    ///
    /// Local-first ordering matters: if a local replica of an
    /// installed agent exists, we want callers to use it instead of
    /// chasing a (potentially stale or attacker-supplied) cross-space
    /// route. The hyperspace registry's `agents` table is empty in
    /// practice — vosx never installs into it — so on a hyperspace
    /// replica the lookup naturally falls through to host_mappings.
    ///
    /// `caller_prefix` is the asking node's 16-bit identity prefix
    /// (passed by `Context::resolve` from the caller's own
    /// `id().node_prefix()`).
    #[msg]
    async fn resolve(&self, name: String, caller_prefix: u64) -> u32 {
        // 1. Local catalog wins.
        if self.agents.iter().any(|a| a.instance_name == name) {
            return instance_service_id(&name, caller_prefix as u16);
        }
        // 2. Hyperspace host mapping (agent hosted on a peer node).
        if let Some(h) = self.host_mappings.iter().find(|h| h.instance_name == name) {
            return instance_service_id(&name, h.host_prefix);
        }
        0
    }

    /// Record (or update) the host node-prefix for an agent. Called
    /// on the **hyperspace registry** by each member space's daemon
    /// at boot, advertising "this space's `<instance_name>` is
    /// hosted at `host_prefix`." Cross-space `resolve` uses the
    /// mapping to return a ServiceId that routes through libp2p to
    /// the right node.
    ///
    /// Idempotent in `instance_name` — re-registering with a new
    /// `host_prefix` overwrites (covers the case where a space
    /// re-keys or migrates between nodes).
    ///
    /// **Trust gap**: this handler is currently unauthenticated. Any
    /// actor on any hyperspace member can call `register_remote` for
    /// any name, including one belonging to another member-space, and
    /// silently redirect that name's resolution to a node of their
    /// choosing. This is acceptable for trusted-deployments testing
    /// (local development, single-operator federations) but NOT for
    /// mixed-trust federations like the cipher-clerk bank case. The
    /// bridge actor pattern is intended to address this by binding
    /// register_remote calls to a known clerk pubkey signature; until
    /// that lands, do not deploy this surface to untrusted peers.
    ///
    /// Returns `STATUS_BAD_PREFIX` when `host_prefix` doesn't fit in
    /// a u16. Otherwise `STATUS_OK`.
    #[msg]
    async fn register_remote(&mut self, instance_name: String, host_prefix: u32) -> u8 {
        if host_prefix > u16::MAX as u32 {
            return STATUS_BAD_PREFIX;
        }
        let host_prefix = host_prefix as u16;
        let mut idx = 0usize;
        while idx < self.host_mappings.len() {
            let cur = &self.host_mappings[idx];
            if cur.instance_name == instance_name {
                self.host_mappings[idx].host_prefix = host_prefix;
                return STATUS_OK;
            }
            if cur.instance_name.as_str() > instance_name.as_str() {
                break;
            }
            idx += 1;
        }
        self.host_mappings.insert(
            idx,
            HostMapping {
                instance_name,
                host_prefix,
            },
        );
        STATUS_OK
    }

    /// Snapshot the host-mapping table. Diagnostic/test surface;
    /// production callers use `resolve`.
    #[msg]
    async fn host_mappings(&self) -> Vec<HostMapping> {
        self.host_mappings.clone()
    }

    // ── Members ────────────────────────────────────────────────

    /// Add a Node member. Idempotent in `prefix` — re-adding
    /// updates `peer_id` and `role`. `role` is
    /// `NODE_ROLE_VOTER` or `NODE_ROLE_OBSERVER`.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn add_node(&mut self, prefix: u32, peer_id: Vec<u8>, role: u8, auth: Vec<u8>) -> u8 {
        if !self.authorize_op(
            &canonical_op_bytes("add_node", &[&prefix.to_le_bytes(), &peer_id, &[role]]),
            &auth,
        ) {
            return STATUS_FORBIDDEN;
        }
        let prefix = prefix as u16;
        let mut idx = 0usize;
        while idx < self.members.len() {
            let cur = &self.members[idx];
            if cur.kind == MEMBER_KIND_NODE && cur.prefix == prefix {
                self.members[idx].key = peer_id;
                self.members[idx].role = role;
                return STATUS_OK;
            }
            // Nodes sort before Identities; within Nodes by prefix.
            if cur.kind == MEMBER_KIND_NODE && cur.prefix > prefix {
                break;
            }
            if cur.kind == MEMBER_KIND_IDENTITY {
                break;
            }
            idx += 1;
        }
        self.members.insert(
            idx,
            MemberRow {
                kind: MEMBER_KIND_NODE,
                key: peer_id,
                prefix,
                role,
                proof_kind: 0,
                proof_data: Vec::new(),
            },
        );
        STATUS_OK
    }

    #[msg(role = SpaceRegistryRole::Admin)]
    async fn remove_node(&mut self, prefix: u32, auth: Vec<u8>) -> u8 {
        if !self.authorize_op(
            &canonical_op_bytes("remove_node", &[&prefix.to_le_bytes()]),
            &auth,
        ) {
            return STATUS_FORBIDDEN;
        }
        let prefix = prefix as u16;
        let mut idx = 0usize;
        while idx < self.members.len() {
            let cur = &self.members[idx];
            if cur.kind == MEMBER_KIND_NODE && cur.prefix == prefix {
                self.members.remove(idx);
                return STATUS_OK;
            }
            idx += 1;
        }
        STATUS_NOT_FOUND
    }

    /// Add an Identity member. The registry stores the `proof`
    /// verbatim — verification happens on the consumer side
    /// when an identity-authored message arrives at an agent.
    /// `proof_kind` is `PROOF_KIND_MERKLE_INCLUSION` (v1) or
    /// `PROOF_KIND_ZK` (future).
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn add_identity(
        &mut self,
        public_key: Vec<u8>,
        proof_kind: u8,
        proof_data: Vec<u8>,
        auth: Vec<u8>,
    ) -> u8 {
        if !self.authorize_op(
            &canonical_op_bytes(
                "add_identity",
                &[&public_key, &[proof_kind], &proof_data],
            ),
            &auth,
        ) {
            return STATUS_FORBIDDEN;
        }
        let mut idx = 0usize;
        while idx < self.members.len() {
            let cur = &self.members[idx];
            if cur.kind == MEMBER_KIND_IDENTITY {
                if cur.key == public_key {
                    self.members[idx].proof_kind = proof_kind;
                    self.members[idx].proof_data = proof_data;
                    return STATUS_OK;
                }
                if compare_bytes(&cur.key, &public_key) > 0 {
                    break;
                }
            }
            idx += 1;
        }
        self.members.insert(
            idx,
            MemberRow {
                kind: MEMBER_KIND_IDENTITY,
                key: public_key,
                prefix: 0,
                role: 0,
                proof_kind,
                proof_data,
            },
        );
        STATUS_OK
    }

    #[msg(role = SpaceRegistryRole::Admin)]
    async fn remove_identity(&mut self, public_key: Vec<u8>, auth: Vec<u8>) -> u8 {
        if !self.authorize_op(
            &canonical_op_bytes("remove_identity", &[&public_key]),
            &auth,
        ) {
            return STATUS_FORBIDDEN;
        }
        let mut idx = 0usize;
        while idx < self.members.len() {
            let cur = &self.members[idx];
            if cur.kind == MEMBER_KIND_IDENTITY && cur.key == public_key {
                self.members.remove(idx);
                return STATUS_OK;
            }
            idx += 1;
        }
        STATUS_NOT_FOUND
    }

    #[msg]
    async fn members(&self) -> Vec<MemberRow> {
        self.members.clone()
    }

    /// Raft-join admission probe: the role of the NODE member enrolled at
    /// `prefix`, encoded `role + 1` so the byte is self-describing —
    /// `0` = not enrolled, `1` = VOTER ([`NODE_ROLE_VOTER`]), `2` =
    /// OBSERVER ([`NODE_ROLE_OBSERVER`]). The Raft leader's host calls this
    /// (as `Caller::System`) before admitting a `RaftJoinReq`, so a peer
    /// that an admin never enrolled cannot make itself a voter. An ungated
    /// read — the answer is non-secret membership metadata, and enrollment
    /// itself stays Admin-gated at [`add_node`](Self::add_node).
    #[msg]
    async fn node_role(&self, prefix: u64) -> u8 {
        let prefix = prefix as u16;
        self.members
            .iter()
            .find(|m| m.kind == MEMBER_KIND_NODE && m.prefix == prefix)
            .map(|m| m.role.saturating_add(1))
            .unwrap_or(0)
    }

    // ── Auth grants (Sprint 2) ─────────────────────────────────

    /// Grant `role` to `peer_id`. Idempotent — re-granting the
    /// same role is a no-op; changing the role updates in place.
    /// `peer_id` is libp2p multihash bytes (same encoding as
    /// `add_node`'s `peer_id` arg).
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn grant_role(&mut self, peer_id: Vec<u8>, role: u8, auth: Vec<u8>) -> u8 {
        if !self.authorize_op(&canonical_op_bytes("grant_role", &[&peer_id, &[role]]), &auth) {
            return STATUS_FORBIDDEN;
        }
        if peer_id.is_empty() {
            return STATUS_BAD_HASH;
        }
        match self
            .auth_grants
            .binary_search_by(|g| compare_bytes(&g.peer_id, &peer_id).cmp(&0))
        {
            Ok(idx) => {
                self.auth_grants[idx].role = role;
                STATUS_OK
            }
            Err(insert_at) => {
                self.auth_grants
                    .insert(insert_at, AuthGrantRow { peer_id, role });
                STATUS_OK
            }
        }
    }

    /// Remove the grant for `peer_id`. Returns
    /// `STATUS_NOT_FOUND` if the peer wasn't granted.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn revoke_role(&mut self, peer_id: Vec<u8>, auth: Vec<u8>) -> u8 {
        if !self.authorize_op(&canonical_op_bytes("revoke_role", &[&peer_id]), &auth) {
            return STATUS_FORBIDDEN;
        }
        match self
            .auth_grants
            .binary_search_by(|g| compare_bytes(&g.peer_id, &peer_id).cmp(&0))
        {
            Ok(idx) => {
                self.auth_grants.remove(idx);
                STATUS_OK
            }
            Err(_) => STATUS_NOT_FOUND,
        }
    }

    /// Look up the role granted to `peer_id`. Returns
    /// `AUTH_ROLE_NONE` if no grant exists — the
    /// dispatch-layer gate treats this as "deny".
    #[msg]
    async fn peer_role(&self, peer_id: Vec<u8>) -> u8 {
        lookup_grant(&self.auth_grants, &peer_id)
    }

    /// Full grants list — for `vosx space role list`.
    #[msg]
    async fn auth_grants(&self) -> Vec<AuthGrantRow> {
        self.auth_grants.clone()
    }

    // ── Actor-local ACLs (M4) ──────────────────────────────────
    //
    // Sibling of the space-level `auth_grants` quartet above —
    // same shape, scoped by `agent_name`. The dispatch path in
    // vos/src/node.rs (M5) consults this table first; misses
    // fall through to `auth_grants` mapped via the actor's
    // `SPACE_ROLE_MAP`. CLI surface (`vosx space role
    // --in <actor>`) lands in M8.

    /// Grant `role` to `peer_id` *scoped to* `agent_name`.
    /// Idempotent — re-granting the same role is a no-op;
    /// changing the role updates in place. `role` is interpreted
    /// in the target actor's `Role` enum (not `SpaceRole`).
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn grant_actor_role(
        &mut self,
        peer_id: Vec<u8>,
        agent_name: String,
        role: u8,
        auth: Vec<u8>,
    ) -> u8 {
        if !self.authorize_op(
            &canonical_op_bytes(
                "grant_actor_role",
                &[&peer_id, agent_name.as_bytes(), &[role]],
            ),
            &auth,
        ) {
            return STATUS_FORBIDDEN;
        }
        if peer_id.is_empty() || agent_name.is_empty() {
            return STATUS_BAD_HASH;
        }
        match self
            .actor_acls
            .binary_search_by(|a| actor_acl_key(&a.peer_id, &a.agent_name, &peer_id, &agent_name))
        {
            Ok(idx) => {
                self.actor_acls[idx].role = role;
                STATUS_OK
            }
            Err(insert_at) => {
                self.actor_acls.insert(
                    insert_at,
                    ActorAclRow {
                        peer_id,
                        agent_name,
                        role,
                    },
                );
                STATUS_OK
            }
        }
    }

    /// Remove the actor-local grant for `(peer_id, agent_name)`.
    /// `STATUS_NOT_FOUND` if no such row exists. Does not affect
    /// the space-level grant in `auth_grants`.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn revoke_actor_role(
        &mut self,
        peer_id: Vec<u8>,
        agent_name: String,
        auth: Vec<u8>,
    ) -> u8 {
        if !self.authorize_op(
            &canonical_op_bytes("revoke_actor_role", &[&peer_id, agent_name.as_bytes()]),
            &auth,
        ) {
            return STATUS_FORBIDDEN;
        }
        match self
            .actor_acls
            .binary_search_by(|a| actor_acl_key(&a.peer_id, &a.agent_name, &peer_id, &agent_name))
        {
            Ok(idx) => {
                self.actor_acls.remove(idx);
                STATUS_OK
            }
            Err(_) => STATUS_NOT_FOUND,
        }
    }

    /// Look up the actor-local role byte granted to `peer_id`
    /// for `agent_name`. Returns `AUTH_ROLE_NONE` when no such
    /// row exists — the dispatch path then falls back to the
    /// space-level grant. (The byte 0 is overloaded with
    /// `AUTH_ROLE_NONE` for the space-level path; actor `Role`
    /// enums may legitimately assign 0 to their lowest tier.
    /// `actor_acl` would shadow that with "no grant", so the
    /// dispatch path uses the `Option<u8>` variant in M5 to
    /// distinguish "no row" from "row with role 0".)
    #[msg]
    async fn actor_role(&self, peer_id: Vec<u8>, agent_name: String) -> u8 {
        match self
            .actor_acls
            .binary_search_by(|a| actor_acl_key(&a.peer_id, &a.agent_name, &peer_id, &agent_name))
        {
            Ok(idx) => self.actor_acls[idx].role,
            Err(_) => AUTH_ROLE_NONE,
        }
    }

    /// Full actor-local ACL list — for `vosx space role list --in
    /// <actor>` and operator audit. Returned in sorted order.
    #[msg]
    async fn actor_acls(&self) -> Vec<ActorAclRow> {
        self.actor_acls.clone()
    }

    // ── Blob bytes ─────────────────────────────────────────────

    /// Insert raw bytes into the registry's blob store, keyed by
    /// the same empty-domain blake2b hash that vosx's
    /// `BlobHash::of` (and therefore `ProgramRow.hash`) uses.
    /// Returns the hash so callers can chain to `publish`
    /// without a separate `BlobHash::of` step on the actor side.
    /// Idempotent: re-uploading identical bytes is a no-op.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn upload_blob(&mut self, bytes: Vec<u8>) -> Vec<u8> {
        let hash: [u8; 32] = vos::crypto::blake2b_hash(&[], &[&bytes]);
        let pos = match self.blobs.binary_search_by(|b| b.hash.cmp(&hash)) {
            Ok(_) => return hash.to_vec(),
            Err(p) => p,
        };
        self.blobs.insert(pos, BlobRow { hash, bytes });
        hash.to_vec()
    }

    /// Fetch raw bytes from the registry's blob store. Returns
    /// an empty vector when the hash isn't present — callers
    /// distinguish "blob absent" from "blob empty" by tracking
    /// whether they uploaded zero-length data (almost certainly
    /// a bug; the dev extension never does).
    #[msg]
    async fn fetch_blob(&self, hash: Vec<u8>) -> Vec<u8> {
        let Some(h) = bytes_to_32(&hash) else {
            return Vec::new();
        };
        match self.blobs.binary_search_by(|b| b.hash.cmp(&h)) {
            Ok(i) => self.blobs[i].bytes.clone(),
            Err(_) => Vec::new(),
        }
    }
}

// ── Signed-op authorization ────────────────────────────────────────
//
// Kept out of the `#[messages]` impl so it stays a plain helper, not
// a dispatchable handler.
impl SpaceRegistry {
    /// Authorize a mutation: the `auth` blob's signature must be valid
    /// for `canonical` (the op's [`canonical_op_bytes`]), AND the
    /// signer must be authorized — the genesis root, or a peer the
    /// already-verified `auth_grants` table marks ADMIN.
    ///
    /// This runs at handler time on BOTH the live dispatch and every
    /// peer's causal replay (where the op arrives as `Caller::System`
    /// and the `#[msg(role)]` gate is a no-op). So a forged op merged
    /// via CRDT — a fabricated AuthGrantRow{ADMIN} or MemberRow{VOTER}
    /// — is refused on each honest node unless it carries a signature
    /// an admin (or the root) actually produced.
    ///
    /// Delegation is transitive without explicit cert chains: a peer
    /// is ADMIN in `auth_grants` only because a prior verified op put
    /// it there, and that op was signed by the root or an earlier
    /// admin — so authority bottoms out at the genesis root, applied
    /// in causal order during replay.
    fn authorize_op(&self, canonical: &[u8], auth: &[u8]) -> bool {
        let Some((signer, sig)) = unpack_auth(auth) else {
            return false;
        };
        if !verify_op_sig(signer, canonical, &sig) {
            return false;
        }
        // The genesis root is the supreme signer. (Before genesis sets
        // a root, `self.root` is empty and only the unsigned `set_root`
        // anchor op is accepted — every signed mutator fails closed.)
        if !self.root.is_empty() && self.root.as_slice() == signer {
            return true;
        }
        lookup_grant(&self.auth_grants, signer) == AUTH_ROLE_ADMIN
    }
}

// ── Helpers ──────────────────────────────────────────────────────

/// Auth role byte granted to `peer_id` in a sorted `auth_grants`
/// table, or [`AUTH_ROLE_NONE`] if no row exists. Shared by the
/// `peer_role` read handler and `authorize_op`.
fn lookup_grant(grants: &[AuthGrantRow], peer_id: &[u8]) -> u8 {
    match grants.binary_search_by(|g| compare_bytes(&g.peer_id, peer_id).cmp(&0)) {
        Ok(idx) => grants[idx].role,
        Err(_) => AUTH_ROLE_NONE,
    }
}

fn bytes_to_32(b: &[u8]) -> Option<[u8; 32]> {
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Some(out)
}

/// Position of an `AgentRow.consistency` byte on the monotone
/// *shareability* lattice — mirrors `vos::node::Consistency::shareability`.
/// Confined tiers keep state node-local (`Ephemeral`=0 → 0, `Local`=1 → 1);
/// `Crdt`(2) and `Raft`(3) both replicate off-node and are rank-equal (2).
/// Any unrecognised byte is treated as fully shared (2) so an unknown wider
/// tier can never slip *under* the guard as if it were confined.
fn shareability(consistency: u8) -> u8 {
    match consistency {
        0 => 0,
        1 => 1,
        _ => 2,
    }
}

/// Defense-in-depth monotone-locality predicate: an instance may only ever
/// move to an equal-or-narrower shareability tier. Raising shareability
/// (widening into broader replication) is refused. Rank-equal moves — a
/// `Crdt`↔`Raft` lateral, or any narrowing — are allowed.
fn may_transition_to(floor: u8, requested: u8) -> bool {
    shareability(requested) <= shareability(floor)
}

/// Current monotone-locality floor for `instance_name`, if one was ever
/// recorded. `None` means the name has never been installed (any tier is
/// allowed).
fn consistency_floor(floors: &[ConsistencyFloorRow], instance_name: &str) -> Option<u8> {
    let mut i = 0usize;
    while i < floors.len() {
        if floors[i].instance_name == instance_name {
            return Some(floors[i].consistency);
        }
        i += 1;
    }
    None
}

/// Record — or *narrow* — the floor for an instance name, keeping the
/// table sorted by `instance_name`. The floor only ever moves to a lower
/// shareability; a genuine widening never reaches here (it's rejected in
/// `install`). Re-installing at the same shareability (including a
/// `Crdt`↔`Raft` lateral) leaves the recorded tier unchanged.
fn record_consistency_floor(
    floors: &mut Vec<ConsistencyFloorRow>,
    instance_name: String,
    consistency: u8,
) {
    let mut idx = 0usize;
    while idx < floors.len() {
        if floors[idx].instance_name == instance_name {
            if shareability(consistency) < shareability(floors[idx].consistency) {
                floors[idx].consistency = consistency;
            }
            return;
        }
        if floors[idx].instance_name.as_str() > instance_name.as_str() {
            break;
        }
        idx += 1;
    }
    floors.insert(
        idx,
        ConsistencyFloorRow {
            instance_name,
            consistency,
        },
    );
}

fn compare_program(a_name: &str, a_version: &str, b_name: &str, b_version: &str) -> i8 {
    if a_name < b_name {
        return -1;
    }
    if a_name > b_name {
        return 1;
    }
    if a_version < b_version {
        return -1;
    }
    if a_version > b_version {
        return 1;
    }
    0
}

/// Total order on `(peer_id, agent_name)` rows in the
/// `actor_acls` table. Primary key is `peer_id` bytes
/// (lexicographic); secondary key is `agent_name`. Returns
/// `Ordering` directly so it can be plugged into
/// `binary_search_by`.
fn actor_acl_key(a_peer: &[u8], a_name: &str, b_peer: &[u8], b_name: &str) -> core::cmp::Ordering {
    match compare_bytes(a_peer, b_peer).cmp(&0) {
        core::cmp::Ordering::Equal => a_name.cmp(b_name),
        other => other,
    }
}

fn compare_bytes(a: &[u8], b: &[u8]) -> i8 {
    let mut i = 0usize;
    while i < a.len() && i < b.len() {
        if a[i] < b[i] {
            return -1;
        }
        if a[i] > b[i] {
            return 1;
        }
        i += 1;
    }
    if a.len() < b.len() {
        -1
    } else if a.len() > b.len() {
        1
    } else {
        0
    }
}

// ── Cross-target helpers (host + actor) ───────────────────────────

/// Deterministic per-node `ServiceId` (packed as u32) for an
/// installed agent named `instance_name` on a node with the
/// given 16-bit `prefix`.
///
/// The low 16 bits are derived from `instance_name` via blake2b
/// and clamped to `[0x100, 0x7FFF]` so they can't collide with
/// `ServiceId::REGISTRY` (= 0) or any reserved low system ids.
/// Stable across restarts of the same node so each instance's
/// redb path persists.
///
/// Cross-target by design — the actor's `resolve` handler and
/// `vosx`'s host code both call this with the same bytes coming
/// out. On riscv64 the blake2b dispatches to the host ECALL
/// precompile; on every other target it runs through
/// `vos::crypto::blake2b_hash` → `blake2b_simd`.
pub fn instance_service_id(instance_name: &str, prefix: u16) -> u32 {
    let raw_bytes: [u8; 2] = vos::crypto::blake2b_hash(
        b"vos-instance-svc-id/v1",
        &[&[0u8], instance_name.as_bytes()],
    );
    let raw = u16::from_le_bytes(raw_bytes);
    let local = (raw & 0x7FFF).max(0x100);
    ((prefix as u32) << 16) | (local as u32)
}

// ── Signed registry ops ──────────────────────────────────
//
// The authority-critical mutations — the auth-grant table
// (`grant_role`/`revoke_role`/`grant_actor_role`/`revoke_actor_role`)
// and the member table (`add_node`/`remove_node`/`add_identity`/
// `remove_identity`) — carry an `auth` blob: the signer's PeerId
// bytes followed by an ed25519 signature over the op's canonical
// bytes. The actor verifies the signature and the signer's authority
// at handler time — and crucially, because the op (with its `auth`
// arg) is recorded into the replicated DAG, the same verification
// re-runs on every peer's causal replay. That closes the forge gap:
// a replayed op that arrives as `Caller::System` still has to carry
// a signature an admin (or the genesis root) actually produced, so a
// peer can't merge a fabricated AuthGrantRow{ADMIN} or
// MemberRow{VOTER} to self-escalate or seize consensus.
//
// The signing seam is the operator's libp2p identity key (held by
// the CLI, and by the daemon at boot). Authority is anchored at the
// genesis `set_root` and delegates through the already-verified
// `auth_grants` table — see [`SpaceRegistry::authorize_op`].
//
// The program/agent CATALOG mutators (`publish`/`unpublish`/`install`/
// `uninstall`/`upgrade`) carry the same `auth` blob, closing the
// catalog-forgery vector (a forged AgentRow/ProgramRow merged via CRDT
// that drives every peer's reconcile to spawn an agent). They are
// reachable from a PVM agent that holds no operator key (the messenger
// clones a channel's actor pair via `create` → `install`) and from the
// daemon's own in-process manifest reconcile, so the signature can't
// always originate at the CLI. The daemon signs them on relay: when a
// catalog mutation reaches the registry it rebuilds these canonical
// bytes from the dispatch `Msg` and signs with the operator key it
// loaded at boot, before the op is recorded into the DAG. Because the
// signature is the operator's, `authorize_op` passes on the operator's
// (admin) node and fails on a joined non-admin node — which is correct:
// a non-admin never authors a catalog row, it consumes the admin's
// already-signed rows via sync, and the reconcile path tolerates the
// resulting STATUS_FORBIDDEN. `register_remote` stays unsigned: it is
// the hyperspace/federation surface and has a separate trust model.

/// Domain tag mixed into the canonical bytes an op is signed over.
/// Prevents a signature from one protocol/version being replayed as
/// a registry op. Bump if [`canonical_op_bytes`] changes.
pub const REGISTRY_OP_DOMAIN: &[u8] = b"vos-registry-op/v1";

/// ed25519 signature length.
pub const OP_SIG_LEN: usize = 64;

/// Canonical byte string a mutation's author signs. Layout:
/// `domain || u16(op.len) || op || (u32(field.len) || field)*`.
/// The signer (CLI/daemon) and the verifier (actor) build these
/// from the same logical args, so the bytes match exactly without
/// re-encoding the wire `Msg`.
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

/// Split an auth blob into `(signer_peer_id, signature)`. `None` if
/// it's too short to hold a signature.
fn unpack_auth(auth: &[u8]) -> Option<(&[u8], [u8; OP_SIG_LEN])> {
    if auth.len() <= OP_SIG_LEN {
        return None;
    }
    let (signer, sig) = auth.split_at(auth.len() - OP_SIG_LEN);
    let mut s = [0u8; OP_SIG_LEN];
    s.copy_from_slice(sig);
    Some((signer, s))
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
/// Returns `None` for any other shape — a non-ed25519 identity can't
/// be a registry signer in v1.
pub fn ed25519_pubkey_from_peer_id(peer_id: &[u8]) -> Option<[u8; 32]> {
    const PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    if peer_id.len() != 38 || peer_id[..6] != PREFIX {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&peer_id[6..]);
    Some(key)
}

/// Verify ed25519 `sig` over `msg` under the key embedded in
/// `signer_peer_id`. Pure (no RNG) and deterministic across host and
/// PVM. `false` on any malformed input or bad signature.
pub fn verify_op_sig(signer_peer_id: &[u8], msg: &[u8], sig: &[u8; OP_SIG_LEN]) -> bool {
    let Some(pk) = ed25519_pubkey_from_peer_id(signer_peer_id) else {
        return false;
    };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify_strict(msg, &signature).is_ok()
}

/// Domain tag for the MLS identity-binding signature (the messenger's
/// `vos-msg/identity-binding/v1`). Separate from [`REGISTRY_OP_DOMAIN`]
/// so a registry-op signature can never be replayed as a binding cert.
pub const BINDING_DOMAIN: &[u8] = b"vos-msg/identity-binding/v1";

/// Canonical bytes the operator's identity key signs to bind an MLS
/// signature key to a space PeerId: `domain || u16(mls_pubkey.len) ||
/// mls_pubkey || u16(peer_id.len) || peer_id || space_id`. Shared so the
/// messenger actor (which verifies the cert on every leaf) and the CLI
/// (`vosx`, which produces it) build identical bytes from one source —
/// it lives here next to [`canonical_op_bytes`] because both are
/// signing-byte builders the PVM actor flavor and the host must agree on.
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

#[cfg(test)]
mod tests {
    use super::*;
    use vos::Message;
    use vos::actors::context::ServiceId;

    fn registry() -> SpaceRegistry {
        let mut r = SpaceRegistry::new();
        // Establish the genesis root so signed mutators authorize
        // against it (tests sign every op as the root via `root_auth`).
        let status = dispatch(
            &mut r,
            SetRoot {
                root: root_peer_id(),
            },
        );
        assert_eq!(status, STATUS_OK, "set_root on a fresh registry");
        r
    }

    fn run<F: core::future::Future>(fut: F) -> F::Output {
        vos::block_on(fut)
    }

    // The `#[messages]` macro lifts each `#[msg]` handler into an
    // `impl Message<X> for SpaceRegistry` and removes the inherent
    // method. To exercise a handler from a test, we construct a
    // throwaway Context and dispatch via the trait. Helper keeps
    // each call site to one line.
    fn dispatch<M>(r: &mut SpaceRegistry, msg: M) -> <SpaceRegistry as Message<M>>::Output
    where
        SpaceRegistry: Message<M>,
    {
        let mut ctx: vos::Context<SpaceRegistry> = vos::Context::new(ServiceId(0));
        run(<SpaceRegistry as Message<M>>::handle(r, msg, &mut ctx))
    }

    // ── actor_acl_key — total order ─────────────────────────────

    #[test]
    fn actor_acl_key_orders_by_peer_then_name() {
        // peer_id is the primary key; agent_name disambiguates
        // rows for the same peer. The dispatch path's binary
        // search depends on this total order.
        use core::cmp::Ordering;
        assert_eq!(actor_acl_key(b"aaa", "x", b"aaa", "x"), Ordering::Equal);
        assert_eq!(actor_acl_key(b"aaa", "x", b"aab", "x"), Ordering::Less);
        assert_eq!(actor_acl_key(b"aab", "x", b"aaa", "x"), Ordering::Greater);
        // Same peer, agent_name disambiguates.
        assert_eq!(actor_acl_key(b"aaa", "x", b"aaa", "y"), Ordering::Less);
        assert_eq!(actor_acl_key(b"aaa", "y", b"aaa", "x"), Ordering::Greater);
    }

    // ── grant_actor_role / actor_role round-trip ────────────────

    #[test]
    fn grant_actor_role_then_lookup_returns_role() {
        let mut r = registry();
        let peer = alloc::vec![1, 2, 3];
        let agent = String::from("dev-project");
        let status = grant_actor(&mut r, &peer, &agent, 2);
        assert_eq!(status, STATUS_OK);

        let role = dispatch(
            &mut r,
            ActorRole {
                peer_id: peer.clone(),
                agent_name: agent.clone(),
            },
        );
        assert_eq!(role, 2, "ActorRole must return the granted byte");
    }

    #[test]
    fn actor_role_unknown_peer_returns_none_byte() {
        // AUTH_ROLE_NONE is the "no row" sentinel — the dispatch
        // path turns this into `Option<u8>::None` before passing
        // to Context::set_caller_roles (M5).
        let mut r = registry();
        let role = dispatch(
            &mut r,
            ActorRole {
                peer_id: alloc::vec![9, 9, 9],
                agent_name: String::from("any"),
            },
        );
        assert_eq!(role, AUTH_ROLE_NONE);
    }

    #[test]
    fn grant_actor_role_is_idempotent_for_same_role() {
        // Re-granting the same row must not duplicate or error.
        // Operators frequently call grant on bootstrap; the
        // second run must be a clean no-op.
        let mut r = registry();
        let peer = alloc::vec![1, 2, 3];
        let agent = String::from("dev-project");
        assert_eq!(grant_actor(&mut r, &peer, &agent, 2), STATUS_OK);
        assert_eq!(grant_actor(&mut r, &peer, &agent, 2), STATUS_OK);
        assert_eq!(
            dispatch(
                &mut r,
                ActorRole {
                    peer_id: peer.clone(),
                    agent_name: agent.clone(),
                },
            ),
            2,
        );
        let all = dispatch(&mut r, ActorAcls);
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn grant_actor_role_changes_role_in_place() {
        // Re-granting with a different role updates rather than
        // inserts. Operators changing a peer's actor-local role
        // expect the old grant to be replaced.
        let mut r = registry();
        let peer = alloc::vec![1, 2, 3];
        let agent = String::from("dev-project");
        grant_actor(&mut r, &peer, &agent, 1);
        grant_actor(&mut r, &peer, &agent, 3);
        assert_eq!(
            dispatch(
                &mut r,
                ActorRole {
                    peer_id: peer.clone(),
                    agent_name: agent.clone(),
                },
            ),
            3,
        );
        assert_eq!(dispatch(&mut r, ActorAcls).len(), 1);
    }

    #[test]
    fn grant_actor_role_rejects_empty_peer_or_name() {
        // Empty peer/name would alias to an unintended row and
        // collide with future identity bytes. STATUS_BAD_HASH
        // matches the existing convention from grant_role.
        let mut r = registry();
        // The op is root-signed (authorize_op passes); the empty-arg
        // guard inside the handler is what rejects.
        assert_eq!(grant_actor(&mut r, &[], "x", 1), STATUS_BAD_HASH);
        assert_eq!(grant_actor(&mut r, &[1], "", 1), STATUS_BAD_HASH);
    }

    // ── revoke_actor_role ───────────────────────────────────────

    #[test]
    fn revoke_actor_role_removes_grant() {
        let mut r = registry();
        let peer = alloc::vec![1, 2, 3];
        let agent = String::from("dev-project");
        grant_actor(&mut r, &peer, &agent, 2);
        let status = revoke_actor(&mut r, &peer, &agent);
        assert_eq!(status, STATUS_OK);
        assert_eq!(
            dispatch(
                &mut r,
                ActorRole {
                    peer_id: peer.clone(),
                    agent_name: agent.clone(),
                },
            ),
            AUTH_ROLE_NONE,
        );
        assert!(dispatch(&mut r, ActorAcls).is_empty());
    }

    #[test]
    fn revoke_actor_role_missing_returns_not_found() {
        let mut r = registry();
        let status = revoke_actor(&mut r, &[1], "x");
        assert_eq!(status, STATUS_NOT_FOUND);
    }

    // ── multi-peer / multi-agent ─────────────────────────────────

    #[test]
    fn one_peer_can_have_distinct_roles_per_agent() {
        // The whole point of actor-local grants: Bob can be
        // Maintainer on dev-project AND Viewer on dev-payments
        // without one role bleeding into the other.
        let mut r = registry();
        let peer = alloc::vec![1, 2, 3];
        grant_actor(&mut r, &peer, "a", 1);
        grant_actor(&mut r, &peer, "b", 3);
        assert_eq!(
            dispatch(
                &mut r,
                ActorRole {
                    peer_id: peer.clone(),
                    agent_name: String::from("a"),
                },
            ),
            1,
        );
        assert_eq!(
            dispatch(
                &mut r,
                ActorRole {
                    peer_id: peer.clone(),
                    agent_name: String::from("b"),
                },
            ),
            3,
        );
        assert_eq!(dispatch(&mut r, ActorAcls).len(), 2);
    }

    #[test]
    fn rows_stay_sorted_under_arbitrary_insertion_order() {
        // binary_search_by depends on a total order. Insert in
        // reverse and confirm actor_acls() returns sorted order.
        let mut r = registry();
        for peer_byte in (1u8..=4).rev() {
            grant_actor(&mut r, &[peer_byte], "z", 1);
        }
        let rows = dispatch(&mut r, ActorAcls);
        for w in rows.windows(2) {
            assert!(
                actor_acl_key(
                    &w[0].peer_id,
                    &w[0].agent_name,
                    &w[1].peer_id,
                    &w[1].agent_name
                ) == core::cmp::Ordering::Less,
                "actor_acls rows must be in sorted order",
            );
        }
    }

    #[test]
    fn space_level_grant_table_unaffected_by_actor_local_grants() {
        // The two tables are independent: granting an actor-
        // local role must not touch the space-level grant
        // and vice versa.
        let mut r = registry();
        let peer = alloc::vec![1, 2, 3];
        grant_space(&mut r, &peer, AUTH_ROLE_DEVELOPER);
        grant_actor(&mut r, &peer, "x", 3);
        assert_eq!(
            dispatch(
                &mut r,
                PeerRole {
                    peer_id: peer.clone(),
                },
            ),
            AUTH_ROLE_DEVELOPER,
        );
        assert_eq!(
            dispatch(
                &mut r,
                ActorRole {
                    peer_id: peer.clone(),
                    agent_name: String::from("x"),
                },
            ),
            3,
        );
    }

    // ── Monotone-locality widen guard ───────────────────────────

    /// Publish a throwaway program (idempotent for the same hash)
    /// and install `name` at `consistency`, returning the status.
    fn install_at(r: &mut SpaceRegistry, name: &str, consistency: u8) -> u8 {
        let hash = alloc::vec![7u8; 32];
        let pub_status = dispatch(
            r,
            Publish {
                name: String::from("p"),
                version: String::from("1"),
                hash: hash.clone(),
                auth: root_auth("publish", &[b"p", b"1", &hash]),
            },
        );
        assert!(pub_status == STATUS_OK, "program publish must succeed");
        let rep = alloc::vec![9u8; 32];
        dispatch(
            r,
            Install {
                instance_name: String::from(name),
                program_name: String::from("p"),
                program_version: String::from("1"),
                program_hash: hash.clone(),
                replication_id: rep.clone(),
                consistency,
                install_args: Vec::new(),
                install_payloads: Vec::new(),
                auth: root_auth(
                    "install",
                    &[
                        name.as_bytes(),
                        b"p",
                        b"1",
                        &hash,
                        &rep,
                        &[consistency],
                        &[],
                        &[],
                    ],
                ),
            },
        )
    }

    fn uninstall(r: &mut SpaceRegistry, name: &str) -> u8 {
        dispatch(
            r,
            Uninstall {
                instance_name: String::from(name),
                auth: root_auth("uninstall", &[name.as_bytes()]),
            },
        )
    }

    #[test]
    fn shareability_orders_confined_below_replicated() {
        assert!(shareability(0) < shareability(1)); // Ephemeral < Local
        assert!(shareability(1) < shareability(2)); // Local < Crdt
        assert_eq!(shareability(2), shareability(3)); // Crdt == Raft (rank-equal)
        // Unknown bytes are treated as fully shared, never confined.
        assert_eq!(shareability(4), 2);
        assert_eq!(shareability(255), 2);
    }

    #[test]
    fn may_transition_to_allows_narrow_and_lateral_only() {
        assert!(may_transition_to(1, 1)); // Local -> Local
        assert!(may_transition_to(1, 0)); // Local -> Ephemeral (narrow)
        assert!(!may_transition_to(1, 2)); // Local -> Crdt (widen) denied
        assert!(!may_transition_to(1, 3)); // Local -> Raft (widen) denied
        assert!(may_transition_to(2, 3)); // Crdt -> Raft (rank-equal lateral)
        assert!(may_transition_to(3, 2)); // Raft -> Crdt (rank-equal lateral)
        assert!(may_transition_to(2, 1)); // Crdt -> Local (narrow)
        assert!(!may_transition_to(0, 1)); // Ephemeral -> Local (widen) denied
    }

    #[test]
    fn reinstall_widening_after_uninstall_is_denied() {
        let mut r = registry();
        assert_eq!(install_at(&mut r, "msg-foo", 1 /* Local */), STATUS_OK);
        assert_eq!(uninstall(&mut r, "msg-foo"), STATUS_OK);
        // The floor survives uninstall: reusing the name at a wider tier
        // is refused — widening needs a fresh name.
        assert_eq!(
            install_at(&mut r, "msg-foo", 2 /* Crdt */),
            STATUS_CONSISTENCY_WIDEN_DENIED
        );
        assert_eq!(
            install_at(&mut r, "msg-foo", 3 /* Raft */),
            STATUS_CONSISTENCY_WIDEN_DENIED
        );
        // Re-installing at the same or a narrower tier is fine.
        assert_eq!(install_at(&mut r, "msg-foo", 1 /* Local */), STATUS_OK);
        assert_eq!(uninstall(&mut r, "msg-foo"), STATUS_OK);
        assert_eq!(install_at(&mut r, "msg-foo", 0 /* Ephemeral */), STATUS_OK);
    }

    #[test]
    fn lateral_crdt_raft_reinstall_is_allowed() {
        let mut r = registry();
        assert_eq!(install_at(&mut r, "shared", 2 /* Crdt */), STATUS_OK);
        assert_eq!(uninstall(&mut r, "shared"), STATUS_OK);
        // Crdt <-> Raft is a rank-equal lateral move, allowed in v0.
        assert_eq!(install_at(&mut r, "shared", 3 /* Raft */), STATUS_OK);
    }

    #[test]
    fn fresh_instance_name_installs_at_any_tier() {
        let mut r = registry();
        assert_eq!(install_at(&mut r, "a", 0 /* Ephemeral */), STATUS_OK);
        assert_eq!(install_at(&mut r, "b", 3 /* Raft */), STATUS_OK);
        assert_eq!(install_at(&mut r, "c", 2 /* Crdt */), STATUS_OK);
    }

    #[test]
    fn floor_tracks_narrowest_ever_so_widening_back_is_denied() {
        // Crdt, then narrow to Local on reinstall — the floor pins at
        // Local, so a later attempt to widen back to Crdt is refused.
        let mut r = registry();
        assert_eq!(install_at(&mut r, "drift", 2 /* Crdt */), STATUS_OK);
        assert_eq!(uninstall(&mut r, "drift"), STATUS_OK);
        assert_eq!(install_at(&mut r, "drift", 1 /* Local */), STATUS_OK);
        assert_eq!(uninstall(&mut r, "drift"), STATUS_OK);
        assert_eq!(
            install_at(&mut r, "drift", 2 /* Crdt */),
            STATUS_CONSISTENCY_WIDEN_DENIED
        );
    }

    #[test]
    fn live_instance_reinstall_reports_exists_not_widen() {
        let mut r = registry();
        assert_eq!(install_at(&mut r, "live", 1 /* Local */), STATUS_OK);
        // A live row takes precedence: even a widen attempt is the
        // pre-existing "already installed" error, not the widen guard.
        assert_eq!(
            install_at(&mut r, "live", 2 /* Crdt */),
            STATUS_INSTANCE_EXISTS
        );
    }

    // ── Signed registry ops ────────────────────────────────

    use ed25519_dalek::{Signer, SigningKey};

    /// Deterministic test signing key standing in for the operator /
    /// genesis root. Fixed bytes → reproducible across runs.
    fn root_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// Build the 38-byte libp2p ed25519 PeerId for a raw pubkey — the
    /// inverse of [`ed25519_pubkey_from_peer_id`], so tests can mint a
    /// PeerId for a dalek key without depending on libp2p.
    fn peer_id_for(pk: &[u8; 32]) -> Vec<u8> {
        let mut id = alloc::vec![0x00u8, 0x24, 0x08, 0x01, 0x12, 0x20];
        id.extend_from_slice(pk);
        id
    }

    fn root_peer_id() -> Vec<u8> {
        peer_id_for(&root_key().verifying_key().to_bytes())
    }

    /// Sign an op's canonical bytes as the root, packing the auth blob
    /// the way the CLI/daemon would.
    fn root_auth(op: &str, fields: &[&[u8]]) -> Vec<u8> {
        let sig = root_key().sign(&canonical_op_bytes(op, fields));
        pack_auth(&root_peer_id(), &sig.to_bytes())
    }

    /// Root-signed `grant_role` dispatch (the common case in tests).
    fn grant_space(r: &mut SpaceRegistry, peer: &[u8], role: u8) -> u8 {
        dispatch(
            r,
            GrantRole {
                peer_id: peer.to_vec(),
                role,
                auth: root_auth("grant_role", &[peer, &[role]]),
            },
        )
    }

    /// Root-signed `grant_actor_role` dispatch.
    fn grant_actor(r: &mut SpaceRegistry, peer: &[u8], agent: &str, role: u8) -> u8 {
        dispatch(
            r,
            GrantActorRole {
                peer_id: peer.to_vec(),
                agent_name: String::from(agent),
                role,
                auth: root_auth("grant_actor_role", &[peer, agent.as_bytes(), &[role]]),
            },
        )
    }

    /// Root-signed `revoke_actor_role` dispatch.
    fn revoke_actor(r: &mut SpaceRegistry, peer: &[u8], agent: &str) -> u8 {
        dispatch(
            r,
            RevokeActorRole {
                peer_id: peer.to_vec(),
                agent_name: String::from(agent),
                auth: root_auth("revoke_actor_role", &[peer, agent.as_bytes()]),
            },
        )
    }

    #[test]
    fn peer_id_pubkey_extraction_round_trips() {
        let pk = root_key().verifying_key().to_bytes();
        let pid = peer_id_for(&pk);
        assert_eq!(pid.len(), 38);
        assert_eq!(ed25519_pubkey_from_peer_id(&pid), Some(pk));
        // Wrong length / wrong prefix → not an ed25519 signer.
        assert_eq!(ed25519_pubkey_from_peer_id(&pid[..37]), None);
        let mut bad = pid.clone();
        bad[0] = 0x12; // not the identity-multihash code
        assert_eq!(ed25519_pubkey_from_peer_id(&bad), None);
    }

    #[test]
    fn verify_op_sig_accepts_valid_and_rejects_tampered() {
        let key = root_key();
        let pid = peer_id_for(&key.verifying_key().to_bytes());
        let canonical = canonical_op_bytes("grant_role", &[&[1, 2, 3], &[AUTH_ROLE_ADMIN]]);
        let sig = key.sign(&canonical).to_bytes();

        assert!(verify_op_sig(&pid, &canonical, &sig), "valid sig accepted");

        // Tampered message (different role) → rejected.
        let other = canonical_op_bytes("grant_role", &[&[1, 2, 3], &[AUTH_ROLE_READONLY]]);
        assert!(!verify_op_sig(&pid, &other, &sig), "wrong message rejected");

        // Tampered signature → rejected.
        let mut bad_sig = sig;
        bad_sig[0] ^= 0xFF;
        assert!(!verify_op_sig(&pid, &canonical, &bad_sig), "bad sig rejected");

        // Different signer identity → rejected (sig doesn't match key).
        let other_key = SigningKey::from_bytes(&[9u8; 32]);
        let other_pid = peer_id_for(&other_key.verifying_key().to_bytes());
        assert!(
            !verify_op_sig(&other_pid, &canonical, &sig),
            "sig under a different key rejected",
        );
    }

    #[test]
    fn unpack_auth_round_trips_and_rejects_short() {
        let pid = root_peer_id();
        let sig = [3u8; OP_SIG_LEN];
        let blob = pack_auth(&pid, &sig);
        let (signer, got) = unpack_auth(&blob).expect("well-formed auth unpacks");
        assert_eq!(signer, pid.as_slice());
        assert_eq!(got, sig);
        // Too short to hold a signature.
        assert!(unpack_auth(&[0u8; OP_SIG_LEN]).is_none());
        assert!(unpack_auth(&[]).is_none());
    }

    #[test]
    fn canonical_op_bytes_is_unambiguous() {
        // Field boundaries are length-prefixed, so concatenation
        // ambiguity ("ab"+"c" vs "a"+"bc") can't collide.
        let a = canonical_op_bytes("op", &[b"ab", b"c"]);
        let b = canonical_op_bytes("op", &[b"a", b"bc"]);
        assert_ne!(a, b);
        // Op name is bound too: same fields, different op → different bytes.
        let c = canonical_op_bytes("op2", &[b"ab", b"c"]);
        assert_ne!(a, c);
    }

    // ── Authorization: the forge gap is closed ────────────────────

    /// Sign an op as an arbitrary key (a would-be attacker or a
    /// delegated admin), packing the auth blob.
    fn auth_as(key: &SigningKey, op: &str, fields: &[&[u8]]) -> Vec<u8> {
        let sig = key.sign(&canonical_op_bytes(op, fields));
        pack_auth(&peer_id_for(&key.verifying_key().to_bytes()), &sig.to_bytes())
    }

    /// Dispatch as `Caller::System` — the trusted caller CRDT replay
    /// uses, which clears the `#[msg(role)]` gate. Models the exact
    /// path a forged op merged via sync takes on an honest node.
    fn dispatch_as_system<M>(
        r: &mut SpaceRegistry,
        msg: M,
    ) -> <SpaceRegistry as Message<M>>::Output
    where
        SpaceRegistry: Message<M>,
    {
        let mut ctx: vos::Context<SpaceRegistry> = vos::Context::new(ServiceId(0));
        ctx.set_caller(vos::actors::auth::Caller::System);
        run(<SpaceRegistry as Message<M>>::handle(r, msg, &mut ctx))
    }

    #[test]
    fn forged_admin_grant_rejected_on_system_replay_path() {
        // The key mechanism: on replay the op arrives as Caller::System,
        // so the #[msg(role=Admin)] gate is a no-op — yet authorize_op
        // still rejects a forgery, so a CRDT-merged AuthGrantRow{ADMIN}
        // never applies on an honest node.
        let mut r = registry();
        let attacker_key = SigningKey::from_bytes(&[42u8; 32]);
        let attacker = peer_id_for(&attacker_key.verifying_key().to_bytes());
        let auth = auth_as(&attacker_key, "grant_role", &[&attacker, &[AUTH_ROLE_ADMIN]]);
        let status = dispatch_as_system(
            &mut r,
            GrantRole {
                peer_id: attacker.clone(),
                role: AUTH_ROLE_ADMIN,
                auth,
            },
        );
        assert_eq!(status, STATUS_FORBIDDEN, "System caller can't bypass authorize_op");
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: attacker }),
            AUTH_ROLE_NONE,
        );
    }

    #[test]
    fn set_root_is_first_write_wins() {
        let mut r = SpaceRegistry::new();
        assert!(dispatch(&mut r, Root).is_empty(), "no root before genesis");
        assert_eq!(
            dispatch(&mut r, SetRoot { root: root_peer_id() }),
            STATUS_OK,
        );
        assert_eq!(dispatch(&mut r, Root), root_peer_id());
        // A second set_root — e.g. a forged genesis merged via CRDT —
        // is refused; the genesis root is immutable.
        assert_eq!(
            dispatch(
                &mut r,
                SetRoot {
                    root: alloc::vec![0xFFu8; 38],
                },
            ),
            STATUS_FORBIDDEN,
        );
        assert_eq!(dispatch(&mut r, Root), root_peer_id());
    }

    #[test]
    fn unsigned_grant_is_rejected() {
        // The exact forge vector: a peer authors a grant_role op with
        // no valid signature. authorize_op fails closed.
        let mut r = registry();
        let victim = alloc::vec![1, 2, 3];
        assert_eq!(
            dispatch(
                &mut r,
                GrantRole {
                    peer_id: victim.clone(),
                    role: AUTH_ROLE_ADMIN,
                    auth: Vec::new(),
                },
            ),
            STATUS_FORBIDDEN,
        );
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: victim }), AUTH_ROLE_NONE);
    }

    #[test]
    fn forged_admin_grant_by_non_admin_is_rejected() {
        // A space member (valid signature, but NOT root and NOT an
        // admin) tries to self-escalate to ADMIN. Refused.
        let mut r = registry();
        let attacker_key = SigningKey::from_bytes(&[42u8; 32]);
        let attacker = peer_id_for(&attacker_key.verifying_key().to_bytes());
        let auth = auth_as(&attacker_key, "grant_role", &[&attacker, &[AUTH_ROLE_ADMIN]]);
        assert_eq!(
            dispatch(
                &mut r,
                GrantRole {
                    peer_id: attacker.clone(),
                    role: AUTH_ROLE_ADMIN,
                    auth,
                },
            ),
            STATUS_FORBIDDEN,
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: attacker }),
            AUTH_ROLE_NONE,
        );
    }

    #[test]
    fn forged_voter_row_by_non_admin_is_rejected() {
        // The other headline: a peer forges a Node VOTER member row to
        // seize raft/chronos consensus. Refused unless an admin signs.
        let mut r = registry();
        // [99;32] is neither the root key ([7;32]) nor a granted admin.
        let attacker_key = SigningKey::from_bytes(&[99u8; 32]);
        let node = peer_id_for(&attacker_key.verifying_key().to_bytes());
        let forged = auth_as(
            &attacker_key,
            "add_node",
            &[&5u32.to_le_bytes(), &node, &[NODE_ROLE_VOTER]],
        );
        assert_eq!(
            dispatch(
                &mut r,
                AddNode {
                    prefix: 5,
                    peer_id: node.clone(),
                    role: NODE_ROLE_VOTER,
                    auth: forged,
                },
            ),
            STATUS_FORBIDDEN,
        );
        assert_eq!(dispatch(&mut r, NodeRole { prefix: 5 }), 0, "not enrolled");

        // Root-signed enrollment of the same node succeeds.
        let ok = root_auth("add_node", &[&5u32.to_le_bytes(), &node, &[NODE_ROLE_VOTER]]);
        assert_eq!(
            dispatch(
                &mut r,
                AddNode {
                    prefix: 5,
                    peer_id: node,
                    role: NODE_ROLE_VOTER,
                    auth: ok,
                },
            ),
            STATUS_OK,
        );
        assert_eq!(dispatch(&mut r, NodeRole { prefix: 5 }), NODE_ROLE_VOTER + 1);
    }

    #[test]
    fn forged_install_rejected_on_system_replay_path() {
        // The catalog-forgery guard: a non-admin peer forges an `install` op (a
        // fabricated AgentRow) and merges it via CRDT. On replay it
        // arrives as Caller::System, so the #[msg(role)] gate is a
        // no-op — yet authorize_op rejects it, so reconcile never sees
        // the row and the forged agent never spawns on an honest node.
        let mut r = registry();
        let attacker_key = SigningKey::from_bytes(&[42u8; 32]);
        let hash = alloc::vec![7u8; 32];
        let rep = alloc::vec![9u8; 32];
        let forged = auth_as(
            &attacker_key,
            "install",
            &[b"evil", b"p", b"1", &hash, &rep, &[2u8], &[], &[]],
        );
        let status = dispatch_as_system(
            &mut r,
            Install {
                instance_name: String::from("evil"),
                program_name: String::from("p"),
                program_version: String::from("1"),
                program_hash: hash,
                replication_id: rep,
                consistency: 2,
                install_args: Vec::new(),
                install_payloads: Vec::new(),
                auth: forged,
            },
        );
        assert_eq!(
            status, STATUS_FORBIDDEN,
            "System caller can't bypass authorize_op for install",
        );
        assert!(
            dispatch(
                &mut r,
                Agent {
                    instance_name: String::from("evil"),
                },
            )
            .is_none(),
            "forged AgentRow must never land",
        );
    }

    #[test]
    fn forged_publish_rejected_on_system_replay_path() {
        // The program-catalog half of the same vector: a forged
        // ProgramRow merged via CRDT is refused on replay.
        let mut r = registry();
        let attacker_key = SigningKey::from_bytes(&[42u8; 32]);
        let hash = alloc::vec![7u8; 32];
        let forged = auth_as(&attacker_key, "publish", &[b"evil", b"1", &hash]);
        let status = dispatch_as_system(
            &mut r,
            Publish {
                name: String::from("evil"),
                version: String::from("1"),
                hash,
                auth: forged,
            },
        );
        assert_eq!(status, STATUS_FORBIDDEN);
        assert!(
            dispatch(
                &mut r,
                Program {
                    name: String::from("evil"),
                    version: String::from("1"),
                },
            )
            .is_none(),
            "forged ProgramRow must never land",
        );
    }

    #[test]
    fn unsigned_install_is_rejected() {
        // An `install` with no auth blob fails closed, just like the
        // auth/member mutators.
        let mut r = registry();
        let status = dispatch(
            &mut r,
            Install {
                instance_name: String::from("x"),
                program_name: String::from("p"),
                program_version: String::from("1"),
                program_hash: alloc::vec![7u8; 32],
                replication_id: alloc::vec![9u8; 32],
                consistency: 2,
                install_args: Vec::new(),
                install_payloads: Vec::new(),
                auth: Vec::new(),
            },
        );
        assert_eq!(status, STATUS_FORBIDDEN);
    }

    #[test]
    fn root_signed_install_lands_the_agent_row() {
        // Positive control: the operator (root) signs publish+install
        // (as the host sign-on-relay seam does on the admin node), so
        // authorize_op passes and the AgentRow materializes — proving
        // the signed path doesn't reject legitimate catalog ops.
        let mut r = registry();
        assert_eq!(install_at(&mut r, "good", 2), STATUS_OK);
        let row = dispatch(
            &mut r,
            Agent {
                instance_name: String::from("good"),
            },
        )
        .expect("root-signed install lands the row");
        assert_eq!(row.instance_name, "good");
    }

    #[test]
    fn root_delegates_admin_and_delegate_can_sign() {
        // State-anchored delegation: root grants ADMIN to Bob; Bob's
        // own signature then authorizes a further grant. Authority
        // chains back to the genesis root through auth_grants.
        let mut r = registry();
        let bob_key = SigningKey::from_bytes(&[11u8; 32]);
        let bob = peer_id_for(&bob_key.verifying_key().to_bytes());
        assert_eq!(grant_space(&mut r, &bob, AUTH_ROLE_ADMIN), STATUS_OK);

        // Bob (now admin) grants Carol READONLY, signing with his key.
        let carol = alloc::vec![3, 3, 3];
        let auth = auth_as(&bob_key, "grant_role", &[&carol, &[AUTH_ROLE_READONLY]]);
        assert_eq!(
            dispatch(
                &mut r,
                GrantRole {
                    peer_id: carol.clone(),
                    role: AUTH_ROLE_READONLY,
                    auth,
                },
            ),
            STATUS_OK,
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: carol }),
            AUTH_ROLE_READONLY,
        );

        // But a peer Bob granted only READONLY can't sign mutations.
        let dave_key = SigningKey::from_bytes(&[12u8; 32]);
        let dave = peer_id_for(&dave_key.verifying_key().to_bytes());
        assert_eq!(grant_space(&mut r, &dave, AUTH_ROLE_READONLY), STATUS_OK);
        let evil = auth_as(&dave_key, "grant_role", &[&dave, &[AUTH_ROLE_ADMIN]]);
        assert_eq!(
            dispatch(
                &mut r,
                GrantRole {
                    peer_id: dave.clone(),
                    role: AUTH_ROLE_ADMIN,
                    auth: evil,
                },
            ),
            STATUS_FORBIDDEN,
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: dave }),
            AUTH_ROLE_READONLY,
            "READONLY peer can't self-escalate",
        );
    }

    #[test]
    fn signature_does_not_authorize_a_different_op() {
        // A valid root signature over revoke_role's canonical bytes
        // must not pass grant_role — the op name is bound into the
        // signed bytes, defeating cross-op replay.
        let mut r = registry();
        let victim = alloc::vec![4, 5, 6];
        let wrong_op_auth = root_auth("revoke_role", &[&victim]);
        assert_eq!(
            dispatch(
                &mut r,
                GrantRole {
                    peer_id: victim.clone(),
                    role: AUTH_ROLE_ADMIN,
                    auth: wrong_op_auth,
                },
            ),
            STATUS_FORBIDDEN,
        );
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: victim }), AUTH_ROLE_NONE);
    }
}
