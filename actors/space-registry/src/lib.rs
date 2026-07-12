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

// ── Protocol (rows, status/role consts, canonical signing bytes) ──
//
// The wire types + the consensus-critical canonical encodings now live
// in `vos::registry` (one source of truth — no host-side mirror). We
// `pub use` them back so this crate's public API is unchanged and the
// actor's own state + handlers keep referring to the same names. The
// verifier-side `verify_op_sig` (ed25519) stays here (below), consuming
// the moved `ed25519_pubkey_from_peer_id`.
pub use vos::registry::{
    ActorAclPage, ActorAclRow, AgentRow, AuthGrantPage, AuthGrantRow, InvitePage, InviteRow,
    MemberPage, MemberRow, ProgramRow, SPACE_ID_DOMAIN_TAG, Status, SyncFloor,
    AUTH_ROLE_ADMIN, AUTH_ROLE_DEVELOPER, AUTH_ROLE_NONE, AUTH_ROLE_READONLY, BINDING_DOMAIN,
    MEMBER_KIND_IDENTITY, MEMBER_KIND_NODE, NODE_ROLE_OBSERVER, NODE_ROLE_VOTER, OP_SIG_LEN,
    PROOF_KIND_MERKLE_INCLUSION, PROOF_KIND_ZK, REGISTRY_OP_DOMAIN, binding_signed_bytes,
    canonical_op_bytes, ed25519_pubkey_from_peer_id, instance_service_id, pack_auth,
};

// ── Programs ──────────────────────────────────────────────────────

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

// ── Agents ────────────────────────────────────────────────────────

// ── Members ──────────────────────────────────────────────────────

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

/// One page of [`SpaceRegistry::host_mappings`]. `more` is the explicit
/// terminator: a page can come back short of the row cap because the
/// byte budget truncated it, so "short page = done" would silently end
/// a drain early — continue from the last row's `instance_name` while
/// `more` is true.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct HostMappingPage {
    pub mappings: Vec<HostMapping>,
    pub more: bool,
}

// ── Result codes ─────────────────────────────────────────────────

// ── Actor ─────────────────────────────────────────────────────────

use vos::prelude::*;
use vos::storage::{StorageMap, StorageSet, StorageValue, fill_page};

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
    /// Node members, one `#[storage]` row per node keyed by its `u16`
    /// `prefix` (a fixed-width key, so iteration is prefix-ordered).
    /// `node_role` point-gets; `members()` pages nodes before identities.
    #[storage]
    nodes: StorageMap<u16, MemberRow>,
    /// Identity members, one `#[storage]` row per identity keyed by
    /// `identity_key(public_key)` (variable-length key folded to fixed
    /// width; the row keeps the plain key). The nodes/identities split
    /// keeps each a single-key-type map — the old flat `Vec<MemberRow>`
    /// mixed `u16` prefixes and variable pubkeys.
    #[storage]
    identities: StorageMap<[u8; 32], MemberRow>,
    /// Opaque metadata blobs keyed by program hash. Stored as raw
    /// `.vos_meta` section bytes so the registry stays agnostic
    /// about the schema format (lives in `vos::metadata` on the
    /// consumer side). A `#[storage]` map so each program's meta is
    /// its own KV row — read by point `meta_for_program`, never
    /// enumerated — instead of riding the state blob.
    #[storage]
    metas: StorageMap<[u8; 32], MetaRow>,
    /// Opaque metadata blobs for native `.so` extensions, keyed by
    /// the manifest `instance_name`. Service-mode extensions have
    /// no program-hash identity in this catalog (the host loads
    /// them off a filesystem path), so we key by the operator-
    /// visible name. `meta_for_instance` falls through here when
    /// the name doesn't match an installed PVM agent. A `#[storage]`
    /// map keyed by `name_key(instance_name)` (the name folded to a
    /// fixed-width key); the row keeps the plain name.
    #[storage]
    extension_metas: StorageMap<[u8; 32], ExtensionMetaRow>,
    /// Sprint 2 — per-PeerId auth grants, one row per peer. A `#[storage]`
    /// map keyed by `peer_key(peer_id)`: `effective_role`/`peer_epoch`
    /// point-get, `auth_grants()` pages. Pre-Sprint-2 state archives don't
    /// have this field; the actor's fall-back-to-fresh behaviour on archive
    /// decode failure (see "Schema evolution" in this file's module doc)
    /// lets upgrades resync from the DAG.
    #[storage]
    auth_grants: StorageMap<[u8; 32], AuthGrantRow>,
    /// M4 — per-(peer, agent) actor-local ACL overrides, one row per pair.
    /// A `#[storage]` map keyed by `acl_key(peer_id, agent_name)`. Empty
    /// until an operator calls `grant_actor_role`. Falls through to
    /// `auth_grants` (space-level) when no actor-local grant exists for
    /// `(peer, target_agent)`.
    #[storage]
    actor_acls: StorageMap<[u8; 32], ActorAclRow>,
    /// Grow-only revoke high-waters for space-level grants, one row per
    /// peer. A `#[storage]` map keyed by `peer_key(peer_id)` so the
    /// floors live beside the grant rows they dominate: a state-blob
    /// drift fallback (`try_decode` failure → fresh struct) must reset
    /// authority state *together* — floors in the blob with grants in
    /// storage would resurrect every revoked grant. A grant is dominated
    /// while its epoch is at or below the peer's entry here (see
    /// [`AuthGrantRow::epoch`]). Retained across re-grants so revocation
    /// can't be undone by replaying a stale-epoch grant.
    #[storage]
    revoke_epochs: StorageMap<[u8; 32], u64>,
    /// Grow-only revoke high-waters for actor-local grants, keyed by
    /// `acl_key(peer_id, agent_name)`. Sibling of `revoke_epochs`.
    #[storage]
    actor_revoke_epochs: StorageMap<[u8; 32], u64>,
    /// Populated on the hyperspace registry replica only — the local
    /// space-registry leaves this empty so its `resolve` keeps the
    /// in-space behaviour (caller_prefix == host). A `#[storage]` map
    /// keyed by `name_key(instance_name)`; `resolve`/`register_remote`
    /// are point ops and `host_mappings()` pages in name order.
    #[storage]
    host_mappings: StorageMap<[u8; 32], HostMapping>,
    /// Monotone-locality floors: the narrowest consistency tier each
    /// `instance_name` was ever installed at (`vos::node::Consistency`
    /// discriminant); retained across `uninstall` so `install` can
    /// refuse to widen a reused name. A `#[storage]` map keyed by
    /// `name_key(instance_name)` — a security floor, kept in storage
    /// for the same drift-fallback reason as `revoke_epochs`.
    #[storage]
    consistency_floors: StorageMap<[u8; 32], u8>,
    /// Genesis root authority: the operator PeerId baked at
    /// `space new` via the first [`set_root`](SpaceRegistry::set_root)
    /// op. Empty until set. [`authorize_op`](SpaceRegistry::authorize_op)
    /// treats the root as the supreme signer of any mutation; every
    /// other admin's authority delegates from it through `auth_grants`.
    /// Pinned into `space_id` (it rides the genesis DAG), so a joiner
    /// verifies it via the same `space new`/`space verify` root recompute.
    /// A `#[storage]` value so the anchor every grant chain bottoms out
    /// at resets (or survives) together with the grant rows and revoke
    /// floors it governs — see `revoke_epochs`.
    #[storage]
    root: StorageValue<Vec<u8>>,
    /// Grow-only set of `replication_id`s any `install` has ever
    /// consumed. An install whose `replication_id` is already here is
    /// refused, so a captured `install` op can't be replayed to
    /// resurrect an uninstalled agent (the tombstone outlives the
    /// `AgentRow`). A legitimate reinstall uses a fresh
    /// `replication_id`. Order-independent: presence is a grow-only
    /// set, so the original install's id blocks the replay regardless
    /// of merge order. A `#[storage]` set — only membership is ever
    /// tested, so the burn/refuse pair is two point ops.
    #[storage]
    used_replication_ids: StorageSet<[u8; 32]>,
    /// Wave-1 invite tokens, one row per `token_pub`. A `#[storage]`
    /// map keyed by the 32-byte token public key: point redeem/revoke,
    /// `invites()` pages. The `revoked` flag is grow-only and lives on
    /// the row (in storage) for the same drift-fallback reason as
    /// `revoke_epochs` — a decode-drift reset must clear invites
    /// together with the grants they seed, never resurrect a revoked
    /// token.
    #[storage]
    invites: StorageMap<[u8; 32], InviteRow>,
}

#[messages]
impl SpaceRegistry {
    fn new() -> Self {
        Self {
            programs: Vec::new(),
            agents: Vec::new(),
            nodes: StorageMap::default(),
            identities: StorageMap::default(),
            metas: StorageMap::default(),
            extension_metas: StorageMap::default(),
            auth_grants: StorageMap::default(),
            actor_acls: StorageMap::default(),
            revoke_epochs: StorageMap::default(),
            actor_revoke_epochs: StorageMap::default(),
            host_mappings: StorageMap::default(),
            consistency_floors: StorageMap::default(),
            root: StorageValue::default(),
            used_replication_ids: StorageSet::default(),
            invites: StorageMap::default(),
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
    async fn set_root(&mut self, root: Vec<u8>) -> Status {
        if root.is_empty() {
            return Status::BadHash;
        }
        if !self.root_bytes().is_empty() {
            return Status::Forbidden;
        }
        self.root.set(&root);
        Status::Ok
    }

    /// The genesis root PeerId, or empty if none is set. Read surface
    /// for diagnostics and joiner verification.
    #[msg]
    async fn root(&self) -> Vec<u8> {
        self.root_bytes()
    }

    // ── Programs catalog ────────────────────────────────────────

    /// Add a program to the catalog. Tags are immutable — if
    /// `(name, version)` already exists, returns
    /// `Status::TagConflict` unless the existing hash matches
    /// (idempotent re-publish).
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn publish(&mut self, name: String, version: String, hash: Vec<u8>, auth: Vec<u8>) -> Status {
        if !self.authorize_op(
            &canonical_op_bytes("publish", &[name.as_bytes(), version.as_bytes(), &hash]),
            &auth,
        ) {
            return Status::Forbidden;
        }
        let Some(hash) = bytes_to_32(&hash) else {
            return Status::BadHash;
        };
        let mut idx = 0usize;
        while idx < self.programs.len() {
            let cur = &self.programs[idx];
            let cmp = compare_program(&cur.name, &cur.version, &name, &version);
            if cmp == 0 {
                if cur.hash == hash {
                    return Status::Ok;
                }
                return Status::TagConflict;
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
        Status::Ok
    }

    /// Remove a program from the catalog. Errors with
    /// `Status::InUse` if any agent still references the version.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn unpublish(&mut self, name: String, version: String, auth: Vec<u8>) -> Status {
        if !self.authorize_op(
            &canonical_op_bytes("unpublish", &[name.as_bytes(), version.as_bytes()]),
            &auth,
        ) {
            return Status::Forbidden;
        }
        let mut idx = 0usize;
        while idx < self.programs.len() {
            let cur = &self.programs[idx];
            if cur.name == name && cur.version == version {
                let hash = cur.hash;
                let mut ai = 0usize;
                while ai < self.agents.len() {
                    if self.agents[ai].program_hash == hash {
                        return Status::InUse;
                    }
                    ai += 1;
                }
                self.programs.remove(idx);
                return Status::Ok;
            }
            idx += 1;
        }
        Status::NotFound
    }

    /// Look up a single program by `(name, version)`.
    #[msg]
    async fn program(&self, name: String, version: String) -> Option<ProgramRow> {
        self.programs
            .iter()
            .find(|p| p.name == name && p.version == version)
            .cloned()
    }

    /// Snapshot the program catalog, sorted by `(name, version)`. Left
    /// unpaginated: `programs` stays blob-backed (so the reply is
    /// heap-bounded like the table itself) and PVM-actor consumers read it
    /// arg-free — pagination would break those callers for no reply-cap
    /// gain until the table actually moves to storage.
    #[msg]
    async fn programs(&self) -> Vec<ProgramRow> {
        self.programs.clone()
    }

    // ── Metadata blobs ──────────────────────────────────────────

    /// Record (or replace) the metadata blob for a program hash.
    /// Idempotent: re-registering the same hash overwrites the
    /// existing blob (lets a manifest re-deploy refresh schema).
    /// Returns `Status::BadHash` if the hash isn't 32 bytes;
    /// otherwise `Status::Ok`. The hash doesn't need to match an
    /// existing `ProgramRow` — schema can be registered before
    /// the program is published if the orchestrator prefers
    /// that order.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn register_meta(&mut self, program_hash: Vec<u8>, blob: Vec<u8>, auth: Vec<u8>) -> Status {
        if !self.authorize_op(
            &canonical_op_bytes("register_meta", &[&program_hash, &blob]),
            &auth,
        ) {
            return Status::Forbidden;
        }
        let Some(program_hash) = bytes_to_32(&program_hash) else {
            return Status::BadHash;
        };
        // Upsert: one point write, keyed by the program hash.
        self.metas.insert(&program_hash, &MetaRow { program_hash, blob });
        Status::Ok
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
        self.metas.get(&program_hash).map(|m| m.blob).unwrap_or_default()
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
                return self.metas.get(&hash).map(|m| m.blob).unwrap_or_default();
            }
            ai += 1;
        }
        // Fall through to the extension-meta table (keyed by name).
        self.extension_metas
            .get(&name_key(&name))
            .map(|e| e.blob)
            .unwrap_or_default()
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
    async fn register_extension_meta(
        &mut self,
        instance_name: String,
        blob: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.authorize_op(
            &canonical_op_bytes("register_extension_meta", &[instance_name.as_bytes(), &blob]),
            &auth,
        ) {
            return Status::Forbidden;
        }
        // An empty blob removes the row; otherwise upsert. Both are one
        // point op, keyed by the instance name.
        let key = name_key(&instance_name);
        if blob.is_empty() {
            self.extension_metas.remove(&key);
        } else {
            self.extension_metas.insert(
                &key,
                &ExtensionMetaRow {
                    instance_name,
                    blob,
                },
            );
        }
        Status::Ok
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
        network_reachable: bool,
        sync_role: u8,
        auth: Vec<u8>,
    ) -> Status {
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
                    &[network_reachable as u8],
                    &[sync_role],
                ],
            ),
            &auth,
        ) {
            return Status::Forbidden;
        }
        let Some(program_hash) = bytes_to_32(&program_hash) else {
            return Status::BadHash;
        };
        let Some(replication_id) = bytes_to_32(&replication_id) else {
            return Status::BadHash;
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
            return Status::ProgramNotFound;
        }

        let mut idx = 0usize;
        while idx < self.agents.len() {
            let cur = &self.agents[idx];
            if cur.instance_name == instance_name {
                return Status::InstanceExists;
            }
            if cur.instance_name.as_str() > instance_name.as_str() {
                break;
            }
            idx += 1;
        }

        // Anti-replay guard: the `replication_id` is a grow-only
        // tombstone. A captured `install` op replayed after the agent
        // was uninstalled reuses its id, so refuse any id already
        // consumed. Order-independent — the original install seeds the
        // id, so the replay is blocked regardless of merge order, and
        // the tombstone outlives the `AgentRow` that `uninstall` removes.
        if self.used_replication_ids.contains(&replication_id) {
            return Status::ReplicationIdReused;
        }

        // Monotone-locality guard (defense-in-depth): if this name was
        // ever installed before, its shareability may only narrow. A
        // reused name can't be *widened* into replication — that needs a
        // fresh name (and a fresh `replication_id`), so private-era state
        // is never folded into a now-shared DAG. The floor outlives the
        // row, so this fires on the uninstall→reinstall-wider path; a live
        // row already returned `Status::InstanceExists` above.
        let floor_key = name_key(&instance_name);
        match self.consistency_floors.get(&floor_key) {
            Some(floor) => {
                if !may_transition_to(floor, consistency) {
                    return Status::ConsistencyWidenDenied;
                }
                // Narrow (never widen) the recorded floor; a lateral
                // re-install leaves it unchanged.
                if shareability(consistency) < shareability(floor) {
                    self.consistency_floors.insert(&floor_key, &consistency);
                }
            }
            None => {
                self.consistency_floors.insert(&floor_key, &consistency);
            }
        }

        self.agents.insert(
            idx,
            AgentRow {
                instance_name,
                program_hash,
                program_name,
                program_version,
                replication_id,
                consistency,
                network_reachable,
                sync_role: SyncFloor::from_u8(sync_role).unwrap_or_default(),
                install_args,
                install_payloads,
            },
        );
        // Burn the replication_id so it can never seed a second install.
        self.used_replication_ids.insert(&replication_id);
        Status::Ok
    }

    /// Tombstone an agent. Local data on each replica moves to
    /// trash on the host side; the registry just removes the row.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn uninstall(&mut self, instance_name: String, auth: Vec<u8>) -> Status {
        if !self.authorize_op(
            &canonical_op_bytes("uninstall", &[instance_name.as_bytes()]),
            &auth,
        ) {
            return Status::Forbidden;
        }
        let mut idx = 0usize;
        while idx < self.agents.len() {
            if self.agents[idx].instance_name == instance_name {
                self.agents.remove(idx);
                return Status::Ok;
            }
            idx += 1;
        }
        Status::NotFound
    }

    /// Repoint an agent at a different program version. State
    /// is preserved (same `replication_id`, same redb); replicas
    /// restart their agent thread on the next sync.
    ///
    /// `from_hash` is the program hash the caller observed the instance
    /// currently running — a compare-and-swap precondition. The upgrade
    /// applies only if the live `AgentRow.program_hash` still equals
    /// `from_hash`, so a captured `upgrade` op replayed (e.g. to roll an
    /// instance back to a superseded version) finds a stale base and is
    /// refused. This is the version-monotonicity guard: each upgrade is
    /// pinned to the exact state it was authored against.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn upgrade(
        &mut self,
        instance_name: String,
        new_program_name: String,
        new_program_version: String,
        new_program_hash: Vec<u8>,
        from_hash: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.authorize_op(
            &canonical_op_bytes(
                "upgrade",
                &[
                    instance_name.as_bytes(),
                    new_program_name.as_bytes(),
                    new_program_version.as_bytes(),
                    &new_program_hash,
                    &from_hash,
                ],
            ),
            &auth,
        ) {
            return Status::Forbidden;
        }
        let Some(new_program_hash) = bytes_to_32(&new_program_hash) else {
            return Status::BadHash;
        };
        let Some(from_hash) = bytes_to_32(&from_hash) else {
            return Status::BadHash;
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
            return Status::ProgramNotFound;
        }

        let mut idx = 0usize;
        while idx < self.agents.len() {
            if self.agents[idx].instance_name == instance_name {
                // Compare-and-swap on the live program hash: a replayed
                // or stale upgrade whose `from_hash` no longer matches is
                // refused, so an instance can't be rolled back by
                // re-injecting a superseded `upgrade` op.
                if self.agents[idx].program_hash != from_hash {
                    return Status::StaleUpgrade;
                }
                self.agents[idx].program_name = new_program_name;
                self.agents[idx].program_version = new_program_version;
                self.agents[idx].program_hash = new_program_hash;
                return Status::Ok;
            }
            idx += 1;
        }
        Status::NotFound
    }

    #[msg]
    async fn agent(&self, instance_name: String) -> Option<AgentRow> {
        self.agents
            .iter()
            .find(|a| a.instance_name == instance_name)
            .cloned()
    }

    /// Snapshot the installed-agent roster, sorted by `instance_name`.
    /// Unpaginated for the same reason as `programs` — blob-backed and read
    /// arg-free by PVM actors (messenger, gateway).
    #[msg]
    async fn agents(&self) -> Vec<AgentRow> {
        self.agents.clone()
    }

    /// Lightweight enumeration of installed agent names, sorted by
    /// `instance_name`. Returns `Vec<String>` so cross-actor callers
    /// without `AgentRow` schema knowledge (e.g. the gateway rendering
    /// `/__schema`) can pull the list without an rkyv dance. Unpaginated on
    /// purpose: it is names-only, its `agents` backing stays blob-backed
    /// (so the reply is heap-bounded like `agents` itself), and the gateway
    /// consumes it arg-free — pagination would break that caller for no
    /// reply-size gain.
    #[msg]
    async fn agent_names(&self) -> Vec<String> {
        self.agents
            .iter()
            .map(|a| a.instance_name.clone())
            .collect()
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
        if let Some(h) = self.host_mappings.get(&name_key(&name)) {
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
    /// Returns `Status::BadPrefix` when `host_prefix` doesn't fit in
    /// a u16. Otherwise `Status::Ok`.
    #[msg]
    async fn register_remote(&mut self, instance_name: String, host_prefix: u32) -> Status {
        if host_prefix > u16::MAX as u32 {
            return Status::BadPrefix;
        }
        // An empty name is not resolvable — and it is the
        // host_mappings() pager's start-of-table sentinel, so a row
        // carrying it would wedge every drain that follows the
        // documented cursor protocol.
        if instance_name.is_empty() {
            return Status::BadHash;
        }
        let host_prefix = host_prefix as u16;
        // Idempotent upsert keyed by the instance name.
        self.host_mappings.insert(
            &name_key(&instance_name),
            &HostMapping {
                instance_name,
                host_prefix,
            },
        );
        Status::Ok
    }

    /// Page the host-mapping table. Diagnostic/test surface; production
    /// callers use `resolve`. Pass an empty `after_name` to start;
    /// continue from the last returned row's `instance_name` while the
    /// page's `more` flag is set (a short page alone doesn't mean done —
    /// the byte budget can truncate one). `budget` caps the page rows
    /// (0 = the handler's max). Rows come back in key (hashed-name)
    /// order, not name order — the cursor round-trips regardless.
    #[msg]
    async fn host_mappings(&self, after_name: String, budget: u32) -> HostMappingPage {
        let skip = (!after_name.is_empty()).then(|| name_key(&after_name));
        let start = skip.unwrap_or([0u8; 32]);
        let mut it = self
            .host_mappings
            .iter_from(&start)
            .filter(move |(k, _)| skip != Some(*k))
            .map(|(_, row)| row);
        let (mappings, more) = fill_page(&mut it, page_rows(budget), PAGE_BYTE_BUDGET);
        HostMappingPage { mappings, more }
    }

    // ── Members ────────────────────────────────────────────────

    /// Add a Node member. Idempotent in `prefix` — re-adding
    /// updates `peer_id` and `role`. `role` is
    /// `NODE_ROLE_VOTER` or `NODE_ROLE_OBSERVER`.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn add_node(&mut self, prefix: u32, peer_id: Vec<u8>, role: u8, auth: Vec<u8>) -> Status {
        if !self.authorize_op(
            &canonical_op_bytes("add_node", &[&prefix.to_le_bytes(), &peer_id, &[role]]),
            &auth,
        ) {
            return Status::Forbidden;
        }
        let prefix = prefix as u16;
        // Idempotent upsert keyed by the node prefix.
        self.nodes.insert(
            &prefix,
            &MemberRow {
                kind: MEMBER_KIND_NODE,
                key: peer_id,
                prefix,
                role,
                proof_kind: 0,
                proof_data: Vec::new(),
            },
        );
        Status::Ok
    }

    #[msg(role = SpaceRegistryRole::Admin)]
    async fn remove_node(&mut self, prefix: u32, auth: Vec<u8>) -> Status {
        if !self.authorize_op(
            &canonical_op_bytes("remove_node", &[&prefix.to_le_bytes()]),
            &auth,
        ) {
            return Status::Forbidden;
        }
        if self.nodes.remove(&(prefix as u16)) {
            Status::Ok
        } else {
            Status::NotFound
        }
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
    ) -> Status {
        if !self.authorize_op(
            &canonical_op_bytes(
                "add_identity",
                &[&public_key, &[proof_kind], &proof_data],
            ),
            &auth,
        ) {
            return Status::Forbidden;
        }
        // An empty key is not an identity — and defense in depth for
        // the members() pager, whose phase-start sentinel is empty.
        if public_key.is_empty() {
            return Status::BadHash;
        }
        // Idempotent upsert keyed by the identity public key.
        self.identities.insert(
            &identity_key(&public_key),
            &MemberRow {
                kind: MEMBER_KIND_IDENTITY,
                key: public_key,
                prefix: 0,
                role: 0,
                proof_kind,
                proof_data,
            },
        );
        Status::Ok
    }

    #[msg(role = SpaceRegistryRole::Admin)]
    async fn remove_identity(&mut self, public_key: Vec<u8>, auth: Vec<u8>) -> Status {
        if !self.authorize_op(
            &canonical_op_bytes("remove_identity", &[&public_key]),
            &auth,
        ) {
            return Status::Forbidden;
        }
        if self.identities.remove(&identity_key(&public_key)) {
            Status::Ok
        } else {
            Status::NotFound
        }
    }

    /// One page of the member roster, nodes (by prefix) before identities
    /// (by key) — the single ordered stream the old flat `Vec<MemberRow>`
    /// presented, now stitched across the two `#[storage]` maps. Pass
    /// `(0, [])` to start; continue from the returned page's
    /// `(next_kind, next_key)` while `more` is true. `budget` caps the page.
    #[msg]
    async fn members(&self, after_kind: u8, after_key: Vec<u8>, budget: u32) -> MemberPage {
        let cap = page_rows(budget);
        // Node phase: whenever the cursor isn't already in the identity
        // phase (a fresh start, or resuming a node prefix).
        if after_kind != MEMBER_KIND_IDENTITY {
            let start: u16 = if after_key.len() == 2 {
                u16::from_be_bytes([after_key[0], after_key[1]])
            } else {
                0
            };
            let skip = (after_key.len() == 2).then_some(start);
            let mut it = self
                .nodes
                .iter_from(&start)
                .filter(move |(k, _)| skip != Some(*k))
                .map(|(_, m)| m);
            let (page, more) = fill_page(&mut it, cap, PAGE_BYTE_BUDGET);
            if !page.is_empty() {
                return if more {
                    let next_key = page.last().map(|m| m.prefix.to_be_bytes().to_vec()).unwrap_or_default();
                    MemberPage { members: page, next_kind: MEMBER_KIND_NODE, next_key, more: true }
                } else {
                    // Nodes drained — the next page starts the identity phase.
                    MemberPage { members: page, next_kind: MEMBER_KIND_IDENTITY, next_key: Vec::new(), more: true }
                };
            }
            // No nodes in range: fall through into the identity phase now.
        }
        // Identity phase. The cursor carries the row's *hashed* 32-byte
        // map key — never the original public key. A hashed cursor can't
        // be empty, so it can't collide with the empty-`next_key`
        // "start of the identity phase" sentinel the node phase hands
        // out (an identity whose original key round-tripped as an empty
        // cursor would restart the phase forever).
        let skip: Option<[u8; 32]> = (after_kind == MEMBER_KIND_IDENTITY
            && after_key.len() == 32)
            .then(|| {
                let mut k = [0u8; 32];
                k.copy_from_slice(&after_key);
                k
            });
        let start = skip.unwrap_or([0u8; 32]);
        let mut it = self
            .identities
            .iter_from(&start)
            .filter(move |(k, _)| skip != Some(*k));
        let (page, more) = fill_page(&mut it, cap, PAGE_BYTE_BUDGET);
        let next_key = if more {
            page.last().map(|(k, _)| k.to_vec()).unwrap_or_default()
        } else {
            Vec::new()
        };
        let members = page.into_iter().map(|(_, m)| m).collect();
        if more {
            MemberPage { members, next_kind: MEMBER_KIND_IDENTITY, next_key, more: true }
        } else {
            MemberPage { members, next_kind: 0, next_key: Vec::new(), more: false }
        }
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
        self.nodes
            .get(&(prefix as u16))
            .map(|m| m.role.saturating_add(1))
            .unwrap_or(0)
    }

    // ── Auth grants (Sprint 2) ─────────────────────────────────

    /// Grant `role` to `peer_id` at `epoch`. `epoch` must be above the
    /// peer's current [`peer_epoch`](Self::peer_epoch) (the CLI reads it
    /// and signs `epoch + 1`); a grant at or below the peer's revoke
    /// high-water is recorded but stays dominated, so a replayed
    /// stale-epoch grant can never resurrect a revoked role. `peer_id`
    /// is libp2p multihash bytes. The grant is attributed to its signer
    /// (`grantor`) so [`effective_role`](Self::effective_role) can void
    /// the subtree if the delegator is later revoked.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn grant_role(&mut self, peer_id: Vec<u8>, role: u8, epoch: u64, auth: Vec<u8>) -> Status {
        if !self.authorize_op(
            &canonical_op_bytes("grant_role", &[&peer_id, &[role], &epoch.to_le_bytes()]),
            &auth,
        ) {
            return Status::Forbidden;
        }
        if peer_id.is_empty() {
            return Status::BadHash;
        }
        let Some((grantor, _)) = unpack_auth(&auth) else {
            return Status::Forbidden;
        };
        let grantor = grantor.to_vec();
        // One row per peer: keep the dominant grant under `grant_supersedes`
        // (root-signed grants are immutable to non-root displacement;
        // otherwise highest epoch wins). A fresh peer always supersedes.
        let key = peer_key(&peer_id);
        let supersedes = match self.auth_grants.get(&key) {
            Some(cur) => {
                grant_supersedes(epoch, &grantor, cur.epoch, &cur.grantor, &self.root_bytes())
            }
            None => true,
        };
        if supersedes {
            self.auth_grants.insert(
                &key,
                &AuthGrantRow {
                    peer_id,
                    role,
                    epoch,
                    grantor,
                },
            );
        }
        Status::Ok
    }

    /// Revoke `peer_id` at `epoch`. Raises the peer's grow-only revoke
    /// high-water, dominating every grant at or below `epoch` — so the
    /// revoke is replay-position independent (a forged grant ground to
    /// sort before this op is still voided once `effective_role`
    /// recomputes). Re-granting later requires a fresh, higher epoch.
    /// Always `Status::Ok`: revoking sets a floor even with no live grant
    /// (it blocks a future replayed grant).
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn revoke_role(&mut self, peer_id: Vec<u8>, epoch: u64, auth: Vec<u8>) -> Status {
        if !self.authorize_op(
            &canonical_op_bytes("revoke_role", &[&peer_id, &epoch.to_le_bytes()]),
            &auth,
        ) {
            return Status::Forbidden;
        }
        self.raise_revoke_floor(&peer_id, epoch);
        Status::Ok
    }

    /// Look up the *effective* role of `peer_id` — the value the
    /// dispatch-layer gate enforces. Resolves revoke-dominance and
    /// delegation order-independently (see
    /// [`effective_role`](Self::effective_role)); `AUTH_ROLE_NONE` means
    /// "deny".
    #[msg]
    async fn peer_role(&self, peer_id: Vec<u8>) -> u8 {
        self.effective_role(&peer_id)
    }

    /// Current freshness epoch for `peer_id`: the higher of its stored
    /// grant epoch and its revoke high-water. The CLI reads this before
    /// authoring a `grant_role`/`revoke_role` and signs `epoch + 1`, so
    /// each authority change for a peer carries a strictly higher epoch
    /// than any it could be replaying. An ungated read (membership
    /// metadata is non-secret).
    #[msg]
    async fn peer_epoch(&self, peer_id: Vec<u8>) -> u64 {
        let grant_hw = self
            .auth_grants
            .get(&peer_key(&peer_id))
            .map(|g| g.epoch)
            .unwrap_or(0);
        grant_hw.max(self.revoke_floor(&peer_id))
    }

    /// One page of grants, resolved to *effective* roles — for
    /// `vosx space role list`. A grant dominated by a revoke or a revoked
    /// delegator is omitted from `grants`, but the returned
    /// [`AuthGrantPage::next`] tracks the last *scanned* peer so the caller
    /// pages the whole table without skipping. Empty `after_peer` starts;
    /// continue until `next` is empty. `budget` caps the page.
    #[msg]
    async fn auth_grants(&self, after_peer: Vec<u8>, budget: u32) -> AuthGrantPage {
        let skip = (!after_peer.is_empty()).then(|| peer_key(&after_peer));
        let start = skip.unwrap_or([0u8; 32]);
        let mut raw = self
            .auth_grants
            .iter_from(&start)
            .filter(move |(k, _)| skip != Some(*k))
            .map(|(_, g)| g);
        let (page, more) = fill_page(&mut raw, page_rows(budget).min(ROLE_PAGE_MAX_ROWS), PAGE_BYTE_BUDGET);
        let next = if more {
            page.last().map(|g| g.peer_id.clone()).unwrap_or_default()
        } else {
            Vec::new()
        };
        let grants = page
            .into_iter()
            .filter_map(|g| {
                let role = self.effective_role(&g.peer_id);
                (role != AUTH_ROLE_NONE).then_some(AuthGrantRow {
                    peer_id: g.peer_id,
                    role,
                    epoch: g.epoch,
                    grantor: g.grantor,
                })
            })
            .collect();
        AuthGrantPage { grants, next }
    }

    // ── Invites ─────────────────────────────────────────────────

    /// Redeem an invite token: grant `role` to `peer_id`. Deliberately
    /// UNGATED — the two carried signatures ARE the auth, so a fresh
    /// joiner (no grant yet) can reach it by remote invoke. Verifies, in
    /// cheap-to-expensive order:
    ///
    ///  1. shape (`token_pub`/sig lengths, non-empty peers) and that
    ///     `role` is an offline tier (`READONLY`/`DEVELOPER`); `admin`
    ///     and voter enrollment are online-admission only,
    ///  2. `redeem_sig` over (`redeem_invite`, `[token_pub, peer_id]`)
    ///     under `token_pub` — the joiner proves it holds the token
    ///     secret, binding the redemption to this node,
    ///  3. `admin_sig` over the invite canonical (`invite`,
    ///     `[space_id, [role], expires_le, token_pub]`) under
    ///     `admin_peer_id`, which must itself be a current-epoch
    ///     effective admin — the delegated-grant chain admin→token→node,
    ///  4. the token isn't revoked (a grow-only flag on the row).
    ///
    /// The invite names its minting admin (`admin_peer_id`) so the
    /// signature is verified in O(1) against a known key rather than by
    /// scanning the grant table; a lie there fails `verify_op_sig` or
    /// `is_effective_admin`, so it can't escalate. No expiry check
    /// happens here — expiry is checked once, host-side, at admission
    /// (replay re-verifies signatures only, never the clock).
    ///
    /// On success it records the redemption (appending `peer_id` to the
    /// token's `redeemed_by` set, sorted + deduped so replicas
    /// converge) and writes the grant with the same effect as
    /// `grant_role`, attributed to the minting admin — so revoking that
    /// admin voids the redeemed grant through the normal
    /// `effective_role` walk. The grant epoch is the admin-committed
    /// `expires_at`: deterministic (it is in the signed canonical),
    /// monotonic with mint time, and above a fresh joiner's zero revoke
    /// high-water.
    #[allow(clippy::too_many_arguments)]
    #[msg]
    async fn redeem_invite(
        &mut self,
        token_pub: Vec<u8>,
        role: u8,
        expires_at: u64,
        admin_peer_id: Vec<u8>,
        admin_sig: Vec<u8>,
        peer_id: Vec<u8>,
        redeem_sig: Vec<u8>,
        node_sig: Vec<u8>,
    ) -> Status {
        let Some(token_pub_key) = bytes_to_32(&token_pub) else {
            return Status::BadHash;
        };
        if peer_id.is_empty() || admin_peer_id.is_empty() {
            return Status::BadHash;
        }
        let Some(admin_sig) = bytes_to_64(&admin_sig) else {
            return Status::BadHash;
        };
        let Some(redeem_sig) = bytes_to_64(&redeem_sig) else {
            return Status::BadHash;
        };
        let Some(node_sig) = bytes_to_64(&node_sig) else {
            return Status::BadHash;
        };
        // Offline tiers only. `admin`/voter enrollment need the serving
        // daemon to countersign online (decision 5); refuse them here.
        if role != AUTH_ROLE_READONLY && role != AUTH_ROLE_DEVELOPER {
            return Status::Forbidden;
        }
        // (2) Token possession AND peer-id control: the redeem canonical
        // is signed BOTH by the token secret (`redeem_sig`, under
        // `token_pub`) and by the joining node's own key (`node_sig`,
        // under `peer_id`). The node_sig is load-bearing: without it a
        // token holder could redeem for an arbitrary victim's `peer_id`,
        // and because the grant epoch is the large `expires_at`, that
        // grant would supersede — silently downgrade — the victim's
        // legitimately-granted role (and cascade-void its delegation
        // subtree). Requiring a signature under `peer_id` binds the grant
        // to a node the redeemer actually controls. Both checks are
        // deterministic, so they re-verify identically on CRDT replay.
        let redeem_canon = canonical_op_bytes("redeem_invite", &[&token_pub, &peer_id]);
        if !verify_raw_sig(&token_pub_key, &redeem_canon, &redeem_sig)
            || !verify_op_sig(&peer_id, &redeem_canon, &node_sig)
        {
            return Status::Forbidden;
        }
        // (3) Admin minting: admin_sig over the invite canonical under a
        // current-epoch effective admin. The canonical binds THIS space's
        // genesis root — held authoritatively by the actor
        // (`self.root_bytes()`), never a caller-supplied space id — so an
        // invite minted for another space cannot be replayed here even
        // when its minter is an effective admin of both spaces: each
        // space's distinct root makes the rebuilt canonical (and thus the
        // signature) mismatch.
        let root = self.root_bytes();
        let invite_canon = canonical_op_bytes(
            "invite",
            &[&root, &[role], &expires_at.to_le_bytes(), &token_pub],
        );
        if !verify_op_sig(&admin_peer_id, &invite_canon, &admin_sig)
            || !self.is_effective_admin(&admin_peer_id)
        {
            return Status::Forbidden;
        }
        // (4) Not revoked (grow-only flag; a replayed redeem can't clear
        // it because revoke_invite only ever sets it).
        if self.invites.get(&token_pub_key).is_some_and(|r| r.revoked) {
            return Status::Forbidden;
        }
        // Record the redemption. `redeemed_by` is a sorted, deduped set
        // so every replica reaches the same value regardless of merge
        // order; a second distinct peer appends a second entry, which
        // `space members` surfaces as a double-redemption.
        let mut row = self.invites.get(&token_pub_key).unwrap_or(InviteRow {
            token_pub: token_pub_key,
            role,
            expires_at,
            redeemed_by: Vec::new(),
            revoked: false,
        });
        if let Err(pos) = row.redeemed_by.binary_search(&peer_id) {
            row.redeemed_by.insert(pos, peer_id.clone());
        }
        self.invites.insert(&token_pub_key, &row);
        // Write the grant, attributed to the minting admin (grantor).
        let epoch = expires_at;
        let key = peer_key(&peer_id);
        let supersedes = match self.auth_grants.get(&key) {
            Some(cur) => {
                grant_supersedes(epoch, &admin_peer_id, cur.epoch, &cur.grantor, &self.root_bytes())
            }
            None => true,
        };
        if supersedes {
            self.auth_grants.insert(
                &key,
                &AuthGrantRow {
                    peer_id,
                    role,
                    epoch,
                    grantor: admin_peer_id,
                },
            );
        }
        Status::Ok
    }

    /// Revoke an invite token (admin-signed). Grow-only: sets the
    /// token's `revoked` flag — creating the row if the token was never
    /// redeemed — so a redeem that merges in later, in any order, is
    /// refused, and no replayed redeem can clear it. Idempotent; always
    /// `Status::Ok` once authorized (marking a floor even with no live
    /// row). Existing already-granted roles are NOT clawed back here —
    /// that is `revoke_role`'s job (decision 6).
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn revoke_invite(&mut self, token_pub: Vec<u8>, auth: Vec<u8>) -> Status {
        if !self.authorize_op(&canonical_op_bytes("revoke_invite", &[&token_pub]), &auth) {
            return Status::Forbidden;
        }
        let Some(token_pub_key) = bytes_to_32(&token_pub) else {
            return Status::BadHash;
        };
        let mut row = self.invites.get(&token_pub_key).unwrap_or(InviteRow {
            token_pub: token_pub_key,
            role: 0,
            expires_at: 0,
            redeemed_by: Vec::new(),
            revoked: false,
        });
        if !row.revoked {
            row.revoked = true;
            self.invites.insert(&token_pub_key, &row);
        }
        Status::Ok
    }

    /// One page of the invites table (for `space members`). Empty
    /// `after` starts; continue from the returned [`InvitePage::next`]
    /// until it comes back empty. `budget` caps the page. An ungated
    /// read (invite metadata is non-secret).
    #[msg]
    async fn invites(&self, after: Vec<u8>, budget: u32) -> InvitePage {
        let skip = bytes_to_32(&after);
        let start = skip.unwrap_or([0u8; 32]);
        let mut it = self
            .invites
            .iter_from(&start)
            .filter(move |(k, _)| skip != Some(*k))
            .map(|(_, r)| r);
        let (page, more) = fill_page(&mut it, page_rows(budget), PAGE_BYTE_BUDGET);
        let next = if more {
            page.last().map(|r| r.token_pub.to_vec()).unwrap_or_default()
        } else {
            Vec::new()
        };
        InvitePage { invites: page, next }
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
        epoch: u64,
        auth: Vec<u8>,
    ) -> Status {
        if !self.authorize_op(
            &canonical_op_bytes(
                "grant_actor_role",
                &[&peer_id, agent_name.as_bytes(), &[role], &epoch.to_le_bytes()],
            ),
            &auth,
        ) {
            return Status::Forbidden;
        }
        if peer_id.is_empty() || agent_name.is_empty() {
            return Status::BadHash;
        }
        let Some((grantor, _)) = unpack_auth(&auth) else {
            return Status::Forbidden;
        };
        let grantor = grantor.to_vec();
        // One row per (peer, agent): same root-dominates ordering as the
        // space-level grants (see `grant_supersedes`). A fresh pair always
        // supersedes.
        let key = acl_key(&peer_id, &agent_name);
        let supersedes = match self.actor_acls.get(&key) {
            Some(cur) => {
                grant_supersedes(epoch, &grantor, cur.epoch, &cur.grantor, &self.root_bytes())
            }
            None => true,
        };
        if supersedes {
            self.actor_acls.insert(
                &key,
                &ActorAclRow {
                    peer_id,
                    agent_name,
                    role,
                    epoch,
                    grantor,
                },
            );
        }
        Status::Ok
    }

    /// Revoke the actor-local grant for `(peer_id, agent_name)` at
    /// `epoch`, raising its grow-only revoke high-water (replay-position
    /// independent — see [`revoke_role`](Self::revoke_role)). Always
    /// `Status::Ok`. Does not affect the space-level grant.
    #[msg(role = SpaceRegistryRole::Admin)]
    async fn revoke_actor_role(
        &mut self,
        peer_id: Vec<u8>,
        agent_name: String,
        epoch: u64,
        auth: Vec<u8>,
    ) -> Status {
        if !self.authorize_op(
            &canonical_op_bytes(
                "revoke_actor_role",
                &[&peer_id, agent_name.as_bytes(), &epoch.to_le_bytes()],
            ),
            &auth,
        ) {
            return Status::Forbidden;
        }
        self.raise_actor_revoke_floor(&peer_id, &agent_name, epoch);
        Status::Ok
    }

    /// Current freshness epoch for an actor-local `(peer_id,
    /// agent_name)` grant — the higher of its stored grant epoch and
    /// its revoke high-water. The CLI reads this before authoring a
    /// `grant_actor_role`/`revoke_actor_role` and signs `epoch + 1`.
    #[msg]
    async fn actor_epoch(&self, peer_id: Vec<u8>, agent_name: String) -> u64 {
        let grant = self
            .actor_acls
            .get(&acl_key(&peer_id, &agent_name))
            .map(|a| a.epoch)
            .unwrap_or(0);
        grant.max(self.actor_revoke_floor(&peer_id, &agent_name))
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
        // Effective role: revoke-dominated or ineffective-grantor grants
        // resolve to AUTH_ROLE_NONE, which the host dispatch path treats
        // as "no grant" (falling through to the space-level role).
        self.effective_actor_role(&peer_id, &agent_name)
            .unwrap_or(AUTH_ROLE_NONE)
    }

    /// One page of actor-local ACLs, resolved to *effective* roles — for
    /// `vosx space role list --in <actor>` and operator audit. Rows with no
    /// effective grant (revoked or revoked-delegator) are omitted from
    /// `acls`; the returned [`ActorAclPage`] cursor tracks the last
    /// *scanned* `(peer, agent)` so the caller pages the whole table.
    /// Empty `after_peer`/`after_agent` starts; continue until both are
    /// empty. `budget` caps the page.
    #[msg]
    async fn actor_acls(
        &self,
        after_peer: Vec<u8>,
        after_agent: String,
        budget: u32,
    ) -> ActorAclPage {
        let skip = (!after_peer.is_empty() || !after_agent.is_empty())
            .then(|| acl_key(&after_peer, &after_agent));
        let start = skip.unwrap_or([0u8; 32]);
        let mut raw = self
            .actor_acls
            .iter_from(&start)
            .filter(move |(k, _)| skip != Some(*k))
            .map(|(_, a)| a);
        let (page, more) = fill_page(&mut raw, page_rows(budget).min(ROLE_PAGE_MAX_ROWS), PAGE_BYTE_BUDGET);
        let (next_peer, next_agent) = if more {
            page.last()
                .map(|a| (a.peer_id.clone(), a.agent_name.clone()))
                .unwrap_or_default()
        } else {
            (Vec::new(), String::new())
        };
        let acls = page
            .into_iter()
            .filter_map(|a| {
                self.effective_actor_role(&a.peer_id, &a.agent_name)
                    .map(|role| ActorAclRow {
                        peer_id: a.peer_id,
                        agent_name: a.agent_name,
                        role,
                        epoch: a.epoch,
                        grantor: a.grantor,
                    })
            })
            .collect();
        ActorAclPage {
            acls,
            next_peer,
            next_agent,
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
    /// signer must be an *effective* admin — the genesis root, or a
    /// peer whose grant chain bottoms out at the root and is not
    /// dominated by a revoke (see [`effective_role`](Self::effective_role)).
    ///
    /// This runs at handler time on BOTH the live dispatch and every
    /// peer's causal replay (where the op arrives as `Caller::System`
    /// and the `#[msg(role)]` gate is a no-op). So a forged op merged
    /// via CRDT — a fabricated AuthGrantRow{ADMIN} or MemberRow{VOTER}
    /// — is refused on each honest node unless it carries a signature
    /// an admin (or the root) actually produced.
    ///
    /// Because `effective_role` is computed on demand from the stored
    /// grant graph and the grow-only revoke high-waters — never from a
    /// cached "is admin" flag — authority is *replay-position
    /// independent*: a signer who was revoked anywhere in the merged
    /// DAG is not an effective admin here, even when a forged node is
    /// ground to sort causally *before* its own revoke. That closes the
    /// re-grant-revoked-admin and revoked-delegator escalation vectors.
    fn authorize_op(&self, canonical: &[u8], auth: &[u8]) -> bool {
        let Some((signer, sig)) = unpack_auth(auth) else {
            return false;
        };
        if !verify_op_sig(signer, canonical, &sig) {
            return false;
        }
        self.is_effective_admin(signer)
    }

    /// The anchored genesis root PeerId, or empty before genesis.
    /// A point read; the dispatch read-cache makes repeated calls
    /// (one per delegation-chain hop) cost a single row.
    fn root_bytes(&self) -> Vec<u8> {
        self.root.get().unwrap_or_default()
    }

    /// Grow-only revoke high-water for `peer_id`, or 0 if never revoked.
    fn revoke_floor(&self, peer_id: &[u8]) -> u64 {
        self.revoke_epochs.get(&peer_key(peer_id)).unwrap_or(0)
    }

    /// Raise (never lower) the revoke high-water for `peer_id`.
    fn raise_revoke_floor(&mut self, peer_id: &[u8], epoch: u64) {
        if epoch > self.revoke_floor(peer_id) {
            self.revoke_epochs.insert(&peer_key(peer_id), &epoch);
        }
    }

    /// Grow-only revoke high-water for an actor-local `(peer_id,
    /// agent_name)` grant, or 0 if never revoked.
    fn actor_revoke_floor(&self, peer_id: &[u8], agent_name: &str) -> u64 {
        self.actor_revoke_epochs
            .get(&acl_key(peer_id, agent_name))
            .unwrap_or(0)
    }

    /// Raise (never lower) the actor revoke high-water for `(peer_id,
    /// agent_name)`.
    fn raise_actor_revoke_floor(&mut self, peer_id: &[u8], agent_name: &str, epoch: u64) {
        if epoch > self.actor_revoke_floor(peer_id, agent_name) {
            self.actor_revoke_epochs
                .insert(&acl_key(peer_id, agent_name), &epoch);
        }
    }

    /// True when `signer` is the genesis root or a transitively
    /// effective ADMIN. The root is the supreme signer — before genesis
    /// sets one, `self.root` is empty and every signed mutator fails
    /// closed (only the unsigned `set_root` anchor is accepted).
    fn is_effective_admin(&self, signer: &[u8]) -> bool {
        let root = self.root_bytes();
        if !root.is_empty() && root.as_slice() == signer {
            return true;
        }
        self.effective_role(signer) == AUTH_ROLE_ADMIN
    }

    /// Effective space-level role of `peer_id`, resolving revoke-
    /// dominance and delegation *order-independently*. A stored grant
    /// counts only if its epoch is strictly above the peer's grow-only
    /// revoke high-water AND its `grantor` is itself effective (the
    /// genesis root, or a transitively-effective admin). Computed on
    /// demand — never cached — so a revoke that merges in after the
    /// grants it dominates (including a forged node ground to sort
    /// before its own revoke during replay) retroactively voids the
    /// whole delegation subtree.
    fn effective_role(&self, peer_id: &[u8]) -> u8 {
        // The peer's own grant carries the candidate result; the walk
        // below decides whether it counts.
        let Some(first) = self.auth_grants.get(&peer_key(peer_id)) else {
            return AUTH_ROLE_NONE;
        };
        if first.epoch <= self.revoke_floor(peer_id) {
            return AUTH_ROLE_NONE;
        }
        let role = first.role;
        let root = self.root_bytes();
        // Walk the grantor chain iteratively, holding ONE decoded row
        // at a time — a recursive walk pins every row on the guest
        // arena simultaneously, so a crafted grantor cycle (e.g. an
        // admin re-granting themselves) OOMs the dispatch once the
        // table is large. Each intermediate grantor must itself be an
        // undominated ADMIN, and the chain must bottom out at the
        // genesis root (always admin, never revocable, needs no row).
        // A chain with more hops than the table has rows must contain
        // a cycle, which can never bottom out — refuse it. The map's
        // count comes from its meta row (cached for the dispatch).
        let mut grantor = first.grantor;
        let mut hops = 0u64;
        let limit = self.auth_grants.len();
        loop {
            if !root.is_empty() && root.as_slice() == grantor.as_slice() {
                return role;
            }
            if hops >= limit {
                return AUTH_ROLE_NONE;
            }
            let Some(row) = self.auth_grants.get(&peer_key(&grantor)) else {
                return AUTH_ROLE_NONE;
            };
            if row.epoch <= self.revoke_floor(&grantor) || row.role != AUTH_ROLE_ADMIN {
                return AUTH_ROLE_NONE;
            }
            grantor = row.grantor;
            hops += 1;
        }
    }

    /// Effective actor-local role of `(peer_id, agent_name)`. Like
    /// [`effective_role`](Self::effective_role): the grant counts only
    /// while its epoch is above the matching actor revoke high-water
    /// AND its `grantor` is an effective *space* admin. Returns `None`
    /// when there is no row at all so the dispatch path can tell "no
    /// grant" from "role 0".
    fn effective_actor_role(&self, peer_id: &[u8], agent_name: &str) -> Option<u8> {
        let row = self.actor_acls.get(&acl_key(peer_id, agent_name))?;
        if row.epoch <= self.actor_revoke_floor(peer_id, agent_name) {
            return None;
        }
        if self.is_effective_admin(&row.grantor) {
            Some(row.role)
        } else {
            None
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────

/// Decide whether an incoming grant should replace the stored grant for
/// the same target (one row per target). The ordering is a max over a
/// total, content-derived order — independent of replay/merge order:
///
///   1. A **root-signed** grant dominates any non-root grant *regardless
///      of epoch*. Root authority is immutable, so a delegated admin can
///      never capture a root-granted target's trust path by re-granting
///      it (which would let revoking that admin void a root delegation).
///   2. Otherwise the higher epoch wins (a stale grant is dominated).
///   3. At equal epoch and equal root-ness, the lexicographically smaller
///      grantor wins — a deterministic tiebreak so two concurrent grants
///      at the same epoch resolve identically on every replica.
fn grant_supersedes(
    new_epoch: u64,
    new_grantor: &[u8],
    cur_epoch: u64,
    cur_grantor: &[u8],
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
    compare_bytes(new_grantor, cur_grantor) < 0
}

fn bytes_to_32(b: &[u8]) -> Option<[u8; 32]> {
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Some(out)
}

fn bytes_to_64(b: &[u8]) -> Option<[u8; OP_SIG_LEN]> {
    if b.len() != OP_SIG_LEN {
        return None;
    }
    let mut out = [0u8; OP_SIG_LEN];
    out.copy_from_slice(b);
    Some(out)
}

/// Row cap for one page of a list handler. Kept well under the
/// per-dispatch touched-row ceiling: a page reads one value row per
/// entry plus a couple of index pages, so the dispatch stays O(page).
const PAGE_MAX_ROWS: usize = 128;

/// Encoded-byte budget for one page. The binding constraint is the
/// 256 KiB guest heap, not the 1 MiB halt-output cap: while a page is
/// being built, each row is resident ~3× (the dispatch read-cache's
/// raw bytes, the decoded row, and `fill_page`'s transient encode), so
/// the budget must leave the arena headroom for all three plus the
/// final reply encode. 48 KiB bounds the page's peak footprint around
/// ~150 KiB worst-case — large rows page earlier, they don't trap the
/// guest allocator.
const PAGE_BYTE_BUDGET: usize = 48 * 1024;

/// Tighter page cap for the two role-list handlers: each row resolves an
/// `effective_role`, an O(chain-depth) point-read walk, so the touched-row
/// count is `page × depth` rather than `page`. Kept low enough that even a
/// worst-case delegation chain stays under the per-dispatch row ceiling.
const ROLE_PAGE_MAX_ROWS: usize = 48;

/// Clamp a caller-supplied page budget to `[1, PAGE_MAX_ROWS]`. A `0`
/// budget (caller didn't care) takes the max.
fn page_rows(budget: u32) -> usize {
    if budget == 0 {
        PAGE_MAX_ROWS
    } else {
        (budget as usize).min(PAGE_MAX_ROWS)
    }
}

/// Fixed-width `StorageMap` key for a variable-length instance name.
/// The storage handles need `[u8; 32]` keys, and instance names are
/// operator-chosen `String`s; fold them with a domain-separated blake2b.
/// The stored row still carries the plain name, so a listing recovers it —
/// only the ordered-by-name iteration is forfeit, and no consumer depends
/// on it (`resolve`/`meta_for_instance` are exact-name point lookups).
fn name_key(name: &str) -> [u8; 32] {
    vos::crypto::blake2b_hash::<32>(b"space-registry/name-key/v1", &[name.as_bytes()])
}

/// Fixed-width `StorageMap` key for a variable-length peer id. One grant
/// row per peer, so this is the whole key. Ordered iteration is by hashed
/// key, not peer id — no consumer depends on peer order (grants are point
/// looked-up in `effective_role`; the list handler pages).
fn peer_key(peer_id: &[u8]) -> [u8; 32] {
    vos::crypto::blake2b_hash::<32>(b"space-registry/peer-key/v1", &[peer_id])
}

/// Fixed-width `StorageMap` key for an actor-local `(peer_id, agent_name)`
/// grant. Length-prefix the peer id so `(p‖q, name)` and `(p, q‖name)`
/// can't collide into the same key.
fn acl_key(peer_id: &[u8], agent_name: &str) -> [u8; 32] {
    vos::crypto::blake2b_hash::<32>(
        b"space-registry/acl-key/v1",
        &[&(peer_id.len() as u32).to_be_bytes(), peer_id, agent_name.as_bytes()],
    )
}

/// Fixed-width `StorageMap` key for an Identity member's variable-length
/// public key. Nodes key directly by their `u16` prefix (order-preserving);
/// only identities need folding.
fn identity_key(public_key: &[u8]) -> [u8; 32] {
    vos::crypto::blake2b_hash::<32>(b"space-registry/identity-key/v1", &[public_key])
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
// resulting Status::Forbidden. `register_remote` stays unsigned: it is
// the hyperspace/federation surface and has a separate trust model.

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

/// Verify ed25519 `sig` over `msg` under the key embedded in
/// `signer_peer_id`. Pure (no RNG) and deterministic across host and
/// PVM. `false` on any malformed input or bad signature.
pub fn verify_op_sig(signer_peer_id: &[u8], msg: &[u8], sig: &[u8; OP_SIG_LEN]) -> bool {
    let Some(pk) = ed25519_pubkey_from_peer_id(signer_peer_id) else {
        return false;
    };
    verify_raw_sig(&pk, msg, sig)
}

/// Verify ed25519 `sig` over `msg` under a RAW 32-byte public key — an
/// invite token key (`token_pub`), which is not a libp2p PeerId so
/// [`verify_op_sig`]'s multihash extraction doesn't apply. Pure and
/// deterministic across host and PVM; `false` on any malformed input or
/// bad signature.
pub fn verify_raw_sig(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; OP_SIG_LEN]) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify_strict(msg, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos::Message;
    use vos::actors::context::ServiceId;

    fn registry() -> SpaceRegistry {
        // The mock keyspace and the dispatch overlay are thread-local,
        // and the test pool reuses threads — every registry starts from
        // the clean slate a fresh agent keyspace presents.
        vos::storage::mock::reset();
        let mut r = SpaceRegistry::new();
        // What the framework's load_or_create does after create():
        // point each #[storage] handle at its key prefix.
        vos::actors::Actor::__init_storage(&mut r);
        // Establish the genesis root so signed mutators authorize
        // against it (tests sign every op as the root via `root_auth`).
        let status = dispatch(
            &mut r,
            SetRoot {
                root: root_peer_id(),
            },
        );
        assert_eq!(status, Status::Ok, "set_root on a fresh registry");
        r
    }

    /// Drain the paginated `actor_acls` handler — tests assert over the
    /// whole table.
    fn actor_acls_all(r: &mut SpaceRegistry) -> Vec<ActorAclRow> {
        let mut out = Vec::new();
        let mut after_peer = Vec::new();
        let mut after_agent = String::new();
        loop {
            let page = dispatch(
                r,
                ActorAcls {
                    after_peer,
                    after_agent,
                    budget: 0,
                },
            );
            out.extend(page.acls);
            if page.next_peer.is_empty() && page.next_agent.is_empty() {
                return out;
            }
            after_peer = page.next_peer;
            after_agent = page.next_agent;
        }
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

    // ── grant_actor_role / actor_role round-trip ────────────────

    #[test]
    fn grant_actor_role_then_lookup_returns_role() {
        let mut r = registry();
        let peer = alloc::vec![1, 2, 3];
        let agent = String::from("dev-project");
        let status = grant_actor(&mut r, &peer, &agent, 2);
        assert_eq!(status, Status::Ok);

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
        assert_eq!(grant_actor(&mut r, &peer, &agent, 2), Status::Ok);
        assert_eq!(grant_actor(&mut r, &peer, &agent, 2), Status::Ok);
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
        let all = actor_acls_all(&mut r);
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
        assert_eq!(actor_acls_all(&mut r).len(), 1);
    }

    #[test]
    fn grant_actor_role_rejects_empty_peer_or_name() {
        // Empty peer/name would alias to an unintended row and
        // collide with future identity bytes. Status::BadHash
        // matches the existing convention from grant_role.
        let mut r = registry();
        // The op is root-signed (authorize_op passes); the empty-arg
        // guard inside the handler is what rejects.
        assert_eq!(grant_actor(&mut r, &[], "x", 1), Status::BadHash);
        assert_eq!(grant_actor(&mut r, &[1], "", 1), Status::BadHash);
    }

    // ── revoke_actor_role ───────────────────────────────────────

    #[test]
    fn revoke_actor_role_removes_grant() {
        let mut r = registry();
        let peer = alloc::vec![1, 2, 3];
        let agent = String::from("dev-project");
        grant_actor(&mut r, &peer, &agent, 2);
        let status = revoke_actor(&mut r, &peer, &agent);
        assert_eq!(status, Status::Ok);
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
        assert!(actor_acls_all(&mut r).is_empty());
    }

    #[test]
    fn revoke_actor_role_missing_sets_floor_ok() {
        // Revoke is grow-only and replay-position independent: revoking
        // a peer with no live grant still raises the revoke high-water,
        // so a later replayed grant at or below this epoch can't take
        // effect. It returns OK rather than NOT_FOUND for that reason.
        let mut r = registry();
        let status = revoke_actor(&mut r, &[1], "x");
        assert_eq!(status, Status::Ok);
        assert_eq!(dispatch(&mut r, ActorEpoch { peer_id: alloc::vec![1], agent_name: String::from("x") }), 1);
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
        assert_eq!(actor_acls_all(&mut r).len(), 2);
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

    /// Monotonically-unique 32-byte `replication_id` for tests — each
    /// install mints a fresh one, as the real CLI / messenger do (the
    /// id is a grow-only anti-replay tombstone, so a reinstall must not
    /// reuse a prior id).
    fn fresh_rep_id() -> Vec<u8> {
        use core::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let mut rep = alloc::vec![0u8; 32];
        rep[..8].copy_from_slice(&n.to_le_bytes());
        rep
    }

    /// Publish a throwaway program (idempotent for the same hash)
    /// and install `name` at `consistency` with a fresh
    /// `replication_id`, returning the status.
    fn install_at(r: &mut SpaceRegistry, name: &str, consistency: u8) -> Status {
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
        assert!(pub_status == Status::Ok, "program publish must succeed");
        let rep = fresh_rep_id();
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
                network_reachable: false,
                sync_role: SyncFloor::Member as u8,
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
                        &[0u8],
                        &[SyncFloor::Member as u8],
                    ],
                ),
            },
        )
    }

    fn uninstall(r: &mut SpaceRegistry, name: &str) -> Status {
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
    fn install_persists_network_reachable() {
        let mut r = registry();
        let hash = alloc::vec![7u8; 32];
        assert_eq!(
            dispatch(
                &mut r,
                Publish {
                    name: String::from("p"),
                    version: String::from("1"),
                    hash: hash.clone(),
                    auth: root_auth("publish", &[b"p", b"1", &hash]),
                },
            ),
            Status::Ok
        );
        // A confined (Ephemeral) bridge that opts into network reachability.
        let rep = fresh_rep_id();
        let st = dispatch(
            &mut r,
            Install {
                instance_name: String::from("bridge"),
                program_name: String::from("p"),
                program_version: String::from("1"),
                program_hash: hash.clone(),
                replication_id: rep.clone(),
                consistency: 0, // Ephemeral
                install_args: Vec::new(),
                install_payloads: Vec::new(),
                network_reachable: true,
                sync_role: SyncFloor::Member as u8,
                auth: root_auth(
                    "install",
                    &[
                        b"bridge", b"p", b"1", &hash, &rep, &[0u8], &[], &[], &[1u8],
                        &[SyncFloor::Member as u8],
                    ],
                ),
            },
        );
        assert_eq!(st, Status::Ok);
        let row = r.agents.iter().find(|a| a.instance_name == "bridge").unwrap();
        assert!(
            row.network_reachable,
            "install must persist network_reachable=true onto the AgentRow"
        );
        // The default install path stays confined.
        assert_eq!(install_at(&mut r, "counter", 2 /* Crdt */), Status::Ok);
        let c = r.agents.iter().find(|a| a.instance_name == "counter").unwrap();
        assert!(!c.network_reachable, "default install is confined");
    }

    #[test]
    fn install_persists_sync_floor() {
        // The `sync_role` floor rides the AgentRow: a `private` install
        // round-trips as `SyncFloor::Private`, and the default install
        // path (via `install_at`) records `Member`.
        let mut r = registry();
        let hash = alloc::vec![7u8; 32];
        assert_eq!(
            dispatch(
                &mut r,
                Publish {
                    name: String::from("p"),
                    version: String::from("1"),
                    hash: hash.clone(),
                    auth: root_auth("publish", &[b"p", b"1", &hash]),
                },
            ),
            Status::Ok
        );
        let rep = fresh_rep_id();
        let st = dispatch(
            &mut r,
            Install {
                instance_name: String::from("secret"),
                program_name: String::from("p"),
                program_version: String::from("1"),
                program_hash: hash.clone(),
                replication_id: rep.clone(),
                consistency: 2, // Crdt
                install_args: Vec::new(),
                install_payloads: Vec::new(),
                network_reachable: false,
                sync_role: SyncFloor::Private as u8,
                auth: root_auth(
                    "install",
                    &[
                        b"secret", b"p", b"1", &hash, &rep, &[2u8], &[], &[], &[0u8],
                        &[SyncFloor::Private as u8],
                    ],
                ),
            },
        );
        assert_eq!(st, Status::Ok);
        let row = r.agents.iter().find(|a| a.instance_name == "secret").unwrap();
        assert_eq!(
            row.sync_role,
            SyncFloor::Private,
            "install must persist the sync floor onto the AgentRow"
        );
        // The default install path (install_at) records Member.
        assert_eq!(install_at(&mut r, "open", 2 /* Crdt */), Status::Ok);
        let o = r.agents.iter().find(|a| a.instance_name == "open").unwrap();
        assert_eq!(o.sync_role, SyncFloor::Member, "default install floor is Member");
    }

    #[test]
    fn reinstall_widening_after_uninstall_is_denied() {
        let mut r = registry();
        assert_eq!(install_at(&mut r, "msg-foo", 1 /* Local */), Status::Ok);
        assert_eq!(uninstall(&mut r, "msg-foo"), Status::Ok);
        // The floor survives uninstall: reusing the name at a wider tier
        // is refused — widening needs a fresh name.
        assert_eq!(
            install_at(&mut r, "msg-foo", 2 /* Crdt */),
            Status::ConsistencyWidenDenied
        );
        assert_eq!(
            install_at(&mut r, "msg-foo", 3 /* Raft */),
            Status::ConsistencyWidenDenied
        );
        // Re-installing at the same or a narrower tier is fine.
        assert_eq!(install_at(&mut r, "msg-foo", 1 /* Local */), Status::Ok);
        assert_eq!(uninstall(&mut r, "msg-foo"), Status::Ok);
        assert_eq!(install_at(&mut r, "msg-foo", 0 /* Ephemeral */), Status::Ok);
    }

    #[test]
    fn lateral_crdt_raft_reinstall_is_allowed() {
        let mut r = registry();
        assert_eq!(install_at(&mut r, "shared", 2 /* Crdt */), Status::Ok);
        assert_eq!(uninstall(&mut r, "shared"), Status::Ok);
        // Crdt <-> Raft is a rank-equal lateral move, allowed in v0.
        assert_eq!(install_at(&mut r, "shared", 3 /* Raft */), Status::Ok);
    }

    #[test]
    fn fresh_instance_name_installs_at_any_tier() {
        let mut r = registry();
        assert_eq!(install_at(&mut r, "a", 0 /* Ephemeral */), Status::Ok);
        assert_eq!(install_at(&mut r, "b", 3 /* Raft */), Status::Ok);
        assert_eq!(install_at(&mut r, "c", 2 /* Crdt */), Status::Ok);
    }

    #[test]
    fn floor_tracks_narrowest_ever_so_widening_back_is_denied() {
        // Crdt, then narrow to Local on reinstall — the floor pins at
        // Local, so a later attempt to widen back to Crdt is refused.
        let mut r = registry();
        assert_eq!(install_at(&mut r, "drift", 2 /* Crdt */), Status::Ok);
        assert_eq!(uninstall(&mut r, "drift"), Status::Ok);
        assert_eq!(install_at(&mut r, "drift", 1 /* Local */), Status::Ok);
        assert_eq!(uninstall(&mut r, "drift"), Status::Ok);
        assert_eq!(
            install_at(&mut r, "drift", 2 /* Crdt */),
            Status::ConsistencyWidenDenied
        );
    }

    #[test]
    fn live_instance_reinstall_reports_exists_not_widen() {
        let mut r = registry();
        assert_eq!(install_at(&mut r, "live", 1 /* Local */), Status::Ok);
        // A live row takes precedence: even a widen attempt is the
        // pre-existing "already installed" error, not the widen guard.
        assert_eq!(
            install_at(&mut r, "live", 2 /* Crdt */),
            Status::InstanceExists
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
    /// Reads the peer's current epoch and signs `epoch + 1`, exactly as
    /// the CLI does, so each grant/revoke for a peer is monotonically
    /// fresh.
    fn grant_space(r: &mut SpaceRegistry, peer: &[u8], role: u8) -> Status {
        let epoch = dispatch(r, PeerEpoch { peer_id: peer.to_vec() }) + 1;
        dispatch(
            r,
            GrantRole {
                peer_id: peer.to_vec(),
                role,
                epoch,
                auth: root_auth("grant_role", &[peer, &[role], &epoch.to_le_bytes()]),
            },
        )
    }

    /// Root-signed `revoke_role` dispatch — reads + bumps the epoch.
    fn revoke_space(r: &mut SpaceRegistry, peer: &[u8]) -> Status {
        let epoch = dispatch(r, PeerEpoch { peer_id: peer.to_vec() }) + 1;
        dispatch(
            r,
            RevokeRole {
                peer_id: peer.to_vec(),
                epoch,
                auth: root_auth("revoke_role", &[peer, &epoch.to_le_bytes()]),
            },
        )
    }

    /// Root-signed `grant_actor_role` dispatch.
    fn grant_actor(r: &mut SpaceRegistry, peer: &[u8], agent: &str, role: u8) -> Status {
        let epoch = dispatch(
            r,
            ActorEpoch {
                peer_id: peer.to_vec(),
                agent_name: String::from(agent),
            },
        ) + 1;
        dispatch(
            r,
            GrantActorRole {
                peer_id: peer.to_vec(),
                agent_name: String::from(agent),
                role,
                epoch,
                auth: root_auth(
                    "grant_actor_role",
                    &[peer, agent.as_bytes(), &[role], &epoch.to_le_bytes()],
                ),
            },
        )
    }

    /// Root-signed `revoke_actor_role` dispatch.
    fn revoke_actor(r: &mut SpaceRegistry, peer: &[u8], agent: &str) -> Status {
        let epoch = dispatch(
            r,
            ActorEpoch {
                peer_id: peer.to_vec(),
                agent_name: String::from(agent),
            },
        ) + 1;
        dispatch(
            r,
            RevokeActorRole {
                peer_id: peer.to_vec(),
                agent_name: String::from(agent),
                epoch,
                auth: root_auth(
                    "revoke_actor_role",
                    &[peer, agent.as_bytes(), &epoch.to_le_bytes()],
                ),
            },
        )
    }

    /// `grant_role` signed by an arbitrary key — delegation tests,
    /// where an admin (not the root) authors the grant.
    fn grant_space_signed(
        r: &mut SpaceRegistry,
        signer: &SigningKey,
        peer: &[u8],
        role: u8,
    ) -> Status {
        let epoch = dispatch(r, PeerEpoch { peer_id: peer.to_vec() }) + 1;
        let canonical = canonical_op_bytes("grant_role", &[peer, &[role], &epoch.to_le_bytes()]);
        let auth = pack_auth(
            &peer_id_for(&signer.verifying_key().to_bytes()),
            &signer.sign(&canonical).to_bytes(),
        );
        dispatch(
            r,
            GrantRole {
                peer_id: peer.to_vec(),
                role,
                epoch,
                auth,
            },
        )
    }

    // ── delegation chains (the iterative effective_role walk) ────

    #[test]
    fn delegated_grant_resolves_through_admin_chain() {
        // root → A (ADMIN) → B (DEVELOPER): B's role holds only while
        // every hop up the chain is an undominated ADMIN, and revoking
        // the delegator voids the whole subtree.
        let mut r = registry();
        let a_key = SigningKey::from_bytes(&[21u8; 32]);
        let a_peer = peer_id_for(&a_key.verifying_key().to_bytes());
        let b_peer = alloc::vec![0xbb; 4];
        assert_eq!(grant_space(&mut r, &a_peer, AUTH_ROLE_ADMIN), Status::Ok);
        assert_eq!(
            grant_space_signed(&mut r, &a_key, &b_peer, AUTH_ROLE_DEVELOPER),
            Status::Ok,
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: b_peer.clone() }),
            AUTH_ROLE_DEVELOPER,
        );
        assert_eq!(revoke_space(&mut r, &a_peer), Status::Ok);
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: b_peer.clone() }),
            AUTH_ROLE_NONE,
            "revoking the delegator voids the delegated grant",
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: a_peer }),
            AUTH_ROLE_NONE,
        );
    }

    #[test]
    fn grantor_cycle_terminates_as_none() {
        // An effective admin can re-grant themselves at a higher epoch
        // (grant_supersedes has no self guard; an admin-signed row is
        // not root-signed, so the higher epoch displaces it). The result
        // is grantor == subject — a chain that never bottoms out at the
        // root. This pins the semantics (a cycle resolves to NONE) and
        // termination. The bounded-MEMORY property is the walk's
        // iterative shape itself — one decoded row live at a time —
        // which a host-side test can't observe; don't take this suite
        // as license to revert the walk to recursion.
        let mut r = registry();
        let a_key = SigningKey::from_bytes(&[22u8; 32]);
        let a_peer = peer_id_for(&a_key.verifying_key().to_bytes());
        let b_key = SigningKey::from_bytes(&[23u8; 32]);
        let b_peer = peer_id_for(&b_key.verifying_key().to_bytes());
        assert_eq!(grant_space(&mut r, &a_peer, AUTH_ROLE_ADMIN), Status::Ok);
        assert_eq!(
            grant_space_signed(&mut r, &a_key, &b_peer, AUTH_ROLE_ADMIN),
            Status::Ok,
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: b_peer.clone() }),
            AUTH_ROLE_ADMIN,
        );
        assert_eq!(
            grant_space_signed(&mut r, &b_key, &b_peer, AUTH_ROLE_ADMIN),
            Status::Ok,
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: b_peer.clone() }),
            AUTH_ROLE_NONE,
            "a grantor cycle resolves to NONE instead of looping",
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: a_peer }),
            AUTH_ROLE_ADMIN,
            "the cycle is self-inflicted; the delegator is untouched",
        );
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
        let auth = auth_as(
            &attacker_key,
            "grant_role",
            &[&attacker, &[AUTH_ROLE_ADMIN], &1u64.to_le_bytes()],
        );
        let status = dispatch_as_system(
            &mut r,
            GrantRole {
                peer_id: attacker.clone(),
                role: AUTH_ROLE_ADMIN,
                epoch: 1,
                auth,
            },
        );
        assert_eq!(status, Status::Forbidden, "System caller can't bypass authorize_op");
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: attacker }),
            AUTH_ROLE_NONE,
        );
    }

    #[test]
    fn register_remote_rejects_the_empty_name() {
        // The empty name is host_mappings()'s start-of-table sentinel;
        // a stored row carrying it would wedge every cursor drain —
        // and register_remote is unauthenticated, so the row would be
        // remotely plantable.
        let mut r = registry();
        assert_eq!(
            dispatch(
                &mut r,
                RegisterRemote {
                    instance_name: String::new(),
                    host_prefix: 7,
                },
            ),
            Status::BadHash,
        );
        assert_eq!(
            dispatch(
                &mut r,
                RegisterRemote {
                    instance_name: String::from("alice"),
                    host_prefix: 7,
                },
            ),
            Status::Ok,
        );
    }

    #[test]
    fn set_root_is_first_write_wins() {
        // Pre-genesis registry: built by hand (the `registry()` helper
        // anchors a root, which is what this test observes happening).
        vos::storage::mock::reset();
        let mut r = SpaceRegistry::new();
        vos::actors::Actor::__init_storage(&mut r);
        assert!(dispatch(&mut r, Root).is_empty(), "no root before genesis");
        assert_eq!(
            dispatch(&mut r, SetRoot { root: root_peer_id() }),
            Status::Ok,
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
            Status::Forbidden,
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
                    epoch: 1,
                    auth: Vec::new(),
                },
            ),
            Status::Forbidden,
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
        let auth = auth_as(
            &attacker_key,
            "grant_role",
            &[&attacker, &[AUTH_ROLE_ADMIN], &1u64.to_le_bytes()],
        );
        assert_eq!(
            dispatch(
                &mut r,
                GrantRole {
                    peer_id: attacker.clone(),
                    role: AUTH_ROLE_ADMIN,
                    epoch: 1,
                    auth,
                },
            ),
            Status::Forbidden,
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
            Status::Forbidden,
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
            Status::Ok,
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
            &[
                b"evil", b"p", b"1", &hash, &rep, &[2u8], &[], &[], &[0u8],
                &[SyncFloor::Member as u8],
            ],
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
                network_reachable: false,
                sync_role: SyncFloor::Member as u8,
                auth: forged,
            },
        );
        assert_eq!(
            status, Status::Forbidden,
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
        assert_eq!(status, Status::Forbidden);
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
                network_reachable: false,
                sync_role: SyncFloor::Member as u8,
                auth: Vec::new(),
            },
        );
        assert_eq!(status, Status::Forbidden);
    }

    #[test]
    fn root_signed_install_lands_the_agent_row() {
        // Positive control: the operator (root) signs publish+install
        // (as the host sign-on-relay seam does on the admin node), so
        // authorize_op passes and the AgentRow materializes — proving
        // the signed path doesn't reject legitimate catalog ops.
        let mut r = registry();
        assert_eq!(install_at(&mut r, "good", 2), Status::Ok);
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
        assert_eq!(grant_space(&mut r, &bob, AUTH_ROLE_ADMIN), Status::Ok);

        // Bob (now admin) grants Carol READONLY, signing with his key.
        let carol = alloc::vec![3, 3, 3];
        let auth = auth_as(
            &bob_key,
            "grant_role",
            &[&carol, &[AUTH_ROLE_READONLY], &1u64.to_le_bytes()],
        );
        assert_eq!(
            dispatch(
                &mut r,
                GrantRole {
                    peer_id: carol.clone(),
                    role: AUTH_ROLE_READONLY,
                    epoch: 1,
                    auth,
                },
            ),
            Status::Ok,
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: carol }),
            AUTH_ROLE_READONLY,
        );

        // But a peer Bob granted only READONLY can't sign mutations.
        let dave_key = SigningKey::from_bytes(&[12u8; 32]);
        let dave = peer_id_for(&dave_key.verifying_key().to_bytes());
        assert_eq!(grant_space(&mut r, &dave, AUTH_ROLE_READONLY), Status::Ok);
        let evil = auth_as(
            &dave_key,
            "grant_role",
            &[&dave, &[AUTH_ROLE_ADMIN], &2u64.to_le_bytes()],
        );
        assert_eq!(
            dispatch(
                &mut r,
                GrantRole {
                    peer_id: dave.clone(),
                    role: AUTH_ROLE_ADMIN,
                    epoch: 2,
                    auth: evil,
                },
            ),
            Status::Forbidden,
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
        let wrong_op_auth = root_auth("revoke_role", &[&victim, &1u64.to_le_bytes()]);
        assert_eq!(
            dispatch(
                &mut r,
                GrantRole {
                    peer_id: victim.clone(),
                    role: AUTH_ROLE_ADMIN,
                    epoch: 1,
                    auth: wrong_op_auth,
                },
            ),
            Status::Forbidden,
        );
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: victim }), AUTH_ROLE_NONE);
    }

    // ── Replay-position-independent authority ──────────────────────

    #[test]
    fn revoking_a_delegator_voids_the_subtree_regardless_of_order() {
        // Scenario: root grants Bob ADMIN; Bob (while admin) grants Carol
        // ADMIN; only AFTER that does root revoke Bob — the exact
        // "author before the revoke" order an attacker would grind.
        // Because authority is resolved on demand from the grant graph
        // plus the grow-only revoke high-water, revoking Bob
        // retroactively voids Carol's delegated grant.
        let mut r = registry();
        let bob_key = SigningKey::from_bytes(&[11u8; 32]);
        let bob = peer_id_for(&bob_key.verifying_key().to_bytes());
        assert_eq!(grant_space(&mut r, &bob, AUTH_ROLE_ADMIN), Status::Ok);

        let carol = alloc::vec![3, 3, 3];
        let e = dispatch(&mut r, PeerEpoch { peer_id: carol.clone() }) + 1;
        let bob_grants_carol = auth_as(
            &bob_key,
            "grant_role",
            &[&carol, &[AUTH_ROLE_ADMIN], &e.to_le_bytes()],
        );
        assert_eq!(
            dispatch(
                &mut r,
                GrantRole {
                    peer_id: carol.clone(),
                    role: AUTH_ROLE_ADMIN,
                    epoch: e,
                    auth: bob_grants_carol,
                },
            ),
            Status::Ok,
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: carol.clone() }),
            AUTH_ROLE_ADMIN,
            "Carol is admin while her delegator Bob is",
        );

        // root revokes Bob — applied AFTER Carol's grant.
        assert_eq!(revoke_space(&mut r, &bob), Status::Ok);
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: bob }),
            AUTH_ROLE_NONE,
            "Bob is revoked",
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: carol }),
            AUTH_ROLE_NONE,
            "revoking the delegator retroactively voids the subtree",
        );
    }

    #[test]
    fn root_granted_peer_survives_a_capturing_admins_revocation() {
        // Grantor-swap vector: root grants Carol ADMIN; a delegated admin
        // (Mallory) re-grants Carol at a HIGHER epoch to capture her trust
        // path, then Mallory is revoked. A root-signed grant is immutable
        // to non-root displacement (grant_supersedes), so Carol's grantor
        // stays root and she keeps ADMIN — revoking Mallory can't void a
        // root delegation.
        let mut r = registry();
        let mallory_key = SigningKey::from_bytes(&[21u8; 32]);
        let mallory = peer_id_for(&mallory_key.verifying_key().to_bytes());
        assert_eq!(grant_space(&mut r, &mallory, AUTH_ROLE_ADMIN), Status::Ok);

        let carol = alloc::vec![3, 3, 3];
        assert_eq!(grant_space(&mut r, &carol, AUTH_ROLE_ADMIN), Status::Ok);
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: carol.clone() }),
            AUTH_ROLE_ADMIN,
        );

        // Mallory re-grants Carol at a higher epoch (read + 1).
        let e = dispatch(&mut r, PeerEpoch { peer_id: carol.clone() }) + 1;
        let capture = auth_as(
            &mallory_key,
            "grant_role",
            &[&carol, &[AUTH_ROLE_ADMIN], &e.to_le_bytes()],
        );
        assert_eq!(
            dispatch(
                &mut r,
                GrantRole {
                    peer_id: carol.clone(),
                    role: AUTH_ROLE_ADMIN,
                    epoch: e,
                    auth: capture,
                },
            ),
            Status::Ok,
        );

        assert_eq!(revoke_space(&mut r, &mallory), Status::Ok);
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: mallory }),
            AUTH_ROLE_NONE,
            "Mallory is revoked",
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: carol }),
            AUTH_ROLE_ADMIN,
            "a root-granted peer can't be captured and voided by a delegated admin",
        );
    }

    #[test]
    fn replayed_stale_grant_cannot_resurrect_a_revoked_role() {
        // Scenario: capture the root-signed grant that first made Bob admin,
        // revoke Bob, then replay the captured grant. Its stale epoch is
        // dominated by the revoke high-water, so Bob stays revoked — but
        // a fresh, higher-epoch re-grant still works (revocation is not
        // a permanent footgun).
        let mut r = registry();
        let bob = alloc::vec![1, 2, 3];
        let captured = root_auth(
            "grant_role",
            &[&bob, &[AUTH_ROLE_ADMIN], &1u64.to_le_bytes()],
        );
        assert_eq!(
            dispatch(
                &mut r,
                GrantRole {
                    peer_id: bob.clone(),
                    role: AUTH_ROLE_ADMIN,
                    epoch: 1,
                    auth: captured.clone(),
                },
            ),
            Status::Ok,
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: bob.clone() }),
            AUTH_ROLE_ADMIN,
        );

        // root revokes Bob (reads epoch 1, bumps the high-water to 2).
        assert_eq!(revoke_space(&mut r, &bob), Status::Ok);
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: bob.clone() }),
            AUTH_ROLE_NONE,
        );

        // Replay the captured epoch-1 grant via the System replay path.
        assert_eq!(
            dispatch_as_system(
                &mut r,
                GrantRole {
                    peer_id: bob.clone(),
                    role: AUTH_ROLE_ADMIN,
                    epoch: 1,
                    auth: captured,
                },
            ),
            Status::Ok,
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: bob.clone() }),
            AUTH_ROLE_NONE,
            "a replayed stale-epoch grant can't resurrect the revoked role",
        );

        // A fresh root re-grant at a higher epoch restores Bob.
        assert_eq!(grant_space(&mut r, &bob, AUTH_ROLE_ADMIN), Status::Ok);
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: bob }),
            AUTH_ROLE_ADMIN,
            "a fresh higher-epoch grant re-authorizes",
        );
    }

    #[test]
    fn replayed_install_cannot_resurrect_an_uninstalled_agent() {
        // The replay guard: the replication_id is a grow-only tombstone. Capturing a
        // root-signed install and replaying it after uninstall reuses
        // the id and is refused; a fresh id reinstalls cleanly.
        let mut r = registry();
        let hash = alloc::vec![7u8; 32];
        dispatch(
            &mut r,
            Publish {
                name: String::from("p"),
                version: String::from("1"),
                hash: hash.clone(),
                auth: root_auth("publish", &[b"p", b"1", &hash]),
            },
        );
        let rep = alloc::vec![5u8; 32];
        let install_auth = root_auth(
            "install",
            &[
                b"res", b"p", b"1", &hash, &rep, &[2u8], &[], &[], &[0u8],
                &[SyncFloor::Member as u8],
            ],
        );
        let install = |r: &mut SpaceRegistry| {
            dispatch(
                r,
                Install {
                    instance_name: String::from("res"),
                    program_name: String::from("p"),
                    program_version: String::from("1"),
                    program_hash: hash.clone(),
                    replication_id: rep.clone(),
                    consistency: 2,
                    install_args: Vec::new(),
                    install_payloads: Vec::new(),
                    network_reachable: false,
                    sync_role: SyncFloor::Member as u8,
                    auth: install_auth.clone(),
                },
            )
        };
        assert_eq!(install(&mut r), Status::Ok);
        assert_eq!(uninstall(&mut r, "res"), Status::Ok);
        // Replay the captured install (same replication_id).
        assert_eq!(install(&mut r), Status::ReplicationIdReused);
        assert!(
            dispatch(
                &mut r,
                Agent {
                    instance_name: String::from("res"),
                },
            )
            .is_none(),
            "resurrect blocked — the AgentRow stays gone",
        );

        // A legitimate reinstall mints a fresh replication_id.
        let rep2 = alloc::vec![6u8; 32];
        assert_eq!(
            dispatch(
                &mut r,
                Install {
                    instance_name: String::from("res"),
                    program_name: String::from("p"),
                    program_version: String::from("1"),
                    program_hash: hash.clone(),
                    replication_id: rep2.clone(),
                    consistency: 2,
                    install_args: Vec::new(),
                    install_payloads: Vec::new(),
                    network_reachable: false,
                    sync_role: SyncFloor::Member as u8,
                    auth: root_auth(
                        "install",
                        &[
                            b"res", b"p", b"1", &hash, &rep2, &[2u8], &[], &[], &[0u8],
                            &[SyncFloor::Member as u8],
                        ],
                    ),
                },
            ),
            Status::Ok,
        );
    }

    #[test]
    fn replayed_upgrade_cannot_roll_back_a_version() {
        // Version-monotonicity guard: upgrade is pinned to the program
        // hash it was authored against (`from_hash`). After upgrading
        // p/1 → p/2, replaying a superseded upgrade whose `from_hash` is
        // the old hash finds a stale base and is refused.
        let mut r = registry();
        let h1 = alloc::vec![1u8; 32];
        let h2 = alloc::vec![2u8; 32];
        for (v, h) in [("1", &h1), ("2", &h2)] {
            dispatch(
                &mut r,
                Publish {
                    name: String::from("p"),
                    version: String::from(v),
                    hash: h.clone(),
                    auth: root_auth("publish", &[b"p", v.as_bytes(), h]),
                },
            );
        }
        let rep = alloc::vec![8u8; 32];
        assert_eq!(
            dispatch(
                &mut r,
                Install {
                    instance_name: String::from("app"),
                    program_name: String::from("p"),
                    program_version: String::from("1"),
                    program_hash: h1.clone(),
                    replication_id: rep.clone(),
                    consistency: 2,
                    install_args: Vec::new(),
                    install_payloads: Vec::new(),
                    network_reachable: false,
                    sync_role: SyncFloor::Member as u8,
                    auth: root_auth(
                        "install",
                        &[
                            b"app", b"p", b"1", &h1, &rep, &[2u8], &[], &[], &[0u8],
                            &[SyncFloor::Member as u8],
                        ],
                    ),
                },
            ),
            Status::Ok,
        );

        // Upgrade app p/1 → p/2, asserting the live base is h1.
        assert_eq!(
            dispatch(
                &mut r,
                Upgrade {
                    instance_name: String::from("app"),
                    new_program_name: String::from("p"),
                    new_program_version: String::from("2"),
                    new_program_hash: h2.clone(),
                    from_hash: h1.clone(),
                    auth: root_auth("upgrade", &[b"app", b"p", b"2", &h2, &h1]),
                },
            ),
            Status::Ok,
        );

        // Replay an upgrade back to p/1 (from_hash = h1) — the live hash
        // is now h2, so the compare-and-swap fails.
        assert_eq!(
            dispatch_as_system(
                &mut r,
                Upgrade {
                    instance_name: String::from("app"),
                    new_program_name: String::from("p"),
                    new_program_version: String::from("1"),
                    new_program_hash: h1.clone(),
                    from_hash: h1.clone(),
                    auth: root_auth("upgrade", &[b"app", b"p", b"1", &h1, &h1]),
                },
            ),
            Status::StaleUpgrade,
        );
        assert_eq!(
            dispatch(
                &mut r,
                Agent {
                    instance_name: String::from("app"),
                },
            )
            .unwrap()
            .program_version,
            "2",
            "the instance stays on the newer version",
        );
    }

    // ── Invites (redeem_invite / revoke_invite) ─────────────────

    const INVITE_EXPIRES: u64 = 2_000_000_000;

    /// A deterministic node signing key for a fixed seed byte — stands in
    /// for a joining node's own key (used to produce `node_sig`).
    fn node_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// The libp2p node peer-id for a node key.
    fn node_peer_of(k: &SigningKey) -> Vec<u8> {
        peer_id_for(&k.verifying_key().to_bytes())
    }

    /// Build a `RedeemInvite` message: `admin_key` mints an invite for
    /// `token_key`, redeemed by node `node`. The invite canonical binds
    /// the genesis root (`root_peer_id()`, set by `registry()`), exactly
    /// as the actor rebuilds it. Deterministic (fixed keys → identical
    /// bytes), so rebuilding it models a CRDT replay of the same op.
    /// Tamper one returned field to exercise a negative path.
    fn redeem_msg(
        admin_key: &SigningKey,
        token_key: &SigningKey,
        role: u8,
        node: &SigningKey,
    ) -> RedeemInvite {
        let token_pub = token_key.verifying_key().to_bytes();
        let peer_id = node_peer_of(node);
        let invite_canon = canonical_op_bytes(
            "invite",
            &[&root_peer_id(), &[role], &INVITE_EXPIRES.to_le_bytes(), &token_pub],
        );
        let admin_sig = admin_key.sign(&invite_canon).to_bytes();
        let redeem_canon = canonical_op_bytes("redeem_invite", &[&token_pub, &peer_id]);
        let redeem_sig = token_key.sign(&redeem_canon).to_bytes();
        let node_sig = node.sign(&redeem_canon).to_bytes();
        RedeemInvite {
            token_pub: token_pub.to_vec(),
            role,
            expires_at: INVITE_EXPIRES,
            admin_peer_id: peer_id_for(&admin_key.verifying_key().to_bytes()),
            admin_sig: admin_sig.to_vec(),
            peer_id,
            redeem_sig: redeem_sig.to_vec(),
            node_sig: node_sig.to_vec(),
        }
    }

    /// Drain the paginated invites table.
    fn invites_all(r: &mut SpaceRegistry) -> Vec<InviteRow> {
        let mut out = Vec::new();
        let mut after = Vec::new();
        loop {
            let page = dispatch(r, Invites { after, budget: 0 });
            out.extend(page.invites);
            if page.next.is_empty() {
                return out;
            }
            after = page.next;
        }
    }

    /// Root-signed `revoke_invite` dispatch.
    fn revoke_invite(r: &mut SpaceRegistry, token_pub: &[u8]) -> Status {
        dispatch(
            r,
            RevokeInvite {
                token_pub: token_pub.to_vec(),
                auth: root_auth("revoke_invite", &[token_pub]),
            },
        )
    }

    #[test]
    fn redeem_invite_happy_chain() {
        let mut r = registry();
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let node = node_key(66);
        let peer = node_peer_of(&node);
        assert_eq!(
            dispatch(&mut r, redeem_msg(&root_key(), &token, AUTH_ROLE_READONLY, &node)),
            Status::Ok,
            "root-minted invite redeems",
        );
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: peer.clone() }),
            AUTH_ROLE_READONLY,
            "redemption grants the token's role to the joining node",
        );
        let rows = invites_all(&mut r);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].redeemed_by, alloc::vec![peer]);
        assert!(!rows[0].revoked);
    }

    #[test]
    fn redeem_invite_developer_tier_ok() {
        let mut r = registry();
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let node = node_key(66);
        assert_eq!(
            dispatch(&mut r, redeem_msg(&root_key(), &token, AUTH_ROLE_DEVELOPER, &node)),
            Status::Ok,
        );
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: node_peer_of(&node) }), AUTH_ROLE_DEVELOPER);
    }

    #[test]
    fn redeem_invite_refuses_admin_tier() {
        // admin / voter enrollment is online-admission only; an offline
        // redeem carrying role=ADMIN is refused outright (decision 5).
        let mut r = registry();
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let node = node_key(66);
        assert_eq!(
            dispatch(&mut r, redeem_msg(&root_key(), &token, AUTH_ROLE_ADMIN, &node)),
            Status::Forbidden,
        );
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: node_peer_of(&node) }), AUTH_ROLE_NONE);
    }

    #[test]
    fn redeem_invite_tampered_admin_sig_rejected() {
        let mut r = registry();
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let node = node_key(66);
        let mut msg = redeem_msg(&root_key(), &token, AUTH_ROLE_READONLY, &node);
        msg.admin_sig[0] ^= 0xff;
        assert_eq!(dispatch(&mut r, msg), Status::Forbidden);
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: node_peer_of(&node) }), AUTH_ROLE_NONE);
    }

    #[test]
    fn redeem_invite_tampered_redeem_sig_rejected() {
        let mut r = registry();
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let node = node_key(66);
        let mut msg = redeem_msg(&root_key(), &token, AUTH_ROLE_READONLY, &node);
        msg.redeem_sig[0] ^= 0xff;
        assert_eq!(dispatch(&mut r, msg), Status::Forbidden);
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: node_peer_of(&node) }), AUTH_ROLE_NONE);
    }

    #[test]
    fn redeem_invite_tampered_node_sig_rejected() {
        // node_sig must verify under peer_id — a corrupted one is refused,
        // proving the peer-id-control gate is live.
        let mut r = registry();
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let node = node_key(66);
        let mut msg = redeem_msg(&root_key(), &token, AUTH_ROLE_READONLY, &node);
        msg.node_sig[0] ^= 0xff;
        assert_eq!(dispatch(&mut r, msg), Status::Forbidden);
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: node_peer_of(&node) }), AUTH_ROLE_NONE);
    }

    #[test]
    fn redeem_invite_non_admin_minter_rejected() {
        // A validly-signed invite whose minter is not an effective admin
        // (a stranger) is refused: the signatures verify, but
        // is_effective_admin(admin_peer_id) fails.
        let mut r = registry();
        let attacker = SigningKey::from_bytes(&[42u8; 32]);
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let node = node_key(66);
        assert_eq!(
            dispatch(&mut r, redeem_msg(&attacker, &token, AUTH_ROLE_READONLY, &node)),
            Status::Forbidden,
        );
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: node_peer_of(&node) }), AUTH_ROLE_NONE);
    }

    #[test]
    fn redeem_invite_lied_admin_peer_id_rejected() {
        // Pointing admin_peer_id at the (real admin) root while the
        // admin_sig stays the attacker's: verify_op_sig fails because the
        // signature wasn't produced by the claimed key.
        let mut r = registry();
        let attacker = SigningKey::from_bytes(&[42u8; 32]);
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let node = node_key(66);
        let mut msg = redeem_msg(&attacker, &token, AUTH_ROLE_READONLY, &node);
        msg.admin_peer_id = root_peer_id();
        assert_eq!(dispatch(&mut r, msg), Status::Forbidden);
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: node_peer_of(&node) }), AUTH_ROLE_NONE);
    }

    #[test]
    fn redeem_invite_cross_space_replay_rejected() {
        // An invite minted for ANOTHER space binds that space's root. The
        // actor rebuilds the invite canonical with its OWN root, so
        // admin_sig fails to verify — even though root_key IS this space's
        // admin. This is the cross-space replay the untrusted space_id arg
        // could not stop.
        let mut r = registry();
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let token_pub = token.verifying_key().to_bytes();
        let node = node_key(66);
        let peer = node_peer_of(&node);
        let other_root = peer_id_for(&SigningKey::from_bytes(&[123u8; 32]).verifying_key().to_bytes());
        let invite_canon = canonical_op_bytes(
            "invite",
            &[&other_root, &[AUTH_ROLE_READONLY], &INVITE_EXPIRES.to_le_bytes(), &token_pub],
        );
        let redeem_canon = canonical_op_bytes("redeem_invite", &[&token_pub, &peer]);
        let msg = RedeemInvite {
            token_pub: token_pub.to_vec(),
            role: AUTH_ROLE_READONLY,
            expires_at: INVITE_EXPIRES,
            admin_peer_id: root_peer_id(),
            admin_sig: root_key().sign(&invite_canon).to_bytes().to_vec(),
            peer_id: peer.clone(),
            redeem_sig: token.sign(&redeem_canon).to_bytes().to_vec(),
            node_sig: node.sign(&redeem_canon).to_bytes().to_vec(),
        };
        assert_eq!(dispatch(&mut r, msg), Status::Forbidden);
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: peer }), AUTH_ROLE_NONE);
    }

    #[test]
    fn redeem_invite_cannot_target_an_uncontrolled_peer() {
        // The Finding-1 downgrade attack: an attacker holding a VALID
        // member token tries to redeem it for a VICTIM's peer_id to
        // supersede the victim's (delegated) admin grant. Without a
        // node_sig under the victim's key the redeem is refused — on both
        // the direct and the CRDT-replay (System) path — so the victim
        // keeps admin.
        let mut r = registry();
        // Victim holds a delegated (non-root) admin grant — the case root
        // protection alone does not cover.
        let a2 = SigningKey::from_bytes(&[13u8; 32]);
        let a2_peer = peer_id_for(&a2.verifying_key().to_bytes());
        assert_eq!(grant_space(&mut r, &a2_peer, AUTH_ROLE_ADMIN), Status::Ok);
        let victim = node_key(90);
        let victim_peer = node_peer_of(&victim);
        assert_eq!(grant_space_signed(&mut r, &a2, &victim_peer, AUTH_ROLE_ADMIN), Status::Ok);
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: victim_peer.clone() }), AUTH_ROLE_ADMIN);

        // Attacker's forged redeem: valid token, target = victim_peer,
        // node_sig by the ATTACKER's key (not the victim's).
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let token_pub = token.verifying_key().to_bytes();
        let attacker = node_key(66);
        let forge = |role: u8| -> RedeemInvite {
            let invite_canon = canonical_op_bytes(
                "invite",
                &[&root_peer_id(), &[role], &INVITE_EXPIRES.to_le_bytes(), &token_pub],
            );
            let redeem_canon = canonical_op_bytes("redeem_invite", &[&token_pub, &victim_peer]);
            RedeemInvite {
                token_pub: token_pub.to_vec(),
                role,
                expires_at: INVITE_EXPIRES,
                admin_peer_id: root_peer_id(),
                admin_sig: root_key().sign(&invite_canon).to_bytes().to_vec(),
                peer_id: victim_peer.clone(),
                redeem_sig: token.sign(&redeem_canon).to_bytes().to_vec(),
                node_sig: attacker.sign(&redeem_canon).to_bytes().to_vec(),
            }
        };
        assert_eq!(dispatch(&mut r, forge(AUTH_ROLE_READONLY)), Status::Forbidden);
        assert_eq!(dispatch_as_system(&mut r, forge(AUTH_ROLE_READONLY)), Status::Forbidden);
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: victim_peer }),
            AUTH_ROLE_ADMIN,
            "victim's admin grant is untouched — no downgrade",
        );
    }

    #[test]
    fn redeem_invite_delegated_admin_can_mint() {
        // A delegated (non-root) admin mints; the joiner redeems.
        // Exercises the admin_peer_id → is_effective_admin path for a
        // non-root signer, and that revoking the minter voids the grant.
        let mut r = registry();
        let bob = SigningKey::from_bytes(&[11u8; 32]);
        let bob_peer = peer_id_for(&bob.verifying_key().to_bytes());
        assert_eq!(grant_space(&mut r, &bob_peer, AUTH_ROLE_ADMIN), Status::Ok);
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let node = node_key(66);
        let peer = node_peer_of(&node);
        assert_eq!(
            dispatch(&mut r, redeem_msg(&bob, &token, AUTH_ROLE_READONLY, &node)),
            Status::Ok,
        );
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: peer.clone() }), AUTH_ROLE_READONLY);
        assert_eq!(revoke_space(&mut r, &bob_peer), Status::Ok);
        assert_eq!(
            dispatch(&mut r, PeerRole { peer_id: peer }),
            AUTH_ROLE_NONE,
            "revoking the minting admin voids the redeemed grant",
        );
    }

    #[test]
    fn revoke_invite_blocks_redemption() {
        // revoke_invite before any redeem pre-creates the revoked row; a
        // later redeem is refused regardless of merge order.
        let mut r = registry();
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let token_pub = token.verifying_key().to_bytes();
        let node = node_key(66);
        assert_eq!(revoke_invite(&mut r, &token_pub), Status::Ok);
        assert_eq!(
            dispatch(&mut r, redeem_msg(&root_key(), &token, AUTH_ROLE_READONLY, &node)),
            Status::Forbidden,
        );
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: node_peer_of(&node) }), AUTH_ROLE_NONE);
    }

    #[test]
    fn revoke_invite_is_idempotent_and_grow_only() {
        let mut r = registry();
        let token_pub = SigningKey::from_bytes(&[55u8; 32]).verifying_key().to_bytes();
        assert_eq!(revoke_invite(&mut r, &token_pub), Status::Ok);
        assert_eq!(revoke_invite(&mut r, &token_pub), Status::Ok);
        let rows = invites_all(&mut r);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].revoked);
    }

    #[test]
    fn forged_revoke_invite_rejected_on_system_replay_path() {
        // A non-admin's forged revoke_invite merged via CRDT (arriving as
        // Caller::System, so the #[msg(role)] gate is a no-op) is still
        // refused by authorize_op — it never marks the token revoked.
        let mut r = registry();
        let attacker = SigningKey::from_bytes(&[42u8; 32]);
        let token_pub = SigningKey::from_bytes(&[55u8; 32]).verifying_key().to_bytes();
        let status = dispatch_as_system(
            &mut r,
            RevokeInvite {
                token_pub: token_pub.to_vec(),
                auth: auth_as(&attacker, "revoke_invite", &[&token_pub]),
            },
        );
        assert_eq!(status, Status::Forbidden);
        assert!(invites_all(&mut r).is_empty(), "forged revoke marks nothing");
    }

    #[test]
    fn redeem_invite_double_redeem_records_both_peers() {
        // Decision 6: single-use is best-effort. Two different nodes
        // redeeming the same token both get granted and both are recorded
        // (sorted) — detection, not prevention.
        let mut r = registry();
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let node_a = node_key(66);
        let node_b = node_key(77);
        let peer_a = node_peer_of(&node_a);
        let peer_b = node_peer_of(&node_b);
        assert_eq!(
            dispatch(&mut r, redeem_msg(&root_key(), &token, AUTH_ROLE_READONLY, &node_a)),
            Status::Ok,
        );
        assert_eq!(
            dispatch(&mut r, redeem_msg(&root_key(), &token, AUTH_ROLE_READONLY, &node_b)),
            Status::Ok,
        );
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: peer_a.clone() }), AUTH_ROLE_READONLY);
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: peer_b.clone() }), AUTH_ROLE_READONLY);
        let rows = invites_all(&mut r);
        assert_eq!(rows.len(), 1);
        let mut expected = alloc::vec![peer_a, peer_b];
        expected.sort();
        assert_eq!(rows[0].redeemed_by, expected, "both redeemers recorded, sorted");
    }

    #[test]
    fn redeem_invite_is_idempotent_on_replay() {
        // Re-dispatching the identical redeem (the CRDT-replay path via
        // Caller::System) is a clean no-op: grant supersede + the sorted
        // redeemed_by set both converge, so the state is unchanged.
        let mut r = registry();
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let node = node_key(66);
        let peer = node_peer_of(&node);
        assert_eq!(
            dispatch(&mut r, redeem_msg(&root_key(), &token, AUTH_ROLE_READONLY, &node)),
            Status::Ok,
        );
        assert_eq!(
            dispatch_as_system(&mut r, redeem_msg(&root_key(), &token, AUTH_ROLE_READONLY, &node)),
            Status::Ok,
        );
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: peer.clone() }), AUTH_ROLE_READONLY);
        let rows = invites_all(&mut r);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].redeemed_by, alloc::vec![peer], "replay doesn't duplicate the peer");
    }

    #[test]
    fn revoked_then_replayed_redeem_stays_revoked() {
        // Capture a valid redeem, revoke the invite, then replay the
        // captured redeem via Caller::System: it stays refused (the
        // revoked flag is grow-only and dominates the replay).
        let mut r = registry();
        let token = SigningKey::from_bytes(&[55u8; 32]);
        let token_pub = token.verifying_key().to_bytes();
        let node = node_key(66);
        let captured = redeem_msg(&root_key(), &token, AUTH_ROLE_READONLY, &node);
        assert_eq!(revoke_invite(&mut r, &token_pub), Status::Ok);
        assert_eq!(dispatch_as_system(&mut r, captured), Status::Forbidden);
        assert_eq!(dispatch(&mut r, PeerRole { peer_id: node_peer_of(&node) }), AUTH_ROLE_NONE);
    }
}
