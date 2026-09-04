//! Space registry — the per-space source of truth.
//!
//! Holds four primary tables, replicated through the registry actor's Merge
//! journal. Mutation signatures are checked again inside the guest; immutable
//! authority-finality receipts are the separate admission boundary for the
//! clean-cutover catalog protocol.
//!
//! 1. **Programs** — named pointers to content-addressed PVM packages.
//!    Every row has an immutable service/AgentActor kind and publication
//!    generation; installed actors retain the exact generation they use.
//! 2. **Agents** — installed conventional service replicas, each with
//!    its own `instance_name`, `replication_id`, consistency,
//!    and state. Multiple agents can share one program.
//! 3. **System actors** — actors installed inside the Local system Agent
//!    Host, with host-returned `AgentId`/`ActorId` identities.
//! 4. **Members** — Nodes (libp2p peers, may vote in consensus)
//!    and Identities (people / bots, author signed messages
//!    with a Merkle-inclusion or ZK proof of set membership).
//!
//! Init args for an installed agent are NOT stored in the
//! Agents table; they live in the registry's own DAG as the
//! genesis effect of the typed install operation. Auditable via
//! the DAG; not part of the queryable schema.
//!
//! Hashes (`program_hash`, `replication_id`, `peer_id`) cross
//! message boundaries as `Vec<u8>` because the dynamic-`Msg`
//! arg system handles a small fixed set of primitive types.
//! The actor validates lengths internally and stores `[u8; 32]`
//! in the rkyv-archived rows.
//!
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
pub use vos::InstallationId;
pub use vos::registry::{
    AUTH_ROLE_ADMIN, AUTH_ROLE_DEVELOPER, AUTH_ROLE_NONE, AUTH_ROLE_READONLY, AgentLookup,
    AgentNamePage, AgentPage, AgentRow, AuthGrantPage, AuthGrantRow, InvitePage, InviteRow,
    MEMBER_KIND_IDENTITY, MEMBER_KIND_NODE, MemberPage, MemberRow, NODE_ROLE_OBSERVER,
    NODE_ROLE_VOTER, OP_SIG_LEN, PROOF_KIND_MERKLE_INCLUSION, PROOF_KIND_ZK,
    ProgramBlobAuthorization, ProgramKind, ProgramLookup, ProgramPage, ProgramRow, ProgramTag,
    PublicationId, REGISTRY_MUTATION_DOMAIN, REGISTRY_SCHEMA_HASH, REGISTRY_SCHEMA_VERSION,
    RegistryProtocol, SPACE_ID_DOMAIN_TAG, Status, SyncFloor, SystemActorInstallReceipt,
    SystemActorLookup, SystemActorPage, SystemActorRow, ed25519_pubkey_from_peer_id,
    install_service_actor_signed_bytes, install_system_actor_signed_bytes, instance_service_id,
    invite_signed_bytes, is_canonical_registry_slug, is_defined_auth_role, is_grantable_auth_role,
    is_offline_invite_role, pack_auth, publish_agent_actor_program_signed_bytes,
    publish_service_program_signed_bytes, registry_mutation_signed_bytes,
    role_authority_invite_attestation_signed_bytes, role_authority_signed_bytes,
    role_grant_supersedes, uninstall_service_actor_signed_bytes,
    uninstall_system_actor_signed_bytes, unpublish_agent_actor_program_signed_bytes,
    unpublish_service_program_signed_bytes, upgrade_service_actor_signed_bytes,
    upgrade_system_actor_signed_bytes,
};

// ── Programs ──────────────────────────────────────────────────────

/// One row in the metadata table — opaque schema bytes attached to a
/// program hash. The wire payload is the raw `.vos_meta` ELF section
/// (binary format defined by `vos::actors::metadata`). The registry validates
/// that format before storing the bytes.
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

// ── Auth grants ───────────────────────────────────────────────────
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
/// Public reads use this role vocabulary. Mutations authenticate their
/// canonical operation bytes inside the handler so live execution and causal
/// replay apply exactly the same rule.
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

/// Per-actor SpaceRole map, declared as a `pub const` so
/// it survives the `#[actor(space_role_map = ...)]` expansion.
/// Maps the four space-level tiers onto this registry's local
/// roles:
///
///   space Admin     → registry Admin     (full control)
///   space Developer → registry Developer (reserved — no
///                                         handlers gate on
///                                         Developer today, but
///                                         the tier is wired so
///                                         operators can
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
    space_role_map = SPACE_REGISTRY_SPACE_ROLE_MAP,
    state_version = 2
)]
pub struct SpaceRegistry {
    /// Sorted by name for fast lookup.
    programs: Vec<ProgramRow>,
    /// Installed service-actor replicas, sorted by `instance_name`.
    agents: Vec<AgentRow>,
    /// Actors installed inside the Local system Agent Host, sorted by
    /// `instance_name` and kept separate from replicated services.
    system_actors: Vec<SystemActorRow>,
    /// Node members, one `#[storage]` row per node keyed by its `u16`
    /// `prefix` (a fixed-width key, so iteration is prefix-ordered).
    /// `node_role` point-gets; `members()` pages nodes before identities.
    #[storage]
    nodes: StorageMap<u16, MemberRow>,
    /// Identity members, one `#[storage]` row per identity keyed by
    /// `identity_key(public_key)` (variable-length key folded to fixed
    /// width; the row keeps the plain key). The nodes/identities split
    /// keeps each a single-key-type map instead of mixing `u16` prefixes and
    /// variable public keys.
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
    /// Exact canonical-authority bindings, one private point row per peer.
    /// This is deliberately a separate storage namespace from `metas`: an
    /// administrator may author program metadata, but only the dedicated service
    /// grant/redeem handlers can write this map. The value is the complete
    /// authority/grant binding digest checked by `effective_role`.
    #[storage]
    authority_grant_witnesses: StorageMap<[u8; 32], [u8; 32]>,
    /// Opaque metadata blobs for native `.so` extensions, keyed by
    /// the manifest `instance_name`. Native extensions have
    /// no program-hash identity in this catalog (the host loads
    /// them off a filesystem path), so we key by the operator-
    /// visible name. `meta_for_instance` falls through here when
    /// the name doesn't match an installed PVM agent. A `#[storage]`
    /// map keyed by `name_key(instance_name)` (the name folded to a
    /// fixed-width key); the row keeps the plain name.
    #[storage]
    extension_metas: StorageMap<[u8; 32], ExtensionMetaRow>,
    /// Per-PeerId auth grants, one row per peer. A `#[storage]`
    /// map keyed by `peer_key(peer_id)`: `effective_role`/`peer_epoch`
    /// point-get, `auth_grants()` pages.
    #[storage]
    auth_grants: StorageMap<[u8; 32], AuthGrantRow>,
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
    /// Immutable identity of the role-authority service for this space.
    #[storage]
    role_authority: StorageValue<[u8; 32]>,
    /// This space's `space_id` (blake2b of the genesis DAG root),
    /// anchored once at boot (first-write-wins). Unlike `root` — the
    /// operator's CLI identity, which is SHARED across every space that
    /// operator runs — `space_id` is distinct per space (the genesis
    /// commit's `origin` is a fresh per-space key), so `redeem_invite`
    /// binds it to make an invite non-replayable at a sibling space. A
    /// `#[storage]` value so it resets/survives together with the
    /// authority state it scopes, per the `revoke_epochs` discipline.
    #[storage]
    space_id: StorageValue<Vec<u8>>,
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
    /// Grow-only burn set for service and system-actor installation
    /// identities. The identity is consumed before a row becomes visible and
    /// survives uninstall, so a captured install cannot resurrect either
    /// class of actor.
    #[storage]
    used_installation_ids: StorageSet<[u8; 32]>,
    /// Grow-only generation map for catalog tag movements. A publication id
    /// maps to a digest of its complete signed CAS preimage, so it can name
    /// exactly one attempted movement. Exact successful retries remain
    /// idempotent, while a retry that changes even the expected base is
    /// refused. Losing ids stay present and cannot become latent work after
    /// an A -> B -> A hash cycle.
    #[storage]
    used_publication_ids: StorageMap<[u8; 32], [u8; 32]>,
    /// Grow-only authorization set for immutable package blob serving.
    /// Catalog names are mutable, while installed/replay/proof records remain
    /// pinned to historical content. Retaining the hash entitlement lets a
    /// fresh replica recover those bytes after a name is moved or removed.
    #[storage]
    authorized_program_hashes: StorageSet<[u8; 32]>,
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
            system_actors: Vec::new(),
            nodes: StorageMap::default(),
            identities: StorageMap::default(),
            metas: StorageMap::default(),
            authority_grant_witnesses: StorageMap::default(),
            extension_metas: StorageMap::default(),
            auth_grants: StorageMap::default(),
            revoke_epochs: StorageMap::default(),
            host_mappings: StorageMap::default(),
            consistency_floors: StorageMap::default(),
            root: StorageValue::default(),
            role_authority: StorageValue::default(),
            space_id: StorageValue::default(),
            used_replication_ids: StorageSet::default(),
            used_installation_ids: StorageSet::default(),
            used_publication_ids: StorageMap::default(),
            authorized_program_hashes: StorageSet::default(),
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
    /// `space_id`. The explicit schema identity is part of the dynamic
    /// message shape, so replaying a historical one-argument `set_root`
    /// cannot cause new code to wrap v1 state in a current v2 envelope.
    #[msg]
    async fn set_root(
        &mut self,
        root: Vec<u8>,
        schema_version: u32,
        schema_hash: Vec<u8>,
    ) -> Status {
        if schema_version != REGISTRY_SCHEMA_VERSION
            || bytes_to_32(&schema_hash) != Some(REGISTRY_SCHEMA_HASH)
        {
            return Status::ProtocolMismatch;
        }
        if ed25519_pubkey_from_peer_id(&root).is_none() {
            return Status::BadHash;
        }
        // Inspect the raw cell, not `root_bytes()`: a v1 root deliberately
        // decodes as unsupported, but it must never become overwriteable.
        if self.root.get().is_some_and(|stored| !stored.is_empty()) {
            return Status::Forbidden;
        }
        self.root.set(&encode_registry_root(&root));
        Status::Ok
    }

    /// Exact wire/state generation opened by this persisted registry. A new
    /// actor over pre-v2 state returns `UNSUPPORTED`; callers must not treat
    /// that state as an empty v2 registry.
    #[msg]
    async fn protocol(&self) -> RegistryProtocol {
        if self.schema_ready() {
            RegistryProtocol::CURRENT
        } else {
            RegistryProtocol::UNSUPPORTED
        }
    }

    /// The genesis root PeerId, or empty if none is set. Read surface
    /// for diagnostics and joiner verification.
    #[msg]
    async fn root(&self) -> Vec<u8> {
        self.root_bytes()
    }

    /// Anchor this space's `space_id` (first-write-wins). The daemon
    /// calls this at boot with the id it validated against the genesis;
    /// `redeem_invite` binds it so an invite minted for this space cannot
    /// be replayed at a sibling space the same operator runs (whose
    /// genesis root — the operator identity — is identical). Unsigned,
    /// like `set_root`: the value is public and verifiable from the
    /// genesis, and first-write-wins pins the earliest (the operator's
    /// own boot, before any peer is invited).
    #[msg]
    async fn set_space_id(&mut self, space_id: Vec<u8>) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        let Some(space_id) = nonzero_32(&space_id) else {
            return Status::BadHash;
        };
        if !self.space_id_bytes().is_empty() {
            return Status::Forbidden;
        }
        self.space_id.set(&space_id.to_vec());
        Status::Ok
    }

    /// This space's anchored `space_id`, or empty if never set.
    #[msg]
    async fn space_id(&self) -> Vec<u8> {
        if !self.schema_ready() {
            return Vec::new();
        }
        self.space_id_bytes()
    }

    /// Exact canonical role-authority incarnation bound to this registry.
    #[msg]
    async fn role_authority(&self) -> Vec<u8> {
        if !self.schema_ready() {
            return Vec::new();
        }
        self.role_authority_id()
            .map(|id| id.to_vec())
            .unwrap_or_default()
    }

    /// Bind the registry to the immutable root's canonical role authority.
    /// First write wins and an identical retry is idempotent.
    #[msg]
    async fn set_role_authority(
        &mut self,
        authority_replication_id: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        let Some(authority_replication_id) = bytes_to_32(&authority_replication_id) else {
            return Status::BadHash;
        };
        if authority_replication_id == [0; 32]
            || !self.authorize_root_op("set_role_authority", &[&authority_replication_id], &auth)
        {
            return Status::Forbidden;
        }
        if let Some(current) = self.role_authority_id() {
            return if current == authority_replication_id {
                Status::Ok
            } else {
                Status::Forbidden
            };
        }
        self.role_authority.set(&authority_replication_id);
        Status::Ok
    }

    // ── Programs catalog ────────────────────────────────────────

    /// Publish a service package. The distinct verb fixes the row kind; the
    /// signed expected tag is a full generation+hash CAS precondition.
    #[msg]
    async fn publish_service_program(
        &mut self,
        name: String,
        hash: Vec<u8>,
        crdt: bool,
        publication_id: Vec<u8>,
        expected_publication_id: Vec<u8>,
        expected_hash: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op(
            "publish_service_program",
            &[
                name.as_bytes(),
                &hash,
                &[crdt as u8],
                &publication_id,
                &expected_publication_id,
                &expected_hash,
            ],
            &auth,
        ) {
            return Status::Forbidden;
        }
        self.publish_program_cas(
            name,
            hash,
            ProgramKind::Service { crdt },
            publication_id,
            expected_publication_id,
            expected_hash,
        )
    }

    /// Publish an AgentActor package. No service/CRDT flag exists on this
    /// wire, so kind confusion cannot be encoded.
    #[msg]
    async fn publish_agent_actor_program(
        &mut self,
        name: String,
        hash: Vec<u8>,
        publication_id: Vec<u8>,
        expected_publication_id: Vec<u8>,
        expected_hash: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op(
            "publish_agent_actor_program",
            &[
                name.as_bytes(),
                &hash,
                &publication_id,
                &expected_publication_id,
                &expected_hash,
            ],
            &auth,
        ) {
            return Status::Forbidden;
        }
        self.publish_program_cas(
            name,
            hash,
            ProgramKind::AgentActor,
            publication_id,
            expected_publication_id,
            expected_hash,
        )
    }

    /// Remove an exact service-program tag generation.
    #[msg]
    async fn unpublish_service_program(
        &mut self,
        name: String,
        expected_publication_id: Vec<u8>,
        expected_hash: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op(
            "unpublish_service_program",
            &[name.as_bytes(), &expected_publication_id, &expected_hash],
            &auth,
        ) {
            return Status::Forbidden;
        }
        self.unpublish_program_cas(
            &name,
            &expected_publication_id,
            &expected_hash,
            ProgramClass::Service,
        )
    }

    /// Remove an exact AgentActor tag generation.
    #[msg]
    async fn unpublish_agent_actor_program(
        &mut self,
        name: String,
        expected_publication_id: Vec<u8>,
        expected_hash: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op(
            "unpublish_agent_actor_program",
            &[name.as_bytes(), &expected_publication_id, &expected_hash],
            &auth,
        ) {
            return Status::Forbidden;
        }
        self.unpublish_program_cas(
            &name,
            &expected_publication_id,
            &expected_hash,
            ProgramClass::AgentActor,
        )
    }

    /// Look up one discriminated program row by name.
    #[msg]
    async fn catalog_program(&self, name: String) -> ProgramLookup {
        ProgramLookup {
            protocol: self.protocol_descriptor(),
            row: self
                .schema_ready()
                .then(|| self.programs.iter().find(|p| p.name == name).cloned())
                .flatten(),
        }
    }

    /// Look up one discriminated program row by immutable hash.
    #[msg]
    async fn catalog_program_by_hash(&self, hash: Vec<u8>) -> ProgramLookup {
        let row = if self.schema_ready() {
            bytes_to_32(&hash)
                .and_then(|hash| self.programs.iter().find(|p| p.hash == hash).cloned())
        } else {
            None
        };
        ProgramLookup {
            protocol: self.protocol_descriptor(),
            row,
        }
    }

    /// Authorize serving an immutable program blob that was admitted by any
    /// successful publication generation. This intentionally outlives the
    /// mutable name tag so pinned actors and replay/proof history can recover
    /// displaced packages.
    #[msg]
    async fn program_blob_authorized(&self, hash: Vec<u8>) -> ProgramBlobAuthorization {
        if !self.schema_ready() {
            return ProgramBlobAuthorization {
                protocol: RegistryProtocol::UNSUPPORTED,
                authorized: false,
            };
        }
        ProgramBlobAuthorization {
            protocol: RegistryProtocol::CURRENT,
            authorized: bytes_to_32(&hash)
                .is_some_and(|hash| self.authorized_program_hashes.contains(&hash)),
        }
    }

    /// Page the program catalog in name order. Pass an empty name to start;
    /// continue from the last returned row while the page's `more` flag is set
    /// (a short page alone doesn't mean done — the byte budget can truncate
    /// one). `budget` caps the page rows (0 = the handler's max). The
    /// backing `programs` is kept sorted on insert, so a natural cursor over
    /// the last emitted row pages the whole catalog without a per-page sort.
    #[msg]
    async fn catalog_programs(&self, after_name: String, budget: u32) -> ProgramPage {
        if !self.schema_ready() {
            return ProgramPage {
                protocol: RegistryProtocol::UNSUPPORTED,
                rows: Vec::new(),
                more: false,
            };
        }
        let started = after_name.is_empty();
        let mut it = self
            .programs
            .iter()
            .filter(|p| started || p.name > after_name)
            .cloned();
        let (rows, more) = fill_page(&mut it, page_rows(budget), PAGE_BYTE_BUDGET);
        ProgramPage {
            protocol: self.protocol_descriptor(),
            rows,
            more,
        }
    }

    // ── Metadata blobs ──────────────────────────────────────────

    /// Record (or replace) the metadata blob for a program hash.
    /// Idempotent: re-registering the same hash overwrites the existing blob.
    /// The hash doesn't need to match an
    /// existing `ProgramRow` — schema can be registered before
    /// the program is published if the orchestrator prefers
    /// that order.
    #[msg]
    async fn register_meta(
        &mut self,
        program_hash: Vec<u8>,
        blob: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op("register_meta", &[&program_hash, &blob], &auth) {
            return Status::Forbidden;
        }
        let Some(program_hash) = bytes_to_32(&program_hash) else {
            return Status::BadHash;
        };
        if vos::metadata::decode(&blob).is_none() {
            return Status::BadMetadata;
        }
        // Upsert: one point write, keyed by the program hash.
        self.metas
            .insert(&program_hash, &MetaRow { program_hash, blob });
        Status::Ok
    }

    /// Look up the metadata blob for a program hash. Returns an
    /// empty vector when no entry exists.
    #[msg]
    async fn meta_for_program(&self, program_hash: Vec<u8>) -> Vec<u8> {
        if !self.schema_ready() {
            return Vec::new();
        }
        let Some(program_hash) = bytes_to_32(&program_hash) else {
            return Vec::new();
        };
        self.metas
            .get(&program_hash)
            .map(|m| m.blob)
            .unwrap_or_default()
    }

    /// Convenience join: find an installed agent by name, then
    /// return its program's metadata blob. Saves the caller a
    /// round trip in the common case (worker resolving a
    /// per-method schema). Empty vector when the agent is
    /// unknown or has no meta registered.
    ///
    /// Falls through to the extension-meta table when no agent
    /// matches — extensions share the same instance-name
    /// namespace from the manifest, and `vosx <ext> <cmd>` needs
    /// a single lookup that doesn't care whether the target is a
    /// PVM agent or a native `.so`. Agents win on collision; an
    /// extension with the same name as an installed agent is
    /// shadowed.
    #[msg]
    async fn meta_for_instance(&self, name: String) -> Vec<u8> {
        if !self.schema_ready() {
            return Vec::new();
        }
        let mut ai = 0usize;
        while ai < self.agents.len() {
            if self.agents[ai].instance_name == name {
                let hash = self.agents[ai].program_hash;
                return self.metas.get(&hash).map(|m| m.blob).unwrap_or_default();
            }
            ai += 1;
        }
        let mut si = 0usize;
        while si < self.system_actors.len() {
            if self.system_actors[si].instance_name == name {
                let hash = self.system_actors[si].program_hash;
                return self.metas.get(&hash).map(|m| m.blob).unwrap_or_default();
            }
            si += 1;
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
    /// An empty `blob` removes the row. Non-empty metadata is decoded before
    /// it becomes visible.
    #[msg]
    async fn register_extension_meta(
        &mut self,
        instance_name: String,
        blob: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op(
            "register_extension_meta",
            &[instance_name.as_bytes(), &blob],
            &auth,
        ) {
            return Status::Forbidden;
        }
        if !is_canonical_registry_slug(&instance_name) {
            return Status::BadHash;
        }
        // An empty blob removes the row; otherwise upsert. Both are one
        // point op, keyed by the instance name.
        let key = name_key(&instance_name);
        if blob.is_empty() {
            self.extension_metas.remove(&key);
        } else {
            if vos::metadata::decode(&blob).is_none() {
                return Status::BadMetadata;
            }
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

    // ── Installed service actors / Local system actors ─────────

    /// Admit a conventional service actor. The catalog generation and opaque
    /// installation id are both signed; the latter is burned forever.
    #[msg]
    async fn install_service_actor(
        &mut self,
        instance_name: String,
        program_name: String,
        program_hash: Vec<u8>,
        program_publication_id: Vec<u8>,
        installation_id: Vec<u8>,
        replication_id: Vec<u8>,
        consistency: u8,
        network_reachable: bool,
        sync_role: u8,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op(
            "install_service_actor",
            &[
                instance_name.as_bytes(),
                program_name.as_bytes(),
                &program_hash,
                &program_publication_id,
                &installation_id,
                &replication_id,
                &[consistency],
                &[network_reachable as u8],
                &[sync_role],
            ],
            &auth,
        ) {
            return Status::Forbidden;
        }
        if !is_canonical_registry_slug(&instance_name) || !is_canonical_registry_slug(&program_name)
        {
            return Status::BadHash;
        }
        let Some(program_hash) = bytes_to_32(&program_hash) else {
            return Status::BadHash;
        };
        let Some(program_publication_id) = nonzero_32(&program_publication_id) else {
            return Status::BadHash;
        };
        let Some(installation_id) = nonzero_32(&installation_id) else {
            return Status::BadHash;
        };
        let Some(replication_id) = nonzero_32(&replication_id) else {
            return Status::BadHash;
        };
        if consistency > 3 {
            return Status::BadHash;
        }
        let Some(sync_role) = SyncFloor::from_u8(sync_role) else {
            return Status::BadHash;
        };
        let position = self
            .agents
            .binary_search_by(|row| row.instance_name.as_str().cmp(&instance_name));
        if let Ok(idx) = position {
            let row = &self.agents[idx];
            if row.installation_id.as_bytes() == &installation_id
                && row.program_name == program_name
                && row.program_hash == program_hash
                && row.program_publication_id.as_bytes() == &program_publication_id
                && row.replication_id == replication_id
                && row.consistency == consistency
                && row.network_reachable == network_reachable
                && row.sync_role == sync_role
            {
                return if self.used_installation_ids.contains(&installation_id)
                    && self.used_replication_ids.contains(&replication_id)
                {
                    Status::Ok
                } else {
                    Status::ProtocolMismatch
                };
            }
        }
        // Once every argument has a canonical structural shape, consume both
        // opaque identities before consulting mutable semantic state. In
        // particular, ProgramNotFound/CrdtOptInRequired/name conflicts and a
        // locality-floor refusal must not leave a captured signed install as
        // latent work that can succeed after the relevant state changes.
        let installation_id_reused = self.used_installation_ids.contains(&installation_id);
        let replication_id_reused = self.used_replication_ids.contains(&replication_id);
        self.used_installation_ids.insert(&installation_id);
        self.used_replication_ids.insert(&replication_id);
        let Some(program) = self.programs.iter().find(|program| {
            program.name == program_name
                && program.hash == program_hash
                && program.publication_id.as_bytes() == &program_publication_id
        }) else {
            return Status::ProgramNotFound;
        };
        let ProgramKind::Service { crdt } = program.kind else {
            return Status::ProgramKindMismatch;
        };
        if consistency == 2 && !crdt {
            return Status::CrdtOptInRequired;
        }
        if self
            .system_actors
            .iter()
            .any(|row| row.instance_name == instance_name)
        {
            // Service and system actors share one externally visible name
            // namespace.
            return Status::InstanceExists;
        }
        if position.is_ok() {
            return Status::InstanceExists;
        }
        if installation_id_reused {
            return Status::InstallationIdReused;
        }
        if replication_id_reused {
            return Status::ReplicationIdReused;
        }
        let floor_key = name_key(&instance_name);
        match self.consistency_floors.get(&floor_key) {
            Some(floor) if !may_transition_to(floor, consistency) => {
                return Status::ConsistencyWidenDenied;
            }
            Some(floor) if shareability(consistency) < shareability(floor) => {
                self.consistency_floors.insert(&floor_key, &consistency);
            }
            None => {
                self.consistency_floors.insert(&floor_key, &consistency);
            }
            Some(_) => {}
        }
        // Both identities were burned before semantic validation. Expose the
        // row only after every precondition has passed in this atomic dispatch.
        self.agents.insert(
            position.expect_err("occupied position returned above"),
            AgentRow {
                instance_name,
                installation_id: InstallationId::new(installation_id),
                revision: 0,
                program_hash,
                program_name,
                program_publication_id: PublicationId::new(program_publication_id),
                replication_id,
                consistency,
                network_reachable,
                sync_role,
            },
        );
        Status::Ok
    }

    /// The loose registry-only system install wire is retained solely so old
    /// clients receive an explicit fail-closed status. A production install
    /// must reserve the intent at finality and present Node-authenticated Host
    /// completion evidence; accepting a root-wrapped opaque receipt here
    /// would permit registry state to diverge from the Local Agent Host.
    #[msg]
    async fn install_system_actor(&mut self, receipt: Vec<u8>, auth: Vec<u8>) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_root_op("install_system_actor", &[&receipt], &auth) {
            return Status::Forbidden;
        }
        Status::HostLifecycleRequired
    }

    #[msg]
    async fn uninstall_service_actor(
        &mut self,
        instance_name: String,
        installation_id: Vec<u8>,
        expected_revision: u64,
        expected_program_hash: Vec<u8>,
        expected_program_publication_id: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op(
            "uninstall_service_actor",
            &[
                instance_name.as_bytes(),
                &installation_id,
                &expected_revision.to_le_bytes(),
                &expected_program_hash,
                &expected_program_publication_id,
            ],
            &auth,
        ) {
            return Status::Forbidden;
        }
        if !is_canonical_registry_slug(&instance_name) {
            return Status::BadHash;
        }
        let (
            Some(installation_id),
            Some(expected_program_hash),
            Some(expected_program_publication_id),
        ) = (
            bytes_to_32(&installation_id),
            bytes_to_32(&expected_program_hash),
            bytes_to_32(&expected_program_publication_id),
        )
        else {
            return Status::BadHash;
        };
        let Some(idx) = self
            .agents
            .iter()
            .position(|row| row.instance_name == instance_name)
        else {
            return Status::NotFound;
        };
        let row = &self.agents[idx];
        if validate_installation_precondition(
            row.installation_id,
            row.revision,
            ProgramTag {
                publication_id: row.program_publication_id,
                hash: row.program_hash,
            },
            installation_id,
            expected_revision,
            ProgramTag {
                publication_id: PublicationId::new(expected_program_publication_id),
                hash: expected_program_hash,
            },
        )
        .is_err()
        {
            return Status::StaleInstallation;
        }
        self.agents.remove(idx);
        Status::Ok
    }

    #[msg]
    async fn uninstall_system_actor(
        &mut self,
        instance_name: String,
        installation_id: Vec<u8>,
        expected_revision: u64,
        expected_program_hash: Vec<u8>,
        expected_program_publication_id: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_root_op(
            "uninstall_system_actor",
            &[
                instance_name.as_bytes(),
                &installation_id,
                &expected_revision.to_le_bytes(),
                &expected_program_hash,
                &expected_program_publication_id,
            ],
            &auth,
        ) {
            return Status::Forbidden;
        }
        Status::HostLifecycleRequired
    }

    #[msg]
    async fn upgrade_service_actor(
        &mut self,
        instance_name: String,
        installation_id: Vec<u8>,
        expected_revision: u64,
        from_program_hash: Vec<u8>,
        from_program_publication_id: Vec<u8>,
        new_program_name: String,
        new_program_hash: Vec<u8>,
        new_program_publication_id: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op(
            "upgrade_service_actor",
            &[
                instance_name.as_bytes(),
                &installation_id,
                &expected_revision.to_le_bytes(),
                &from_program_hash,
                &from_program_publication_id,
                new_program_name.as_bytes(),
                &new_program_hash,
                &new_program_publication_id,
            ],
            &auth,
        ) {
            return Status::Forbidden;
        }
        Status::HostLifecycleRequired
    }

    #[msg]
    async fn upgrade_system_actor(
        &mut self,
        instance_name: String,
        installation_id: Vec<u8>,
        expected_revision: u64,
        from_program_hash: Vec<u8>,
        from_program_publication_id: Vec<u8>,
        new_program_name: String,
        new_program_hash: Vec<u8>,
        new_program_publication_id: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_root_op(
            "upgrade_system_actor",
            &[
                instance_name.as_bytes(),
                &installation_id,
                &expected_revision.to_le_bytes(),
                &from_program_hash,
                &from_program_publication_id,
                new_program_name.as_bytes(),
                &new_program_hash,
                &new_program_publication_id,
            ],
            &auth,
        ) {
            return Status::Forbidden;
        }
        Status::HostLifecycleRequired
    }

    #[msg]
    async fn service_actor(&self, instance_name: String) -> AgentLookup {
        AgentLookup {
            protocol: self.protocol_descriptor(),
            row: self
                .schema_ready()
                .then(|| {
                    self.agents
                        .iter()
                        .find(|a| a.instance_name == instance_name)
                        .cloned()
                })
                .flatten(),
        }
    }

    /// The first installed agent (in `instance_name` order) whose name
    /// starts with `prefix` and ends with `suffix` — a template lookup so a
    /// caller cloning a channel's program rows (the messenger, creating a
    /// `msg-*-log`/`-ctl` pair) needn't drain the whole roster. `agents` is
    /// kept sorted on insert, so "first" is deterministic.
    #[msg]
    async fn service_actor_by_pattern(&self, prefix: String, suffix: String) -> AgentLookup {
        AgentLookup {
            protocol: self.protocol_descriptor(),
            row: self
                .schema_ready()
                .then(|| {
                    self.agents
                        .iter()
                        .find(|a| {
                            a.instance_name.starts_with(&prefix)
                                && a.instance_name.ends_with(&suffix)
                        })
                        .cloned()
                })
                .flatten(),
        }
    }

    /// Page the installed-agent roster, in `instance_name` order. Pass an
    /// empty `after_name` to start; continue from the last returned row's
    /// `instance_name` while the page's `more` flag is set. `budget` caps
    /// the page rows (0 = the handler's max). `agents` is kept sorted on
    /// insert, so a natural cursor over the last emitted row pages the whole
    /// roster without a per-page sort.
    #[msg]
    async fn service_actors(&self, after_name: String, budget: u32) -> AgentPage {
        if !self.schema_ready() {
            return AgentPage {
                protocol: RegistryProtocol::UNSUPPORTED,
                rows: Vec::new(),
                more: false,
            };
        }
        let started = after_name.is_empty();
        let mut it = self
            .agents
            .iter()
            .filter(|a| started || a.instance_name.as_str() > after_name.as_str())
            .cloned();
        let (rows, more) = fill_page(&mut it, page_rows(budget), PAGE_BYTE_BUDGET);
        AgentPage {
            protocol: self.protocol_descriptor(),
            rows,
            more,
        }
    }

    #[msg]
    async fn system_actor(&self, instance_name: String) -> SystemActorLookup {
        SystemActorLookup {
            protocol: self.protocol_descriptor(),
            row: self
                .schema_ready()
                .then(|| {
                    self.system_actors
                        .iter()
                        .find(|row| row.instance_name == instance_name)
                        .cloned()
                })
                .flatten(),
        }
    }

    #[msg]
    async fn system_actors(&self, after_name: String, budget: u32) -> SystemActorPage {
        if !self.schema_ready() {
            return SystemActorPage {
                protocol: RegistryProtocol::UNSUPPORTED,
                rows: Vec::new(),
                more: false,
            };
        }
        let started = after_name.is_empty();
        let mut it = self
            .system_actors
            .iter()
            .filter(|row| started || row.instance_name.as_str() > after_name.as_str())
            .cloned();
        let (rows, more) = fill_page(&mut it, page_rows(budget), PAGE_BYTE_BUDGET);
        SystemActorPage {
            protocol: self.protocol_descriptor(),
            rows,
            more,
        }
    }

    /// Page installed-agent names (names only), in `instance_name` order —
    /// so cross-actor callers without `AgentRow` schema knowledge (e.g. the
    /// HTTP ingress rendering `/__schema`) pull the list without an rkyv dance.
    /// Same cursor/`more` contract as
    /// [`service_actors`](Self::service_actors).
    #[msg]
    async fn service_actor_names(&self, after_name: String, budget: u32) -> AgentNamePage {
        if !self.schema_ready() {
            return AgentNamePage {
                protocol: RegistryProtocol::UNSUPPORTED,
                names: Vec::new(),
                more: false,
            };
        }
        let started = after_name.is_empty();
        let mut it = self
            .agents
            .iter()
            .filter(|a| started || a.instance_name.as_str() > after_name.as_str())
            .map(|a| a.instance_name.clone());
        let (names, more) = fill_page(&mut it, page_rows(budget), PAGE_BYTE_BUDGET);
        AgentNamePage {
            protocol: self.protocol_descriptor(),
            names,
            more,
        }
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
        if !self.schema_ready() {
            return 0;
        }
        let Ok(caller_prefix) = u16::try_from(caller_prefix) else {
            return 0;
        };
        // 1. Local catalog wins.
        if self.agents.iter().any(|a| a.instance_name == name) {
            return instance_service_id(&name, caller_prefix);
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
    /// Returns `Status::BadPrefix` when `host_prefix` doesn't fit in
    /// a u16. Otherwise `Status::Ok`.
    #[msg]
    async fn register_remote(
        &mut self,
        instance_name: String,
        host_prefix: u32,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op(
            "register_remote",
            &[instance_name.as_bytes(), &host_prefix.to_le_bytes()],
            &auth,
        ) {
            return Status::Forbidden;
        }
        if host_prefix > u16::MAX as u32 {
            return Status::BadPrefix;
        }
        // An empty name is not resolvable — and it is the
        // host_mappings() pager's start-of-table sentinel, so a row
        // carrying it would wedge every drain that follows the
        // documented cursor protocol.
        if !is_canonical_registry_slug(&instance_name) {
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
        if !self.schema_ready() {
            return HostMappingPage {
                mappings: Vec::new(),
                more: false,
            };
        }
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
    #[msg]
    async fn add_node(&mut self, prefix: u32, peer_id: Vec<u8>, role: u8, auth: Vec<u8>) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op(
            "add_node",
            &[&prefix.to_le_bytes(), &peer_id, &[role]],
            &auth,
        ) {
            return Status::Forbidden;
        }
        if prefix > u16::MAX as u32
            || ed25519_pubkey_from_peer_id(&peer_id).is_none()
            || (role != NODE_ROLE_VOTER && role != NODE_ROLE_OBSERVER)
        {
            return Status::BadHash;
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

    #[msg]
    async fn remove_node(&mut self, prefix: u32, auth: Vec<u8>) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op("remove_node", &[&prefix.to_le_bytes()], &auth) {
            return Status::Forbidden;
        }
        if prefix > u16::MAX as u32 {
            return Status::BadPrefix;
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
    /// `proof_kind` is `PROOF_KIND_MERKLE_INCLUSION` or `PROOF_KIND_ZK`.
    #[msg]
    async fn add_identity(
        &mut self,
        public_key: Vec<u8>,
        proof_kind: u8,
        proof_data: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op(
            "add_identity",
            &[&public_key, &[proof_kind], &proof_data],
            &auth,
        ) {
            return Status::Forbidden;
        }
        // An empty key is not an identity — and defense in depth for
        // the members() pager, whose phase-start sentinel is empty.
        if public_key.is_empty()
            || (proof_kind != PROOF_KIND_MERKLE_INCLUSION && proof_kind != PROOF_KIND_ZK)
        {
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

    #[msg]
    async fn remove_identity(&mut self, public_key: Vec<u8>, auth: Vec<u8>) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op("remove_identity", &[&public_key], &auth) {
            return Status::Forbidden;
        }
        if public_key.is_empty() {
            return Status::BadHash;
        }
        if self.identities.remove(&identity_key(&public_key)) {
            Status::Ok
        } else {
            Status::NotFound
        }
    }

    /// One page of the member roster, nodes (by prefix) before identities
    /// (by key), stitched across the two `#[storage]` maps. Pass
    /// `(0, [])` to start; continue from the returned page's
    /// `(next_kind, next_key)` while `more` is true. `budget` caps the page.
    #[msg]
    async fn members(&self, after_kind: u8, after_key: Vec<u8>, budget: u32) -> MemberPage {
        if !self.schema_ready() {
            return MemberPage {
                members: Vec::new(),
                next_kind: 0,
                next_key: Vec::new(),
                more: false,
            };
        }
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
                    let next_key = page
                        .last()
                        .map(|m| m.prefix.to_be_bytes().to_vec())
                        .unwrap_or_default();
                    MemberPage {
                        members: page,
                        next_kind: MEMBER_KIND_NODE,
                        next_key,
                        more: true,
                    }
                } else {
                    // Nodes drained — the next page starts the identity phase.
                    MemberPage {
                        members: page,
                        next_kind: MEMBER_KIND_IDENTITY,
                        next_key: Vec::new(),
                        more: true,
                    }
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
        let skip: Option<[u8; 32]> = (after_kind == MEMBER_KIND_IDENTITY && after_key.len() == 32)
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
            MemberPage {
                members,
                next_kind: MEMBER_KIND_IDENTITY,
                next_key,
                more: true,
            }
        } else {
            MemberPage {
                members,
                next_kind: 0,
                next_key: Vec::new(),
                more: false,
            }
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
        if !self.schema_ready() {
            return 0;
        }
        let Ok(prefix) = u16::try_from(prefix) else {
            return 0;
        };
        self.nodes
            .get(&prefix)
            .map(|m| m.role.saturating_add(1))
            .unwrap_or(0)
    }

    // ── Auth grants ────────────────────────────────────────────

    /// Canonical-authority counterpart of `grant_role`. It is a distinct
    /// message so captured pre-cutover calls cannot be reinterpreted as
    /// post-cutover evidence. Only the immutable root may author it, and its
    /// exact winning row is bound to the sealed authority incarnation.
    #[msg]
    async fn grant_role(
        &mut self,
        peer_id: Vec<u8>,
        role: u8,
        epoch: u64,
        authority_replication_id: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        let Some(authority) = bytes_to_32(&authority_replication_id) else {
            return Status::BadHash;
        };
        if ed25519_pubkey_from_peer_id(&peer_id).is_none() || !is_grantable_auth_role(role) {
            return Status::BadHash;
        }
        if self.role_authority_id() != Some(authority)
            || !self.authorize_root_op(
                "grant_role",
                &[&peer_id, &[role], &epoch.to_le_bytes(), &authority],
                &auth,
            )
        {
            return Status::Forbidden;
        }
        let root = self.root_bytes();
        let Some(row) = self.store_role_grant(peer_id, role, epoch, root) else {
            return Status::Forbidden;
        };
        if row.role == role && row.epoch == epoch && row.grantor == self.root_bytes() {
            self.bind_authority_grant(authority, &row);
        }
        Status::Ok
    }

    #[msg]
    async fn revoke_role(
        &mut self,
        peer_id: Vec<u8>,
        epoch: u64,
        authority_replication_id: Vec<u8>,
        auth: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        let Some(authority) = bytes_to_32(&authority_replication_id) else {
            return Status::BadHash;
        };
        if ed25519_pubkey_from_peer_id(&peer_id).is_none() {
            return Status::BadHash;
        }
        if self.role_authority_id() != Some(authority)
            || !self.authorize_root_op(
                "revoke_role",
                &[&peer_id, &epoch.to_le_bytes(), &authority],
                &auth,
            )
        {
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
        if !self.schema_ready() {
            return AUTH_ROLE_NONE;
        }
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
        if !self.schema_ready() {
            return 0;
        }
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
        if !self.schema_ready() {
            return AuthGrantPage {
                grants: Vec::new(),
                next: Vec::new(),
            };
        }
        let skip = (!after_peer.is_empty()).then(|| peer_key(&after_peer));
        let start = skip.unwrap_or([0u8; 32]);
        let mut raw = self
            .auth_grants
            .iter_from(&start)
            .filter(move |(k, _)| skip != Some(*k))
            .map(|(_, g)| g);
        let (page, more) = fill_page(
            &mut raw,
            page_rows(budget).min(ROLE_PAGE_MAX_ROWS),
            PAGE_BYTE_BUDGET,
        );
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
    ///     `[space_id, [role], expires_le, token_pub,
    ///     authority_replication_id]`) under
    ///     `admin_peer_id`, which must itself be a current-epoch
    ///     effective admin — the delegated-grant chain admin→token→node,
    ///  4. the token isn't revoked (a grow-only flag on the row).
    ///
    /// The invite names its minting admin (`admin_peer_id`) so the
    /// signature is verified in O(1) against a known key rather than by
    /// scanning the grant table; a lie there fails `verify_op_sig` or
    /// `is_effective_admin`, so it can't escalate. The mandatory signed
    /// authority marker must equal the guest-owned cutover barrier, preventing
    /// replica-local catalog absence from selecting registry-only completion.
    /// No expiry check happens here —
    /// expiry is checked once, host-side, at admission
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
        authority_replication_id: Vec<u8>,
        admin_peer_id: Vec<u8>,
        admin_sig: Vec<u8>,
        peer_id: Vec<u8>,
        redeem_sig: Vec<u8>,
        node_sig: Vec<u8>,
        authority_attestation: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        let Some(token_pub_key) = bytes_to_32(&token_pub) else {
            return Status::BadHash;
        };
        if ed25519_pubkey_from_peer_id(&peer_id).is_none()
            || ed25519_pubkey_from_peer_id(&admin_peer_id).is_none()
        {
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
        if !is_defined_auth_role(role) {
            return Status::BadHash;
        }
        if !is_offline_invite_role(role) {
            return Status::Forbidden;
        }
        let Some(space_id) = self.anchored_space_id() else {
            return Status::Forbidden;
        };
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
        let redeem_canon =
            registry_mutation_signed_bytes(&space_id, "redeem_invite", &[&token_pub, &peer_id]);
        if !verify_raw_sig(&token_pub_key, &redeem_canon, &redeem_sig)
            || !verify_op_sig(&peer_id, &redeem_canon, &node_sig)
        {
            return Status::Forbidden;
        }
        // (3) Admin minting: admin_sig over the invite canonical under a
        // current-epoch effective admin. The canonical binds THIS space's
        // `space_id` — anchored authoritatively in the actor
        // (`self.space_id_bytes()`), never a caller-supplied value — so an
        // invite minted for another space cannot be replayed here even
        // when its minter is an effective admin of both. The genesis root
        // alone can't distinguish two spaces one operator runs (it is the
        // shared operator identity); `space_id` (a fresh per-space genesis
        // origin) can, so a mismatched space rebuilds a different canonical
        // and the signature fails.
        let Some(authority_replication_id) = bytes_to_32(&authority_replication_id) else {
            return Status::BadHash;
        };
        if self.role_authority_id() != Some(authority_replication_id) {
            return Status::Forbidden;
        }
        // The root host adds this signature only after the canonical Raft
        // authority has durably returned `true` for the exact redemption.
        // It is recorded in the CRDT message, so every replay verifies the
        // same attestation without consulting a node-local availability set.
        if !self.authorize_root_op(
            "attest_role_authority_invite",
            &[
                &authority_replication_id,
                &token_pub,
                &[role],
                &expires_at.to_le_bytes(),
                &admin_peer_id,
                &admin_sig,
                &peer_id,
                &redeem_sig,
                &node_sig,
            ],
            &authority_attestation,
        ) {
            return Status::Forbidden;
        }
        let invite_canon = invite_signed_bytes(
            &space_id,
            role,
            expires_at,
            &token_pub_key,
            &authority_replication_id,
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
        let Some(grant) = self.store_role_grant(peer_id, role, epoch, admin_peer_id.clone()) else {
            return Status::Forbidden;
        };
        if grant.role == role && grant.epoch == epoch && grant.grantor == admin_peer_id {
            self.bind_authority_grant(authority_replication_id, &grant);
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
    #[msg]
    async fn revoke_invite(&mut self, token_pub: Vec<u8>, auth: Vec<u8>) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !self.authorize_op("revoke_invite", &[&token_pub], &auth) {
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
        if !self.schema_ready() {
            return InvitePage {
                invites: Vec::new(),
                next: Vec::new(),
            };
        }
        let skip = bytes_to_32(&after);
        let start = skip.unwrap_or([0u8; 32]);
        let mut it = self
            .invites
            .iter_from(&start)
            .filter(move |(k, _)| skip != Some(*k))
            .map(|(_, r)| r);
        let (page, more) = fill_page(&mut it, page_rows(budget), PAGE_BYTE_BUDGET);
        let next = if more {
            page.last()
                .map(|r| r.token_pub.to_vec())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        InvitePage {
            invites: page,
            next,
        }
    }
}

// ── Signed-op authorization ────────────────────────────────────────
//
// Kept out of the `#[messages]` impl so it stays a plain helper, not
// a dispatchable handler.
impl SpaceRegistry {
    fn store_role_grant(
        &mut self,
        peer_id: Vec<u8>,
        role: u8,
        epoch: u64,
        grantor: Vec<u8>,
    ) -> Option<AuthGrantRow> {
        let key = peer_key(&peer_id);
        let supersedes = match self.auth_grants.get(&key) {
            Some(cur) => role_grant_supersedes(
                epoch,
                &grantor,
                role,
                cur.epoch,
                &cur.grantor,
                cur.role,
                &self.root_bytes(),
            ),
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
        self.auth_grants.get(&key)
    }

    fn role_authority_id(&self) -> Option<[u8; 32]> {
        self.role_authority.get().filter(|id| *id != [0; 32])
    }

    fn bind_authority_grant(&mut self, authority: [u8; 32], row: &AuthGrantRow) {
        if self.role_authority_id() != Some(authority) {
            return;
        }
        let peer = peer_key(&row.peer_id);
        let key = role_authority_grant_witness_key(authority, peer);
        let binding = role_authority_grant_binding(authority, row);
        self.authority_grant_witnesses.insert(&key, &binding);
    }

    fn authority_grant_is_bound(&self, authority: [u8; 32], row: &AuthGrantRow) -> bool {
        let peer = peer_key(&row.peer_id);
        let key = role_authority_grant_witness_key(authority, peer);
        let expected = role_authority_grant_binding(authority, row);
        self.authority_grant_witnesses.get(&key) == Some(expected)
    }

    /// Authorize a mutation: the `auth` blob's signature must be valid
    /// for the exact anchored-space canonical preimage, AND the
    /// signer must be an *effective* admin — the genesis root, or a
    /// peer whose grant chain bottoms out at the root and is not
    /// dominated by a revoke (see [`effective_role`](Self::effective_role)).
    ///
    /// This runs at handler time on both live dispatch and causal replay. A forged op merged
    /// via CRDT — a fabricated AuthGrantRow{ADMIN} or MemberRow{VOTER}
    /// — is refused on each honest node unless it carries a signature
    /// an admin (or the root) actually produced.
    ///
    /// `effective_role` is computed on demand from the stored grant graph and
    /// grow-only revoke high-waters, never from a cached "is admin" flag.
    /// This signature check is defense in depth, not immutable finality:
    /// replay must eventually consume an authority-certified catalog receipt
    /// rather than reinterpret an author's historical signature against the
    /// current grant graph.
    fn authorize_op(&self, op: &str, fields: &[&[u8]], auth: &[u8]) -> bool {
        if !self.schema_ready() {
            return false;
        }
        let Some(space_id) = self.anchored_space_id() else {
            return false;
        };
        let Some((signer, sig)) = unpack_auth(auth) else {
            return false;
        };
        let canonical = registry_mutation_signed_bytes(&space_id, op, fields);
        if !verify_op_sig(signer, &canonical, &sig) {
            return false;
        }
        self.is_effective_admin(signer)
    }

    fn authorize_root_op(&self, op: &str, fields: &[&[u8]], auth: &[u8]) -> bool {
        if !self.schema_ready() {
            return false;
        }
        let Some(space_id) = self.anchored_space_id() else {
            return false;
        };
        let root = self.root_bytes();
        let Some((signer, signature)) = unpack_auth(auth) else {
            return false;
        };
        let canonical = registry_mutation_signed_bytes(&space_id, op, fields);
        !root.is_empty() && signer == root && verify_op_sig(signer, &canonical, &signature)
    }

    /// The anchored genesis root PeerId, or empty before genesis.
    /// A point read; the dispatch read-cache makes repeated calls
    /// (one per delegation-chain hop) cost a single row.
    fn root_bytes(&self) -> Vec<u8> {
        self.root
            .get()
            .and_then(|stored| decode_registry_root(&stored).map(<[u8]>::to_vec))
            .unwrap_or_default()
    }

    fn schema_ready(&self) -> bool {
        self.root
            .get()
            .is_some_and(|stored| decode_registry_root(&stored).is_some())
    }

    fn protocol_descriptor(&self) -> RegistryProtocol {
        if self.schema_ready() {
            RegistryProtocol::CURRENT
        } else {
            RegistryProtocol::UNSUPPORTED
        }
    }

    fn publish_program_cas(
        &mut self,
        name: String,
        hash: Vec<u8>,
        kind: ProgramKind,
        publication_id: Vec<u8>,
        expected_publication_id: Vec<u8>,
        expected_hash: Vec<u8>,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        let Some(space_id) = self.anchored_space_id() else {
            return Status::ProtocolMismatch;
        };
        if !is_canonical_registry_slug(&name) {
            return Status::BadHash;
        }
        let Some(hash) = nonzero_32(&hash) else {
            return Status::BadHash;
        };
        let Some(publication_id) = nonzero_32(&publication_id) else {
            return Status::BadHash;
        };
        let Ok(expected) = decode_optional_program_tag(&expected_publication_id, &expected_hash)
        else {
            return Status::BadHash;
        };
        let preimage_binding = publication_cas_preimage_binding(
            &space_id,
            &name,
            &hash,
            &kind,
            &publication_id,
            &expected_publication_id,
            &expected_hash,
        );
        let position = self
            .programs
            .binary_search_by(|row| row.name.as_str().cmp(&name));
        if let Ok(idx) = position {
            let current = &self.programs[idx];
            if current.hash == hash
                && current.publication_id.as_bytes() == &publication_id
                && &current.kind == &kind
            {
                return match self.used_publication_ids.get(&publication_id) {
                    Some(binding) if binding == preimage_binding => Status::Ok,
                    Some(_) => Status::PublicationIdReused,
                    None => Status::ProtocolMismatch,
                };
            }
        }
        if self.used_publication_ids.get(&publication_id).is_some() {
            return Status::PublicationIdReused;
        }
        // Consume a valid signed operation identity before evaluating its CAS
        // precondition. A losing publication must never become latent work
        // that succeeds after a later absent/present cycle.
        self.used_publication_ids
            .insert(&publication_id, &preimage_binding);
        let idx = match position {
            Ok(idx) => {
                let current = &self.programs[idx];
                if let Err(status) =
                    validate_catalog_precondition(Some(current), expected, ProgramClass::of(&kind))
                {
                    return status;
                }
                idx
            }
            Err(idx) => {
                if let Err(status) =
                    validate_catalog_precondition(None, expected, ProgramClass::of(&kind))
                {
                    return status;
                }
                idx
            }
        };
        self.authorized_program_hashes.insert(&hash);
        let row = ProgramRow {
            name,
            hash,
            publication_id: PublicationId::new(publication_id),
            kind,
        };
        if idx < self.programs.len() && self.programs[idx].name == row.name {
            self.programs[idx] = row;
        } else {
            self.programs.insert(idx, row);
        }
        Status::Ok
    }

    fn unpublish_program_cas(
        &mut self,
        name: &str,
        expected_publication_id: &[u8],
        expected_hash: &[u8],
        class: ProgramClass,
    ) -> Status {
        if !self.schema_ready() {
            return Status::ProtocolMismatch;
        }
        if !is_canonical_registry_slug(name) {
            return Status::BadHash;
        }
        let Ok(Some(expected)) =
            decode_optional_program_tag(expected_publication_id, expected_hash)
        else {
            return Status::BadHash;
        };
        let Ok(idx) = self
            .programs
            .binary_search_by(|row| row.name.as_str().cmp(name))
        else {
            return Status::NotFound;
        };
        let row = &self.programs[idx];
        if !program_kind_matches(&row.kind, class) {
            return Status::ProgramKindMismatch;
        }
        if row.tag() != expected {
            return Status::StaleCatalog;
        }
        let in_use = match class {
            ProgramClass::Service => self.agents.iter().any(|agent| {
                agent.program_hash == row.hash && agent.program_publication_id == row.publication_id
            }),
            ProgramClass::AgentActor => self.system_actors.iter().any(|actor| {
                actor.program_hash == row.hash && actor.program_publication_id == row.publication_id
            }),
        };
        if in_use {
            return Status::InUse;
        }
        self.programs.remove(idx);
        Status::Ok
    }

    /// This space's anchored `space_id`, or empty before it is set.
    fn space_id_bytes(&self) -> Vec<u8> {
        self.space_id.get().unwrap_or_default()
    }

    fn anchored_space_id(&self) -> Option<[u8; 32]> {
        nonzero_32(&self.space_id_bytes())
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

    /// Effective current space-level role of `peer_id`, resolving revoke-
    /// dominance and delegation across the merged grant state. A stored grant
    /// counts only if its epoch is strictly above the peer's grow-only
    /// revoke high-water AND its `grantor` is itself effective (the
    /// genesis root, or a transitively-effective admin). Computed on
    /// demand — never cached — so a revoke that merges in after the
    /// grants it dominates (including a forged node ground to sort
    /// before its own revoke during replay) retroactively voids the
    /// whole delegation subtree.
    fn effective_role(&self, peer_id: &[u8]) -> u8 {
        let root = self.root_bytes();
        if !root.is_empty() && root.as_slice() == peer_id {
            return AUTH_ROLE_ADMIN;
        }
        let Some(authority) = self.role_authority_id() else {
            return AUTH_ROLE_NONE;
        };
        // The peer's own grant carries the candidate result; the walk
        // below decides whether it counts.
        let Some(first) = self.auth_grants.get(&peer_key(peer_id)) else {
            return AUTH_ROLE_NONE;
        };
        if first.epoch <= self.revoke_floor(peer_id) {
            return AUTH_ROLE_NONE;
        }
        let role = first.role;
        if !self.authority_grant_is_bound(authority, &first) {
            return AUTH_ROLE_NONE;
        }
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
            if !self.authority_grant_is_bound(authority, &row) {
                return AUTH_ROLE_NONE;
            }
            grantor = row.grantor;
            hops += 1;
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────

const REGISTRY_ROOT_MAGIC: &[u8; 8] = b"VOSREG2\0";
const REGISTRY_ROOT_HEADER_BYTES: usize =
    REGISTRY_ROOT_MAGIC.len() + core::mem::size_of::<u32>() + REGISTRY_SCHEMA_HASH.len();

fn encode_registry_root(root: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(REGISTRY_ROOT_HEADER_BYTES + root.len());
    encoded.extend_from_slice(REGISTRY_ROOT_MAGIC);
    encoded.extend_from_slice(&REGISTRY_SCHEMA_VERSION.to_le_bytes());
    encoded.extend_from_slice(&REGISTRY_SCHEMA_HASH);
    encoded.extend_from_slice(root);
    encoded
}

fn decode_registry_root(stored: &[u8]) -> Option<&[u8]> {
    if stored.len() <= REGISTRY_ROOT_HEADER_BYTES
        || &stored[..REGISTRY_ROOT_MAGIC.len()] != REGISTRY_ROOT_MAGIC
        || stored[REGISTRY_ROOT_MAGIC.len()..REGISTRY_ROOT_MAGIC.len() + 4]
            != REGISTRY_SCHEMA_VERSION.to_le_bytes()
        || stored[REGISTRY_ROOT_MAGIC.len() + 4..REGISTRY_ROOT_HEADER_BYTES] != REGISTRY_SCHEMA_HASH
    {
        return None;
    }
    Some(&stored[REGISTRY_ROOT_HEADER_BYTES..])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProgramClass {
    Service,
    AgentActor,
}

impl ProgramClass {
    fn of(kind: &ProgramKind) -> Self {
        match kind {
            ProgramKind::Service { .. } => Self::Service,
            ProgramKind::AgentActor => Self::AgentActor,
        }
    }
}

fn program_kind_matches(kind: &ProgramKind, class: ProgramClass) -> bool {
    matches!(
        (kind, class),
        (ProgramKind::Service { .. }, ProgramClass::Service)
            | (ProgramKind::AgentActor, ProgramClass::AgentActor)
    )
}

/// Durable identity of the complete canonical bytes authorized for one
/// publication attempt. `publication_id` alone prevents reuse across names,
/// while this binding makes the successful idempotency shortcut exact over
/// the original CAS base as well as the resulting row.
fn publication_cas_preimage_binding(
    space_id: &[u8; 32],
    name: &str,
    hash: &[u8; 32],
    kind: &ProgramKind,
    publication_id: &[u8; 32],
    expected_publication_id: &[u8],
    expected_hash: &[u8],
) -> [u8; 32] {
    let canonical = match kind {
        ProgramKind::Service { crdt } => publish_service_program_signed_bytes(
            space_id,
            name,
            hash,
            *crdt,
            publication_id,
            expected_publication_id,
            expected_hash,
        ),
        ProgramKind::AgentActor => publish_agent_actor_program_signed_bytes(
            space_id,
            name,
            hash,
            publication_id,
            expected_publication_id,
            expected_hash,
        ),
    };
    vos::crypto::blake2b_hash::<32>(b"space-registry/publication-cas-preimage", &[&canonical])
}

fn validate_catalog_precondition(
    current: Option<&ProgramRow>,
    expected: Option<ProgramTag>,
    class: ProgramClass,
) -> core::result::Result<(), Status> {
    match current {
        Some(row) if !program_kind_matches(&row.kind, class) => Err(Status::ProgramKindMismatch),
        Some(row) if expected != Some(row.tag()) => Err(Status::StaleCatalog),
        None if expected.is_some() => Err(Status::StaleCatalog),
        _ => Ok(()),
    }
}

fn valid_system_actor_install_receipt(receipt: &SystemActorInstallReceipt) -> bool {
    receipt.protocol.is_current()
        && receipt.installation_id != InstallationId::ZERO
        && receipt.system_agent_id != AgentId::ZERO
        && receipt.actor_id != ActorId::ZERO
        && is_canonical_registry_slug(&receipt.instance_name)
        && is_canonical_registry_slug(&receipt.program_name)
        && !receipt.host_receipt.is_empty()
        && receipt.actor_id == ActorId::top_level(receipt.system_agent_id, &receipt.instance_name)
}

fn next_installation_revision(
    installation_id: InstallationId,
    revision: u64,
    program: ProgramTag,
    expected_installation_id: [u8; 32],
    expected_revision: u64,
    expected_program: ProgramTag,
) -> core::result::Result<u64, Status> {
    validate_installation_precondition(
        installation_id,
        revision,
        program,
        expected_installation_id,
        expected_revision,
        expected_program,
    )?;
    revision.checked_add(1).ok_or(Status::StaleInstallation)
}

fn validate_installation_precondition(
    installation_id: InstallationId,
    revision: u64,
    program: ProgramTag,
    expected_installation_id: [u8; 32],
    expected_revision: u64,
    expected_program: ProgramTag,
) -> core::result::Result<(), Status> {
    if installation_id.as_bytes() != &expected_installation_id
        || revision != expected_revision
        || program != expected_program
    {
        return Err(Status::StaleInstallation);
    }
    Ok(())
}

fn decode_optional_program_tag(
    publication_id: &[u8],
    hash: &[u8],
) -> core::result::Result<Option<ProgramTag>, ()> {
    if publication_id.is_empty() && hash.is_empty() {
        return Ok(None);
    }
    let publication_id = nonzero_32(publication_id).ok_or(())?;
    let hash = nonzero_32(hash).ok_or(())?;
    Ok(Some(ProgramTag {
        publication_id: PublicationId::new(publication_id),
        hash,
    }))
}

fn bytes_to_32(b: &[u8]) -> Option<[u8; 32]> {
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Some(out)
}

fn nonzero_32(b: &[u8]) -> Option<[u8; 32]> {
    bytes_to_32(b).filter(|bytes| *bytes != [0; 32])
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
    vos::crypto::blake2b_hash::<32>(b"space-registry/name-key", &[name.as_bytes()])
}

/// Fixed-width `StorageMap` key for a variable-length peer id. One grant
/// row per peer, so this is the whole key. Ordered iteration is by hashed
/// key, not peer id — no consumer depends on peer order (grants are point
/// looked-up in `effective_role`; the list handler pages).
fn peer_key(peer_id: &[u8]) -> [u8; 32] {
    vos::crypto::blake2b_hash::<32>(b"space-registry/peer-key", &[peer_id])
}

fn role_authority_grant_binding(authority: [u8; 32], row: &AuthGrantRow) -> [u8; 32] {
    vos::crypto::blake2b_hash::<32>(
        b"space-registry/role-authority-grant/service",
        &[
            &authority,
            &row.peer_id,
            &[row.role],
            &row.epoch.to_le_bytes(),
            &row.grantor,
        ],
    )
}

fn role_authority_grant_witness_key(authority: [u8; 32], peer: [u8; 32]) -> [u8; 32] {
    vos::crypto::blake2b_hash::<32>(
        b"space-registry/role-authority-grant-witness",
        &[&authority, &peer],
    )
}

/// Fixed-width `StorageMap` key for an Identity member's variable-length
/// public key. Nodes key directly by their `u16` prefix (order-preserving);
/// only identities need folding.
fn identity_key(public_key: &[u8]) -> [u8; 32] {
    vos::crypto::blake2b_hash::<32>(b"space-registry/identity-key", &[public_key])
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

// ── Signed registry ops ──────────────────────────────────
//
// The authority-critical mutations — the auth-grant table
// (`grant_role`/`revoke_role`)
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
// the CLI, and by the daemon's explicit boot/reconcile caller). Authority is anchored at the
// genesis `set_root` and delegates through the already-verified
// `auth_grants` table — see [`SpaceRegistry::authorize_op`].
//
// The class-specific program/installation CATALOG mutators carry the same
// `auth` blob, closing the
// catalog-forgery vector (a forged AgentRow/ProgramRow merged via CRDT
// that drives every peer's reconcile to spawn an agent). They are
// authored either by the one-shot CLI before network dispatch or by the
// daemon's explicit in-process boot/reconcile call. The network host binds
// the embedded signer to its authenticated ingress identity without changing
// the payload. A keyless PVM actor cannot borrow ambient daemon authority and
// its empty/forged authorization is refused. Because the signature is the
// actual caller's, `authorize_op` passes on an admin node and fails for a
// joined non-admin node — which is correct:
// a non-admin never authors a catalog row, it consumes the admin's
// already-signed rows via sync, and the reconcile path tolerates the
// resulting Status::Forbidden. `register_remote` is subject to the same
// anchored-space authorization. A federation registry without a durable
// root/space anchor therefore rejects advertisements rather than accepting an
// unauthenticated mapping.

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
    #[cfg(feature = "bin")]
    use crate::__vos_worker::{
        vos_extension_create, vos_extension_drop, vos_extension_free, vos_extension_load,
        vos_extension_state_v2,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use vos::Message;
    use vos::abi::service::ServiceId;
    use vos::value::FromDynamic as _;

    const TEST_SPACE_ID: [u8; 32] = [0xa5; 32];

    fn dispatch<M>(
        registry: &mut SpaceRegistry,
        message: M,
    ) -> <SpaceRegistry as Message<M>>::Output
    where
        SpaceRegistry: Message<M>,
    {
        let mut context = Context::new(ServiceId(0));
        vos::block_on(<SpaceRegistry as Message<M>>::handle(
            registry,
            message,
            &mut context,
        ))
    }

    fn root_peer(signing: &SigningKey) -> Vec<u8> {
        let mut peer = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
        peer.extend_from_slice(signing.verifying_key().as_bytes());
        peer
    }

    fn root_auth(signing: &SigningKey, canonical: &[u8]) -> Vec<u8> {
        pack_auth(&root_peer(signing), &signing.sign(canonical).to_bytes())
    }

    fn anchor_test_space(registry: &mut SpaceRegistry, prefix: &'static [u8]) {
        registry.space_id.__init(prefix);
        registry.space_id.set(&TEST_SPACE_ID.to_vec());
    }

    #[allow(clippy::too_many_arguments)]
    fn install_service_for_test(
        registry: &mut SpaceRegistry,
        signing: &SigningKey,
        instance_name: &str,
        program_name: &str,
        program: ProgramTag,
        installation_id: [u8; 32],
        replication_id: [u8; 32],
    ) -> Status {
        install_service_with_consistency_for_test(
            registry,
            signing,
            instance_name,
            program_name,
            program,
            installation_id,
            replication_id,
            1,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn install_service_with_consistency_for_test(
        registry: &mut SpaceRegistry,
        signing: &SigningKey,
        instance_name: &str,
        program_name: &str,
        program: ProgramTag,
        installation_id: [u8; 32],
        replication_id: [u8; 32],
        consistency: u8,
    ) -> Status {
        let network_reachable = false;
        let sync_role = SyncFloor::Member as u8;
        let canonical = install_service_actor_signed_bytes(
            &registry.anchored_space_id().expect("test space anchor"),
            instance_name,
            program_name,
            &program.hash,
            program.publication_id.as_bytes(),
            &installation_id,
            &replication_id,
            consistency,
            network_reachable,
            sync_role,
        );
        dispatch(
            registry,
            InstallServiceActor {
                instance_name: instance_name.into(),
                program_name: program_name.into(),
                program_hash: program.hash.to_vec(),
                program_publication_id: program.publication_id.as_bytes().to_vec(),
                installation_id: installation_id.to_vec(),
                replication_id: replication_id.to_vec(),
                consistency,
                network_reachable,
                sync_role,
                auth: root_auth(signing, &canonical),
            },
        )
    }

    #[test]
    fn v1_registry_read_verbs_are_absent() {
        for method in [
            "program",
            "program_by_hash",
            "programs",
            "agent",
            "agent_by_pattern",
            "agents",
            "agent_names",
        ] {
            assert!(
                SpaceRegistryMsg::from_dynamic(&Msg::new(method)).is_none(),
                "legacy read verb {method} must fail closed",
            );
        }
    }

    #[test]
    fn consistency_can_only_narrow() {
        assert!(may_transition_to(2, 1));
        assert!(may_transition_to(3, 2));
        assert!(!may_transition_to(1, 2));
        assert!(!may_transition_to(0, 1));
    }

    #[test]
    fn malformed_hashes_are_rejected() {
        assert_eq!(bytes_to_32(&[7; 32]), Some([7; 32]));
        assert_eq!(bytes_to_32(&[7; 31]), None);
    }

    #[test]
    fn page_budget_is_bounded() {
        assert_eq!(page_rows(0), PAGE_MAX_ROWS);
        assert_eq!(page_rows(1), 1);
        assert_eq!(page_rows(u32::MAX), PAGE_MAX_ROWS);
    }

    fn program(kind: ProgramKind, publication: u8, hash: u8) -> ProgramRow {
        ProgramRow {
            name: "program".into(),
            hash: [hash; 32],
            publication_id: PublicationId::new([publication; 32]),
            kind,
        }
    }

    #[test]
    fn catalog_cas_binds_kind_hash_and_generation() {
        let current = program(ProgramKind::Service { crdt: true }, 1, 7);
        assert_eq!(
            validate_catalog_precondition(
                Some(&current),
                Some(current.tag()),
                ProgramClass::Service,
            ),
            Ok(())
        );
        assert_eq!(
            validate_catalog_precondition(Some(&current), None, ProgramClass::Service),
            Err(Status::StaleCatalog),
        );
        // Same hash after an A -> B -> A cycle is not the same tag generation.
        assert_eq!(
            validate_catalog_precondition(
                Some(&current),
                Some(ProgramTag {
                    publication_id: PublicationId::new([2; 32]),
                    hash: current.hash,
                }),
                ProgramClass::Service,
            ),
            Err(Status::StaleCatalog),
        );
        assert_eq!(
            validate_catalog_precondition(
                Some(&current),
                Some(current.tag()),
                ProgramClass::AgentActor,
            ),
            Err(Status::ProgramKindMismatch),
        );
        assert_eq!(
            validate_catalog_precondition(None, Some(current.tag()), ProgramClass::Service),
            Err(Status::StaleCatalog),
        );
        assert_eq!(
            validate_catalog_precondition(None, None, ProgramClass::Service),
            Ok(()),
        );
    }

    #[test]
    fn expected_tag_wire_rejects_partial_zero_or_drifted_shapes() {
        assert_eq!(decode_optional_program_tag(&[], &[]), Ok(None));
        assert!(decode_optional_program_tag(&[1; 32], &[]).is_err());
        assert!(decode_optional_program_tag(&[], &[1; 32]).is_err());
        assert!(decode_optional_program_tag(&[0; 32], &[1; 32]).is_err());
        assert!(decode_optional_program_tag(&[1; 32], &[0; 32]).is_err());
        assert!(decode_optional_program_tag(&[1; 31], &[2; 32]).is_err());
    }

    #[test]
    fn live_installation_cas_rejects_replayed_revision_after_aba() {
        let installation_id = InstallationId::new([3; 32]);
        let program = ProgramTag {
            publication_id: PublicationId::new([4; 32]),
            hash: [5; 32],
        };
        assert_eq!(
            next_installation_revision(installation_id, 0, program, [3; 32], 0, program,),
            Ok(1),
        );
        // Even if a later upgrade returns to this exact named program tag,
        // the captured revision-zero signature can no longer apply.
        assert_eq!(
            next_installation_revision(installation_id, 2, program, [3; 32], 0, program,),
            Err(Status::StaleInstallation),
        );
        assert_eq!(
            next_installation_revision(
                installation_id,
                u64::MAX,
                program,
                [3; 32],
                u64::MAX,
                program,
            ),
            Err(Status::StaleInstallation),
        );
    }

    #[test]
    fn v2_root_envelope_rejects_old_or_drifted_archives() {
        let root = [0x42; 38];
        assert!(
            decode_registry_root(&root).is_none(),
            "raw v1 root must fail closed"
        );
        let encoded = encode_registry_root(&root);
        assert_eq!(decode_registry_root(&encoded), Some(root.as_slice()));

        let mut wrong_version = encoded.clone();
        wrong_version[REGISTRY_ROOT_MAGIC.len()] ^= 1;
        assert!(decode_registry_root(&wrong_version).is_none());
        let mut wrong_schema = encoded;
        wrong_schema[REGISTRY_ROOT_MAGIC.len() + 4] ^= 1;
        assert!(decode_registry_root(&wrong_schema).is_none());
        assert!(decode_registry_root(&wrong_schema[..REGISTRY_ROOT_HEADER_BYTES]).is_none());

        assert_eq!(<SpaceRegistry as vos::Actor>::STATE_SCHEMA_VERSION, 2);
        assert_ne!(<SpaceRegistry as vos::Actor>::STATE_SCHEMA_FINGERPRINT, 0);
    }

    #[test]
    fn set_root_requires_current_schema_identity_on_wire() {
        let signing = SigningKey::from_bytes(&[0x2e; 32]);
        let root = root_peer(&signing);

        let historical = Msg::new("set_root").with("root", root.clone());
        assert!(
            SpaceRegistryMsg::from_dynamic(&historical).is_none(),
            "the historical one-argument v1 wire must not decode as current genesis",
        );
        let current = Msg::new("set_root")
            .with("root", root.clone())
            .with("schema_version", REGISTRY_SCHEMA_VERSION)
            .with("schema_hash", REGISTRY_SCHEMA_HASH.to_vec());
        assert!(SpaceRegistryMsg::from_dynamic(&current).is_some());

        let mut registry = SpaceRegistry::new();
        registry.root.__init(b"test/versioned-set-root/root/");
        let mut oversized_root = root.clone();
        oversized_root.push(0);
        for malformed_root in [
            Vec::new(),
            vec![0x2f; 38],
            root[..root.len() - 1].to_vec(),
            oversized_root,
        ] {
            assert_eq!(
                dispatch(
                    &mut registry,
                    SetRoot {
                        root: malformed_root,
                        schema_version: REGISTRY_SCHEMA_VERSION,
                        schema_hash: REGISTRY_SCHEMA_HASH.to_vec(),
                    },
                ),
                Status::BadHash,
            );
            assert!(registry.root.get().is_none());
        }
        assert_eq!(
            dispatch(
                &mut registry,
                SetRoot {
                    root: root.clone(),
                    schema_version: REGISTRY_SCHEMA_VERSION - 1,
                    schema_hash: REGISTRY_SCHEMA_HASH.to_vec(),
                },
            ),
            Status::ProtocolMismatch,
        );
        assert!(registry.root.get().is_none());
        let mut wrong_hash = REGISTRY_SCHEMA_HASH;
        wrong_hash[0] ^= 1;
        assert_eq!(
            dispatch(
                &mut registry,
                SetRoot {
                    root: root.clone(),
                    schema_version: REGISTRY_SCHEMA_VERSION,
                    schema_hash: wrong_hash.to_vec(),
                },
            ),
            Status::ProtocolMismatch,
        );
        assert!(registry.root.get().is_none());
        assert_eq!(
            dispatch(
                &mut registry,
                SetRoot {
                    root: root.clone(),
                    schema_version: REGISTRY_SCHEMA_VERSION,
                    schema_hash: REGISTRY_SCHEMA_HASH.to_vec(),
                },
            ),
            Status::Ok,
        );
        assert_eq!(registry.root_bytes(), root);
    }

    #[test]
    fn stale_schema_gates_behavior_reads_and_invite_redemption_before_other_storage() {
        let admin = SigningKey::from_bytes(&[0x31; 32]);
        let mut registry = SpaceRegistry::new();

        // Initialize ONLY the root handle. Every other storage handle remains
        // deliberately unusable, so a read that crosses its schema gate will
        // panic instead of accidentally consulting stale rows. The raw v1 root
        // is nevertheless a valid PeerId so it cannot be mistaken for merely
        // malformed caller data.
        registry.root.__init(b"test/stale-schema/root/");
        registry.root.set(&root_peer(&admin));

        let catalogued = program(ProgramKind::Service { crdt: false }, 0x32, 0x33);
        registry.programs.push(catalogued.clone());
        registry.agents.push(AgentRow {
            instance_name: "stale-service".into(),
            installation_id: InstallationId::new([0x34; 32]),
            revision: 7,
            program_hash: catalogued.hash,
            program_name: catalogued.name.clone(),
            program_publication_id: catalogued.publication_id,
            replication_id: [0x35; 32],
            consistency: 1,
            network_reachable: false,
            sync_role: SyncFloor::Member,
        });
        let system_agent_id = AgentId::new([0x36; 32]);
        registry.system_actors.push(SystemActorRow {
            instance_name: "stale-system".into(),
            installation_id: InstallationId::new([0x37; 32]),
            revision: 9,
            system_agent_id,
            actor_id: ActorId::top_level(system_agent_id, "stale-system"),
            program_hash: [0x38; 32],
            program_name: "stale-agent-program".into(),
            program_publication_id: PublicationId::new([0x39; 32]),
            host_receipt_hash: [0x3a; 32],
        });

        assert_eq!(
            dispatch(&mut registry, Protocol),
            RegistryProtocol::UNSUPPORTED
        );
        assert!(dispatch(&mut registry, Root).is_empty());
        assert!(dispatch(&mut registry, SpaceId).is_empty());
        assert!(dispatch(&mut registry, RoleAuthority).is_empty());

        let lookup = dispatch(
            &mut registry,
            CatalogProgram {
                name: catalogued.name.clone(),
            },
        );
        assert_eq!(lookup.protocol, RegistryProtocol::UNSUPPORTED);
        assert!(lookup.row.is_none());
        let lookup = dispatch(
            &mut registry,
            CatalogProgramByHash {
                hash: catalogued.hash.to_vec(),
            },
        );
        assert_eq!(lookup.protocol, RegistryProtocol::UNSUPPORTED);
        assert!(lookup.row.is_none());
        let authorization = dispatch(
            &mut registry,
            ProgramBlobAuthorized {
                hash: catalogued.hash.to_vec(),
            },
        );
        assert_eq!(authorization.protocol, RegistryProtocol::UNSUPPORTED);
        assert!(!authorization.authorized);
        let page = dispatch(
            &mut registry,
            CatalogPrograms {
                after_name: String::new(),
                budget: 0,
            },
        );
        assert_eq!(page.protocol, RegistryProtocol::UNSUPPORTED);
        assert!(page.rows.is_empty());
        assert!(!page.more);

        assert!(
            dispatch(
                &mut registry,
                MetaForProgram {
                    program_hash: catalogued.hash.to_vec(),
                },
            )
            .is_empty()
        );
        assert!(
            dispatch(
                &mut registry,
                MetaForInstance {
                    name: "stale-service".into(),
                },
            )
            .is_empty()
        );

        let service = dispatch(
            &mut registry,
            ServiceActor {
                instance_name: "stale-service".into(),
            },
        );
        assert_eq!(service.protocol, RegistryProtocol::UNSUPPORTED);
        assert!(service.row.is_none());
        let service = dispatch(
            &mut registry,
            ServiceActorByPattern {
                prefix: "stale".into(),
                suffix: "service".into(),
            },
        );
        assert_eq!(service.protocol, RegistryProtocol::UNSUPPORTED);
        assert!(service.row.is_none());
        let services = dispatch(
            &mut registry,
            ServiceActors {
                after_name: String::new(),
                budget: 0,
            },
        );
        assert_eq!(services.protocol, RegistryProtocol::UNSUPPORTED);
        assert!(services.rows.is_empty());
        assert!(!services.more);
        let names = dispatch(
            &mut registry,
            ServiceActorNames {
                after_name: String::new(),
                budget: 0,
            },
        );
        assert_eq!(names.protocol, RegistryProtocol::UNSUPPORTED);
        assert!(names.names.is_empty());
        assert!(!names.more);

        let system = dispatch(
            &mut registry,
            SystemActor {
                instance_name: "stale-system".into(),
            },
        );
        assert_eq!(system.protocol, RegistryProtocol::UNSUPPORTED);
        assert!(system.row.is_none());
        let systems = dispatch(
            &mut registry,
            SystemActors {
                after_name: String::new(),
                budget: 0,
            },
        );
        assert_eq!(systems.protocol, RegistryProtocol::UNSUPPORTED);
        assert!(systems.rows.is_empty());
        assert!(!systems.more);

        assert_eq!(
            dispatch(
                &mut registry,
                Resolve {
                    name: "stale-service".into(),
                    caller_prefix: 7,
                },
            ),
            0
        );
        let mappings = dispatch(
            &mut registry,
            HostMappings {
                after_name: String::new(),
                budget: 0,
            },
        );
        assert!(mappings.mappings.is_empty());
        assert!(!mappings.more);
        let members = dispatch(
            &mut registry,
            Members {
                after_kind: 0,
                after_key: Vec::new(),
                budget: 0,
            },
        );
        assert!(members.members.is_empty());
        assert!(!members.more);
        assert_eq!(dispatch(&mut registry, NodeRole { prefix: 7 }), 0);
        assert_eq!(
            dispatch(
                &mut registry,
                PeerRole {
                    peer_id: root_peer(&admin),
                },
            ),
            AUTH_ROLE_NONE
        );
        assert_eq!(
            dispatch(
                &mut registry,
                PeerEpoch {
                    peer_id: root_peer(&admin),
                },
            ),
            0
        );
        let grants = dispatch(
            &mut registry,
            AuthGrants {
                after_peer: Vec::new(),
                budget: 0,
            },
        );
        assert!(grants.grants.is_empty());
        assert!(grants.next.is_empty());
        let invites = dispatch(
            &mut registry,
            Invites {
                after: Vec::new(),
                budget: 0,
            },
        );
        assert!(invites.invites.is_empty());
        assert!(invites.next.is_empty());

        // redeem_invite is intentionally role-ungated. Its protocol gate
        // must still run before invite/authority storage is touched. Valid
        // possession signatures ensure that removing/reordering the gate
        // would advance to the deliberately uninitialized `space_id` handle.
        let token = SigningKey::from_bytes(&[0x3b; 32]);
        let joining_node = SigningKey::from_bytes(&[0x3c; 32]);
        let token_pub = token.verifying_key().as_bytes().to_vec();
        let joining_peer = root_peer(&joining_node);
        let redeem = registry_mutation_signed_bytes(
            &TEST_SPACE_ID,
            "redeem_invite",
            &[&token_pub, &joining_peer],
        );
        assert_eq!(
            dispatch(
                &mut registry,
                RedeemInvite {
                    token_pub,
                    role: AUTH_ROLE_READONLY,
                    expires_at: 100,
                    authority_replication_id: vec![0x3d; 32],
                    admin_peer_id: root_peer(&admin),
                    admin_sig: vec![0; OP_SIG_LEN],
                    peer_id: joining_peer,
                    redeem_sig: token.sign(&redeem).to_bytes().to_vec(),
                    node_sig: joining_node.sign(&redeem).to_bytes().to_vec(),
                    authority_attestation: vec![0; OP_SIG_LEN],
                },
            ),
            Status::ProtocolMismatch,
        );
    }

    #[test]
    fn losing_publication_and_install_ids_are_burned_while_live_retries_are_idempotent() {
        let signing = SigningKey::from_bytes(&[0x51; 32]);
        let mut registry = SpaceRegistry::new();
        registry.root.__init(b"test/id-burn/root/");
        registry
            .root
            .set(&encode_registry_root(&root_peer(&signing)));
        anchor_test_space(&mut registry, b"test/id-burn/space/");
        registry
            .used_publication_ids
            .__init(b"test/id-burn/publications/");
        registry
            .authorized_program_hashes
            .__init(b"test/id-burn/blobs/");
        registry
            .used_installation_ids
            .__init(b"test/id-burn/installations/");
        registry
            .used_replication_ids
            .__init(b"test/id-burn/replications/");
        registry
            .consistency_floors
            .__init(b"test/id-burn/consistency/");

        let winner = ProgramTag {
            publication_id: PublicationId::new([0x52; 32]),
            hash: [0x53; 32],
        };
        assert_eq!(
            registry.publish_program_cas(
                "program".into(),
                winner.hash.to_vec(),
                ProgramKind::Service { crdt: false },
                winner.publication_id.as_bytes().to_vec(),
                Vec::new(),
                Vec::new(),
            ),
            Status::Ok,
        );
        assert_eq!(
            registry.publish_program_cas(
                "program".into(),
                winner.hash.to_vec(),
                ProgramKind::Service { crdt: false },
                winner.publication_id.as_bytes().to_vec(),
                Vec::new(),
                Vec::new(),
            ),
            Status::Ok,
            "an exact retry of the live publication is idempotent",
        );
        assert_eq!(
            registry.publish_program_cas(
                "program".into(),
                winner.hash.to_vec(),
                ProgramKind::Service { crdt: false },
                winner.publication_id.as_bytes().to_vec(),
                winner.publication_id.as_bytes().to_vec(),
                winner.hash.to_vec(),
            ),
            Status::PublicationIdReused,
            "the same result with a different signed CAS base is not an exact retry",
        );
        assert_eq!(
            registry.publish_program_cas(
                "program".into(),
                winner.hash.to_vec(),
                ProgramKind::Service { crdt: false },
                winner.publication_id.as_bytes().to_vec(),
                Vec::new(),
                Vec::new(),
            ),
            Status::Ok,
            "a preimage mismatch must not disturb the original retry binding",
        );

        let losing_publication = PublicationId::new([0x54; 32]);
        assert_eq!(
            registry.publish_program_cas(
                "program".into(),
                vec![0x55; 32],
                ProgramKind::Service { crdt: false },
                losing_publication.as_bytes().to_vec(),
                Vec::new(),
                Vec::new(),
            ),
            Status::StaleCatalog,
        );
        assert_eq!(
            registry.unpublish_program_cas(
                "program",
                winner.publication_id.as_bytes(),
                &winner.hash,
                ProgramClass::Service,
            ),
            Status::Ok,
        );
        assert_eq!(
            registry.publish_program_cas(
                "program".into(),
                vec![0x55; 32],
                ProgramKind::Service { crdt: false },
                losing_publication.as_bytes().to_vec(),
                Vec::new(),
                Vec::new(),
            ),
            Status::PublicationIdReused,
            "a losing CAS cannot become latent work after the name is removed",
        );

        let future_program = ProgramTag {
            publication_id: PublicationId::new([0x5d; 32]),
            hash: [0x5e; 32],
        };
        let future_installation = [0x5f; 32];
        let future_replication = [0x60; 32];
        assert_eq!(
            install_service_for_test(
                &mut registry,
                &signing,
                "future-service",
                "future-code",
                future_program,
                future_installation,
                future_replication,
            ),
            Status::ProgramNotFound,
        );
        assert!(
            registry
                .used_installation_ids
                .contains(&future_installation)
        );
        assert!(registry.used_replication_ids.contains(&future_replication));
        assert_eq!(
            registry.publish_program_cas(
                "future-code".into(),
                future_program.hash.to_vec(),
                ProgramKind::Service { crdt: false },
                future_program.publication_id.as_bytes().to_vec(),
                Vec::new(),
                Vec::new(),
            ),
            Status::Ok,
        );
        assert_eq!(
            install_service_for_test(
                &mut registry,
                &signing,
                "future-service",
                "future-code",
                future_program,
                future_installation,
                future_replication,
            ),
            Status::InstallationIdReused,
            "a structurally valid install cannot become latent work after its program appears",
        );
        assert!(
            registry
                .agents
                .iter()
                .all(|row| row.instance_name != "future-service")
        );

        let install_program = ProgramTag {
            publication_id: PublicationId::new([0x56; 32]),
            hash: [0x57; 32],
        };
        assert_eq!(
            registry.publish_program_cas(
                "service-code".into(),
                install_program.hash.to_vec(),
                ProgramKind::Service { crdt: false },
                install_program.publication_id.as_bytes().to_vec(),
                Vec::new(),
                Vec::new(),
            ),
            Status::Ok,
        );
        let crdt_loser_installation = [0x61; 32];
        let crdt_loser_replication = [0x62; 32];
        assert_eq!(
            install_service_with_consistency_for_test(
                &mut registry,
                &signing,
                "crdt-required",
                "service-code",
                install_program,
                crdt_loser_installation,
                crdt_loser_replication,
                2,
            ),
            Status::CrdtOptInRequired,
        );
        assert!(
            registry
                .used_installation_ids
                .contains(&crdt_loser_installation)
        );
        assert!(
            registry
                .used_replication_ids
                .contains(&crdt_loser_replication)
        );
        let winning_installation = [0x58; 32];
        let winning_replication = [0x59; 32];
        assert_eq!(
            install_service_for_test(
                &mut registry,
                &signing,
                "service",
                "service-code",
                install_program,
                winning_installation,
                winning_replication,
            ),
            Status::Ok,
        );
        assert_eq!(
            install_service_for_test(
                &mut registry,
                &signing,
                "service",
                "service-code",
                install_program,
                winning_installation,
                winning_replication,
            ),
            Status::Ok,
            "an exact retry of the live installation is idempotent",
        );

        let losing_installation = [0x5a; 32];
        let losing_replication = [0x5b; 32];
        assert_eq!(
            install_service_for_test(
                &mut registry,
                &signing,
                "service",
                "service-code",
                install_program,
                losing_installation,
                losing_replication,
            ),
            Status::InstanceExists,
        );
        registry.agents.clear();
        assert_eq!(
            install_service_for_test(
                &mut registry,
                &signing,
                "service",
                "service-code",
                install_program,
                losing_installation,
                losing_replication,
            ),
            Status::InstallationIdReused,
            "the losing installation identity remains burned after removal",
        );
        assert_eq!(
            install_service_for_test(
                &mut registry,
                &signing,
                "service",
                "service-code",
                install_program,
                [0x5c; 32],
                losing_replication,
            ),
            Status::ReplicationIdReused,
            "the losing replication identity remains burned after removal",
        );
    }

    #[test]
    fn blob_authorization_retains_successful_history_but_excludes_failed_admission() {
        let mut registry = SpaceRegistry::new();
        registry.root.__init(b"test/blob-history/root/");
        registry.root.set(&encode_registry_root(&[0x61; 38]));
        anchor_test_space(&mut registry, b"test/blob-history/space/");
        registry
            .used_publication_ids
            .__init(b"test/blob-history/publications/");
        registry
            .authorized_program_hashes
            .__init(b"test/blob-history/authorized/");

        let first = ProgramTag {
            publication_id: PublicationId::new([0x62; 32]),
            hash: [0x63; 32],
        };
        let second = ProgramTag {
            publication_id: PublicationId::new([0x64; 32]),
            hash: [0x65; 32],
        };
        assert_eq!(
            registry.publish_program_cas(
                "moving".into(),
                first.hash.to_vec(),
                ProgramKind::AgentActor,
                first.publication_id.as_bytes().to_vec(),
                Vec::new(),
                Vec::new(),
            ),
            Status::Ok,
        );
        assert_eq!(
            registry.publish_program_cas(
                "moving".into(),
                second.hash.to_vec(),
                ProgramKind::AgentActor,
                second.publication_id.as_bytes().to_vec(),
                first.publication_id.as_bytes().to_vec(),
                first.hash.to_vec(),
            ),
            Status::Ok,
        );

        let losing_hash = [0x66; 32];
        assert_eq!(
            registry.publish_program_cas(
                "moving".into(),
                losing_hash.to_vec(),
                ProgramKind::AgentActor,
                vec![0x67; 32],
                first.publication_id.as_bytes().to_vec(),
                first.hash.to_vec(),
            ),
            Status::StaleCatalog,
        );
        let invalid_hash = [0; 32];
        assert_eq!(
            registry.publish_program_cas(
                "invalid".into(),
                invalid_hash.to_vec(),
                ProgramKind::AgentActor,
                vec![0x68; 32],
                Vec::new(),
                Vec::new(),
            ),
            Status::BadHash,
        );
        assert_eq!(
            registry.unpublish_program_cas(
                "moving",
                second.publication_id.as_bytes(),
                &second.hash,
                ProgramClass::AgentActor,
            ),
            Status::Ok,
        );

        for retained in [first.hash, second.hash] {
            let authorization = dispatch(
                &mut registry,
                ProgramBlobAuthorized {
                    hash: retained.to_vec(),
                },
            );
            assert_eq!(authorization.protocol, RegistryProtocol::CURRENT);
            assert!(authorization.authorized);
        }
        for rejected in [losing_hash, invalid_hash] {
            let authorization = dispatch(
                &mut registry,
                ProgramBlobAuthorized {
                    hash: rejected.to_vec(),
                },
            );
            assert_eq!(authorization.protocol, RegistryProtocol::CURRENT);
            assert!(!authorization.authorized);
        }
    }

    #[test]
    fn space_id_rejects_zero_and_noncanonical_lengths() {
        let mut registry = SpaceRegistry::new();
        registry.root.__init(b"test/space-id/root/");
        registry.root.set(&encode_registry_root(&[0x71; 38]));
        registry.space_id.__init(b"test/space-id/value/");

        for invalid in [Vec::new(), vec![0x72; 31], vec![0; 32], vec![0x72; 33]] {
            assert_eq!(
                dispatch(&mut registry, SetSpaceId { space_id: invalid },),
                Status::BadHash,
            );
            assert!(dispatch(&mut registry, SpaceId).is_empty());
        }

        let valid = vec![0x73; 32];
        assert_eq!(
            dispatch(
                &mut registry,
                SetSpaceId {
                    space_id: valid.clone(),
                },
            ),
            Status::Ok,
        );
        assert_eq!(dispatch(&mut registry, SpaceId), valid);
        for replacement in [vec![0x73; 32], vec![0x74; 32]] {
            assert_eq!(
                dispatch(
                    &mut registry,
                    SetSpaceId {
                        space_id: replacement,
                    },
                ),
                Status::Forbidden,
                "the exact first space anchor is immutable",
            );
            assert_eq!(dispatch(&mut registry, SpaceId), vec![0x73; 32]);
        }
    }

    #[test]
    fn signed_mutations_require_the_exact_durable_space_anchor() {
        let signing = SigningKey::from_bytes(&[0x75; 32]);
        let root = encode_registry_root(&root_peer(&signing));
        let space_a = [0x76; 32];
        let space_b = [0x77; 32];
        let prefix = 23u32;
        let node_peer = root_peer(&SigningKey::from_bytes(&[0x78; 32]));
        let canonical = registry_mutation_signed_bytes(
            &space_a,
            "add_node",
            &[&prefix.to_le_bytes(), &node_peer, &[NODE_ROLE_VOTER]],
        );
        let auth = root_auth(&signing, &canonical);

        let mut unanchored = SpaceRegistry::new();
        unanchored.root.__init(b"test/scoped-auth/unanchored/root/");
        unanchored.root.set(&root);
        unanchored
            .space_id
            .__init(b"test/scoped-auth/unanchored/space/");
        unanchored
            .nodes
            .__init(b"test/scoped-auth/unanchored/nodes/");
        unanchored
            .host_mappings
            .__init(b"test/scoped-auth/unanchored/remotes/");
        assert_eq!(
            dispatch(
                &mut unanchored,
                AddNode {
                    prefix,
                    peer_id: node_peer.clone(),
                    role: NODE_ROLE_VOTER,
                    auth: auth.clone(),
                },
            ),
            Status::Forbidden,
            "no signed mutation is admissible before the space anchor",
        );
        assert_eq!(
            dispatch(
                &mut unanchored,
                SetSpaceId {
                    space_id: space_a.to_vec(),
                },
            ),
            Status::Ok,
        );
        assert_eq!(
            dispatch(
                &mut unanchored,
                AddNode {
                    prefix,
                    peer_id: node_peer.clone(),
                    role: NODE_ROLE_VOTER,
                    auth: auth.clone(),
                },
            ),
            Status::Ok,
            "the identical operation is valid after the durable anchor exists",
        );

        let mut sibling = SpaceRegistry::new();
        sibling.root.__init(b"test/scoped-auth/sibling/root/");
        sibling.root.set(&root);
        sibling.space_id.__init(b"test/scoped-auth/sibling/space/");
        sibling.space_id.set(&space_b.to_vec());
        sibling.nodes.__init(b"test/scoped-auth/sibling/nodes/");
        sibling
            .host_mappings
            .__init(b"test/scoped-auth/sibling/remotes/");
        assert_eq!(
            dispatch(
                &mut sibling,
                AddNode {
                    prefix,
                    peer_id: node_peer.clone(),
                    role: NODE_ROLE_VOTER,
                    auth,
                },
            ),
            Status::Forbidden,
            "an operation signed by the same root for another space must not transplant",
        );
        let sibling_canonical = registry_mutation_signed_bytes(
            &space_b,
            "add_node",
            &[&prefix.to_le_bytes(), &node_peer, &[NODE_ROLE_VOTER]],
        );
        assert_eq!(
            dispatch(
                &mut sibling,
                AddNode {
                    prefix,
                    peer_id: node_peer,
                    role: NODE_ROLE_VOTER,
                    auth: root_auth(&signing, &sibling_canonical),
                },
            ),
            Status::Ok,
        );

        let host_prefix = 29u32;
        let remote_canonical = registry_mutation_signed_bytes(
            &space_a,
            "register_remote",
            &[b"counter", &host_prefix.to_le_bytes()],
        );
        let remote_auth = root_auth(&signing, &remote_canonical);
        assert_eq!(
            dispatch(
                &mut unanchored,
                RegisterRemote {
                    instance_name: "counter".into(),
                    host_prefix,
                    auth: remote_auth.clone(),
                },
            ),
            Status::Ok,
        );
        assert_eq!(
            dispatch(
                &mut sibling,
                RegisterRemote {
                    instance_name: "counter".into(),
                    host_prefix,
                    auth: remote_auth,
                },
            ),
            Status::Forbidden,
            "a federation advertisement also binds its registry's exact space anchor",
        );
    }

    #[test]
    fn membership_mutations_reject_lossy_or_undocumented_shapes() {
        let signing = SigningKey::from_bytes(&[0x79; 32]);
        let mut registry = SpaceRegistry::new();
        registry.root.__init(b"test/member-shapes/root/");
        registry
            .root
            .set(&encode_registry_root(&root_peer(&signing)));
        anchor_test_space(&mut registry, b"test/member-shapes/space/");
        registry.nodes.__init(b"test/member-shapes/nodes/");
        registry
            .identities
            .__init(b"test/member-shapes/identities/");

        let valid_peer = root_peer(&SigningKey::from_bytes(&[0x7a; 32]));
        for (prefix, peer_id, role) in [
            (u16::MAX as u32 + 1, valid_peer.clone(), NODE_ROLE_VOTER),
            (7, vec![0x7b; 38], NODE_ROLE_VOTER),
            (7, valid_peer.clone(), 99),
        ] {
            let canonical = registry_mutation_signed_bytes(
                &TEST_SPACE_ID,
                "add_node",
                &[&prefix.to_le_bytes(), &peer_id, &[role]],
            );
            assert_eq!(
                dispatch(
                    &mut registry,
                    AddNode {
                        prefix,
                        peer_id,
                        role,
                        auth: root_auth(&signing, &canonical),
                    },
                ),
                Status::BadHash,
            );
        }

        let prefix = u16::MAX as u32 + 1;
        let canonical =
            registry_mutation_signed_bytes(&TEST_SPACE_ID, "remove_node", &[&prefix.to_le_bytes()]);
        assert_eq!(
            dispatch(
                &mut registry,
                RemoveNode {
                    prefix,
                    auth: root_auth(&signing, &canonical),
                },
            ),
            Status::BadPrefix,
        );

        let public_key = vec![0x7c; 32];
        let proof_kind = 99;
        let proof_data = vec![0x7d];
        let canonical = registry_mutation_signed_bytes(
            &TEST_SPACE_ID,
            "add_identity",
            &[&public_key, &[proof_kind], &proof_data],
        );
        assert_eq!(
            dispatch(
                &mut registry,
                AddIdentity {
                    public_key,
                    proof_kind,
                    proof_data,
                    auth: root_auth(&signing, &canonical),
                },
            ),
            Status::BadHash,
        );
    }

    #[test]
    fn prefix_queries_reject_values_that_do_not_fit_the_persisted_u16_key() {
        let signing = SigningKey::from_bytes(&[0x7e; 32]);
        let mut registry = SpaceRegistry::new();
        registry.root.__init(b"test/prefix-query-shapes/root/");
        registry
            .root
            .set(&encode_registry_root(&root_peer(&signing)));
        registry.nodes.__init(b"test/prefix-query-shapes/nodes/");

        let prefix = 7u16;
        registry.nodes.insert(
            &prefix,
            &MemberRow {
                kind: MEMBER_KIND_NODE,
                key: root_peer(&SigningKey::from_bytes(&[0x7f; 32])),
                prefix,
                role: NODE_ROLE_VOTER,
                proof_kind: 0,
                proof_data: Vec::new(),
            },
        );
        registry.agents.push(AgentRow {
            instance_name: "counter".into(),
            installation_id: InstallationId::new([0x70; 32]),
            revision: 0,
            program_hash: [0x71; 32],
            program_name: "counter-program".into(),
            program_publication_id: PublicationId::new([0x72; 32]),
            replication_id: [0x73; 32],
            consistency: 1,
            network_reachable: false,
            sync_role: SyncFloor::Member,
        });

        assert_eq!(
            dispatch(
                &mut registry,
                NodeRole {
                    prefix: u64::from(prefix),
                },
            ),
            NODE_ROLE_VOTER + 1,
        );
        assert_eq!(
            dispatch(
                &mut registry,
                Resolve {
                    name: "counter".into(),
                    caller_prefix: u64::from(prefix),
                },
            ),
            instance_service_id("counter", prefix),
        );

        for aliased in [u64::from(u16::MAX) + 1 + u64::from(prefix), u64::MAX] {
            assert_eq!(dispatch(&mut registry, NodeRole { prefix: aliased }), 0);
            assert_eq!(
                dispatch(
                    &mut registry,
                    Resolve {
                        name: "counter".into(),
                        caller_prefix: aliased,
                    },
                ),
                0,
            );
        }
    }

    #[test]
    fn role_mutations_reject_bad_shapes_and_replay_cannot_restore_a_revoked_grant() {
        let signing = SigningKey::from_bytes(&[0x80; 32]);
        let authority = [0x81; 32];
        let mut registry = SpaceRegistry::new();
        registry.root.__init(b"test/role-shapes/root/");
        registry
            .root
            .set(&encode_registry_root(&root_peer(&signing)));
        anchor_test_space(&mut registry, b"test/role-shapes/space/");
        registry
            .role_authority
            .__init(b"test/role-shapes/authority/");
        registry.role_authority.set(&authority);
        registry.auth_grants.__init(b"test/role-shapes/grants/");
        registry.revoke_epochs.__init(b"test/role-shapes/revokes/");
        registry
            .authority_grant_witnesses
            .__init(b"test/role-shapes/witnesses/");

        let rejected_target = root_peer(&SigningKey::from_bytes(&[0x82; 32]));
        for role in [AUTH_ROLE_NONE, AUTH_ROLE_ADMIN + 1, u8::MAX] {
            let epoch = 1u64;
            let canonical = registry_mutation_signed_bytes(
                &TEST_SPACE_ID,
                "grant_role",
                &[&rejected_target, &[role], &epoch.to_le_bytes(), &authority],
            );
            for _ in 0..2 {
                assert_eq!(
                    dispatch(
                        &mut registry,
                        GrantRole {
                            peer_id: rejected_target.clone(),
                            role,
                            epoch,
                            authority_replication_id: authority.to_vec(),
                            auth: root_auth(&signing, &canonical),
                        },
                    ),
                    Status::BadHash,
                );
            }
        }
        assert!(
            registry
                .auth_grants
                .get(&peer_key(&rejected_target))
                .is_none(),
            "malformed or non-grantable role must not create replayable state",
        );

        let malformed_target = rejected_target[..rejected_target.len() - 1].to_vec();
        let role = AUTH_ROLE_READONLY;
        let epoch = 1u64;
        let canonical = registry_mutation_signed_bytes(
            &TEST_SPACE_ID,
            "grant_role",
            &[&malformed_target, &[role], &epoch.to_le_bytes(), &authority],
        );
        assert_eq!(
            dispatch(
                &mut registry,
                GrantRole {
                    peer_id: malformed_target.clone(),
                    role,
                    epoch,
                    authority_replication_id: authority.to_vec(),
                    auth: root_auth(&signing, &canonical),
                },
            ),
            Status::BadHash,
        );
        assert!(
            registry
                .auth_grants
                .get(&peer_key(&malformed_target))
                .is_none()
        );

        let mut granted = Vec::new();
        for (seed, role, epoch) in [
            (0x83, AUTH_ROLE_READONLY, 1u64),
            (0x84, AUTH_ROLE_DEVELOPER, 2u64),
            (0x85, AUTH_ROLE_ADMIN, 3u64),
        ] {
            let peer_id = root_peer(&SigningKey::from_bytes(&[seed; 32]));
            let canonical = registry_mutation_signed_bytes(
                &TEST_SPACE_ID,
                "grant_role",
                &[&peer_id, &[role], &epoch.to_le_bytes(), &authority],
            );
            assert_eq!(
                dispatch(
                    &mut registry,
                    GrantRole {
                        peer_id: peer_id.clone(),
                        role,
                        epoch,
                        authority_replication_id: authority.to_vec(),
                        auth: root_auth(&signing, &canonical),
                    },
                ),
                Status::Ok,
            );
            assert_eq!(
                dispatch(
                    &mut registry,
                    PeerRole {
                        peer_id: peer_id.clone(),
                    },
                ),
                role,
            );
            granted.push((peer_id, role, epoch, canonical));
        }

        let malformed_revoke = vec![0x86; 38];
        let revoke_epoch = 10u64;
        let canonical = registry_mutation_signed_bytes(
            &TEST_SPACE_ID,
            "revoke_role",
            &[&malformed_revoke, &revoke_epoch.to_le_bytes(), &authority],
        );
        assert_eq!(
            dispatch(
                &mut registry,
                RevokeRole {
                    peer_id: malformed_revoke.clone(),
                    epoch: revoke_epoch,
                    authority_replication_id: authority.to_vec(),
                    auth: root_auth(&signing, &canonical),
                },
            ),
            Status::BadHash,
        );
        assert_eq!(registry.revoke_floor(&malformed_revoke), 0);

        let (peer_id, role, grant_epoch, grant_canonical) = &granted[0];
        let canonical = registry_mutation_signed_bytes(
            &TEST_SPACE_ID,
            "revoke_role",
            &[peer_id, &revoke_epoch.to_le_bytes(), &authority],
        );
        let revoke = || RevokeRole {
            peer_id: peer_id.clone(),
            epoch: revoke_epoch,
            authority_replication_id: authority.to_vec(),
            auth: root_auth(&signing, &canonical),
        };
        assert_eq!(dispatch(&mut registry, revoke()), Status::Ok);
        assert_eq!(dispatch(&mut registry, revoke()), Status::Ok);
        assert_eq!(
            dispatch(
                &mut registry,
                PeerRole {
                    peer_id: peer_id.clone(),
                },
            ),
            AUTH_ROLE_NONE,
        );

        assert_eq!(
            dispatch(
                &mut registry,
                GrantRole {
                    peer_id: peer_id.clone(),
                    role: *role,
                    epoch: *grant_epoch,
                    authority_replication_id: authority.to_vec(),
                    auth: root_auth(&signing, grant_canonical),
                },
            ),
            Status::Ok,
        );
        assert_eq!(
            dispatch(
                &mut registry,
                PeerRole {
                    peer_id: peer_id.clone(),
                },
            ),
            AUTH_ROLE_NONE,
            "replaying a pre-revoke grant must not restore its capability",
        );
    }

    #[test]
    fn invite_role_shape_is_distinct_from_offline_invite_policy_and_replays_idempotently() {
        let admin = SigningKey::from_bytes(&[0x87; 32]);
        let joining = SigningKey::from_bytes(&[0x88; 32]);
        let token = SigningKey::from_bytes(&[0x89; 32]);
        let admin_peer_id = root_peer(&admin);
        let peer_id = root_peer(&joining);
        let token_pub = token.verifying_key().as_bytes().to_vec();
        let authority = [0x8a; 32];
        let expires_at = 100u64;

        let mut registry = SpaceRegistry::new();
        registry.root.__init(b"test/invite-role-shapes/root/");
        registry.root.set(&encode_registry_root(&admin_peer_id));
        anchor_test_space(&mut registry, b"test/invite-role-shapes/space/");
        registry
            .role_authority
            .__init(b"test/invite-role-shapes/authority/");
        registry.role_authority.set(&authority);
        registry
            .auth_grants
            .__init(b"test/invite-role-shapes/grants/");
        registry
            .revoke_epochs
            .__init(b"test/invite-role-shapes/revokes/");
        registry
            .authority_grant_witnesses
            .__init(b"test/invite-role-shapes/witnesses/");
        registry.invites.__init(b"test/invite-role-shapes/invites/");

        let malformed_role_message = |role| RedeemInvite {
            token_pub: token_pub.clone(),
            role,
            expires_at,
            authority_replication_id: authority.to_vec(),
            admin_peer_id: admin_peer_id.clone(),
            admin_sig: vec![0; OP_SIG_LEN],
            peer_id: peer_id.clone(),
            redeem_sig: vec![0; OP_SIG_LEN],
            node_sig: vec![0; OP_SIG_LEN],
            authority_attestation: vec![0; OP_SIG_LEN],
        };
        for role in [AUTH_ROLE_ADMIN + 1, u8::MAX] {
            assert_eq!(
                dispatch(&mut registry, malformed_role_message(role)),
                Status::BadHash,
            );
        }
        for role in [AUTH_ROLE_NONE, AUTH_ROLE_ADMIN] {
            assert_eq!(
                dispatch(&mut registry, malformed_role_message(role)),
                Status::Forbidden,
            );
        }
        assert_eq!(registry.invites.len(), 0);
        assert_eq!(registry.auth_grants.len(), 0);

        let role = AUTH_ROLE_READONLY;
        let token_pub_key = bytes_to_32(&token_pub).unwrap();
        let invite_canonical =
            invite_signed_bytes(&TEST_SPACE_ID, role, expires_at, &token_pub_key, &authority);
        let admin_sig = admin.sign(&invite_canonical).to_bytes().to_vec();
        let redeem_canonical = registry_mutation_signed_bytes(
            &TEST_SPACE_ID,
            "redeem_invite",
            &[&token_pub, &peer_id],
        );
        let redeem_sig = token.sign(&redeem_canonical).to_bytes().to_vec();
        let node_sig = joining.sign(&redeem_canonical).to_bytes().to_vec();
        let attestation_canonical = registry_mutation_signed_bytes(
            &TEST_SPACE_ID,
            "attest_role_authority_invite",
            &[
                &authority,
                &token_pub,
                &[role],
                &expires_at.to_le_bytes(),
                &admin_peer_id,
                &admin_sig,
                &peer_id,
                &redeem_sig,
                &node_sig,
            ],
        );
        let redeem = || RedeemInvite {
            token_pub: token_pub.clone(),
            role,
            expires_at,
            authority_replication_id: authority.to_vec(),
            admin_peer_id: admin_peer_id.clone(),
            admin_sig: admin_sig.clone(),
            peer_id: peer_id.clone(),
            redeem_sig: redeem_sig.clone(),
            node_sig: node_sig.clone(),
            authority_attestation: root_auth(&admin, &attestation_canonical),
        };
        assert_eq!(dispatch(&mut registry, redeem()), Status::Ok);
        assert_eq!(dispatch(&mut registry, redeem()), Status::Ok);
        assert_eq!(
            dispatch(
                &mut registry,
                PeerRole {
                    peer_id: peer_id.clone(),
                },
            ),
            role,
        );
        let invite = registry.invites.get(&token_pub_key).unwrap();
        assert_eq!(invite.role, role);
        assert_eq!(invite.redeemed_by, vec![peer_id]);
    }

    #[test]
    fn registry_storage_boundaries_accept_only_canonical_slugs() {
        for valid in [
            "a".to_owned(),
            "0".to_owned(),
            "agent-01".to_owned(),
            "a--b".to_owned(),
            format!("a{}z", "0".repeat(61)),
        ] {
            assert!(
                is_canonical_registry_slug(&valid),
                "valid slug rejected: {valid}"
            );
        }
        for invalid in [
            String::new(),
            "-agent".into(),
            "agent-".into(),
            "Agent".into(),
            "agent_actor".into(),
            "agent.actor".into(),
            "agent/actor".into(),
            "agent actor".into(),
            "é".into(),
            "a".repeat(64),
        ] {
            assert!(
                !is_canonical_registry_slug(&invalid),
                "noncanonical slug accepted: {invalid:?}",
            );
        }

        let signing = SigningKey::from_bytes(&[0x74; 32]);
        let mut registry = SpaceRegistry::new();
        registry.root.__init(b"test/slug-boundary/root/");
        registry
            .root
            .set(&encode_registry_root(&root_peer(&signing)));
        anchor_test_space(&mut registry, b"test/slug-boundary/space/");
        registry
            .used_publication_ids
            .__init(b"test/slug-boundary/publications/");
        registry
            .authorized_program_hashes
            .__init(b"test/slug-boundary/authorized/");

        assert_eq!(
            registry.publish_program_cas(
                "Bad-Program".into(),
                vec![0x75; 32],
                ProgramKind::Service { crdt: false },
                vec![0x76; 32],
                Vec::new(),
                Vec::new(),
            ),
            Status::BadHash,
        );

        // These maps remain intentionally uninitialized. BadHash therefore
        // proves validation ran before either invalid name could become a
        // storage key.
        let remote_canonical = registry_mutation_signed_bytes(
            &TEST_SPACE_ID,
            "register_remote",
            &["bad_name".as_bytes(), &7u32.to_le_bytes()],
        );
        assert_eq!(
            dispatch(
                &mut registry,
                RegisterRemote {
                    instance_name: "bad_name".into(),
                    host_prefix: 7,
                    auth: root_auth(&signing, &remote_canonical),
                },
            ),
            Status::BadHash,
        );
        let extension_name = "bad.extension";
        let extension_blob = Vec::new();
        let extension_canonical = registry_mutation_signed_bytes(
            &TEST_SPACE_ID,
            "register_extension_meta",
            &[extension_name.as_bytes(), &extension_blob],
        );
        assert_eq!(
            dispatch(
                &mut registry,
                RegisterExtensionMeta {
                    instance_name: extension_name.into(),
                    blob: extension_blob,
                    auth: root_auth(&signing, &extension_canonical),
                },
            ),
            Status::BadHash,
        );

        let program = ProgramTag {
            publication_id: PublicationId::new([0x77; 32]),
            hash: [0x78; 32],
        };
        assert_eq!(
            install_service_for_test(
                &mut registry,
                &signing,
                "Bad-Instance",
                "program",
                program,
                [0x79; 32],
                [0x7a; 32],
            ),
            Status::BadHash,
        );
        assert_eq!(
            install_service_for_test(
                &mut registry,
                &signing,
                "instance",
                "bad_program",
                program,
                [0x7b; 32],
                [0x7c; 32],
            ),
            Status::BadHash,
        );

        let system_agent = AgentId::new([0x7d; 32]);
        let mut receipt = SystemActorInstallReceipt {
            protocol: RegistryProtocol::CURRENT,
            installation_id: InstallationId::new([0x7e; 32]),
            system_agent_id: system_agent,
            actor_id: ActorId::top_level(system_agent, "system-actor"),
            instance_name: "system-actor".into(),
            program_name: "system-program".into(),
            program_hash: [0x7f; 32],
            program_publication_id: PublicationId::new([0x80; 32]),
            host_receipt: vec![0x81],
        };
        assert!(valid_system_actor_install_receipt(&receipt));
        receipt.instance_name = "system_actor".into();
        assert!(!valid_system_actor_install_receipt(&receipt));
        receipt.instance_name = "system-actor".into();
        receipt.program_name = "System-Program".into();
        assert!(!valid_system_actor_install_receipt(&receipt));
    }

    #[test]
    fn service_and_system_actors_share_one_instance_name_namespace() {
        let signing = SigningKey::from_bytes(&[0x82; 32]);
        let mut registry = SpaceRegistry::new();
        registry.root.__init(b"test/shared-name/root/");
        registry
            .root
            .set(&encode_registry_root(&root_peer(&signing)));
        anchor_test_space(&mut registry, b"test/shared-name/space/");
        registry
            .used_publication_ids
            .__init(b"test/shared-name/publications/");
        registry
            .authorized_program_hashes
            .__init(b"test/shared-name/authorized/");
        registry
            .used_installation_ids
            .__init(b"test/shared-name/installations/");
        registry
            .used_replication_ids
            .__init(b"test/shared-name/replications/");
        registry
            .consistency_floors
            .__init(b"test/shared-name/consistency/");

        let program = ProgramTag {
            publication_id: PublicationId::new([0x83; 32]),
            hash: [0x84; 32],
        };
        assert_eq!(
            registry.publish_program_cas(
                "service-program".into(),
                program.hash.to_vec(),
                ProgramKind::Service { crdt: false },
                program.publication_id.as_bytes().to_vec(),
                Vec::new(),
                Vec::new(),
            ),
            Status::Ok,
        );
        let system_agent = AgentId::new([0x85; 32]);
        registry.system_actors.push(SystemActorRow {
            instance_name: "shared-name".into(),
            installation_id: InstallationId::new([0x86; 32]),
            revision: 0,
            system_agent_id: system_agent,
            actor_id: ActorId::top_level(system_agent, "shared-name"),
            program_hash: [0x87; 32],
            program_name: "system-program".into(),
            program_publication_id: PublicationId::new([0x88; 32]),
            host_receipt_hash: [0x89; 32],
        });

        let losing_installation = [0x8a; 32];
        let losing_replication = [0x8b; 32];
        assert_eq!(
            install_service_for_test(
                &mut registry,
                &signing,
                "shared-name",
                "service-program",
                program,
                losing_installation,
                losing_replication,
            ),
            Status::InstanceExists,
        );
        assert!(registry.agents.is_empty());
        assert!(
            registry
                .used_installation_ids
                .contains(&losing_installation)
        );
        assert!(registry.used_replication_ids.contains(&losing_replication));
    }

    #[test]
    fn loose_host_lifecycle_handlers_fail_closed_after_schema_and_auth() {
        let signing = SigningKey::from_bytes(&[0x91; 32]);
        let mut registry = SpaceRegistry::new();
        registry.root.__init(b"test/host-lifecycle/root/");
        registry
            .root
            .set(&encode_registry_root(&root_peer(&signing)));
        anchor_test_space(&mut registry, b"test/host-lifecycle/space/");

        // No lifecycle-related storage handle is initialized. An authorized
        // call can return HostLifecycleRequired only if the obsolete registry
        // mutation path is completely side-effect free.
        let receipt = vec![0x92; 32];
        assert_eq!(
            dispatch(
                &mut registry,
                InstallSystemActor {
                    receipt: receipt.clone(),
                    auth: Vec::new(),
                },
            ),
            Status::Forbidden,
        );
        let canonical = install_system_actor_signed_bytes(&TEST_SPACE_ID, &receipt);
        assert_eq!(
            dispatch(
                &mut registry,
                InstallSystemActor {
                    receipt,
                    auth: root_auth(&signing, &canonical),
                },
            ),
            Status::HostLifecycleRequired,
        );

        let instance_name = "system-actor";
        let installation_id = vec![0x93; 32];
        let expected_program_hash = vec![0x94; 32];
        let expected_publication_id = vec![0x95; 32];
        let canonical = uninstall_system_actor_signed_bytes(
            &TEST_SPACE_ID,
            instance_name,
            &installation_id,
            4,
            &expected_program_hash,
            &expected_publication_id,
        );
        assert_eq!(
            dispatch(
                &mut registry,
                UninstallSystemActor {
                    instance_name: instance_name.into(),
                    installation_id: installation_id.clone(),
                    expected_revision: 4,
                    expected_program_hash: expected_program_hash.clone(),
                    expected_program_publication_id: expected_publication_id.clone(),
                    auth: Vec::new(),
                },
            ),
            Status::Forbidden,
        );
        assert_eq!(
            dispatch(
                &mut registry,
                UninstallSystemActor {
                    instance_name: instance_name.into(),
                    installation_id: installation_id.clone(),
                    expected_revision: 4,
                    expected_program_hash: expected_program_hash.clone(),
                    expected_program_publication_id: expected_publication_id.clone(),
                    auth: root_auth(&signing, &canonical),
                },
            ),
            Status::HostLifecycleRequired,
        );

        let new_program_name = "system-program-v2";
        let new_program_hash = vec![0x96; 32];
        let new_publication_id = vec![0x97; 32];
        let canonical = upgrade_system_actor_signed_bytes(
            &TEST_SPACE_ID,
            instance_name,
            &installation_id,
            4,
            &expected_program_hash,
            &expected_publication_id,
            new_program_name,
            &new_program_hash,
            &new_publication_id,
        );
        assert_eq!(
            dispatch(
                &mut registry,
                UpgradeSystemActor {
                    instance_name: instance_name.into(),
                    installation_id: installation_id.clone(),
                    expected_revision: 4,
                    from_program_hash: expected_program_hash.clone(),
                    from_program_publication_id: expected_publication_id.clone(),
                    new_program_name: new_program_name.into(),
                    new_program_hash: new_program_hash.clone(),
                    new_program_publication_id: new_publication_id.clone(),
                    auth: Vec::new(),
                },
            ),
            Status::Forbidden,
        );
        assert_eq!(
            dispatch(
                &mut registry,
                UpgradeSystemActor {
                    instance_name: instance_name.into(),
                    installation_id: installation_id.clone(),
                    expected_revision: 4,
                    from_program_hash: expected_program_hash.clone(),
                    from_program_publication_id: expected_publication_id.clone(),
                    new_program_name: new_program_name.into(),
                    new_program_hash: new_program_hash.clone(),
                    new_program_publication_id: new_publication_id.clone(),
                    auth: root_auth(&signing, &canonical),
                },
            ),
            Status::HostLifecycleRequired,
        );

        let service_canonical = upgrade_service_actor_signed_bytes(
            &TEST_SPACE_ID,
            "service-actor",
            &installation_id,
            2,
            &expected_program_hash,
            &expected_publication_id,
            "service-program-v2",
            &new_program_hash,
            &new_publication_id,
        );
        assert_eq!(
            dispatch(
                &mut registry,
                UpgradeServiceActor {
                    instance_name: "service-actor".into(),
                    installation_id: installation_id.clone(),
                    expected_revision: 2,
                    from_program_hash: expected_program_hash.clone(),
                    from_program_publication_id: expected_publication_id.clone(),
                    new_program_name: "service-program-v2".into(),
                    new_program_hash: new_program_hash.clone(),
                    new_program_publication_id: new_publication_id.clone(),
                    auth: Vec::new(),
                },
            ),
            Status::Forbidden,
        );
        assert_eq!(
            dispatch(
                &mut registry,
                UpgradeServiceActor {
                    instance_name: "service-actor".into(),
                    installation_id,
                    expected_revision: 2,
                    from_program_hash: expected_program_hash,
                    from_program_publication_id: expected_publication_id,
                    new_program_name: "service-program-v2".into(),
                    new_program_hash,
                    new_program_publication_id: new_publication_id,
                    auth: root_auth(&signing, &service_canonical),
                },
            ),
            Status::HostLifecycleRequired,
        );
        assert!(registry.agents.is_empty());
        assert!(registry.system_actors.is_empty());

        let mut stale = SpaceRegistry::new();
        stale.root.__init(b"test/host-lifecycle/stale-root/");
        stale.root.set(&root_peer(&signing));
        let stale_receipt = vec![0x98; 32];
        let stale_canonical = install_system_actor_signed_bytes(&TEST_SPACE_ID, &stale_receipt);
        assert_eq!(
            dispatch(
                &mut stale,
                InstallSystemActor {
                    receipt: stale_receipt,
                    auth: root_auth(&signing, &stale_canonical),
                },
            ),
            Status::ProtocolMismatch,
        );
    }

    #[test]
    #[cfg(feature = "bin")]
    fn extension_restart_refuses_old_state_header() {
        let live = vos_extension_create(core::ptr::null(), 0);
        assert!(!live.is_null());

        let mut ptr = core::ptr::null_mut();
        let mut len = 0usize;
        let mut capacity = 0usize;
        vos_extension_state_v2(live, &mut ptr, &mut len, &mut capacity);
        assert!(!ptr.is_null());
        let mut state = unsafe { core::slice::from_raw_parts(ptr, len) }.to_vec();
        vos_extension_free(ptr, len, capacity);
        vos_extension_drop(live);

        assert_eq!(&state[..8], b"VOSXST02");
        assert_eq!(
            u64::from_le_bytes(state[8..16].try_into().unwrap()),
            <SpaceRegistry as vos::Actor>::STATE_SCHEMA_VERSION,
        );
        let restored = vos_extension_load(state.as_ptr(), state.len());
        assert!(!restored.is_null(), "current state header must restart");
        vos_extension_drop(restored);

        state[8..16].copy_from_slice(&1u64.to_le_bytes());
        assert!(
            vos_extension_load(state.as_ptr(), state.len()).is_null(),
            "a v1 actor snapshot must fail closed at restart",
        );

        state[8..16]
            .copy_from_slice(&<SpaceRegistry as vos::Actor>::STATE_SCHEMA_VERSION.to_le_bytes());
        state[16] ^= 1;
        assert!(
            vos_extension_load(state.as_ptr(), state.len()).is_null(),
            "a drifted v2 state fingerprint must fail closed at restart",
        );
    }

    #[test]
    fn system_install_receipt_binds_host_derived_actor_identity() {
        let agent = AgentId::new([0x31; 32]);
        let mut receipt = SystemActorInstallReceipt {
            protocol: RegistryProtocol::CURRENT,
            installation_id: InstallationId::new([0x32; 32]),
            system_agent_id: agent,
            actor_id: ActorId::top_level(agent, "worker"),
            instance_name: "worker".into(),
            program_name: "worker-code".into(),
            program_hash: [0x33; 32],
            program_publication_id: PublicationId::new([0x34; 32]),
            host_receipt: vec![0x35],
        };
        assert!(valid_system_actor_install_receipt(&receipt));
        receipt.actor_id = ActorId::new([0x99; 32]);
        assert!(!valid_system_actor_install_receipt(&receipt));
        receipt.actor_id = ActorId::top_level(agent, "worker");
        receipt.protocol = RegistryProtocol::UNSUPPORTED;
        assert!(!valid_system_actor_install_receipt(&receipt));
    }
}
