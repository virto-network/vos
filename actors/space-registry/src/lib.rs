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

// ── Actor ─────────────────────────────────────────────────────────

use vos::prelude::*;

#[actor]
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
        }
    }

    // ── Programs catalog ────────────────────────────────────────

    /// Add a program to the catalog. Tags are immutable — if
    /// `(name, version)` already exists, returns
    /// `STATUS_TAG_CONFLICT` unless the existing hash matches
    /// (idempotent re-publish).
    #[msg]
    async fn publish(&mut self, name: String, version: String, hash: Vec<u8>) -> u8 {
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
    #[msg]
    async fn unpublish(&mut self, name: String, version: String) -> u8 {
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
    #[msg]
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
        self.metas.push(MetaRow {
            program_hash,
            blob,
        });
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
    #[msg]
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
    #[msg]
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
    ) -> u8 {
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
    #[msg]
    async fn uninstall(&mut self, instance_name: String) -> u8 {
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
    #[msg]
    async fn upgrade(
        &mut self,
        instance_name: String,
        new_program_name: String,
        new_program_version: String,
        new_program_hash: Vec<u8>,
    ) -> u8 {
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
    /// occupies on the caller's node, packed as a u32.
    /// `caller_prefix` is the asking node's 16-bit identity
    /// prefix (passed by `Context::resolve` from the caller's
    /// own `id().node_prefix()`); the registry derives the
    /// local half via `instance_service_id`. Returns 0 when no
    /// agent with that name is installed.
    ///
    /// This is the runtime name → ServiceId lookup actors reach
    /// for via `ctx.resolve(name)`. Same formula `space up`
    /// uses host-side, so the derived id matches the actual
    /// per-node registration.
    #[msg]
    async fn resolve(&self, name: String, caller_prefix: u64) -> u32 {
        if !self.agents.iter().any(|a| a.instance_name == name) {
            return 0;
        }
        instance_service_id(&name, caller_prefix as u16)
    }

    // ── Members ────────────────────────────────────────────────

    /// Add a Node member. Idempotent in `prefix` — re-adding
    /// updates `peer_id` and `role`. `role` is
    /// `NODE_ROLE_VOTER` or `NODE_ROLE_OBSERVER`.
    #[msg]
    async fn add_node(&mut self, prefix: u32, peer_id: Vec<u8>, role: u8) -> u8 {
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

    #[msg]
    async fn remove_node(&mut self, prefix: u32) -> u8 {
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
    #[msg]
    async fn add_identity(
        &mut self,
        public_key: Vec<u8>,
        proof_kind: u8,
        proof_data: Vec<u8>,
    ) -> u8 {
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

    #[msg]
    async fn remove_identity(&mut self, public_key: Vec<u8>) -> u8 {
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

    // ── Auth grants (Sprint 2) ─────────────────────────────────

    /// Grant `role` to `peer_id`. Idempotent — re-granting the
    /// same role is a no-op; changing the role updates in place.
    /// `peer_id` is libp2p multihash bytes (same encoding as
    /// `add_node`'s `peer_id` arg).
    #[msg]
    async fn grant_role(&mut self, peer_id: Vec<u8>, role: u8) -> u8 {
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
    #[msg]
    async fn revoke_role(&mut self, peer_id: Vec<u8>) -> u8 {
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
        match self
            .auth_grants
            .binary_search_by(|g| compare_bytes(&g.peer_id, &peer_id).cmp(&0))
        {
            Ok(idx) => self.auth_grants[idx].role,
            Err(_) => AUTH_ROLE_NONE,
        }
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
    #[msg]
    async fn grant_actor_role(&mut self, peer_id: Vec<u8>, agent_name: String, role: u8) -> u8 {
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
    #[msg]
    async fn revoke_actor_role(&mut self, peer_id: Vec<u8>, agent_name: String) -> u8 {
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
    #[msg]
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

// ── Helpers ──────────────────────────────────────────────────────

fn bytes_to_32(b: &[u8]) -> Option<[u8; 32]> {
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Some(out)
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
fn actor_acl_key(
    a_peer: &[u8],
    a_name: &str,
    b_peer: &[u8],
    b_name: &str,
) -> core::cmp::Ordering {
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

#[cfg(test)]
mod tests {
    use super::*;
    use vos::Message;
    use vos::actors::context::ServiceId;

    fn registry() -> SpaceRegistry {
        SpaceRegistry::new()
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
        let status = dispatch(
            &mut r,
            GrantActorRole {
                peer_id: peer.clone(),
                agent_name: agent.clone(),
                role: 2,
            },
        );
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
        assert_eq!(
            dispatch(
                &mut r,
                GrantActorRole {
                    peer_id: peer.clone(),
                    agent_name: agent.clone(),
                    role: 2,
                },
            ),
            STATUS_OK,
        );
        assert_eq!(
            dispatch(
                &mut r,
                GrantActorRole {
                    peer_id: peer.clone(),
                    agent_name: agent.clone(),
                    role: 2,
                },
            ),
            STATUS_OK,
        );
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
        dispatch(
            &mut r,
            GrantActorRole {
                peer_id: peer.clone(),
                agent_name: agent.clone(),
                role: 1,
            },
        );
        dispatch(
            &mut r,
            GrantActorRole {
                peer_id: peer.clone(),
                agent_name: agent.clone(),
                role: 3,
            },
        );
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
        assert_eq!(
            dispatch(
                &mut r,
                GrantActorRole {
                    peer_id: Vec::new(),
                    agent_name: String::from("x"),
                    role: 1,
                },
            ),
            STATUS_BAD_HASH,
        );
        assert_eq!(
            dispatch(
                &mut r,
                GrantActorRole {
                    peer_id: alloc::vec![1],
                    agent_name: String::new(),
                    role: 1,
                },
            ),
            STATUS_BAD_HASH,
        );
    }

    // ── revoke_actor_role ───────────────────────────────────────

    #[test]
    fn revoke_actor_role_removes_grant() {
        let mut r = registry();
        let peer = alloc::vec![1, 2, 3];
        let agent = String::from("dev-project");
        dispatch(
            &mut r,
            GrantActorRole {
                peer_id: peer.clone(),
                agent_name: agent.clone(),
                role: 2,
            },
        );
        let status = dispatch(
            &mut r,
            RevokeActorRole {
                peer_id: peer.clone(),
                agent_name: agent.clone(),
            },
        );
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
        let status = dispatch(
            &mut r,
            RevokeActorRole {
                peer_id: alloc::vec![1],
                agent_name: String::from("x"),
            },
        );
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
        dispatch(
            &mut r,
            GrantActorRole {
                peer_id: peer.clone(),
                agent_name: String::from("a"),
                role: 1,
            },
        );
        dispatch(
            &mut r,
            GrantActorRole {
                peer_id: peer.clone(),
                agent_name: String::from("b"),
                role: 3,
            },
        );
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
            dispatch(
                &mut r,
                GrantActorRole {
                    peer_id: alloc::vec![peer_byte],
                    agent_name: String::from("z"),
                    role: 1,
                },
            );
        }
        let rows = dispatch(&mut r, ActorAcls);
        for w in rows.windows(2) {
            assert!(
                actor_acl_key(&w[0].peer_id, &w[0].agent_name, &w[1].peer_id, &w[1].agent_name)
                    == core::cmp::Ordering::Less,
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
        dispatch(
            &mut r,
            GrantRole {
                peer_id: peer.clone(),
                role: AUTH_ROLE_DEVELOPER,
            },
        );
        dispatch(
            &mut r,
            GrantActorRole {
                peer_id: peer.clone(),
                agent_name: String::from("x"),
                role: 3,
            },
        );
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
}
