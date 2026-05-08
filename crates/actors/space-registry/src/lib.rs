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
#[derive(vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = vos::rkyv)]
pub struct ProgramRow {
    pub name: String,
    pub version: String,
    pub hash: [u8; 32],
}

// ── Agents ────────────────────────────────────────────────────────

/// One row in the agent (instance) catalog.
#[derive(vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
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
#[derive(vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
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
}

#[messages]
impl SpaceRegistry {
    fn new() -> Self {
        Self {
            programs: Vec::new(),
            agents: Vec::new(),
            members: Vec::new(),
        }
    }

    // ── Programs catalog ────────────────────────────────────────

    /// Add a program to the catalog. Tags are immutable — if
    /// `(name, version)` already exists, returns
    /// `STATUS_TAG_CONFLICT` unless the existing hash matches
    /// (idempotent re-publish).
    #[msg]
    async fn publish(
        &mut self,
        name: String,
        version: String,
        hash: Vec<u8>,
    ) -> u8 {
        let Some(hash) = bytes_to_32(&hash) else { return STATUS_BAD_HASH; };
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
        self.programs.insert(idx, ProgramRow { name, version, hash });
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
        let Some(program_hash) = bytes_to_32(&program_hash) else { return STATUS_BAD_HASH; };
        let Some(replication_id) = bytes_to_32(&replication_id) else { return STATUS_BAD_HASH; };

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
        let Some(new_program_hash) = bytes_to_32(&new_program_hash) else { return STATUS_BAD_HASH; };

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

