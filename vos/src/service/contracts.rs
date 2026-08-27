use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::string::String;
#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

use crate::attestation::{AttestationPreparation, AttestationStatement};

use super::identity::*;
use super::wire::{DecodeError, Decoder, Encoder, ServiceWire};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceIdentity {
    pub space: SpaceId,
    pub root_service: RootServiceId,
    pub deployment: DeploymentId,
    pub service_program: ProgramId,
    pub platform: Hash,
    pub execution_semantics: Hash,
    /// Consensus-visible execution budget. Replicas must reject work whose
    /// declared schedule differs from the host schedule used to run it.
    pub gas_schedule: GasSchedule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GasSchedule {
    pub refine: u64,
    pub accumulate: u64,
}

impl GasSchedule {
    pub const fn new(refine: u64, accumulate: u64) -> Self {
        Self { refine, accumulate }
    }

    pub const fn is_valid(self) -> bool {
        self.refine != 0 && self.accumulate != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConsistencyMode {
    Ephemeral = 0,
    Local = 1,
    Raft = 2,
    Crdt = 3,
}

impl ConsistencyMode {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match decoder.u8()? {
            0 => Ok(Self::Ephemeral),
            1 => Ok(Self::Local),
            2 => Ok(Self::Raft),
            3 => Ok(Self::Crdt),
            _ => Err(DecodeError::InvalidTag),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsistencyBase {
    Linear { revision: u64, state_root: Hash },
    Crdt { heads: Vec<Hash> },
}

impl ConsistencyBase {
    pub fn mode_compatible(&self, mode: ConsistencyMode) -> bool {
        matches!(
            (self, mode),
            (
                Self::Linear { .. },
                ConsistencyMode::Ephemeral | ConsistencyMode::Local | ConsistencyMode::Raft
            ) | (Self::Crdt { .. }, ConsistencyMode::Crdt)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationEvidence {
    /// Method policy explicitly allows anonymous invocation.
    Public,
    /// Opaque credential disclosed to ordinary authorization validation and
    /// the generated policy it must satisfy. Attested private roles use
    /// [`Self::PrivateCredential`] instead.
    Credential {
        policy: Hash,
        credential_commitment: Hash,
        bytes: Vec<u8>,
    },
    /// Private attestation witness. Refine/proving receives the preimage as an
    /// imported blob, while work and statement wires expose only this content
    /// reference, the credential commitment, and the generated policy.
    PrivateCredential {
        policy: Hash,
        credential_commitment: Hash,
        witness: BlobRef,
    },
    /// Authenticated platform operation. This never bypasses the method's
    /// generated policy.
    SystemCapability {
        capability: SystemCapabilityId,
        authenticator: Vec<u8>,
    },
}

/// Canonical authenticated role grant used as disclosed authorization input
/// or as the private witness of an attested call.
///
/// `authenticator` is issued and checked by the platform credential provider;
/// the generic service additionally binds the exact bytes to `holder`, the
/// invocation-specific authorization scope, and both generated role
/// thresholds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleCredential {
    pub holder: Origin,
    pub scope: Hash,
    pub space_role: Option<crate::SpaceRole>,
    pub capability: Option<CapabilityId>,
    pub actor_role: Option<u8>,
    pub authenticator: Vec<u8>,
}

/// Exact registry service whose accumulated replies may authorize role-gated
/// work in an installed root tree. This binding is platform configuration,
/// not credential-controlled input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAuthorityBinding {
    pub service: ServiceIdentity,
    pub actor: ActorId,
}

pub const ROLE_AUTHORITY_MUTATION_METHOD_: &str = "mutate_role";
pub const ROLE_AUTHORITY_INVITE_METHOD_: &str = "redeem_invite";
pub const ROLE_AUTHORITY_INVITE_REVOKE_METHOD_: &str = "revoke_invite";
pub const ROLE_AUTHORITY_DECISION_METHOD_: &str = "authorize_role";
/// Reserved installed root name for the one canonical authority service in a
/// space. Application manifests cannot choose a sibling authority by route.
pub const ROLE_AUTHORITY_INSTANCE_: &str = "space-authority";

/// Signed authority-state mutation. The canonical service wire bytes are the
/// exact Ed25519 message verified by the authority actor, so a signature for
/// one space, holder, role, epoch, or operation cannot be replayed as another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleAuthorityMutation {
    Grant {
        space: SpaceId,
        holder: Origin,
        role: crate::SpaceRole,
        epoch: u64,
    },
    Revoke {
        space: SpaceId,
        holder: Origin,
        epoch: u64,
    },
}

impl RoleAuthorityMutation {
    pub fn space(&self) -> SpaceId {
        match self {
            Self::Grant { space, .. } | Self::Revoke { space, .. } => *space,
        }
    }

    pub fn holder(&self) -> Origin {
        match self {
            Self::Grant { holder, .. } | Self::Revoke { holder, .. } => *holder,
        }
    }

    pub fn epoch(&self) -> u64 {
        match self {
            Self::Grant { epoch, .. } | Self::Revoke { epoch, .. } => *epoch,
        }
    }
}

/// Offline delegated-grant evidence carried from invite minting through
/// redemption into the canonical role authority.
///
/// The admin signature binds `(space, role, expires_at, token_pub)`. The token
/// and joining node signatures both bind `(token_pub, holder_peer_id)`. The
/// authority verifies the complete chain and records the admin as grantor, so
/// revoking that admin invalidates grants derived from its invites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAuthorityInviteRedemption {
    pub space: SpaceId,
    /// Signed durable marker naming the exact canonical authority
    /// incarnation this bearer must commit through.
    pub authority_replication_id: [u8; 32],
    pub token_pub: [u8; 32],
    pub role: crate::SpaceRole,
    pub expires_at: u64,
    pub admin_peer_id: Vec<u8>,
    pub admin_signature: [u8; 64],
    pub holder_peer_id: Vec<u8>,
    pub redeem_signature: [u8; 64],
    pub holder_signature: [u8; 64],
}

impl RoleAuthorityInviteRedemption {
    pub fn holder(&self) -> Origin {
        Origin::Member(SubjectId::of_authenticated_peer(&self.holder_peer_id))
    }

    pub fn grantor(&self) -> Origin {
        Origin::Member(SubjectId::of_authenticated_peer(&self.admin_peer_id))
    }
}

/// Admin-signed cancellation of one offline invite bearer. The wire binds the
/// space as well as the token, so an administrator of two spaces cannot replay
/// one signature across their independent authorities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAuthorityInviteRevocation {
    pub space: SpaceId,
    pub token_pub: [u8; 32],
    pub admin_peer_id: Vec<u8>,
}

impl RoleAuthorityInviteRevocation {
    pub fn grantor(&self) -> Origin {
        Origin::Member(SubjectId::of_authenticated_peer(&self.admin_peer_id))
    }
}

/// One invocation-scoped role decision produced by the space's pinned
/// authority service.
///
/// Binding the complete destination prevents an old grant response from being
/// replayed for another actor, method, generated policy, or invocation. A
/// revocation racing after this assertion therefore has ordinary causal
/// semantics: this already-authorized invocation may proceed, but a later
/// invocation requires a different assertion and receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAuthorizationClaim {
    pub space: SpaceId,
    pub holder: Origin,
    /// Transitional fixed threshold. Capability-native packages leave this
    /// empty; it is removed with the clean-break platform repin.
    pub role: Option<crate::SpaceRole>,
    /// Exact package-declared space capability being authorized.
    pub capability: Option<CapabilityId>,
    pub audience: ServiceIdentity,
    pub invocation: InvocationId,
    /// Complete invocation authorization scope, including target deployment,
    /// program, arguments, origin, causal identity, and proof mode.
    pub scope: Hash,
    pub target: ActorId,
    pub method: String,
    pub policy: Hash,
}

impl RoleAuthorizationClaim {
    /// Stable authority workflow identity for this one exact decision.
    pub fn authority_invocation(&self) -> InvocationId {
        InvocationId::derive(b"vos/role-authorization/service", &self.encode())
    }

    /// Reply shape the authority service must commit for this decision.
    pub fn authority_reply(&self, authority: ActorId) -> ReplyRecord {
        ReplyRecord {
            call_id: self.authority_invocation().root_reply_id(),
            producer: authority,
            // Generated actor methods returning `Vec<u8>` use the canonical
            // dynamic actor ABI: the bytes are framed as `Value::Bytes`.
            result: crate::Encode::encode(&crate::value::Value::Bytes(self.encode())),
        }
    }
}

/// Receipt-bound role assertion carried by a future disclosed credential or
/// private authorization witness. Guest Accumulate still asks the platform
/// receipt verifier for finality; this type proves that the finalized reply is
/// the exact invocation-scoped claim issued by the pinned authority service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulatedRoleAssertion {
    pub claim: RoleAuthorizationClaim,
    pub receipt: AccumulationReceipt,
}

impl AccumulatedRoleAssertion {
    pub fn matches_authority(&self, authority: &RoleAuthorityBinding) -> bool {
        self.claim.space == authority.service.space
            && self.receipt.service == authority.service
            && self.receipt.reply_commitment
                == Some(self.claim.authority_reply(authority.actor).commitment())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRef {
    pub hash: Hash,
    pub len: u64,
}

impl BlobRef {
    /// Construct a content reference for bytes imported into or exported from
    /// a VOS service service invocation.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self {
            hash: Hash::digest(b"vos/blob/service", &[bytes]),
            len: bytes.len() as u64,
        }
    }

    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.len == bytes.len() as u64 && *self == Self::of_bytes(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedActor {
    pub actor: ActorId,
    pub name: String,
    pub parent: Option<ActorId>,
    /// Exact signed package supplying this actor's code and policy surface.
    pub deployment: DeploymentId,
    pub program: ProgramId,
    /// Exact signed Task surface of this actor package. The executable bytes
    /// travel once in `RefineImports::programs`; this compact mapping binds
    /// the content address and witness window used by actor INVOKE.
    pub task_dependencies: Vec<TaskDependency>,
    /// First canonical state materialization for this actor at the work base.
    /// Linear work has exactly this state. CRDT work may additionally import
    /// concurrent frontier states which the actor PVM merges before dispatch.
    pub state: BlobRef,
    pub causal_states: Vec<BlobRef>,
    pub continuation: Option<BlobRef>,
    /// Base-authenticated point reads discovered before the final Refine run.
    /// A missing value is witnessed explicitly so an actor cannot confuse an
    /// absent row with an omitted witness. Storage witnesses are linear-only;
    /// CRDT actors use field-operation materializations instead.
    pub storage_rows: Vec<ActorStorageRow>,
}

/// One actor-local storage row at the exact linear work base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorStorageRow {
    pub key: Vec<u8>,
    /// Content address of the row bytes supplied only to Refine. Keeping the
    /// potentially large value out of `WorkEnvelope` also keeps exact
    /// resume tokens compact; guest Accumulate authenticates this reference
    /// by hashing the row at the committed linear base.
    pub value: Option<BlobRef>,
}

/// Host-local request emitted when speculative Refine discovers a row that
/// was not yet carried by the authenticated work envelope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActorStorageKey {
    pub actor: ActorId,
    pub key: Vec<u8>,
}

/// Compact guest-owned binding for one content-addressed pure Task.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TaskDependency {
    /// Hash used by `Tasks::spawn*` and the INVOKE wire.
    pub task: Hash,
    /// Canonical executable identity in the service program catalog.
    pub program: ProgramId,
    /// Flat-memory witness window preserved from the signed Task ELF.
    pub witness_address: u32,
    pub witness_capacity: u32,
}

/// Exact root-tree member materialized into an actor's invocation-owned IPC
/// input. Its canonical list index selects the CALLABLE slot granted by the
/// generic service (`ACTOR_CALLABLE_BASE_SLOT + index`). This is deliberately
/// directory metadata only: sibling state remains private until an authorized
/// inline call actually enters that sibling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorTreeImport {
    pub actor: ActorId,
    pub name: String,
    pub parent: Option<ActorId>,
    pub deployment: DeploymentId,
    pub program: ProgramId,
}

/// Canonical code supplied to Refine. An ELF, JIT image, or proving artifact
/// is never accepted here: `pvm` is the exact executable/proof identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedProgram {
    pub program: ProgramId,
    pub pvm: Vec<u8>,
}

/// Content-addressed bytes supplied to Refine for one declared blob reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedBlob {
    pub reference: BlobRef,
    pub bytes: Vec<u8>,
}

/// Install-time authenticated binding to an actor owned by another root
/// service. Application code resolves `name`; the remaining identities are
/// consensus inputs and never come from an attestation package itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalActorBinding {
    pub name: String,
    pub service: ServiceIdentity,
    pub actor: ActorId,
    pub producer: ProducerId,
    pub actor_deployment: DeploymentId,
    pub program: ProgramId,
}

/// Canonical guest-owned dependency directory installed with one root tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalActorDirectory {
    pub actors: Vec<ExternalActorBinding>,
}

/// Complete immutable import set for one Refine execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefineImports {
    pub programs: Vec<ImportedProgram>,
    pub blobs: Vec<ImportedBlob>,
    /// Invocation-private witnesses supplied directly to Refine/proving.
    /// These bytes are never work imports, Accumulate candidates, CRDT sync
    /// payloads, or recoverable service-state blobs.
    pub private_blobs: Vec<ImportedBlob>,
}

/// Input placed in the invocation-owned IPC DATA capability before the
/// generic service CALLs an actor VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorSliceInput {
    pub actor: ActorId,
    /// First tree-wide await ordinal available to this actor and its inline
    /// descendants.
    pub first_await_ordinal: u64,
    /// Canonical generated actor-message bytes.
    pub message: Vec<u8>,
}

/// Invocation-private input returned only to the currently active actor VM.
///
/// The generic service host derives `actor` and `origin` from PVM's live CALL
/// stack. A parent actor therefore receives no sibling materialization and
/// cannot impersonate another same-tree caller by rewriting the shared IPC
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorPrivateInput {
    pub actor: ActorId,
    /// Complete host-derived root-tree directory. It shares no page with
    /// caller-controlled actor IPC, so a nested caller cannot remap another
    /// actor's directory-indexed CALLABLE slots.
    pub actor_tree: Vec<ActorTreeImport>,
    /// Install-time authenticated cross-root dependencies. This directory is
    /// host-private for the same reason as `actor_tree`: a nested caller must
    /// not substitute a different recipient or producer identity.
    pub external_actors: Vec<ExternalActorBinding>,
    /// Canonical identity of the workflow slice executing this actor.
    pub input: WorkInputId,
    /// Batch identity and scheduler dispatch ordinal allocated by the generic
    /// service. Present only for an explicitly CRDT service.
    pub change: Option<CrdtDispatch>,
    pub state: Vec<u8>,
    /// Additional canonical CRDT frontier materializations. The generated
    /// actor merger folds these into `state` before the message is observed.
    pub causal_states: Vec<Vec<u8>>,
    /// Scheduler-derived actor-tree-indexed set of the active same-tree call
    /// stack, including `actor`. Actor IPC cannot rewrite this value.
    pub active_actor_mask: u64,
    pub origin: Origin,
    /// Exact root service which authenticated an [`Origin::Actor`].
    ///
    /// Cross-root work derives this from the committed causal call context;
    /// inline calls derive it from the currently executing root. Actor IDs are
    /// intentionally reusable across roots, so the actor identity alone is
    /// never sufficient to authorize an irreversible destination operation.
    /// Non-actor origins must carry `None`.
    pub origin_service: Option<ServiceIdentity>,
    /// Authenticated role recovered from the disclosed credential or private
    /// witness before entering the canonical actor PVM.
    pub space_role: Option<u8>,
    pub actor_role: Option<u8>,
}

/// Minimal result visible to an inline same-tree caller.
///
/// Actor state and buffered effects travel over the private scheduler
/// capability instead; a caller observes only the method result and durable
/// checkpoint control flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorCallResult {
    pub actor: ActorId,
    pub first_await_ordinal: u64,
    /// First tree-wide await ordinal not consumed by this actor subtree.
    pub next_await_ordinal: u64,
    pub reply: Vec<u8>,
    pub yielded: bool,
    pub forbidden: bool,
    pub checkpoint: Option<CheckpointToken>,
}

/// Latest actor-local CRDT materialization produced by one or more inline
/// dispatches in the same outer Refine slice.
///
/// `next_dispatch_ordinal` is owned by the generic service scheduler. It
/// prevents a repeated call to one actor from reusing an operation namespace
/// while keeping sibling state out of caller-visible IPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorCrdtState {
    pub actor: ActorId,
    pub state: Vec<u8>,
    pub next_dispatch_ordinal: u32,
}

/// Actor-to-service request to create one same-package owned child. Refine
/// content-addresses `initial_state` before placing the request in a
/// transition; no actor can select a different program or policy surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorSpawnRequest {
    pub actor: ActorId,
    pub name: String,
    pub parent: ActorId,
    pub initial_state: Vec<u8>,
}

/// Canonical child creation committed atomically with one linear actor slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorSpawn {
    pub actor: ActorId,
    pub name: String,
    pub parent: ActorId,
    pub initial_state: BlobRef,
}

/// Opaque per-dispatch effects returned to the generic service VM after the
/// root actor stack unwinds. Temporal order is execution order; the service
/// guest canonicalizes the final transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorEffectBatch {
    pub outputs: Vec<ActorSliceOutput>,
}

/// Unique operation-allocation namespace for one actor dispatch inside a CRDT
/// execution slice. A scheduler must never reuse `ordinal` within one change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrdtDispatch {
    pub change: ChangeId,
    pub ordinal: u32,
}

impl ActorPrivateInput {
    pub fn actor_import(&self, actor: ActorId) -> Option<&ActorTreeImport> {
        self.actor_tree
            .binary_search_by_key(&actor, |candidate| candidate.actor)
            .ok()
            .map(|index| &self.actor_tree[index])
    }

    pub fn resolve_owned(&self, parent: Option<ActorId>, name: &str) -> Option<ActorId> {
        self.actor_tree
            .iter()
            .find(|actor| actor.parent == parent && actor.name == name)
            .map(|actor| actor.actor)
    }

    /// Actor-local directory slot for a same-tree peer. Availability is
    /// enforced by the live PVM CNode: the scheduler omits or revokes the
    /// CALLABLE for suspended actors, including after snapshot restore.
    pub fn callable_slot(&self, actor: ActorId) -> Option<u8> {
        let index = self
            .actor_tree
            .binary_search_by_key(&actor, |candidate| candidate.actor)
            .ok()?;
        let imported = &self.actor_tree[index];
        if imported.actor == self.actor {
            return None;
        }
        super::ACTOR_CALLABLE_BASE_SLOT.checked_add(index as u8)
    }
}

/// Actor-produced result returned through the same IPC DATA capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorSliceOutput {
    pub actor: ActorId,
    pub first_await_ordinal: u64,
    /// First tree-wide await ordinal not consumed by this actor tree slice.
    pub next_await_ordinal: u64,
    pub writes: Vec<ActorWrite>,
    /// Concrete field operations emitted by one `#[actor(crdt)]` execution
    /// slice. Ordinary actors always leave this empty.
    pub crdt_operations: Vec<CrdtOperation>,
    /// Final canonical materializations for the CRDT actors executed by this
    /// subtree. An individual actor export contains exactly its own entry;
    /// the generic service aggregates the final entry for every actor.
    pub crdt_states: Vec<ActorCrdtState>,
    /// Same-package owned children requested by actors executed in this slice.
    pub spawns: Vec<ActorSpawnRequest>,
    /// Cross-root calls emitted by this slice. The owning service derives each
    /// stable `CallId` from the work invocation and `await_ordinal`.
    pub outbox: Vec<ActorCallRequest>,
    pub reply: Vec<u8>,
    pub yielded: bool,
    pub forbidden: bool,
    /// Present after a restored continuation or when this slice creates a new
    /// durable checkpoint. The generic service uses it to bind the transition
    /// to the current base and atomically replace/delete continuation state.
    pub checkpoint: Option<CheckpointToken>,
}

/// Pure host-to-guest handoff written only after PVM captured the exact
/// pre-result machine snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointToken {
    pub input: WorkInputId,
    pub base: ConsistencyBase,
    /// Hash of the current work envelope. A restored service frame still
    /// contains the envelope from the slice that created the checkpoint, so
    /// the host must bind the resumed slice explicitly.
    pub work_hash: Hash,
    // The exact work envelope is deliberately absent from this actor-visible
    // control token. A restored infrastructure service VM fetches it over a
    // host-private Refine channel and authenticates it against `work_hash`.
    // This keeps as many as 256 storage-witness keys and references out of
    // the fixed 4 KiB suspension buffer without weakening the committed
    // read-set binding.
    /// Causal height of `base` for a CRDT slice. Linear slices carry `None`.
    pub base_causal_height: Option<u64>,
    /// Fresh allocator namespace installed after an exact CRDT resume.
    pub change: Option<CrdtDispatch>,
    pub expected: Option<Hash>,
    pub replacement: Option<BlobRef>,
    pub pending_call: Option<CallId>,
    /// Exact actor VM which issued `pending_call`, derived from the live PVM
    /// stack by the scheduler. `None` for an explicit yield.
    pub pending_actor: Option<ActorId>,
    /// Actors locked by the continuation being replaced or deleted.
    pub previously_suspended: Vec<ActorId>,
    /// Exact actor stack locked by `replacement`. Empty when the workflow
    /// completes and deletes its continuation.
    pub suspended: Vec<ActorId>,
}

/// Actor-to-scheduler portion of a durable cross-root call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorCallRequest {
    pub await_ordinal: u64,
    pub from: ActorId,
    /// Exact installed root service which owns `to`. The actor VM obtains
    /// this identity from its authenticated external directory; transport
    /// may not select a different root which happens to reuse the ActorId.
    pub to_service: ServiceIdentity,
    pub to: ActorId,
    pub payload: Vec<u8>,
    pub authorization: AuthorizationEvidence,
    /// The caller used an attested generated handle and therefore requires a
    /// proof package, not merely the committed reply value.
    pub proof_requested: bool,
    pub deadline_timeslot: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkEnvelope {
    pub service: ServiceIdentity,
    /// Stable identity of the complete workflow across durable awaits.
    pub invocation: InvocationId,
    /// Zero-based execution slice within `invocation`. Each committed await
    /// advances this value, so retries deduplicate without conflating later
    /// checkpoints with the first transition.
    pub workflow_step: u64,
    /// Consensus-supplied service platform logical timeslot at which this work item is
    /// scheduled. Durable deadlines are compared only to this input, never to
    /// a wall clock.
    pub logical_timeslot: u64,
    pub target: ActorId,
    pub target_deployment: DeploymentId,
    pub target_program: ProgramId,
    pub method: String,
    pub arguments: Vec<u8>,
    /// Content address of producer-private step-zero arguments. The Refine
    /// request carries the plaintext transiently, while guest-owned ingress
    /// and workflow rows retain only this reference. Private-input slices may
    /// not suspend, so no kernel snapshot can persist the hydrated bytes.
    pub private_arguments: Option<BlobRef>,
    pub origin: Origin,
    pub authorization: AuthorizationEvidence,
    pub causal_parent: Option<InvocationId>,
    pub parent_call: Option<CallId>,
    /// Authenticated metadata for `parent_call`. Unlike the consumable inbox
    /// row, this compact context survives every continuation slice so causal
    /// cycle and inherited-deadline checks do not depend on deleted state.
    pub causal_context: Option<CausalCallContext>,
    /// Present only when restoring a continuation waiting on a committed
    /// cross-root result. The reply is admitted by guest Accumulate before
    /// Refine may inject it at the captured protocol-call boundary.
    pub awaited_reply: Option<AccumulatedReply>,
    /// Present only after guest Accumulate atomically expires the pending
    /// cross-root outbox row at a consensus logical timeslot. The timeout is
    /// injected at the captured call boundary without replaying the handler.
    /// Heap-backed so the complete receipt-bound timeout does not enlarge
    /// every workflow operation on the service PVM's bounded stack. The
    /// canonical wire is unchanged.
    pub awaited_timeout: Option<Box<AccumulatedTimeout>>,
    pub consistency: ConsistencyMode,
    pub base: ConsistencyBase,
    /// Maximum causal height among `base` heads. Present only for CRDT work;
    /// Accumulate recomputes it from committed parent nodes before accepting
    /// the child change.
    pub base_causal_height: Option<u64>,
    pub imported_actors: Vec<ImportedActor>,
    /// Complete install-time authenticated cross-root dependency directory.
    /// Accumulate compares it byte-for-byte with guest-owned state, so Refine
    /// cannot substitute a different name or producer binding.
    pub external_actors: Vec<ExternalActorBinding>,
    pub imported_blobs: Vec<BlobRef>,
    pub proof_requested: bool,
}

impl WorkEnvelope {
    pub const fn input_id(&self) -> WorkInputId {
        WorkInputId {
            invocation: self.invocation,
            workflow_step: self.workflow_step,
        }
    }

    /// Consensus identity of the complete work input, including origin,
    /// authorization evidence, consistency base, and every import reference.
    pub fn hash(&self) -> Hash {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&Self::MAGIC);
        bytes.extend_from_slice(&super::PLATFORM_ID.0);
        self.encode_body_with_arguments(
            &mut bytes,
            if self.private_arguments.is_some() {
                &[]
            } else {
                &self.arguments
            },
        );
        Hash::digest(b"vos/work/service", &[&bytes])
    }

    /// Intent that a role authority signs for one invocation.
    ///
    /// The consistency frontier and scheduler timeslot are excluded so stale
    /// work may be rescheduled without minting a new credential. Actor,
    /// deployment, invocation, method, arguments, origin, causal identity,
    /// and proof mode are included, preventing a disclosed credential from
    /// being replayed for another call or service.
    pub fn authorization_scope(&self) -> Hash {
        let mut bytes = Vec::new();
        let mut e = Encoder(&mut bytes);
        encode_service(&mut e, &self.service);
        e.fixed(&self.invocation.0);
        e.fixed(&self.target.0);
        e.fixed(&self.target_deployment.0);
        e.fixed(&self.target_program.0);
        e.string(&self.method);
        e.option(&self.private_arguments, encode_blob_ref);
        if self.private_arguments.is_none() {
            e.bytes(&self.arguments);
        }
        encode_origin(&mut e, self.origin);
        e.option(&self.causal_parent, |e, id| e.fixed(&id.0));
        e.option(&self.parent_call, |e, id| e.fixed(&id.0));
        e.option(&self.causal_context, encode_causal_context);
        e.bool(self.proof_requested);
        Hash::digest(b"vos/authorization-scope/service", &[&bytes])
    }

    /// Stable identity shared by every slice of one suspended workflow.
    /// Volatile scheduling inputs (step, timeslot, arguments, consistency
    /// frontier, and imported state) are deliberately excluded; service,
    /// actor/program, method, caller, authorization, and consistency mode are
    /// not allowed to change while an exact continuation is live.
    pub fn workflow_identity(&self) -> Hash {
        let mut bytes = Vec::new();
        let mut e = Encoder(&mut bytes);
        encode_service(&mut e, &self.service);
        e.fixed(&self.invocation.0);
        e.fixed(&self.target.0);
        e.fixed(&self.target_deployment.0);
        e.fixed(&self.target_program.0);
        e.string(&self.method);
        e.option(&self.private_arguments, encode_blob_ref);
        encode_origin(&mut e, self.origin);
        encode_auth(&mut e, &self.authorization);
        e.list(&self.external_actors, encode_external_actor);
        e.option(&self.causal_parent, |e, id| e.fixed(&id.0));
        e.option(&self.parent_call, |e, id| e.fixed(&id.0));
        e.option(&self.causal_context, encode_causal_context);
        e.u8(self.consistency as u8);
        e.bool(self.proof_requested);
        Hash::digest(b"vos/workflow/service", &[&bytes])
    }

    /// Canonical CRDT workflow record retained in the causal DAG. Scheduling
    /// time, an already-consumed awaited reply, and actor materialization
    /// references are slice-local imports rather than resume instructions.
    /// Normalizing them lets an exact restored service VM emit the same
    /// checkpoint as guest Accumulate derives from the newly admitted work.
    pub fn workflow_checkpoint(&self) -> Self {
        let mut checkpoint = self.durable_work();
        checkpoint.logical_timeslot = 0;
        checkpoint.awaited_reply = None;
        checkpoint.awaited_timeout = None;
        // Direct CRDT ingress retains disclosed credential bytes once in its
        // content-addressed admission blob. Repeating the authority assertion
        // in every causal workflow checkpoint needlessly multiplies the
        // bounded guest heap and the synchronization payload. Inbox-backed
        // workflows keep their complete authorization because they have no
        // direct-ingress blob from which a scheduler can rehydrate it.
        if checkpoint.consistency == ConsistencyMode::Crdt
            && checkpoint.parent_call.is_none()
            && let AuthorizationEvidence::Credential { bytes, .. } = &mut checkpoint.authorization
        {
            bytes.clear();
        }
        let empty = BlobRef::of_bytes(&[]);
        for actor in &mut checkpoint.imported_actors {
            actor.state = empty.clone();
            actor.causal_states.clear();
            actor.continuation = None;
            actor.storage_rows.clear();
        }
        checkpoint
    }

    /// Exact linear work retained in guest-owned workflow state. Private
    /// arguments are represented only by their committed sidecar reference;
    /// every other field remains byte-identical to the applied slice.
    pub fn durable_work(&self) -> Self {
        let mut work = self.clone();
        if work.private_arguments.is_some() {
            work.arguments.clear();
        }
        work
    }

    /// Logical CRDT execution identity shared by independently scheduled
    /// retries. Dynamic causal imports, the observed base, and the trusted
    /// scheduling slot may differ; every caller-controlled input and exact
    /// awaited outcome must remain identical.
    pub fn matches_crdt_retry(&self, candidate: &Self) -> bool {
        self.input_id() == candidate.input_id()
            && self.workflow_identity() == candidate.workflow_identity()
            && self.arguments == candidate.arguments
            && match (&self.awaited_reply, &candidate.awaited_reply) {
                (Some(left), Some(right)) => left.logical_identity() == right.logical_identity(),
                (None, None) => true,
                _ => false,
            }
            && self.awaited_timeout == candidate.awaited_timeout
            && self.imported_blobs == candidate.imported_blobs
            && self.imported_actors.len() == candidate.imported_actors.len()
            && self
                .imported_actors
                .iter()
                .zip(&candidate.imported_actors)
                .all(|(left, right)| {
                    left.actor == right.actor
                        && left.name == right.name
                        && left.parent == right.parent
                        && left.deployment == right.deployment
                        && left.program == right.program
                })
    }

    /// Stable operation-allocation identity for one logical CRDT slice.
    /// Physical DAG nodes still bind the exact work hash, including the
    /// trusted slot and observed causal base; actor operation IDs deliberately
    /// omit only those scheduler-owned observations so concurrent retries do
    /// not apply the same logical mutation twice.
    pub fn crdt_retry_commitment(&self) -> Option<Hash> {
        let ConsistencyBase::Crdt { .. } = self.base else {
            return None;
        };
        let mut normalized = self.clone();
        normalized.logical_timeslot = 0;
        // Await outcomes are consumed inputs, not durable resume
        // instructions, and are already removed from the canonical workflow
        // checkpoint. Divergent outcomes still produce divergent operations,
        // materializations, or replies and are rejected during retry-branch
        // comparison.
        normalized.awaited_reply = None;
        normalized.awaited_timeout = None;
        normalized.base = ConsistencyBase::Crdt { heads: Vec::new() };
        normalized.base_causal_height = Some(0);
        let empty = BlobRef::of_bytes(&[]);
        for actor in &mut normalized.imported_actors {
            actor.state = empty.clone();
            actor.causal_states.clear();
            actor.continuation = None;
            actor.storage_rows.clear();
        }
        Some(Hash::digest(
            b"vos/crdt-retry/service",
            &[&normalized.encode()],
        ))
    }
}

/// Exactly-once identity of one consumable workflow slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkInputId {
    pub invocation: InvocationId,
    pub workflow_step: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorWrite {
    pub actor: ActorId,
    pub key: Vec<u8>,
    /// `None` deletes the row. The actor itself is never represented by a
    /// magic storage key.
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrdtOperation {
    pub actor: ActorId,
    /// Scheduler order of this actor dispatch within the complete slice.
    pub dispatch_ordinal: u32,
    /// Generated stable field tag, independent of the field's source order.
    pub field: Hash,
    /// Mutation emission order within the actor dispatch.
    pub ordinal: u32,
    pub id: OperationId,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrdtMaterialization {
    pub actor: ActorId,
    pub state: BlobRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationChange {
    pub actor: ActorId,
    pub expected: Option<Hash>,
    pub replacement: Option<BlobRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRecord {
    pub call_id: CallId,
    pub caller_invocation: InvocationId,
    pub await_ordinal: u64,
    /// Exact source root which committed this message in its outbox.
    pub from_service: ServiceIdentity,
    pub from: ActorId,
    /// Exact destination root committed by the caller's installed external
    /// directory. Delivery must enter this service identity.
    pub to_service: ServiceIdentity,
    pub to: ActorId,
    pub parent: Option<CallId>,
    pub payload: Vec<u8>,
    pub authorization: AuthorizationEvidence,
    pub proof_requested: bool,
    pub deadline_timeslot: Option<u64>,
}

impl MessageRecord {
    pub fn commitment(&self) -> Hash {
        let mut bytes = Vec::new();
        encode_message(&mut Encoder(&mut bytes), self);
        Hash::digest(b"vos/message/service", &[&bytes])
    }

    /// Commitment carried by the source accumulation receipt. Delivery sends
    /// the complete canonical outbox so destination Accumulate can verify
    /// membership without trusting transport-selected message bytes.
    pub fn outbox_commitment(messages: &[Self]) -> Option<Hash> {
        if messages.is_empty() {
            return None;
        }
        let mut bytes = Vec::new();
        Encoder(&mut bytes).list(messages, encode_message);
        Some(Hash::digest(b"vos/outbox/service", &[&bytes]))
    }

    /// Canonical destination authorization projection for durable step-zero
    /// work. Hosts use it to request a scoped authority decision; guest
    /// Accumulate uses the same projection when verifying that decision.
    pub fn authorization_work(
        &self,
        service: &ServiceIdentity,
        logical_timeslot: u64,
        authorization: AuthorizationEvidence,
        consistency: ConsistencyMode,
        base: ConsistencyBase,
        actor: &ActorGenesis,
    ) -> Option<WorkEnvelope> {
        if self.authorization != AuthorizationEvidence::Public
            || self.to_service != *service
            || self.to != actor.actor
        {
            return None;
        }
        let method = if self.payload.first() == Some(&crate::value::TAG_DYNAMIC) {
            <crate::value::Msg as crate::Decode>::try_decode(&self.payload[1..])
                .map(|message| message.name)
        } else {
            None
        }?;
        Some(WorkEnvelope {
            service: service.clone(),
            invocation: InvocationId::for_call(self.call_id),
            workflow_step: 0,
            logical_timeslot,
            target: self.to,
            target_deployment: actor.deployment,
            target_program: actor.program,
            method,
            arguments: self.payload.clone(),
            private_arguments: None,
            origin: Origin::Actor(self.from),
            authorization,
            causal_parent: Some(self.caller_invocation),
            parent_call: Some(self.call_id),
            causal_context: Some(CausalCallContext::from(self)),
            awaited_reply: None,
            awaited_timeout: None,
            consistency,
            base,
            base_causal_height: None,
            imported_actors: Vec::new(),
            external_actors: Vec::new(),
            imported_blobs: Vec::new(),
            proof_requested: self.proof_requested,
        })
    }
}

/// Compact authenticated portion of a durable parent call retained after its
/// inbox row is consumed at step 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CausalCallContext {
    pub call_id: CallId,
    pub caller_invocation: InvocationId,
    pub from_service: ServiceIdentity,
    pub from: ActorId,
    pub to: ActorId,
    pub parent: Option<CallId>,
    pub deadline_timeslot: Option<u64>,
}

impl From<&MessageRecord> for CausalCallContext {
    fn from(message: &MessageRecord) -> Self {
        Self {
            call_id: message.call_id,
            caller_invocation: message.caller_invocation,
            from_service: message.from_service.clone(),
            from: message.from,
            to: message.to,
            parent: message.parent,
            deadline_timeslot: message.deadline_timeslot,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyRecord {
    pub call_id: CallId,
    pub producer: ActorId,
    pub result: Vec<u8>,
}

impl ReplyRecord {
    /// Commitment transported in the accumulation receipt before the reply is
    /// released to a caller.
    pub fn commitment(&self) -> Hash {
        let mut bytes = Vec::new();
        encode_reply(&mut Encoder(&mut bytes), self);
        Hash::digest(b"vos/reply/service", &[&bytes])
    }
}

/// Receipt-bound attestation metadata released with a committed reply. Proof
/// bytes remain content addressed; the destination imports and verifies the
/// exact blob before injecting it into a restored actor VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationDelivery {
    pub producer_name: String,
    pub producer: ProducerId,
    pub statement: AttestationStatement,
    pub proof: ProofCommitment,
}

/// A reply released by another service only after its Accumulate commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulatedReply {
    pub reply: ReplyRecord,
    pub receipt: AccumulationReceipt,
    pub attestation: Option<Box<AttestationDelivery>>,
}

/// Deterministic result of expiring one durable cross-root call. Deadlines
/// and observation times are service platform logical timeslots, never wall-clock values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallTimeout {
    pub call_id: CallId,
    pub caller_invocation: InvocationId,
    /// Exact installed actor which emitted the durable outbox row. This lets
    /// replicas authenticate a standalone CRDT expiration receipt without
    /// trusting a transport-selected producer.
    pub caller_actor: ActorId,
    /// Workflow slice whose durable checkpoint is waiting on this call.
    pub checkpoint_step: u64,
    pub await_ordinal: u64,
    pub deadline_timeslot: u64,
    pub expired_at: u64,
}

impl CallTimeout {
    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/call-timeout/service", &[&self.encode()])
    }
}

/// Guest-owned request to expire one pending outbox row. Linear services bind
/// the exact revision; CRDT services bind the observed causal frontier and a
/// workflow-only DAG node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallExpirationEnvelope {
    pub service: ServiceIdentity,
    pub timeout: CallTimeout,
    pub base: ConsistencyBase,
    pub base_causal_height: Option<u64>,
    pub crdt_change: Option<CrdtChange>,
}

impl CallExpirationEnvelope {
    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/call-expiration/service", &[&self.encode()])
    }
}

/// Receipt-bound timeout committed by the source service's Accumulate path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulatedTimeout {
    pub expiration: CallExpirationEnvelope,
    pub receipt: AccumulationReceipt,
}

impl AccumulatedTimeout {
    pub fn validate(&self) -> Result<(), DecodeError> {
        let accepted_transition = self.expiration.crdt_change.as_ref().map_or_else(
            || self.expiration.commitment(),
            CrdtChange::receipt_commitment,
        );
        if self.receipt.service != self.expiration.service
            || self.receipt.accepted_transition != accepted_transition
            || self.receipt.checkpoint != self.expiration.timeout.checkpoint_step
            || self.receipt.reply_commitment.is_some()
            || self.receipt.outbox_commitment.is_some()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl AccumulatedReply {
    /// Logical reply identity shared by equivalent finalized CRDT branches.
    /// The physical accumulation receipt is verification evidence, not part
    /// of the value injected into the caller. Attested replies retain their
    /// complete attestation identity because its proof is not reconstructible
    /// from causal workflow data alone.
    pub fn logical_identity(&self) -> Hash {
        let mut bytes = Vec::new();
        let mut encoder = Encoder(&mut bytes);
        // The producer service and its consistency/finality domain are part
        // of logical identity. Only branch-local receipt fields are omitted.
        encode_service(&mut encoder, &self.receipt.service);
        encoder.u8(self.receipt.consistency as u8);
        encode_reply(&mut encoder, &self.reply);
        encoder.option(&self.attestation, |encoder, attestation| {
            encoder.string(&attestation.producer_name);
            encoder.fixed(&attestation.producer.0);
            encoder.bytes(&attestation.statement.encode());
            encode_proof(encoder, &attestation.proof);
        });
        Hash::digest(b"vos/accumulated-reply-logical/service", &[&bytes])
    }

    pub fn validate(&self) -> Result<(), crate::AttestationError> {
        if self.receipt.reply_commitment != Some(self.reply.commitment()) {
            return Err(crate::AttestationError::ReceiptMismatch);
        }
        if let Some(attestation) = &self.attestation {
            if attestation.producer_name.is_empty()
                || attestation.producer_name != attestation.statement.producer_name
            {
                return Err(crate::AttestationError::WrongProducer);
            }
            if attestation.producer != attestation.statement.producer {
                return Err(crate::AttestationError::WrongProducer);
            }
            validate_attestation_delivery(
                &self.reply,
                &self.receipt,
                &attestation.statement,
                &attestation.proof,
            )?;
        }
        Ok(())
    }
}

/// Attestation package placed in the guest-owned suspension buffer. The
/// generic service resolves `proof.proof_blob` from Refine imports; native
/// transport cannot inject unrelated proof bytes into the actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationResume {
    pub producer_name: String,
    pub producer: ProducerId,
    pub statement: AttestationStatement,
    pub proof: ProofCommitment,
    /// Byte window in the invocation-owned actor IPC capability. The generic
    /// service writes the imported proof there before resuming PVM; only this
    /// small descriptor crosses the bounded protocol-call stack buffer.
    pub proof_offset: u32,
    pub proof_len: u32,
}

/// Payload injected into the exact suspended protocol-call buffer after the
/// awaited result's accumulation receipt has been admitted as work input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwaitResume {
    pub checkpoint: CheckpointToken,
    pub reply: ReplyRecord,
    pub attestation: Option<Box<AttestationResume>>,
}

fn validate_attestation_delivery(
    reply: &ReplyRecord,
    receipt: &AccumulationReceipt,
    statement: &AttestationStatement,
    proof: &ProofCommitment,
) -> Result<(), crate::AttestationError> {
    statement.validate()?;
    if proof.proof_blob.len == 0
        || statement.actor != reply.producer
        || statement.accumulation_receipt != *receipt
        || statement.claim_commitment != Hash::digest(b"vos/attestation-claim", &[&reply.result])
        || proof.statement != statement.commitment()
    {
        return Err(crate::AttestationError::InvalidStatement);
    }
    Ok(())
}

/// Exact public input passed to the platform's accumulation-receipt verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptVerificationRequest {
    /// The actor the finalized service must own. A receipt cannot authenticate
    /// a reply merely by committing bytes that claim another actor as producer.
    pub expected_producer: ActorId,
    pub receipt: AccumulationReceipt,
}

impl ReceiptVerificationRequest {
    pub fn hash(&self) -> Hash {
        Hash::digest(b"vos/receipt-verification/service", &[&self.encode()])
    }
}

/// Fixed-schema workflow operations merged alongside application CRDT fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowOperation {
    /// Complete scheduler checkpoint for one admitted workflow slice. A peer
    /// syncing only the causal DAG can reconstruct the next exact resume input
    /// without process-local request state.
    Checkpoint(WorkEnvelope),
    Continuation(ContinuationChange),
    Inbox(MessageRecord),
    Outbox(MessageRecord),
    /// Causally consume the durable request completed by an awaited reply.
    /// The reply receipt itself is an accumulation input, not persistent
    /// workflow state copied into every later DAG node.
    ConsumeOutbox(CallId),
    /// Causally remove one pending outbox row and retain its deterministic
    /// logical-timeslot outcome for exact continuation resumption.
    ExpireCall(CallTimeout),
    Reply(ReplyRecord),
    /// Direct caller input admitted before actor execution. CRDT services
    /// carry this as its own causal node so a busy or restarted replica can
    /// recover the queued invocation without relying on host memory.
    Ingress(CrdtIngress),
    /// Finalized cross-root message admitted into a CRDT destination. The
    /// complete source receipt/outbox and destination observation are retained
    /// so another replica can reconstruct the permanent delivery identity as
    /// well as the visible inbox row from causal history alone.
    Delivery(DeliveryEnvelope),
}

/// Stable caller-controlled portion of a causal direct-ingress admission.
/// The surrounding [`DirectIngress`] supplies the observed causal base and
/// the exact change which contains this operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrdtIngress {
    pub service: ServiceIdentity,
    pub invocation: InvocationId,
    pub logical_timeslot: u64,
    pub target: ActorId,
    pub method: String,
    pub arguments: Vec<u8>,
    pub origin: Origin,
    pub authorization: AuthorizationEvidence,
    /// Content address of disclosed credential bytes. The causal operation
    /// binds the policy and credential commitment inline without retaining a
    /// second copy of the authority assertion.
    pub authorization_blob: Option<BlobRef>,
    pub imported_blobs: Vec<BlobRef>,
    pub proof_requested: bool,
}

impl CrdtIngress {
    /// Commitment shared by the admitted ingress record and its causal DAG
    /// node. It binds the complete admission observation; causal ancestry is
    /// additionally bound by the surrounding [`CrdtChange`].
    pub fn commitment(&self) -> Hash {
        let mut bytes = Vec::new();
        encode_crdt_ingress(&mut Encoder(&mut bytes), self);
        Hash::digest(b"vos/crdt-ingress/service", &[&bytes])
    }

    /// Stable caller intent shared by retries admitted at different trusted
    /// slots. Only the scheduler-owned observation time may differ here;
    /// causal ancestry lives on the containing change.
    pub fn matches_retry(&self, candidate: &Self) -> bool {
        self.service == candidate.service
            && self.invocation == candidate.invocation
            && self.target == candidate.target
            && self.method == candidate.method
            && self.arguments == candidate.arguments
            && self.origin == candidate.origin
            && self.authorization == candidate.authorization
            && self.authorization_blob == candidate.authorization_blob
            && self.imported_blobs == candidate.imported_blobs
            && self.proof_requested == candidate.proof_requested
    }

    /// Bind the causal operation to every non-authorization field of its
    /// compact direct-admission carrier. CRDT authorization lives only here;
    /// the outer field is a canonical public sentinel.
    pub fn matches_direct(&self, direct: &DirectIngress) -> bool {
        self.service == direct.service
            && self.invocation == direct.invocation
            && self.logical_timeslot == direct.logical_timeslot
            && self.target == direct.target
            && self.method == direct.method
            && self.arguments == direct.arguments
            && self.origin == direct.origin
            && match (
                &self.authorization,
                self.authorization_blob.as_ref(),
                &direct.authorization,
            ) {
                (AuthorizationEvidence::Public, None, AuthorizationEvidence::Public) => true,
                (
                    AuthorizationEvidence::Credential {
                        policy,
                        credential_commitment,
                        bytes,
                    },
                    Some(reference),
                    AuthorizationEvidence::Credential {
                        policy: direct_policy,
                        credential_commitment: direct_commitment,
                        bytes: direct_bytes,
                    },
                ) => {
                    bytes.is_empty()
                        && policy == direct_policy
                        && credential_commitment == direct_commitment
                        && reference.matches(direct_bytes)
                }
                (
                    AuthorizationEvidence::Credential { bytes, .. },
                    Some(reference),
                    AuthorizationEvidence::Public,
                ) => bytes.is_empty() && reference.len != 0,
                _ => false,
            }
            && self.imported_blobs == direct.imported_blobs
            && self.proof_requested == direct.proof_requested
    }

    /// A fresh admission must carry the disclosed credential in the outer
    /// request so guest Accumulate can verify it before retaining only its
    /// compact causal reference. The public outer sentinel is reserved for
    /// already-admitted rows reconstructed from the CRDT DAG.
    pub fn matches_fresh_direct(&self, direct: &DirectIngress) -> bool {
        self.matches_direct(direct)
            && matches!(
                (&self.authorization, &direct.authorization),
                (AuthorizationEvidence::Public, AuthorizationEvidence::Public)
                    | (
                        AuthorizationEvidence::Credential { .. },
                        AuthorizationEvidence::Credential { .. }
                    )
            )
    }
}

/// One atomic CRDT DAG payload for an entire actor execution slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrdtChange {
    pub id: ChangeId,
    /// Exact immutable work envelope whose deterministic execution emitted
    /// this physical causal branch.
    pub work_hash: Hash,
    pub causal_dependencies: Vec<Hash>,
    pub causal_height: u64,
    pub operations: Vec<CrdtOperation>,
    pub workflow: Vec<WorkflowOperation>,
    pub materializations: Vec<CrdtMaterialization>,
    /// Finalized reply consumed by this slice, retained outside the
    /// normalized workflow checkpoint. Replicas need the exact value to
    /// reconstruct the permanent reply-admission row after DAG sync.
    pub awaited_reply: Option<AccumulatedReply>,
    /// Every blob made externally visible by this slice. In the current ABI
    /// these are exactly the replacement continuation snapshots. Keeping the
    /// set in the causal node makes the receipt authenticate the same effects
    /// both at the original commit and after DAG rematerialization.
    pub exported_blobs: Vec<BlobRef>,
}

impl CrdtChange {
    pub fn derive_id(work: &WorkEnvelope) -> Option<ChangeId> {
        let ConsistencyBase::Crdt { .. } = &work.base else {
            return None;
        };
        Some(Self::derive_id_from_work_hash(work.hash()))
    }

    pub fn derive_id_from_work_hash(work_hash: Hash) -> ChangeId {
        let mut bytes = Vec::new();
        let mut e = Encoder(&mut bytes);
        e.fixed(&work_hash.0);
        ChangeId(Hash::digest(b"vos/crdt-change-id/service", &[&bytes]).0)
    }

    /// Logical actor-operation namespace shared by independently scheduled
    /// executions of the same invocation step. This is intentionally not the
    /// physical DAG-node ID returned by [`Self::derive_id`].
    pub fn derive_operation_scope(work: &WorkEnvelope) -> Option<ChangeId> {
        let retry = work.crdt_retry_commitment()?;
        Some(ChangeId(
            Hash::digest(b"vos/crdt-operation-scope/service", &[&retry.0]).0,
        ))
    }

    pub fn cid(&self) -> Hash {
        Hash::digest(b"vos/crdt-dag-node/service", &[&self.encode()])
    }

    /// Receipt identity for one exact CRDT node. Unlike membership in a
    /// later receipt's head set, this commitment cannot authenticate an
    /// unrelated transition which merely retains this node as an ancestor.
    pub fn receipt_commitment(&self) -> Hash {
        Self::receipt_commitment_from_cid(self.cid())
    }

    pub(crate) fn receipt_commitment_from_cid(cid: Hash) -> Hash {
        Hash::digest(b"vos/crdt-transition/service", &[&cid.0])
    }

    pub fn derive_expiration_id(
        service: &ServiceIdentity,
        timeout: &CallTimeout,
        heads: &[Hash],
    ) -> ChangeId {
        let mut bytes = Vec::new();
        let mut e = Encoder(&mut bytes);
        encode_service(&mut e, service);
        e.bytes(&timeout.encode());
        e.list(heads, |e, head| e.fixed(&head.0));
        ChangeId(Hash::digest(b"vos/crdt-expiration-id/service", &[&bytes]).0)
    }

    pub fn derive_ingress_id(ingress: &CrdtIngress, heads: &[Hash]) -> ChangeId {
        Self::derive_ingress_id_from_commitment(ingress.commitment(), heads)
    }

    pub(crate) fn derive_ingress_id_from_commitment(ingress: Hash, heads: &[Hash]) -> ChangeId {
        let mut bytes = Vec::new();
        let mut e = Encoder(&mut bytes);
        e.fixed(&ingress.0);
        e.list(heads, |e, head| e.fixed(&head.0));
        ChangeId(Hash::digest(b"vos/crdt-ingress-id/service", &[&bytes]).0)
    }

    /// Physical identity of one destination-side delivery observation. Exact
    /// retries on the same base reuse the node; retries admitted concurrently
    /// on another base remain distinct nodes and are contracted by their
    /// stable [`DeliveryEnvelope::retry_identity`].
    pub fn derive_delivery_id(delivery: &DeliveryEnvelope) -> ChangeId {
        ChangeId(Hash::digest(b"vos/crdt-delivery-id/service", &[&delivery.commitment().0]).0)
    }

    /// Actor whose finalized service receipt authenticates this causal node.
    /// Platform-only ingress and expiration nodes name their actor directly;
    /// an execution slice must contain exactly one checkpoint producer.
    pub fn expected_producer(&self) -> Option<ActorId> {
        if let [WorkflowOperation::ExpireCall(timeout)] = self.workflow.as_slice() {
            return Some(timeout.caller_actor);
        }
        if let [WorkflowOperation::Ingress(ingress)] = self.workflow.as_slice() {
            return Some(ingress.target);
        }
        if let [WorkflowOperation::Delivery(delivery)] = self.workflow.as_slice() {
            return Some(delivery.message.to);
        }
        let mut checkpoints = self.workflow.iter().filter_map(|operation| {
            if let WorkflowOperation::Checkpoint(work) = operation {
                Some(work.target)
            } else {
                None
            }
        });
        let producer = checkpoints.next()?;
        checkpoints.next().is_none().then_some(producer)
    }

    /// Reconstruct the transport-visible effects committed directly in this
    /// causal node. Proof packages intentionally live outside the DAG, so a
    /// proof-bearing checkpoint requires its durable publication row.
    pub(crate) fn published_effects(&self) -> Result<Option<PublishedEffects>, ()> {
        let mut reply = None;
        let mut outbox = Vec::new();
        for operation in &self.workflow {
            match operation {
                WorkflowOperation::Checkpoint(work) if work.proof_requested => return Ok(None),
                WorkflowOperation::Reply(candidate) if reply.is_none() => {
                    reply = Some(candidate.clone());
                }
                WorkflowOperation::Reply(_) => return Err(()),
                WorkflowOperation::Outbox(message) => outbox.push(message.clone()),
                _ => {}
            }
        }
        outbox.sort_by_key(|message| message.call_id);
        Ok(Some(PublishedEffects {
            reply,
            outbox,
            exported_blobs: self.exported_blobs.clone(),
            proof: None,
            attestation: None,
        }))
    }

    /// Verify the service receipt against every effect and causal field
    /// committed by this exact node.
    pub(crate) fn matches_receipt(
        &self,
        service: &ServiceIdentity,
        receipt: &AccumulationReceipt,
    ) -> bool {
        let mut checkpoints = self
            .workflow
            .iter()
            .filter_map(|operation| match operation {
                WorkflowOperation::Checkpoint(work) => Some(work.workflow_step),
                WorkflowOperation::ExpireCall(timeout) => Some(timeout.checkpoint_step),
                WorkflowOperation::Ingress(_) | WorkflowOperation::Delivery(_) => Some(0),
                _ => None,
            });
        let Some(checkpoint) = checkpoints.next() else {
            return false;
        };
        if checkpoints.any(|candidate| candidate != checkpoint) {
            return false;
        }
        let mut replies = self
            .workflow
            .iter()
            .filter_map(|operation| match operation {
                WorkflowOperation::Reply(reply) => Some(reply),
                _ => None,
            });
        let reply_commitment = replies.next().map(ReplyRecord::commitment);
        if replies.next().is_some() {
            return false;
        }
        let outbox = self
            .workflow
            .iter()
            .filter_map(|operation| match operation {
                WorkflowOperation::Outbox(message) => Some(message.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        receipt.service == *service
            && receipt.accepted_transition == self.receipt_commitment()
            && receipt.reply_commitment == reply_commitment
            && receipt.outbox_commitment == MessageRecord::outbox_commitment(&outbox)
            && receipt.resulting_state_root.is_none()
            && receipt
                .resulting_crdt_heads
                .binary_search(&self.cid())
                .is_ok()
            && receipt.sequence == self.causal_height
            && receipt.checkpoint == checkpoint
            && receipt.consistency == ConsistencyMode::Crdt
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GasAccounting {
    pub refine_used: u64,
    pub proof_used: u64,
    pub accumulate_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofCommitment {
    pub statement: Hash,
    pub trace: Hash,
    pub proof_blob: BlobRef,
}

/// Bounded root artifact for a streamed production proof.
///
/// [`ProofCommitment::proof_blob`] addresses the encoding of this manifest;
/// each listed segment lives independently in the verifier's durable CAS.
/// Segment order is significant because adjacent STARK segments prove
/// boundary continuity. The manifest remains the one compact proof object on
/// service wires while segment bodies stay below the node frame ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationProofManifest {
    pub proof_system: Hash,
    pub initial_root: Hash,
    pub segments: Vec<ProofArtifactId>,
}

/// Content identifier in the producer/verifier proof CAS. This intentionally
/// does not reuse [`BlobRef`]: the deployed prover already publishes
/// segment bodies through the node CAS's native hash domain, and their exact
/// length is checked when the verifier fetches each bounded frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProofArtifactId(pub [u8; 32]);

impl AttestationProofManifest {
    pub fn proof_system() -> Hash {
        Hash::digest(
            b"vos/attestation-proof-system/service",
            &[&super::EXECUTION_SEMANTICS_ID.0],
        )
    }
}

/// Exact public inputs passed from guest Accumulate to the configured proof
/// verifier capability. Proof bytes remain content addressed and are read by
/// the host from `proof_blob`; the guest never trusts a host-supplied claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofVerificationRequest {
    pub actor_program: ProgramId,
    pub execution_semantics: Hash,
    pub statement: Hash,
    pub trace: Hash,
    pub proof_blob: BlobRef,
}

impl ProofVerificationRequest {
    pub fn hash(&self) -> Hash {
        Hash::digest(b"vos/proof-verification/service", &[&self.encode()])
    }
}

/// Consensus-authoritative verification input for one disclosed role
/// credential. The authority checks the authenticator over the credential's
/// invocation-specific scope; guest Accumulate separately checks the decoded
/// holder and role thresholds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleCredentialVerificationRequest {
    pub service: ServiceIdentity,
    pub actor: ActorId,
    pub policy: Hash,
    pub scope: Hash,
    pub credential_commitment: Hash,
    pub credential: Vec<u8>,
}

impl RoleCredentialVerificationRequest {
    pub fn hash(&self) -> Hash {
        Hash::digest(
            b"vos/role-credential-verification/service",
            &[&self.encode()],
        )
    }

    pub fn for_work(work: &WorkEnvelope) -> Option<Self> {
        let AuthorizationEvidence::Credential {
            policy,
            credential_commitment,
            bytes,
        } = &work.authorization
        else {
            return None;
        };
        let credential = RoleCredential::decode(bytes).ok()?;
        Some(Self {
            service: work.service.clone(),
            actor: work.target,
            policy: *policy,
            scope: credential.scope,
            credential_commitment: *credential_commitment,
            credential: bytes.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub service: ServiceIdentity,
    pub consumed_input: WorkInputId,
    pub target_deployment: DeploymentId,
    pub target_program: ProgramId,
    pub base: ConsistencyBase,
    pub writes: Vec<ActorWrite>,
    pub spawns: Vec<ActorSpawn>,
    pub crdt_change: Option<CrdtChange>,
    pub continuations: Vec<ContinuationChange>,
    pub inbox: Vec<MessageRecord>,
    pub outbox: Vec<MessageRecord>,
    pub reply: Option<ReplyRecord>,
    pub exported_blobs: Vec<BlobRef>,
    pub gas: GasAccounting,
    pub proof: Option<ProofCommitment>,
}

impl Transition {
    /// Hash of the complete transport value, including an attached proof.
    /// This is useful for blob/cache identity but is deliberately not the
    /// value accepted by an accumulation receipt.
    pub fn hash(&self) -> Hash {
        let encoded = self.encode();
        Hash::digest(b"vos/transition-wire/service", &[&encoded])
    }

    /// Consensus commitment to the actor execution before proof attachment.
    ///
    /// An attestation proves a statement containing the predicted accumulation
    /// receipt. The receipt therefore cannot commit to proof bytes which are
    /// generated from that same statement. Accumulate accepts this projection,
    /// while independently requiring and validating the proof for attested
    /// methods.
    pub fn commitment(&self) -> Hash {
        if let Some(change) = self.crdt_change.as_ref() {
            return change.receipt_commitment();
        }
        // Construct the projection directly. Cloning `self` first needlessly
        // allocates proof bytes in the guest before receipt construction; the
        // proof is explicitly outside this commitment and must not perturb
        // execution of the proved transition.
        let candidate = self.proofless_clone();
        Hash::digest(b"vos/transition/service", &[&candidate.encode()])
    }

    pub(crate) fn proofless_clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            consumed_input: self.consumed_input,
            target_deployment: self.target_deployment,
            target_program: self.target_program,
            base: self.base.clone(),
            writes: self.writes.clone(),
            spawns: self.spawns.clone(),
            crdt_change: self.crdt_change.clone(),
            continuations: self.continuations.clone(),
            inbox: self.inbox.clone(),
            outbox: self.outbox.clone(),
            reply: self.reply.clone(),
            exported_blobs: self.exported_blobs.clone(),
            gas: self.gas,
            proof: None,
        }
    }

    pub fn workflow_operations(&self, work: &WorkEnvelope) -> Vec<WorkflowOperation> {
        self.workflow_operations_with_consumed_outbox(
            work,
            work.awaited_reply
                .as_ref()
                .map(|awaited| awaited.reply.call_id)
                .or_else(|| {
                    work.awaited_timeout
                        .as_ref()
                        .map(|awaited| awaited.expiration.timeout.call_id)
                }),
        )
    }

    /// Build the canonical workflow payload when the exact restored service
    /// VM learns the consumed call from its checkpoint token rather than from
    /// the pre-suspension `WorkEnvelope` captured in that same snapshot.
    #[doc(hidden)]
    pub fn workflow_operations_with_consumed_outbox(
        &self,
        work: &WorkEnvelope,
        consumed_outbox: Option<CallId>,
    ) -> Vec<WorkflowOperation> {
        let mut operations = Vec::with_capacity(
            1 + self.continuations.len()
                + self.inbox.len()
                + self.outbox.len()
                + usize::from(consumed_outbox.is_some())
                + usize::from(self.reply.is_some()),
        );
        operations.push(WorkflowOperation::Checkpoint(work.workflow_checkpoint()));
        operations.extend(
            self.continuations
                .iter()
                .cloned()
                .map(WorkflowOperation::Continuation),
        );
        operations.extend(self.inbox.iter().cloned().map(WorkflowOperation::Inbox));
        operations.extend(self.outbox.iter().cloned().map(WorkflowOperation::Outbox));
        operations.extend(consumed_outbox.map(WorkflowOperation::ConsumeOutbox));
        operations.extend(self.reply.iter().cloned().map(WorkflowOperation::Reply));
        // Workflow encodings are required to be strictly unique, so stable
        // ordering has no semantic effect. The unstable sorter has a much
        // smaller stack profile in the bounded service PVM than slice's
        // stable drift sort for this large enum.
        operations.sort_unstable_by_key(workflow_operation_bytes);
        operations
    }
}

/// Pure physical Refine output. Candidate blob bytes are carried alongside
/// the transition instead of being written through a protocol capability;
/// Accumulate must independently validate and stage them before commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefineOutput {
    pub transition: Transition,
    pub candidate_blobs: Vec<ImportedBlob>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulationReceipt {
    pub service: ServiceIdentity,
    pub accepted_transition: Hash,
    /// Direct commitment to the reply released only after this commit.
    pub reply_commitment: Option<Hash>,
    /// Commitment to the complete canonical outbox released only after this
    /// commit. A destination receives these exact records with the finalized
    /// receipt and verifies membership inside guest Accumulate.
    pub outbox_commitment: Option<Hash>,
    pub resulting_state_root: Option<Hash>,
    pub resulting_crdt_heads: Vec<Hash>,
    pub sequence: u64,
    pub checkpoint: u64,
    pub consistency: ConsistencyMode,
}

/// Generated policy bound to one actor method at service installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodPolicy {
    pub method: String,
    pub schema: Hash,
    pub policy: Hash,
    pub public: bool,
    pub attested: bool,
    pub space_role: Option<u8>,
    pub capability: Option<CapabilityId>,
    pub actor_role: Option<u8>,
}

/// One canonical actor installed into the root actor tree owned by a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorGenesis {
    pub actor: ActorId,
    /// Stable name within the parent's owned namespace. The one root actor's
    /// name is unique in the service root namespace.
    pub name: String,
    /// `None` identifies the single root actor; every child names an actor in
    /// the same genesis tree.
    pub parent: Option<ActorId>,
    /// Signer of the exact canonical package from which this actor was
    /// installed. Guest-owned state retains this identity so later proof
    /// verification never has to trust a producer label carried by a package.
    pub producer: ProducerId,
    /// Exact signed package from which the current actor code, schemas, and
    /// generated policy surface were installed. This may change only through
    /// guest-owned `UpgradeActor`; the root service deployment stays stable.
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub initial_state: BlobRef,
    pub crdt: bool,
    /// Exact canonical policy artifact retained from the signed deployment.
    /// Guest Install decodes method rows from these bytes; callers cannot
    /// supply an independent, weaker `methods` list.
    pub role_policies: Vec<u8>,
}

/// Canonical membership of the root actor tree committed at installation.
///
/// The directory is deliberately a guest-owned state row. A native scheduler
/// may resolve names for convenience, but it cannot omit a sibling program or
/// state from Refine without guest Accumulate detecting the partial import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorDirectory {
    pub actors: Vec<ActorId>,
}

/// Initialization accepted only by an empty service store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceGenesis {
    pub service: ServiceIdentity,
    pub consistency: ConsistencyMode,
    pub actors: Vec<ActorGenesis>,
    pub external_actors: Vec<ExternalActorBinding>,
    pub role_authority: Option<RoleAuthorityBinding>,
    pub authorization: AuthorizationEvidence,
}

/// Guest-authorized replacement for one installed actor's canonical program
/// and generated policy surface. Identity, ownership, consistency kind, and
/// materialized application state remain unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorUpgrade {
    pub service: ServiceIdentity,
    pub actor: ActorId,
    pub expected_deployment: DeploymentId,
    pub expected_program: ProgramId,
    pub replacement_deployment: DeploymentId,
    pub replacement_program: ProgramId,
    pub producer: ProducerId,
    /// Exact canonical policy artifact from the signed replacement package.
    /// Guest Accumulate derives method rows from these bytes.
    pub role_policies: Vec<u8>,
    pub base: ConsistencyBase,
    /// Authenticated platform/package-registry authority. `System` remains an
    /// identity class only; the exact capability is verified as work input.
    pub authorization: AuthorizationEvidence,
}

impl ActorUpgrade {
    pub fn hash(&self) -> Hash {
        Hash::digest(b"vos/actor-upgrade/service", &[&self.encode()])
    }
}

/// Complete input required by guest-owned Accumulate to validate a Refine
/// result. The host does not supply a journal or a native apply plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulationEnvelope {
    pub work: WorkEnvelope,
    pub transition: Transition,
    /// Candidate content-addressed bytes produced by Refine or its exact PVM
    /// snapshot boundary. They remain unobservable unless this Accumulate
    /// transaction commits.
    pub provided_blobs: Vec<ImportedBlob>,
}

/// Authenticated direct invocation admitted through guest Accumulate before
/// Refine may execute it. Unlike a `WorkEnvelope`, this record contains only
/// stable caller input; the scheduler derives the current program, state, and
/// consistency base when the actor becomes idle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectIngress {
    pub service: ServiceIdentity,
    pub invocation: InvocationId,
    pub logical_timeslot: u64,
    pub target: ActorId,
    pub method: String,
    pub arguments: Vec<u8>,
    /// Durable commitment to Local producer-private invocation arguments.
    /// When present, `arguments` is empty and the host hydrates the bytes from
    /// a separate durable sidecar before Refine.
    pub private_arguments: Option<BlobRef>,
    pub origin: Origin,
    pub authorization: AuthorizationEvidence,
    pub imported_blobs: Vec<BlobRef>,
    pub proof_requested: bool,
    pub base: ConsistencyBase,
    pub base_causal_height: Option<u64>,
    pub crdt_change: Option<CrdtChange>,
}

impl DirectIngress {
    pub fn matches_arguments(&self, arguments: &[u8]) -> bool {
        self.private_arguments
            .as_ref()
            .map_or(self.arguments.as_slice() == arguments, |reference| {
                reference.matches(arguments)
            })
    }

    fn encode_body_with_authorization(
        &self,
        out: &mut Vec<u8>,
        authorization: &AuthorizationEvidence,
    ) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.fixed(&self.invocation.0);
        e.u64(self.logical_timeslot);
        e.fixed(&self.target.0);
        e.string(&self.method);
        e.bytes(&self.arguments);
        e.option(&self.private_arguments, encode_blob_ref);
        encode_origin(&mut e, self.origin);
        encode_auth(&mut e, authorization);
        e.list(&self.imported_blobs, encode_blob_ref);
        e.bool(self.proof_requested);
        encode_base(&mut e, &self.base);
        e.option(&self.base_causal_height, |e, height| e.u64(*height));
        e.option(&self.crdt_change, |e, change| e.bytes(&change.encode()));
    }

    /// Encode the permanent admission row without retaining a second copy of
    /// disclosed CRDT credential bytes. The causal operation already binds
    /// their content address, policy, and credential commitment.
    pub(crate) fn encode_admitted(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&Self::MAGIC);
        out.extend_from_slice(&super::PLATFORM_ID.0);
        let authorization = if self.crdt_change.is_some() {
            &AuthorizationEvidence::Public
        } else {
            &self.authorization
        };
        self.encode_body_with_authorization(&mut out, authorization);
        out
    }

    /// Encode a CRDT admission reconstructed from its canonical DAG node.
    ///
    /// This borrowed form avoids cloning the complete change merely to build
    /// the permanent ingress row inside the bounded service guest.
    pub(crate) fn encode_materialized(ingress: &CrdtIngress, change: &CrdtChange) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&Self::MAGIC);
        out.extend_from_slice(&super::PLATFORM_ID.0);
        let mut e = Encoder(&mut out);
        encode_service(&mut e, &ingress.service);
        e.fixed(&ingress.invocation.0);
        e.u64(ingress.logical_timeslot);
        e.fixed(&ingress.target.0);
        e.string(&ingress.method);
        e.bytes(&ingress.arguments);
        e.option(&None::<BlobRef>, encode_blob_ref);
        encode_origin(&mut e, ingress.origin);
        encode_auth(&mut e, &AuthorizationEvidence::Public);
        e.list(&ingress.imported_blobs, encode_blob_ref);
        e.bool(ingress.proof_requested);
        e.u8(1);
        e.list(&change.causal_dependencies, |e, head| e.fixed(&head.0));
        e.bool(true);
        e.u64(change.causal_height.saturating_sub(1));
        e.bool(true);
        e.bytes(&change.encode());
        out
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/direct-ingress/service", &[&self.encode()])
    }

    /// A transport retry may carry a newer observation timeslot, but every
    /// caller-controlled input must match the guest-admitted invocation.
    pub fn matches_retry(&self, candidate: &Self) -> bool {
        self.service == candidate.service
            && self.invocation == candidate.invocation
            && self.target == candidate.target
            && self.method == candidate.method
            && self.arguments == candidate.arguments
            && self.private_arguments == candidate.private_arguments
            && self.origin == candidate.origin
            && self.logical_authorization_matches(candidate)
            && self.imported_blobs == candidate.imported_blobs
            && self.proof_requested == candidate.proof_requested
    }

    fn logical_authorization_matches(&self, candidate: &Self) -> bool {
        match (self.crdt_ingress(), candidate.crdt_ingress()) {
            (Some(_), _) => self.authorization_matches(candidate.authorization()),
            (None, Some(_)) => candidate.authorization_matches(self.authorization()),
            (None, None) => self.authorization == candidate.authorization,
        }
    }

    pub fn crdt_operation(&self) -> CrdtIngress {
        let (authorization, authorization_blob) = match &self.authorization {
            AuthorizationEvidence::Credential {
                policy,
                credential_commitment,
                bytes,
            } => (
                AuthorizationEvidence::Credential {
                    policy: *policy,
                    credential_commitment: *credential_commitment,
                    bytes: Vec::new(),
                },
                Some(BlobRef::of_bytes(bytes)),
            ),
            authorization => (authorization.clone(), None),
        };
        CrdtIngress {
            service: self.service.clone(),
            invocation: self.invocation,
            logical_timeslot: self.logical_timeslot,
            target: self.target,
            method: self.method.clone(),
            arguments: self.arguments.clone(),
            origin: self.origin,
            authorization,
            authorization_blob,
            imported_blobs: self.imported_blobs.clone(),
            proof_requested: self.proof_requested,
        }
    }

    /// Effective authorization carried by this admission. Linear ingress owns
    /// it directly. CRDT ingress owns it once in the causal operation and uses
    /// a public top-level sentinel.
    pub fn authorization(&self) -> &AuthorizationEvidence {
        if self.authorization != AuthorizationEvidence::Public {
            &self.authorization
        } else {
            self.crdt_ingress()
                .map_or(&self.authorization, |ingress| &ingress.authorization)
        }
    }

    pub fn crdt_ingress(&self) -> Option<&CrdtIngress> {
        self.crdt_change.as_ref().and_then(|change| {
            let [WorkflowOperation::Ingress(ingress)] = change.workflow.as_slice() else {
                return None;
            };
            Some(ingress)
        })
    }

    pub(crate) fn authorization_matches(&self, candidate: &AuthorizationEvidence) -> bool {
        let Some(ingress) = self.crdt_ingress() else {
            return &self.authorization == candidate;
        };
        match (
            &ingress.authorization,
            ingress.authorization_blob.as_ref(),
            candidate,
        ) {
            (AuthorizationEvidence::Public, None, AuthorizationEvidence::Public) => true,
            (
                AuthorizationEvidence::Credential {
                    policy,
                    credential_commitment,
                    bytes,
                },
                Some(reference),
                AuthorizationEvidence::Credential {
                    policy: candidate_policy,
                    credential_commitment: candidate_commitment,
                    bytes: candidate_bytes,
                },
            ) => {
                bytes.is_empty()
                    && policy == candidate_policy
                    && credential_commitment == candidate_commitment
                    && (candidate_bytes.is_empty() || reference.matches(candidate_bytes))
            }
            _ => false,
        }
    }

    pub fn matches_work(&self, work: &WorkEnvelope) -> bool {
        self.service == work.service
            && self.invocation == work.invocation
            && work.workflow_step == 0
            && self.logical_timeslot == work.logical_timeslot
            && self.target == work.target
            && self.method == work.method
            && self.private_arguments == work.private_arguments
            && match self.private_arguments.as_ref() {
                Some(reference) => work.arguments.is_empty() || reference.matches(&work.arguments),
                None => self.arguments == work.arguments,
            }
            && self.origin == work.origin
            && self.authorization_matches(&work.authorization)
            && work.causal_parent.is_none()
            && work.parent_call.is_none()
            && work.awaited_reply.is_none()
            && work.awaited_timeout.is_none()
            && self.imported_blobs == work.imported_blobs
            && self.proof_requested == work.proof_requested
    }
}

/// Authenticated cross-root admission input. The destination service guest,
/// not the native transport, validates the finalized source receipt and
/// atomically creates the durable inbox row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryEnvelope {
    pub service: ServiceIdentity,
    pub logical_timeslot: u64,
    pub base: ConsistencyBase,
    /// Destination-scoped authorization selected by the authenticated
    /// transport and independently verified by guest Accumulate. The source
    /// message remains `Public`, so its finalized outbox receipt cannot be
    /// rewritten to smuggle destination credentials.
    pub authorization: AuthorizationEvidence,
    pub message: MessageRecord,
    pub source_outbox: Vec<MessageRecord>,
    pub source_receipt: AccumulationReceipt,
}

impl DeliveryEnvelope {
    /// Inbox record committed by the destination after both the source
    /// receipt and destination authorization have been verified.
    pub fn admitted_message(&self) -> MessageRecord {
        let mut message = self.message.clone();
        message.authorization = self.authorization.clone();
        message
    }

    /// Exact first-admission commitment, including the current destination
    /// base which the accepted delivery advances.
    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/delivery/service", &[&self.encode()])
    }

    /// Stable retry identity of one finalized source message. The destination
    /// base and admission timeslot are deliberately excluded: inbox execution
    /// may advance the base, and a trusted destination scheduler may allocate
    /// a later slot, before a transport retry reaches the same service. The
    /// first accepted slot remains durable in [`super::DeliveryRecord`].
    pub fn retry_identity(&self) -> Hash {
        let mut bytes = Vec::new();
        let mut e = Encoder(&mut bytes);
        encode_service(&mut e, &self.service);
        encode_auth(&mut e, &self.authorization);
        e.bytes(&self.message.encode());
        e.list(&self.source_outbox, |e, message| e.bytes(&message.encode()));
        // A CRDT source may finalize the same logical outbox on several
        // physical branches. The exact receipt remains mandatory evidence at
        // every admission, but it must not split destination-side retry
        // identity when the authenticated service, message and outbox agree.
        encode_service(&mut e, &self.source_receipt.service);
        e.u8(self.source_receipt.consistency as u8);
        Hash::digest(b"vos/delivery-retry/service", &[&bytes])
    }
}

/// Guest-owned terminal disposition for one deadline-bearing destination
/// inbox. The trusted observation slot is supplied by the physical Accumulate
/// host rather than encoded here; `deadline_timeslot` binds the exact admitted
/// message which may be retired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxRetirement {
    pub service: ServiceIdentity,
    pub call_id: CallId,
    pub deadline_timeslot: u64,
    pub base: ConsistencyBase,
}

/// One causal node imported from another replica of the same CRDT service.
/// The finalized accumulation receipt authenticates that this exact CID was
/// admitted by the canonical service guest; sync never trusts unsigned DAG
/// bytes supplied by the native transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrdtSyncNode {
    pub change: CrdtChange,
    pub receipt: AccumulationReceipt,
}

/// Complete CRDT synchronization input accepted by guest Accumulate. Nodes
/// and blobs may be a delta, but `advertised_heads` must have complete ancestry
/// after combining the delta with locally committed nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrdtSyncEnvelope {
    pub service: ServiceIdentity,
    pub advertised_heads: Vec<Hash>,
    pub nodes: Vec<CrdtSyncNode>,
    pub provided_blobs: Vec<ImportedBlob>,
}

impl CrdtSyncEnvelope {
    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/crdt-sync/service", &[&self.encode()])
    }
}

/// Guest-owned acknowledgement that a committed publication reached its
/// external consumer. Removal is another physical Accumulate transaction;
/// native transport never deletes a recoverable publication row directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationAck {
    pub service: ServiceIdentity,
    pub input: WorkInputId,
    pub publication: Hash,
}

/// Physical IC-5 request. Every mutation of service, transport, or causal
/// synchronization bookkeeping remains guest-owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccumulateRequest {
    Install(ServiceGenesis),
    AdmitIngress(DirectIngress),
    Apply(AccumulationEnvelope),
    PrepareAttested(AccumulationEnvelope),
    Deliver(DeliveryEnvelope),
    RetireInbox(InboxRetirement),
    ExpireCall(CallExpirationEnvelope),
    AcknowledgePublication(PublicationAck),
    SyncCrdt(CrdtSyncEnvelope),
    UpgradeActor(ActorUpgrade),
}

impl AccumulateRequest {
    /// Service identity whose physical account/program receives this request.
    ///
    /// Guest Accumulate validates this identity against committed state. The
    /// platform dispatcher separately binds its `service_program` to the
    /// canonical PVM selected for execution before entering the guest.
    pub fn service(&self) -> &ServiceIdentity {
        match self {
            Self::Install(genesis) => &genesis.service,
            Self::AdmitIngress(ingress) => &ingress.service,
            Self::Apply(envelope) | Self::PrepareAttested(envelope) => &envelope.work.service,
            Self::Deliver(envelope) => &envelope.service,
            Self::RetireInbox(retirement) => &retirement.service,
            Self::ExpireCall(envelope) => &envelope.service,
            Self::AcknowledgePublication(acknowledgement) => &acknowledgement.service,
            Self::SyncCrdt(envelope) => &envelope.service,
            Self::UpgradeActor(upgrade) => &upgrade.service,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublishedEffects {
    pub reply: Option<ReplyRecord>,
    pub outbox: Vec<MessageRecord>,
    pub exported_blobs: Vec<BlobRef>,
    pub proof: Option<ProofCommitment>,
    /// Guest-derived, receipt-bound package metadata retained with the
    /// publication so transport can recover an attested reply after restart.
    pub attestation: Option<Box<AttestationDelivery>>,
}

impl PublishedEffects {
    /// Stable identity of effects whose external delivery must happen once.
    /// Exported continuation blobs are causal reconstruction artifacts rather
    /// than consumers; equivalent CRDT retries may legitimately reference a
    /// different physical snapshot while publishing the same reply/outbox.
    pub fn transport_commitment(&self) -> Hash {
        let mut bytes = Vec::new();
        let mut encoder = Encoder(&mut bytes);
        encoder.option(&self.reply, encode_reply);
        encoder.list(&self.outbox, encode_message);
        encoder.option(&self.proof, encode_proof);
        encoder.option(&self.attestation, |encoder, attestation| {
            encoder.string(&attestation.producer_name);
            encoder.fixed(&attestation.producer.0);
            encoder.bytes(&attestation.statement.encode());
            encode_proof(encoder, &attestation.proof);
        });
        Hash::digest(b"vos/published-transport/service", &[&bytes])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInstallReceipt {
    pub service: ServiceIdentity,
    pub consistency: ConsistencyMode,
    pub resulting_state_root: Option<Hash>,
    pub resulting_crdt_heads: Vec<Hash>,
}

/// Stable rejection codes returned without committing guest storage writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccumulationRejection {
    StoreAlreadyInitialized,
    StoreUninitialized,
    WrongService,
    WrongPlatform,
    WrongExecutionSemantics,
    WrongProgram,
    InvalidConsistency,
    Unauthorized,
    MissingBlob(Hash),
    MissingProof,
    ProofUnavailable,
    InvalidProof,
    StaleLinearWork {
        expected_revision: u64,
        actual_revision: u64,
    },
    StaleStateRoot,
    MissingCausalDependency(Hash),
    TransitionInputMismatch,
    TransitionBaseMismatch,
    DivergentDuplicate,
    InvalidWorkflowTransition,
    ContinuationConflict(ActorId),
    MessageCycle,
    StorageFull,
    SequenceOverflow,
    NonCanonical,
    ReceiptUnavailable,
    InvalidReceipt,
    ActorBusy(ActorId),
}

impl AccumulationRejection {
    /// A retry can succeed without changing the submitted logical operation.
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::StaleLinearWork { .. }
                | Self::StaleStateRoot
                | Self::MissingBlob(_)
                | Self::MissingCausalDependency(_)
                | Self::ContinuationConflict(_)
                | Self::StorageFull
                | Self::ProofUnavailable
                | Self::ReceiptUnavailable
                | Self::ActorBusy(_)
        )
    }
}

/// Guest output. New installs, ingress admissions, accepted transitions,
/// call/inbox expirations, actor upgrades, and publication acknowledgements
/// authorize a commit when non-duplicate; `Prepared` and `Rejected` are
/// read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccumulationResult {
    Installed(ServiceInstallReceipt),
    IngressAdmitted {
        invocation: InvocationId,
        receipt: AccumulationReceipt,
        duplicate: bool,
    },
    Accepted {
        receipt: AccumulationReceipt,
        published: PublishedEffects,
        duplicate: bool,
    },
    Prepared(AttestationPreparation),
    CallExpired {
        timeout: AccumulatedTimeout,
        duplicate: bool,
    },
    InboxRetired {
        call_id: CallId,
        duplicate: bool,
    },
    PublicationAcknowledged {
        input: WorkInputId,
        duplicate: bool,
    },
    ActorUpgraded {
        actor: ActorId,
        previous_deployment: DeploymentId,
        previous_program: ProgramId,
        deployment: DeploymentId,
        program: ProgramId,
        receipt: AccumulationReceipt,
        duplicate: bool,
    },
    Rejected(AccumulationRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefineError {
    WrongPlatform,
    WrongExecutionSemantics,
    MissingImport(Hash),
    InvalidImport(Hash),
    NonCanonicalImports,
    InvalidConsistency,
    Execution(Vec<u8>),
}

impl core::fmt::Display for RefineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "refine failed: {self:?}")
    }
}

impl core::error::Error for RefineError {}

impl RefineImports {
    /// Verify that Refine has every byte named by the work envelope and that
    /// no imported code/blob can masquerade under a different content ID.
    pub fn validate_for(&self, work: &WorkEnvelope) -> Result<(), RefineError> {
        if work.service.platform != super::PLATFORM_ID {
            return Err(RefineError::WrongPlatform);
        }
        if work.service.execution_semantics != super::EXECUTION_SEMANTICS_ID {
            return Err(RefineError::WrongExecutionSemantics);
        }
        if !work.base.mode_compatible(work.consistency) {
            return Err(RefineError::InvalidConsistency);
        }

        if self
            .programs
            .windows(2)
            .any(|pair| pair[0].program >= pair[1].program)
            || self
                .blobs
                .windows(2)
                .any(|pair| pair[0].reference.hash >= pair[1].reference.hash)
            || self
                .private_blobs
                .windows(2)
                .any(|pair| pair[0].reference.hash >= pair[1].reference.hash)
        {
            return Err(RefineError::NonCanonicalImports);
        }
        for imported in &self.programs {
            if imported.pvm.is_empty() || ProgramId::of_pvm(&imported.pvm) != imported.program {
                return Err(RefineError::InvalidImport(Hash(imported.program.0)));
            }
        }
        for imported in &self.blobs {
            if !imported.reference.matches(&imported.bytes) {
                return Err(RefineError::InvalidImport(imported.reference.hash));
            }
        }
        for imported in &self.private_blobs {
            if !imported.reference.matches(&imported.bytes)
                || self
                    .blobs
                    .binary_search_by_key(&imported.reference.hash, |blob| blob.reference.hash)
                    .is_ok()
            {
                return Err(RefineError::InvalidImport(imported.reference.hash));
            }
        }
        match &work.authorization {
            AuthorizationEvidence::Credential {
                credential_commitment,
                bytes,
                ..
            } if bytes.is_empty()
                && work.consistency == ConsistencyMode::Crdt
                && work.parent_call.is_none() =>
            {
                if !self.blobs.iter().any(|blob| {
                    Hash::digest(b"vos/credential-commitment/service", &[&blob.bytes])
                        == *credential_commitment
                }) {
                    return Err(RefineError::MissingImport(*credential_commitment));
                }
            }
            AuthorizationEvidence::PrivateCredential { witness, .. } => {
                if self.private_blobs.len() != 1 {
                    return Err(RefineError::NonCanonicalImports);
                }
                self.require_private_blob(witness)?;
            }
            _ if !self.private_blobs.is_empty() => {
                return Err(RefineError::NonCanonicalImports);
            }
            _ => {}
        }

        let target = work
            .imported_actors
            .iter()
            .find(|actor| actor.actor == work.target)
            .ok_or(RefineError::MissingImport(Hash(work.target.0)))?;
        if target.deployment != work.target_deployment || target.program != work.target_program {
            return Err(RefineError::InvalidImport(Hash(target.program.0)));
        }

        for actor in &work.imported_actors {
            if self
                .programs
                .binary_search_by_key(&actor.program, |program| program.program)
                .is_err()
            {
                return Err(RefineError::MissingImport(Hash(actor.program.0)));
            }
            for dependency in &actor.task_dependencies {
                if self
                    .programs
                    .binary_search_by_key(&dependency.program, |program| program.program)
                    .is_err()
                {
                    return Err(RefineError::MissingImport(Hash(dependency.program.0)));
                }
            }
            self.require_blob(&actor.state)?;
            for state in &actor.causal_states {
                self.require_blob(state)?;
            }
            if let Some(continuation) = &actor.continuation {
                self.require_blob(continuation)?;
            }
            for row in &actor.storage_rows {
                if let Some(value) = &row.value {
                    self.require_blob(value)?;
                }
            }
        }
        for reference in &work.imported_blobs {
            self.require_blob(reference)?;
        }
        if let Some(proof) = work
            .awaited_reply
            .as_ref()
            .and_then(|reply| reply.attestation.as_ref())
            .map(|attestation| &attestation.proof.proof_blob)
        {
            self.require_blob(proof)?;
        }
        Ok(())
    }

    fn require_blob(&self, reference: &BlobRef) -> Result<(), RefineError> {
        let imported = self
            .blobs
            .binary_search_by_key(&reference.hash, |blob| blob.reference.hash)
            .ok()
            .map(|index| &self.blobs[index])
            .ok_or(RefineError::MissingImport(reference.hash))?;
        if imported.reference != *reference {
            return Err(RefineError::InvalidImport(reference.hash));
        }
        Ok(())
    }

    fn require_private_blob(&self, reference: &BlobRef) -> Result<(), RefineError> {
        let imported = self
            .private_blobs
            .binary_search_by_key(&reference.hash, |blob| blob.reference.hash)
            .ok()
            .map(|index| &self.private_blobs[index])
            .ok_or(RefineError::MissingImport(reference.hash))?;
        if imported.reference != *reference {
            return Err(RefineError::InvalidImport(reference.hash));
        }
        Ok(())
    }
}

impl ServiceWire for WorkEnvelope {
    const MAGIC: [u8; 4] = *b"VWKW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        self.encode_body_with_arguments(out, &self.arguments);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let service = decode_service(d)?;
        let invocation = InvocationId(d.fixed()?);
        let workflow_step = d.u64()?;
        let logical_timeslot = d.u64()?;
        let target = ActorId(d.fixed()?);
        let target_deployment = DeploymentId(d.fixed()?);
        let target_program = ProgramId(d.fixed()?);
        let method = d.string()?;
        if method.is_empty() {
            return Err(DecodeError::NonCanonical);
        }
        let arguments = d.bytes()?;
        let private_arguments = d.option(decode_blob_ref)?;
        if private_arguments.as_ref().is_some_and(|reference| {
            workflow_step != 0
                || reference.len == 0
                || !arguments.is_empty() && !reference.matches(&arguments)
        }) {
            return Err(DecodeError::NonCanonical);
        }
        let origin = decode_origin(d)?;
        let authorization = decode_auth(d)?;
        let causal_parent = d.option(|d| d.fixed().map(InvocationId))?;
        let parent_call = d.option(|d| d.fixed().map(CallId))?;
        let causal_context = d.option(decode_causal_context)?;
        match (&causal_context, parent_call, causal_parent, origin) {
            (Some(context), Some(call), Some(parent), Origin::Actor(from))
                if context.call_id == call
                    && context.caller_invocation == parent
                    && context.from == from
                    && context.to == target => {}
            (None, None, _, _) => {}
            _ => return Err(DecodeError::NonCanonical),
        }
        let awaited_reply = d.option(|d| AccumulatedReply::decode(&d.bytes()?))?;
        let awaited_timeout =
            d.option(|d| AccumulatedTimeout::decode(&d.bytes()?).map(Box::new))?;
        if (awaited_reply.is_some() || awaited_timeout.is_some()) && workflow_step == 0
            || awaited_reply.is_some() && awaited_timeout.is_some()
        {
            return Err(DecodeError::NonCanonical);
        }
        let consistency = ConsistencyMode::decode(d)?;
        if private_arguments.is_some() && consistency == ConsistencyMode::Crdt {
            return Err(DecodeError::NonCanonical);
        }
        let base = decode_base(d)?;
        if !base.mode_compatible(consistency) {
            return Err(DecodeError::NonCanonical);
        }
        let base_causal_height = d.option(Decoder::u64)?;
        match (&base, base_causal_height) {
            (ConsistencyBase::Linear { .. }, None) => {}
            (ConsistencyBase::Crdt { heads }, Some(0)) if heads.is_empty() => {}
            (ConsistencyBase::Crdt { heads }, Some(height)) if !heads.is_empty() && height != 0 => {
            }
            _ => return Err(DecodeError::NonCanonical),
        }
        let imported_actors = d.list(decode_imported_actor)?;
        let external_actors = d.list(decode_external_actor)?;
        let imported_blobs = d.list(decode_blob_ref)?;
        let proof_requested = d.bool()?;
        ensure_sorted_unique(&imported_actors, |actor| actor.actor.0)?;
        ensure_external_actors_canonical(&external_actors)?;
        ensure_sorted_unique(&imported_blobs, |b| b.hash.0)?;
        validate_imported_actor_tree(&imported_actors, target, target_deployment, target_program)?;
        if let AuthorizationEvidence::PrivateCredential { witness, .. } = &authorization {
            let leaked_into_public_imports = imported_blobs
                .binary_search_by_key(&witness.hash, |blob| blob.hash)
                .ok()
                .is_some_and(|index| imported_blobs[index] == *witness);
            if !proof_requested || witness.len == 0 || leaked_into_public_imports {
                return Err(DecodeError::NonCanonical);
            }
        }
        if awaited_reply
            .as_ref()
            .and_then(|reply| reply.attestation.as_ref())
            .is_some_and(|attestation| attestation.producer_name.is_empty())
        {
            return Err(DecodeError::NonCanonical);
        }
        if awaited_timeout.as_ref().is_some_and(|timeout| {
            timeout.expiration.service != service
                || timeout.expiration.timeout.caller_invocation != invocation
                || timeout.expiration.timeout.checkpoint_step.checked_add(1) != Some(workflow_step)
                || logical_timeslot < timeout.expiration.timeout.expired_at
        }) {
            return Err(DecodeError::NonCanonical);
        }
        let storage_witness_count = imported_actors
            .iter()
            .try_fold(0usize, |total, actor| {
                total.checked_add(actor.storage_rows.len())
            })
            .ok_or(DecodeError::LimitExceeded)?;
        let storage_witness_bytes = imported_actors
            .iter()
            .flat_map(|actor| &actor.storage_rows)
            .filter_map(|row| row.value.as_ref())
            .try_fold(0usize, |total, value| {
                usize::try_from(value.len)
                    .ok()
                    .and_then(|len| total.checked_add(len))
            })
            .ok_or(DecodeError::LimitExceeded)?;
        if storage_witness_count > super::MAX_ACTOR_STORAGE_WITNESSES
            || storage_witness_bytes > super::MAX_ACTOR_STORAGE_WITNESS_BYTES
        {
            return Err(DecodeError::LimitExceeded);
        }
        for actor in &imported_actors {
            ensure_sorted_unique(&actor.causal_states, |state| state.hash.0)?;
            ensure_sorted_unique(&actor.storage_rows, |row| row.key.clone())?;
            if actor
                .causal_states
                .iter()
                .any(|state| state.hash == actor.state.hash)
                || actor
                    .causal_states
                    .first()
                    .is_some_and(|state| state.hash <= actor.state.hash)
                || (consistency != ConsistencyMode::Crdt && !actor.causal_states.is_empty())
                || (consistency == ConsistencyMode::Crdt && !actor.storage_rows.is_empty())
                || actor.storage_rows.iter().any(|row| {
                    row.key.is_empty() || row.key.len() > super::MAX_ACTOR_STORAGE_KEY_BYTES
                })
            {
                return Err(DecodeError::NonCanonical);
            }
        }
        if external_actors.iter().any(|external| {
            external.service == service
                || external.service.execution_semantics != super::EXECUTION_SEMANTICS_ID
                || imported_actors
                    .iter()
                    .any(|local| local.actor == external.actor)
                || imported_actors
                    .iter()
                    .any(|local| local.parent.is_none() && local.name == external.name)
        }) {
            return Err(DecodeError::NonCanonical);
        }
        Ok(Self {
            service,
            invocation,
            workflow_step,
            logical_timeslot,
            target,
            target_deployment,
            target_program,
            method,
            arguments,
            private_arguments,
            origin,
            authorization,
            causal_parent,
            parent_call,
            causal_context,
            awaited_reply,
            awaited_timeout,
            consistency,
            base,
            base_causal_height,
            imported_actors,
            external_actors,
            imported_blobs,
            proof_requested,
        })
    }
}

impl WorkEnvelope {
    pub fn matches_arguments(&self, arguments: &[u8]) -> bool {
        self.private_arguments
            .as_ref()
            .map_or(self.arguments.as_slice() == arguments, |reference| {
                reference.matches(arguments)
            })
    }

    fn encode_body_with_arguments(&self, out: &mut Vec<u8>, arguments: &[u8]) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.fixed(&self.invocation.0);
        e.u64(self.workflow_step);
        e.u64(self.logical_timeslot);
        e.fixed(&self.target.0);
        e.fixed(&self.target_deployment.0);
        e.fixed(&self.target_program.0);
        e.string(&self.method);
        e.bytes(arguments);
        e.option(&self.private_arguments, encode_blob_ref);
        encode_origin(&mut e, self.origin);
        encode_auth(&mut e, &self.authorization);
        e.option(&self.causal_parent, |e, id| e.fixed(&id.0));
        e.option(&self.parent_call, |e, id| e.fixed(&id.0));
        e.option(&self.causal_context, encode_causal_context);
        e.option(&self.awaited_reply, |e, reply| e.bytes(&reply.encode()));
        e.option(&self.awaited_timeout, |e, timeout| {
            e.bytes(&timeout.encode())
        });
        e.u8(self.consistency as u8);
        encode_base(&mut e, &self.base);
        e.option(&self.base_causal_height, |e, height| e.u64(*height));
        e.list(&self.imported_actors, encode_imported_actor);
        e.list(&self.external_actors, encode_external_actor);
        e.list(&self.imported_blobs, encode_blob_ref);
        e.bool(self.proof_requested);
    }
}

impl ServiceWire for RefineImports {
    const MAGIC: [u8; 4] = *b"VRIW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.list(&self.programs, |e, program| {
            e.fixed(&program.program.0);
            e.bytes(&program.pvm);
        });
        e.list(&self.blobs, |e, blob| {
            encode_blob_ref(e, &blob.reference);
            e.bytes(&blob.bytes);
        });
        e.list(&self.private_blobs, |e, blob| {
            encode_blob_ref(e, &blob.reference);
            e.bytes(&blob.bytes);
        });
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            programs: d.list(|d| {
                Ok(ImportedProgram {
                    program: ProgramId(d.fixed()?),
                    pvm: d.bytes()?,
                })
            })?,
            blobs: d.list(|d| {
                Ok(ImportedBlob {
                    reference: decode_blob_ref(d)?,
                    bytes: d.bytes()?,
                })
            })?,
            private_blobs: d.list(|d| {
                Ok(ImportedBlob {
                    reference: decode_blob_ref(d)?,
                    bytes: d.bytes()?,
                })
            })?,
        };
        ensure_sorted_unique(&value.programs, |program| program.program.0)?;
        ensure_sorted_unique(&value.blobs, |blob| blob.reference.hash.0)?;
        ensure_sorted_unique(&value.private_blobs, |blob| blob.reference.hash.0)?;
        for program in &value.programs {
            if program.pvm.is_empty() || ProgramId::of_pvm(&program.pvm) != program.program {
                return Err(DecodeError::NonCanonical);
            }
        }
        if value
            .blobs
            .iter()
            .chain(value.private_blobs.iter())
            .any(|blob| !blob.reference.matches(&blob.bytes))
            || value.private_blobs.iter().any(|private| {
                value
                    .blobs
                    .binary_search_by_key(&private.reference.hash, |blob| blob.reference.hash)
                    .is_ok()
            })
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for ActorSliceInput {
    const MAGIC: [u8; 4] = *b"VSIW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.actor.0);
        e.u64(self.first_await_ordinal);
        e.bytes(&self.message);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            actor: ActorId(d.fixed()?),
            first_await_ordinal: d.u64()?,
            message: d.bytes()?,
        };
        Ok(value)
    }
}

impl ServiceWire for ActorPrivateInput {
    const MAGIC: [u8; 4] = *b"VPIW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.actor.0);
        e.list(&self.actor_tree, encode_actor_tree_import);
        e.list(&self.external_actors, encode_external_actor);
        e.fixed(&self.input.invocation.0);
        e.u64(self.input.workflow_step);
        e.option(&self.change, |e, dispatch| {
            e.fixed(&dispatch.change.0);
            e.u32(dispatch.ordinal);
        });
        e.bytes(&self.state);
        e.list(&self.causal_states, |e, state| e.bytes(state));
        e.u64(self.active_actor_mask);
        encode_origin(&mut e, self.origin);
        e.option(&self.origin_service, encode_service);
        e.option(&self.space_role, |e, role| e.u8(*role));
        e.option(&self.actor_role, |e, role| e.u8(*role));
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            actor: ActorId(d.fixed()?),
            actor_tree: d.list(decode_actor_tree_import)?,
            external_actors: d.list(decode_external_actor)?,
            input: WorkInputId {
                invocation: InvocationId(d.fixed()?),
                workflow_step: d.u64()?,
            },
            change: d.option(|d| {
                Ok(CrdtDispatch {
                    change: ChangeId(d.fixed()?),
                    ordinal: d.u32()?,
                })
            })?,
            state: d.bytes()?,
            causal_states: d.list(Decoder::bytes)?,
            active_actor_mask: d.u64()?,
            origin: decode_origin(d)?,
            origin_service: d.option(decode_service)?,
            space_role: d.option(|d| {
                let role = d.u8()?;
                crate::SpaceRole::from_u8(role)
                    .map(|_| role)
                    .ok_or(DecodeError::NonCanonical)
            })?,
            actor_role: d.option(Decoder::u8)?,
        };
        ensure_sorted_unique(&value.actor_tree, |actor| actor.actor.0)?;
        ensure_external_actors_canonical(&value.external_actors)?;
        validate_actor_slice_tree(&value.actor_tree)?;
        let Some(self_index) = value
            .actor_tree
            .binary_search_by_key(&value.actor, |actor| actor.actor)
            .ok()
        else {
            return Err(DecodeError::NonCanonical);
        };
        let valid_actor_mask = (1u64 << value.actor_tree.len()) - 1;
        if value.active_actor_mask & (1u64 << self_index) == 0
            || value.active_actor_mask & !valid_actor_mask != 0
            || (value.change.is_none() && !value.causal_states.is_empty())
            || matches!(value.origin, Origin::Actor(_)) != value.origin_service.is_some()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for ActorCallResult {
    const MAGIC: [u8; 4] = *b"VACW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.actor.0);
        e.u64(self.first_await_ordinal);
        e.u64(self.next_await_ordinal);
        e.bytes(&self.reply);
        e.bool(self.yielded);
        e.bool(self.forbidden);
        e.option(&self.checkpoint, encode_checkpoint_token);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            actor: ActorId(d.fixed()?),
            first_await_ordinal: d.u64()?,
            next_await_ordinal: d.u64()?,
            reply: d.bytes()?,
            yielded: d.bool()?,
            forbidden: d.bool()?,
            checkpoint: d.option(decode_checkpoint_token)?,
        };
        if value.first_await_ordinal > value.next_await_ordinal
            || value.yielded
                != value
                    .checkpoint
                    .as_ref()
                    .and_then(|checkpoint| checkpoint.replacement.as_ref())
                    .is_some()
            || (value.forbidden
                && (value.yielded || !value.reply.is_empty() || value.checkpoint.is_some()))
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for ActorEffectBatch {
    const MAGIC: [u8; 4] = *b"VEBW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.list(&self.outputs, |e, output| e.bytes(&output.encode()));
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let outputs = d.list(|d| ActorSliceOutput::decode(&d.bytes()?))?;
        if outputs.is_empty() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(Self { outputs })
    }
}

impl ServiceWire for ActorSliceOutput {
    const MAGIC: [u8; 4] = *b"VSOW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.actor.0);
        e.u64(self.first_await_ordinal);
        e.u64(self.next_await_ordinal);
        e.list(&self.writes, encode_write);
        e.list(&self.crdt_operations, encode_crdt_op);
        e.list(&self.crdt_states, |e, state| {
            e.fixed(&state.actor.0);
            e.bytes(&state.state);
            e.u32(state.next_dispatch_ordinal);
        });
        e.list(&self.spawns, encode_actor_spawn_request);
        e.list(&self.outbox, encode_actor_call);
        e.bytes(&self.reply);
        e.bool(self.yielded);
        e.bool(self.forbidden);
        e.option(&self.checkpoint, encode_checkpoint_token);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            actor: ActorId(d.fixed()?),
            first_await_ordinal: d.u64()?,
            next_await_ordinal: d.u64()?,
            writes: d.list(decode_write)?,
            crdt_operations: d.list(decode_crdt_op)?,
            crdt_states: d.list(|d| {
                Ok(ActorCrdtState {
                    actor: ActorId(d.fixed()?),
                    state: d.bytes()?,
                    next_dispatch_ordinal: d.u32()?,
                })
            })?,
            spawns: d.list(decode_actor_spawn_request)?,
            outbox: d.list(decode_actor_call)?,
            reply: d.bytes()?,
            yielded: d.bool()?,
            forbidden: d.bool()?,
            checkpoint: d.option(decode_checkpoint_token)?,
        };
        if value.first_await_ordinal > value.next_await_ordinal
            || value.outbox.iter().any(|call| {
                call.await_ordinal < value.first_await_ordinal
                    || call.await_ordinal >= value.next_await_ordinal
            })
            || value.writes.iter().any(|write| write.actor != value.actor)
            || value
                .writes
                .windows(2)
                .any(|pair| pair[0].key >= pair[1].key)
            || value.crdt_operations.iter().any(|operation| {
                operation.payload.is_empty()
                    || value
                        .crdt_states
                        .binary_search_by_key(&operation.actor, |state| state.actor)
                        .ok()
                        .is_none_or(|index| {
                            operation.dispatch_ordinal
                                >= value.crdt_states[index].next_dispatch_ordinal
                        })
            })
            || value.crdt_operations.windows(2).any(|pair| {
                (pair[0].dispatch_ordinal, pair[0].ordinal)
                    >= (pair[1].dispatch_ordinal, pair[1].ordinal)
            })
            || value.crdt_operations.first().is_some_and(|first| {
                value
                    .crdt_operations
                    .iter()
                    .any(|operation| operation.dispatch_ordinal != first.dispatch_ordinal)
            })
            || value
                .outbox
                .windows(2)
                .any(|pair| pair[0].await_ordinal >= pair[1].await_ordinal)
            || value
                .outbox
                .iter()
                .any(|call| call.from != value.actor || call.payload.is_empty())
            || value
                .crdt_states
                .windows(2)
                .any(|pair| pair[0].actor >= pair[1].actor)
            || value
                .spawns
                .windows(2)
                .any(|pair| pair[0].actor >= pair[1].actor)
            || value.spawns.iter().any(|spawn| {
                spawn.parent != value.actor
                    || spawn.name.is_empty()
                    || spawn.name.len() > super::MAX_ACTOR_NAME_BYTES
                    || spawn.actor != ActorId::owned_child(spawn.parent, &spawn.name)
            })
            || value
                .crdt_states
                .iter()
                .any(|state| state.state.is_empty() || state.next_dispatch_ordinal == 0)
            || (!value.crdt_operations.is_empty() && value.crdt_states.is_empty())
            || (value.yielded
                && value
                    .checkpoint
                    .as_ref()
                    .and_then(|checkpoint| checkpoint.replacement.as_ref())
                    .is_none())
            || value.checkpoint.as_ref().is_some_and(|checkpoint| {
                checkpoint
                    .previously_suspended
                    .binary_search(&value.actor)
                    .is_err()
                    && checkpoint.suspended.binary_search(&value.actor).is_err()
            })
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for CheckpointToken {
    const MAGIC: [u8; 4] = *b"VCPW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        encode_checkpoint_token(&mut Encoder(out), self);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_checkpoint_token(d)
    }
}

impl ServiceWire for AwaitResume {
    const MAGIC: [u8; 4] = *b"VRSW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_checkpoint_token(&mut e, &self.checkpoint);
        encode_reply(&mut e, &self.reply);
        e.option(&self.attestation, |e, attestation| {
            e.string(&attestation.producer_name);
            e.fixed(&attestation.producer.0);
            e.bytes(&attestation.statement.encode());
            encode_proof(e, &attestation.proof);
            e.u32(attestation.proof_offset);
            e.u32(attestation.proof_len);
        });
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            checkpoint: decode_checkpoint_token(d)?,
            reply: decode_reply(d)?,
            attestation: d.option(|d| {
                Ok(Box::new(AttestationResume {
                    producer_name: d.string()?,
                    producer: ProducerId(d.fixed()?),
                    statement: AttestationStatement::decode(&d.bytes()?)?,
                    proof: decode_proof(d)?,
                    proof_offset: d.u32()?,
                    proof_len: d.u32()?,
                }))
            })?,
        };
        if value.checkpoint.pending_call != Some(value.reply.call_id)
            || value.attestation.as_ref().is_some_and(|attestation| {
                attestation.producer_name.is_empty()
                    || attestation.producer_name != attestation.statement.producer_name
                    || validate_attestation_delivery(
                        &value.reply,
                        &attestation.statement.accumulation_receipt,
                        &attestation.statement,
                        &attestation.proof,
                    )
                    .is_err()
                    || attestation.proof.proof_blob.len != u64::from(attestation.proof_len)
                    || attestation
                        .proof_offset
                        .checked_add(attestation.proof_len)
                        .is_none()
            })
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for Transition {
    const MAGIC: [u8; 4] = *b"VTRW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.fixed(&self.consumed_input.invocation.0);
        e.u64(self.consumed_input.workflow_step);
        e.fixed(&self.target_deployment.0);
        e.fixed(&self.target_program.0);
        encode_base(&mut e, &self.base);
        e.list(&self.writes, encode_write);
        e.list(&self.spawns, encode_actor_spawn);
        e.option(&self.crdt_change, |e, change| e.bytes(&change.encode()));
        e.list(&self.continuations, encode_continuation_change);
        e.list(&self.inbox, encode_message);
        e.list(&self.outbox, encode_message);
        e.option(&self.reply, encode_reply);
        e.list(&self.exported_blobs, encode_blob_ref);
        e.u64(self.gas.refine_used);
        e.u64(self.gas.proof_used);
        e.u64(self.gas.accumulate_used);
        e.option(&self.proof, encode_proof);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let result = Self {
            service: decode_service(d)?,
            consumed_input: WorkInputId {
                invocation: InvocationId(d.fixed()?),
                workflow_step: d.u64()?,
            },
            target_deployment: DeploymentId(d.fixed()?),
            target_program: ProgramId(d.fixed()?),
            base: decode_base(d)?,
            writes: d.list(decode_write)?,
            spawns: d.list(decode_actor_spawn)?,
            crdt_change: d.option(|d| CrdtChange::decode(&d.bytes()?))?,
            continuations: d.list(decode_continuation_change)?,
            inbox: d.list(decode_message)?,
            outbox: d.list(decode_message)?,
            reply: d.option(decode_reply)?,
            exported_blobs: d.list(decode_blob_ref)?,
            gas: GasAccounting {
                refine_used: d.u64()?,
                proof_used: d.u64()?,
                accumulate_used: d.u64()?,
            },
            proof: d.option(decode_proof)?,
        };
        ensure_sorted_unique(&result.spawns, |spawn| spawn.actor.0)?;
        ensure_sorted_unique(&result.exported_blobs, |b| b.hash.0)?;
        Ok(result)
    }
}

impl ServiceWire for RefineOutput {
    const MAGIC: [u8; 4] = *b"VROW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.bytes(&self.transition.encode());
        e.list(&self.candidate_blobs, |e, blob| {
            encode_blob_ref(e, &blob.reference);
            e.bytes(&blob.bytes);
        });
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            transition: Transition::decode(&d.bytes()?)?,
            candidate_blobs: d.list(|d| {
                Ok(ImportedBlob {
                    reference: decode_blob_ref(d)?,
                    bytes: d.bytes()?,
                })
            })?,
        };
        validate_candidate_blobs(None, &value.transition, &value.candidate_blobs)?;
        Ok(value)
    }
}

impl ServiceWire for CrdtChange {
    const MAGIC: [u8; 4] = *b"VCGW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.id.0);
        e.fixed(&self.work_hash.0);
        e.list(&self.causal_dependencies, |e, dependency| {
            e.fixed(&dependency.0)
        });
        e.u64(self.causal_height);
        e.list(&self.operations, encode_crdt_op);
        e.list(&self.workflow, encode_workflow_operation);
        e.list(&self.materializations, |e, materialization| {
            e.fixed(&materialization.actor.0);
            encode_blob_ref(e, &materialization.state);
        });
        e.option(&self.awaited_reply, |e, reply| e.bytes(&reply.encode()));
        e.list(&self.exported_blobs, encode_blob_ref);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            id: ChangeId(d.fixed()?),
            work_hash: Hash(d.fixed()?),
            causal_dependencies: d.list(|d| d.fixed().map(Hash))?,
            causal_height: d.u64()?,
            operations: d.list(decode_crdt_op)?,
            workflow: d.list(decode_workflow_operation)?,
            materializations: d.list(|d| {
                Ok(CrdtMaterialization {
                    actor: ActorId(d.fixed()?),
                    state: decode_blob_ref(d)?,
                })
            })?,
            awaited_reply: d.option(|d| AccumulatedReply::decode(&d.bytes()?))?,
            exported_blobs: d.list(decode_blob_ref)?,
        };
        ensure_sorted_unique(&value.causal_dependencies, |hash| hash.0)?;
        ensure_sorted_unique(&value.operations, |operation| {
            (
                operation.actor.0,
                operation.dispatch_ordinal,
                operation.ordinal,
            )
        })?;
        ensure_sorted_unique(&value.materializations, |materialization| {
            materialization.actor.0
        })?;
        ensure_sorted_unique(&value.exported_blobs, |reference| reference.hash.0)?;
        let checkpoint_exports_match = value.exported_blobs.iter().all(|reference| {
            value.workflow.iter().any(|operation| {
                matches!(operation,
                    WorkflowOperation::Continuation(change)
                        if change.replacement.as_ref() == Some(reference))
            })
        }) && value.workflow.iter().all(|operation| {
            let WorkflowOperation::Continuation(change) = operation else {
                return true;
            };
            change.replacement.as_ref().is_none_or(|reference| {
                value
                    .exported_blobs
                    .binary_search_by_key(&reference.hash, |candidate| candidate.hash)
                    .ok()
                    .is_some_and(|index| value.exported_blobs[index] == *reference)
            })
        });
        let operation_scope = value.workflow.iter().find_map(|operation| match operation {
            WorkflowOperation::Checkpoint(work) => Self::derive_operation_scope(work),
            _ => None,
        });
        let consumed_reply_call = value
            .awaited_reply
            .as_ref()
            .map(|reply| reply.reply.call_id);
        let mut consumed_outbox_calls =
            value
                .workflow
                .iter()
                .filter_map(|operation| match operation {
                    WorkflowOperation::ConsumeOutbox(call) => Some(*call),
                    _ => None,
                });
        let consumed_reply_is_canonical = consumed_reply_call.is_none_or(|call| {
            consumed_outbox_calls.next() == Some(call) && consumed_outbox_calls.next().is_none()
        });
        if value.causal_height == 0
            || value.operations.iter().any(|operation| {
                operation.payload.is_empty()
                    || operation_scope.is_none_or(|scope| {
                        operation.id
                            != scope.operation(
                                operation.actor,
                                operation.dispatch_ordinal,
                                operation.field,
                                operation.ordinal,
                            )
                    })
            })
            || !checkpoint_exports_match
            || !consumed_reply_is_canonical
            || value.workflow.windows(2).any(|pair| {
                workflow_operation_bytes(&pair[0]) >= workflow_operation_bytes(&pair[1])
            })
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for BlobRef {
    const MAGIC: [u8; 4] = *b"VBRW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        encode_blob_ref(&mut Encoder(out), self);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_blob_ref(d)
    }
}

impl ServiceWire for RoleAuthorityBinding {
    const MAGIC: [u8; 4] = *b"VABW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encode_service(&mut encoder, &self.service);
        encoder.fixed(&self.actor.0);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(decoder)?,
            actor: ActorId(decoder.fixed()?),
        };
        if value.actor == ActorId::ZERO {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for RoleAuthorityMutation {
    const MAGIC: [u8; 4] = *b"VRMW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        match self {
            Self::Grant {
                space,
                holder,
                role,
                epoch,
            } => {
                encoder.u8(0);
                encoder.fixed(&space.0);
                encode_origin(&mut encoder, *holder);
                encoder.u8(role.as_u8());
                encoder.u64(*epoch);
            }
            Self::Revoke {
                space,
                holder,
                epoch,
            } => {
                encoder.u8(1);
                encoder.fixed(&space.0);
                encode_origin(&mut encoder, *holder);
                encoder.u64(*epoch);
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = match decoder.u8()? {
            0 => Self::Grant {
                space: SpaceId(decoder.fixed()?),
                holder: decode_origin(decoder)?,
                role: crate::SpaceRole::from_u8(decoder.u8()?).ok_or(DecodeError::NonCanonical)?,
                epoch: decoder.u64()?,
            },
            1 => Self::Revoke {
                space: SpaceId(decoder.fixed()?),
                holder: decode_origin(decoder)?,
                epoch: decoder.u64()?,
            },
            _ => return Err(DecodeError::InvalidTag),
        };
        if value.epoch() == 0 || !matches!(value.holder(), Origin::Member(_) | Origin::Actor(_)) {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for RoleAuthorityInviteRedemption {
    const MAGIC: [u8; 4] = *b"VIGW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.authority_replication_id);
        encoder.fixed(&self.token_pub);
        encoder.u8(self.role.as_u8());
        encoder.u64(self.expires_at);
        encoder.bytes(&self.admin_peer_id);
        encoder.bytes(&self.admin_signature);
        encoder.bytes(&self.holder_peer_id);
        encoder.bytes(&self.redeem_signature);
        encoder.bytes(&self.holder_signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            space: SpaceId(decoder.fixed()?),
            authority_replication_id: decoder.fixed()?,
            token_pub: decoder.fixed()?,
            role: crate::SpaceRole::from_u8(decoder.u8()?).ok_or(DecodeError::NonCanonical)?,
            expires_at: decoder.u64()?,
            admin_peer_id: decoder.bytes()?,
            admin_signature: decoder
                .bytes()?
                .try_into()
                .map_err(|_| DecodeError::NonCanonical)?,
            holder_peer_id: decoder.bytes()?,
            redeem_signature: decoder
                .bytes()?
                .try_into()
                .map_err(|_| DecodeError::NonCanonical)?,
            holder_signature: decoder
                .bytes()?
                .try_into()
                .map_err(|_| DecodeError::NonCanonical)?,
        };
        if value.authority_replication_id == [0; 32]
            || !matches!(
                value.role,
                crate::SpaceRole::Member | crate::SpaceRole::Developer
            )
            || value.expires_at == 0
            || value.admin_peer_id.is_empty()
            || value.admin_peer_id.len() > 256
            || value.holder_peer_id.is_empty()
            || value.holder_peer_id.len() > 256
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for RoleAuthorityInviteRevocation {
    const MAGIC: [u8; 4] = *b"VIRW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.token_pub);
        encoder.bytes(&self.admin_peer_id);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            space: SpaceId(decoder.fixed()?),
            token_pub: decoder.fixed()?,
            admin_peer_id: decoder.bytes()?,
        };
        if value.admin_peer_id.is_empty() || value.admin_peer_id.len() > 256 {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for RoleAuthorizationClaim {
    const MAGIC: [u8; 4] = *b"VCLW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.fixed(&self.space.0);
        encode_origin(&mut encoder, self.holder);
        encoder.option(&self.role, |encoder, role| encoder.u8(role.as_u8()));
        encoder.option(&self.capability, |encoder, capability| {
            encoder.fixed(&capability.0)
        });
        encode_service(&mut encoder, &self.audience);
        encoder.fixed(&self.invocation.0);
        encoder.fixed(&self.scope.0);
        encoder.fixed(&self.target.0);
        encoder.string(&self.method);
        encoder.fixed(&self.policy.0);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            space: SpaceId(decoder.fixed()?),
            holder: decode_origin(decoder)?,
            role: decoder.option(|decoder| {
                crate::SpaceRole::from_u8(decoder.u8()?).ok_or(DecodeError::NonCanonical)
            })?,
            capability: decoder.option(|decoder| Ok(CapabilityId(decoder.fixed()?)))?,
            audience: decode_service(decoder)?,
            invocation: InvocationId(decoder.fixed()?),
            scope: Hash(decoder.fixed()?),
            target: ActorId(decoder.fixed()?),
            method: decoder.string()?,
            policy: Hash(decoder.fixed()?),
        };
        if !matches!(value.holder, Origin::Member(_) | Origin::Actor(_))
            || (value.role.is_some() == value.capability.is_some())
            || value.space != value.audience.space
            || value.invocation == InvocationId::ZERO
            || value.scope == Hash::ZERO
            || value.target == ActorId::ZERO
            || value.method.is_empty()
            || value.policy == Hash::ZERO
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for AccumulatedRoleAssertion {
    const MAGIC: [u8; 4] = *b"VRAW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.bytes(&self.claim.encode());
        encoder.bytes(&self.receipt.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            claim: RoleAuthorizationClaim::decode(&decoder.bytes()?)?,
            receipt: AccumulationReceipt::decode(&decoder.bytes()?)?,
        };
        if value.receipt.service.space != value.claim.space
            || value.receipt.reply_commitment.is_none()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl RoleCredential {
    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/credential-commitment/service", &[&self.encode()])
    }

    pub fn disclosed_evidence(&self, policy: Hash) -> AuthorizationEvidence {
        let bytes = self.encode();
        AuthorizationEvidence::Credential {
            policy,
            credential_commitment: Hash::digest(b"vos/credential-commitment/service", &[&bytes]),
            bytes,
        }
    }

    pub fn private_evidence(&self, policy: Hash) -> (AuthorizationEvidence, ImportedBlob) {
        let bytes = self.encode();
        let reference = BlobRef::of_bytes(&bytes);
        (
            AuthorizationEvidence::PrivateCredential {
                policy,
                credential_commitment: Hash::digest(
                    b"vos/credential-commitment/service",
                    &[&bytes],
                ),
                witness: reference.clone(),
            },
            ImportedBlob { reference, bytes },
        )
    }
}

impl ServiceWire for RoleCredential {
    const MAGIC: [u8; 4] = *b"VRCW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encode_origin(&mut encoder, self.holder);
        encoder.fixed(&self.scope.0);
        encoder.option(&self.space_role, |encoder, role| encoder.u8(role.as_u8()));
        encoder.option(&self.capability, |encoder, capability| {
            encoder.fixed(&capability.0)
        });
        encoder.option(&self.actor_role, |encoder, role| encoder.u8(*role));
        encoder.bytes(&self.authenticator);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            holder: decode_origin(decoder)?,
            scope: Hash(decoder.fixed()?),
            space_role: decoder.option(|decoder| {
                crate::SpaceRole::from_u8(decoder.u8()?).ok_or(DecodeError::NonCanonical)
            })?,
            capability: decoder.option(|decoder| Ok(CapabilityId(decoder.fixed()?)))?,
            actor_role: decoder.option(Decoder::u8)?,
            authenticator: decoder.bytes()?,
        };
        if !matches!(value.holder, Origin::Member(_) | Origin::Actor(_))
            || value.scope == Hash::ZERO
            || value.actor_role == Some(u8::MAX)
            || (value.space_role.is_none()
                && value.capability.is_none()
                && value.actor_role.is_none())
            || (value.space_role.is_some() && value.capability.is_some())
            || value.authenticator.is_empty()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for MethodPolicy {
    const MAGIC: [u8; 4] = *b"VMPW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.string(&self.method);
        e.fixed(&self.schema.0);
        e.fixed(&self.policy.0);
        e.bool(self.public);
        e.bool(self.attested);
        e.option(&self.space_role, |e, role| e.u8(*role));
        e.option(&self.capability, |e, capability| e.fixed(&capability.0));
        e.option(&self.actor_role, |e, role| e.u8(*role));
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            method: d.string()?,
            schema: Hash(d.fixed()?),
            policy: Hash(d.fixed()?),
            public: d.bool()?,
            attested: d.bool()?,
            space_role: d.option(|d| {
                let role = d.u8()?;
                crate::SpaceRole::from_u8(role)
                    .map(|_| role)
                    .ok_or(DecodeError::NonCanonical)
            })?,
            capability: d.option(|d| Ok(CapabilityId(d.fixed()?)))?,
            actor_role: d.option(Decoder::u8)?,
        };
        if value.method.is_empty()
            || value.public
                != (value.space_role.is_none()
                    && value.capability.is_none()
                    && value.actor_role.is_none())
            || super::package::method_authorization_policy_hash(
                value.capability,
                value.space_role,
                value.actor_role,
            ) != Some(value.policy)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for ActorGenesis {
    const MAGIC: [u8; 4] = *b"VAGW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        encode_actor_genesis(&mut Encoder(out), self);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_actor_genesis(d)
    }
}

impl ServiceWire for ActorDirectory {
    const MAGIC: [u8; 4] = *b"VADW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        Encoder(out).list(&self.actors, |e, actor| e.fixed(&actor.0));
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            actors: d.list(|d| d.fixed().map(ActorId))?,
        };
        if value.actors.is_empty() || value.actors.len() > super::MAX_ROOT_TREE_ACTORS {
            return Err(DecodeError::NonCanonical);
        }
        ensure_sorted_unique(&value.actors, |actor| actor.0)?;
        Ok(value)
    }
}

impl ServiceWire for ExternalActorDirectory {
    const MAGIC: [u8; 4] = *b"VEXW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        Encoder(out).list(&self.actors, encode_external_actor);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            actors: d.list(decode_external_actor)?,
        };
        ensure_external_actors_canonical(&value.actors)?;
        Ok(value)
    }
}

impl ServiceWire for MessageRecord {
    const MAGIC: [u8; 4] = *b"VMRW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        encode_message(&mut Encoder(out), self);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_message(d)
    }
}

impl ServiceWire for AccumulatedReply {
    const MAGIC: [u8; 4] = *b"VRPW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_reply(&mut e, &self.reply);
        e.bytes(&self.receipt.encode());
        e.option(&self.attestation, |e, attestation| {
            e.string(&attestation.producer_name);
            e.fixed(&attestation.producer.0);
            e.bytes(&attestation.statement.encode());
            encode_proof(e, &attestation.proof);
        });
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            reply: decode_reply(d)?,
            receipt: AccumulationReceipt::decode(&d.bytes()?)?,
            attestation: d.option(|d| {
                Ok(Box::new(AttestationDelivery {
                    producer_name: d.string()?,
                    producer: ProducerId(d.fixed()?),
                    statement: AttestationStatement::decode(&d.bytes()?)?,
                    proof: decode_proof(d)?,
                }))
            })?,
        };
        value.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(value)
    }
}

impl ServiceWire for CallTimeout {
    const MAGIC: [u8; 4] = *b"VTOW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.call_id.0);
        e.fixed(&self.caller_invocation.0);
        e.fixed(&self.caller_actor.0);
        e.u64(self.checkpoint_step);
        e.u64(self.await_ordinal);
        e.u64(self.deadline_timeslot);
        e.u64(self.expired_at);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            call_id: CallId(d.fixed()?),
            caller_invocation: InvocationId(d.fixed()?),
            caller_actor: ActorId(d.fixed()?),
            checkpoint_step: d.u64()?,
            await_ordinal: d.u64()?,
            deadline_timeslot: d.u64()?,
            expired_at: d.u64()?,
        };
        if value.call_id != value.caller_invocation.call_id(value.await_ordinal)
            || value.caller_actor == ActorId::ZERO
            || value.expired_at != value.deadline_timeslot
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for CallExpirationEnvelope {
    const MAGIC: [u8; 4] = *b"VCEW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.bytes(&self.timeout.encode());
        encode_base(&mut e, &self.base);
        e.option(&self.base_causal_height, |e, height| e.u64(*height));
        e.option(&self.crdt_change, |e, change| e.bytes(&change.encode()));
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(d)?,
            timeout: CallTimeout::decode(&d.bytes()?)?,
            base: decode_base(d)?,
            base_causal_height: d.option(Decoder::u64)?,
            crdt_change: d.option(|d| CrdtChange::decode(&d.bytes()?))?,
        };
        match (&value.base, value.base_causal_height, &value.crdt_change) {
            (ConsistencyBase::Linear { .. }, None, None) => {}
            (ConsistencyBase::Crdt { heads }, Some(height), Some(change))
                if change.id
                    == CrdtChange::derive_expiration_id(&value.service, &value.timeout, heads)
                    && change.causal_dependencies == *heads
                    && height.checked_add(1) == Some(change.causal_height)
                    && change.work_hash == value.timeout.commitment()
                    && change.operations.is_empty()
                    && change.materializations.is_empty()
                    && change.workflow
                        == [WorkflowOperation::ExpireCall(value.timeout.clone())] => {}
            _ => return Err(DecodeError::NonCanonical),
        }
        Ok(value)
    }
}

impl ServiceWire for AccumulatedTimeout {
    const MAGIC: [u8; 4] = *b"VATW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.bytes(&self.expiration.encode());
        e.bytes(&self.receipt.encode());
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            expiration: CallExpirationEnvelope::decode(&d.bytes()?)?,
            receipt: AccumulationReceipt::decode(&d.bytes()?)?,
        };
        value.validate()?;
        Ok(value)
    }
}

impl ServiceWire for AccumulationReceipt {
    const MAGIC: [u8; 4] = *b"VARW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.fixed(&self.accepted_transition.0);
        e.option(&self.reply_commitment, |e, hash| e.fixed(&hash.0));
        e.option(&self.outbox_commitment, |e, hash| e.fixed(&hash.0));
        e.option(&self.resulting_state_root, |e, h| e.fixed(&h.0));
        e.list(&self.resulting_crdt_heads, |e, h| e.fixed(&h.0));
        e.u64(self.sequence);
        e.u64(self.checkpoint);
        e.u8(self.consistency as u8);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(d)?,
            accepted_transition: Hash(d.fixed()?),
            reply_commitment: d.option(|d| d.fixed().map(Hash))?,
            outbox_commitment: d.option(|d| d.fixed().map(Hash))?,
            resulting_state_root: d.option(|d| d.fixed().map(Hash))?,
            resulting_crdt_heads: d.list(|d| d.fixed().map(Hash))?,
            sequence: d.u64()?,
            checkpoint: d.u64()?,
            consistency: ConsistencyMode::decode(d)?,
        };
        ensure_sorted_unique(&value.resulting_crdt_heads, |h| h.0)?;
        validate_result_commitment(
            value.consistency,
            value.resulting_state_root,
            &value.resulting_crdt_heads,
        )?;
        Ok(value)
    }
}

impl ServiceWire for ReceiptVerificationRequest {
    const MAGIC: [u8; 4] = *b"VRRQ";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.expected_producer.0);
        e.bytes(&self.receipt.encode());
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            expected_producer: ActorId(d.fixed()?),
            receipt: AccumulationReceipt::decode(&d.bytes()?)?,
        })
    }
}

impl ServiceWire for ProofVerificationRequest {
    const MAGIC: [u8; 4] = *b"VPRQ";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.actor_program.0);
        e.fixed(&self.execution_semantics.0);
        e.fixed(&self.statement.0);
        e.fixed(&self.trace.0);
        encode_blob_ref(&mut e, &self.proof_blob);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            actor_program: ProgramId(d.fixed()?),
            execution_semantics: Hash(d.fixed()?),
            statement: Hash(d.fixed()?),
            trace: Hash(d.fixed()?),
            proof_blob: decode_blob_ref(d)?,
        };
        if value.statement == Hash::ZERO || value.trace == Hash::ZERO {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for AttestationProofManifest {
    const MAGIC: [u8; 4] = *b"VPMW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.proof_system.0);
        e.fixed(&self.initial_root.0);
        e.list(&self.segments, |e, segment| e.fixed(&segment.0));
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            proof_system: Hash(d.fixed()?),
            initial_root: Hash(d.fixed()?),
            segments: d.list(|d| d.fixed().map(ProofArtifactId))?,
        };
        if value.proof_system != Self::proof_system()
            || value.initial_root == Hash::ZERO
            || value.segments.is_empty()
            || value.segments.len() > super::MAX_ATTESTATION_PROOF_SEGMENTS
            || value.segments.iter().any(|segment| segment.0 == [0; 32])
        {
            return Err(DecodeError::NonCanonical);
        }
        let mut hashes = value.segments.to_vec();
        hashes.sort_unstable();
        if hashes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for RoleCredentialVerificationRequest {
    const MAGIC: [u8; 4] = *b"VCRQ";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.fixed(&self.actor.0);
        e.fixed(&self.policy.0);
        e.fixed(&self.scope.0);
        e.fixed(&self.credential_commitment.0);
        e.bytes(&self.credential);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(d)?,
            actor: ActorId(d.fixed()?),
            policy: Hash(d.fixed()?),
            scope: Hash(d.fixed()?),
            credential_commitment: Hash(d.fixed()?),
            credential: d.bytes()?,
        };
        if value.policy == Hash::ZERO
            || value.scope == Hash::ZERO
            || value.credential_commitment == Hash::ZERO
            || value.credential.is_empty()
            || Hash::digest(b"vos/credential-commitment/service", &[&value.credential])
                != value.credential_commitment
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for ServiceGenesis {
    const MAGIC: [u8; 4] = *b"VGNW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.u8(self.consistency as u8);
        e.list(&self.actors, encode_actor_genesis);
        e.list(&self.external_actors, encode_external_actor);
        e.option(&self.role_authority, |e, authority| {
            e.bytes(&authority.encode())
        });
        encode_auth(&mut e, &self.authorization);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(d)?,
            consistency: ConsistencyMode::decode(d)?,
            actors: d.list(decode_actor_genesis)?,
            external_actors: d.list(decode_external_actor)?,
            role_authority: d.option(|d| RoleAuthorityBinding::decode(&d.bytes()?))?,
            authorization: decode_auth(d)?,
        };
        validate_genesis(&value)?;
        Ok(value)
    }
}

impl ServiceGenesis {
    /// Validate the typed value before any installation-side availability
    /// checks or state writes. Wire decoding calls the same validator.
    pub fn validate(&self) -> Result<(), DecodeError> {
        validate_genesis(self)
    }
}

impl ServiceWire for ActorUpgrade {
    const MAGIC: [u8; 4] = *b"VAUW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.fixed(&self.actor.0);
        e.fixed(&self.expected_deployment.0);
        e.fixed(&self.expected_program.0);
        e.fixed(&self.replacement_deployment.0);
        e.fixed(&self.replacement_program.0);
        e.fixed(&self.producer.0);
        e.bytes(&self.role_policies);
        encode_base(&mut e, &self.base);
        encode_auth(&mut e, &self.authorization);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(d)?,
            actor: ActorId(d.fixed()?),
            expected_deployment: DeploymentId(d.fixed()?),
            expected_program: ProgramId(d.fixed()?),
            replacement_deployment: DeploymentId(d.fixed()?),
            replacement_program: ProgramId(d.fixed()?),
            producer: ProducerId(d.fixed()?),
            role_policies: d.bytes()?,
            base: decode_base(d)?,
            authorization: decode_auth(d)?,
        };
        if value.service.execution_semantics != super::EXECUTION_SEMANTICS_ID
            || value.expected_deployment == value.replacement_deployment
            || super::PackageRolePolicies::decode(&value.role_policies).is_err()
            || !matches!(
                &value.authorization,
                AuthorizationEvidence::SystemCapability { authenticator, .. }
                    if !authenticator.is_empty()
            )
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for AccumulationEnvelope {
    const MAGIC: [u8; 4] = *b"VAEW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.bytes(&self.work.encode());
        e.bytes(&self.transition.encode());
        e.list(&self.provided_blobs, |e, blob| {
            encode_blob_ref(e, &blob.reference);
            e.bytes(&blob.bytes);
        });
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            work: WorkEnvelope::decode(&d.bytes()?)?,
            transition: Transition::decode(&d.bytes()?)?,
            provided_blobs: d.list(|d| {
                Ok(ImportedBlob {
                    reference: decode_blob_ref(d)?,
                    bytes: d.bytes()?,
                })
            })?,
        };
        validate_accumulation_envelope(&value)?;
        Ok(value)
    }
}

impl ServiceWire for DeliveryEnvelope {
    const MAGIC: [u8; 4] = *b"VDLW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.u64(self.logical_timeslot);
        encode_base(&mut e, &self.base);
        encode_auth(&mut e, &self.authorization);
        encode_message(&mut e, &self.message);
        e.list(&self.source_outbox, encode_message);
        e.bytes(&self.source_receipt.encode());
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(d)?,
            logical_timeslot: d.u64()?,
            base: decode_base(d)?,
            authorization: decode_auth(d)?,
            message: decode_message(d)?,
            source_outbox: d.list(decode_message)?,
            source_receipt: AccumulationReceipt::decode(&d.bytes()?)?,
        };
        ensure_sorted_unique(&value.source_outbox, |message| message.call_id.0)?;
        if value.message.authorization != AuthorizationEvidence::Public
            || value
                .source_outbox
                .binary_search_by_key(&value.message.call_id, |message| message.call_id)
                .ok()
                .is_none_or(|index| value.source_outbox[index] != value.message)
            || value.source_receipt.outbox_commitment
                != MessageRecord::outbox_commitment(&value.source_outbox)
            || !matches!(
                value.source_receipt.consistency,
                ConsistencyMode::Local | ConsistencyMode::Raft | ConsistencyMode::Crdt
            )
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for InboxRetirement {
    const MAGIC: [u8; 4] = *b"VIRX";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.fixed(&self.call_id.0);
        e.u64(self.deadline_timeslot);
        encode_base(&mut e, &self.base);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(d)?,
            call_id: CallId(d.fixed()?),
            deadline_timeslot: d.u64()?,
            base: decode_base(d)?,
        };
        if value.call_id == CallId::ZERO
            || value.deadline_timeslot == 0
            || !matches!(value.base, ConsistencyBase::Linear { .. })
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for PublicationAck {
    const MAGIC: [u8; 4] = *b"VPAW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.fixed(&self.input.invocation.0);
        e.u64(self.input.workflow_step);
        e.fixed(&self.publication.0);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(d)?,
            input: WorkInputId {
                invocation: InvocationId(d.fixed()?),
                workflow_step: d.u64()?,
            },
            publication: Hash(d.fixed()?),
        };
        if value.invocation_or_publication_is_zero() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl PublicationAck {
    fn invocation_or_publication_is_zero(&self) -> bool {
        self.input.invocation == InvocationId::ZERO || self.publication == Hash::ZERO
    }
}

impl ServiceWire for DirectIngress {
    const MAGIC: [u8; 4] = *b"VDIW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        self.encode_body_with_authorization(out, &self.authorization);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(d)?,
            invocation: InvocationId(d.fixed()?),
            logical_timeslot: d.u64()?,
            target: ActorId(d.fixed()?),
            method: d.string()?,
            arguments: d.bytes()?,
            private_arguments: d.option(decode_blob_ref)?,
            origin: decode_origin(d)?,
            authorization: decode_auth(d)?,
            imported_blobs: d.list(decode_blob_ref)?,
            proof_requested: d.bool()?,
            base: decode_base(d)?,
            base_causal_height: d.option(Decoder::u64)?,
            crdt_change: d.option(|d| CrdtChange::decode(&d.bytes()?))?,
        };
        ensure_sorted_unique(&value.imported_blobs, |blob| blob.hash.0)?;
        if value.invocation == InvocationId::ZERO
            || value.target == ActorId::ZERO
            || value.method.is_empty()
            || match value.private_arguments.as_ref() {
                Some(reference) => reference.len == 0 || !value.arguments.is_empty(),
                None => value.arguments.is_empty(),
            }
        {
            return Err(DecodeError::NonCanonical);
        }
        match (&value.base, value.base_causal_height, &value.crdt_change) {
            (ConsistencyBase::Linear { .. }, None, None) => {}
            (ConsistencyBase::Crdt { heads }, Some(height), Some(change)) => {
                let [WorkflowOperation::Ingress(operation)] = change.workflow.as_slice() else {
                    return Err(DecodeError::NonCanonical);
                };
                if !operation.matches_direct(&value)
                    || change.id != CrdtChange::derive_ingress_id(operation, heads)
                    || change.work_hash != operation.commitment()
                    || change.causal_dependencies != *heads
                    || height.checked_add(1) != Some(change.causal_height)
                    || !change.operations.is_empty()
                    || !change.materializations.is_empty()
                {
                    return Err(DecodeError::NonCanonical);
                }
            }
            _ => return Err(DecodeError::NonCanonical),
        }
        Ok(value)
    }
}

impl ServiceWire for CrdtSyncEnvelope {
    const MAGIC: [u8; 4] = *b"VCSW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.list(&self.advertised_heads, |e, head| e.fixed(&head.0));
        e.list(&self.nodes, |e, node| {
            e.bytes(&node.change.encode());
            e.bytes(&node.receipt.encode());
        });
        e.list(&self.provided_blobs, |e, blob| {
            encode_blob_ref(e, &blob.reference);
            e.bytes(&blob.bytes);
        });
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(d)?,
            advertised_heads: d.list(|d| d.fixed().map(Hash))?,
            nodes: d.list(|d| {
                Ok(CrdtSyncNode {
                    change: CrdtChange::decode(&d.bytes()?)?,
                    receipt: AccumulationReceipt::decode(&d.bytes()?)?,
                })
            })?,
            provided_blobs: d.list(|d| {
                Ok(ImportedBlob {
                    reference: decode_blob_ref(d)?,
                    bytes: d.bytes()?,
                })
            })?,
        };
        ensure_sorted_unique(&value.advertised_heads, |head| head.0)?;
        if value.advertised_heads.is_empty()
            || value
                .nodes
                .windows(2)
                .any(|pair| pair[0].change.cid() >= pair[1].change.cid())
        {
            return Err(DecodeError::NonCanonical);
        }
        ensure_sorted_unique(&value.provided_blobs, |blob| blob.reference.hash.0)?;
        for node in &value.nodes {
            let cid = node.change.cid();
            if node.receipt.service != value.service
                || node.receipt.consistency != ConsistencyMode::Crdt
                || node.receipt.resulting_state_root.is_some()
                || node.receipt.sequence != node.change.causal_height
                || node
                    .receipt
                    .resulting_crdt_heads
                    .binary_search(&cid)
                    .is_err()
            {
                return Err(DecodeError::NonCanonical);
            }
        }
        for blob in &value.provided_blobs {
            if !blob.reference.matches(&blob.bytes)
                || !value.nodes.iter().any(|node| {
                    crdt_change_blob_references(&node.change)
                        .into_iter()
                        .any(|reference| reference == &blob.reference)
                })
            {
                return Err(DecodeError::NonCanonical);
            }
        }
        Ok(value)
    }
}

impl ServiceWire for AccumulateRequest {
    const MAGIC: [u8; 4] = *b"VACW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        match self {
            Self::Install(genesis) => {
                e.u8(0);
                e.bytes(&genesis.encode());
            }
            Self::AdmitIngress(ingress) => {
                e.u8(6);
                e.bytes(&ingress.encode());
            }
            Self::Apply(envelope) => {
                e.u8(1);
                e.bytes(&envelope.encode());
            }
            Self::PrepareAttested(envelope) => {
                e.u8(2);
                e.bytes(&envelope.encode());
            }
            Self::Deliver(envelope) => {
                e.u8(3);
                e.bytes(&envelope.encode());
            }
            Self::RetireInbox(retirement) => {
                e.u8(9);
                e.bytes(&retirement.encode());
            }
            Self::ExpireCall(envelope) => {
                e.u8(7);
                e.bytes(&envelope.encode());
            }
            Self::AcknowledgePublication(acknowledgement) => {
                e.u8(4);
                e.bytes(&acknowledgement.encode());
            }
            Self::SyncCrdt(envelope) => {
                e.u8(5);
                e.bytes(&envelope.encode());
            }
            Self::UpgradeActor(upgrade) => {
                e.u8(8);
                e.bytes(&upgrade.encode());
            }
        }
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match d.u8()? {
            0 => Ok(Self::Install(ServiceGenesis::decode(&d.bytes()?)?)),
            6 => Ok(Self::AdmitIngress(DirectIngress::decode(&d.bytes()?)?)),
            1 => Ok(Self::Apply(AccumulationEnvelope::decode(&d.bytes()?)?)),
            2 => Ok(Self::PrepareAttested(AccumulationEnvelope::decode(
                &d.bytes()?,
            )?)),
            3 => Ok(Self::Deliver(DeliveryEnvelope::decode(&d.bytes()?)?)),
            9 => Ok(Self::RetireInbox(InboxRetirement::decode(&d.bytes()?)?)),
            7 => Ok(Self::ExpireCall(CallExpirationEnvelope::decode(
                &d.bytes()?,
            )?)),
            4 => Ok(Self::AcknowledgePublication(PublicationAck::decode(
                &d.bytes()?,
            )?)),
            5 => Ok(Self::SyncCrdt(CrdtSyncEnvelope::decode(&d.bytes()?)?)),
            8 => Ok(Self::UpgradeActor(ActorUpgrade::decode(&d.bytes()?)?)),
            _ => Err(DecodeError::InvalidTag),
        }
    }
}

impl ServiceWire for PublishedEffects {
    const MAGIC: [u8; 4] = *b"VEFW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.option(&self.reply, encode_reply);
        e.list(&self.outbox, encode_message);
        e.list(&self.exported_blobs, encode_blob_ref);
        e.option(&self.proof, encode_proof);
        e.option(&self.attestation, |e, attestation| {
            e.string(&attestation.producer_name);
            e.fixed(&attestation.producer.0);
            e.bytes(&attestation.statement.encode());
            encode_proof(e, &attestation.proof);
        });
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            reply: d.option(decode_reply)?,
            outbox: d.list(decode_message)?,
            exported_blobs: d.list(decode_blob_ref)?,
            proof: d.option(decode_proof)?,
            attestation: d.option(|d| {
                Ok(Box::new(AttestationDelivery {
                    producer_name: d.string()?,
                    producer: ProducerId(d.fixed()?),
                    statement: AttestationStatement::decode(&d.bytes()?)?,
                    proof: decode_proof(d)?,
                }))
            })?,
        };
        ensure_sorted_unique(&value.outbox, |message| message.call_id.0)?;
        ensure_sorted_unique(&value.exported_blobs, |blob| blob.hash.0)?;
        match (&value.proof, &value.attestation) {
            (None, None) => {}
            (Some(proof), Some(attestation))
                if attestation.producer_name.is_empty()
                    || attestation.producer == ProducerId::ZERO
                    || attestation.producer_name != attestation.statement.producer_name
                    || attestation.producer != attestation.statement.producer
                    || proof.statement != attestation.statement.commitment()
                    || &attestation.proof != proof =>
            {
                return Err(DecodeError::NonCanonical);
            }
            (Some(_), Some(_)) => {}
            _ => return Err(DecodeError::NonCanonical),
        }
        Ok(value)
    }
}

impl ServiceWire for AccumulationResult {
    const MAGIC: [u8; 4] = *b"VAOW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        match self {
            Self::Installed(receipt) => {
                e.u8(0);
                encode_install_receipt(&mut e, receipt);
            }
            Self::IngressAdmitted {
                invocation,
                receipt,
                duplicate,
            } => {
                e.u8(5);
                e.fixed(&invocation.0);
                e.bytes(&receipt.encode());
                e.bool(*duplicate);
            }
            Self::Accepted {
                receipt,
                published,
                duplicate,
            } => {
                e.u8(1);
                e.bytes(&receipt.encode());
                e.bytes(&published.encode());
                e.bool(*duplicate);
            }
            Self::Prepared(preparation) => {
                e.u8(2);
                e.bytes(&preparation.encode());
            }
            Self::CallExpired { timeout, duplicate } => {
                e.u8(6);
                e.bytes(&timeout.encode());
                e.bool(*duplicate);
            }
            Self::InboxRetired { call_id, duplicate } => {
                e.u8(8);
                e.fixed(&call_id.0);
                e.bool(*duplicate);
            }
            Self::PublicationAcknowledged { input, duplicate } => {
                e.u8(4);
                e.fixed(&input.invocation.0);
                e.u64(input.workflow_step);
                e.bool(*duplicate);
            }
            Self::ActorUpgraded {
                actor,
                previous_deployment,
                previous_program,
                deployment,
                program,
                receipt,
                duplicate,
            } => {
                e.u8(7);
                e.fixed(&actor.0);
                e.fixed(&previous_deployment.0);
                e.fixed(&previous_program.0);
                e.fixed(&deployment.0);
                e.fixed(&program.0);
                e.bytes(&receipt.encode());
                e.bool(*duplicate);
            }
            Self::Rejected(rejection) => {
                e.u8(3);
                encode_rejection(&mut e, rejection);
            }
        }
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match d.u8()? {
            0 => Ok(Self::Installed(decode_install_receipt(d)?)),
            5 => {
                let invocation = InvocationId(d.fixed()?);
                let receipt = AccumulationReceipt::decode(&d.bytes()?)?;
                let duplicate = d.bool()?;
                if invocation == InvocationId::ZERO || receipt.checkpoint != 0 {
                    return Err(DecodeError::NonCanonical);
                }
                Ok(Self::IngressAdmitted {
                    invocation,
                    receipt,
                    duplicate,
                })
            }
            1 => {
                let receipt = AccumulationReceipt::decode(&d.bytes()?)?;
                let published = PublishedEffects::decode(&d.bytes()?)?;
                let duplicate = d.bool()?;
                if duplicate && published != PublishedEffects::default() {
                    return Err(DecodeError::NonCanonical);
                }
                if !duplicate
                    && (published.reply.as_ref().map(ReplyRecord::commitment)
                        != receipt.reply_commitment
                        || MessageRecord::outbox_commitment(&published.outbox)
                            != receipt.outbox_commitment)
                {
                    return Err(DecodeError::NonCanonical);
                }
                Ok(Self::Accepted {
                    receipt,
                    published,
                    duplicate,
                })
            }
            2 => Ok(Self::Prepared(AttestationPreparation::decode(&d.bytes()?)?)),
            6 => Ok(Self::CallExpired {
                timeout: AccumulatedTimeout::decode(&d.bytes()?)?,
                duplicate: d.bool()?,
            }),
            8 => {
                let call_id = CallId(d.fixed()?);
                let duplicate = d.bool()?;
                if call_id == CallId::ZERO {
                    return Err(DecodeError::NonCanonical);
                }
                Ok(Self::InboxRetired { call_id, duplicate })
            }
            3 => Ok(Self::Rejected(decode_rejection(d)?)),
            4 => {
                let input = WorkInputId {
                    invocation: InvocationId(d.fixed()?),
                    workflow_step: d.u64()?,
                };
                let duplicate = d.bool()?;
                if input.invocation == InvocationId::ZERO {
                    return Err(DecodeError::NonCanonical);
                }
                Ok(Self::PublicationAcknowledged { input, duplicate })
            }
            7 => {
                let actor = ActorId(d.fixed()?);
                let previous_deployment = DeploymentId(d.fixed()?);
                let previous_program = ProgramId(d.fixed()?);
                let deployment = DeploymentId(d.fixed()?);
                let program = ProgramId(d.fixed()?);
                let receipt = AccumulationReceipt::decode(&d.bytes()?)?;
                let duplicate = d.bool()?;
                if previous_deployment == deployment
                    || receipt.reply_commitment.is_some()
                    || receipt.outbox_commitment.is_some()
                    || receipt.checkpoint != 0
                {
                    return Err(DecodeError::NonCanonical);
                }
                Ok(Self::ActorUpgraded {
                    actor,
                    previous_deployment,
                    previous_program,
                    deployment,
                    program,
                    receipt,
                    duplicate,
                })
            }
            _ => Err(DecodeError::InvalidTag),
        }
    }
}

fn encode_actor_genesis(e: &mut Encoder<'_>, value: &ActorGenesis) {
    e.fixed(&value.actor.0);
    e.string(&value.name);
    e.option(&value.parent, |e, parent| e.fixed(&parent.0));
    e.fixed(&value.producer.0);
    e.fixed(&value.deployment.0);
    e.fixed(&value.program.0);
    encode_blob_ref(e, &value.initial_state);
    e.bool(value.crdt);
    e.bytes(&value.role_policies);
}

fn decode_actor_genesis(d: &mut Decoder<'_>) -> Result<ActorGenesis, DecodeError> {
    let value = ActorGenesis {
        actor: ActorId(d.fixed()?),
        name: d.string()?,
        parent: d.option(|d| d.fixed().map(ActorId))?,
        producer: ProducerId(d.fixed()?),
        deployment: DeploymentId(d.fixed()?),
        program: ProgramId(d.fixed()?),
        initial_state: decode_blob_ref(d)?,
        crdt: d.bool()?,
        role_policies: d.bytes()?,
    };
    if value.name.is_empty()
        || value.name.len() > super::MAX_ACTOR_NAME_BYTES
        || super::package::PackageRolePolicies::decode(&value.role_policies).is_err()
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn validate_genesis(value: &ServiceGenesis) -> Result<(), DecodeError> {
    if value.actors.is_empty() || value.actors.len() > super::MAX_ROOT_TREE_ACTORS {
        return Err(DecodeError::NonCanonical);
    }
    ensure_sorted_unique(&value.actors, |actor| actor.actor.0)?;
    let roots: Vec<_> = value
        .actors
        .iter()
        .filter(|actor| actor.parent.is_none())
        .map(|actor| actor.actor)
        .collect();
    if roots.len() != 1 {
        return Err(DecodeError::NonCanonical);
    }
    let root = roots[0];
    let known: BTreeSet<_> = value.actors.iter().map(|actor| actor.actor).collect();
    let mut names = BTreeSet::new();
    for actor in &value.actors {
        if actor.crdt != (value.consistency == ConsistencyMode::Crdt) {
            return Err(DecodeError::NonCanonical);
        }
        if actor.name.is_empty()
            || actor.name.len() > super::MAX_ACTOR_NAME_BYTES
            || actor.parent == Some(actor.actor)
            || actor.parent.is_some_and(|parent| !known.contains(&parent))
            || !names.insert((actor.parent, actor.name.as_str()))
        {
            return Err(DecodeError::NonCanonical);
        }
        let mut cursor = actor.actor;
        for _ in 0..value.actors.len() {
            if cursor == root {
                break;
            }
            let parent = value
                .actors
                .iter()
                .find(|candidate| candidate.actor == cursor)
                .and_then(|candidate| candidate.parent)
                .ok_or(DecodeError::NonCanonical)?;
            cursor = parent;
        }
        if cursor != root {
            return Err(DecodeError::NonCanonical);
        }
    }
    ensure_external_actors_canonical(&value.external_actors)?;
    let root_names = value
        .actors
        .iter()
        .filter(|actor| actor.parent.is_none())
        .map(|actor| actor.name.as_str())
        .collect::<BTreeSet<_>>();
    for external in &value.external_actors {
        if external.name.is_empty()
            || external.service == value.service
            || external.service.platform != super::PLATFORM_ID
            || external.service.execution_semantics != super::EXECUTION_SEMANTICS_ID
            || known.contains(&external.actor)
            || root_names.contains(external.name.as_str())
        {
            return Err(DecodeError::NonCanonical);
        }
    }
    if value.role_authority.as_ref().is_some_and(|authority| {
        authority.service.space != value.service.space
            || authority.service == value.service
            || authority.service.platform != super::PLATFORM_ID
            || authority.service.execution_semantics != super::EXECUTION_SEMANTICS_ID
            || authority.actor == ActorId::ZERO
    }) {
        return Err(DecodeError::NonCanonical);
    }
    match &value.authorization {
        AuthorizationEvidence::SystemCapability { authenticator, .. }
            if !authenticator.is_empty() =>
        {
            Ok(())
        }
        _ => Err(DecodeError::NonCanonical),
    }
}

fn validate_imported_actor_tree(
    actors: &[ImportedActor],
    target: ActorId,
    target_deployment: DeploymentId,
    target_program: ProgramId,
) -> Result<(), DecodeError> {
    if actors.is_empty() || actors.len() > super::MAX_ROOT_TREE_ACTORS {
        return Err(DecodeError::NonCanonical);
    }
    let known: BTreeSet<_> = actors.iter().map(|actor| actor.actor).collect();
    let roots = actors.iter().filter(|actor| actor.parent.is_none()).count();
    let mut names = BTreeSet::new();
    for actor in actors {
        if actor.name.is_empty()
            || actor.name.len() > super::MAX_ACTOR_NAME_BYTES
            || actor.parent == Some(actor.actor)
            || actor.parent.is_some_and(|parent| !known.contains(&parent))
            || !names.insert((actor.parent, actor.name.as_str()))
        {
            return Err(DecodeError::NonCanonical);
        }
    }
    let target_matches = actors
        .binary_search_by_key(&target, |actor| actor.actor)
        .ok()
        .is_some_and(|index| {
            actors[index].deployment == target_deployment && actors[index].program == target_program
        });
    if roots != 1 || !target_matches {
        return Err(DecodeError::NonCanonical);
    }
    let root = actors
        .iter()
        .find(|actor| actor.parent.is_none())
        .map(|actor| actor.actor)
        .ok_or(DecodeError::NonCanonical)?;
    for actor in actors {
        let mut cursor = actor.actor;
        for _ in 0..actors.len() {
            if cursor == root {
                break;
            }
            cursor = actors
                .iter()
                .find(|candidate| candidate.actor == cursor)
                .and_then(|candidate| candidate.parent)
                .ok_or(DecodeError::NonCanonical)?;
        }
        if cursor != root {
            return Err(DecodeError::NonCanonical);
        }
    }
    Ok(())
}

fn validate_actor_slice_tree(actors: &[ActorTreeImport]) -> Result<(), DecodeError> {
    if actors.is_empty() || actors.len() > super::MAX_ROOT_TREE_ACTORS {
        return Err(DecodeError::NonCanonical);
    }
    let known: BTreeSet<_> = actors.iter().map(|actor| actor.actor).collect();
    let roots = actors.iter().filter(|actor| actor.parent.is_none()).count();
    let mut names = BTreeSet::new();
    for actor in actors {
        if actor.name.is_empty()
            || actor.name.len() > super::MAX_ACTOR_NAME_BYTES
            || actor.parent == Some(actor.actor)
            || actor.parent.is_some_and(|parent| !known.contains(&parent))
            || !names.insert((actor.parent, actor.name.as_str()))
        {
            return Err(DecodeError::NonCanonical);
        }
    }
    if roots != 1 {
        return Err(DecodeError::NonCanonical);
    }
    let root = actors
        .iter()
        .find(|actor| actor.parent.is_none())
        .map(|actor| actor.actor)
        .ok_or(DecodeError::NonCanonical)?;
    for actor in actors {
        let mut cursor = actor.actor;
        for _ in 0..actors.len() {
            if cursor == root {
                break;
            }
            cursor = actors
                .iter()
                .find(|candidate| candidate.actor == cursor)
                .and_then(|candidate| candidate.parent)
                .ok_or(DecodeError::NonCanonical)?;
        }
        if cursor != root {
            return Err(DecodeError::NonCanonical);
        }
    }
    Ok(())
}

fn validate_accumulation_envelope(value: &AccumulationEnvelope) -> Result<(), DecodeError> {
    if value.work.service != value.transition.service
        || value.work.input_id() != value.transition.consumed_input
        || value.work.target_deployment != value.transition.target_deployment
        || value.work.target_program != value.transition.target_program
        || value.work.base != value.transition.base
        || !value.work.base.mode_compatible(value.work.consistency)
    {
        return Err(DecodeError::NonCanonical);
    }
    match (&value.work.base, &value.transition.crdt_change) {
        (ConsistencyBase::Crdt { heads }, Some(change))
            if value.work.consistency == ConsistencyMode::Crdt
                && value.transition.writes.is_empty()
                && value.transition.spawns.is_empty()
                && Some(change.id) == CrdtChange::derive_id(&value.work)
                && change.work_hash == value.work.hash()
                && change.causal_dependencies.as_slice() == heads.as_slice()
                && value
                    .work
                    .base_causal_height
                    .and_then(|height| height.checked_add(1))
                    == Some(change.causal_height)
                && change.workflow == value.transition.workflow_operations(&value.work)
                && change.awaited_reply == value.work.awaited_reply
                && change.exported_blobs == value.transition.exported_blobs =>
        {
            Ok(())
        }
        (ConsistencyBase::Linear { .. }, None)
            if value.work.consistency != ConsistencyMode::Crdt =>
        {
            Ok(())
        }
        _ => Err(DecodeError::NonCanonical),
    }?;
    validate_candidate_blobs(Some(&value.work), &value.transition, &value.provided_blobs)?;
    Ok(())
}

fn validate_candidate_blobs(
    work: Option<&WorkEnvelope>,
    transition: &Transition,
    candidates: &[ImportedBlob],
) -> Result<(), DecodeError> {
    ensure_sorted_unique(candidates, |blob| blob.reference.hash.0)?;
    let awaited_proof = work
        .and_then(|work| work.awaited_reply.as_ref())
        .and_then(|reply| reply.attestation.as_ref())
        .map(|attestation| &attestation.proof.proof_blob);
    for candidate in candidates {
        if !candidate.reference.matches(&candidate.bytes)
            || !(transition_blob_references(transition)
                .any(|reference| reference == &candidate.reference)
                || awaited_proof == Some(&candidate.reference))
        {
            return Err(DecodeError::NonCanonical);
        }
    }
    Ok(())
}

fn transition_blob_references(transition: &Transition) -> impl Iterator<Item = &BlobRef> {
    transition
        .exported_blobs
        .iter()
        .chain(transition.spawns.iter().map(|spawn| &spawn.initial_state))
        .chain(
            transition
                .continuations
                .iter()
                .filter_map(|change| change.replacement.as_ref()),
        )
        .chain(
            transition
                .crdt_change
                .iter()
                .flat_map(|change| change.materializations.iter())
                .map(|materialization| &materialization.state),
        )
        .chain(transition.proof.iter().map(|proof| &proof.proof_blob))
}

pub(crate) fn crdt_change_blob_references(change: &CrdtChange) -> Vec<&BlobRef> {
    let mut references = change
        .materializations
        .iter()
        .map(|materialization| &materialization.state)
        .collect::<Vec<_>>();
    references.extend(change.exported_blobs.iter());
    for operation in &change.workflow {
        match operation {
            WorkflowOperation::Checkpoint(work) => {
                references.extend(work.imported_blobs.iter());
            }
            WorkflowOperation::Continuation(change) => {
                references.extend(change.replacement.iter());
            }
            WorkflowOperation::Ingress(ingress) => {
                references.extend(ingress.authorization_blob.iter());
                references.extend(ingress.imported_blobs.iter());
            }
            WorkflowOperation::Delivery(_)
            | WorkflowOperation::Inbox(_)
            | WorkflowOperation::Outbox(_)
            | WorkflowOperation::ConsumeOutbox(_)
            | WorkflowOperation::ExpireCall(_)
            | WorkflowOperation::Reply(_) => {}
        }
    }
    references
}

fn encode_install_receipt(e: &mut Encoder<'_>, value: &ServiceInstallReceipt) {
    encode_service(e, &value.service);
    e.u8(value.consistency as u8);
    e.option(&value.resulting_state_root, |e, root| e.fixed(&root.0));
    e.list(&value.resulting_crdt_heads, |e, head| e.fixed(&head.0));
}

fn decode_install_receipt(d: &mut Decoder<'_>) -> Result<ServiceInstallReceipt, DecodeError> {
    let value = ServiceInstallReceipt {
        service: decode_service(d)?,
        consistency: ConsistencyMode::decode(d)?,
        resulting_state_root: d.option(|d| d.fixed().map(Hash))?,
        resulting_crdt_heads: d.list(|d| d.fixed().map(Hash))?,
    };
    ensure_sorted_unique(&value.resulting_crdt_heads, |head| head.0)?;
    validate_result_commitment(
        value.consistency,
        value.resulting_state_root,
        &value.resulting_crdt_heads,
    )?;
    Ok(value)
}

fn validate_result_commitment(
    consistency: ConsistencyMode,
    state_root: Option<Hash>,
    crdt_heads: &[Hash],
) -> Result<(), DecodeError> {
    let valid = match consistency {
        ConsistencyMode::Crdt => state_root.is_none(),
        ConsistencyMode::Ephemeral | ConsistencyMode::Local | ConsistencyMode::Raft => {
            state_root.is_some() && crdt_heads.is_empty()
        }
    };
    valid.then_some(()).ok_or(DecodeError::NonCanonical)
}

fn encode_rejection(e: &mut Encoder<'_>, value: &AccumulationRejection) {
    use AccumulationRejection as R;
    match value {
        R::StoreAlreadyInitialized => e.u8(0),
        R::StoreUninitialized => e.u8(1),
        R::WrongService => e.u8(2),
        R::WrongPlatform => e.u8(3),
        R::WrongExecutionSemantics => e.u8(4),
        R::WrongProgram => e.u8(5),
        R::InvalidConsistency => e.u8(6),
        R::Unauthorized => e.u8(7),
        R::MissingBlob(hash) => {
            e.u8(8);
            e.fixed(&hash.0);
        }
        R::MissingProof => e.u8(9),
        R::ProofUnavailable => e.u8(10),
        R::InvalidProof => e.u8(11),
        R::StaleLinearWork {
            expected_revision,
            actual_revision,
        } => {
            e.u8(12);
            e.u64(*expected_revision);
            e.u64(*actual_revision);
        }
        R::StaleStateRoot => e.u8(13),
        R::MissingCausalDependency(hash) => {
            e.u8(14);
            e.fixed(&hash.0);
        }
        R::TransitionInputMismatch => e.u8(15),
        R::TransitionBaseMismatch => e.u8(16),
        R::DivergentDuplicate => e.u8(17),
        R::InvalidWorkflowTransition => e.u8(18),
        R::ContinuationConflict(actor) => {
            e.u8(19);
            e.fixed(&actor.0);
        }
        R::MessageCycle => e.u8(20),
        R::StorageFull => e.u8(21),
        R::SequenceOverflow => e.u8(22),
        R::NonCanonical => e.u8(23),
        R::ReceiptUnavailable => e.u8(24),
        R::InvalidReceipt => e.u8(25),
        R::ActorBusy(actor) => {
            e.u8(26);
            e.fixed(&actor.0);
        }
    }
}

fn decode_rejection(d: &mut Decoder<'_>) -> Result<AccumulationRejection, DecodeError> {
    use AccumulationRejection as R;
    match d.u8()? {
        0 => Ok(R::StoreAlreadyInitialized),
        1 => Ok(R::StoreUninitialized),
        2 => Ok(R::WrongService),
        3 => Ok(R::WrongPlatform),
        4 => Ok(R::WrongExecutionSemantics),
        5 => Ok(R::WrongProgram),
        6 => Ok(R::InvalidConsistency),
        7 => Ok(R::Unauthorized),
        8 => Ok(R::MissingBlob(Hash(d.fixed()?))),
        9 => Ok(R::MissingProof),
        10 => Ok(R::ProofUnavailable),
        11 => Ok(R::InvalidProof),
        12 => Ok(R::StaleLinearWork {
            expected_revision: d.u64()?,
            actual_revision: d.u64()?,
        }),
        13 => Ok(R::StaleStateRoot),
        14 => Ok(R::MissingCausalDependency(Hash(d.fixed()?))),
        15 => Ok(R::TransitionInputMismatch),
        16 => Ok(R::TransitionBaseMismatch),
        17 => Ok(R::DivergentDuplicate),
        18 => Ok(R::InvalidWorkflowTransition),
        19 => Ok(R::ContinuationConflict(ActorId(d.fixed()?))),
        20 => Ok(R::MessageCycle),
        21 => Ok(R::StorageFull),
        22 => Ok(R::SequenceOverflow),
        23 => Ok(R::NonCanonical),
        24 => Ok(R::ReceiptUnavailable),
        25 => Ok(R::InvalidReceipt),
        26 => Ok(R::ActorBusy(ActorId(d.fixed()?))),
        _ => Err(DecodeError::InvalidTag),
    }
}

pub(super) fn encode_service(e: &mut Encoder<'_>, value: &ServiceIdentity) {
    e.fixed(&value.space.0);
    e.fixed(&value.root_service.0);
    e.fixed(&value.deployment.0);
    e.fixed(&value.service_program.0);
    e.fixed(&value.platform.0);
    e.fixed(&value.execution_semantics.0);
    e.u64(value.gas_schedule.refine);
    e.u64(value.gas_schedule.accumulate);
}

pub(super) fn decode_service(d: &mut Decoder<'_>) -> Result<ServiceIdentity, DecodeError> {
    let value = ServiceIdentity {
        space: SpaceId(d.fixed()?),
        root_service: RootServiceId(d.fixed()?),
        deployment: DeploymentId(d.fixed()?),
        service_program: ProgramId(d.fixed()?),
        platform: Hash(d.fixed()?),
        execution_semantics: Hash(d.fixed()?),
        gas_schedule: GasSchedule::new(d.u64()?, d.u64()?),
    };
    if value.platform != super::PLATFORM_ID || !value.gas_schedule.is_valid() {
        return Err(DecodeError::InvalidPlatform);
    }
    Ok(value)
}

fn encode_base(e: &mut Encoder<'_>, value: &ConsistencyBase) {
    match value {
        ConsistencyBase::Linear {
            revision,
            state_root,
        } => {
            e.u8(0);
            e.u64(*revision);
            e.fixed(&state_root.0);
        }
        ConsistencyBase::Crdt { heads } => {
            e.u8(1);
            e.list(heads, |e, h| e.fixed(&h.0));
        }
    }
}

fn decode_base(d: &mut Decoder<'_>) -> Result<ConsistencyBase, DecodeError> {
    match d.u8()? {
        0 => Ok(ConsistencyBase::Linear {
            revision: d.u64()?,
            state_root: Hash(d.fixed()?),
        }),
        1 => {
            let heads = d.list(|d| d.fixed().map(Hash))?;
            ensure_sorted_unique(&heads, |h| h.0)?;
            Ok(ConsistencyBase::Crdt { heads })
        }
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_origin(e: &mut Encoder<'_>, value: Origin) {
    match value {
        Origin::Anonymous => e.u8(0),
        Origin::Member(id) => {
            e.u8(1);
            e.fixed(&id.0);
        }
        Origin::Actor(id) => {
            e.u8(2);
            e.fixed(&id.0);
        }
        Origin::System => e.u8(3),
    }
}

fn decode_origin(d: &mut Decoder<'_>) -> Result<Origin, DecodeError> {
    match d.u8()? {
        0 => Ok(Origin::Anonymous),
        1 => Ok(Origin::Member(SubjectId(d.fixed()?))),
        2 => Ok(Origin::Actor(ActorId(d.fixed()?))),
        3 => Ok(Origin::System),
        _ => Err(DecodeError::InvalidTag),
    }
}

pub(super) fn encode_auth(e: &mut Encoder<'_>, value: &AuthorizationEvidence) {
    match value {
        AuthorizationEvidence::Public => e.u8(0),
        AuthorizationEvidence::Credential {
            policy,
            credential_commitment,
            bytes,
        } => {
            e.u8(1);
            e.fixed(&policy.0);
            e.fixed(&credential_commitment.0);
            e.bytes(bytes);
        }
        AuthorizationEvidence::SystemCapability {
            capability,
            authenticator,
        } => {
            e.u8(2);
            e.fixed(&capability.0);
            e.bytes(authenticator);
        }
        AuthorizationEvidence::PrivateCredential {
            policy,
            credential_commitment,
            witness,
        } => {
            e.u8(3);
            e.fixed(&policy.0);
            e.fixed(&credential_commitment.0);
            encode_blob_ref(e, witness);
        }
    }
}

pub(super) fn decode_auth(d: &mut Decoder<'_>) -> Result<AuthorizationEvidence, DecodeError> {
    match d.u8()? {
        0 => Ok(AuthorizationEvidence::Public),
        1 => Ok(AuthorizationEvidence::Credential {
            policy: Hash(d.fixed()?),
            credential_commitment: Hash(d.fixed()?),
            bytes: d.bytes()?,
        }),
        2 => Ok(AuthorizationEvidence::SystemCapability {
            capability: SystemCapabilityId(d.fixed()?),
            authenticator: d.bytes()?,
        }),
        3 => Ok(AuthorizationEvidence::PrivateCredential {
            policy: Hash(d.fixed()?),
            credential_commitment: Hash(d.fixed()?),
            witness: decode_blob_ref(d)?,
        }),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_blob_ref(e: &mut Encoder<'_>, value: &BlobRef) {
    e.fixed(&value.hash.0);
    e.u64(value.len);
}

fn decode_blob_ref(d: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    let hash = Hash(d.fixed()?);
    let len = d.u64()?;
    // service platform uses u64::MAX as the missing-preimage sentinel. Keeping that value
    // out of canonical references prevents absence from comparing equal to a
    // claimed blob length at any host boundary.
    if len == u64::MAX {
        return Err(DecodeError::NonCanonical);
    }
    Ok(BlobRef { hash, len })
}

fn encode_imported_actor(e: &mut Encoder<'_>, value: &ImportedActor) {
    e.fixed(&value.actor.0);
    e.string(&value.name);
    e.option(&value.parent, |e, parent| e.fixed(&parent.0));
    e.fixed(&value.deployment.0);
    e.fixed(&value.program.0);
    e.list(&value.task_dependencies, encode_task_dependency);
    encode_blob_ref(e, &value.state);
    e.list(&value.causal_states, encode_blob_ref);
    e.option(&value.continuation, encode_blob_ref);
    e.list(&value.storage_rows, |e, row| {
        e.bytes(&row.key);
        e.option(&row.value, encode_blob_ref);
    });
}

fn decode_imported_actor(d: &mut Decoder<'_>) -> Result<ImportedActor, DecodeError> {
    let value = ImportedActor {
        actor: ActorId(d.fixed()?),
        name: d.string()?,
        parent: d.option(|d| d.fixed().map(ActorId))?,
        deployment: DeploymentId(d.fixed()?),
        program: ProgramId(d.fixed()?),
        task_dependencies: d.list(decode_task_dependency)?,
        state: decode_blob_ref(d)?,
        causal_states: d.list(decode_blob_ref)?,
        continuation: d.option(decode_blob_ref)?,
        storage_rows: d.list(|d| {
            Ok(ActorStorageRow {
                key: d.bytes()?,
                value: d.option(decode_blob_ref)?,
            })
        })?,
    };
    validate_task_dependencies(&value.task_dependencies)?;
    Ok(value)
}

fn encode_task_dependency(e: &mut Encoder<'_>, value: &TaskDependency) {
    e.fixed(&value.task.0);
    e.fixed(&value.program.0);
    e.u32(value.witness_address);
    e.u32(value.witness_capacity);
}

fn decode_task_dependency(d: &mut Decoder<'_>) -> Result<TaskDependency, DecodeError> {
    let value = TaskDependency {
        task: Hash(d.fixed()?),
        program: ProgramId(d.fixed()?),
        witness_address: d.u32()?,
        witness_capacity: d.u32()?,
    };
    if value.witness_address == 0
        || value.witness_capacity == 0
        || value
            .witness_address
            .checked_add(value.witness_capacity)
            .is_none()
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn validate_task_dependencies(values: &[TaskDependency]) -> Result<(), DecodeError> {
    if values.len() > super::MAX_PACKAGE_TASK_DEPENDENCIES
        || values.windows(2).any(|pair| pair[0].task >= pair[1].task)
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

fn encode_actor_tree_import(e: &mut Encoder<'_>, value: &ActorTreeImport) {
    e.fixed(&value.actor.0);
    e.string(&value.name);
    e.option(&value.parent, |e, parent| e.fixed(&parent.0));
    e.fixed(&value.deployment.0);
    e.fixed(&value.program.0);
}

fn decode_actor_tree_import(d: &mut Decoder<'_>) -> Result<ActorTreeImport, DecodeError> {
    let value = ActorTreeImport {
        actor: ActorId(d.fixed()?),
        name: d.string()?,
        parent: d.option(|d| d.fixed().map(ActorId))?,
        deployment: DeploymentId(d.fixed()?),
        program: ProgramId(d.fixed()?),
    };
    if value.name.is_empty()
        || value.name.len() > super::MAX_ACTOR_NAME_BYTES
        || value.parent == Some(value.actor)
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn encode_external_actor(e: &mut Encoder<'_>, value: &ExternalActorBinding) {
    e.string(&value.name);
    encode_service(e, &value.service);
    e.fixed(&value.actor.0);
    e.fixed(&value.producer.0);
    e.fixed(&value.actor_deployment.0);
    e.fixed(&value.program.0);
}

fn decode_external_actor(d: &mut Decoder<'_>) -> Result<ExternalActorBinding, DecodeError> {
    let value = ExternalActorBinding {
        name: d.string()?,
        service: decode_service(d)?,
        actor: ActorId(d.fixed()?),
        producer: ProducerId(d.fixed()?),
        actor_deployment: DeploymentId(d.fixed()?),
        program: ProgramId(d.fixed()?),
    };
    if value.name.is_empty() || value.service.execution_semantics != super::EXECUTION_SEMANTICS_ID {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn encode_write(e: &mut Encoder<'_>, value: &ActorWrite) {
    e.fixed(&value.actor.0);
    e.bytes(&value.key);
    e.option(&value.value, |e, value| e.bytes(value));
}

fn encode_actor_spawn_request(e: &mut Encoder<'_>, value: &ActorSpawnRequest) {
    e.fixed(&value.actor.0);
    e.string(&value.name);
    e.fixed(&value.parent.0);
    e.bytes(&value.initial_state);
}

fn decode_actor_spawn_request(d: &mut Decoder<'_>) -> Result<ActorSpawnRequest, DecodeError> {
    Ok(ActorSpawnRequest {
        actor: ActorId(d.fixed()?),
        name: d.string()?,
        parent: ActorId(d.fixed()?),
        initial_state: d.bytes()?,
    })
}

fn encode_actor_spawn(e: &mut Encoder<'_>, value: &ActorSpawn) {
    e.fixed(&value.actor.0);
    e.string(&value.name);
    e.fixed(&value.parent.0);
    encode_blob_ref(e, &value.initial_state);
}

fn decode_actor_spawn(d: &mut Decoder<'_>) -> Result<ActorSpawn, DecodeError> {
    let value = ActorSpawn {
        actor: ActorId(d.fixed()?),
        name: d.string()?,
        parent: ActorId(d.fixed()?),
        initial_state: decode_blob_ref(d)?,
    };
    if value.name.is_empty()
        || value.name.len() > super::MAX_ACTOR_NAME_BYTES
        || value.actor != ActorId::owned_child(value.parent, &value.name)
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn decode_write(d: &mut Decoder<'_>) -> Result<ActorWrite, DecodeError> {
    let value = ActorWrite {
        actor: ActorId(d.fixed()?),
        key: d.bytes()?,
        value: d.option(Decoder::bytes)?,
    };
    if value.key.is_empty() {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn encode_crdt_op(e: &mut Encoder<'_>, value: &CrdtOperation) {
    e.fixed(&value.actor.0);
    e.u32(value.dispatch_ordinal);
    e.fixed(&value.field.0);
    e.u32(value.ordinal);
    e.fixed(&value.id.0);
    e.bytes(&value.payload);
}

fn decode_crdt_op(d: &mut Decoder<'_>) -> Result<CrdtOperation, DecodeError> {
    Ok(CrdtOperation {
        actor: ActorId(d.fixed()?),
        dispatch_ordinal: d.u32()?,
        field: Hash(d.fixed()?),
        ordinal: d.u32()?,
        id: OperationId(d.fixed()?),
        payload: d.bytes()?,
    })
}

fn encode_workflow_operation(e: &mut Encoder<'_>, value: &WorkflowOperation) {
    match value {
        WorkflowOperation::Checkpoint(work) => {
            e.u8(0);
            e.bytes(&work.encode());
        }
        WorkflowOperation::Continuation(change) => {
            e.u8(1);
            encode_continuation_change(e, change);
        }
        WorkflowOperation::Inbox(message) => {
            e.u8(2);
            encode_message(e, message);
        }
        WorkflowOperation::Outbox(message) => {
            e.u8(3);
            encode_message(e, message);
        }
        WorkflowOperation::Reply(reply) => {
            e.u8(4);
            encode_reply(e, reply);
        }
        WorkflowOperation::ConsumeOutbox(call) => {
            e.u8(5);
            e.fixed(&call.0);
        }
        WorkflowOperation::ExpireCall(timeout) => {
            e.u8(8);
            e.bytes(&timeout.encode());
        }
        WorkflowOperation::Ingress(ingress) => {
            e.u8(6);
            encode_crdt_ingress(e, ingress);
        }
        WorkflowOperation::Delivery(delivery) => {
            e.u8(7);
            e.bytes(&delivery.encode());
        }
    }
}

fn decode_workflow_operation(d: &mut Decoder<'_>) -> Result<WorkflowOperation, DecodeError> {
    match d.u8()? {
        0 => Ok(WorkflowOperation::Checkpoint(WorkEnvelope::decode(
            &d.bytes()?,
        )?)),
        1 => Ok(WorkflowOperation::Continuation(decode_continuation_change(
            d,
        )?)),
        2 => Ok(WorkflowOperation::Inbox(decode_message(d)?)),
        3 => Ok(WorkflowOperation::Outbox(decode_message(d)?)),
        4 => Ok(WorkflowOperation::Reply(decode_reply(d)?)),
        5 => Ok(WorkflowOperation::ConsumeOutbox(CallId(d.fixed()?))),
        6 => Ok(WorkflowOperation::Ingress(decode_crdt_ingress(d)?)),
        7 => Ok(WorkflowOperation::Delivery(DeliveryEnvelope::decode(
            &d.bytes()?,
        )?)),
        8 => Ok(WorkflowOperation::ExpireCall(CallTimeout::decode(
            &d.bytes()?,
        )?)),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_crdt_ingress(e: &mut Encoder<'_>, value: &CrdtIngress) {
    encode_service(e, &value.service);
    e.fixed(&value.invocation.0);
    e.u64(value.logical_timeslot);
    e.fixed(&value.target.0);
    e.string(&value.method);
    e.bytes(&value.arguments);
    encode_origin(e, value.origin);
    encode_auth(e, &value.authorization);
    e.option(&value.authorization_blob, encode_blob_ref);
    e.list(&value.imported_blobs, encode_blob_ref);
    e.bool(value.proof_requested);
}

fn decode_crdt_ingress(d: &mut Decoder<'_>) -> Result<CrdtIngress, DecodeError> {
    let value = CrdtIngress {
        service: decode_service(d)?,
        invocation: InvocationId(d.fixed()?),
        logical_timeslot: d.u64()?,
        target: ActorId(d.fixed()?),
        method: d.string()?,
        arguments: d.bytes()?,
        origin: decode_origin(d)?,
        authorization: decode_auth(d)?,
        authorization_blob: d.option(decode_blob_ref)?,
        imported_blobs: d.list(decode_blob_ref)?,
        proof_requested: d.bool()?,
    };
    ensure_sorted_unique(&value.imported_blobs, |blob| blob.hash.0)?;
    if value.invocation == InvocationId::ZERO
        || value.target == ActorId::ZERO
        || value.method.is_empty()
        || value.arguments.is_empty()
        || !match (&value.authorization, value.authorization_blob.as_ref()) {
            (AuthorizationEvidence::Public, None) => true,
            (AuthorizationEvidence::Credential { bytes, .. }, Some(_)) => bytes.is_empty(),
            _ => false,
        }
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn workflow_operation_bytes(value: &WorkflowOperation) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode_workflow_operation(&mut Encoder(&mut bytes), value);
    bytes
}

fn encode_continuation_change(e: &mut Encoder<'_>, value: &ContinuationChange) {
    e.fixed(&value.actor.0);
    e.option(&value.expected, |e, h| e.fixed(&h.0));
    e.option(&value.replacement, encode_blob_ref);
}

fn encode_checkpoint_token(e: &mut Encoder<'_>, value: &CheckpointToken) {
    e.fixed(&value.input.invocation.0);
    e.u64(value.input.workflow_step);
    encode_base(e, &value.base);
    e.fixed(&value.work_hash.0);
    e.option(&value.base_causal_height, |e, height| e.u64(*height));
    e.option(&value.change, |e, dispatch| {
        e.fixed(&dispatch.change.0);
        e.u32(dispatch.ordinal);
    });
    e.option(&value.expected, |e, hash| e.fixed(&hash.0));
    e.option(&value.replacement, encode_blob_ref);
    e.option(&value.pending_call, |e, call| e.fixed(&call.0));
    e.option(&value.pending_actor, |e, actor| e.fixed(&actor.0));
    e.list(&value.previously_suspended, |e, actor| e.fixed(&actor.0));
    e.list(&value.suspended, |e, actor| e.fixed(&actor.0));
}

fn decode_checkpoint_token(d: &mut Decoder<'_>) -> Result<CheckpointToken, DecodeError> {
    let value = CheckpointToken {
        input: WorkInputId {
            invocation: InvocationId(d.fixed()?),
            workflow_step: d.u64()?,
        },
        base: decode_base(d)?,
        work_hash: Hash(d.fixed()?),
        base_causal_height: d.option(Decoder::u64)?,
        change: d.option(|d| {
            Ok(CrdtDispatch {
                change: ChangeId(d.fixed()?),
                ordinal: d.u32()?,
            })
        })?,
        expected: d.option(|d| d.fixed().map(Hash))?,
        replacement: d.option(decode_blob_ref)?,
        pending_call: d.option(|d| d.fixed().map(CallId))?,
        pending_actor: d.option(|d| d.fixed().map(ActorId))?,
        previously_suspended: d.list(|d| d.fixed().map(ActorId))?,
        suspended: d.list(|d| d.fixed().map(ActorId))?,
    };
    let is_crdt = matches!(value.base, ConsistencyBase::Crdt { .. });
    if value.change.is_some() != is_crdt
        || value.base_causal_height.is_some() != is_crdt
        || value.change.is_some_and(|dispatch| dispatch.ordinal != 0)
        || value.expected.is_some() == value.previously_suspended.is_empty()
        || value.replacement.is_some() == value.suspended.is_empty()
        || value.pending_call.is_some() != value.pending_actor.is_some()
        || value.pending_actor.is_some_and(|actor| {
            value.suspended.binary_search(&actor).is_err()
                && value.previously_suspended.binary_search(&actor).is_err()
        })
        || (value.previously_suspended.is_empty() && value.suspended.is_empty())
        || value
            .previously_suspended
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || value.suspended.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn encode_actor_call(e: &mut Encoder<'_>, value: &ActorCallRequest) {
    e.u64(value.await_ordinal);
    e.fixed(&value.from.0);
    encode_service(e, &value.to_service);
    e.fixed(&value.to.0);
    e.bytes(&value.payload);
    encode_auth(e, &value.authorization);
    e.bool(value.proof_requested);
    e.option(&value.deadline_timeslot, |e, value| e.u64(*value));
}

fn decode_actor_call(d: &mut Decoder<'_>) -> Result<ActorCallRequest, DecodeError> {
    Ok(ActorCallRequest {
        await_ordinal: d.u64()?,
        from: ActorId(d.fixed()?),
        to_service: decode_service(d)?,
        to: ActorId(d.fixed()?),
        payload: d.bytes()?,
        authorization: decode_auth(d)?,
        proof_requested: d.bool()?,
        deadline_timeslot: d.option(Decoder::u64)?,
    })
}

fn decode_continuation_change(d: &mut Decoder<'_>) -> Result<ContinuationChange, DecodeError> {
    Ok(ContinuationChange {
        actor: ActorId(d.fixed()?),
        expected: d.option(|d| d.fixed().map(Hash))?,
        replacement: d.option(decode_blob_ref)?,
    })
}

fn encode_message(e: &mut Encoder<'_>, value: &MessageRecord) {
    e.fixed(&value.call_id.0);
    e.fixed(&value.caller_invocation.0);
    e.u64(value.await_ordinal);
    encode_service(e, &value.from_service);
    e.fixed(&value.from.0);
    encode_service(e, &value.to_service);
    e.fixed(&value.to.0);
    e.option(&value.parent, |e, id| e.fixed(&id.0));
    e.bytes(&value.payload);
    encode_auth(e, &value.authorization);
    e.bool(value.proof_requested);
    e.option(&value.deadline_timeslot, |e, value| e.u64(*value));
}

fn decode_message(d: &mut Decoder<'_>) -> Result<MessageRecord, DecodeError> {
    let value = MessageRecord {
        call_id: CallId(d.fixed()?),
        caller_invocation: InvocationId(d.fixed()?),
        await_ordinal: d.u64()?,
        from_service: decode_service(d)?,
        from: ActorId(d.fixed()?),
        to_service: decode_service(d)?,
        to: ActorId(d.fixed()?),
        parent: d.option(|d| d.fixed().map(CallId))?,
        payload: d.bytes()?,
        authorization: decode_auth(d)?,
        proof_requested: d.bool()?,
        deadline_timeslot: d.option(Decoder::u64)?,
    };
    if value.payload.is_empty()
        || value.call_id != value.caller_invocation.call_id(value.await_ordinal)
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn encode_causal_context(e: &mut Encoder<'_>, value: &CausalCallContext) {
    e.fixed(&value.call_id.0);
    e.fixed(&value.caller_invocation.0);
    encode_service(e, &value.from_service);
    e.fixed(&value.from.0);
    e.fixed(&value.to.0);
    e.option(&value.parent, |e, id| e.fixed(&id.0));
    e.option(&value.deadline_timeslot, |e, value| e.u64(*value));
}

fn decode_causal_context(d: &mut Decoder<'_>) -> Result<CausalCallContext, DecodeError> {
    Ok(CausalCallContext {
        call_id: CallId(d.fixed()?),
        caller_invocation: InvocationId(d.fixed()?),
        from_service: decode_service(d)?,
        from: ActorId(d.fixed()?),
        to: ActorId(d.fixed()?),
        parent: d.option(|d| d.fixed().map(CallId))?,
        deadline_timeslot: d.option(Decoder::u64)?,
    })
}

fn encode_reply(e: &mut Encoder<'_>, value: &ReplyRecord) {
    e.fixed(&value.call_id.0);
    e.fixed(&value.producer.0);
    e.bytes(&value.result);
}

fn decode_reply(d: &mut Decoder<'_>) -> Result<ReplyRecord, DecodeError> {
    Ok(ReplyRecord {
        call_id: CallId(d.fixed()?),
        producer: ActorId(d.fixed()?),
        result: d.bytes()?,
    })
}

pub(crate) fn encode_proof(e: &mut Encoder<'_>, value: &ProofCommitment) {
    e.fixed(&value.statement.0);
    e.fixed(&value.trace.0);
    encode_blob_ref(e, &value.proof_blob);
}

pub(crate) fn decode_proof(d: &mut Decoder<'_>) -> Result<ProofCommitment, DecodeError> {
    let value = ProofCommitment {
        statement: Hash(d.fixed()?),
        trace: Hash(d.fixed()?),
        proof_blob: decode_blob_ref(d)?,
    };
    if value.statement == Hash::ZERO || value.trace == Hash::ZERO {
        return Err(DecodeError::InvalidPlatform);
    }
    Ok(value)
}

fn ensure_external_actors_canonical(actors: &[ExternalActorBinding]) -> Result<(), DecodeError> {
    if actors.windows(2).any(|pair| pair[0].name >= pair[1].name) {
        return Err(DecodeError::NonCanonical);
    }
    let mut actor_ids = actors
        .iter()
        .map(|binding| binding.actor)
        .collect::<Vec<_>>();
    actor_ids.sort_unstable();
    if actor_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

fn ensure_sorted_unique<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> Result<(), DecodeError> {
    if values.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role_policies(methods: Vec<MethodPolicy>) -> Vec<u8> {
        super::super::PackageRolePolicies {
            methods,
            task_dependencies: vec![],
        }
        .encode()
    }

    fn service() -> ServiceIdentity {
        ServiceIdentity {
            space: SpaceId([0; 32]),
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: ProgramId([3; 32]),
            platform: super::super::PLATFORM_ID,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
            gas_schedule: GasSchedule::new(1_000_000_000, 5_000_000_000),
        }
    }

    fn work() -> WorkEnvelope {
        WorkEnvelope {
            service: service(),
            invocation: InvocationId([4; 32]),
            workflow_step: 0,
            logical_timeslot: 5,
            target: ActorId([5; 32]),
            target_deployment: DeploymentId([9; 32]),
            target_program: ProgramId([6; 32]),
            method: "increment".into(),
            arguments: vec![1, 2],
            private_arguments: None,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            consistency: ConsistencyMode::Local,
            base: ConsistencyBase::Linear {
                revision: 7,
                state_root: Hash([8; 32]),
            },
            base_causal_height: None,
            imported_actors: vec![ImportedActor {
                actor: ActorId([5; 32]),
                name: "root".into(),
                parent: None,
                deployment: DeploymentId([9; 32]),
                program: ProgramId([6; 32]),
                task_dependencies: vec![],
                state: BlobRef::of_bytes(b"state"),
                causal_states: vec![],
                continuation: None,
                storage_rows: vec![],
            }],
            external_actors: vec![],
            imported_blobs: vec![],
            proof_requested: false,
        }
    }

    #[test]
    fn actor_storage_witnesses_are_bounded_linear_and_canonical() {
        let mut valid = work();
        valid.imported_actors[0].storage_rows = (0..super::super::MAX_ACTOR_STORAGE_WITNESSES)
            .map(|index| {
                let value = (index as u32).to_be_bytes();
                ActorStorageRow {
                    key: value.to_vec(),
                    value: Some(BlobRef::of_bytes(&value)),
                }
            })
            .collect();
        assert_eq!(WorkEnvelope::decode(&valid.encode()), Ok(valid.clone()));
        assert!(
            valid.encode().len() > super::super::CHECKPOINT_TOKEN_CAPACITY,
            "the maximum canonical witness metadata reproduces the old token overflow"
        );
        let token = CheckpointToken {
            input: valid.input_id(),
            base: valid.base.clone(),
            work_hash: valid.hash(),
            base_causal_height: None,
            change: None,
            expected: None,
            replacement: Some(BlobRef::of_bytes(b"checkpoint")),
            pending_call: None,
            pending_actor: None,
            previously_suspended: vec![],
            suspended: vec![valid.target],
        };
        assert!(
            token.encode().len() <= super::super::CHECKPOINT_TOKEN_CAPACITY,
            "storage witnesses travel over the private resume-work channel, not the control token"
        );
        assert_eq!(CheckpointToken::decode(&token.encode()), Ok(token));

        let mut unsorted = valid.clone();
        unsorted.imported_actors[0].storage_rows.reverse();
        assert_eq!(
            WorkEnvelope::decode(&unsorted.encode()),
            Err(DecodeError::NonCanonical),
        );

        let mut crdt = valid.clone();
        crdt.consistency = ConsistencyMode::Crdt;
        crdt.base = ConsistencyBase::Crdt { heads: vec![] };
        crdt.base_causal_height = Some(0);
        assert_eq!(
            WorkEnvelope::decode(&crdt.encode()),
            Err(DecodeError::NonCanonical),
        );

        let mut too_many = work();
        too_many.imported_actors[0].storage_rows = (0..=super::super::MAX_ACTOR_STORAGE_WITNESSES)
            .map(|index| ActorStorageRow {
                key: (index as u32).to_be_bytes().to_vec(),
                value: None,
            })
            .collect();
        assert_eq!(
            WorkEnvelope::decode(&too_many.encode()),
            Err(DecodeError::LimitExceeded),
        );

        let mut too_large = work();
        too_large.imported_actors[0]
            .storage_rows
            .push(ActorStorageRow {
                key: b"large".to_vec(),
                value: Some(BlobRef::of_bytes(&vec![
                    0;
                    super::super::MAX_ACTOR_STORAGE_WITNESS_BYTES
                        + 1
                ])),
            });
        assert_eq!(
            WorkEnvelope::decode(&too_large.encode()),
            Err(DecodeError::LimitExceeded),
        );
    }

    fn message(byte: u8, await_ordinal: u64) -> MessageRecord {
        let caller_invocation = InvocationId([byte; 32]);
        MessageRecord {
            call_id: caller_invocation.call_id(await_ordinal),
            caller_invocation,
            await_ordinal,
            from_service: service(),
            from: ActorId([byte.wrapping_add(1); 32]),
            to_service: service(),
            to: ActorId([byte.wrapping_add(2); 32]),
            parent: None,
            payload: vec![byte],
            authorization: AuthorizationEvidence::Public,
            proof_requested: false,
            deadline_timeslot: Some(50),
        }
    }

    #[test]
    fn authority_mutation_signature_bytes_bind_operation_and_epoch() {
        let grant = RoleAuthorityMutation::Grant {
            space: SpaceId([34; 32]),
            holder: Origin::Member(SubjectId([35; 32])),
            role: crate::SpaceRole::Developer,
            epoch: 7,
        };
        assert_eq!(
            RoleAuthorityMutation::decode(&grant.encode()).unwrap(),
            grant
        );

        let revoke = RoleAuthorityMutation::Revoke {
            space: grant.space(),
            holder: grant.holder(),
            epoch: grant.epoch(),
        };
        assert_ne!(grant.encode(), revoke.encode());

        let mut next_epoch = grant.clone();
        let RoleAuthorityMutation::Grant { epoch, .. } = &mut next_epoch else {
            unreachable!()
        };
        *epoch += 1;
        assert_ne!(grant.encode(), next_epoch.encode());

        let invalid = RoleAuthorityMutation::Revoke {
            space: SpaceId([34; 32]),
            holder: Origin::System,
            epoch: 1,
        };
        assert_eq!(
            RoleAuthorityMutation::decode(&invalid.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn authority_invite_wire_binds_the_complete_delegation_chain() {
        let redemption = RoleAuthorityInviteRedemption {
            space: SpaceId([41; 32]),
            authority_replication_id: [40; 32],
            token_pub: [42; 32],
            role: crate::SpaceRole::Developer,
            expires_at: 43,
            admin_peer_id: vec![44; 38],
            admin_signature: [45; 64],
            holder_peer_id: vec![46; 38],
            redeem_signature: [47; 64],
            holder_signature: [48; 64],
        };
        assert_eq!(
            RoleAuthorityInviteRedemption::decode(&redemption.encode()).unwrap(),
            redemption,
        );
        assert!(matches!(redemption.holder(), Origin::Member(_)));
        assert!(matches!(redemption.grantor(), Origin::Member(_)));

        let mut admin = redemption.clone();
        admin.role = crate::SpaceRole::Admin;
        assert_eq!(
            RoleAuthorityInviteRedemption::decode(&admin.encode()),
            Err(DecodeError::NonCanonical),
        );
        let mut malformed = redemption;
        malformed.holder_peer_id.clear();
        assert_eq!(
            RoleAuthorityInviteRedemption::decode(&malformed.encode()),
            Err(DecodeError::NonCanonical),
        );

        let revocation = RoleAuthorityInviteRevocation {
            space: SpaceId([49; 32]),
            token_pub: [50; 32],
            admin_peer_id: vec![51; 38],
        };
        assert_eq!(
            RoleAuthorityInviteRevocation::decode(&revocation.encode()).unwrap(),
            revocation,
        );
        assert!(matches!(revocation.grantor(), Origin::Member(_)));
        let mut other_space = revocation.clone();
        other_space.space.0[0] ^= 1;
        assert_ne!(other_space.encode(), revocation.encode());
        let mut malformed = revocation;
        malformed.admin_peer_id.clear();
        assert_eq!(
            RoleAuthorityInviteRevocation::decode(&malformed.encode()),
            Err(DecodeError::NonCanonical),
        );
    }

    #[test]
    fn accumulated_role_assertion_binds_authority_and_exact_invocation() {
        let audience = service();
        let authority = RoleAuthorityBinding {
            service: ServiceIdentity {
                space: audience.space,
                root_service: RootServiceId([40; 32]),
                deployment: DeploymentId([41; 32]),
                service_program: ProgramId([42; 32]),
                platform: super::super::PLATFORM_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                gas_schedule: GasSchedule::new(1_000_000_000, 5_000_000_000),
            },
            actor: ActorId([43; 32]),
        };
        let claim = RoleAuthorizationClaim {
            space: audience.space,
            holder: Origin::Member(SubjectId([44; 32])),
            role: Some(crate::SpaceRole::Developer),
            capability: None,
            audience,
            invocation: InvocationId([45; 32]),
            scope: Hash([52; 32]),
            target: ActorId([46; 32]),
            method: "publish".into(),
            policy: Hash([47; 32]),
        };
        let assertion = AccumulatedRoleAssertion {
            receipt: AccumulationReceipt {
                service: authority.service.clone(),
                accepted_transition: Hash([48; 32]),
                reply_commitment: Some(claim.authority_reply(authority.actor).commitment()),
                outbox_commitment: None,
                resulting_state_root: Some(Hash([49; 32])),
                resulting_crdt_heads: vec![],
                sequence: 7,
                checkpoint: 7,
                consistency: ConsistencyMode::Local,
            },
            claim,
        };
        let crate::value::Value::Bytes(result) =
            <crate::value::Value as crate::Decode>::try_decode(
                &assertion.claim.authority_reply(authority.actor).result,
            )
            .unwrap()
        else {
            panic!("authority actor reply must use the canonical bytes frame")
        };
        assert_eq!(result, assertion.claim.encode());
        assert!(assertion.matches_authority(&authority));
        assert_eq!(
            AccumulatedRoleAssertion::decode(&assertion.encode()).unwrap(),
            assertion
        );

        let mut replayed = assertion.clone();
        replayed.claim.invocation = InvocationId([50; 32]);
        assert!(!replayed.matches_authority(&authority));

        let mut sibling_authority = authority;
        sibling_authority.service.root_service = RootServiceId([51; 32]);
        assert!(!assertion.matches_authority(&sibling_authority));
    }

    #[test]
    fn work_wire_is_strict_and_deterministic() {
        let value = work();
        let bytes = value.encode();
        assert_eq!(bytes, value.encode());
        assert_eq!(WorkEnvelope::decode(&bytes).unwrap(), value);

        let mut private = value.clone();
        private.arguments = (80_u8..128).collect();
        private.private_arguments = Some(BlobRef::of_bytes(&private.arguments));
        assert_eq!(WorkEnvelope::decode(&private.encode()).unwrap(), private);
        let mut raft_private = private.clone();
        raft_private.consistency = ConsistencyMode::Raft;
        assert_eq!(
            WorkEnvelope::decode(&raft_private.encode()).unwrap(),
            raft_private,
            "Raft carries only the commitment while the host side-CAS supplies bytes",
        );
        let mut crdt_private = private.clone();
        crdt_private.consistency = ConsistencyMode::Crdt;
        assert_eq!(
            WorkEnvelope::decode(&crdt_private.encode()),
            Err(DecodeError::NonCanonical),
            "CRDT private-input availability remains fail-closed",
        );
        let checkpoint = private.durable_work();
        assert!(checkpoint.arguments.is_empty());
        assert_eq!(checkpoint.hash(), private.hash());
        assert_eq!(
            checkpoint.authorization_scope(),
            private.authorization_scope(),
            "the role scope binds the private commitment, not its hydrated representation",
        );
        assert!(
            !checkpoint
                .encode()
                .windows(private.arguments.len())
                .any(|window| window == private.arguments),
            "durable workflow encoding must contain no private plaintext",
        );
        let mut mismatched_private = private.clone();
        mismatched_private.arguments[0] ^= 1;
        assert_eq!(
            WorkEnvelope::decode(&mismatched_private.encode()),
            Err(DecodeError::NonCanonical),
        );

        let mut different_schedule = value.clone();
        different_schedule.service.gas_schedule.accumulate += 1;
        assert_ne!(
            different_schedule.encode(),
            bytes,
            "the service wire must bind the exact gas schedule"
        );
        assert_ne!(
            different_schedule.authorization_scope(),
            value.authorization_scope(),
            "authorization cannot cross a gas-schedule change"
        );

        let mut invalid_schedule = value.clone();
        invalid_schedule.service.gas_schedule.refine = 0;
        assert_eq!(
            WorkEnvelope::decode(&invalid_schedule.encode()),
            Err(DecodeError::InvalidPlatform)
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            WorkEnvelope::decode(&trailing),
            Err(DecodeError::TrailingBytes)
        );
        let mut old = bytes;
        old[4..6].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            WorkEnvelope::decode(&old),
            Err(DecodeError::InvalidPlatform)
        );

        let mut causal = value.clone();
        let parent_invocation = InvocationId([40; 32]);
        let parent_call = parent_invocation.call_id(2);
        let parent_actor = ActorId([41; 32]);
        causal.origin = Origin::Actor(parent_actor);
        causal.causal_parent = Some(parent_invocation);
        causal.parent_call = Some(parent_call);
        causal.causal_context = Some(CausalCallContext {
            call_id: parent_call,
            caller_invocation: parent_invocation,
            from_service: service(),
            from: parent_actor,
            to: causal.target,
            parent: None,
            deadline_timeslot: Some(50),
        });
        assert_eq!(WorkEnvelope::decode(&causal.encode()).unwrap(), causal);
        causal.causal_context.as_mut().unwrap().to = ActorId([42; 32]);
        assert_eq!(
            WorkEnvelope::decode(&causal.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut sentinel = value;
        sentinel.imported_blobs.push(BlobRef {
            hash: Hash([42; 32]),
            len: u64::MAX,
        });
        assert_eq!(
            WorkEnvelope::decode(&sentinel.encode()),
            Err(DecodeError::NonCanonical)
        );

        let origin = Origin::Member(SubjectId([43; 32]));
        let mut private = work();
        private.origin = origin;
        private.proof_requested = true;
        let credential = RoleCredential {
            holder: origin,
            scope: private.authorization_scope(),
            space_role: Some(crate::SpaceRole::Member),
            capability: None,
            actor_role: None,
            authenticator: b"private role witness".to_vec(),
        };
        let policy =
            super::super::space_role_policy_hash(crate::SpaceRole::Member.as_u8()).unwrap();
        let (authorization, witness) = credential.private_evidence(policy);
        private.authorization = authorization;
        assert_eq!(WorkEnvelope::decode(&private.encode()).unwrap(), private);
        assert!(
            !private
                .encode()
                .windows(witness.bytes.len())
                .any(|window| window == witness.bytes),
            "private witness bytes are imports, not public work-wire fields"
        );

        private.proof_requested = false;
        assert_eq!(
            WorkEnvelope::decode(&private.encode()),
            Err(DecodeError::NonCanonical)
        );
        private.proof_requested = true;
        private.imported_blobs = vec![witness.reference];
        assert_eq!(
            WorkEnvelope::decode(&private.encode()),
            Err(DecodeError::NonCanonical),
            "private witnesses cannot be declared as persistent/shared work imports"
        );
    }

    #[test]
    fn role_credentials_reject_reserved_scope_and_role_values() {
        let mut credential = RoleCredential {
            holder: Origin::Member(SubjectId([44; 32])),
            scope: Hash::ZERO,
            space_role: Some(crate::SpaceRole::Member),
            capability: None,
            actor_role: None,
            authenticator: b"signed grant".to_vec(),
        };

        assert_eq!(
            RoleCredential::decode(&credential.encode()),
            Err(DecodeError::NonCanonical)
        );

        credential.scope = Hash([45; 32]);
        credential.space_role = None;
        credential.actor_role = Some(u8::MAX);
        assert_eq!(
            RoleCredential::decode(&credential.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn package_only_upgrade_invalidates_the_previous_role_credential_scope() {
        let before = work();
        let before_scope = before.authorization_scope();

        let mut after = before.clone();
        after.target_deployment = DeploymentId([46; 32]);
        after.imported_actors[0].deployment = after.target_deployment;

        assert_eq!(after.target_program, before.target_program);
        assert_ne!(after.target_deployment, before.target_deployment);
        assert_ne!(
            after.authorization_scope(),
            before_scope,
            "a credential signed for the old package must not authorize the same program under a new deployment"
        );
    }

    #[test]
    fn refine_imports_bind_all_program_and_blob_bytes() {
        let pvm = b"canonical-actor-pvm".to_vec();
        let program = ProgramId::of_pvm(&pvm);
        let state_bytes = b"actor-state".to_vec();
        let state = BlobRef::of_bytes(&state_bytes);
        let extra_bytes = b"schema-or-credential".to_vec();
        let extra = BlobRef::of_bytes(&extra_bytes);

        let mut work = work();
        work.target_program = program;
        work.imported_actors = vec![ImportedActor {
            actor: work.target,
            name: "root".into(),
            parent: None,
            deployment: work.target_deployment,
            program,
            task_dependencies: vec![],
            state: state.clone(),
            causal_states: vec![],
            continuation: None,
            storage_rows: vec![],
        }];
        work.imported_blobs = vec![extra.clone()];

        let mut blobs = vec![
            ImportedBlob {
                reference: state,
                bytes: state_bytes,
            },
            ImportedBlob {
                reference: extra,
                bytes: extra_bytes,
            },
        ];
        blobs.sort_by_key(|blob| blob.reference.hash);
        let mut external_service = work.service.clone();
        external_service.root_service = RootServiceId([31; 32]);
        external_service.deployment = DeploymentId([32; 32]);
        work.external_actors = vec![ExternalActorBinding {
            name: "peer".into(),
            service: external_service,
            actor: ActorId([33; 32]),
            producer: ProducerId([34; 32]),
            actor_deployment: DeploymentId([36; 32]),
            program: ProgramId([35; 32]),
        }];
        let imports = RefineImports {
            programs: vec![ImportedProgram { program, pvm }],
            blobs,
            private_blobs: vec![],
        };
        imports.validate_for(&work).unwrap();
        let encoded = imports.encode();
        assert_eq!(RefineImports::decode(&encoded).unwrap(), imports);

        let mut wrong_deployment = work.clone();
        wrong_deployment.target_deployment = DeploymentId([37; 32]);
        assert_eq!(
            WorkEnvelope::decode(&wrong_deployment.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut missing = imports.clone();
        missing
            .blobs
            .retain(|blob| blob.reference != work.imported_blobs[0]);
        assert_eq!(
            missing.validate_for(&work),
            Err(RefineError::MissingImport(work.imported_blobs[0].hash))
        );

        let mut tampered = imports;
        tampered.programs[0].pvm.push(0);
        assert_eq!(
            tampered.validate_for(&work),
            Err(RefineError::InvalidImport(Hash(program.0)))
        );
    }

    #[test]
    fn actor_slice_wires_round_trip_and_require_canonical_writes() {
        let input = ActorSliceInput {
            actor: ActorId([21; 32]),
            first_await_ordinal: 7,
            message: b"message".to_vec(),
        };
        let private = ActorPrivateInput {
            actor: input.actor,
            actor_tree: vec![
                ActorTreeImport {
                    actor: ActorId([21; 32]),
                    name: "root".into(),
                    parent: None,
                    deployment: DeploymentId([23; 32]),
                    program: ProgramId([24; 32]),
                },
                ActorTreeImport {
                    actor: ActorId([22; 32]),
                    name: "child".into(),
                    parent: Some(ActorId([21; 32])),
                    deployment: DeploymentId([23; 32]),
                    program: ProgramId([25; 32]),
                },
            ],
            external_actors: vec![ExternalActorBinding {
                name: "peer".into(),
                service: service(),
                actor: ActorId([26; 32]),
                producer: ProducerId([27; 32]),
                actor_deployment: DeploymentId([29; 32]),
                program: ProgramId([28; 32]),
            }],
            input: WorkInputId {
                invocation: InvocationId([23; 32]),
                workflow_step: 7,
            },
            change: Some(CrdtDispatch {
                change: ChangeId([23; 32]),
                ordinal: 4,
            }),
            state: b"before".to_vec(),
            causal_states: vec![b"concurrent".to_vec()],
            active_actor_mask: 1,
            origin: Origin::Actor(ActorId([22; 32])),
            origin_service: Some(service()),
            space_role: Some(crate::SpaceRole::Developer.as_u8()),
            actor_role: Some(7),
        };
        assert_eq!(ActorSliceInput::decode(&input.encode()).unwrap(), input);
        let mut invalid_active_set = private.clone();
        invalid_active_set.active_actor_mask |= 1u64 << 63;
        assert_eq!(
            ActorPrivateInput::decode(&invalid_active_set.encode()),
            Err(DecodeError::NonCanonical)
        );
        assert_eq!(
            ActorPrivateInput::decode(&private.encode()).unwrap(),
            private
        );
        let mut missing_origin_service = private.clone();
        missing_origin_service.origin_service = None;
        assert_eq!(
            ActorPrivateInput::decode(&missing_origin_service.encode()),
            Err(DecodeError::NonCanonical)
        );
        let mut unexpected_origin_service = private.clone();
        unexpected_origin_service.origin = Origin::Anonymous;
        assert_eq!(
            ActorPrivateInput::decode(&unexpected_origin_service.encode()),
            Err(DecodeError::NonCanonical)
        );
        assert!(
            !input
                .encode()
                .windows(private.state.len())
                .any(|window| window == private.state),
            "shared same-tree IPC must not disclose an actor materialization"
        );
        assert!(
            !input
                .encode()
                .windows(b"child".len())
                .any(|window| window == b"child"),
            "the route directory is host-authenticated private input, not caller-owned IPC"
        );
        assert_eq!(
            private.resolve_owned(Some(input.actor), "child"),
            Some(ActorId([22; 32]))
        );
        assert_eq!(private.callable_slot(input.actor), None);
        assert_eq!(
            private.callable_slot(ActorId([22; 32])),
            Some(super::super::ACTOR_CALLABLE_BASE_SLOT + 1)
        );

        let output = ActorSliceOutput {
            actor: ActorId([21; 32]),
            first_await_ordinal: 7,
            next_await_ordinal: 8,
            writes: vec![ActorWrite {
                actor: ActorId([21; 32]),
                key: b"state".to_vec(),
                value: Some(b"after".to_vec()),
            }],
            crdt_operations: vec![],
            crdt_states: vec![],
            spawns: vec![ActorSpawnRequest {
                actor: ActorId::owned_child(ActorId([21; 32]), "worker"),
                name: "worker".into(),
                parent: ActorId([21; 32]),
                initial_state: vec![],
            }],
            outbox: vec![ActorCallRequest {
                await_ordinal: 7,
                from: ActorId([21; 32]),
                to_service: service(),
                to: ActorId([27; 32]),
                payload: b"peer request".to_vec(),
                authorization: AuthorizationEvidence::Public,
                proof_requested: false,
                deadline_timeslot: Some(30),
            }],
            reply: b"ok".to_vec(),
            yielded: false,
            forbidden: false,
            checkpoint: None,
        };
        assert_eq!(ActorSliceOutput::decode(&output.encode()).unwrap(), output);
        let mut wrong_spawn = output.clone();
        wrong_spawn.spawns[0].actor = ActorId([99; 32]);
        assert_eq!(
            ActorSliceOutput::decode(&wrong_spawn.encode()),
            Err(DecodeError::NonCanonical)
        );

        let change = ChangeId([31; 32]);
        let field = Hash([32; 32]);
        let crdt_output = ActorSliceOutput {
            actor: ActorId([21; 32]),
            first_await_ordinal: 0,
            next_await_ordinal: 0,
            writes: vec![],
            crdt_operations: vec![CrdtOperation {
                actor: ActorId([21; 32]),
                dispatch_ordinal: 1,
                field,
                ordinal: 0,
                id: change.operation(ActorId([21; 32]), 1, field, 0),
                payload: vec![1],
            }],
            crdt_states: vec![ActorCrdtState {
                actor: ActorId([21; 32]),
                state: vec![2],
                next_dispatch_ordinal: 2,
            }],
            spawns: vec![],
            outbox: vec![],
            reply: vec![],
            yielded: false,
            forbidden: false,
            checkpoint: None,
        };
        assert_eq!(
            ActorSliceOutput::decode(&crdt_output.encode()).unwrap(),
            crdt_output
        );
        let mut stale_dispatch = crdt_output;
        stale_dispatch.crdt_states[0].next_dispatch_ordinal = 1;
        assert_eq!(
            ActorSliceOutput::decode(&stale_dispatch.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut duplicate_write = output;
        duplicate_write
            .writes
            .push(duplicate_write.writes[0].clone());
        assert_eq!(
            ActorSliceOutput::decode(&duplicate_write.encode()),
            Err(DecodeError::NonCanonical)
        );

        let replacement = BlobRef::of_bytes(b"kernel snapshot");
        let checkpoint = CheckpointToken {
            input: WorkInputId {
                invocation: InvocationId([24; 32]),
                workflow_step: 3,
            },
            base: ConsistencyBase::Linear {
                revision: 3,
                state_root: Hash([25; 32]),
            },
            work_hash: Hash([27; 32]),
            base_causal_height: None,
            change: None,
            expected: Some(Hash([26; 32])),
            replacement: Some(replacement),
            pending_call: Some(InvocationId([24; 32]).call_id(3)),
            pending_actor: Some(ActorId([23; 32])),
            previously_suspended: vec![ActorId([21; 32])],
            suspended: vec![ActorId([21; 32]), ActorId([23; 32])],
        };
        assert_eq!(
            CheckpointToken::decode(&checkpoint.encode()).unwrap(),
            checkpoint
        );

        let mut mismatched_change = checkpoint.clone();
        mismatched_change.change = Some(CrdtDispatch {
            change: ChangeId([27; 32]),
            ordinal: 0,
        });
        assert_eq!(
            CheckpointToken::decode(&mismatched_change.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut crdt_checkpoint = mismatched_change;
        crdt_checkpoint.base = ConsistencyBase::Crdt {
            heads: vec![Hash([28; 32])],
        };
        crdt_checkpoint.base_causal_height = Some(3);
        assert_eq!(
            CheckpointToken::decode(&crdt_checkpoint.encode()).unwrap(),
            crdt_checkpoint
        );

        let mut nonzero_dispatch = crdt_checkpoint;
        nonzero_dispatch.change.as_mut().unwrap().ordinal = 1;
        assert_eq!(
            CheckpointToken::decode(&nonzero_dispatch.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut invalid_yield = ActorSliceOutput {
            actor: ActorId([21; 32]),
            first_await_ordinal: 7,
            next_await_ordinal: 7,
            writes: vec![],
            crdt_operations: vec![],
            crdt_states: vec![],
            spawns: vec![],
            outbox: vec![],
            reply: vec![],
            yielded: true,
            forbidden: false,
            checkpoint: None,
        };
        assert_eq!(
            ActorSliceOutput::decode(&invalid_yield.encode()),
            Err(DecodeError::NonCanonical)
        );
        invalid_yield.checkpoint = Some(checkpoint.clone());
        assert_eq!(
            ActorSliceOutput::decode(&invalid_yield.encode()).unwrap(),
            invalid_yield
        );

        let resume = AwaitResume {
            checkpoint: CheckpointToken {
                replacement: None,
                previously_suspended: checkpoint.suspended.clone(),
                suspended: vec![],
                ..checkpoint.clone()
            },
            reply: ReplyRecord {
                call_id: checkpoint.pending_call.unwrap(),
                producer: ActorId([28; 32]),
                result: b"committed reply".to_vec(),
            },
            attestation: None,
        };
        assert_eq!(AwaitResume::decode(&resume.encode()).unwrap(), resume);
        let mut mismatched = resume;
        mismatched.reply.call_id = InvocationId([29; 32]).call_id(3);
        assert_eq!(
            AwaitResume::decode(&mismatched.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn attested_reply_wire_binds_receipt_claim_and_content_addressed_proof() {
        let invocation = InvocationId([41; 32]);
        let call = invocation.call_id(2);
        let actor = ActorId([42; 32]);
        let reply = ReplyRecord {
            call_id: call,
            producer: actor,
            result: b"adult".to_vec(),
        };
        let receipt = AccumulationReceipt {
            service: service(),
            accepted_transition: Hash([43; 32]),
            reply_commitment: Some(reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([44; 32])),
            resulting_crdt_heads: vec![],
            sequence: 3,
            checkpoint: 0,
            consistency: ConsistencyMode::Local,
        };
        let statement = AttestationStatement {
            space: receipt.service.space,
            actor,
            producer_name: "private-age".into(),
            producer: ProducerId([51; 32]),
            deployment: receipt.service.deployment,
            actor_program: ProgramId([45; 32]),
            method: "is_adult".into(),
            schema: Hash([46; 32]),
            invocation: InvocationId::for_call(call),
            reply_call: call,
            before: crate::attestation::StateCommitment::Linear(Hash([47; 32])),
            after: crate::attestation::StateCommitment::Linear(Hash([44; 32])),
            claim_commitment: Hash::digest(b"vos/attestation-claim", &[&reply.result]),
            input_commitment: Hash([48; 32]),
            authorization_policy: Hash([49; 32]),
            accumulation_receipt: receipt.clone(),
        };
        let proof_bytes = b"proof".to_vec();
        let proof = ProofCommitment {
            statement: statement.commitment(),
            trace: Hash([50; 32]),
            proof_blob: BlobRef::of_bytes(&proof_bytes),
        };
        let accumulated = AccumulatedReply {
            reply: reply.clone(),
            receipt: receipt.clone(),
            attestation: Some(Box::new(AttestationDelivery {
                producer_name: "private-age".into(),
                producer: ProducerId([51; 32]),
                statement: statement.clone(),
                proof: proof.clone(),
            })),
        };
        assert_eq!(
            AccumulatedReply::decode(&accumulated.encode()).unwrap(),
            accumulated
        );

        let checkpoint = CheckpointToken {
            input: WorkInputId {
                invocation,
                workflow_step: 1,
            },
            base: ConsistencyBase::Linear {
                revision: 2,
                state_root: Hash([52; 32]),
            },
            work_hash: Hash([55; 32]),
            base_causal_height: None,
            change: None,
            expected: Some(Hash([53; 32])),
            replacement: None,
            pending_call: Some(call),
            pending_actor: Some(ActorId([54; 32])),
            previously_suspended: vec![ActorId([54; 32])],
            suspended: vec![],
        };
        let resume = AwaitResume {
            checkpoint,
            reply,
            attestation: Some(Box::new(AttestationResume {
                producer_name: "private-age".into(),
                producer: ProducerId([51; 32]),
                statement,
                proof,
                proof_offset: 1024,
                proof_len: proof_bytes.len() as u32,
            })),
        };
        assert_eq!(AwaitResume::decode(&resume.encode()).unwrap(), resume);

        let mut tampered = resume;
        tampered.attestation.as_mut().unwrap().proof_len += 1;
        assert_eq!(
            AwaitResume::decode(&tampered.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn transition_commitment_binds_execution_but_not_attached_proof() {
        let base = Transition {
            service: service(),
            consumed_input: WorkInputId {
                invocation: InvocationId([9; 32]),
                workflow_step: 0,
            },
            target_deployment: DeploymentId([15; 32]),
            target_program: ProgramId([10; 32]),
            base: ConsistencyBase::Linear {
                revision: 0,
                state_root: Hash::ZERO,
            },
            writes: vec![],
            crdt_change: None,
            spawns: vec![],
            continuations: vec![],
            inbox: vec![],
            outbox: vec![],
            reply: None,
            exported_blobs: vec![],
            gas: GasAccounting::default(),
            proof: None,
        };
        let mut changed = base.clone();
        changed.reply = Some(ReplyRecord {
            call_id: CallId([11; 32]),
            producer: ActorId([12; 32]),
            result: b"ok".to_vec(),
        });
        assert_ne!(base.hash(), changed.hash());
        assert_ne!(base.commitment(), changed.commitment());

        let mut spawned = changed.clone();
        spawned.spawns.push(ActorSpawn {
            actor: ActorId::owned_child(ActorId([12; 32]), "child"),
            name: "child".into(),
            parent: ActorId([12; 32]),
            initial_state: BlobRef::of_bytes(b"initial child state"),
        });
        assert_ne!(spawned.commitment(), changed.commitment());

        let mut proved = changed.clone();
        proved.proof = Some(ProofCommitment {
            statement: Hash([14; 32]),
            trace: Hash([13; 32]),
            proof_blob: BlobRef::of_bytes(b"proof"),
        });
        assert_ne!(proved.hash(), changed.hash());
        assert_eq!(proved.commitment(), changed.commitment());
        assert_eq!(Transition::decode(&changed.encode()).unwrap(), changed);
    }

    #[test]
    fn durable_message_binds_call_identity_and_authorization() {
        let caller_invocation = InvocationId([71; 32]);
        let message = MessageRecord {
            call_id: caller_invocation.call_id(3),
            caller_invocation,
            await_ordinal: 3,
            from_service: service(),
            from: ActorId([72; 32]),
            to_service: service(),
            to: ActorId([73; 32]),
            parent: Some(CallId([74; 32])),
            payload: b"message".to_vec(),
            authorization: AuthorizationEvidence::Credential {
                policy: Hash([75; 32]),
                credential_commitment: Hash([76; 32]),
                bytes: vec![77],
            },
            proof_requested: false,
            deadline_timeslot: Some(78),
        };
        assert_eq!(MessageRecord::decode(&message.encode()).unwrap(), message);

        let mut wrong_ordinal = message;
        wrong_ordinal.await_ordinal = 4;
        assert_eq!(
            MessageRecord::decode(&wrong_ordinal.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut empty_payload = wrong_ordinal;
        empty_payload.await_ordinal = 3;
        empty_payload.payload.clear();
        assert_eq!(
            MessageRecord::decode(&empty_payload.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn accumulate_request_wires_bind_install_and_apply_inputs() {
        let genesis = ServiceGenesis {
            role_authority: None,
            service: service(),
            consistency: ConsistencyMode::Local,
            actors: vec![
                ActorGenesis {
                    actor: ActorId([5; 32]),
                    name: "root".into(),
                    parent: None,
                    producer: ProducerId([4; 32]),
                    deployment: DeploymentId([2; 32]),
                    program: ProgramId([6; 32]),
                    initial_state: BlobRef::of_bytes(b"root-state"),
                    crdt: false,
                    role_policies: role_policies(vec![MethodPolicy {
                        method: "increment".into(),
                        schema: Hash([7; 32]),
                        policy: super::super::public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        capability: None,
                        actor_role: None,
                    }]),
                },
                ActorGenesis {
                    actor: ActorId([9; 32]),
                    name: "child".into(),
                    parent: Some(ActorId([5; 32])),
                    producer: ProducerId([4; 32]),
                    deployment: DeploymentId([12; 32]),
                    program: ProgramId([10; 32]),
                    initial_state: BlobRef::of_bytes(b"child-state"),
                    crdt: false,
                    role_policies: role_policies(vec![]),
                },
            ],
            external_actors: vec![],
            authorization: AuthorizationEvidence::SystemCapability {
                capability: SystemCapabilityId([11; 32]),
                authenticator: b"platform-authenticator".to_vec(),
            },
        };
        let install = AccumulateRequest::Install(genesis);
        assert_eq!(
            AccumulateRequest::decode(&install.encode()).unwrap(),
            install
        );

        let work = work();
        let artifact = ImportedBlob {
            reference: BlobRef::of_bytes(b"candidate artifact"),
            bytes: b"candidate artifact".to_vec(),
        };
        let transition = Transition {
            service: work.service.clone(),
            consumed_input: work.input_id(),
            target_deployment: work.target_deployment,
            target_program: work.target_program,
            base: work.base.clone(),
            writes: vec![],
            crdt_change: None,
            spawns: vec![],
            continuations: vec![],
            inbox: vec![],
            outbox: vec![],
            reply: None,
            exported_blobs: vec![artifact.reference.clone()],
            gas: GasAccounting::default(),
            proof: None,
        };
        let refined = RefineOutput {
            transition: transition.clone(),
            candidate_blobs: vec![artifact.clone()],
        };
        assert_eq!(RefineOutput::decode(&refined.encode()).unwrap(), refined);
        let apply = AccumulateRequest::Apply(AccumulationEnvelope {
            work,
            transition,
            provided_blobs: vec![artifact],
        });
        assert_eq!(AccumulateRequest::decode(&apply.encode()).unwrap(), apply);

        let admission = AccumulateRequest::AdmitIngress(DirectIngress {
            service: service(),
            invocation: InvocationId([18; 32]),
            logical_timeslot: 7,
            target: ActorId([5; 32]),
            method: "set".into(),
            arguments: vec![1],
            private_arguments: None,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
            imported_blobs: vec![],
            proof_requested: false,
            base: ConsistencyBase::Linear {
                revision: 1,
                state_root: Hash([19; 32]),
            },
            base_causal_height: None,
            crdt_change: None,
        });
        assert_eq!(
            AccumulateRequest::decode(&admission.encode()).unwrap(),
            admission
        );

        let AccumulateRequest::Apply(mut mismatched_proof) = apply.clone() else {
            unreachable!()
        };
        let proof_bytes = b"canonical proof bytes";
        let proof_blob = BlobRef::of_bytes(proof_bytes);
        mismatched_proof.transition.proof = Some(ProofCommitment {
            statement: Hash([14; 32]),
            trace: Hash([15; 32]),
            proof_blob: proof_blob.clone(),
        });
        mismatched_proof.provided_blobs = vec![ImportedBlob {
            reference: proof_blob,
            bytes: b"different proof bytes".to_vec(),
        }];
        assert_eq!(
            AccumulateRequest::decode(&AccumulateRequest::Apply(mismatched_proof).encode()),
            Err(DecodeError::NonCanonical),
            "a content-mismatched proof cannot enter a canonical Raft request"
        );

        let upgrade = ActorUpgrade {
            service: service(),
            actor: ActorId([5; 32]),
            expected_deployment: DeploymentId([2; 32]),
            expected_program: ProgramId([6; 32]),
            replacement_deployment: DeploymentId([20; 32]),
            replacement_program: ProgramId([20; 32]),
            producer: ProducerId([21; 32]),
            role_policies: role_policies(vec![MethodPolicy {
                method: "set".into(),
                schema: Hash([22; 32]),
                policy: super::super::public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                capability: None,
                actor_role: None,
            }]),
            base: ConsistencyBase::Linear {
                revision: 7,
                state_root: Hash([8; 32]),
            },
            authorization: AuthorizationEvidence::SystemCapability {
                capability: SystemCapabilityId([23; 32]),
                authenticator: vec![24],
            },
        };
        let upgrade_request = AccumulateRequest::UpgradeActor(upgrade.clone());
        assert_eq!(
            AccumulateRequest::decode(&upgrade_request.encode()).unwrap(),
            upgrade_request
        );
        assert_ne!(upgrade.hash(), Hash::ZERO);
        let upgraded = AccumulationResult::ActorUpgraded {
            actor: upgrade.actor,
            previous_deployment: upgrade.expected_deployment,
            previous_program: upgrade.expected_program,
            deployment: upgrade.replacement_deployment,
            program: upgrade.replacement_program,
            receipt: AccumulationReceipt {
                service: service(),
                accepted_transition: upgrade.hash(),
                reply_commitment: None,
                outbox_commitment: None,
                resulting_state_root: Some(Hash([25; 32])),
                resulting_crdt_heads: vec![],
                sequence: 8,
                checkpoint: 0,
                consistency: ConsistencyMode::Local,
            },
            duplicate: false,
        };
        assert_eq!(
            AccumulationResult::decode(&upgraded.encode()).unwrap(),
            upgraded
        );
        let mut invalid_upgrade = upgrade;
        invalid_upgrade.authorization = AuthorizationEvidence::Public;
        assert_eq!(
            ActorUpgrade::decode(&invalid_upgrade.encode()),
            Err(DecodeError::NonCanonical)
        );

        let AccumulateRequest::Apply(mut divergent) = apply else {
            unreachable!()
        };
        divergent.transition.consumed_input.workflow_step += 1;
        assert_eq!(
            AccumulationEnvelope::decode(&divergent.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut unexpected = divergent;
        unexpected.transition.consumed_input = unexpected.work.input_id();
        unexpected.provided_blobs[0] = ImportedBlob {
            reference: BlobRef::of_bytes(b"not referenced"),
            bytes: b"not referenced".to_vec(),
        };
        assert_eq!(
            AccumulationEnvelope::decode(&unexpected.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn crdt_ingress_compacts_disclosed_authorization_only_after_admission() {
        let credential = b"finalized role assertion".to_vec();
        let authorization = AuthorizationEvidence::Credential {
            policy: Hash([31; 32]),
            credential_commitment: Hash::digest(
                b"vos/credential-commitment/service",
                &[&credential],
            ),
            bytes: credential.clone(),
        };
        let mut ingress = DirectIngress {
            service: service(),
            invocation: InvocationId([32; 32]),
            logical_timeslot: 9,
            target: ActorId([5; 32]),
            method: "member_only".into(),
            arguments: vec![1],
            private_arguments: None,
            origin: Origin::Member(SubjectId([33; 32])),
            authorization,
            imported_blobs: vec![],
            proof_requested: false,
            base: ConsistencyBase::Crdt { heads: vec![] },
            base_causal_height: Some(0),
            crdt_change: None,
        };
        let operation = ingress.crdt_operation();
        let change = CrdtChange {
            id: CrdtChange::derive_ingress_id(&operation, &[]),
            work_hash: operation.commitment(),
            causal_dependencies: vec![],
            causal_height: 1,
            operations: vec![],
            workflow: vec![WorkflowOperation::Ingress(operation.clone())],
            materializations: vec![],
            awaited_reply: None,
            exported_blobs: vec![],
        };
        ingress.crdt_change = Some(change);
        assert_eq!(DirectIngress::decode(&ingress.encode()).unwrap(), ingress);

        let admitted = DirectIngress::decode(&ingress.encode_admitted()).unwrap();
        let materialized = DirectIngress::decode(&DirectIngress::encode_materialized(
            &operation,
            ingress.crdt_change.as_ref().unwrap(),
        ))
        .unwrap();
        assert_eq!(materialized, admitted);
        assert_eq!(admitted.authorization, AuthorizationEvidence::Public);
        assert!(admitted.authorization_matches(&ingress.authorization));
        assert!(admitted.matches_retry(&ingress));
        assert!(!operation.matches_fresh_direct(&admitted));
        assert_eq!(
            admitted
                .crdt_ingress()
                .and_then(|causal| causal.authorization_blob.as_ref()),
            Some(&BlobRef::of_bytes(&credential)),
        );
    }

    #[test]
    fn genesis_rejects_invalid_consistency_names_and_cycles() {
        let mut genesis = ServiceGenesis {
            role_authority: None,
            service: service(),
            consistency: ConsistencyMode::Crdt,
            actors: vec![ActorGenesis {
                actor: ActorId([5; 32]),
                name: "root".into(),
                parent: None,
                producer: ProducerId([4; 32]),
                deployment: DeploymentId([2; 32]),
                program: ProgramId([6; 32]),
                initial_state: BlobRef::of_bytes(b"state"),
                crdt: false,
                role_policies: role_policies(vec![]),
            }],
            external_actors: vec![],
            authorization: AuthorizationEvidence::SystemCapability {
                capability: SystemCapabilityId([7; 32]),
                authenticator: vec![1],
            },
        };
        assert_eq!(
            ServiceGenesis::decode(&genesis.encode()),
            Err(DecodeError::NonCanonical)
        );

        genesis.consistency = ConsistencyMode::Local;
        genesis.actors[0].crdt = true;
        assert_eq!(genesis.validate(), Err(DecodeError::NonCanonical));

        genesis.actors[0].crdt = false;
        genesis.actors[0].name = "x".repeat(super::super::MAX_ACTOR_NAME_BYTES + 1);
        assert_eq!(genesis.validate(), Err(DecodeError::NonCanonical));

        genesis.actors[0].name = "root".into();
        genesis.actors[0].parent = Some(genesis.actors[0].actor);
        assert_eq!(genesis.validate(), Err(DecodeError::NonCanonical));

        genesis.actors[0].parent = None;
        genesis.role_authority = Some(RoleAuthorityBinding {
            service: genesis.service.clone(),
            actor: ActorId([10; 32]),
        });
        assert_eq!(
            genesis.validate(),
            Err(DecodeError::NonCanonical),
            "a service cannot issue its own platform role assertions"
        );

        let authority = genesis.role_authority.as_mut().unwrap();
        authority.service.root_service = RootServiceId([11; 32]);
        authority.service.space = SpaceId([12; 32]);
        assert_eq!(
            genesis.validate(),
            Err(DecodeError::NonCanonical),
            "an authority from a sibling space is not trusted"
        );
    }

    #[test]
    fn external_directory_rejects_duplicate_actor_identities() {
        let actor = ActorId([21; 32]);
        let directory = ExternalActorDirectory {
            actors: vec![
                ExternalActorBinding {
                    name: "first".into(),
                    service: service(),
                    actor,
                    producer: ProducerId([22; 32]),
                    actor_deployment: DeploymentId([28; 32]),
                    program: ProgramId([23; 32]),
                },
                ExternalActorBinding {
                    name: "second".into(),
                    service: ServiceIdentity {
                        root_service: RootServiceId([24; 32]),
                        deployment: DeploymentId([25; 32]),
                        ..service()
                    },
                    actor,
                    producer: ProducerId([26; 32]),
                    actor_deployment: DeploymentId([29; 32]),
                    program: ProgramId([27; 32]),
                },
            ],
        };
        assert_eq!(
            ExternalActorDirectory::decode(&directory.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn actor_directory_requires_sorted_complete_membership() {
        let directory = ActorDirectory {
            actors: vec![ActorId([4; 32]), ActorId([5; 32])],
        };
        assert_eq!(
            ActorDirectory::decode(&directory.encode()).unwrap(),
            directory
        );

        for actors in [
            vec![],
            vec![ActorId([5; 32]), ActorId([4; 32])],
            vec![ActorId([4; 32]), ActorId([4; 32])],
            (0..=super::super::MAX_ROOT_TREE_ACTORS)
                .map(|index| {
                    let mut actor = [0; 32];
                    actor[24..].copy_from_slice(&(index as u64).to_be_bytes());
                    ActorId(actor)
                })
                .collect(),
        ] {
            let invalid = ActorDirectory { actors };
            assert_eq!(
                ActorDirectory::decode(&invalid.encode()),
                Err(DecodeError::NonCanonical)
            );
        }
    }

    #[test]
    fn accumulation_results_are_commit_decisions_on_the_wire() {
        let receipt = AccumulationReceipt {
            service: service(),
            accepted_transition: Hash([10; 32]),
            reply_commitment: None,
            outbox_commitment: None,
            resulting_state_root: Some(Hash([9; 32])),
            resulting_crdt_heads: vec![],
            sequence: 3,
            checkpoint: 0,
            consistency: ConsistencyMode::Local,
        };
        let admitted = AccumulationResult::IngressAdmitted {
            invocation: InvocationId([11; 32]),
            receipt,
            duplicate: false,
        };
        assert_eq!(
            AccumulationResult::decode(&admitted.encode()).unwrap(),
            admitted
        );

        let receipt = AccumulationReceipt {
            service: service(),
            accepted_transition: Hash([12; 32]),
            reply_commitment: None,
            outbox_commitment: None,
            resulting_state_root: Some(Hash([13; 32])),
            resulting_crdt_heads: vec![],
            sequence: 4,
            checkpoint: 2,
            consistency: ConsistencyMode::Local,
        };
        let accepted = AccumulationResult::Accepted {
            receipt: receipt.clone(),
            published: PublishedEffects::default(),
            duplicate: false,
        };
        assert_eq!(
            AccumulationResult::decode(&accepted.encode()).unwrap(),
            accepted
        );

        let reply = ReplyRecord {
            call_id: CallId([14; 32]),
            producer: ActorId([15; 32]),
            result: b"committed reply".to_vec(),
        };
        let mut reply_receipt = receipt.clone();
        reply_receipt.reply_commitment = Some(reply.commitment());
        let with_reply = AccumulationResult::Accepted {
            receipt: reply_receipt,
            published: PublishedEffects {
                reply: Some(reply.clone()),
                ..PublishedEffects::default()
            },
            duplicate: false,
        };
        assert_eq!(
            AccumulationResult::decode(&with_reply.encode()).unwrap(),
            with_reply
        );
        let mismatched = AccumulationResult::Accepted {
            receipt: receipt.clone(),
            published: PublishedEffects {
                reply: Some(reply),
                ..PublishedEffects::default()
            },
            duplicate: false,
        };
        assert_eq!(
            AccumulationResult::decode(&mismatched.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut outbox = vec![message(16, 0), message(17, 1)];
        outbox.sort_by_key(|message| message.call_id);
        let mut outbox_receipt = receipt.clone();
        outbox_receipt.outbox_commitment = MessageRecord::outbox_commitment(&outbox);
        let with_outbox = AccumulationResult::Accepted {
            receipt: outbox_receipt,
            published: PublishedEffects {
                outbox: outbox.clone(),
                ..PublishedEffects::default()
            },
            duplicate: false,
        };
        assert_eq!(
            AccumulationResult::decode(&with_outbox.encode()).unwrap(),
            with_outbox
        );
        let mismatched_outbox = AccumulationResult::Accepted {
            receipt: receipt.clone(),
            published: PublishedEffects {
                outbox,
                ..PublishedEffects::default()
            },
            duplicate: false,
        };
        assert_eq!(
            AccumulationResult::decode(&mismatched_outbox.encode()),
            Err(DecodeError::NonCanonical)
        );

        let duplicate = AccumulationResult::Accepted {
            receipt,
            published: PublishedEffects::default(),
            duplicate: true,
        };
        assert_eq!(
            AccumulationResult::decode(&duplicate.encode()).unwrap(),
            duplicate
        );

        let rejection = AccumulationResult::Rejected(AccumulationRejection::StaleLinearWork {
            expected_revision: 3,
            actual_revision: 4,
        });
        assert_eq!(
            AccumulationResult::decode(&rejection.encode()).unwrap(),
            rejection
        );
        assert!(AccumulationRejection::StaleStateRoot.is_retryable());
        assert!(!AccumulationRejection::DivergentDuplicate.is_retryable());
    }

    #[test]
    fn delivery_wire_binds_complete_source_outbox_and_has_stable_retry_identity() {
        let mut source_service = service();
        source_service.root_service = RootServiceId([30; 32]);
        let mut source_outbox = vec![message(31, 0), message(32, 1)];
        source_outbox.sort_by_key(|message| message.call_id);
        let first = source_outbox[0].clone();
        let source_receipt = AccumulationReceipt {
            service: source_service,
            accepted_transition: Hash([33; 32]),
            reply_commitment: None,
            outbox_commitment: MessageRecord::outbox_commitment(&source_outbox),
            resulting_state_root: Some(Hash([34; 32])),
            resulting_crdt_heads: vec![],
            sequence: 8,
            checkpoint: 0,
            consistency: ConsistencyMode::Local,
        };
        let delivery = DeliveryEnvelope {
            service: service(),
            logical_timeslot: 9,
            base: ConsistencyBase::Linear {
                revision: 3,
                state_root: Hash([35; 32]),
            },
            authorization: AuthorizationEvidence::Public,
            message: first,
            source_outbox,
            source_receipt,
        };
        assert_eq!(
            DeliveryEnvelope::decode(&delivery.encode()).unwrap(),
            delivery
        );
        assert_eq!(
            AccumulateRequest::decode(&AccumulateRequest::Deliver(delivery.clone()).encode())
                .unwrap(),
            AccumulateRequest::Deliver(delivery.clone())
        );

        let mut later_base = delivery.clone();
        later_base.base = ConsistencyBase::Linear {
            revision: 4,
            state_root: Hash([36; 32]),
        };
        later_base.logical_timeslot += 5;
        assert_eq!(later_base.retry_identity(), delivery.retry_identity());
        assert_ne!(later_base.commitment(), delivery.commitment());

        let mut different_authorization = delivery.clone();
        different_authorization.authorization = AuthorizationEvidence::Credential {
            policy: Hash([37; 32]),
            credential_commitment: Hash([38; 32]),
            bytes: vec![39],
        };
        assert_ne!(
            different_authorization.retry_identity(),
            delivery.retry_identity(),
            "destination authorization is part of logical delivery identity",
        );

        let mut source_authorized = delivery.clone();
        source_authorized.message.authorization = different_authorization.authorization;
        source_authorized.source_outbox[0] = source_authorized.message.clone();
        source_authorized.source_receipt.outbox_commitment =
            MessageRecord::outbox_commitment(&source_authorized.source_outbox);
        assert_eq!(
            DeliveryEnvelope::decode(&source_authorized.encode()),
            Err(DecodeError::NonCanonical),
            "source messages cannot smuggle destination authorization",
        );

        let mut alternate_receipt = delivery.clone();
        alternate_receipt.source_receipt.accepted_transition = Hash([38; 32]);
        alternate_receipt.source_receipt.sequence += 1;
        assert_eq!(
            alternate_receipt.retry_identity(),
            delivery.retry_identity(),
            "physical finality evidence is not logical delivery identity"
        );
        assert_ne!(alternate_receipt.commitment(), delivery.commitment());

        let mut wrong_finality_domain = alternate_receipt.clone();
        wrong_finality_domain.source_receipt.consistency = ConsistencyMode::Crdt;
        assert_ne!(
            wrong_finality_domain.retry_identity(),
            delivery.retry_identity(),
            "the source finality domain remains part of logical delivery identity"
        );

        let mut missing_member = delivery.clone();
        missing_member.message = message(37, 0);
        assert_eq!(
            DeliveryEnvelope::decode(&missing_member.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut tampered_outbox = delivery.clone();
        tampered_outbox.source_outbox[0].payload.push(0);
        assert_eq!(
            DeliveryEnvelope::decode(&tampered_outbox.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut reordered = delivery;
        reordered.source_outbox.swap(0, 1);
        assert_eq!(
            DeliveryEnvelope::decode(&reordered.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn publication_acknowledgement_is_a_canonical_guest_request_and_result() {
        let input = WorkInputId {
            invocation: InvocationId([40; 32]),
            workflow_step: 2,
        };
        let acknowledgement = PublicationAck {
            service: service(),
            input,
            publication: Hash([41; 32]),
        };
        let request = AccumulateRequest::AcknowledgePublication(acknowledgement);
        assert_eq!(
            AccumulateRequest::decode(&request.encode()).unwrap(),
            request
        );

        let result = AccumulationResult::PublicationAcknowledged {
            input,
            duplicate: false,
        };
        assert_eq!(
            AccumulationResult::decode(&result.encode()).unwrap(),
            result
        );
    }

    #[test]
    fn accumulated_reply_binds_exact_reply_to_receipt() {
        let reply = ReplyRecord {
            call_id: CallId([61; 32]),
            producer: ActorId([62; 32]),
            result: b"committed result".to_vec(),
        };
        let mut remote = service();
        remote.root_service = RootServiceId([63; 32]);
        let accumulated = AccumulatedReply {
            receipt: AccumulationReceipt {
                service: remote,
                accepted_transition: Hash([64; 32]),
                reply_commitment: Some(reply.commitment()),
                outbox_commitment: None,
                resulting_state_root: Some(Hash([65; 32])),
                resulting_crdt_heads: vec![],
                sequence: 7,
                checkpoint: 1,
                consistency: ConsistencyMode::Local,
            },
            reply,
            attestation: None,
        };
        assert_eq!(
            AccumulatedReply::decode(&accumulated.encode()).unwrap(),
            accumulated
        );
        let request = ReceiptVerificationRequest {
            expected_producer: accumulated.reply.producer,
            receipt: accumulated.receipt.clone(),
        };
        assert_eq!(
            ReceiptVerificationRequest::decode(&request.encode()).unwrap(),
            request
        );

        let mut mismatched = accumulated.clone();
        mismatched.reply.result.push(0);
        assert_eq!(
            AccumulatedReply::decode(&mismatched.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut initial = work();
        initial.awaited_reply = Some(accumulated);
        assert_eq!(
            WorkEnvelope::decode(&initial.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn call_expiration_wires_bind_the_exact_logical_timeout() {
        let caller_invocation = InvocationId([70; 32]);
        let timeout = CallTimeout {
            call_id: caller_invocation.call_id(2),
            caller_invocation,
            caller_actor: ActorId([71; 32]),
            checkpoint_step: 0,
            await_ordinal: 2,
            deadline_timeslot: 9,
            expired_at: 9,
        };
        let expiration = CallExpirationEnvelope {
            service: service(),
            timeout: timeout.clone(),
            base: ConsistencyBase::Linear {
                revision: 7,
                state_root: Hash([8; 32]),
            },
            base_causal_height: None,
            crdt_change: None,
        };
        let request = AccumulateRequest::ExpireCall(expiration.clone());
        assert_eq!(
            AccumulateRequest::decode(&request.encode()).unwrap(),
            request
        );

        let accumulated = AccumulatedTimeout {
            expiration: expiration.clone(),
            receipt: AccumulationReceipt {
                service: service(),
                accepted_transition: expiration.commitment(),
                reply_commitment: None,
                outbox_commitment: None,
                resulting_state_root: Some(Hash([24; 32])),
                resulting_crdt_heads: vec![],
                sequence: 8,
                checkpoint: 0,
                consistency: ConsistencyMode::Local,
            },
        };
        let result = AccumulationResult::CallExpired {
            timeout: accumulated,
            duplicate: false,
        };
        assert_eq!(
            AccumulationResult::decode(&result.encode()).unwrap(),
            result
        );

        let retirement = InboxRetirement {
            service: service(),
            call_id: timeout.call_id,
            deadline_timeslot: timeout.deadline_timeslot,
            base: ConsistencyBase::Linear {
                revision: 8,
                state_root: Hash([25; 32]),
            },
        };
        let request = AccumulateRequest::RetireInbox(retirement.clone());
        assert_eq!(
            AccumulateRequest::decode(&request.encode()).unwrap(),
            request
        );
        let retired = AccumulationResult::InboxRetired {
            call_id: retirement.call_id,
            duplicate: false,
        };
        assert_eq!(
            AccumulationResult::decode(&retired.encode()).unwrap(),
            retired
        );

        let mut early = expiration;
        early.timeout.expired_at = 8;
        assert_eq!(
            CallExpirationEnvelope::decode(&early.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn one_crdt_change_binds_the_complete_execution_slice() {
        let mut work = work();
        work.consistency = ConsistencyMode::Crdt;
        work.base = ConsistencyBase::Crdt {
            heads: vec![Hash([31; 32])],
        };
        work.base_causal_height = Some(3);
        let change_id = CrdtChange::derive_id(&work).unwrap();
        let operation_scope = CrdtChange::derive_operation_scope(&work).unwrap();
        let field = Hash([32; 32]);
        let transition = Transition {
            service: work.service.clone(),
            consumed_input: work.input_id(),
            target_deployment: work.target_deployment,
            target_program: work.target_program,
            base: work.base.clone(),
            writes: vec![],
            crdt_change: Some(CrdtChange {
                id: change_id,
                work_hash: work.hash(),
                causal_dependencies: vec![Hash([31; 32])],
                causal_height: 4,
                operations: vec![CrdtOperation {
                    actor: work.target,
                    dispatch_ordinal: 0,
                    field,
                    ordinal: 0,
                    id: operation_scope.operation(work.target, 0, field, 0),
                    payload: b"counter +1".to_vec(),
                }],
                workflow: vec![WorkflowOperation::Checkpoint(work.workflow_checkpoint())],
                materializations: vec![CrdtMaterialization {
                    actor: work.target,
                    state: BlobRef::of_bytes(b"materialized-state"),
                }],
                awaited_reply: None,
                exported_blobs: vec![],
            }),
            spawns: vec![],
            continuations: vec![],
            inbox: vec![],
            outbox: vec![],
            reply: None,
            exported_blobs: vec![],
            gas: GasAccounting::default(),
            proof: None,
        };
        let expected_checkpoint = work.workflow_checkpoint();
        let envelope = AccumulationEnvelope {
            work,
            transition,
            provided_blobs: vec![],
        };
        let decoded = AccumulationEnvelope::decode(&envelope.encode()).unwrap();
        assert_eq!(decoded, envelope);
        assert!(matches!(
            &decoded.transition.crdt_change.as_ref().unwrap().workflow[0],
            WorkflowOperation::Checkpoint(checkpoint) if checkpoint == &expected_checkpoint
        ));

        let mut bad_id = envelope.clone();
        bad_id.transition.crdt_change.as_mut().unwrap().operations[0].id = OperationId([99; 32]);
        assert_eq!(
            AccumulationEnvelope::decode(&bad_id.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut bad_work_hash = envelope.clone();
        bad_work_hash
            .transition
            .crdt_change
            .as_mut()
            .unwrap()
            .work_hash = Hash([98; 32]);
        assert_eq!(
            AccumulationEnvelope::decode(&bad_work_hash.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut missing_workflow_reply = envelope;
        missing_workflow_reply.transition.reply = Some(ReplyRecord {
            call_id: CallId([44; 32]),
            producer: ActorId([45; 32]),
            result: b"done".to_vec(),
        });
        assert_eq!(
            AccumulationEnvelope::decode(&missing_workflow_reply.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn crdt_change_identity_distinguishes_physical_retry_branches() {
        let mut first = work();
        first.consistency = ConsistencyMode::Crdt;
        first.base = ConsistencyBase::Crdt {
            heads: vec![Hash([41; 32])],
        };
        let mut different_base = first.clone();
        different_base.base = ConsistencyBase::Crdt {
            heads: vec![Hash([42; 32])],
        };

        assert_ne!(
            CrdtChange::derive_id(&first),
            CrdtChange::derive_id(&different_base),
            "different physical causal branches need distinct DAG identities"
        );
        assert_eq!(
            CrdtChange::derive_operation_scope(&first),
            CrdtChange::derive_operation_scope(&different_base),
            "logical retries must allocate the same idempotent CRDT operation IDs"
        );
        assert_ne!(
            first.hash(),
            different_base.hash(),
            "changing the causal base is not an exact retry"
        );
        assert!(
            first.matches_crdt_retry(&different_base),
            "the canonical materializer still recognizes the same logical invocation"
        );
        different_base.arguments.push(99);
        assert!(
            !first.matches_crdt_retry(&different_base),
            "caller-controlled inputs are part of stable retry identity"
        );
    }

    #[test]
    fn crdt_operations_are_encoded_in_emission_order_not_hash_order() {
        let mut work = work();
        work.consistency = ConsistencyMode::Crdt;
        work.base = ConsistencyBase::Crdt { heads: vec![] };
        work.base_causal_height = Some(0);
        let change = CrdtChange::derive_id(&work).unwrap();
        let operation_scope = CrdtChange::derive_operation_scope(&work).unwrap();
        let first_field = Hash([51; 32]);
        let first_id = operation_scope.operation(work.target, 0, first_field, 0);
        let (second_field, second_id) = (0u16..=u16::MAX)
            .find_map(|nonce| {
                let mut bytes = [0u8; 32];
                bytes[..2].copy_from_slice(&nonce.to_le_bytes());
                let field = Hash(bytes);
                let id = operation_scope.operation(work.target, 0, field, 1);
                (id < first_id).then_some((field, id))
            })
            .expect("a descending hash-order fixture exists");
        let operations = vec![
            CrdtOperation {
                actor: work.target,
                dispatch_ordinal: 0,
                field: first_field,
                ordinal: 0,
                id: first_id,
                payload: vec![1],
            },
            CrdtOperation {
                actor: work.target,
                dispatch_ordinal: 0,
                field: second_field,
                ordinal: 1,
                id: second_id,
                payload: vec![2],
            },
        ];
        assert!(operations[0].id > operations[1].id);
        let value = CrdtChange {
            id: change,
            work_hash: work.hash(),
            causal_dependencies: vec![],
            causal_height: 1,
            operations,
            workflow: vec![WorkflowOperation::Checkpoint(work.clone())],
            materializations: vec![],
            awaited_reply: None,
            exported_blobs: vec![],
        };
        assert_eq!(CrdtChange::decode(&value.encode()).unwrap(), value);

        let mut reordered = value;
        reordered.operations.swap(0, 1);
        assert_eq!(
            CrdtChange::decode(&reordered.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn attestation_proof_manifests_are_bounded_anchored_and_canonical() {
        let first = ProofArtifactId([92; 32]);
        let second = ProofArtifactId([93; 32]);
        let manifest = AttestationProofManifest {
            proof_system: AttestationProofManifest::proof_system(),
            initial_root: Hash([91; 32]),
            segments: vec![first, second],
        };
        assert_eq!(
            AttestationProofManifest::decode(&manifest.encode()).unwrap(),
            manifest
        );

        let mut unanchored = manifest.clone();
        unanchored.initial_root = Hash::ZERO;
        assert_eq!(
            AttestationProofManifest::decode(&unanchored.encode()),
            Err(DecodeError::NonCanonical)
        );
        let mut duplicate = manifest.clone();
        duplicate.segments.push(first);
        assert_eq!(
            AttestationProofManifest::decode(&duplicate.encode()),
            Err(DecodeError::NonCanonical)
        );
        let mut invalid = manifest;
        invalid.segments[0] = ProofArtifactId([0; 32]);
        assert_eq!(
            AttestationProofManifest::decode(&invalid.encode()),
            Err(DecodeError::NonCanonical)
        );
    }
}
