//! Canonical service contracts.
//!
//! A root actor tree is owned by one service program. Refine receives every
//! input explicitly and returns a deterministic [`Transition`]. Only
//! Accumulate may mutate service state or publish effects. Persisted objects
//! bind [`PLATFORM_ID`]; bytes from any other platform are rejected.

mod causal;
mod continuation;
mod contracts;
mod guest_accumulate;
mod identity;
#[cfg(feature = "std")]
mod local_store;
mod package;
#[cfg(feature = "std")]
mod pvm;
#[cfg(feature = "std")]
mod root_service;
#[cfg(feature = "std")]
mod scheduler;
#[cfg(feature = "std")]
#[allow(clippy::module_inception)]
mod service;
mod state_tree;
mod storage;
#[cfg(feature = "std")]
mod transport;
pub(crate) mod wire;

pub use crate::attestation::AttestationPreparation;

pub use continuation::{ContinuationProgram, ContinuationSnapshot};
#[cfg(all(feature = "std", feature = "network", feature = "storage"))]
pub(crate) use contracts::crdt_change_blob_references;
pub use contracts::{
    AccumulateRequest, AccumulatedReply, AccumulatedRoleAssertion, AccumulatedTimeout,
    AccumulationEnvelope, AccumulationReceipt, AccumulationRejection, AccumulationResult,
    ActorCallRequest, ActorCallResult, ActorCrdtState, ActorDirectory, ActorEffectBatch,
    ActorGenesis, ActorPrivateInput, ActorSliceInput, ActorSliceOutput, ActorSpawn,
    ActorSpawnRequest, ActorStorageKey, ActorStorageRow, ActorTreeImport, ActorUpgrade, ActorWrite,
    AttestationDelivery, AttestationProofManifest, AttestationResume, AuthorizationEvidence,
    AwaitResume, BlobRef, CallExpirationEnvelope, CallTimeout, CausalCallContext, CheckpointToken,
    ConsistencyBase, ConsistencyMode, ContinuationChange, CrdtChange, CrdtDispatch, CrdtIngress,
    CrdtMaterialization, CrdtOperation, CrdtSyncEnvelope, CrdtSyncNode, DeliveryEnvelope,
    DirectIngress, ExternalActorBinding, ExternalActorDirectory, GasAccounting, GasSchedule,
    ImportedActor, ImportedBlob, ImportedProgram, InboxRetirement, MessageRecord, MethodPolicy,
    ProofArtifactId, ProofCommitment, ProofVerificationRequest, PublicationAck, PublishedEffects,
    ROLE_AUTHORITY_DECISION_METHOD_, ROLE_AUTHORITY_INSTANCE_, ROLE_AUTHORITY_INVITE_METHOD_,
    ROLE_AUTHORITY_INVITE_REVOKE_METHOD_, ROLE_AUTHORITY_MUTATION_METHOD_,
    ReceiptVerificationRequest, RefineError, RefineImports, RefineOutput, ReplyRecord,
    RoleAuthorityBinding, RoleAuthorityInviteRedemption, RoleAuthorityInviteRevocation,
    RoleAuthorityMutation, RoleAuthorizationClaim, RoleCredential,
    RoleCredentialVerificationRequest, ServiceGenesis, ServiceIdentity, ServiceInstallReceipt,
    TaskDependency, Transition, WorkEnvelope, WorkInputId, WorkflowOperation,
};
pub use guest_accumulate::{
    GuestAccumulateError, GuestAccumulateStore, ProofVerification, ReceiptVerification,
    execute_canonical_guest_accumulate, execute_guest_accumulate,
    execute_owned_canonical_guest_accumulate,
};
pub use identity::{
    ActorId, CallId, ChangeId, DeploymentId, Hash, InvocationId, OperationId, Origin, ProducerId,
    ProgramId, RootServiceId, SpaceId, SubjectId, SystemCapabilityId,
};
#[cfg(feature = "std")]
pub use local_store::{
    CommittedImageStore, CommittedServiceImageHost, DurableServiceStore, DurableStoreOpenError,
    FileCommittedImageStore, LocalStoreReadError, MemoryServiceHost, MemoryServiceSnapshot,
    MemoryServiceStore, PrivateIngressStaging, ProductionTrust, ProductionTrustDecision,
    ProductionTrustError, ProofArtifactStore, ServiceImageInstallError,
};
pub use package::{
    DeploymentSignature, PackageDiagnostics, PackageError, PackageManifest, PackageRolePolicies,
    PackageTaskDependency, VosPackage, artifact_hash, method_role_policy_hash, method_schema_hash,
    public_policy_hash, space_role_policy_hash, task_dependencies_hash,
};
#[cfg(feature = "std")]
pub use pvm::{
    AccumulateProtocolHost, AccumulateTransaction, DeviceSecret, DeviceSignerRefineHost,
    NoRefineProtocolHost, ProducedProvableRecord, ReceiptVerificationHost, RefineProtocolHost,
    RefineTrace, SERVICE_ARGUMENT_PAGES_, ServicePvm, ServicePvmError, ServicePvmOutput,
    transpile_service_elf, validate_actor_program_layout,
};
#[cfg(feature = "std")]
pub use root_service::{
    AttestedRootTreeInvokeError, CommittedCrdtSync, CommittedRootTreeSlice, LocalRootTreeConfig,
    LocalRootTreeConfigError, LocalRootTreeInvokeError, LocalRootTreeOpenError,
    LocalRootTreeService, ROOT_UPGRADE_METHOD_, RootTreeAttestedResult, RootTreeIngressRecovery,
    RootTreeInvocation, RootTreeTransport, RootTreeUpgradeRequest,
};
#[cfg(feature = "std")]
pub use scheduler::{LocalWorkRequest, LocalWorkScheduler, PreparedWork, ScheduleError};
#[cfg(feature = "std")]
pub use service::{
    AccumulatedServiceOutput, AttestedServiceError, CommittedAccumulateBatch,
    CommittedAccumulateEntry, CommittedAccumulateLog, CommittedAttestationOutput,
    CommittedProofArtifact, CommittedServiceSnapshot, RefinedServiceOutput, ReplicatedServiceError,
    ReplicatedServiceRuntime, ServiceDispatchError, ServiceRuntime,
};
pub use state_tree::{
    SERVICE_STATE_KEY_DOMAIN, SERVICE_STATE_LEAF_DOMAIN, SERVICE_STATE_NODE_DOMAIN,
    ServiceStateTree, StateTreeError, StateTreeStore, empty_state_root, state_position,
};
pub use storage::{
    ActorUpgradeRecord, DedupRecord, DeliveryRecord, IngressRecord, PendingCallDeadline,
    PublicationAckRecord, PublicationRecord, ReplyAdmissionRecord, RoleAssertionEligibility,
    StateKey, StoreHeader, StoreOpenError, WorkflowCheckpoint, actor_upgrade_storage_key,
    call_expiration_storage_key, crdt_change_storage_key, crdt_node_receipt_storage_key,
    crdt_node_storage_key, dedup_storage_key, delivery_storage_key, header_storage_key,
    ingress_storage_key, pending_call_deadline_storage_key, publication_ack_storage_key,
    publication_storage_key, receipt_storage_key, reply_admission_storage_key,
    role_assertion_eligibility_storage_key,
};
#[cfg(feature = "std")]
pub use transport::{
    AttestedTransportError, CommittedDelivery, CommittedInboxSlice, CommittedReplyResume,
    InboxDrainOutcome, LocalTransport, LocalTransportError,
};
pub use wire::{DecodeError, ServiceWire};

/// Identity of the canonical wire, package, store, continuation, and
/// attestation contract. A contract change creates a new clean platform
/// identity; no alternate decoder is retained.
pub const PLATFORM_ID: Hash = Hash(*b"vos-platform-canonical-20260825!");

/// Program identity of the canonical [`vos-service.pvm`](../../../services/vos-service/vos-service.pvm).
///
/// This is protocol infrastructure, not a locally derived cache key. A fresh
/// service build must match both the committed bytes and this identity.
pub const VOS_SERVICE_PROGRAM_ID: ProgramId = ProgramId([
    0x41, 0xbe, 0xfb, 0xcb, 0x4a, 0xd2, 0xa5, 0x5a, 0x1b, 0x0c, 0xe5, 0x9d, 0x64, 0x78, 0xd6, 0x46,
    0x17, 0x46, 0xb6, 0xa3, 0x52, 0x6b, 0x5e, 0x1f, 0x32, 0xc3, 0xcd, 0x95, 0xdb, 0x9c, 0x4f, 0xc8,
]);

/// Instruction counter for the service Refine entry.
pub const REFINE_ENTRY_IC: u32 = 0;
/// Instruction counter for the service Accumulate entry.
pub const ACCUMULATE_ENTRY_IC: u32 = 5;

/// Owning HANDLE through which the generic service enters the target actor VM.
/// This is a PVM capability-table slot supplied at invocation setup.
pub const TARGET_ACTOR_HANDLE_SLOT: u8 = 144;
/// Maximum actor programs in one root tree.
///
/// The PVM kernel owns one shared code-capability table with five
/// entries. The generic VOS service consumes the first entry, leaving four
/// application actors. This is a kernel limit, not a VOS wire-size limit.
pub const MAX_ROOT_TREE_ACTORS: usize = 4;

/// Maximum signed pure-Task dependencies carried by one actor package.
/// Dependency programs are not installed as dormant root-tree VMs and
/// therefore do not consume the root tree's scarce code-capability slots,
/// but the package/work wires still need a deterministic bound.
pub const MAX_PACKAGE_TASK_DEPENDENCIES: usize = 16;

/// Maximum actor-local storage rows one Refine slice may authenticate.
pub const MAX_ACTOR_STORAGE_WITNESSES: usize = 256;
/// Maximum adaptive discovery/restart rounds for one Refine slice. One round
/// may discover many independent reads; this caps host work when later reads
/// are selected by values obtained in earlier rounds.
pub const MAX_ACTOR_STORAGE_WITNESS_ROUNDS: usize = 16;
/// Maximum physical actor-storage key accepted into one authenticated witness.
pub const MAX_ACTOR_STORAGE_KEY_BYTES: usize = 4096;
/// Maximum aggregate value bytes hydrated for actor storage reads in one
/// Refine slice. Point reads remain bounded even when individual rows approach
/// the storage layer's 64-KiB value ceiling.
pub const MAX_ACTOR_STORAGE_WITNESS_BYTES: usize = 1024 * 1024;

#[cfg(feature = "std")]
const _: () = assert!(MAX_ROOT_TREE_ACTORS + 1 == vos_pvm::vm_pool::MAX_CODE_CAPS);

/// Maximum UTF-8 byte length of one actor's parent-scoped name.
pub const MAX_ACTOR_NAME_BYTES: usize = 128;

/// First per-actor CALLABLE slot used for same-tree routes. The canonical
/// actor directory index selects the exact slot in every actor CNode.
pub const ACTOR_CALLABLE_BASE_SLOT: u8 = 128;

/// Move-only DATA capability used for service↔actor slice input/output.
/// Kept above the complete root HANDLE window (144..=147).
pub const ACTOR_IPC_CAP_SLOT: u8 = 240;
/// Temporary actor-CNode slot used while CALL owns the reserved IPC slot 0.
pub const ACTOR_SAVED_ARGS_CAP_SLOT: u8 = 253;
/// Actor-local spare used to pass the exclusive IPC cap through nested CALL.
pub const ACTOR_NESTED_IPC_CAP_SLOT: u8 = 252;
/// High virtual page kept outside transpiler-owned actor memory layouts.
pub const ACTOR_IPC_BASE_PAGE: u32 = 0x000f_0000;
/// Maximum shared directory/message input handed to one application actor.
pub const ACTOR_SLICE_INPUT_MAX_BYTES: usize = 64 * 1024;
/// Maximum private state frontier handed to one active actor VM.
///
/// Application actors retain the compact 256 KiB heap while the generic
/// service may receive multi-megabyte work envelopes. State is bounded
/// separately from shared IPC so one actor never receives a sibling's bytes.
pub const ACTOR_PRIVATE_INPUT_MAX_BYTES: usize = 64 * 1024;
/// Maximum message accepted by one host-private device-sign operation.
///
/// Signing is host work rather than PVM instructions, so payload size and
/// call count are bounded independently of the actor's ordinary gas budget.
pub const DEVICE_SIGN_MAX_PAYLOAD_BYTES: usize = 4 * 1024;
/// Maximum host-private signatures produced during one Refine slice.
pub const DEVICE_SIGN_MAX_CALLS_PER_REFINE: u32 = 8;
/// Maximum opaque actor-effect batch returned to the generic service guest.
pub const ACTOR_EFFECT_BATCH_MAX_BYTES: usize =
    MAX_ROOT_TREE_ACTORS * ACTOR_PRIVATE_INPUT_MAX_BYTES;
/// Bounded stack window receiving a checkpoint token after snapshot capture.
pub const CHECKPOINT_TOKEN_CAPACITY: usize = 4096;
/// Maximum portable proof payload carried through one actor resume. Bytes are
/// staged in the invocation-owned IPC capability, never the stack token.
pub const MAX_ATTESTATION_PROOF_BYTES: usize = 16 * 4096;
/// Maximum number of independently content-addressed STARK segments in one
/// attestation manifest. The current Clerk-scale trace uses 707; 1024 leaves
/// headroom while keeping manifest decode and verifier scheduling bounded.
pub const MAX_ATTESTATION_PROOF_SEGMENTS: usize = 1024;
/// Each streamed proof artifact must fit comfortably inside the node's 8-MiB
/// frame together with its authenticated transport envelope.
pub const MAX_ATTESTATION_PROOF_SEGMENT_BYTES: u64 = 4 * 1024 * 1024;
/// Register marker distinguishing an awaited-call suspension from an explicit
/// scheduler yield at the shared SUSPEND capability.
pub const AWAIT_SUSPEND_MAGIC: u64 = 0x564f_532d_4157_5432;
/// Marker passed in phi[10] so the canonical actor entry selects CALL/REPLY.
pub const NESTED_ACTOR_CALL_MAGIC: u64 = 0x564f_532d_4143_5432;

/// The two functions exposed by the generic service program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServiceFunction {
    Refine = REFINE_ENTRY_IC,
    Accumulate = ACCUMULATE_ENTRY_IC,
}

impl ServiceFunction {
    pub const fn from_entry_ic(entry_ic: u32) -> Option<Self> {
        match entry_ic {
            REFINE_ENTRY_IC => Some(Self::Refine),
            ACCUMULATE_ENTRY_IC => Some(Self::Accumulate),
            _ => None,
        }
    }
}

/// Source revision imported into the runtime, compiler, proof tracer, and
/// verifier. Upstream provenance is documented inside [`pvm`](../../../pvm/README.md).
pub const PVM_REVISION: &str = "41d31e64b0f5d6c57a43769d7b8785556a311684";

/// Consensus-visible execution semantics. Changing interpreter/recompiler or
/// trace behavior requires a new identifier even if the public Rust API did
/// not change.
pub const EXECUTION_SEMANTICS_ID: Hash = Hash(*b"vos-pvm-41d31e6-semantics-cut001");
