//! VOS runtime v2: JAM-aligned service contracts.
//!
//! A root actor tree is owned by one logical JAM service. One generic service
//! program exposes the two Gray Paper entry instruction counters: Refine at IC
//! 0 and Accumulate at IC 5. Registers `phi[7]`/`phi[8]` retain their standard
//! argument-window meaning. Refine receives every input explicitly and returns
//! a deterministic [`TransitionV2`]. Only Accumulate may mutate service state
//! or publish effects.
//!
//! This is a clean boundary. None of the types in this module accept legacy
//! `RefinePayload`, `EffectLog`, or continuation encodings.

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
mod service;
mod state_tree;
mod storage;
#[cfg(feature = "std")]
mod transport;
pub(crate) mod wire;

pub use crate::attestation::AttestationPreparationV2;

pub use continuation::{ContinuationProgramV2, ContinuationSnapshotV2};
pub use contracts::{
    AccumulateRequestV2, AccumulatedReplyV2, AccumulatedRoleAssertionV2, AccumulatedTimeoutV2,
    AccumulationEnvelopeV2, AccumulationReceiptV2, AccumulationRejectionV2, AccumulationResultV2,
    ActorCallRequestV2, ActorCallResultV2, ActorCrdtStateV2, ActorDirectoryV2, ActorEffectBatchV2,
    ActorGenesisV2, ActorPrivateInputV2, ActorSliceInputV2, ActorSliceOutputV2,
    ActorSpawnRequestV2, ActorSpawnV2, ActorTreeImportV2, ActorUpgradeV2, ActorWriteV2,
    AttestationDeliveryV2, AttestationResumeV2, AuthorizationEvidenceV2, AwaitResumeV2, BlobRefV2,
    CallExpirationEnvelopeV2, CallTimeoutV2, CausalCallContextV2, CheckpointTokenV2,
    ConsistencyBaseV2, ConsistencyModeV2, ContinuationChangeV2, CrdtChangeV2, CrdtDispatchV2,
    CrdtIngressV2, CrdtMaterializationV2, CrdtOperationV2, CrdtSyncEnvelopeV2, CrdtSyncNodeV2,
    DeliveryEnvelopeV2, DirectIngressV2, ExternalActorBindingV2, ExternalActorDirectoryV2,
    GasAccountingV2, ImportedActorV2, ImportedBlobV2, ImportedProgramV2, MessageRecordV2,
    MethodPolicyV2, ProofCommitmentV2, ProofVerificationRequestV2, PublicationAckV2,
    PublishedEffectsV2, ROLE_AUTHORITY_DECISION_METHOD_V2, ROLE_AUTHORITY_MUTATION_METHOD_V2,
    ReceiptVerificationRequestV2, RefineError, RefineImportsV2, RefineOutputV2, ReplyRecordV2,
    RoleAuthorityBindingV2, RoleAuthorityMutationV2, RoleAuthorizationClaimV2, RoleCredentialV2,
    RoleCredentialVerificationRequestV2, ServiceGenesisV2, ServiceIdentityV2,
    ServiceInstallReceiptV2, TransitionV2, WorkEnvelopeV2, WorkInputIdV2, WorkflowOperationV2,
};
pub use guest_accumulate::{
    GuestAccumulateError, GuestAccumulateStoreV2, ProofVerificationV2, ReceiptVerificationV2,
    execute_canonical_guest_accumulate, execute_guest_accumulate,
};
pub use identity::{
    ActorId, CallId, ChangeId, DeploymentId, Hash, InvocationId, OperationId, Origin, ProducerId,
    ProgramId, RootServiceId, SpaceId, SubjectId, SystemCapabilityId,
};
#[cfg(feature = "std")]
pub use local_store::{
    CommittedImageStoreV2, CommittedServiceImageHostV2, DurableJamStoreV2, DurableStoreOpenErrorV2,
    FileCommittedImageStoreV2, LocalJamStoreHostV2, LocalJamStoreSnapshotV2, LocalJamStoreV2,
    LocalStoreReadErrorV2, ProofArtifactStoreV2, ServiceImageInstallErrorV2,
};
pub use package::{
    DeploymentSignatureV2, PackageDiagnosticsV2, PackageError, PackageManifestV2,
    PackageRolePoliciesV2, VosPackageV2, artifact_hash, method_role_policy_hash,
    method_schema_hash, public_policy_hash, space_role_policy_hash,
};
#[cfg(feature = "std")]
pub use pvm::{
    AccumulateProtocolHostV2, AccumulateTransactionV2, NoRefineProtocolHostV2,
    RefineProtocolHostV2, RefineTraceV2, SERVICE_ARGUMENT_PAGES_V2, ServicePvmErrorV2,
    ServicePvmOutputV2, ServicePvmV2, transpile_service_elf, validate_actor_program_layout,
};
#[cfg(feature = "std")]
pub use root_service::{
    CommittedCrdtSyncV2, CommittedRootTreeSliceV2, LocalRootTreeConfigErrorV2,
    LocalRootTreeConfigV2, LocalRootTreeInvokeErrorV2, LocalRootTreeOpenErrorV2,
    LocalRootTreeServiceV2, RootTreeIngressRecoveryV2, RootTreeInvocationV2, RootTreeTransportV2,
};
#[cfg(feature = "std")]
pub use scheduler::{LocalWorkRequestV2, LocalWorkSchedulerV2, PreparedWorkV2, ScheduleErrorV2};
#[cfg(feature = "std")]
pub use service::{
    AccumulatedServiceOutputV2, AttestedServiceErrorV2, CommittedAccumulateBatchV2,
    CommittedAccumulateEntryV2, CommittedAccumulateLogV2, CommittedAttestationOutputV2,
    CommittedServiceSnapshotV2, JamServiceV2, RefinedServiceOutputV2, ReplicatedJamServiceV2,
    ReplicatedServiceErrorV2, ServiceDispatchError,
};
pub use state_tree::{
    SERVICE_STATE_KEY_DOMAIN, SERVICE_STATE_LEAF_DOMAIN, SERVICE_STATE_NODE_DOMAIN,
    ServiceStateTreeV2, StateTreeError, StateTreeStore, empty_state_root, state_position,
};
pub use storage::{
    ActorUpgradeRecordV2, DedupRecordV2, DeliveryRecordV2, IngressRecordV2, PendingCallDeadlineV2,
    PublicationRecordV2, ReplyAdmissionRecordV2, RoleAssertionEligibilityV2,
    SERVICE_STORE_SCHEMA_VERSION, StateKeyV2, StoreHeaderV2, StoreOpenError, WorkflowCheckpointV2,
    actor_upgrade_storage_key, call_expiration_storage_key, crdt_change_storage_key,
    crdt_node_receipt_storage_key, crdt_node_storage_key, dedup_storage_key, delivery_storage_key,
    header_storage_key, ingress_storage_key, pending_call_deadline_storage_key,
    publication_storage_key, receipt_storage_key, reply_admission_storage_key,
    role_assertion_eligibility_storage_key,
};
#[cfg(feature = "std")]
pub use transport::{
    AttestedTransportErrorV2, CommittedDeliveryV2, CommittedInboxSliceV2, CommittedReplyResumeV2,
    InboxDrainOutcomeV2, LocalTransportErrorV2, LocalTransportV2,
};
pub use wire::{DecodeError, V2Wire};

/// Platform wire/ABI version carried by v2 work, transitions, and receipts.
pub const ABI_VERSION: u16 = 5;
/// Portable continuation format version.
pub const SNAPSHOT_VERSION: u16 = 6;
/// Attestation statement version required by runtime v2.
pub const ATTESTATION_STATEMENT_VERSION: u16 = 3;

/// Program identity of the canonical [`vos-service.pvm`](../../../services/vos-service/vos-service.pvm).
///
/// This is protocol infrastructure, not a locally derived cache key. A fresh
/// service build must match both the committed bytes and this identity.
pub const VOS_SERVICE_PROGRAM_ID: ProgramId = ProgramId([
    0x11, 0xf2, 0xbe, 0xfb, 0x0c, 0xb4, 0x70, 0x4e, 0xd1, 0x75, 0xa9, 0x39, 0x24, 0x2f, 0x6a, 0x17,
    0x42, 0x74, 0x2f, 0x3b, 0x6e, 0xac, 0x73, 0xe1, 0x23, 0x37, 0x85, 0xf7, 0xa6, 0xbd, 0x7d, 0x9b,
]);

/// Gray Paper instruction counter for the service Refine entry.
pub const REFINE_ENTRY_IC: u32 = 0;
/// Gray Paper instruction counter for the service Accumulate entry.
pub const ACCUMULATE_ENTRY_IC: u32 = 5;

/// Owning HANDLE through which the generic service enters the target actor VM.
/// This is a JAR capability-table slot supplied at invocation setup, not a JAM
/// protocol capability or hostcall number.
pub const TARGET_ACTOR_HANDLE_SLOT: u8 = 144;
/// Maximum actor programs in one root tree.
///
/// The pinned JAR kernel owns one shared code-capability table with five
/// entries. The generic VOS service consumes the first entry, leaving four
/// application actors. This is a kernel limit, not a VOS wire-size limit.
pub const MAX_ROOT_TREE_ACTORS: usize = 4;

#[cfg(feature = "std")]
const _: () = assert!(MAX_ROOT_TREE_ACTORS + 1 == javm::vm_pool::MAX_CODE_CAPS);

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
/// Maximum opaque actor-effect batch returned to the generic service guest.
pub const ACTOR_EFFECT_BATCH_MAX_BYTES: usize =
    MAX_ROOT_TREE_ACTORS * ACTOR_PRIVATE_INPUT_MAX_BYTES;
/// Bounded stack window receiving a checkpoint token after snapshot capture.
pub const CHECKPOINT_TOKEN_CAPACITY: usize = 4096;
/// Maximum portable proof payload carried through one actor resume. Bytes are
/// staged in the invocation-owned IPC capability, never the stack token.
pub const MAX_ATTESTATION_PROOF_BYTES: usize = 16 * 4096;
/// Register marker distinguishing an awaited-call suspension from an explicit
/// scheduler yield at the shared SUSPEND capability.
pub const AWAIT_SUSPEND_MAGIC: u64 = 0x564f_532d_4157_5432;
/// Marker passed in phi[10] so the canonical actor entry selects CALL/REPLY.
pub const NESTED_ACTOR_CALL_MAGIC: u64 = 0x564f_532d_4143_5432;

/// The two functions exposed by the generic service program through the Gray
/// Paper two-slot entry prologue.
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

/// Revision shared by JAVM, the transpiler, proof tracer, verifier, and fuzz
/// targets. `just check-jar-revisions` verifies that every manifest uses it.
pub const JAR_REVISION: &str = "41d31e64b0f5d6c57a43769d7b8785556a311684";

/// Consensus-visible execution semantics. Changing interpreter/recompiler or
/// trace behavior requires a new identifier even if the public Rust API did
/// not change.
pub const EXECUTION_SEMANTICS_ID: Hash = Hash(*b"vos-jar-v2-41d31e6-semantics-v4\0");
