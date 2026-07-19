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

mod accumulate;
mod continuation;
mod contracts;
mod identity;
mod package;
#[cfg(feature = "std")]
mod pvm;
mod service;
mod storage;
pub(crate) mod wire;

pub use accumulate::{
    AccumulateError, AccumulationOutcome, AccumulationValidator, AllowPublic, InMemoryServiceState,
    PublishedEffects,
};
pub use continuation::{
    CapabilitySnapshotV2, ContinuationSnapshotV2, MemoryPageRefV2, PendingProtocolCallV2,
    ResumedKernelV2, SchedulerSnapshotV2, VmLifecycleV2, VmSnapshotV2,
};
pub use contracts::{
    AccumulationReceiptV2, ActorSliceInputV2, ActorSliceOutputV2, ActorWriteV2,
    AuthorizationEvidenceV2, BlobRefV2, ConsistencyBaseV2, ConsistencyModeV2,
    ContinuationChangeV2, CrdtOperationV2, GasAccountingV2, ImportedActorV2, ImportedBlobV2,
    ImportedProgramV2, MessageRecordV2, ProofCommitmentV2, Refine, RefineError, RefineImportsV2,
    ReplyRecordV2, ServiceIdentityV2, TransitionV2, WorkEnvelopeV2, WorkInputIdV2,
};
pub use identity::{
    ActorId, CallId, DeploymentId, Hash, InvocationId, OperationId, Origin, ProducerId, ProgramId,
    RootServiceId, SpaceId, SubjectId, SystemCapabilityId,
};
pub use package::{
    DeploymentSignatureV2, PackageDiagnosticsV2, PackageError, PackageManifestV2, VosPackageV2,
    artifact_hash,
};
#[cfg(feature = "std")]
pub use pvm::{
    AccumulateProtocolHostV2, AccumulateTransactionV2, NoRefineProtocolHostV2,
    RefineProtocolHostV2, ServicePvmErrorV2, ServicePvmOutputV2, ServicePvmV2,
};
pub use service::{JamServiceV2, ServiceDispatchError, ServiceDispatchOutputV2};
pub use storage::{StoreHeaderV2, StoreOpenError};
pub use wire::{DecodeError, V2Wire};

/// Platform wire/ABI version carried by v2 work, transitions, and receipts.
pub const ABI_VERSION: u16 = 2;
/// Portable continuation format version.
pub const SNAPSHOT_VERSION: u16 = 2;
/// Attestation statement version required by runtime v2.
pub const ATTESTATION_STATEMENT_VERSION: u16 = 3;

/// Gray Paper instruction counter for the service Refine entry.
pub const REFINE_ENTRY_IC: u32 = 0;
/// Gray Paper instruction counter for the service Accumulate entry.
pub const ACCUMULATE_ENTRY_IC: u32 = 5;

/// Owning HANDLE through which the generic service enters the target actor VM.
/// This is a JAR capability-table slot supplied at invocation setup, not a JAM
/// protocol capability or hostcall number.
pub const TARGET_ACTOR_HANDLE_SLOT: u8 = 80;

/// Move-only DATA capability used for service↔actor slice input/output.
pub const ACTOR_IPC_CAP_SLOT: u8 = 90;
/// Temporary actor-CNode slot used while CALL owns the reserved IPC slot 0.
pub const ACTOR_SAVED_ARGS_CAP_SLOT: u8 = 253;
/// High virtual page kept outside transpiler-owned actor memory layouts.
pub const ACTOR_IPC_BASE_PAGE: u32 = 0x000f_0000;
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
pub const JAR_REVISION: &str = "0423af155f02457bec46f068cb82f1c7a15611c7";

/// Consensus-visible execution semantics. Changing interpreter/recompiler or
/// trace behavior requires a new identifier even if the public Rust API did
/// not change.
pub const EXECUTION_SEMANTICS_ID: Hash = Hash(*b"vos-jar-v2-0423af1-semantics-v2\0");
