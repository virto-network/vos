//! VOS runtime v2: JAM-aligned service contracts.
//!
//! A root actor tree is owned by one logical JAM service. The service has one
//! physical entry point; `phi[7]` selects the logical function. Refine receives
//! every input explicitly and returns a deterministic [`TransitionV2`]. Only
//! Accumulate may mutate service state or publish effects.
//!
//! This is a clean boundary. None of the types in this module accept legacy
//! `RefinePayload`, `EffectLog`, or continuation encodings.

mod accumulate;
mod continuation;
mod contracts;
mod identity;
mod package;
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
    AccumulationReceiptV2, ActorWriteV2, AuthorizationEvidenceV2, BlobRefV2, ConsistencyBaseV2,
    ConsistencyModeV2, ContinuationChangeV2, CrdtOperationV2, GasAccountingV2, ImportedActorV2,
    MessageRecordV2, ProofCommitmentV2, Refine, RefineError, ReplyRecordV2, ServiceIdentityV2,
    TransitionV2, WorkEnvelopeV2,
};
pub use identity::{
    ActorId, CallId, DeploymentId, Hash, InvocationId, OperationId, Origin, ProducerId, ProgramId,
    RootServiceId, SpaceId, SubjectId, SystemCapabilityId,
};
pub use package::{
    DeploymentSignatureV2, PackageDiagnosticsV2, PackageError, PackageManifestV2, VosPackageV2,
    artifact_hash,
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

/// The two logical functions exposed through the service PVM's physical PC-0
/// entry point. JAM supplies the selector in `phi[7]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ServiceFunction {
    Refine = 0,
    Accumulate = 1,
}

impl ServiceFunction {
    pub const fn from_phi7(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Refine),
            1 => Some(Self::Accumulate),
            _ => None,
        }
    }
}

/// Revision shared by JAVM, the transpiler, proof tracer, verifier, and fuzz
/// targets. `just check-jar-revisions` verifies that every manifest uses it.
pub const JAR_REVISION: &str = "ba1276acffa3e84f33cb90491e389280fd070a48";

/// Consensus-visible execution semantics. Changing interpreter/recompiler or
/// trace behavior requires a new identifier even if the public Rust API did
/// not change.
pub const EXECUTION_SEMANTICS_ID: Hash = Hash([
    0x76, 0x6f, 0x73, 0x2d, 0x6a, 0x61, 0x72, 0x2d, 0x76, 0x32, 0x2d, 0x62, 0x61, 0x31, 0x32, 0x37,
    0x36, 0x61, 0x2d, 0x73, 0x65, 0x6d, 0x61, 0x6e, 0x74, 0x69, 0x63, 0x73, 0x00, 0x00, 0x00, 0x01,
]);
