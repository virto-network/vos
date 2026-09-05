use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::authority::AuthorityReceipt;
use crate::contract::RuntimePackageContract;
use crate::{
    ActorDirectoryPage, ActorEntry, ActorId, ActorLifecycleDebt, AgentDescriptor, AgentIdentity,
    AgentReplica, BlobRef, CallId, CapabilityId, CredentialId, DeploymentId, Hash, InstallActor,
    InvocationId, MethodMode, NodeId, PrincipalId, ProducerId, ProgramId, RuntimeCapabilities,
    SpaceId, StateLane, UpgradeActor,
};

pub const MAX_INVOCATION_MESSAGE_BYTES: usize = 8 * 1024;
pub const MAX_INVOCATION_REPLY_BYTES: usize = 8 * 1024;
pub const MAX_RESUME_INPUT_BYTES: usize = 8 * 1024;
pub const MAX_RUNTIME_AVAILABILITY_ITEMS: usize = 16;
pub const MAX_RUNTIME_AVAILABILITY_BYTES: usize = 64 * 1024;
pub const MAX_AFTER_COMMIT_MERGE_MESSAGES: usize = 256;

/// Runtime-owned durable state split only at replication boundaries. Hosts
/// persist/order components but never interpret their bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeState {
    pub control: Vec<u8>,
    pub linear: Vec<u8>,
    pub merge: Vec<u8>,
    pub local: Vec<u8>,
}

impl RuntimeState {
    pub fn is_empty(&self) -> bool {
        self.control.is_empty()
            && self.linear.is_empty()
            && self.merge.is_empty()
            && self.local.is_empty()
    }

    pub fn component(&self, lane: StateLane) -> &[u8] {
        match lane {
            StateLane::Linear => &self.linear,
            StateLane::Merge => &self.merge,
            StateLane::Local => &self.local,
        }
    }

    pub fn encoded_len(&self) -> Option<usize> {
        self.control
            .len()
            .checked_add(self.linear.len())?
            .checked_add(self.merge.len())?
            .checked_add(self.local.len())
    }

    pub fn validate(&self) -> bool {
        self.encoded_len()
            .is_some_and(|length| length <= crate::MAX_RUNTIME_STATE_BYTES)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBlob {
    pub reference: BlobRef,
    pub bytes: Vec<u8>,
}

impl RuntimeBlob {
    pub fn validate(&self) -> bool {
        self.bytes.len() <= MAX_RUNTIME_AVAILABILITY_BYTES && self.reference.matches(&self.bytes)
    }
}

/// Explicit authenticated caller identities. Principals, transport nodes, and
/// credentials are non-interchangeable; actor provenance is independent of
/// all three.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InvocationOrigin {
    pub principal: Option<PrincipalId>,
    pub transport_node: Option<NodeId>,
    pub credential: Option<CredentialId>,
    pub actor: Option<ActorId>,
    pub capability: Option<CapabilityId>,
}

impl InvocationOrigin {
    pub const fn anonymous() -> Self {
        Self {
            principal: None,
            transport_node: None,
            credential: None,
            actor: None,
            capability: None,
        }
    }

    pub fn validate(&self) -> bool {
        if self.principal == Some(PrincipalId::ZERO)
            || self.transport_node == Some(NodeId::ZERO)
            || self.credential == Some(CredentialId::ZERO)
            || self.actor == Some(ActorId::ZERO)
            || self.capability == Some(CapabilityId::ZERO)
        {
            return false;
        }
        // A credential authenticates a principal; it is never itself an
        // actor origin or a replica identity.
        self.credential.is_none() || self.principal.is_some()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationWork {
    pub space: SpaceId,
    pub agent: crate::AgentId,
    pub runtime_deployment: DeploymentId,
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub mode: MethodMode,
    pub origin: InvocationOrigin,
    pub message: Vec<u8>,
    pub availability: Vec<RuntimeBlob>,
    pub gas: u64,
    /// Exact-result recovery may read an existing disposition but cannot run
    /// unseen application work.
    pub recovery_only: bool,
}

impl InvocationWork {
    pub fn validate(&self) -> bool {
        self.space != SpaceId::ZERO
            && self.agent != crate::AgentId::ZERO
            && self.runtime_deployment != DeploymentId::ZERO
            && self.invocation != InvocationId::ZERO
            && self.actor != ActorId::ZERO
            && self.incarnation != Hash::ZERO
            && self.deployment != DeploymentId::ZERO
            && self.program != ProgramId::ZERO
            && self.origin.validate()
            && self.message.len() <= MAX_INVOCATION_MESSAGE_BYTES
            && self.availability.len() <= MAX_RUNTIME_AVAILABILITY_ITEMS
            && self.availability.iter().all(RuntimeBlob::validate)
            && self
                .availability
                .windows(2)
                .all(|pair| pair[0].reference < pair[1].reference)
            && self
                .availability
                .iter()
                .try_fold(0usize, |total, blob| total.checked_add(blob.bytes.len()))
                .is_some_and(|total| total <= MAX_RUNTIME_AVAILABILITY_BYTES)
            && self.gas != 0
    }

    /// Commitment matched by an Invoke authority selector.
    pub fn commitment(&self) -> Hash {
        crate::wire::invocation_work_commitment(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManagementRequest {
    Create(Box<AgentDescriptor>),
    InspectActors {
        after: Option<ActorId>,
        limit: u16,
    },
    InspectResources,
    Install(Box<InstallActor>),
    UpgradeActor(Box<UpgradeActor>),
    Suspend {
        actor: ActorId,
        expected_deployment: DeploymentId,
    },
    Resume {
        actor: ActorId,
        expected_deployment: DeploymentId,
    },
    RemoveLeaf {
        actor: ActorId,
        expected_deployment: DeploymentId,
    },
    UpgradeRuntime(Box<RuntimeUpgrade>),
    ChangeReplicas {
        expected_generation: Hash,
        replicas: Vec<AgentReplica>,
    },
}

impl ManagementRequest {
    /// Commitment matched by a management authority selector.
    pub fn commitment(&self) -> Hash {
        crate::wire::management_request_commitment(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeUpgrade {
    pub from_deployment: DeploymentId,
    pub to_deployment: DeploymentId,
    pub to_program: ProgramId,
    pub producer: ProducerId,
    pub package: BlobRef,
    pub contract: RuntimePackageContract,
    pub capabilities: RuntimeCapabilities,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuntimeResourceUsage {
    pub actors: u32,
    pub active_machines: u8,
    pub continuations: u32,
    pub inbox: u32,
    pub outbox: u32,
    pub schedules: u32,
    pub proof_artifacts: u32,
    pub state_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManagementReply {
    Created(AgentIdentity),
    Actors(ActorDirectoryPage),
    Resources(RuntimeResourceUsage),
    Installed(ActorEntry),
    Upgraded(ActorEntry),
    Suspended(ActorEntry),
    Resumed(ActorEntry),
    Removed(ActorId),
    RuntimeUpgraded(AgentIdentity),
    ReplicasChanged { generation: Hash },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementError {
    NotCreated,
    AlreadyCreated,
    NotFound,
    AlreadyExists,
    StaleDeployment,
    UnsupportedRuntime,
    UnsupportedLane,
    Busy(ActorLifecycleDebt),
    DirectoryFull,
    InvalidRequest,
    AuthoritySequenceRegressed,
    AuthoritySequenceConflict,
    AuthoritySlotRegressed,
    ResourceLimit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeWork {
    Manage {
        space: SpaceId,
        agent: crate::AgentId,
        runtime_deployment: DeploymentId,
        state: RuntimeState,
        request: Box<ManagementRequest>,
        authority: Option<Box<AuthorityReceipt>>,
        observed_slot: u64,
    },
    Invoke {
        state: RuntimeState,
        invocation: Box<InvocationWork>,
        authority: Box<AuthorityReceipt>,
        observed_slot: u64,
    },
    Resume {
        state: RuntimeState,
        resume: Box<ResumeWork>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YieldReason {
    Cooperative,
    Await { call: CallId },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResumeInput {
    Ready(Vec<u8>),
    Failed(u32),
}

impl ResumeInput {
    pub fn validate(&self) -> bool {
        match self {
            Self::Ready(bytes) => bytes.len() <= MAX_RESUME_INPUT_BYTES,
            Self::Failed(code) => *code != 0,
        }
    }
}

/// Exact tuple required to resume the FIFO head. The referenced opaque
/// continuation snapshot additionally binds the invocation commitment and
/// actor state generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeWork {
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub mode: MethodMode,
    pub continuation: BlobRef,
    pub ready_sequence: u64,
    pub input: Option<ResumeInput>,
}

impl ResumeWork {
    pub fn validate(&self) -> bool {
        valid_continuation_identity(
            self.invocation,
            self.actor,
            self.incarnation,
            self.deployment,
            self.program,
            &self.continuation,
        ) && self.input.as_ref().is_none_or(ResumeInput::validate)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InvocationObservation {
    pub linear_revision: Option<u64>,
    pub merge_frontier: Option<Hash>,
    pub local_revision: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InvocationStatus {
    Done = 0,
    Forbidden = 1,
    Panicked = 2,
    OutOfGas = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationReply {
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub mode: MethodMode,
    pub lane: Option<StateLane>,
    pub status: InvocationStatus,
    pub reply: Vec<u8>,
    pub gas_remaining: u64,
    pub observation: InvocationObservation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationError {
    NotCreated,
    NotFound,
    StaleIncarnation,
    Suspended,
    StaleDeployment,
    WrongProgram,
    UnsupportedMethod,
    UnsupportedResultStorage,
    MissingState,
    InvalidAvailability,
    InvalidInput,
    InvalidActorOutput,
    DivergentInvocation,
    ResultCapacity,
    InvalidAuthorization,
    AuthorityExpired,
    AuthoritySlotRegressed,
    UnsupportedHostCall(u64),
    StaleContinuation,
    NotReady,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YieldedInvocation {
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub mode: MethodMode,
    pub continuation: BlobRef,
    pub ready_sequence: u64,
    pub reason: YieldReason,
}

impl YieldedInvocation {
    pub fn validate(&self) -> bool {
        valid_continuation_identity(
            self.invocation,
            self.actor,
            self.incarnation,
            self.deployment,
            self.program,
            &self.continuation,
        ) && match self.reason {
            YieldReason::Cooperative => true,
            YieldReason::Await { call } => call != CallId::ZERO,
        }
    }
}

fn valid_continuation_identity(
    invocation: InvocationId,
    actor: ActorId,
    incarnation: Hash,
    deployment: DeploymentId,
    program: ProgramId,
    continuation: &BlobRef,
) -> bool {
    invocation != InvocationId::ZERO
        && actor != ActorId::ZERO
        && incarnation != Hash::ZERO
        && deployment != DeploymentId::ZERO
        && program != ProgramId::ZERO
        && continuation.hash != Hash::ZERO
        && continuation.len != 0
        && continuation.len <= crate::MAX_RUNTIME_STATE_BYTES as u64
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeOutcome {
    Management(Result<ManagementReply, ManagementError>),
    Completed(Result<InvocationReply, InvocationError>),
    Yielded(YieldedInvocation),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeTransition {
    pub state: RuntimeState,
    pub outcome: RuntimeOutcome,
}

impl RuntimeTransition {
    pub fn validate(&self) -> bool {
        self.state.validate()
            && match &self.outcome {
                RuntimeOutcome::Management(Ok(ManagementReply::Actors(page))) => {
                    page.validate().is_ok()
                }
                RuntimeOutcome::Completed(Ok(reply)) => {
                    reply.invocation != InvocationId::ZERO
                        && reply.actor != ActorId::ZERO
                        && reply.incarnation != Hash::ZERO
                        && reply.deployment != DeploymentId::ZERO
                        && reply.reply.len() <= MAX_INVOCATION_REPLY_BYTES
                        && reply.observation.merge_frontier != Some(Hash::ZERO)
                }
                RuntimeOutcome::Yielded(yielded) => yielded.validate(),
                _ => true,
            }
    }
}

/// Host-independent contract implemented by every custom AgentRuntime.
pub trait AgentRuntime {
    fn capabilities(&self) -> RuntimeCapabilities;
    fn apply(&mut self, work: RuntimeWork) -> RuntimeTransition;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuation_tuple_rejects_zero_or_oversized_references() {
        let mut resume = ResumeWork {
            invocation: InvocationId([1; 32]),
            actor: ActorId([2; 32]),
            incarnation: Hash([3; 32]),
            deployment: DeploymentId([4; 32]),
            program: ProgramId([5; 32]),
            mode: MethodMode::Linear,
            continuation: BlobRef {
                hash: Hash([6; 32]),
                len: 128,
            },
            ready_sequence: 7,
            input: None,
        };
        assert!(resume.validate());
        resume.continuation.len = crate::MAX_RUNTIME_STATE_BYTES as u64 + 1;
        assert!(!resume.validate());
    }

    #[test]
    fn credentials_never_stand_in_for_principals() {
        let origin = InvocationOrigin {
            credential: Some(CredentialId([1; 32])),
            ..InvocationOrigin::anonymous()
        };
        assert!(!origin.validate());
    }

    #[test]
    fn invocation_availability_is_a_strictly_sorted_content_map() {
        let blob = |bytes: &[u8]| RuntimeBlob {
            reference: BlobRef::of_bytes(bytes),
            bytes: bytes.to_vec(),
        };
        let mut availability = alloc::vec![blob(b"first"), blob(b"second")];
        availability.sort_by(|left, right| left.reference.cmp(&right.reference));
        let mut invocation = InvocationWork {
            space: SpaceId([1; 32]),
            agent: crate::AgentId([2; 32]),
            runtime_deployment: DeploymentId([3; 32]),
            invocation: InvocationId([4; 32]),
            actor: ActorId([5; 32]),
            incarnation: Hash([6; 32]),
            deployment: DeploymentId([7; 32]),
            program: ProgramId([8; 32]),
            mode: MethodMode::Linear,
            origin: InvocationOrigin::anonymous(),
            message: alloc::vec![],
            availability,
            gas: 1,
            recovery_only: false,
        };

        assert!(invocation.validate());
        invocation.availability.swap(0, 1);
        assert!(!invocation.validate());
        invocation.availability[1] = invocation.availability[0].clone();
        assert!(!invocation.validate());
    }
}
