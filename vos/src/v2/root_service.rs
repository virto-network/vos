//! Durable local ownership of one v2 root actor tree.
//!
//! This is host orchestration, not an alternate actor runtime. Installation,
//! transition validation, state mutation, deduplication, and publication
//! acknowledgement all enter the canonical generic service at physical IC-5.
//! The host prepares Refine imports from committed guest state and persists
//! the resulting complete service image at the configured atomic boundary.

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use crate::attestation::AttestationProofProducerV2;

use super::wire::{DecodeError, Decoder, Encoder};
use super::{
    AccumulateRequestV2, AccumulatedServiceOutputV2, AccumulationEnvelopeV2, AccumulationReceiptV2,
    AccumulationRejectionV2, AccumulationResultV2, AccumulatedReplyV2, AccumulatedTimeoutV2,
    ActorDirectoryV2, ActorGenesisV2, ActorId, ActorUpgradeV2, AttestationDeliveryV2,
    AttestedServiceErrorV2, AuthorizationEvidenceV2, BlobRefV2, CommittedAttestationOutputV2,
    CommittedAttestationPackageV2, CommittedImageStoreV2, ConsistencyModeV2,
    ConsistencyBaseV2, ContinuationSnapshotV2, CrdtSyncEnvelopeV2, DirectIngressV2,
    DurableJamStoreV2, DurableStoreOpenErrorV2, ExternalActorBindingV2,
    ExternalActorDirectoryV2, ImportedBlobV2, JamServiceV2, LocalJamStoreV2,
    LocalStoreReadErrorV2, LocalWorkRequestV2, LocalWorkSchedulerV2, MessageRecordV2,
    MethodPolicyV2, NoRefineProtocolHostV2, PackageError, PackageRolePoliciesV2, PreparedWorkV2,
    ProgramId, PublicationAckV2, PublicationRecordV2, PublishedEffectsV2,
    ReceiptVerificationRequestV2, RefinedServiceOutputV2, ScheduleErrorV2, ServiceDispatchError,
    ServiceGenesisV2, ServiceIdentityV2, StateKeyV2, StoreHeaderV2, V2Wire, VosPackageV2,
    WorkInputIdV2, WorkflowCheckpointV2,
};

#[cfg(feature = "storage")]
use super::{ReplicatedJamServiceV2, ReplicatedServiceErrorV2};
#[cfg(feature = "storage")]
use crate::commit::CommitError;
#[cfg(feature = "storage")]
use crate::raft::RaftAccumulateLogV2;

/// Strict host/network ingress for one direct root-tree invocation. Origin and
/// authorization are deliberately absent: the receiving host derives them
/// from its authenticated transport and grant state before scheduling work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootTreeInvocationV2 {
    pub invocation: super::InvocationId,
    pub logical_timeslot: u64,
    pub target: ActorId,
    pub method: String,
    pub arguments: Vec<u8>,
    pub proof_requested: bool,
}

impl V2Wire for RootTreeInvocationV2 {
    const MAGIC: [u8; 4] = *b"VRI2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.fixed(&self.invocation.0);
        encoder.u64(self.logical_timeslot);
        encoder.fixed(&self.target.0);
        encoder.string(&self.method);
        encoder.bytes(&self.arguments);
        encoder.bool(self.proof_requested);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            invocation: super::InvocationId(decoder.fixed()?),
            logical_timeslot: decoder.u64()?,
            target: ActorId(decoder.fixed()?),
            method: decoder.string()?,
            arguments: decoder.bytes()?,
            proof_requested: decoder.bool()?,
        };
        if value.invocation == super::InvocationId::ZERO
            || value.target == ActorId::ZERO
            || value.method.is_empty()
            || value.arguments.is_empty()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

/// Node-to-node/root transport carrying only effects already committed by a
/// source service guest. The destination still enters physical Accumulate;
/// this wire is not permission to mutate a destination store natively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootTreeTransportV2 {
    OutboxDelivery {
        logical_timeslot: u64,
        publication: PublicationRecordV2,
        message: MessageRecordV2,
    },
    Reply {
        logical_timeslot: u64,
        caller_invocation: super::InvocationId,
        publication: PublicationRecordV2,
        attestation: Option<CommittedAttestationPackageV2>,
    },
    PublicationAccepted {
        input: WorkInputIdV2,
        publication: super::Hash,
        call: super::CallId,
    },
}

impl V2Wire for RootTreeTransportV2 {
    const MAGIC: [u8; 4] = *b"VRT2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        match self {
            Self::OutboxDelivery {
                logical_timeslot,
                publication,
                message,
            } => {
                encoder.u8(0);
                encoder.u64(*logical_timeslot);
                encoder.bytes(&publication.encode());
                encoder.bytes(&message.encode());
            }
            Self::Reply {
                logical_timeslot,
                caller_invocation,
                publication,
                attestation,
            } => {
                encoder.u8(1);
                encoder.u64(*logical_timeslot);
                encoder.fixed(&caller_invocation.0);
                encoder.bytes(&publication.encode());
                encoder.option(attestation, |encoder, package| {
                    encoder.bytes(&package.encode());
                });
            }
            Self::PublicationAccepted {
                input,
                publication,
                call,
            } => {
                encoder.u8(2);
                encoder.fixed(&input.invocation.0);
                encoder.u64(input.workflow_step);
                encoder.fixed(&publication.0);
                encoder.fixed(&call.0);
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = match decoder.u8()? {
            0 => Self::OutboxDelivery {
                logical_timeslot: decoder.u64()?,
                publication: PublicationRecordV2::decode(&decoder.bytes()?)?,
                message: MessageRecordV2::decode(&decoder.bytes()?)?,
            },
            1 => Self::Reply {
                logical_timeslot: decoder.u64()?,
                caller_invocation: super::InvocationId(decoder.fixed()?),
                publication: PublicationRecordV2::decode(&decoder.bytes()?)?,
                attestation: decoder.option(|decoder| {
                    CommittedAttestationPackageV2::decode(&decoder.bytes()?)
                })?,
            },
            2 => Self::PublicationAccepted {
                input: WorkInputIdV2 {
                    invocation: super::InvocationId(decoder.fixed()?),
                    workflow_step: decoder.u64()?,
                },
                publication: super::Hash(decoder.fixed()?),
                call: super::CallId(decoder.fixed()?),
            },
            _ => return Err(DecodeError::InvalidTag),
        };
        if !value.is_canonical() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl RootTreeTransportV2 {
    fn is_canonical(&self) -> bool {
        match self {
            Self::OutboxDelivery {
                publication,
                message,
                ..
            } => {
                publication.published.reply.is_none()
                    && publication.published.proof.is_none()
                    && publication
                        .published
                        .outbox
                        .binary_search_by_key(&message.call_id, |candidate| candidate.call_id)
                        .is_ok()
            }
            Self::Reply {
                caller_invocation,
                publication,
                attestation,
                ..
            } => {
                *caller_invocation != super::InvocationId::ZERO
                    && publication.published.outbox.is_empty()
                    && publication.published.exported_blobs.is_empty()
                    && match (
                        publication.published.reply.as_ref(),
                        publication.published.statement.as_ref(),
                        publication.published.proof.as_ref(),
                        attestation.as_ref(),
                    ) {
                        (Some(_), None, None, None) => true,
                        (Some(reply), Some(statement), Some(proof), Some(package)) => {
                            package.validate().is_ok()
                                && package.reply.reply == *reply
                                && package.reply.receipt == publication.receipt
                                && package
                                    .reply
                                    .attestation
                                    .as_ref()
                                    .is_some_and(|delivery| {
                                        delivery.statement == *statement
                                            && delivery.proof == *proof
                                    })
                        }
                        _ => false,
                    }
            }
            Self::PublicationAccepted {
                input,
                publication,
                call,
            } => {
                input.invocation != super::InvocationId::ZERO
                    && *publication != super::Hash::ZERO
                    && *call != super::CallId::ZERO
            }
        }
    }
}

fn return_target_from_checkpoint(
    checkpoint: &WorkflowCheckpointV2,
    publication: &PublicationRecordV2,
) -> Result<Option<(ActorId, super::InvocationId)>, LocalRootTreeInvokeErrorV2> {
    let Some(reply) = publication.published.reply.as_ref() else {
        return Ok(None);
    };
    let work = &checkpoint.resume_work;
    if checkpoint.input != publication.input || work.invocation != publication.input.invocation {
        return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
    }
    let Some(parent_call) = work.parent_call else {
        return if reply.call_id == work.invocation.root_reply_id() {
            Ok(None)
        } else {
            Err(LocalRootTreeInvokeErrorV2::DivergentReplay)
        };
    };
    if parent_call != reply.call_id
        || super::InvocationId::for_call(reply.call_id) != work.invocation
    {
        return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
    }
    match (work.origin, work.causal_parent) {
        (super::Origin::Actor(actor), Some(invocation)) => Ok(Some((actor, invocation))),
        _ => Ok(None),
    }
}

fn direct_ingress_matches_checkpoint(
    request: &LocalWorkRequestV2,
    checkpoint: &WorkflowCheckpointV2,
) -> bool {
    let work = &checkpoint.resume_work;
    checkpoint.input.invocation == request.invocation
        && work.invocation == request.invocation
        && request.workflow_step == 0
        && request.causal_parent.is_none()
        && request.parent_call.is_none()
        && request.awaited_reply.is_none()
        && request.awaited_timeout.is_none()
        && work.target == request.target
        && work.method == request.method
        && work.arguments == request.arguments
        && work.origin == request.origin
        && work.authorization == request.authorization
        && work.causal_parent == request.causal_parent
        && work.parent_call == request.parent_call
        && work.imported_blobs == request.imported_blobs
        && work.proof_requested == request.proof_requested
}

fn direct_ingress_from_request(
    store: &LocalJamStoreV2,
    service: &ServiceIdentityV2,
    request: &LocalWorkRequestV2,
) -> Result<DirectIngressV2, LocalRootTreeInvokeErrorV2> {
    if request.workflow_step != 0
        || request.causal_parent.is_some()
        || request.parent_call.is_some()
        || request.awaited_reply.is_some()
        || request.awaited_timeout.is_some()
    {
        return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
    }
    LocalWorkSchedulerV2::prepare_direct_ingress(store, service, request)
        .map_err(LocalRootTreeInvokeErrorV2::Schedule)
}

fn request_from_direct_ingress(ingress: DirectIngressV2) -> LocalWorkRequestV2 {
    LocalWorkRequestV2 {
        invocation: ingress.invocation,
        workflow_step: 0,
        logical_timeslot: ingress.logical_timeslot,
        target: ingress.target,
        method: ingress.method,
        arguments: ingress.arguments,
        origin: ingress.origin,
        authorization: ingress.authorization,
        causal_parent: None,
        parent_call: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: ingress.imported_blobs,
        proof_requested: ingress.proof_requested,
    }
}

/// One owned descendant installed with a locally hosted root tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedActorInstallV2 {
    /// Stable actor identity allocated by the deployment controller.
    pub actor: ActorId,
    /// Stable name within `parent`'s owned namespace.
    pub name: String,
    /// Existing root-tree member which owns this actor.
    pub parent: ActorId,
    /// Canonical initial state bytes committed by guest Accumulate.
    pub initial_state: Vec<u8>,
}

/// Complete immutable installation input for one locally hosted root tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRootTreeConfigV2 {
    pub service_pvm: Vec<u8>,
    pub package: VosPackageV2,
    pub service: ServiceIdentityV2,
    pub root_actor: ActorId,
    pub actor_name: String,
    pub consistency: ConsistencyModeV2,
    pub initial_state: Vec<u8>,
    /// Owned descendants installed atomically with the root. Every member
    /// executes the package's one canonical actor PVM; actor IDs and initial
    /// state are instance data and therefore do not alter `DeploymentId`.
    pub owned_actors: Vec<OwnedActorInstallV2>,
    pub external_actors: Vec<ExternalActorBindingV2>,
    pub install_authorization: AuthorizationEvidenceV2,
    pub refine_gas: u64,
    pub accumulate_gas: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRootTreeConfigErrorV2 {
    InvalidPackage(PackageError),
    EmptyActorName,
    WrongDeployment,
    WrongServiceProgram,
    WrongServiceAbi,
    WrongExecutionSemantics,
    InvalidConsistency,
    InvalidOwnedActorTree,
    TooManyOwnedActors,
    ReplicationDriverRequired,
    ZeroGas,
}

#[derive(Debug)]
pub enum LocalRootTreeOpenErrorV2<E> {
    InvalidConfig(LocalRootTreeConfigErrorV2),
    Store(DurableStoreOpenErrorV2<E>),
    CorruptStore(LocalStoreReadErrorV2),
    Service(ServiceDispatchError),
    #[cfg(feature = "storage")]
    Replication(ReplicatedServiceErrorV2<CommitError>),
    InstallRejected(AccumulationRejectionV2),
    UnexpectedInstallResult,
    ExistingServiceMismatch,
    ExistingActorMismatch,
    MissingInstalledProgram(ProgramId),
}

#[derive(Debug)]
pub enum LocalRootTreeInvokeErrorV2 {
    ProofProducerRequired,
    ProofModeMismatch,
    AttestationPreparationFailed,
    ProofProductionFailed,
    InvalidProducedProof,
    ProofUnavailable,
    AttestationCommitMismatch,
    InvalidAttestationPublication,
    Schedule(ScheduleErrorV2),
    Service(ServiceDispatchError),
    #[cfg(feature = "storage")]
    Replication(ReplicatedServiceErrorV2<CommitError>),
    Rejected(AccumulationRejectionV2),
    UnexpectedResult,
    CorruptStore(LocalStoreReadErrorV2),
    MissingPublication,
    DivergentReplay,
    ServiceNotInstalled,
    ExistingServiceMismatch,
    ExistingActorMismatch,
    MissingInstalledProgram(ProgramId),
    InvalidUpgradePackage(PackageError),
    UpgradePackageMismatch,
}

/// Result made visible only after physical Accumulate committed the durable
/// service image. Non-empty effects remain in a recoverable publication row
/// until the consumer acknowledges its exact commitment through IC-5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedRootTreeSliceV2 {
    pub input: WorkInputIdV2,
    pub receipt: AccumulationReceiptV2,
    pub published: PublishedEffectsV2,
    pub publication: Option<PublicationRecordV2>,
    pub duplicate: bool,
    pub refine_gas_used: u64,
    pub accumulate_gas_used: u64,
}

/// Destination-side result of admitting one finalized cross-root message.
/// The inbox is visible only after physical Accumulate commits this receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedDeliveryV2 {
    pub receipt: AccumulationReceiptV2,
    pub duplicate: bool,
    pub accumulate_gas_used: u64,
}

/// Guest-committed deterministic timeout for one suspended outbound call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedCallExpirationV2 {
    pub invocation: super::InvocationId,
    pub timeout: AccumulatedTimeoutV2,
    pub duplicate: bool,
    pub accumulate_gas_used: u64,
}

/// Result of importing an authenticated causal delta through physical IC-5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedCrdtSyncV2 {
    pub receipt: AccumulationReceiptV2,
    pub duplicate: bool,
    pub accumulate_gas_used: u64,
}

/// Exact actor-program replacement made visible only after guest Accumulate
/// commits its descriptor, policy, receipt, revision, and deduplication row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedActorUpgradeV2 {
    pub actor: ActorId,
    pub previous_program: ProgramId,
    pub program: ProgramId,
    pub receipt: AccumulationReceiptV2,
    pub duplicate: bool,
    pub accumulate_gas_used: u64,
}

/// Durable disposition of a retried direct root invocation.
///
/// The caller may attach to `Suspended` without executing slice zero again.
/// A pending publication is returned with the timeslot committed by its
/// actual slice, which can be later than the retried ingress timeslot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootTreeIngressRecoveryV2 {
    Fresh,
    Queued {
        logical_timeslot: u64,
    },
    Suspended,
    PendingPublication {
        publication: PublicationRecordV2,
        logical_timeslot: u64,
    },
    /// The invocation finished and its externally accepted publication has
    /// already been acknowledged. Its actor execution must not be replayed.
    Completed {
        reply: super::ReplyRecordV2,
    },
    /// A proof-bearing completed invocation retains its guest-owned physical
    /// publication archive so an exact retry returns the identical package.
    CompletedAttested {
        publication: PublicationRecordV2,
    },
}

/// A durable local host for exactly one logical JAM service/root actor tree.
enum RootTreeServiceDriverV2<B> {
    Direct(JamServiceV2<NoRefineProtocolHostV2, DurableJamStoreV2<B>>),
    #[cfg(feature = "storage")]
    Raft(ReplicatedJamServiceV2<NoRefineProtocolHostV2, DurableJamStoreV2<B>, RaftAccumulateLogV2>),
}

enum RootTreeDriverConfigV2 {
    Direct,
    #[cfg(feature = "storage")]
    Raft(RaftAccumulateLogV2),
}

enum RootTreeDriverErrorV2 {
    Direct(ServiceDispatchError),
    #[cfg(feature = "storage")]
    Raft(ReplicatedServiceErrorV2<CommitError>),
}

impl RootTreeDriverErrorV2 {
    fn into_invoke(self) -> LocalRootTreeInvokeErrorV2 {
        match self {
            Self::Direct(error) => LocalRootTreeInvokeErrorV2::Service(error),
            #[cfg(feature = "storage")]
            Self::Raft(error) => LocalRootTreeInvokeErrorV2::Replication(error),
        }
    }
}

impl<B: CommittedImageStoreV2> RootTreeServiceDriverV2<B> {
    fn accumulate_host(&self) -> &DurableJamStoreV2<B> {
        match self {
            Self::Direct(service) => service.accumulate_host(),
            #[cfg(feature = "storage")]
            Self::Raft(service) => service.service().accumulate_host(),
        }
    }

    fn accumulate_host_mut(&mut self) -> &mut DurableJamStoreV2<B> {
        match self {
            Self::Direct(service) => service.accumulate_host_mut(),
            #[cfg(feature = "storage")]
            Self::Raft(service) => service.service_mut().accumulate_host_mut(),
        }
    }

    fn catch_up(&mut self) -> Result<(), RootTreeDriverErrorV2> {
        match self {
            Self::Direct(_) => Ok(()),
            #[cfg(feature = "storage")]
            Self::Raft(service) => service
                .catch_up()
                .map(|_| ())
                .map_err(RootTreeDriverErrorV2::Raft),
        }
    }

    fn is_writable(&self) -> bool {
        match self {
            Self::Direct(_) => true,
            #[cfg(feature = "storage")]
            Self::Raft(service) => service.log().is_writable(),
        }
    }

    fn refine_actor_tree(
        &mut self,
        work: &super::WorkEnvelopeV2,
        imports: &super::RefineImportsV2,
    ) -> Result<RefinedServiceOutputV2, RootTreeDriverErrorV2> {
        match self {
            Self::Direct(service) => service
                .refine_actor_tree(work, imports)
                .map_err(RootTreeDriverErrorV2::Direct),
            #[cfg(feature = "storage")]
            Self::Raft(service) => service
                .refine_actor_tree(work, imports)
                .map_err(RootTreeDriverErrorV2::Raft),
        }
    }

    fn accumulate(
        &mut self,
        request: &AccumulateRequestV2,
    ) -> Result<AccumulatedServiceOutputV2, RootTreeDriverErrorV2> {
        match self {
            Self::Direct(service) => service
                .accumulate(request)
                .map_err(RootTreeDriverErrorV2::Direct),
            #[cfg(feature = "storage")]
            Self::Raft(service) => service
                .accumulate(request)
                .map_err(RootTreeDriverErrorV2::Raft),
        }
    }

    fn accumulate_attested<P: AttestationProofProducerV2>(
        &mut self,
        envelope: AccumulationEnvelopeV2,
        imports: &super::RefineImportsV2,
        producer: &mut P,
    ) -> Result<CommittedAttestationOutputV2, LocalRootTreeInvokeErrorV2> {
        match self {
            Self::Direct(service) => service
                .accumulate_attested(envelope, imports, producer)
                .map_err(map_direct_attested_error),
            #[cfg(feature = "storage")]
            Self::Raft(service) => service
                .accumulate_attested(envelope, imports, producer)
                .map_err(map_raft_attested_error),
        }
    }

    fn into_store(self) -> DurableJamStoreV2<B> {
        match self {
            Self::Direct(service) => service.into_hosts().1,
            #[cfg(feature = "storage")]
            Self::Raft(service) => service.into_parts().0.into_hosts().1,
        }
    }
}

fn map_direct_attested_error<P>(
    error: AttestedServiceErrorV2<ServiceDispatchError, P>,
) -> LocalRootTreeInvokeErrorV2 {
    match error {
        AttestedServiceErrorV2::Service(error) => LocalRootTreeInvokeErrorV2::Service(error),
        AttestedServiceErrorV2::Rejected(error) => LocalRootTreeInvokeErrorV2::Rejected(error),
        AttestedServiceErrorV2::InvalidPreparation => {
            LocalRootTreeInvokeErrorV2::AttestationPreparationFailed
        }
        AttestedServiceErrorV2::Producer(_) => {
            LocalRootTreeInvokeErrorV2::ProofProductionFailed
        }
        AttestedServiceErrorV2::InvalidProducedProof => {
            LocalRootTreeInvokeErrorV2::InvalidProducedProof
        }
        AttestedServiceErrorV2::ProofUnavailable => {
            LocalRootTreeInvokeErrorV2::ProofUnavailable
        }
        AttestedServiceErrorV2::CommitMismatch => {
            LocalRootTreeInvokeErrorV2::AttestationCommitMismatch
        }
    }
}

#[cfg(feature = "storage")]
fn map_raft_attested_error<P>(
    error: AttestedServiceErrorV2<ReplicatedServiceErrorV2<CommitError>, P>,
) -> LocalRootTreeInvokeErrorV2 {
    match error {
        AttestedServiceErrorV2::Service(error) => LocalRootTreeInvokeErrorV2::Replication(error),
        AttestedServiceErrorV2::Rejected(error) => LocalRootTreeInvokeErrorV2::Rejected(error),
        AttestedServiceErrorV2::InvalidPreparation => {
            LocalRootTreeInvokeErrorV2::AttestationPreparationFailed
        }
        AttestedServiceErrorV2::Producer(_) => {
            LocalRootTreeInvokeErrorV2::ProofProductionFailed
        }
        AttestedServiceErrorV2::InvalidProducedProof => {
            LocalRootTreeInvokeErrorV2::InvalidProducedProof
        }
        AttestedServiceErrorV2::ProofUnavailable => {
            LocalRootTreeInvokeErrorV2::ProofUnavailable
        }
        AttestedServiceErrorV2::CommitMismatch => {
            LocalRootTreeInvokeErrorV2::AttestationCommitMismatch
        }
    }
}

pub struct LocalRootTreeServiceV2<B> {
    service: RootTreeServiceDriverV2<B>,
    identity: ServiceIdentityV2,
    root_actor: ActorId,
    consistency: ConsistencyModeV2,
    genesis: ServiceGenesisV2,
    expected_actors: Vec<ActorGenesisV2>,
    expected_external_actors: Vec<ExternalActorBindingV2>,
}

impl LocalRootTreeConfigV2 {
    pub fn validate(&self) -> Result<(), LocalRootTreeConfigErrorV2> {
        self.package
            .validate()
            .map_err(LocalRootTreeConfigErrorV2::InvalidPackage)?;
        if self.actor_name.is_empty() {
            return Err(LocalRootTreeConfigErrorV2::EmptyActorName);
        }
        if self.root_actor == ActorId::ZERO {
            return Err(LocalRootTreeConfigErrorV2::InvalidOwnedActorTree);
        }
        if self.service.deployment != self.package.deployment_id() {
            return Err(LocalRootTreeConfigErrorV2::WrongDeployment);
        }
        let service_program = ProgramId::of_pvm(&self.service_pvm);
        if self.service.service_program != service_program
            || self.package.manifest.service_program != service_program
        {
            return Err(LocalRootTreeConfigErrorV2::WrongServiceProgram);
        }
        if self.service.service_abi != super::ABI_VERSION
            || self.package.manifest.service_abi != super::ABI_VERSION
        {
            return Err(LocalRootTreeConfigErrorV2::WrongServiceAbi);
        }
        if self.service.execution_semantics != super::EXECUTION_SEMANTICS_ID
            || self.package.manifest.execution_semantics != super::EXECUTION_SEMANTICS_ID
        {
            return Err(LocalRootTreeConfigErrorV2::WrongExecutionSemantics);
        }
        if self.package.manifest.crdt != (self.consistency == ConsistencyModeV2::Crdt) {
            return Err(LocalRootTreeConfigErrorV2::InvalidConsistency);
        }
        if self.owned_actors.len().saturating_add(1) > super::MAX_ROOT_TREE_ACTORS {
            return Err(LocalRootTreeConfigErrorV2::TooManyOwnedActors);
        }
        let mut known = BTreeSet::from([self.root_actor]);
        let mut names = BTreeSet::from([(None, self.actor_name.as_str())]);
        for actor in &self.owned_actors {
            if actor.actor == ActorId::ZERO
                || actor.actor == self.root_actor
                || actor.name.is_empty()
                || !known.insert(actor.actor)
                || !names.insert((Some(actor.parent), actor.name.as_str()))
            {
                return Err(LocalRootTreeConfigErrorV2::InvalidOwnedActorTree);
            }
        }
        for actor in &self.owned_actors {
            if !known.contains(&actor.parent) {
                return Err(LocalRootTreeConfigErrorV2::InvalidOwnedActorTree);
            }
            let mut cursor = actor.actor;
            for _ in 0..known.len() {
                if cursor == self.root_actor {
                    break;
                }
                cursor = self
                    .owned_actors
                    .iter()
                    .find(|candidate| candidate.actor == cursor)
                    .map(|candidate| candidate.parent)
                    .ok_or(LocalRootTreeConfigErrorV2::InvalidOwnedActorTree)?;
            }
            if cursor != self.root_actor {
                return Err(LocalRootTreeConfigErrorV2::InvalidOwnedActorTree);
            }
        }
        if self.refine_gas == 0 || self.accumulate_gas == 0 {
            return Err(LocalRootTreeConfigErrorV2::ZeroGas);
        }
        Ok(())
    }
}

impl<B: CommittedImageStoreV2> LocalRootTreeServiceV2<B> {
    /// Open a committed service image or install a new tree through physical
    /// Accumulate when the backing store is empty.
    pub fn open(
        config: LocalRootTreeConfigV2,
        backend: B,
    ) -> Result<Self, LocalRootTreeOpenErrorV2<B::Error>> {
        if config.consistency == ConsistencyModeV2::Raft {
            return Err(LocalRootTreeOpenErrorV2::InvalidConfig(
                LocalRootTreeConfigErrorV2::ReplicationDriverRequired,
            ));
        }
        Self::open_with_driver(config, backend, RootTreeDriverConfigV2::Direct)
    }

    /// Open a Raft root tree whose every mutating request, including genesis,
    /// is quorum-ordered before the canonical service guest executes IC-5.
    #[cfg(feature = "storage")]
    pub fn open_raft(
        config: LocalRootTreeConfigV2,
        backend: B,
        log: RaftAccumulateLogV2,
    ) -> Result<Self, LocalRootTreeOpenErrorV2<B::Error>> {
        if config.consistency != ConsistencyModeV2::Raft {
            return Err(LocalRootTreeOpenErrorV2::InvalidConfig(
                LocalRootTreeConfigErrorV2::InvalidConsistency,
            ));
        }
        Self::open_with_driver(config, backend, RootTreeDriverConfigV2::Raft(log))
    }

    fn open_with_driver(
        config: LocalRootTreeConfigV2,
        backend: B,
        driver: RootTreeDriverConfigV2,
    ) -> Result<Self, LocalRootTreeOpenErrorV2<B::Error>> {
        config
            .validate()
            .map_err(LocalRootTreeOpenErrorV2::InvalidConfig)?;
        let root_initial_state = BlobRefV2::of_bytes(&config.initial_state);
        let expected_root = config
            .package
            .actor_genesis(
                config.root_actor,
                config.actor_name.clone(),
                None,
                root_initial_state.clone(),
            )
            .map_err(|error| {
                LocalRootTreeOpenErrorV2::InvalidConfig(LocalRootTreeConfigErrorV2::InvalidPackage(
                    error,
                ))
            })?;
        let mut expected_actors = Vec::with_capacity(config.owned_actors.len() + 1);
        expected_actors.push(expected_root);
        for actor in &config.owned_actors {
            expected_actors.push(
                config
                    .package
                    .actor_genesis(
                        actor.actor,
                        actor.name.clone(),
                        Some(actor.parent),
                        BlobRefV2::of_bytes(&actor.initial_state),
                    )
                    .map_err(|error| {
                        LocalRootTreeOpenErrorV2::InvalidConfig(
                            LocalRootTreeConfigErrorV2::InvalidPackage(error),
                        )
                    })?,
            );
        }
        expected_actors.sort_by_key(|actor| actor.actor);
        let store = DurableJamStoreV2::open(backend).map_err(LocalRootTreeOpenErrorV2::Store)?;
        let needs_imports = store
            .header()
            .map_err(LocalRootTreeOpenErrorV2::CorruptStore)?
            .is_none();
        let expected_program = config.service.service_program;
        let mut service = JamServiceV2::new(
            config.service_pvm,
            expected_program,
            NoRefineProtocolHostV2,
            store,
            config.refine_gas,
            config.accumulate_gas,
        )
        .map_err(LocalRootTreeOpenErrorV2::Service)?;

        let actor_program = config.package.manifest.actor_program;
        if needs_imports {
            let root_initial = service
                .accumulate_host_mut()
                .import_blob(config.initial_state);
            if root_initial != root_initial_state {
                return Err(LocalRootTreeOpenErrorV2::ExistingActorMismatch);
            }
            for actor in config.owned_actors {
                let expected = BlobRefV2::of_bytes(&actor.initial_state);
                let imported = service
                    .accumulate_host_mut()
                    .import_blob(actor.initial_state);
                if imported != expected {
                    return Err(LocalRootTreeOpenErrorV2::ExistingActorMismatch);
                }
            }
            let imported_program = service
                .accumulate_host_mut()
                .import_program(config.package.actor_pvm);
            if imported_program != actor_program {
                return Err(LocalRootTreeOpenErrorV2::InvalidConfig(
                    LocalRootTreeConfigErrorV2::InvalidPackage(PackageError::ProgramIdMismatch),
                ));
            }
        }
        let genesis = ServiceGenesisV2 {
            service: config.service.clone(),
            consistency: config.consistency,
            actors: expected_actors.clone(),
            external_actors: config.external_actors.clone(),
            authorization: config.install_authorization,
        };
        service.accumulate_host_mut().allow_install(&genesis);
        let service = match driver {
            RootTreeDriverConfigV2::Direct => RootTreeServiceDriverV2::Direct(service),
            #[cfg(feature = "storage")]
            RootTreeDriverConfigV2::Raft(log) => {
                RootTreeServiceDriverV2::Raft(ReplicatedJamServiceV2::new(service, log))
            }
        };

        let mut root = Self {
            service,
            identity: config.service,
            root_actor: config.root_actor,
            consistency: config.consistency,
            genesis,
            expected_actors,
            expected_external_actors: config.external_actors,
        };
        root.ensure_installed().map_err(|error| match error {
            LocalRootTreeInvokeErrorV2::Service(error) => LocalRootTreeOpenErrorV2::Service(error),
            #[cfg(feature = "storage")]
            LocalRootTreeInvokeErrorV2::Replication(error) => {
                LocalRootTreeOpenErrorV2::Replication(error)
            }
            LocalRootTreeInvokeErrorV2::Rejected(error) => {
                LocalRootTreeOpenErrorV2::InstallRejected(error)
            }
            LocalRootTreeInvokeErrorV2::UnexpectedResult => {
                LocalRootTreeOpenErrorV2::UnexpectedInstallResult
            }
            LocalRootTreeInvokeErrorV2::CorruptStore(error) => {
                LocalRootTreeOpenErrorV2::CorruptStore(error)
            }
            LocalRootTreeInvokeErrorV2::ExistingServiceMismatch => {
                LocalRootTreeOpenErrorV2::ExistingServiceMismatch
            }
            LocalRootTreeInvokeErrorV2::ExistingActorMismatch => {
                LocalRootTreeOpenErrorV2::ExistingActorMismatch
            }
            LocalRootTreeInvokeErrorV2::MissingInstalledProgram(program) => {
                LocalRootTreeOpenErrorV2::MissingInstalledProgram(program)
            }
            _ => LocalRootTreeOpenErrorV2::UnexpectedInstallResult,
        })?;
        Ok(root)
    }

    pub fn identity(&self) -> &ServiceIdentityV2 {
        &self.identity
    }

    pub const fn root_actor(&self) -> ActorId {
        self.root_actor
    }

    /// Canonical identities of every actor owned by this physical service
    /// route. Transport authentication binds the complete tree, since an
    /// inline child may be the producer of a durable cross-root message.
    pub fn actor_ids(&self) -> Result<Vec<ActorId>, LocalRootTreeInvokeErrorV2> {
        let Some(header) = self
            .service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
        else {
            // An uninitialized Raft follower still reserves the signed static
            // tree while it waits for the genesis log entry.
            return Ok(self
                .expected_actors
                .iter()
                .map(|actor| actor.actor)
                .collect());
        };
        let bytes = self
            .service
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::ActorDirectory)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::ExistingActorMismatch)?;
        ActorDirectoryV2::decode(&bytes)
            .map(|directory| directory.actors)
            .map_err(|_| LocalRootTreeInvokeErrorV2::ExistingActorMismatch)
    }

    pub fn owns_actor(&self, actor: ActorId) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        Ok(self.actor_ids()?.binary_search(&actor).is_ok())
    }

    pub const fn consistency(&self) -> ConsistencyModeV2 {
        self.consistency
    }

    pub fn store(&self) -> &DurableJamStoreV2<B> {
        self.service.accumulate_host()
    }

    pub fn store_mut(&mut self) -> &mut DurableJamStoreV2<B> {
        self.service.accumulate_host_mut()
    }

    /// Build the exact upgrade request against the currently committed actor
    /// descriptor and consistency base. Deployment controllers should retain
    /// this value across retries; changing the base or authorization creates a
    /// different operation rather than an exactly-once retry.
    pub fn prepare_actor_upgrade(
        &mut self,
        actor: ActorId,
        package: &VosPackageV2,
        authorization: AuthorizationEvidenceV2,
    ) -> Result<ActorUpgradeV2, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        self.validate_upgrade_package(package)?;
        let header = self.installed_header()?;
        let descriptor = self.installed_actor_descriptor(&header, actor)?;
        let policies = PackageRolePoliciesV2::decode(&package.role_policies)
            .map_err(|_| LocalRootTreeInvokeErrorV2::UpgradePackageMismatch)?;
        if descriptor.program == package.manifest.actor_program {
            return Err(LocalRootTreeInvokeErrorV2::UpgradePackageMismatch);
        }
        let base = match header.consistency {
            ConsistencyModeV2::Crdt => ConsistencyBaseV2::Crdt {
                heads: header.crdt_heads,
            },
            ConsistencyModeV2::Ephemeral
            | ConsistencyModeV2::Local
            | ConsistencyModeV2::Raft => ConsistencyBaseV2::Linear {
                revision: header.revision,
                state_root: header
                    .state_root
                    .ok_or(LocalRootTreeInvokeErrorV2::ExistingServiceMismatch)?,
            },
        };
        Ok(ActorUpgradeV2 {
            service: self.identity.clone(),
            actor,
            expected_program: descriptor.program,
            replacement_program: package.manifest.actor_program,
            producer: package.deployment_signature.producer,
            methods: policies.methods,
            base,
            authorization,
        })
    }

    /// Make one exact signed replacement package and authorization available
    /// to the local physical service host without committing actor state.
    ///
    /// Raft operators call this on every replica before the leader appends the
    /// matching request. The program cache becomes durable with the same
    /// service-image commit that accepts the upgrade.
    pub fn stage_actor_upgrade(
        &mut self,
        package: &VosPackageV2,
        upgrade: &ActorUpgradeV2,
    ) -> Result<(), LocalRootTreeInvokeErrorV2> {
        self.validate_upgrade_package(package)?;
        let policies = PackageRolePoliciesV2::decode(&package.role_policies)
            .map_err(|_| LocalRootTreeInvokeErrorV2::UpgradePackageMismatch)?;
        if upgrade.service != self.identity
            || upgrade.replacement_program != package.manifest.actor_program
            || upgrade.producer != package.deployment_signature.producer
            || upgrade.methods != policies.methods
        {
            return Err(LocalRootTreeInvokeErrorV2::UpgradePackageMismatch);
        }
        let imported = self
            .service
            .accumulate_host_mut()
            .import_program(package.actor_pvm.clone());
        if imported != upgrade.replacement_program
            || !self
                .service
                .accumulate_host_mut()
                .allow_upgrade(upgrade)
        {
            return Err(LocalRootTreeInvokeErrorV2::UpgradePackageMismatch);
        }
        Ok(())
    }

    /// Submit one previously staged exact request through physical IC-5.
    /// Exact retries return the original receipt without advancing state.
    pub fn commit_actor_upgrade(
        &mut self,
        upgrade: &ActorUpgradeV2,
    ) -> Result<CommittedActorUpgradeV2, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        let accumulated = self
            .service
            .accumulate(&AccumulateRequestV2::UpgradeActor(upgrade.clone()))
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        match accumulated.result {
            AccumulationResultV2::ActorUpgraded {
                actor,
                previous_program,
                program,
                receipt,
                duplicate,
            } => Ok(CommittedActorUpgradeV2 {
                actor,
                previous_program,
                program,
                receipt,
                duplicate,
                accumulate_gas_used: accumulated.gas_used,
            }),
            AccumulationResultV2::Rejected(rejection) => {
                Err(LocalRootTreeInvokeErrorV2::Rejected(rejection))
            }
            _ => Err(LocalRootTreeInvokeErrorV2::UnexpectedResult),
        }
    }

    fn validate_upgrade_package(
        &self,
        package: &VosPackageV2,
    ) -> Result<(), LocalRootTreeInvokeErrorV2> {
        package
            .validate()
            .map_err(LocalRootTreeInvokeErrorV2::InvalidUpgradePackage)?;
        if package.manifest.service_program != self.identity.service_program
            || package.manifest.crdt != (self.consistency == ConsistencyModeV2::Crdt)
        {
            return Err(LocalRootTreeInvokeErrorV2::UpgradePackageMismatch);
        }
        Ok(())
    }

    fn installed_header(&self) -> Result<StoreHeaderV2, LocalRootTreeInvokeErrorV2> {
        self.service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::ServiceNotInstalled)
    }

    fn installed_actor_descriptor(
        &self,
        header: &StoreHeaderV2,
        actor: ActorId,
    ) -> Result<ActorGenesisV2, LocalRootTreeInvokeErrorV2> {
        self.service
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::ActorDescriptor(actor))
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .and_then(|bytes| ActorGenesisV2::decode(&bytes).ok())
            .ok_or(LocalRootTreeInvokeErrorV2::ExistingActorMismatch)
    }

    /// Apply every newly committed Raft request to this replica's physical
    /// service image. A direct Local/CRDT conformance owner is already current.
    /// Followers may remain uninstalled until the leader's genesis request is
    /// committed; callers must not schedule actor work while this returns
    /// `false`.
    pub fn catch_up(&mut self) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        self.ensure_installed()
    }

    fn ensure_installed(&mut self) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        self.service
            .catch_up()
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        if self.validate_installed()? {
            return Ok(true);
        }
        if !self.service.is_writable() {
            return Ok(false);
        }
        let result = self
            .service
            .accumulate(&AccumulateRequestV2::Install(self.genesis.clone()))
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        match result.result {
            AccumulationResultV2::Installed(_) => {}
            AccumulationResultV2::Rejected(rejection) => {
                return Err(LocalRootTreeInvokeErrorV2::Rejected(rejection));
            }
            _ => return Err(LocalRootTreeInvokeErrorV2::UnexpectedResult),
        }
        if self.validate_installed()? {
            Ok(true)
        } else {
            Err(LocalRootTreeInvokeErrorV2::ServiceNotInstalled)
        }
    }

    fn require_installed(&mut self) -> Result<(), LocalRootTreeInvokeErrorV2> {
        if self.ensure_installed()? {
            Ok(())
        } else {
            Err(LocalRootTreeInvokeErrorV2::ServiceNotInstalled)
        }
    }

    fn validate_installed(&self) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        let Some(header) = self
            .service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
        else {
            return Ok(false);
        };
        if header.service != self.identity || header.consistency != self.consistency {
            return Err(LocalRootTreeInvokeErrorV2::ExistingServiceMismatch);
        }
        let expected_program = self.expected_actors[0].program;
        if self
            .service
            .accumulate_host()
            .program(expected_program)
            .is_none()
        {
            return Err(LocalRootTreeInvokeErrorV2::MissingInstalledProgram(
                expected_program,
            ));
        }
        let directory = self
            .service
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::ActorDirectory)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .and_then(|bytes| ActorDirectoryV2::decode(&bytes).ok());
        let Some(directory) = directory else {
            return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
        };
        if directory.actors.len() > super::MAX_ROOT_TREE_ACTORS
            || self
                .expected_actors
                .iter()
                .any(|expected| directory.actors.binary_search(&expected.actor).is_err())
        {
            return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
        }

        let mut descriptors = Vec::with_capacity(directory.actors.len());
        let mut names = BTreeSet::new();
        for actor in &directory.actors {
            let descriptor = self
                .service
                .accumulate_host()
                .state_row(header.service_root, &StateKeyV2::ActorDescriptor(*actor))
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
                .and_then(|bytes| ActorGenesisV2::decode(&bytes).ok())
                .ok_or(LocalRootTreeInvokeErrorV2::ExistingActorMismatch)?;
            if descriptor.actor != *actor
                || descriptor.name.is_empty()
                || descriptor.parent == Some(*actor)
                || !names.insert((descriptor.parent, descriptor.name.clone()))
                || self
                    .service
                    .accumulate_host()
                    .program(descriptor.program)
                    .is_none()
            {
                return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
            }
            let name_row = self
                .service
                .accumulate_host()
                .state_row(
                    header.service_root,
                    &StateKeyV2::ActorName {
                        parent: descriptor.parent,
                        name: descriptor.name.clone(),
                    },
                )
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?;
            if name_row.as_deref() != Some(actor.0.as_slice()) {
                return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
            }
            for method in &descriptor.methods {
                let policy = self
                    .service
                    .accumulate_host()
                    .state_row(
                        header.service_root,
                        &StateKeyV2::MethodPolicy {
                            actor: *actor,
                            method: method.method.clone(),
                        },
                    )
                    .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?;
                if policy.as_deref() != Some(method.encode().as_slice()) {
                    return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
                }
            }
            let state_key = if self.consistency == ConsistencyModeV2::Crdt {
                StateKeyV2::CrdtMaterialization(*actor)
            } else {
                StateKeyV2::ActorRow {
                    actor: *actor,
                    key: crate::actors::lifecycle::STATE_KEY_BYTES.to_vec(),
                }
            };
            let state = self
                .service
                .accumulate_host()
                .state_row(header.service_root, &state_key)
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
                .and_then(|bytes| BlobRefV2::decode(&bytes).ok());
            if state
                .as_ref()
                .is_none_or(|state| self.service.accumulate_host().blob(state).is_none())
                || self
                    .service
                    .accumulate_host()
                    .blob(&descriptor.initial_state)
                    .is_none()
            {
                return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
            }
            descriptors.push(descriptor);
        }
        if descriptors
            .iter()
            .filter(|descriptor| descriptor.parent.is_none())
            .map(|descriptor| descriptor.actor)
            .ne(core::iter::once(self.root_actor))
        {
            return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
        }
        for descriptor in &descriptors {
            if let Some(expected) = self
                .expected_actors
                .iter()
                .find(|expected| expected.actor == descriptor.actor)
            {
                // Program, producer, and generated method policies are the
                // actor fields changed by guest-owned UpgradeActor. Stable
                // instance identity, ownership, state kind, and install blob
                // must still match the signed genesis configuration exactly.
                if descriptor.actor != expected.actor
                    || descriptor.name != expected.name
                    || descriptor.parent != expected.parent
                    || descriptor.initial_state != expected.initial_state
                    || descriptor.crdt != expected.crdt
                {
                    return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
                }
            } else {
                let Some(parent_id) = descriptor.parent else {
                    return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
                };
                let Some(parent) = descriptors
                    .iter()
                    .find(|candidate| candidate.actor == parent_id)
                else {
                    return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
                };
                if descriptor.actor != ActorId::owned_child(parent_id, &descriptor.name)
                    || descriptor.crdt != parent.crdt
                {
                    return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
                }
            }
            let mut cursor = descriptor.actor;
            for _ in 0..descriptors.len() {
                if cursor == self.root_actor {
                    break;
                }
                cursor = descriptors
                    .iter()
                    .find(|candidate| candidate.actor == cursor)
                    .and_then(|candidate| candidate.parent)
                    .ok_or(LocalRootTreeInvokeErrorV2::ExistingActorMismatch)?;
            }
            if cursor != self.root_actor {
                return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
            }
        }
        let external = self
            .service
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::ExternalActorDirectory)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .and_then(|bytes| ExternalActorDirectoryV2::decode(&bytes).ok());
        if external.as_ref().is_none_or(|directory| {
            directory.actors.as_slice() != self.expected_external_actors.as_slice()
        }) {
            return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
        }
        Ok(true)
    }

    pub fn actor_method_policy(
        &self,
        actor: ActorId,
        method: &str,
    ) -> Result<Option<MethodPolicyV2>, LocalRootTreeInvokeErrorV2> {
        if !self.owns_actor(actor)? {
            return Ok(None);
        }
        let header = self
            .service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::UnexpectedResult)?;
        let descriptor = self
            .service
            .accumulate_host()
            .state_row(
                header.service_root,
                &StateKeyV2::ActorDescriptor(actor),
            )
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .and_then(|bytes| ActorGenesisV2::decode(&bytes).ok())
            .ok_or(LocalRootTreeInvokeErrorV2::UnexpectedResult)?;
        Ok(descriptor
            .methods
            .binary_search_by(|policy| policy.method.as_str().cmp(method))
            .ok()
            .map(|index| descriptor.methods[index].clone()))
    }

    /// Classify a direct invocation retry from guest-authenticated workflow
    /// and continuation state. Volatile timeslots and continuation-step
    /// inputs are deliberately excluded from the original-ingress identity.
    pub fn recover_ingress(
        &self,
        request: &LocalWorkRequestV2,
    ) -> Result<RootTreeIngressRecoveryV2, LocalRootTreeInvokeErrorV2> {
        if request.workflow_step != 0
            || request.causal_parent.is_some()
            || request.parent_call.is_some()
            || request.awaited_reply.is_some()
        {
            return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
        }
        let checkpoint = self
            .service
            .accumulate_host()
            .workflow_checkpoint(request.invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?;
        let Some(checkpoint) = checkpoint else {
            let Some(record) = self
                .service
                .accumulate_host()
                .ingress_record(request.invocation)
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            else {
                return Ok(RootTreeIngressRecoveryV2::Fresh);
            };
            let candidate = direct_ingress_from_request(
                self.service.accumulate_host(),
                &self.identity,
                request,
            )?;
            if record.consumed || !record.ingress.matches_retry(&candidate) {
                return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
            }
            return Ok(RootTreeIngressRecoveryV2::Queued {
                logical_timeslot: record.ingress.logical_timeslot,
            });
        };
        if !direct_ingress_matches_checkpoint(request, &checkpoint) {
            return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
        }

        let mut publications = self
            .pending_publications()?
            .into_iter()
            .filter(|publication| publication.input.invocation == request.invocation);
        if let Some(publication) = publications.next() {
            if publications.next().is_some() || publication.input != checkpoint.input {
                return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
            }
            return Ok(RootTreeIngressRecoveryV2::PendingPublication {
                publication,
                logical_timeslot: checkpoint.resume_work.logical_timeslot,
            });
        }

        let header = self
            .service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::UnexpectedResult)?;
        let continuation = self
            .service
            .accumulate_host()
            .state_row(
                header.service_root,
                &StateKeyV2::Continuation(request.target),
            )
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .map(|bytes| BlobRefV2::decode(&bytes))
            .transpose()
            .map_err(|_| {
                LocalRootTreeInvokeErrorV2::Schedule(ScheduleErrorV2::InvalidContinuation(
                    request.target,
                ))
            })?;
        let Some(continuation) = continuation else {
            if let Some(publication) = self
                .service
                .accumulate_host()
                .archived_attestation(checkpoint.input)
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            {
                if publication.published.reply.as_ref() != checkpoint.reply.as_ref() {
                    return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
                }
                return Ok(RootTreeIngressRecoveryV2::CompletedAttested { publication });
            }
            let reply = checkpoint
                .reply
                .ok_or(LocalRootTreeInvokeErrorV2::UnexpectedResult)?;
            return Ok(RootTreeIngressRecoveryV2::Completed { reply });
        };
        let bytes = self.service.accumulate_host().blob(&continuation).ok_or(
            LocalRootTreeInvokeErrorV2::Schedule(ScheduleErrorV2::MissingBlob(continuation.hash)),
        )?;
        let snapshot = ContinuationSnapshotV2::decode(bytes).map_err(|_| {
            LocalRootTreeInvokeErrorV2::Schedule(ScheduleErrorV2::InvalidContinuation(
                request.target,
            ))
        })?;
        if snapshot.invocation != request.invocation {
            if let Some(publication) = self
                .service
                .accumulate_host()
                .archived_attestation(checkpoint.input)
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            {
                if publication.published.reply.as_ref() != checkpoint.reply.as_ref() {
                    return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
                }
                return Ok(RootTreeIngressRecoveryV2::CompletedAttested { publication });
            }
            let reply = checkpoint
                .reply
                .ok_or(LocalRootTreeInvokeErrorV2::UnexpectedResult)?;
            return Ok(RootTreeIngressRecoveryV2::Completed { reply });
        }
        snapshot
            .validate_checkpoint_for(&checkpoint.resume_work)
            .map_err(|_| {
                LocalRootTreeInvokeErrorV2::Schedule(ScheduleErrorV2::InvalidContinuation(
                    request.target,
                ))
            })?;
        Ok(RootTreeIngressRecoveryV2::Suspended)
    }

    /// Persist one direct invocation through physical Accumulate before any
    /// Refine execution. The returned flag is true for an exact duplicate.
    pub fn admit_ingress(
        &mut self,
        request: &LocalWorkRequestV2,
    ) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        let ingress =
            direct_ingress_from_request(self.service.accumulate_host(), &self.identity, request)?;
        let accumulated = self
            .service
            .accumulate(&AccumulateRequestV2::AdmitIngress(ingress))
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        match accumulated.result {
            AccumulationResultV2::IngressAdmitted {
                invocation,
                receipt: _,
                duplicate,
            } if invocation == request.invocation => Ok(duplicate),
            AccumulationResultV2::Rejected(rejection) => {
                Err(LocalRootTreeInvokeErrorV2::Rejected(rejection))
            }
            _ => Err(LocalRootTreeInvokeErrorV2::UnexpectedResult),
        }
    }

    /// Schedule a previously guest-admitted direct invocation from its exact
    /// persisted input. A busy actor leaves the record untouched for retry.
    pub fn invoke_admitted(
        &mut self,
        invocation: super::InvocationId,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        let record = self
            .service
            .accumulate_host()
            .ingress_record(invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::UnexpectedResult)?;
        if record.consumed {
            return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
        }
        self.invoke(request_from_direct_ingress(record.ingress))
    }

    /// Execute one ordinary slice. Attested work requires a configured proof
    /// producer and uses the separate proof-before-Accumulate path.
    pub fn invoke(
        &mut self,
        request: LocalWorkRequestV2,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        if request.proof_requested {
            return Err(LocalRootTreeInvokeErrorV2::ProofProducerRequired);
        }
        let prepared = LocalWorkSchedulerV2::prepare(self.service.accumulate_host(), request)
            .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        self.invoke_prepared(prepared)
    }

    /// Execute one single-slice attested invocation. The exact live Refine
    /// output is prepared by guest Accumulate, handed to `producer`, and only
    /// then committed through physical Accumulate with the produced proof.
    pub fn invoke_attested<P: AttestationProofProducerV2>(
        &mut self,
        request: LocalWorkRequestV2,
        producer: &mut P,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        if !request.proof_requested {
            return Err(LocalRootTreeInvokeErrorV2::ProofModeMismatch);
        }
        let prepared = LocalWorkSchedulerV2::prepare(self.service.accumulate_host(), request)
            .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        self.invoke_prepared_attested(prepared, producer)
    }

    /// Execute a message only after destination Accumulate has admitted its
    /// finalized source outbox record into the guest-owned inbox.
    pub fn invoke_inbox(
        &mut self,
        call: super::CallId,
        logical_timeslot: u64,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        let prepared = LocalWorkSchedulerV2::prepare_inbox(
            self.service.accumulate_host(),
            call,
            logical_timeslot,
        )
        .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        if prepared.work.proof_requested {
            return Err(LocalRootTreeInvokeErrorV2::ProofProducerRequired);
        }
        self.invoke_prepared(prepared)
    }

    /// Execute a guest-admitted attested inbox message with a configured proof
    /// producer. This is used for cross-root calls to attested methods.
    pub fn invoke_inbox_attested<P: AttestationProofProducerV2>(
        &mut self,
        call: super::CallId,
        logical_timeslot: u64,
        producer: &mut P,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        let prepared = LocalWorkSchedulerV2::prepare_inbox(
            self.service.accumulate_host(),
            call,
            logical_timeslot,
        )
        .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        if !prepared.work.proof_requested {
            return Err(LocalRootTreeInvokeErrorV2::ProofModeMismatch);
        }
        self.invoke_prepared_attested(prepared, producer)
    }

    /// Schedule a previously guest-admitted attested direct invocation.
    pub fn invoke_admitted_attested<P: AttestationProofProducerV2>(
        &mut self,
        invocation: super::InvocationId,
        producer: &mut P,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        let record = self
            .service
            .accumulate_host()
            .ingress_record(invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::UnexpectedResult)?;
        if record.consumed {
            return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
        }
        let request = request_from_direct_ingress(record.ingress);
        if !request.proof_requested {
            return Err(LocalRootTreeInvokeErrorV2::ProofModeMismatch);
        }
        let prepared = LocalWorkSchedulerV2::prepare(self.service.accumulate_host(), request)
            .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        self.invoke_prepared_attested(prepared, producer)
    }

    /// Resume the exact committed machine snapshot for an invocation. The
    /// scheduler reconstructs the slice from guest state rather than a
    /// process-local handler future.
    pub fn resume(
        &mut self,
        invocation: super::InvocationId,
        logical_timeslot: u64,
        awaited_reply: Option<super::AccumulatedReplyV2>,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        let prepared = LocalWorkSchedulerV2::prepare_resume(
            self.service.accumulate_host(),
            invocation,
            logical_timeslot,
            awaited_reply,
        )
        .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        if prepared.work.proof_requested {
            return Err(LocalRootTreeInvokeErrorV2::ProofProducerRequired);
        }
        self.invoke_prepared(prepared)
    }

    /// Commit every due outbound-call timeout through physical Accumulate.
    /// The scan is reconstructed from guest bookkeeping, so a process restart
    /// does not need a native timer table.
    pub fn expire_due_calls(
        &mut self,
        logical_timeslot: u64,
    ) -> Result<Vec<CommittedCallExpirationV2>, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        let invocations = self
            .service
            .accumulate_host()
            .known_workflow_invocations()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?;
        let mut expired = Vec::new();
        for invocation in invocations {
            let Some(envelope) = LocalWorkSchedulerV2::prepare_call_expiration(
                self.service.accumulate_host(),
                invocation,
                logical_timeslot,
            )
            .map_err(LocalRootTreeInvokeErrorV2::Schedule)?
            else {
                continue;
            };
            let accumulated = self
                .service
                .accumulate(&AccumulateRequestV2::ExpireCall(envelope))
                .map_err(RootTreeDriverErrorV2::into_invoke)?;
            match accumulated.result {
                AccumulationResultV2::CallExpired { timeout, duplicate } => {
                    expired.push(CommittedCallExpirationV2 {
                        invocation,
                        timeout,
                        duplicate,
                        accumulate_gas_used: accumulated.gas_used,
                    });
                }
                AccumulationResultV2::Rejected(rejection) => {
                    return Err(LocalRootTreeInvokeErrorV2::Rejected(rejection));
                }
                _ => return Err(LocalRootTreeInvokeErrorV2::UnexpectedResult),
            }
        }
        Ok(expired)
    }

    /// Resume every continuation whose timeout was already committed. This
    /// deliberately runs as a separate pass so a crash between expiration and
    /// actor execution is recovered without manufacturing a host error value.
    pub fn resume_expired_calls(
        &mut self,
        logical_timeslot: u64,
    ) -> Result<Vec<CommittedRootTreeSliceV2>, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        let invocations = self
            .service
            .accumulate_host()
            .known_workflow_invocations()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?;
        let mut resumed = Vec::new();
        for invocation in invocations {
            let Some(prepared) = LocalWorkSchedulerV2::prepare_timeout_resume(
                self.service.accumulate_host(),
                invocation,
                logical_timeslot,
            )
            .map_err(LocalRootTreeInvokeErrorV2::Schedule)?
            else {
                continue;
            };
            if prepared.work.proof_requested {
                return Err(LocalRootTreeInvokeErrorV2::ProofProducerRequired);
            }
            resumed.push(self.invoke_prepared(prepared)?);
        }
        Ok(resumed)
    }

    /// Make one exact platform-finalized receipt available to the next guest
    /// Accumulate verification. This changes host verifier policy only; it is
    /// excluded from the committed service image.
    pub(crate) fn allow_finalized_receipt(&mut self, receipt: &AccumulationReceiptV2) {
        self.service
            .accumulate_host_mut()
            .allow_receipt(&ReceiptVerificationRequestV2 {
                receipt: receipt.clone(),
            });
    }

    /// Stage proof bytes received from another root in the content-addressed
    /// blob cache used to construct Refine imports. This is only an early
    /// transport filter: resumed guest Accumulate rechecks the exact package,
    /// receipt, pending call, and installed external-actor binding before any
    /// workflow state can commit.
    pub(crate) fn stage_finalized_attestation(
        &mut self,
        package: &CommittedAttestationPackageV2,
    ) -> Result<(), LocalRootTreeInvokeErrorV2> {
        package
            .validate()
            .map_err(|_| LocalRootTreeInvokeErrorV2::InvalidAttestationPublication)?;
        let delivery = package
            .reply
            .attestation
            .as_ref()
            .ok_or(LocalRootTreeInvokeErrorV2::InvalidAttestationPublication)?;
        let header = self
            .service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::ServiceNotInstalled)?;
        let binding = self
            .service
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::ExternalActorDirectory)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .and_then(|bytes| ExternalActorDirectoryV2::decode(&bytes).ok())
            .and_then(|directory| {
                directory
                    .actors
                    .into_iter()
                    .find(|binding| binding.actor == package.reply.reply.producer)
            })
            .ok_or(LocalRootTreeInvokeErrorV2::InvalidAttestationPublication)?;
        if binding.name != delivery.producer_name
            || binding.service != package.reply.receipt.service
            || binding.actor != delivery.statement.actor
            || binding.producer != delivery.producer
            || binding.program != delivery.statement.actor_program
        {
            return Err(LocalRootTreeInvokeErrorV2::InvalidAttestationPublication);
        }
        let imported = self
            .service
            .accumulate_host_mut()
            .import_blob(package.proof_blob.bytes.clone());
        if imported != package.proof_blob.reference {
            return Err(LocalRootTreeInvokeErrorV2::InvalidAttestationPublication);
        }
        Ok(())
    }

    /// Export the complete authenticated causal DAG from committed guest
    /// state. An empty freshly-installed CRDT has no transport envelope yet.
    pub fn crdt_sync_envelope(
        &self,
    ) -> Result<Option<CrdtSyncEnvelopeV2>, LocalRootTreeInvokeErrorV2> {
        if self.consistency != ConsistencyModeV2::Crdt {
            return Err(LocalRootTreeInvokeErrorV2::Schedule(
                ScheduleErrorV2::UnsupportedConsistency(self.consistency),
            ));
        }
        let header = self
            .service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::ServiceNotInstalled)?;
        if header.crdt_heads.is_empty() {
            return Ok(None);
        }
        LocalWorkSchedulerV2::prepare_crdt_sync(self.service.accumulate_host())
            .map(Some)
            .map_err(LocalRootTreeInvokeErrorV2::Schedule)
    }

    /// Import finalized peer nodes only through the canonical guest's
    /// SyncCrdt Accumulate request. The local conformance harness supplies the
    /// exact receipt-verification availability; all identity, ancestry, CID,
    /// blob, and workflow validation remains guest-owned.
    pub fn sync_finalized_crdt(
        &mut self,
        envelope: CrdtSyncEnvelopeV2,
    ) -> Result<CommittedCrdtSyncV2, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        if self.consistency != ConsistencyModeV2::Crdt || envelope.service != self.identity {
            return Err(LocalRootTreeInvokeErrorV2::Rejected(
                AccumulationRejectionV2::InvalidConsistency,
            ));
        }
        for node in &envelope.nodes {
            self.allow_finalized_receipt(&node.receipt);
        }
        let accumulated = self
            .service
            .accumulate(&AccumulateRequestV2::SyncCrdt(envelope))
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        match accumulated.result {
            AccumulationResultV2::Accepted {
                receipt,
                published,
                duplicate,
            } if published == PublishedEffectsV2::default() => Ok(CommittedCrdtSyncV2 {
                receipt,
                duplicate,
                accumulate_gas_used: accumulated.gas_used,
            }),
            AccumulationResultV2::Rejected(rejection) => {
                Err(LocalRootTreeInvokeErrorV2::Rejected(rejection))
            }
            _ => Err(LocalRootTreeInvokeErrorV2::UnexpectedResult),
        }
    }

    /// Whether this exact accumulated reply already advanced the durable
    /// workflow. This lets transport resend its acknowledgement after an ACK
    /// loss without restoring or executing the continuation a second time.
    pub(crate) fn reply_already_accumulated(
        &self,
        invocation: super::InvocationId,
        reply: &super::AccumulatedReplyV2,
    ) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        let checkpoint = self
            .service
            .accumulate_host()
            .workflow_checkpoint(invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?;
        Ok(checkpoint.is_some_and(|checkpoint| {
            checkpoint.input.invocation == invocation
                && checkpoint.input.workflow_step > 0
                && checkpoint.resume_work.awaited_reply.as_ref() == Some(reply)
        }))
    }

    /// Admit one finalized source outbox record through destination physical
    /// Accumulate. The host policy makes only this exact receipt available;
    /// membership, service identity, base freshness and deduplication remain
    /// guest-owned checks.
    pub fn deliver_finalized(
        &mut self,
        logical_timeslot: u64,
        message: MessageRecordV2,
        source_outbox: Vec<MessageRecordV2>,
        source_receipt: AccumulationReceiptV2,
    ) -> Result<CommittedDeliveryV2, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        self.allow_finalized_receipt(&source_receipt);
        let delivery = LocalWorkSchedulerV2::prepare_delivery(
            self.service.accumulate_host(),
            logical_timeslot,
            message,
            source_outbox,
            source_receipt,
        )
        .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        let accumulated = self
            .service
            .accumulate(&AccumulateRequestV2::Deliver(delivery))
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        match accumulated.result {
            AccumulationResultV2::Accepted {
                receipt,
                published,
                duplicate,
            } if published == PublishedEffectsV2::default() => Ok(CommittedDeliveryV2 {
                receipt,
                duplicate,
                accumulate_gas_used: accumulated.gas_used,
            }),
            AccumulationResultV2::Rejected(rejection) => {
                Err(LocalRootTreeInvokeErrorV2::Rejected(rejection))
            }
            _ => Err(LocalRootTreeInvokeErrorV2::UnexpectedResult),
        }
    }

    fn invoke_prepared(
        &mut self,
        prepared: PreparedWorkV2,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        if prepared.work.proof_requested {
            return Err(LocalRootTreeInvokeErrorV2::ProofProducerRequired);
        }
        let refined = self
            .service
            .refine_actor_tree(&prepared.work, &prepared.imports)
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        let input = prepared.work.input_id();
        let accumulated = self
            .service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: prepared.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            }))
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        let (receipt, published, duplicate) = match accumulated.result {
            AccumulationResultV2::Accepted {
                receipt,
                published,
                duplicate,
            } => (receipt, published, duplicate),
            AccumulationResultV2::Rejected(rejection) => {
                return Err(LocalRootTreeInvokeErrorV2::Rejected(rejection));
            }
            _ => return Err(LocalRootTreeInvokeErrorV2::UnexpectedResult),
        };
        let publication = self
            .service
            .accumulate_host()
            .pending_publications()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .into_iter()
            .find(|publication| publication.input == input);
        if published != PublishedEffectsV2::default() && publication.is_none() {
            return Err(LocalRootTreeInvokeErrorV2::MissingPublication);
        }
        Ok(CommittedRootTreeSliceV2 {
            input,
            receipt,
            published,
            publication,
            duplicate,
            refine_gas_used: refined.gas_used,
            accumulate_gas_used: accumulated.gas_used,
        })
    }

    fn invoke_prepared_attested<P: AttestationProofProducerV2>(
        &mut self,
        prepared: PreparedWorkV2,
        producer: &mut P,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        if !prepared.work.proof_requested {
            return Err(LocalRootTreeInvokeErrorV2::ProofModeMismatch);
        }
        let refined = self
            .service
            .refine_actor_tree(&prepared.work, &prepared.imports)
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        let input = prepared.work.input_id();
        let committed = self.service.accumulate_attested(
            AccumulationEnvelopeV2 {
                work: prepared.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            },
            &prepared.imports,
            producer,
        )?;
        let receipt = committed.preparation.receipt;
        let published = committed.published;
        let publication = self
            .service
            .accumulate_host()
            .pending_publications()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .into_iter()
            .find(|publication| publication.input == input);
        if publication.is_none() {
            return Err(LocalRootTreeInvokeErrorV2::MissingPublication);
        }
        Ok(CommittedRootTreeSliceV2 {
            input,
            receipt,
            published,
            publication,
            duplicate: false,
            refine_gas_used: refined.gas_used,
            accumulate_gas_used: committed
                .prepare_gas_used
                .saturating_add(committed.accumulate_gas_used),
        })
    }

    /// Remove a committed publication only after its external consumer has
    /// accepted the reply/outbox/proof package.
    pub fn acknowledge_publication(
        &mut self,
        publication: &PublicationRecordV2,
    ) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        let result = self
            .service
            .accumulate(&AccumulateRequestV2::AcknowledgePublication(
                PublicationAckV2 {
                    service: self.identity.clone(),
                    input: publication.input,
                    publication: publication.commitment(),
                },
            ))
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        match result.result {
            AccumulationResultV2::PublicationAcknowledged { duplicate, .. } => Ok(duplicate),
            AccumulationResultV2::Rejected(rejection) => {
                Err(LocalRootTreeInvokeErrorV2::Rejected(rejection))
            }
            _ => Err(LocalRootTreeInvokeErrorV2::UnexpectedResult),
        }
    }

    pub fn pending_publications(
        &self,
    ) -> Result<Vec<PublicationRecordV2>, LocalRootTreeInvokeErrorV2> {
        self.service
            .accumulate_host()
            .pending_publications()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)
    }

    /// Whether guest state still permits transport to expose this outbox
    /// effect. Expiration and reply admission remove the live row even though
    /// the immutable publication receipt may remain for retry bookkeeping.
    pub(crate) fn outbox_call_is_pending(
        &self,
        call: super::CallId,
    ) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        self.service
            .accumulate_host()
            .outbox_message(call)
            .map(|message| message.is_some())
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)
    }

    /// Reconstruct a complete committed attestation package from guest-owned
    /// publication state and its content-addressed proof bytes. This remains
    /// available after restart until the caller acknowledges the publication.
    pub fn committed_attestation_package(
        &self,
        publication: &PublicationRecordV2,
    ) -> Result<CommittedAttestationPackageV2, LocalRootTreeInvokeErrorV2> {
        let canonical = PublicationRecordV2::decode(&publication.encode())
            .map_err(|_| LocalRootTreeInvokeErrorV2::InvalidAttestationPublication)?;
        let is_pending = self
            .pending_publications()?
            .iter()
            .any(|candidate| candidate == publication);
        let is_archived = self
            .service
            .accumulate_host()
            .archived_attestation(publication.input)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .as_ref()
            == Some(publication);
        if canonical != *publication || (!is_pending && !is_archived) {
            return Err(LocalRootTreeInvokeErrorV2::MissingPublication);
        }
        let statement = publication
            .published
            .statement
            .clone()
            .ok_or(LocalRootTreeInvokeErrorV2::InvalidAttestationPublication)?;
        let proof = publication
            .published
            .proof
            .clone()
            .ok_or(LocalRootTreeInvokeErrorV2::InvalidAttestationPublication)?;
        let proof_reference = proof.proof_blob.clone();
        let reply = publication
            .published
            .reply
            .clone()
            .ok_or(LocalRootTreeInvokeErrorV2::InvalidAttestationPublication)?;
        let header = self
            .service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::ServiceNotInstalled)?;
        let descriptor = self
            .service
            .accumulate_host()
            .state_row(
                header.service_root,
                &StateKeyV2::ActorDescriptor(statement.actor),
            )
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .and_then(|bytes| ActorGenesisV2::decode(&bytes).ok())
            .ok_or(LocalRootTreeInvokeErrorV2::InvalidAttestationPublication)?;
        if descriptor.actor != statement.actor
            || descriptor.program != statement.actor_program
            || reply.producer != descriptor.actor
        {
            return Err(LocalRootTreeInvokeErrorV2::InvalidAttestationPublication);
        }
        let proof_bytes = self
            .service
            .accumulate_host()
            .blob(&proof.proof_blob)
            .ok_or(LocalRootTreeInvokeErrorV2::Schedule(
                ScheduleErrorV2::MissingBlob(proof.proof_blob.hash),
            ))?
            .to_vec();
        let package = CommittedAttestationPackageV2 {
            reply: AccumulatedReplyV2 {
                reply,
                receipt: publication.receipt.clone(),
                attestation: Some(Box::new(AttestationDeliveryV2 {
                    producer_name: descriptor.name,
                    producer: descriptor.producer,
                    statement,
                    proof,
                })),
            },
            proof_blob: ImportedBlobV2 {
                reference: proof_reference,
                bytes: proof_bytes,
            },
        };
        package
            .validate()
            .map_err(|_| LocalRootTreeInvokeErrorV2::InvalidAttestationPublication)?;
        Ok(package)
    }

    /// Finalized cross-root calls still present in the guest inbox. This is a
    /// read-only scheduling view; execution consumes the row and marks its
    /// delivery record through the physical Accumulate transaction.
    pub(crate) fn pending_inbox_calls(
        &self,
    ) -> Result<Vec<(super::CallId, u64)>, LocalRootTreeInvokeErrorV2> {
        self.service
            .accumulate_host()
            .pending_inbox_calls()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)
    }

    pub(crate) fn pending_ingresses(
        &self,
    ) -> Result<Vec<DirectIngressV2>, LocalRootTreeInvokeErrorV2> {
        self.service
            .accumulate_host()
            .pending_ingresses()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)
    }

    /// Recover the exact logical timeslot committed with a pending
    /// publication. Transport retries must reproduce the original delivery
    /// bytes; substituting a host clock would turn an exact retry into a
    /// divergent duplicate at destination Accumulate.
    pub(crate) fn publication_logical_timeslot(
        &self,
        publication: &PublicationRecordV2,
    ) -> Result<u64, LocalRootTreeInvokeErrorV2> {
        let checkpoint = self
            .service
            .accumulate_host()
            .workflow_checkpoint(publication.input.invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::DivergentReplay)?;
        if checkpoint.input != publication.input {
            return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
        }
        Ok(checkpoint.resume_work.logical_timeslot)
    }

    /// Reconstruct the caller of a pending callee reply from authenticated
    /// workflow state. A host restart must not need a process-local return
    /// route to retry a reply publication.
    pub(crate) fn publication_return_target(
        &self,
        publication: &PublicationRecordV2,
    ) -> Result<Option<(ActorId, super::InvocationId)>, LocalRootTreeInvokeErrorV2> {
        if publication.published.reply.is_none() {
            return Ok(None);
        }
        let checkpoint = self
            .service
            .accumulate_host()
            .workflow_checkpoint(publication.input.invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::DivergentReplay)?;
        return_target_from_checkpoint(&checkpoint, publication)
    }

    pub fn into_backend(self) -> B {
        let store = self.service.into_store();
        let (_, backend) = store.into_parts();
        backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_identity(byte: u8) -> ServiceIdentityV2 {
        ServiceIdentityV2 {
            space: super::super::SpaceId([1; 32]),
            root_service: super::super::RootServiceId([byte; 32]),
            deployment: super::super::DeploymentId([3; 32]),
            service_program: ProgramId([4; 32]),
            service_abi: super::super::ABI_VERSION,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        }
    }

    fn outbox_publication() -> (PublicationRecordV2, MessageRecordV2) {
        let invocation = super::super::InvocationId([5; 32]);
        let message = MessageRecordV2 {
            call_id: invocation.call_id(0),
            caller_invocation: invocation,
            await_ordinal: 0,
            from: ActorId([6; 32]),
            to: ActorId([7; 32]),
            parent: None,
            payload: vec![8],
            authorization: AuthorizationEvidenceV2::Public,
            proof_requested: false,
            deadline_timeslot: Some(20),
        };
        let input = WorkInputIdV2 {
            invocation,
            workflow_step: 0,
        };
        let receipt = AccumulationReceiptV2 {
            service: service_identity(2),
            accepted_transition: super::super::Hash([9; 32]),
            reply_commitment: None,
            outbox_commitment: MessageRecordV2::outbox_commitment(core::slice::from_ref(&message)),
            resulting_state_root: Some(super::super::Hash([10; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        };
        (
            PublicationRecordV2 {
                input,
                receipt,
                published: PublishedEffectsV2 {
                    outbox: vec![message.clone()],
                    ..PublishedEffectsV2::default()
                },
            },
            message,
        )
    }

    #[test]
    fn ingress_wire_is_strict_and_binds_invocation_identity() {
        let ingress = RootTreeInvocationV2 {
            invocation: super::super::InvocationId([1; 32]),
            logical_timeslot: 7,
            target: ActorId([2; 32]),
            method: "value".into(),
            arguments: vec![3],
            proof_requested: false,
        };
        let bytes = ingress.encode();
        assert_eq!(RootTreeInvocationV2::decode(&bytes).unwrap(), ingress);
        let mut trailing = bytes;
        trailing.push(0);
        assert!(RootTreeInvocationV2::decode(&trailing).is_err());

        let mut invalid = ingress;
        invalid.invocation = super::super::InvocationId::ZERO;
        assert!(RootTreeInvocationV2::decode(&invalid.encode()).is_err());
    }

    #[test]
    fn pending_reply_recovers_its_caller_from_the_durable_workflow() {
        let caller_invocation = super::super::InvocationId([21; 32]);
        let call = caller_invocation.call_id(3);
        let callee_invocation = super::super::InvocationId::for_call(call);
        let callee = ActorId([22; 32]);
        let caller = ActorId([23; 32]);
        let input = WorkInputIdV2 {
            invocation: callee_invocation,
            workflow_step: 0,
        };
        let state = BlobRefV2::of_bytes(&[]);
        let work = super::super::WorkEnvelopeV2 {
            service: service_identity(24),
            invocation: callee_invocation,
            workflow_step: 0,
            logical_timeslot: 9,
            target: callee,
            target_program: ProgramId([25; 32]),
            method: "value".into(),
            arguments: vec![26],
            origin: super::super::Origin::Actor(caller),
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: Some(caller_invocation),
            parent_call: Some(call),
            awaited_reply: None,
            awaited_timeout: None,
            consistency: ConsistencyModeV2::Local,
            base: super::super::ConsistencyBaseV2::Linear {
                revision: 1,
                state_root: super::super::Hash([27; 32]),
            },
            base_causal_height: None,
            imported_actors: vec![super::super::ImportedActorV2 {
                actor: callee,
                name: "callee".into(),
                parent: None,
                program: ProgramId([25; 32]),
                state,
                causal_states: vec![],
                continuation: None,
            }],
            external_actors: vec![],
            imported_blobs: vec![],
            proof_requested: false,
        };
        let reply = super::super::ReplyRecordV2 {
            call_id: call,
            producer: callee,
            result: vec![28],
        };
        let publication = PublicationRecordV2 {
            input,
            receipt: AccumulationReceiptV2 {
                service: work.service.clone(),
                accepted_transition: super::super::Hash([29; 32]),
                reply_commitment: Some(reply.commitment()),
                outbox_commitment: None,
                resulting_state_root: Some(super::super::Hash([30; 32])),
                resulting_crdt_heads: vec![],
                sequence: 2,
                checkpoint: 0,
                consistency: ConsistencyModeV2::Local,
            },
            published: PublishedEffectsV2 {
                reply: Some(reply.clone()),
                ..PublishedEffectsV2::default()
            },
        };
        let checkpoint = WorkflowCheckpointV2 {
            input,
            workflow_identity: work.workflow_identity(),
            work_hash: work.hash(),
            transition_commitment: publication.receipt.accepted_transition,
            resume_work: work,
            reply: Some(reply),
        };

        assert_eq!(
            return_target_from_checkpoint(&checkpoint, &publication).unwrap(),
            Some((caller, caller_invocation))
        );

        let mut divergent = publication;
        divergent.published.reply.as_mut().unwrap().call_id = caller_invocation.call_id(4);
        assert!(matches!(
            return_target_from_checkpoint(&checkpoint, &divergent),
            Err(LocalRootTreeInvokeErrorV2::DivergentReplay)
        ));
    }

    #[test]
    fn root_transport_carries_only_committed_canonical_publications() {
        let (publication, message) = outbox_publication();
        let delivery = RootTreeTransportV2::OutboxDelivery {
            logical_timeslot: 11,
            publication: publication.clone(),
            message: message.clone(),
        };
        assert_eq!(
            RootTreeTransportV2::decode(&delivery.encode()).unwrap(),
            delivery
        );

        let mut checkpoint_publication = publication.clone();
        checkpoint_publication
            .published
            .exported_blobs
            .push(super::super::BlobRefV2::of_bytes(b"source continuation"));
        let checkpoint_delivery = RootTreeTransportV2::OutboxDelivery {
            logical_timeslot: 11,
            publication: checkpoint_publication,
            message: message.clone(),
        };
        assert_eq!(
            RootTreeTransportV2::decode(&checkpoint_delivery.encode()).unwrap(),
            checkpoint_delivery,
            "source-owned checkpoint blobs may coexist with a durable outbox record"
        );

        let accepted = RootTreeTransportV2::PublicationAccepted {
            input: publication.input,
            publication: publication.commitment(),
            call: message.call_id,
        };
        assert_eq!(
            RootTreeTransportV2::decode(&accepted.encode()).unwrap(),
            accepted
        );

        let mut unrelated = message;
        unrelated.call_id = super::super::CallId([12; 32]);
        let invalid = RootTreeTransportV2::OutboxDelivery {
            logical_timeslot: 11,
            publication,
            message: unrelated,
        };
        assert!(RootTreeTransportV2::decode(&invalid.encode()).is_err());
    }
}
