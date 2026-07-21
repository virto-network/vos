//! Durable local ownership of one v2 root actor tree.
//!
//! This is host orchestration, not an alternate actor runtime. Installation,
//! transition validation, state mutation, deduplication, and publication
//! acknowledgement all enter the canonical generic service at physical IC-5.
//! The host prepares Refine imports only from committed guest state and makes
//! effects visible only after the configured image store accepts the complete
//! post-Accumulate image.

use alloc::string::String;
use alloc::vec::Vec;

use super::wire::{DecodeError, Decoder, Encoder};
use super::{
    AccumulateRequestV2, AccumulatedServiceOutputV2, AccumulationEnvelopeV2, AccumulationReceiptV2,
    AccumulationRejectionV2, AccumulationResultV2, ActorDirectoryV2, ActorGenesisV2, ActorId,
    AuthorizationEvidenceV2, BlobRefV2, CommittedImageStoreV2, ConsistencyModeV2,
    ContinuationSnapshotV2, CrdtChangeV2, CrdtSyncEnvelopeV2, DedupRecordV2, DirectIngressV2,
    DurableJamStoreV2, DurableStoreOpenErrorV2, ExternalActorBindingV2, ExternalActorDirectoryV2,
    JamServiceV2, LocalJamStoreHostV2, LocalJamStoreV2, LocalStoreReadErrorV2, LocalWorkRequestV2,
    LocalWorkSchedulerV2, MethodPolicyV2, NoRefineProtocolHostV2, PackageError,
    PackageRolePoliciesV2, ProgramId, ProofArtifactStoreV2, PublicationAckV2, PublicationRecordV2,
    PublishedEffectsV2, ReceiptVerificationRequestV2, RefinedServiceOutputV2, ScheduleErrorV2,
    ServiceDispatchError, ServiceGenesisV2, ServiceIdentityV2, StateKeyV2, V2Wire, VosPackageV2,
    WorkInputIdV2, WorkflowCheckpointV2, crdt_node_storage_key, dedup_storage_key,
};

#[cfg(feature = "storage")]
use super::{ReplicatedJamServiceV2, ReplicatedServiceErrorV2};
#[cfg(feature = "storage")]
use crate::commit::CommitError;
#[cfg(feature = "storage")]
use crate::raft::RaftAccumulateLogV2;

/// Strict host ingress for one direct invocation of a registered v2 root.
///
/// The payload remains the canonical actor message wire
/// (`TAG_DYNAMIC ++ rkyv(Msg)`). This outer envelope preserves the full
/// canonical actor identity and invocation identity until the root service
/// constructs its [`super::WorkEnvelopeV2`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootTreeInvocationV2 {
    pub invocation: super::InvocationId,
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
        encoder.fixed(&self.target.0);
        encoder.string(&self.method);
        encoder.bytes(&self.arguments);
        encoder.bool(self.proof_requested);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            invocation: super::InvocationId(decoder.fixed()?),
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

fn direct_ingress_from_request(
    store: &LocalJamStoreV2,
    service: &ServiceIdentityV2,
    request: &LocalWorkRequestV2,
) -> Result<DirectIngressV2, LocalRootTreeInvokeErrorV2> {
    if request.workflow_step != 0
        || request.causal_parent.is_some()
        || request.parent_call.is_some()
        || request.causal_context.is_some()
        || request.awaited_reply.is_some()
        || request.awaited_timeout.is_some()
    {
        return Err(LocalRootTreeInvokeErrorV2::DivergentInvocation);
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
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: ingress.imported_blobs,
        proof_requested: ingress.proof_requested,
    }
}

/// Complete immutable installation input for one locally hosted root tree.
///
/// `external_actors` is authenticated by the installation authority. A later
/// package-format batch may additionally bind dependency declarations into
/// `DeploymentId`; this host never invents or rewrites those bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRootTreeConfigV2 {
    pub service_pvm: Vec<u8>,
    pub package: VosPackageV2,
    pub service: ServiceIdentityV2,
    pub root_actor: ActorId,
    pub actor_name: String,
    pub consistency: ConsistencyModeV2,
    pub initial_state: Vec<u8>,
    pub external_actors: Vec<ExternalActorBindingV2>,
    pub install_authorization: AuthorizationEvidenceV2,
    pub refine_gas: u64,
    pub accumulate_gas: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRootTreeConfigErrorV2 {
    InvalidPackage(PackageError),
    InvalidPackageSignature,
    InvalidActorProgramLayout,
    InvalidGenesis,
    WrongDeployment,
    WrongServiceProgram,
    WrongServiceAbi,
    WrongExecutionSemantics,
    InvalidConsistency,
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

impl<E: core::fmt::Debug> core::fmt::Display for LocalRootTreeOpenErrorV2<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cannot open VOS v2 root tree: {self:?}")
    }
}

impl<E: core::fmt::Debug> core::error::Error for LocalRootTreeOpenErrorV2<E> {}

#[derive(Debug)]
pub enum LocalRootTreeInvokeErrorV2 {
    ProofProducerRequired,
    Schedule(ScheduleErrorV2),
    Service(ServiceDispatchError),
    #[cfg(feature = "storage")]
    Replication(ReplicatedServiceErrorV2<CommitError>),
    Rejected(AccumulationRejectionV2),
    UnexpectedResult,
    CorruptStore(LocalStoreReadErrorV2),
    CorruptWorkflow,
    DivergentInvocation,
    MissingPublication,
    ServiceNotInstalled,
    ExistingServiceMismatch,
    ExistingActorMismatch,
    MissingInstalledProgram(ProgramId),
}

impl core::fmt::Display for LocalRootTreeInvokeErrorV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cannot invoke VOS v2 root tree: {self:?}")
    }
}

impl core::error::Error for LocalRootTreeInvokeErrorV2 {}

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

/// Result of importing an authenticated causal delta through physical IC-5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedCrdtSyncV2 {
    pub receipt: AccumulationReceiptV2,
    pub duplicate: bool,
    pub accumulate_gas_used: u64,
}

/// Durable disposition of a retried direct root invocation.
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
    Completed,
}

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

impl<B> RootTreeServiceDriverV2<B>
where
    B: CommittedImageStoreV2 + ProofArtifactStoreV2<Error = <B as CommittedImageStoreV2>::Error>,
{
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

    /// Establish the Raft current-term barrier and apply through it. Direct
    /// services have no promotion boundary and are already authoritative.
    fn admission_barrier(&mut self) -> Result<(), RootTreeDriverErrorV2> {
        match self {
            Self::Direct(_) => Ok(()),
            #[cfg(feature = "storage")]
            Self::Raft(service) => service
                .leadership_barrier_and_catch_up()
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

    fn refine_actor_tree_after_barrier(
        &self,
        work: &super::WorkEnvelopeV2,
        imports: &super::RefineImportsV2,
    ) -> Result<RefinedServiceOutputV2, RootTreeDriverErrorV2> {
        match self {
            Self::Direct(service) => service
                .refine_actor_tree(work, imports)
                .map_err(RootTreeDriverErrorV2::Direct),
            #[cfg(feature = "storage")]
            Self::Raft(service) => service
                .refine_actor_tree_after_barrier(work, imports)
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

    fn accumulate_after_barrier(
        &mut self,
        request: &AccumulateRequestV2,
    ) -> Result<AccumulatedServiceOutputV2, RootTreeDriverErrorV2> {
        match self {
            Self::Direct(service) => service
                .accumulate(request)
                .map_err(RootTreeDriverErrorV2::Direct),
            #[cfg(feature = "storage")]
            Self::Raft(service) => service
                .accumulate_after_barrier(request)
                .map_err(RootTreeDriverErrorV2::Raft),
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

/// A durable local host for exactly one logical JAM service/root actor tree.
pub struct LocalRootTreeServiceV2<B> {
    service: RootTreeServiceDriverV2<B>,
    identity: ServiceIdentityV2,
    root_actor: ActorId,
    consistency: ConsistencyModeV2,
    genesis: ServiceGenesisV2,
    expected_root: ActorGenesisV2,
    expected_external_actors: Vec<ExternalActorBindingV2>,
}

fn verify_ed25519_signature(public_key_wire: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // `.vos` v2 deployment keys are the canonical libp2p Ed25519 public-key
    // protobuf: field 1 = key type 1, field 2 = exactly 32 key bytes. Decode
    // this tiny frozen wire locally so a bare std host does not need the
    // network stack (and so no host-only dependency enters canonical guests).
    let Some(public_key) = public_key_wire
        .strip_prefix(&[0x08, 0x01, 0x12, 0x20])
        .and_then(|bytes| <&[u8; 32]>::try_from(bytes).ok())
    else {
        return false;
    };
    let provider = futures_rustls::rustls::crypto::ring::default_provider();
    let Some(verifier) = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(scheme, _)| *scheme == futures_rustls::rustls::SignatureScheme::ED25519)
        .and_then(|(_, algorithms)| algorithms.first())
    else {
        return false;
    };
    verifier
        .verify_signature(public_key, message, signature)
        .is_ok()
}

fn verify_package_signature(package: &VosPackageV2) -> Result<(), LocalRootTreeConfigErrorV2> {
    verify_ed25519_signature(
        &package.deployment_signature.public_key,
        &package.signing_message(),
        &package.deployment_signature.signature,
    )
    .then_some(())
    .ok_or(LocalRootTreeConfigErrorV2::InvalidPackageSignature)
}

impl LocalRootTreeConfigV2 {
    fn installation(
        &self,
    ) -> Result<(ActorGenesisV2, ServiceGenesisV2), LocalRootTreeConfigErrorV2> {
        self.package
            .validate()
            .map_err(LocalRootTreeConfigErrorV2::InvalidPackage)?;
        verify_package_signature(&self.package)?;
        super::validate_actor_program_layout(&self.package.actor_pvm)
            .map_err(|_| LocalRootTreeConfigErrorV2::InvalidActorProgramLayout)?;
        if self.root_actor == ActorId::ZERO {
            return Err(LocalRootTreeConfigErrorV2::InvalidGenesis);
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
        if self.refine_gas == 0 || self.accumulate_gas == 0 {
            return Err(LocalRootTreeConfigErrorV2::ZeroGas);
        }

        let descriptor = self
            .package
            .actor_genesis(
                self.root_actor,
                self.actor_name.clone(),
                None,
                BlobRefV2::of_bytes(&self.initial_state),
            )
            .map_err(LocalRootTreeConfigErrorV2::InvalidPackage)?;
        let genesis = ServiceGenesisV2 {
            service: self.service.clone(),
            consistency: self.consistency,
            actors: vec![descriptor.clone()],
            external_actors: self.external_actors.clone(),
            authorization: self.install_authorization.clone(),
        };
        ServiceGenesisV2::decode(&genesis.encode())
            .map_err(|_| LocalRootTreeConfigErrorV2::InvalidGenesis)?;
        Ok((descriptor, genesis))
    }

    pub fn validate(&self) -> Result<(), LocalRootTreeConfigErrorV2> {
        self.installation().map(|_| ())
    }
}

impl<B> LocalRootTreeServiceV2<B>
where
    B: CommittedImageStoreV2 + ProofArtifactStoreV2<Error = <B as CommittedImageStoreV2>::Error>,
{
    fn recover_committed_invocation(
        &self,
        request: &LocalWorkRequestV2,
    ) -> Result<Option<CommittedRootTreeSliceV2>, LocalRootTreeInvokeErrorV2> {
        let header = self
            .service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        let Some(bytes) = self
            .service
            .accumulate_host()
            .state_row(
                header.service_root,
                &StateKeyV2::Workflow(request.invocation),
            )
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
        else {
            return Ok(None);
        };
        let checkpoint = WorkflowCheckpointV2::decode(&bytes)
            .map_err(|_| LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        let committed = &checkpoint.resume_work;
        let exact_ingress = request.workflow_step == 0
            && checkpoint.input.workflow_step == 0
            && checkpoint.input.invocation == request.invocation
            && committed.invocation == request.invocation
            && committed.target == request.target
            && committed.method == request.method
            && committed.arguments == request.arguments
            && committed.origin == request.origin
            && committed.authorization == request.authorization
            && committed.causal_parent == request.causal_parent
            && committed.parent_call == request.parent_call
            && committed.causal_context == request.causal_context
            && request.awaited_reply.is_none()
            && request.awaited_timeout.is_none()
            && committed.imported_blobs == request.imported_blobs
            && committed.proof_requested == request.proof_requested;
        // Deliberately do not compare `logical_timeslot`: the node stamps a
        // fresh trusted admission slot on every attempt. The authenticated
        // checkpoint/dedup bridge below retains the original committed work
        // hash (and therefore its original slot), so an exact retry reattaches
        // that result while divergent invocation reuse is still rejected.
        if !exact_ingress {
            return Err(LocalRootTreeInvokeErrorV2::DivergentInvocation);
        }

        let dedup = self
            .service
            .accumulate_host()
            .row(&dedup_storage_key(checkpoint.input))
            .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)
            .and_then(|bytes| {
                DedupRecordV2::decode(bytes)
                    .map_err(|_| LocalRootTreeInvokeErrorV2::CorruptWorkflow)
            })?;
        if dedup.input != checkpoint.input
            || dedup.receipt.service != self.identity
            || dedup.receipt.consistency != header.consistency
        {
            return Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow);
        }
        // Linear workflow rows retain the admitted work and transition hashes
        // directly. A CRDT workflow row is reconstructed from its normalized
        // DAG checkpoint, so authenticate the bridge through the checkpoint's
        // content-addressed change: that node retains the admitted work hash
        // and its CID is committed as a resulting receipt head.
        let checkpoint_is_bound = if header.consistency == ConsistencyModeV2::Crdt {
            let change = self
                .service
                .accumulate_host()
                .row(&crdt_node_storage_key(checkpoint.transition_hash))
                .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)
                .and_then(|bytes| {
                    CrdtChangeV2::decode(bytes)
                        .map_err(|_| LocalRootTreeInvokeErrorV2::CorruptWorkflow)
                })?;
            change.cid() == checkpoint.transition_hash
                && change.work_hash == dedup.work_hash
                && dedup
                    .receipt
                    .resulting_crdt_heads
                    .binary_search(&checkpoint.transition_hash)
                    .is_ok()
        } else {
            checkpoint.work_hash == dedup.work_hash
                && checkpoint.transition_hash == dedup.transition_commitment
        };
        if !checkpoint_is_bound {
            return Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow);
        }
        let publication = self
            .service
            .accumulate_host()
            .pending_publications()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .into_iter()
            .find(|publication| publication.input == checkpoint.input);
        if publication
            .as_ref()
            .is_some_and(|publication| publication.receipt != dedup.receipt)
        {
            return Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow);
        }
        Ok(Some(CommittedRootTreeSliceV2 {
            input: checkpoint.input,
            receipt: dedup.receipt,
            published: publication
                .as_ref()
                .map_or_else(PublishedEffectsV2::default, |row| row.published.clone()),
            publication,
            duplicate: true,
            refine_gas_used: 0,
            accumulate_gas_used: 0,
        }))
    }

    /// Open a committed service image or install a new root through physical
    /// Accumulate when the backing store is empty.
    pub fn open(
        config: LocalRootTreeConfigV2,
        backend: B,
    ) -> Result<Self, LocalRootTreeOpenErrorV2<<B as CommittedImageStoreV2>::Error>> {
        if config.consistency == ConsistencyModeV2::Raft {
            return Err(LocalRootTreeOpenErrorV2::InvalidConfig(
                LocalRootTreeConfigErrorV2::ReplicationDriverRequired,
            ));
        }
        Self::open_with_driver(config, backend, RootTreeDriverConfigV2::Direct)
    }

    /// Open a Raft root tree whose genesis and every later mutation are
    /// committed as canonical IC-5 request bytes before local application.
    #[cfg(feature = "storage")]
    pub fn open_raft(
        config: LocalRootTreeConfigV2,
        backend: B,
        log: RaftAccumulateLogV2,
    ) -> Result<Self, LocalRootTreeOpenErrorV2<<B as CommittedImageStoreV2>::Error>> {
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
    ) -> Result<Self, LocalRootTreeOpenErrorV2<<B as CommittedImageStoreV2>::Error>> {
        let (expected_root, genesis) = config
            .installation()
            .map_err(LocalRootTreeOpenErrorV2::InvalidConfig)?;
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

        if needs_imports {
            let initial = service
                .accumulate_host_mut()
                .import_blob(config.initial_state.clone());
            if initial != expected_root.initial_state {
                return Err(LocalRootTreeOpenErrorV2::ExistingActorMismatch);
            }
            let imported_program = service
                .accumulate_host_mut()
                .import_program(config.package.actor_pvm.clone());
            if imported_program != expected_root.program {
                return Err(LocalRootTreeOpenErrorV2::InvalidConfig(
                    LocalRootTreeConfigErrorV2::InvalidPackage(PackageError::ProgramIdMismatch),
                ));
            }
        }
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
            expected_root,
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

    pub const fn consistency(&self) -> ConsistencyModeV2 {
        self.consistency
    }

    pub fn store(&self) -> &DurableJamStoreV2<B> {
        self.service.accumulate_host()
    }

    pub fn store_mut(&mut self) -> &mut DurableJamStoreV2<B> {
        self.service.accumulate_host_mut()
    }

    /// Classify a direct invocation retry from guest-authenticated ingress,
    /// workflow, publication, and continuation state.
    pub fn recover_ingress(
        &self,
        request: &LocalWorkRequestV2,
    ) -> Result<RootTreeIngressRecoveryV2, LocalRootTreeInvokeErrorV2> {
        let candidate = direct_ingress_from_request(
            self.service.accumulate_host().local_store(),
            &self.identity,
            request,
        )?;
        let checkpoint = self
            .service
            .accumulate_host()
            .workflow_checkpoint(request.invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?;
        let ingress = self
            .service
            .accumulate_host()
            .ingress_record(request.invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?;

        if checkpoint.is_none() {
            return match ingress {
                None => Ok(RootTreeIngressRecoveryV2::Fresh),
                Some(record) if !record.consumed && record.ingress.matches_retry(&candidate) => {
                    Ok(RootTreeIngressRecoveryV2::Queued {
                        logical_timeslot: record.ingress.logical_timeslot,
                    })
                }
                Some(_) => Err(LocalRootTreeInvokeErrorV2::DivergentInvocation),
            };
        }
        if ingress
            .as_ref()
            .is_none_or(|record| !record.consumed || !record.ingress.matches_retry(&candidate))
        {
            return Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow);
        }

        let committed = self
            .recover_committed_invocation(request)?
            .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        let Some(checkpoint) = checkpoint else {
            return Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow);
        };
        if let Some(publication) = committed.publication {
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
            .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
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
            return Ok(RootTreeIngressRecoveryV2::Completed);
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
            return Ok(RootTreeIngressRecoveryV2::Completed);
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

    /// Apply every committed Raft request not yet present in this replica's
    /// physical service image. Direct Local/CRDT owners are already current.
    /// A follower may remain uninstalled until the leader commits genesis.
    pub fn catch_up(&mut self) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        self.ensure_installed()
    }

    /// Establish the current-term admission barrier and return the durable
    /// service high-water visible after applying through it. Node ingress must
    /// restore and allocate its trusted timeslot from this value, then call
    /// [`Self::invoke_after_admission_barrier`] without another catch-up.
    pub(crate) fn prepare_admission_barrier(&mut self) -> Result<u64, LocalRootTreeInvokeErrorV2> {
        self.service
            .admission_barrier()
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        if !self.validate_installed()? {
            if !self.service.is_writable() {
                return Err(LocalRootTreeInvokeErrorV2::ServiceNotInstalled);
            }
            // Genesis installation, when this replica has just become the
            // first writable leader, is ordered after the same barrier and
            // before any actor admission slot exists. Use the no-catch-up path
            // so the ordering remains one contiguous critical sequence.
            let result = self
                .service
                .accumulate_after_barrier(&AccumulateRequestV2::Install(self.genesis.clone()))
                .map_err(RootTreeDriverErrorV2::into_invoke)?;
            match result.result {
                AccumulationResultV2::Installed(_) => {}
                AccumulationResultV2::Rejected(rejection) => {
                    return Err(LocalRootTreeInvokeErrorV2::Rejected(rejection));
                }
                _ => return Err(LocalRootTreeInvokeErrorV2::UnexpectedResult),
            }
            if !self.validate_installed()? {
                return Err(LocalRootTreeInvokeErrorV2::ServiceNotInstalled);
            }
        }
        self.service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .map(|header| header.admission_timeslot_high_water)
            .ok_or(LocalRootTreeInvokeErrorV2::ServiceNotInstalled)
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
        if self
            .service
            .accumulate_host()
            .program(self.expected_root.program)
            .is_none()
        {
            return Err(LocalRootTreeInvokeErrorV2::MissingInstalledProgram(
                self.expected_root.program,
            ));
        }
        let directory = self
            .service
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::ActorDirectory)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .and_then(|bytes| ActorDirectoryV2::decode(&bytes).ok());
        if directory
            .as_ref()
            .is_none_or(|directory| directory.actors.binary_search(&self.root_actor).is_err())
        {
            return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
        }
        let descriptor = self
            .service
            .accumulate_host()
            .state_row(
                header.service_root,
                &StateKeyV2::ActorDescriptor(self.root_actor),
            )
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .and_then(|bytes| ActorGenesisV2::decode(&bytes).ok());
        let external = self
            .service
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::ExternalActorDirectory)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .and_then(|bytes| ExternalActorDirectoryV2::decode(&bytes).ok());
        if descriptor.as_ref() != Some(&self.expected_root)
            || external.as_ref().is_none_or(|directory| {
                directory.actors.as_slice() != self.expected_external_actors.as_slice()
            })
        {
            return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
        }
        Ok(true)
    }

    /// Read one installed method policy from the canonical signed artifact
    /// retained in guest-owned actor state.
    pub fn root_method_policy(
        &self,
        method: &str,
    ) -> Result<Option<MethodPolicyV2>, LocalRootTreeInvokeErrorV2> {
        let header = self
            .service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        let descriptor = self
            .service
            .accumulate_host()
            .state_row(
                header.service_root,
                &StateKeyV2::ActorDescriptor(self.root_actor),
            )
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .and_then(|bytes| ActorGenesisV2::decode(&bytes).ok())
            .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        let policies = PackageRolePoliciesV2::decode(&descriptor.role_policies)
            .map_err(|_| LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        Ok(policies
            .methods
            .binary_search_by(|candidate| candidate.method.as_str().cmp(method))
            .ok()
            .map(|index| policies.methods[index].clone()))
    }

    /// Execute one ordinary slice. Attested work requires a configured proof
    /// producer and uses the separate proof-before-Accumulate path.
    pub fn invoke(
        &mut self,
        request: LocalWorkRequestV2,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        self.prepare_admission_barrier()?;
        self.invoke_after_admission_barrier(request)
    }

    /// Admit and execute ingress after [`Self::prepare_admission_barrier`]
    /// returned and the caller allocated a slot above its high-water.
    pub(crate) fn invoke_after_admission_barrier(
        &mut self,
        request: LocalWorkRequestV2,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        if let Some(committed) = self.recover_committed_invocation(&request)? {
            return Ok(committed);
        }
        let invocation = request.invocation;
        self.admit_ingress_after_barrier(&request)?;
        self.invoke_admitted_after_barrier(invocation)
    }

    /// Persist one direct invocation through guest Accumulate before Refine.
    pub fn admit_ingress(
        &mut self,
        request: &LocalWorkRequestV2,
    ) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        self.prepare_admission_barrier()?;
        self.admit_ingress_after_barrier(request)
    }

    pub(crate) fn admit_ingress_after_barrier(
        &mut self,
        request: &LocalWorkRequestV2,
    ) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        let ingress = direct_ingress_from_request(
            self.service.accumulate_host().local_store(),
            &self.identity,
            request,
        )?;
        let accumulated = self
            .service
            .accumulate_after_barrier(&AccumulateRequestV2::AdmitIngress(ingress))
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
        self.prepare_admission_barrier()?;
        self.invoke_admitted_after_barrier(invocation)
    }

    pub(crate) fn invoke_admitted_after_barrier(
        &mut self,
        invocation: super::InvocationId,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        let record = self
            .service
            .accumulate_host()
            .ingress_record(invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        if record.consumed {
            return Err(LocalRootTreeInvokeErrorV2::DivergentInvocation);
        }
        self.execute_admitted_after_barrier(request_from_direct_ingress(record.ingress))
    }

    fn execute_admitted_after_barrier(
        &mut self,
        request: LocalWorkRequestV2,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        if request.proof_requested {
            return Err(LocalRootTreeInvokeErrorV2::ProofProducerRequired);
        }
        if let Some(committed) = self.recover_committed_invocation(&request)? {
            return Ok(committed);
        }
        let prepared = LocalWorkSchedulerV2::prepare(self.service.accumulate_host(), request)
            .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        let refined = self
            .service
            .refine_actor_tree_after_barrier(&prepared.work, &prepared.imports)
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        let input = prepared.work.input_id();
        let accumulated = self
            .service
            .accumulate_after_barrier(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
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
        LocalWorkSchedulerV2::prepare_crdt_sync(self.service.accumulate_host().local_store())
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
            let expected_producer = node
                .change
                .expected_producer()
                .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
            self.service
                .accumulate_host_mut()
                .allow_receipt(&ReceiptVerificationRequestV2 {
                    expected_producer,
                    receipt: node.receipt.clone(),
                });
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

    /// Remove a committed publication only after its external consumer has
    /// accepted the exact reply/outbox/proof package.
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

    pub fn pending_ingresses(&self) -> Result<Vec<DirectIngressV2>, LocalRootTreeInvokeErrorV2> {
        self.service
            .accumulate_host()
            .pending_ingresses()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)
    }

    pub fn into_backend(self) -> B {
        let store = self.service.into_store();
        let (_, backend) = store.into_parts();
        backend
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::super::InvocationId;
    use super::*;

    #[test]
    fn root_tree_invocation_wire_is_strict_and_canonical() {
        let invocation = RootTreeInvocationV2 {
            invocation: InvocationId([1; 32]),
            target: ActorId([2; 32]),
            method: "increment".into(),
            arguments: vec![crate::value::TAG_DYNAMIC, 3, 4],
            proof_requested: false,
        };
        let encoded = invocation.encode();
        assert_eq!(RootTreeInvocationV2::decode(&encoded).unwrap(), invocation);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            RootTreeInvocationV2::decode(&trailing),
            Err(DecodeError::TrailingBytes)
        );

        for invalid in [
            RootTreeInvocationV2 {
                invocation: InvocationId::ZERO,
                ..invocation.clone()
            },
            RootTreeInvocationV2 {
                target: ActorId::ZERO,
                ..invocation.clone()
            },
            RootTreeInvocationV2 {
                method: String::new(),
                ..invocation.clone()
            },
            RootTreeInvocationV2 {
                arguments: Vec::new(),
                ..invocation.clone()
            },
        ] {
            assert_eq!(
                RootTreeInvocationV2::decode(&invalid.encode()),
                Err(DecodeError::NonCanonical)
            );
        }
    }

    #[test]
    fn native_std_signature_verifier_does_not_require_network_transport() {
        let signing = SigningKey::from_bytes(&[0x33; 32]);
        let message = b"signed package identity";
        let mut public_key_wire = vec![0x08, 0x01, 0x12, 0x20];
        public_key_wire.extend_from_slice(signing.verifying_key().as_bytes());
        let signature = signing.sign(message).to_bytes();
        assert!(verify_ed25519_signature(
            &public_key_wire,
            message,
            &signature
        ));

        let mut forged = signature;
        forged[0] ^= 0x80;
        assert!(!verify_ed25519_signature(
            &public_key_wire,
            message,
            &forged
        ));
        public_key_wire.push(0);
        assert!(!verify_ed25519_signature(
            &public_key_wire,
            message,
            &signature
        ));
    }
}
