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
    AccumulateRequestV2, AccumulationEnvelopeV2, AccumulationReceiptV2, AccumulationRejectionV2,
    AccumulationResultV2, ActorDirectoryV2, ActorGenesisV2, ActorId, AuthorizationEvidenceV2,
    BlobRefV2, CommittedImageStoreV2, ConsistencyModeV2, CrdtChangeV2, DedupRecordV2,
    DurableJamStoreV2, DurableStoreOpenErrorV2, ExternalActorBindingV2, ExternalActorDirectoryV2,
    JamServiceV2, LocalStoreReadErrorV2, LocalWorkRequestV2, LocalWorkSchedulerV2, MethodPolicyV2,
    NoRefineProtocolHostV2, PackageError, PackageRolePoliciesV2, ProgramId, PublicationAckV2,
    PublicationRecordV2, PublishedEffectsV2, ScheduleErrorV2, ServiceDispatchError,
    ServiceGenesisV2, ServiceIdentityV2, StateKeyV2, V2Wire, VosPackageV2, WorkInputIdV2,
    WorkflowCheckpointV2, crdt_node_storage_key, dedup_storage_key,
};

/// Strict host ingress for one direct invocation of a registered v2 root.
///
/// The payload remains the canonical actor message wire
/// (`TAG_DYNAMIC ++ rkyv(Msg)`). This outer envelope preserves the full
/// canonical actor identity and invocation identity until the root service
/// constructs its [`super::WorkEnvelopeV2`].
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
    PackageSignatureVerifierUnavailable,
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
    Rejected(AccumulationRejectionV2),
    UnexpectedResult,
    CorruptStore(LocalStoreReadErrorV2),
    CorruptWorkflow,
    DivergentInvocation,
    MissingPublication,
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

/// A durable local host for exactly one logical JAM service/root actor tree.
pub struct LocalRootTreeServiceV2<B> {
    service: JamServiceV2<NoRefineProtocolHostV2, DurableJamStoreV2<B>>,
    identity: ServiceIdentityV2,
    root_actor: ActorId,
}

fn verify_package_signature(package: &VosPackageV2) -> Result<(), LocalRootTreeConfigErrorV2> {
    #[cfg(feature = "network")]
    {
        let public_key = libp2p::identity::PublicKey::try_decode_protobuf(
            &package.deployment_signature.public_key,
        )
        .map_err(|_| LocalRootTreeConfigErrorV2::InvalidPackageSignature)?;
        if !public_key.verify(
            &package.signing_message(),
            &package.deployment_signature.signature,
        ) {
            return Err(LocalRootTreeConfigErrorV2::InvalidPackageSignature);
        }
        Ok(())
    }
    #[cfg(not(feature = "network"))]
    {
        // Signature verification must never degrade into the structural
        // package check when the native verifier is unavailable.
        let _ = package;
        Err(LocalRootTreeConfigErrorV2::PackageSignatureVerifierUnavailable)
    }
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
        if self.consistency == ConsistencyModeV2::Raft {
            return Err(LocalRootTreeConfigErrorV2::ReplicationDriverRequired);
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

impl<B: CommittedImageStoreV2> LocalRootTreeServiceV2<B> {
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
    ) -> Result<Self, LocalRootTreeOpenErrorV2<B::Error>> {
        let (expected_root, genesis) = config
            .installation()
            .map_err(LocalRootTreeOpenErrorV2::InvalidConfig)?;
        let store = DurableJamStoreV2::open(backend).map_err(LocalRootTreeOpenErrorV2::Store)?;
        let header = store
            .header()
            .map_err(LocalRootTreeOpenErrorV2::CorruptStore)?;
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

        if let Some(header) = header {
            if header.service != config.service || header.consistency != config.consistency {
                return Err(LocalRootTreeOpenErrorV2::ExistingServiceMismatch);
            }
            if service
                .accumulate_host()
                .program(config.package.manifest.actor_program)
                .is_none()
            {
                return Err(LocalRootTreeOpenErrorV2::MissingInstalledProgram(
                    config.package.manifest.actor_program,
                ));
            }
            let directory = service
                .accumulate_host()
                .state_row(header.service_root, &StateKeyV2::ActorDirectory)
                .map_err(LocalRootTreeOpenErrorV2::CorruptStore)?
                .and_then(|bytes| ActorDirectoryV2::decode(&bytes).ok());
            if directory
                .as_ref()
                .is_none_or(|directory| directory.actors.binary_search(&config.root_actor).is_err())
            {
                return Err(LocalRootTreeOpenErrorV2::ExistingActorMismatch);
            }
            let descriptor = service
                .accumulate_host()
                .state_row(
                    header.service_root,
                    &StateKeyV2::ActorDescriptor(config.root_actor),
                )
                .map_err(LocalRootTreeOpenErrorV2::CorruptStore)?
                .and_then(|bytes| ActorGenesisV2::decode(&bytes).ok());
            let external = service
                .accumulate_host()
                .state_row(header.service_root, &StateKeyV2::ExternalActorDirectory)
                .map_err(LocalRootTreeOpenErrorV2::CorruptStore)?
                .and_then(|bytes| ExternalActorDirectoryV2::decode(&bytes).ok());
            if descriptor.as_ref() != Some(&expected_root)
                || external.as_ref().is_none_or(|directory| {
                    directory.actors.as_slice() != config.external_actors.as_slice()
                })
            {
                return Err(LocalRootTreeOpenErrorV2::ExistingActorMismatch);
            }
        } else {
            let initial = service
                .accumulate_host_mut()
                .import_blob(config.initial_state);
            if initial != expected_root.initial_state {
                return Err(LocalRootTreeOpenErrorV2::ExistingActorMismatch);
            }
            let imported_program = service
                .accumulate_host_mut()
                .import_program(config.package.actor_pvm);
            if imported_program != expected_root.program {
                return Err(LocalRootTreeOpenErrorV2::InvalidConfig(
                    LocalRootTreeConfigErrorV2::InvalidPackage(PackageError::ProgramIdMismatch),
                ));
            }
            service.accumulate_host_mut().allow_install(&genesis);
            match service
                .accumulate(&AccumulateRequestV2::Install(genesis))
                .map_err(LocalRootTreeOpenErrorV2::Service)?
                .result
            {
                AccumulationResultV2::Installed(_) => {}
                AccumulationResultV2::Rejected(rejection) => {
                    return Err(LocalRootTreeOpenErrorV2::InstallRejected(rejection));
                }
                _ => return Err(LocalRootTreeOpenErrorV2::UnexpectedInstallResult),
            }
        }

        Ok(Self {
            service,
            identity: config.service,
            root_actor: config.root_actor,
        })
    }

    pub fn identity(&self) -> &ServiceIdentityV2 {
        &self.identity
    }

    pub const fn root_actor(&self) -> ActorId {
        self.root_actor
    }

    pub fn store(&self) -> &DurableJamStoreV2<B> {
        self.service.accumulate_host()
    }

    pub fn store_mut(&mut self) -> &mut DurableJamStoreV2<B> {
        self.service.accumulate_host_mut()
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
            .refine_actor_tree(&prepared.work, &prepared.imports)
            .map_err(LocalRootTreeInvokeErrorV2::Service)?;
        let input = prepared.work.input_id();
        let accumulated = self
            .service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: prepared.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            }))
            .map_err(LocalRootTreeInvokeErrorV2::Service)?;
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

    /// Remove a committed publication only after its external consumer has
    /// accepted the exact reply/outbox/proof package.
    pub fn acknowledge_publication(
        &mut self,
        publication: &PublicationRecordV2,
    ) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        let result = self
            .service
            .accumulate(&AccumulateRequestV2::AcknowledgePublication(
                PublicationAckV2 {
                    service: self.identity.clone(),
                    input: publication.input,
                    publication: publication.commitment(),
                },
            ))
            .map_err(LocalRootTreeInvokeErrorV2::Service)?;
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

    pub fn into_backend(self) -> B {
        let (_, store) = self.service.into_hosts();
        let (_, backend) = store.into_parts();
        backend
    }
}

#[cfg(test)]
mod tests {
    use super::super::InvocationId;
    use super::*;

    #[test]
    fn root_tree_invocation_wire_is_strict_and_canonical() {
        let invocation = RootTreeInvocationV2 {
            invocation: InvocationId([1; 32]),
            logical_timeslot: 7,
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
}
