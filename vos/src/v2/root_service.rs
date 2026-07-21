//! Durable local ownership of one v2 root actor tree.
//!
//! This is host orchestration, not an alternate actor runtime. Installation,
//! transition validation, state mutation, deduplication, and publication
//! acknowledgement all enter the canonical generic service at physical IC-5.
//! The host prepares Refine imports from committed guest state and persists
//! the resulting complete service image at the configured atomic boundary.

use alloc::string::String;
use alloc::vec::Vec;

use super::wire::{DecodeError, Decoder, Encoder};
use super::{
    AccumulateRequestV2, AccumulationEnvelopeV2, AccumulationReceiptV2, AccumulationRejectionV2,
    AccumulationResultV2, ActorDirectoryV2, ActorGenesisV2, ActorId, AuthorizationEvidenceV2,
    BlobRefV2, CommittedImageStoreV2, ConsistencyModeV2, DurableJamStoreV2,
    DurableStoreOpenErrorV2, ExternalActorBindingV2, ExternalActorDirectoryV2, JamServiceV2,
    LocalStoreReadErrorV2, LocalWorkRequestV2, LocalWorkSchedulerV2, MethodPolicyV2,
    NoRefineProtocolHostV2, PackageError, ProgramId, PublicationAckV2, PublicationRecordV2,
    PublishedEffectsV2, ScheduleErrorV2, ServiceDispatchError, ServiceGenesisV2, ServiceIdentityV2,
    StateKeyV2, V2Wire, VosPackageV2, WorkInputIdV2,
};

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

#[derive(Debug)]
pub enum LocalRootTreeInvokeErrorV2 {
    ProofProducerRequired,
    Schedule(ScheduleErrorV2),
    Service(ServiceDispatchError),
    Rejected(AccumulationRejectionV2),
    UnexpectedResult,
    CorruptStore(LocalStoreReadErrorV2),
    MissingPublication,
    DivergentReplay,
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

/// A durable local host for exactly one logical JAM service/root actor tree.
pub struct LocalRootTreeServiceV2<B> {
    service: JamServiceV2<NoRefineProtocolHostV2, DurableJamStoreV2<B>>,
    identity: ServiceIdentityV2,
    root_actor: ActorId,
}

impl LocalRootTreeConfigV2 {
    pub fn validate(&self) -> Result<(), LocalRootTreeConfigErrorV2> {
        self.package
            .validate()
            .map_err(LocalRootTreeConfigErrorV2::InvalidPackage)?;
        if self.actor_name.is_empty() {
            return Err(LocalRootTreeConfigErrorV2::EmptyActorName);
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
        config
            .validate()
            .map_err(LocalRootTreeOpenErrorV2::InvalidConfig)?;
        let initial_state = BlobRefV2::of_bytes(&config.initial_state);
        let expected_root = config
            .package
            .actor_genesis(
                config.root_actor,
                config.actor_name.clone(),
                None,
                initial_state.clone(),
            )
            .map_err(|error| {
                LocalRootTreeOpenErrorV2::InvalidConfig(LocalRootTreeConfigErrorV2::InvalidPackage(
                    error,
                ))
            })?;
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
            if initial != initial_state {
                return Err(LocalRootTreeOpenErrorV2::ExistingActorMismatch);
            }
            let imported_program = service
                .accumulate_host_mut()
                .import_program(config.package.actor_pvm.clone());
            if imported_program != config.package.manifest.actor_program {
                return Err(LocalRootTreeOpenErrorV2::InvalidConfig(
                    LocalRootTreeConfigErrorV2::InvalidPackage(PackageError::ProgramIdMismatch),
                ));
            }
            let genesis = ServiceGenesisV2 {
                service: config.service.clone(),
                consistency: config.consistency,
                actors: vec![expected_root],
                external_actors: config.external_actors,
                authorization: config.install_authorization,
            };
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

    pub fn root_method_policy(
        &self,
        method: &str,
    ) -> Result<Option<MethodPolicyV2>, LocalRootTreeInvokeErrorV2> {
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
                &StateKeyV2::ActorDescriptor(self.root_actor),
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

    /// Return a still-pending publication only when the retry is byte-for-byte
    /// equivalent to the work identity already committed by the guest.
    pub fn recover_publication(
        &self,
        request: &LocalWorkRequestV2,
    ) -> Result<Option<PublicationRecordV2>, LocalRootTreeInvokeErrorV2> {
        let input = WorkInputIdV2 {
            invocation: request.invocation,
            workflow_step: request.workflow_step,
        };
        let publication = self
            .pending_publications()?
            .into_iter()
            .find(|publication| publication.input == input);
        let Some(publication) = publication else {
            return Ok(None);
        };
        let checkpoint = self
            .service
            .accumulate_host()
            .workflow_checkpoint(request.invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::DivergentReplay)?;
        let work = checkpoint.resume_work;
        if work.input_id() != input
            || work.logical_timeslot != request.logical_timeslot
            || work.target != request.target
            || work.method != request.method
            || work.arguments != request.arguments
            || work.origin != request.origin
            || work.authorization != request.authorization
            || work.causal_parent != request.causal_parent
            || work.parent_call != request.parent_call
            || work.awaited_reply != request.awaited_reply
            || work.imported_blobs != request.imported_blobs
            || work.proof_requested != request.proof_requested
        {
            return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
        }
        Ok(Some(publication))
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
    /// accepted the reply/outbox/proof package.
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
    use super::*;

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
}
