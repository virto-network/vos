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
    LocalStoreReadErrorV2, LocalWorkRequestV2, LocalWorkSchedulerV2, MessageRecordV2,
    MethodPolicyV2, NoRefineProtocolHostV2, PackageError, PreparedWorkV2, ProgramId,
    PublicationAckV2, PublicationRecordV2, PublishedEffectsV2, ReceiptVerificationRequestV2,
    ScheduleErrorV2, ServiceDispatchError, ServiceGenesisV2, ServiceIdentityV2, StateKeyV2, V2Wire,
    VosPackageV2, WorkInputIdV2, WorkflowCheckpointV2,
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
            } => {
                encoder.u8(1);
                encoder.u64(*logical_timeslot);
                encoder.fixed(&caller_invocation.0);
                encoder.bytes(&publication.encode());
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
                ..
            } => {
                *caller_invocation != super::InvocationId::ZERO
                    && publication.published.reply.is_some()
                    && publication.published.outbox.is_empty()
                    && publication.published.exported_blobs.is_empty()
                    && publication.published.proof.is_none()
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

/// Destination-side result of admitting one finalized cross-root message.
/// The inbox is visible only after physical Accumulate commits this receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedDeliveryV2 {
    pub receipt: AccumulationReceiptV2,
    pub duplicate: bool,
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
        self.invoke_prepared(prepared)
    }

    /// Execute a message only after destination Accumulate has admitted its
    /// finalized source outbox record into the guest-owned inbox.
    pub fn invoke_inbox(
        &mut self,
        call: super::CallId,
        logical_timeslot: u64,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
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

    /// Resume the exact committed machine snapshot for an invocation. The
    /// scheduler reconstructs the slice from guest state rather than a
    /// process-local handler future.
    pub fn resume(
        &mut self,
        invocation: super::InvocationId,
        logical_timeslot: u64,
        awaited_reply: Option<super::AccumulatedReplyV2>,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
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
            .map_err(LocalRootTreeInvokeErrorV2::Service)?;
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
        let (_, store) = self.service.into_hosts();
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
                reply: Some(reply),
                ..PublishedEffectsV2::default()
            },
        };
        let checkpoint = WorkflowCheckpointV2 {
            input,
            workflow_identity: work.workflow_identity(),
            work_hash: work.hash(),
            transition_commitment: publication.receipt.accepted_transition,
            resume_work: work,
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
