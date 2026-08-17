//! Durable local ownership of one v2 root actor tree.
//!
//! This is host orchestration, not an alternate actor runtime. Installation,
//! transition validation, state mutation, deduplication, and publication
//! acknowledgement all enter the canonical generic service at physical IC-5.
//! The host prepares Refine imports only from committed guest state and makes
//! effects visible only after the configured image store accepts the complete
//! post-Accumulate image.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::attestation::{AttestationProofHostV2, AttestationProofProducerV2};

use super::contracts::{decode_service, encode_service};
use super::wire::{DecodeError, Decoder, Encoder};
use super::{
    AccumulateRequestV2, AccumulatedRoleAssertionV2, AccumulatedServiceOutputV2,
    AccumulationEnvelopeV2, AccumulationReceiptV2, AccumulationRejectionV2, AccumulationResultV2,
    ActorDirectoryV2, ActorGenesisV2, ActorId, AttestedServiceErrorV2, AuthorizationEvidenceV2,
    BlobRefV2, CausalCallContextV2, CommittedImageStoreV2, ConsistencyBaseV2, ConsistencyModeV2,
    ContinuationSnapshotV2, CrdtChangeV2, CrdtSyncEnvelopeV2, DedupRecordV2, DeliveryRecordV2,
    DirectIngressV2, DurableJamStoreV2, DurableStoreOpenErrorV2, ExternalActorBindingV2,
    ExternalActorDirectoryV2, ImportedBlobV2, ImportedProgramV2, JamServiceV2, LocalJamStoreHostV2,
    LocalJamStoreV2, LocalStoreReadErrorV2, LocalWorkRequestV2, LocalWorkSchedulerV2,
    MessageRecordV2, MethodPolicyV2, NoRefineProtocolHostV2, Origin, PackageError,
    PackageRolePoliciesV2, PreparedWorkV2, ProgramId, ProofArtifactStoreV2, PublicationAckV2,
    PublicationRecordV2, PublishedEffectsV2, RefinedServiceOutputV2, RoleAssertionEligibilityV2,
    RoleAuthorityBindingV2, RoleAuthorizationClaimV2, RoleCredentialV2, ScheduleErrorV2,
    ServiceDispatchError, ServiceGenesisV2, ServiceIdentityV2, StateKeyV2, V2Wire, VosPackageV2,
    WorkInputIdV2, WorkflowCheckpointV2, crdt_node_storage_key, dedup_storage_key,
    delivery_storage_key,
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

/// Host-facing result for one attested root invocation. The actor reply and
/// proof package are released together only after guest Accumulate committed
/// the publication. The canonical wire is carried inside the ordinary node
/// invoke envelope so generated clients cannot confuse it with an unproved
/// method reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootTreeAttestedResultV2 {
    pub reply: Vec<u8>,
    pub attestation: super::AttestationDeliveryV2,
    pub proof: Vec<u8>,
}

impl RootTreeAttestedResultV2 {
    pub fn validate(&self) -> Result<(), DecodeError> {
        let delivery = &self.attestation;
        let statement = &delivery.statement;
        let reply = super::ReplyRecordV2 {
            call_id: statement.reply_call,
            producer: statement.actor,
            result: self.reply.clone(),
        };
        let accumulated = super::AccumulatedReplyV2 {
            reply,
            receipt: statement.accumulation_receipt.clone(),
            attestation: Some(Box::new(delivery.clone())),
        };
        if delivery.producer_name.is_empty()
            || delivery.producer_name != statement.producer_name
            || delivery.producer != statement.producer
            || delivery.proof.trace == super::Hash::ZERO
            || !delivery.proof.proof_blob.matches(&self.proof)
            || accumulated.validate().is_err()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl V2Wire for RootTreeAttestedResultV2 {
    const MAGIC: [u8; 4] = *b"VAR2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.bytes(&self.reply);
        encoder.string(&self.attestation.producer_name);
        encoder.fixed(&self.attestation.producer.0);
        encoder.bytes(&self.attestation.statement.encode());
        super::contracts::encode_proof(&mut encoder, &self.attestation.proof);
        encoder.bytes(&self.proof);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            reply: decoder.bytes()?,
            attestation: super::AttestationDeliveryV2 {
                producer_name: decoder.string()?,
                producer: super::ProducerId(decoder.fixed()?),
                statement: crate::AttestationStatementV3::decode(&decoder.bytes()?)?,
                proof: super::contracts::decode_proof(decoder)?,
            },
            proof: decoder.bytes()?,
        };
        value.validate()?;
        Ok(value)
    }
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

/// Canonical node-to-node wire for effects already committed by a source
/// root service. Observation time is intentionally absent: the receiving
/// node allocates a trusted logical timeslot only after its local admission
/// barrier. The destination guest still authenticates the source receipt,
/// full outbox membership, service identity, deadline and deduplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootTreeTransportV2 {
    OutboxDelivery {
        publication: PublicationRecordV2,
        message: super::MessageRecordV2,
    },
    Reply {
        caller: ActorId,
        caller_service: ServiceIdentityV2,
        caller_invocation: super::InvocationId,
        publication: PublicationRecordV2,
        /// Content-addressed proof bytes for an attested reply. These hydrate
        /// the caller's durable side CAS and are replicated with its final
        /// Apply; they never enter actor/service state.
        proof: Option<ImportedBlobV2>,
    },
    PublicationAccepted {
        acceptor: ActorId,
        acceptor_service: ServiceIdentityV2,
        service: ServiceIdentityV2,
        input: WorkInputIdV2,
        publication: super::Hash,
        call: super::CallId,
    },
    /// One causally ordered, independently committable delta from another
    /// authenticated replica of the same CRDT root. Large histories are
    /// split below the network frame limit and advance only after the peer
    /// acknowledges the preceding chunk. The wire does not confer receipt
    /// authority: the receiving node supplies verifier decisions separately
    /// to physical Accumulate after authenticating the exact Noise peer.
    CrdtSyncChunk {
        transfer: super::Hash,
        chunk_index: u32,
        chunk_count: u32,
        envelope: CrdtSyncEnvelopeV2,
    },
    /// Process-local transport progress for one committed CRDT delta. Losing
    /// this acknowledgement is safe: the source retries the same chunk and
    /// guest Accumulate classifies its already-committed nodes idempotently.
    CrdtSyncAccepted {
        service: ServiceIdentityV2,
        transfer: super::Hash,
        next_chunk: u32,
    },
}

impl V2Wire for RootTreeTransportV2 {
    const MAGIC: [u8; 4] = *b"VRT2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        match self {
            Self::OutboxDelivery {
                publication,
                message,
            } => {
                encoder.u8(0);
                encoder.bytes(&publication.encode());
                encoder.bytes(&message.encode());
            }
            Self::Reply {
                caller,
                caller_service,
                caller_invocation,
                publication,
                proof,
            } => {
                encoder.u8(1);
                encoder.fixed(&caller.0);
                encode_service(&mut encoder, caller_service);
                encoder.fixed(&caller_invocation.0);
                encoder.bytes(&publication.encode());
                encoder.option(proof, |encoder, proof| {
                    encoder.fixed(&proof.reference.hash.0);
                    encoder.u64(proof.reference.len);
                    encoder.bytes(&proof.bytes);
                });
            }
            Self::PublicationAccepted {
                acceptor,
                acceptor_service,
                service,
                input,
                publication,
                call,
            } => {
                encoder.u8(2);
                encoder.fixed(&acceptor.0);
                encode_service(&mut encoder, acceptor_service);
                encode_service(&mut encoder, service);
                encoder.fixed(&input.invocation.0);
                encoder.u64(input.workflow_step);
                encoder.fixed(&publication.0);
                encoder.fixed(&call.0);
            }
            Self::CrdtSyncChunk {
                transfer,
                chunk_index,
                chunk_count,
                envelope,
            } => {
                encoder.u8(3);
                encoder.fixed(&transfer.0);
                encoder.u32(*chunk_index);
                encoder.u32(*chunk_count);
                encoder.bytes(&envelope.encode());
            }
            Self::CrdtSyncAccepted {
                service,
                transfer,
                next_chunk,
            } => {
                encoder.u8(4);
                encode_service(&mut encoder, service);
                encoder.fixed(&transfer.0);
                encoder.u32(*next_chunk);
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = match decoder.u8()? {
            0 => Self::OutboxDelivery {
                publication: PublicationRecordV2::decode(&decoder.bytes()?)?,
                message: super::MessageRecordV2::decode(&decoder.bytes()?)?,
            },
            1 => Self::Reply {
                caller: ActorId(decoder.fixed()?),
                caller_service: decode_service(decoder)?,
                caller_invocation: super::InvocationId(decoder.fixed()?),
                publication: PublicationRecordV2::decode(&decoder.bytes()?)?,
                proof: decoder.option(|decoder| {
                    Ok(ImportedBlobV2 {
                        reference: BlobRefV2 {
                            hash: super::Hash(decoder.fixed()?),
                            len: decoder.u64()?,
                        },
                        bytes: decoder.bytes()?,
                    })
                })?,
            },
            2 => Self::PublicationAccepted {
                acceptor: ActorId(decoder.fixed()?),
                acceptor_service: decode_service(decoder)?,
                service: decode_service(decoder)?,
                input: WorkInputIdV2 {
                    invocation: super::InvocationId(decoder.fixed()?),
                    workflow_step: decoder.u64()?,
                },
                publication: super::Hash(decoder.fixed()?),
                call: super::CallId(decoder.fixed()?),
            },
            3 => Self::CrdtSyncChunk {
                transfer: super::Hash(decoder.fixed()?),
                chunk_index: decoder.u32()?,
                chunk_count: decoder.u32()?,
                envelope: CrdtSyncEnvelopeV2::decode(&decoder.bytes()?)?,
            },
            4 => Self::CrdtSyncAccepted {
                service: decode_service(decoder)?,
                transfer: super::Hash(decoder.fixed()?),
                next_chunk: decoder.u32()?,
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
            } => {
                publication.published.reply.is_none()
                    && matches!(
                        publication.receipt.consistency,
                        ConsistencyModeV2::Local
                            | ConsistencyModeV2::Raft
                            | ConsistencyModeV2::Crdt
                    )
                    && publication.published.proof.is_none()
                    && publication.published.attestation.is_none()
                    && message.from_service == publication.receipt.service
                    && publication
                        .published
                        .outbox
                        .binary_search_by_key(&message.call_id, |candidate| candidate.call_id)
                        .ok()
                        .is_some_and(|index| publication.published.outbox[index] == *message)
            }
            Self::Reply {
                caller,
                caller_invocation,
                publication,
                proof,
                ..
            } => {
                *caller != ActorId::ZERO
                    && *caller_invocation != super::InvocationId::ZERO
                    && matches!(
                        publication.receipt.consistency,
                        ConsistencyModeV2::Local
                            | ConsistencyModeV2::Raft
                            | ConsistencyModeV2::Crdt
                    )
                    && publication.published.reply.is_some()
                    && publication.published.outbox.is_empty()
                    && match (publication.published.attestation.as_deref(), proof) {
                        (None, None) => publication.published.proof.is_none(),
                        (Some(attestation), Some(proof)) => {
                            publication.published.proof.as_ref() == Some(&attestation.proof)
                                && proof.reference == attestation.proof.proof_blob
                                && proof.reference.matches(&proof.bytes)
                        }
                        _ => false,
                    }
            }
            Self::PublicationAccepted {
                acceptor,
                input,
                publication,
                call,
                ..
            } => {
                *acceptor != ActorId::ZERO
                    && input.invocation != super::InvocationId::ZERO
                    && *publication != super::Hash::ZERO
                    && *call != super::CallId::ZERO
            }
            Self::CrdtSyncChunk {
                transfer,
                chunk_index,
                chunk_count,
                envelope,
            } => {
                *transfer != super::Hash::ZERO
                    && *chunk_count != 0
                    && chunk_index < chunk_count
                    && !envelope.advertised_heads.is_empty()
                    && !envelope.nodes.is_empty()
            }
            Self::CrdtSyncAccepted {
                transfer,
                next_chunk,
                ..
            } => *transfer != super::Hash::ZERO && *next_chunk != 0,
        }
    }
}

fn direct_ingress_from_request(
    store: &LocalJamStoreV2,
    service: &ServiceIdentityV2,
    request: &LocalWorkRequestV2,
    private_arguments: bool,
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
    let mut ingress = LocalWorkSchedulerV2::prepare_direct_ingress(store, service, request)
        .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
    if private_arguments {
        if request.arguments.is_empty() {
            return Err(LocalRootTreeInvokeErrorV2::PrivateIngressUnavailable);
        }
        ingress.private_arguments = Some(BlobRefV2::of_bytes(&request.arguments));
        ingress.arguments.clear();
    }
    Ok(ingress)
}

fn direct_ingress_authorization(
    store: &LocalJamStoreV2,
    ingress: &DirectIngressV2,
) -> Result<AuthorizationEvidenceV2, LocalRootTreeInvokeErrorV2> {
    let Some(causal) = ingress.crdt_ingress() else {
        return Ok(ingress.authorization.clone());
    };
    match (&causal.authorization, causal.authorization_blob.as_ref()) {
        (AuthorizationEvidenceV2::Public, None) => Ok(AuthorizationEvidenceV2::Public),
        (
            AuthorizationEvidenceV2::Credential {
                policy,
                credential_commitment,
                bytes,
            },
            Some(reference),
        ) if bytes.is_empty() => {
            let bytes = store
                .blob(reference)
                .filter(|bytes| reference.matches(bytes))
                .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?
                .to_vec();
            Ok(AuthorizationEvidenceV2::Credential {
                policy: *policy,
                credential_commitment: *credential_commitment,
                bytes,
            })
        }
        _ => Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow),
    }
}

fn request_from_direct_ingress(
    ingress: DirectIngressV2,
    private_arguments: Option<Vec<u8>>,
    allow_redacted_private_arguments: bool,
) -> Result<LocalWorkRequestV2, LocalRootTreeInvokeErrorV2> {
    let authorization = ingress
        .crdt_ingress()
        .map(|causal| causal.authorization.clone())
        .unwrap_or_else(|| ingress.authorization.clone());
    let arguments = match (&ingress.private_arguments, private_arguments) {
        (Some(reference), Some(arguments)) if reference.matches(&arguments) => arguments,
        (Some(_), None) if allow_redacted_private_arguments => Vec::new(),
        (None, None) => ingress.arguments,
        _ => return Err(LocalRootTreeInvokeErrorV2::PrivateIngressUnavailable),
    };
    Ok(LocalWorkRequestV2 {
        invocation: ingress.invocation,
        workflow_step: 0,
        logical_timeslot: ingress.logical_timeslot,
        target: ingress.target,
        method: ingress.method,
        arguments,
        origin: ingress.origin,
        authorization,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        imported_blobs: ingress.imported_blobs,
        proof_requested: ingress.proof_requested,
    })
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
    pub role_authority: Option<RoleAuthorityBindingV2>,
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
    WrongGasSchedule,
    InvalidConsistency,
    ReplicatedPrivateTaskUnsupported,
    InvalidRoleAuthority,
    ReplicationDriverRequired,
    RaftInstallEntryTooLarge,
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
    ProofHistoryUnavailable,
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
    ProofUnavailable,
    ProducerRecordUnavailable,
    PrivateIngressUnavailable,
    PrivateIngressRetirementFailed,
    Schedule(ScheduleErrorV2),
    Service(ServiceDispatchError),
    #[cfg(feature = "storage")]
    Replication(ReplicatedServiceErrorV2<CommitError>),
    Rejected(AccumulationRejectionV2),
    UnexpectedResult,
    CorruptStore(LocalStoreReadErrorV2),
    CorruptWorkflow,
    DivergentInvocation,
    DivergentReplay,
    MissingPublication,
    InvalidRoleAssertionPublication,
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

/// Failure while preparing, producing, or committing an attested root slice.
/// Host/service failures remain distinguishable from proof-producer failures
/// so orchestration can retry unavailable infrastructure without treating a
/// malformed proof as transient.
#[derive(Debug)]
pub enum AttestedRootTreeInvokeErrorV2<P> {
    Root(LocalRootTreeInvokeErrorV2),
    Producer(P),
    InvalidPreparation,
    InvalidProducedProof,
    ProofUnavailable,
    CommitMismatch,
}

impl<P> From<LocalRootTreeInvokeErrorV2> for AttestedRootTreeInvokeErrorV2<P> {
    fn from(error: LocalRootTreeInvokeErrorV2) -> Self {
        Self::Root(error)
    }
}

impl<P: core::fmt::Debug> core::fmt::Display for AttestedRootTreeInvokeErrorV2<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cannot invoke attested VOS v2 root tree: {self:?}")
    }
}

impl<P: core::fmt::Debug> core::error::Error for AttestedRootTreeInvokeErrorV2<P> {}

/// Result made visible only after physical Accumulate committed the durable
/// service image. Non-empty effects remain in a recoverable publication row
/// until the consumer acknowledges its exact commitment through IC-5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedRootTreeSliceV2 {
    pub input: WorkInputIdV2,
    pub receipt: AccumulationReceiptV2,
    pub published: PublishedEffectsV2,
    pub publication: Option<PublicationRecordV2>,
    pub role_assertion_eligibility: Option<RoleAssertionEligibilityV2>,
    pub duplicate: bool,
    pub refine_gas_used: u64,
    pub accumulate_gas_used: u64,
}

impl CommittedRootTreeSliceV2 {
    /// Extract the exact finalized role decision produced by a generic
    /// authority service. Authority decisions are single-slice replies; any
    /// suspension, outbox, exported artifact, or attestation side effect
    /// makes the result ambiguous and therefore unusable as authorization.
    pub fn role_assertion(
        &self,
        claim: RoleAuthorizationClaimV2,
        authority: &RoleAuthorityBindingV2,
    ) -> Result<AccumulatedRoleAssertionV2, LocalRootTreeInvokeErrorV2> {
        let expected_reply = claim.authority_reply(authority.actor);
        let valid = !self.duplicate
            && self.input.invocation == claim.authority_invocation()
            && self.input.workflow_step == 0
            && self.receipt.service == authority.service
            && self.receipt.checkpoint == 0
            && self.receipt.reply_commitment == Some(expected_reply.commitment())
            && self.receipt.outbox_commitment.is_none()
            && self
                .role_assertion_eligibility
                .as_ref()
                .is_some_and(|eligibility| {
                    eligibility.input == self.input
                        && eligibility.transition_commitment == self.receipt.accepted_transition
                        && eligibility.reply_commitment == expected_reply.commitment()
                })
            && self.published.reply.as_ref() == Some(&expected_reply)
            && self.published.outbox.is_empty()
            && self.published.exported_blobs.is_empty()
            && self.published.proof.is_none()
            && self.published.attestation.is_none()
            && self.publication.as_ref().is_some_and(|publication| {
                publication.input == self.input
                    && publication.receipt == self.receipt
                    && publication.published == self.published
            });
        if !valid {
            return Err(LocalRootTreeInvokeErrorV2::InvalidRoleAssertionPublication);
        }
        let assertion = AccumulatedRoleAssertionV2 {
            claim,
            receipt: self.receipt.clone(),
        };
        if !assertion.matches_authority(authority) {
            return Err(LocalRootTreeInvokeErrorV2::InvalidRoleAssertionPublication);
        }
        Ok(assertion)
    }
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

fn map_attested_root_error<E, P>(
    error: AttestedServiceErrorV2<E, P>,
    service: impl FnOnce(E) -> LocalRootTreeInvokeErrorV2,
) -> AttestedRootTreeInvokeErrorV2<P> {
    match error {
        AttestedServiceErrorV2::Service(error) => service(error).into(),
        AttestedServiceErrorV2::Rejected(rejection) => {
            LocalRootTreeInvokeErrorV2::Rejected(rejection).into()
        }
        AttestedServiceErrorV2::InvalidPreparation => {
            AttestedRootTreeInvokeErrorV2::InvalidPreparation
        }
        AttestedServiceErrorV2::Producer(error) => AttestedRootTreeInvokeErrorV2::Producer(error),
        AttestedServiceErrorV2::InvalidProducedProof => {
            AttestedRootTreeInvokeErrorV2::InvalidProducedProof
        }
        AttestedServiceErrorV2::ProofUnavailable => AttestedRootTreeInvokeErrorV2::ProofUnavailable,
        AttestedServiceErrorV2::CommitMismatch => AttestedRootTreeInvokeErrorV2::CommitMismatch,
    }
}

impl<B> RootTreeServiceDriverV2<B>
where
    B: CommittedImageStoreV2 + ProofArtifactStoreV2<Error = <B as CommittedImageStoreV2>::Error>,
{
    fn refresh_proof_provenance_snapshot(&mut self) -> Result<(), RootTreeDriverErrorV2> {
        match self {
            Self::Direct(_) => Ok(()),
            #[cfg(feature = "storage")]
            Self::Raft(service) => service
                .refresh_applied_service_snapshot()
                .map_err(RootTreeDriverErrorV2::Raft),
        }
    }

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

    #[cfg(all(feature = "storage", feature = "network"))]
    fn leader_hint(&self) -> Option<u16> {
        match self {
            Self::Direct(_) => None,
            Self::Raft(service) => service
                .log()
                .worker_handle()?
                .snapshot()
                .and_then(|snapshot| snapshot.leader_hint),
        }
    }

    fn replication_id(&self) -> Option<[u8; 32]> {
        match self {
            Self::Direct(_) => None,
            #[cfg(feature = "storage")]
            Self::Raft(service) => Some(service.log().replication_id()),
        }
    }

    #[cfg(all(feature = "storage", feature = "network"))]
    fn raft_propose_timeout_ms(&self) -> Option<u64> {
        match self {
            Self::Direct(_) => None,
            Self::Raft(service) => Some(service.log().propose_timeout_ms()),
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

    fn accumulate_with_availability(
        &mut self,
        request: &AccumulateRequestV2,
        programs: &[ImportedProgramV2],
        blobs: &[ImportedBlobV2],
    ) -> Result<AccumulatedServiceOutputV2, RootTreeDriverErrorV2> {
        match self {
            Self::Direct(service) => service
                .accumulate_with_availability(request, programs, blobs)
                .map_err(RootTreeDriverErrorV2::Direct),
            #[cfg(feature = "storage")]
            Self::Raft(service) => service
                .accumulate_with_availability(request, programs, blobs)
                .map_err(RootTreeDriverErrorV2::Raft),
        }
    }

    fn accumulate_with_receipt_verifications_after_barrier(
        &mut self,
        request: &AccumulateRequestV2,
        receipt_verifications: &[super::ReceiptVerificationRequestV2],
    ) -> Result<AccumulatedServiceOutputV2, RootTreeDriverErrorV2> {
        match self {
            Self::Direct(service) => {
                super::CommittedAccumulateEntryV2::validate_receipt_verifications(
                    request,
                    receipt_verifications,
                )
                .map_err(|_| {
                    RootTreeDriverErrorV2::Direct(
                        super::ServiceDispatchError::InvalidAvailabilityArtifacts,
                    )
                })?;
                for verification in receipt_verifications {
                    super::ReceiptVerificationHostV2::make_receipt_available(
                        service.accumulate_host_mut(),
                        verification,
                    );
                }
                service
                    .accumulate(request)
                    .map_err(RootTreeDriverErrorV2::Direct)
            }
            #[cfg(feature = "storage")]
            Self::Raft(service) => service
                .accumulate_with_receipt_verifications_after_barrier(request, receipt_verifications)
                .map_err(RootTreeDriverErrorV2::Raft),
        }
    }

    fn accumulate_attested_after_barrier<P: AttestationProofProducerV2 + ?Sized>(
        &mut self,
        envelope: AccumulationEnvelopeV2,
        imports: &super::RefineImportsV2,
        producer: &mut P,
    ) -> Result<super::CommittedAttestationOutputV2, AttestedRootTreeInvokeErrorV2<P::Error>> {
        match self {
            Self::Direct(service) => service
                .accumulate_attested(envelope, imports, producer)
                .map_err(|error| {
                    map_attested_root_error(error, LocalRootTreeInvokeErrorV2::Service)
                }),
            #[cfg(feature = "storage")]
            Self::Raft(service) => service
                .accumulate_attested_after_barrier(envelope, imports, producer)
                .map_err(|error| {
                    map_attested_root_error(error, LocalRootTreeInvokeErrorV2::Replication)
                }),
        }
    }

    fn accumulate_with_availability_after_barrier(
        &mut self,
        request: &AccumulateRequestV2,
        programs: &[ImportedProgramV2],
        blobs: &[ImportedBlobV2],
    ) -> Result<AccumulatedServiceOutputV2, RootTreeDriverErrorV2> {
        match self {
            Self::Direct(service) => service
                .accumulate_with_availability(request, programs, blobs)
                .map_err(RootTreeDriverErrorV2::Direct),
            #[cfg(feature = "storage")]
            Self::Raft(service) => service
                .accumulate_with_availability_after_barrier(request, programs, blobs)
                .map_err(RootTreeDriverErrorV2::Raft),
        }
    }

    fn accumulate_at_after_barrier(
        &mut self,
        request: &AccumulateRequestV2,
        logical_timeslot: u64,
    ) -> Result<AccumulatedServiceOutputV2, RootTreeDriverErrorV2> {
        match self {
            Self::Direct(service) => service
                .accumulate_at(request, logical_timeslot)
                .map_err(RootTreeDriverErrorV2::Direct),
            #[cfg(feature = "storage")]
            Self::Raft(service) => service
                .accumulate_at_after_barrier(request, logical_timeslot)
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
    /// One-shot bytes needed only until genesis is present in the durable
    /// service image. Followers retain them while waiting for the committed
    /// Install entry; an installed or caught-up root drops them immediately.
    pending_install_availability: Option<(Vec<ImportedProgramV2>, Vec<ImportedBlobV2>)>,
    expected_root: ActorGenesisV2,
    expected_external_actors: Vec<ExternalActorBindingV2>,
    expected_role_authority: Option<RoleAuthorityBindingV2>,
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

fn installation_availability(
    config: &LocalRootTreeConfigV2,
    descriptor: &ActorGenesisV2,
) -> (Vec<ImportedProgramV2>, Vec<ImportedBlobV2>) {
    let mut programs = vec![ImportedProgramV2 {
        program: descriptor.program,
        pvm: config.package.actor_pvm.clone(),
    }];
    programs.extend(
        config
            .package
            .task_dependencies
            .iter()
            .map(|dependency| ImportedProgramV2 {
                program: dependency.binding.program,
                pvm: dependency.pvm.clone(),
            }),
    );
    programs.sort_by_key(|program| program.program);
    programs.dedup_by_key(|program| program.program);
    let blobs = vec![ImportedBlobV2 {
        reference: descriptor.initial_state.clone(),
        bytes: config.initial_state.clone(),
    }];
    (programs, blobs)
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
        if self.consistency == ConsistencyModeV2::Crdt && !self.package.task_dependencies.is_empty()
        {
            // Raft roots stage commitment-only ingress on every steady-state
            // voter before admission. CRDT still lacks a causally authorized
            // producer-availability rule for the private preimage.
            return Err(LocalRootTreeConfigErrorV2::ReplicatedPrivateTaskUnsupported);
        }
        if self.role_authority.as_ref().is_some_and(|authority| {
            authority.service.space != self.service.space
                || authority.service == self.service
                || authority.service.service_abi != super::ABI_VERSION
                || authority.service.execution_semantics != super::EXECUTION_SEMANTICS_ID
                || !authority.service.gas_schedule.is_valid()
                || authority.actor == ActorId::ZERO
        }) {
            return Err(LocalRootTreeConfigErrorV2::InvalidRoleAuthority);
        }
        if self.refine_gas == 0 || self.accumulate_gas == 0 {
            return Err(LocalRootTreeConfigErrorV2::ZeroGas);
        }
        if self.service.gas_schedule
            != super::GasScheduleV2::new(self.refine_gas, self.accumulate_gas)
        {
            return Err(LocalRootTreeConfigErrorV2::WrongGasSchedule);
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
            role_authority: self.role_authority.clone(),
            authorization: self.install_authorization.clone(),
        };
        ServiceGenesisV2::decode(&genesis.encode())
            .map_err(|_| LocalRootTreeConfigErrorV2::InvalidGenesis)?;
        #[cfg(feature = "storage")]
        if self.consistency == ConsistencyModeV2::Raft {
            let request = AccumulateRequestV2::Install(genesis.clone());
            let (programs, blobs) = installation_availability(self, &descriptor);
            if !crate::raft::v2::accumulate_entry_fits_network_frame(
                &request,
                None,
                &programs,
                &blobs,
                &[],
            )
            .map_err(|_| LocalRootTreeConfigErrorV2::InvalidGenesis)?
            {
                return Err(LocalRootTreeConfigErrorV2::RaftInstallEntryTooLarge);
            }
        }
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
    fn request_from_admitted_ingress(
        &self,
        record: super::IngressRecordV2,
    ) -> Result<(LocalWorkRequestV2, Option<BlobRefV2>), LocalRootTreeInvokeErrorV2> {
        let consumed = record.consumed;
        let ingress = record.ingress;
        let private_reference = ingress.private_arguments.clone();
        let private_arguments = private_reference.as_ref().and_then(|reference| {
            self.service
                .accumulate_host()
                .private_ingress(ingress.invocation, reference)
        });
        if private_reference.is_some() && private_arguments.is_none() && !consumed {
            return Err(LocalRootTreeInvokeErrorV2::PrivateIngressUnavailable);
        }
        Ok((
            request_from_direct_ingress(ingress, private_arguments, consumed)?,
            private_reference,
        ))
    }

    fn prepare_request(
        &self,
        request: LocalWorkRequestV2,
        private_arguments: Option<BlobRefV2>,
    ) -> Result<PreparedWorkV2, LocalRootTreeInvokeErrorV2> {
        let mut prepared = LocalWorkSchedulerV2::prepare(self.service.accumulate_host(), request)
            .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        prepared.work.private_arguments = private_arguments;
        Ok(prepared)
    }

    fn retire_consumed_private_ingress(
        &mut self,
        invocation: super::InvocationId,
    ) -> Result<(), LocalRootTreeInvokeErrorV2> {
        let record = self
            .service
            .accumulate_host()
            .ingress_record(invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?;
        if record
            .is_some_and(|record| record.consumed && record.ingress.private_arguments.is_some())
        {
            self.service
                .accumulate_host_mut()
                .retire_private_ingress_after_commit(invocation);
        }
        Ok(())
    }

    fn recover_committed_invocation(
        &self,
        request: &LocalWorkRequestV2,
    ) -> Result<Option<CommittedRootTreeSliceV2>, LocalRootTreeInvokeErrorV2> {
        self.recover_committed_invocation_with_private_reference(request, None)
    }

    /// Recover from guest-owned admitted input after its one-shot private
    /// preimage has been retired. Only the durable ingress path may supply
    /// `private_reference`; caller-provided exact retries still have to prove
    /// equality by presenting plaintext that hashes to the stored reference.
    fn recover_committed_invocation_with_private_reference(
        &self,
        request: &LocalWorkRequestV2,
        private_reference: Option<&BlobRefV2>,
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
        if header.consistency == ConsistencyModeV2::Crdt
            && request.workflow_step == 0
            && checkpoint.input.workflow_step != 0
        {
            let candidate = direct_ingress_from_request(
                self.service.accumulate_host().local_store(),
                &self.identity,
                request,
                self.request_uses_private_ingress(request)?,
            )?;
            let ingress = self
                .service
                .accumulate_host()
                .ingress_record(request.invocation)
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
                .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
            if !ingress.consumed || !ingress.ingress.matches_retry(&candidate) {
                return Err(LocalRootTreeInvokeErrorV2::DivergentInvocation);
            }
            let input = WorkInputIdV2 {
                invocation: request.invocation,
                workflow_step: 0,
            };
            let dedup = self
                .service
                .accumulate_host()
                .row(&dedup_storage_key(input))
                .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)
                .and_then(|bytes| {
                    DedupRecordV2::decode(bytes)
                        .map_err(|_| LocalRootTreeInvokeErrorV2::CorruptWorkflow)
                })?;
            let bound = dedup.receipt.service == self.identity
                && dedup.receipt.consistency == ConsistencyModeV2::Crdt
                && dedup.receipt.resulting_crdt_heads.iter().any(|cid| {
                    self.service
                        .accumulate_host()
                        .row(&crdt_node_storage_key(*cid))
                        .and_then(|bytes| CrdtChangeV2::decode(bytes).ok())
                        .is_some_and(|change| {
                            change.cid() == *cid
                                && change.work_hash == dedup.work_hash
                                && change.receipt_commitment() == dedup.transition_commitment
                                && change.workflow.iter().any(|operation| {
                                    matches!(operation, super::WorkflowOperationV2::Checkpoint(work)
                                        if work.input_id() == input)
                                })
                        })
                });
            if !bound {
                return Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow);
            }
            let publication = self
                .service
                .accumulate_host()
                .pending_publications()
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
                .into_iter()
                .find(|publication| publication.input == input);
            if publication
                .as_ref()
                .is_some_and(|publication| publication.receipt != dedup.receipt)
            {
                return Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow);
            }
            return Ok(Some(CommittedRootTreeSliceV2 {
                input,
                receipt: dedup.receipt,
                published: publication
                    .as_ref()
                    .map_or_else(PublishedEffectsV2::default, |row| row.published.clone()),
                publication,
                role_assertion_eligibility: self
                    .service
                    .accumulate_host()
                    .local_store()
                    .role_assertion_eligibility(input)
                    .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?,
                duplicate: true,
                refine_gas_used: 0,
                accumulate_gas_used: 0,
            }));
        }
        let committed = &checkpoint.resume_work;
        let authorization_matches = if header.consistency == ConsistencyModeV2::Crdt {
            let candidate = direct_ingress_from_request(
                self.service.accumulate_host().local_store(),
                &self.identity,
                request,
                self.request_uses_private_ingress(request)?,
            )?;
            self.service
                .accumulate_host()
                .ingress_record(request.invocation)
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
                .is_some_and(|record| record.consumed && record.ingress.matches_retry(&candidate))
        } else {
            committed.authorization == request.authorization
        };
        let arguments_match = private_reference.map_or_else(
            || committed.matches_arguments(&request.arguments),
            |reference| committed.private_arguments.as_ref() == Some(reference),
        );
        let exact_ingress = request.workflow_step == 0
            && checkpoint.input.workflow_step == 0
            && checkpoint.input.invocation == request.invocation
            && committed.invocation == request.invocation
            && committed.target == request.target
            && committed.method == request.method
            && arguments_match
            && committed.origin == request.origin
            && authorization_matches
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
        let crdt_change = if header.consistency == ConsistencyModeV2::Crdt {
            Some(
                self.service
                    .accumulate_host()
                    .row(&crdt_node_storage_key(checkpoint.transition_hash))
                    .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)
                    .and_then(|bytes| {
                        CrdtChangeV2::decode(bytes)
                            .map_err(|_| LocalRootTreeInvokeErrorV2::CorruptWorkflow)
                    })?,
            )
        } else {
            None
        };
        let checkpoint_is_bound = if let Some(change) = crdt_change.as_ref() {
            change.cid() == checkpoint.transition_hash
                && change.work_hash == dedup.work_hash
                && change.matches_receipt(&self.identity, &dedup.receipt)
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
        let published = match (publication.as_ref(), crdt_change.as_ref()) {
            (Some(publication), _) => publication.published.clone(),
            (None, Some(change)) => change
                .published_effects()
                .map_err(|()| LocalRootTreeInvokeErrorV2::CorruptWorkflow)?
                .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?,
            (None, None) => PublishedEffectsV2::default(),
        };
        Ok(Some(CommittedRootTreeSliceV2 {
            input: checkpoint.input,
            receipt: dedup.receipt,
            published,
            publication,
            role_assertion_eligibility: self
                .service
                .accumulate_host()
                .local_store()
                .role_assertion_eligibility(checkpoint.input)
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?,
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
        Self::open_with_driver(config, backend, RootTreeDriverConfigV2::Direct, None)
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
        Self::open_with_driver(config, backend, RootTreeDriverConfigV2::Raft(log), None)
    }

    /// Open a Raft root with its proof verifier installed before snapshot or
    /// log replay. This is the node registration path; keeping it separate
    /// from the conformance constructor prevents a follower from hydrating a
    /// proof under the local allowlist seam during recovery.
    #[cfg(feature = "storage")]
    pub(crate) fn open_raft_with_proof_verifier(
        config: LocalRootTreeConfigV2,
        backend: B,
        log: RaftAccumulateLogV2,
        proof_verifier: Arc<super::local_store::ProofVerifierFnV2>,
    ) -> Result<Self, LocalRootTreeOpenErrorV2<<B as CommittedImageStoreV2>::Error>> {
        if config.consistency != ConsistencyModeV2::Raft {
            return Err(LocalRootTreeOpenErrorV2::InvalidConfig(
                LocalRootTreeConfigErrorV2::InvalidConsistency,
            ));
        }
        Self::open_with_driver(
            config,
            backend,
            RootTreeDriverConfigV2::Raft(log),
            Some(proof_verifier),
        )
    }

    fn open_with_driver(
        config: LocalRootTreeConfigV2,
        backend: B,
        driver: RootTreeDriverConfigV2,
        proof_verifier: Option<Arc<super::local_store::ProofVerifierFnV2>>,
    ) -> Result<Self, LocalRootTreeOpenErrorV2<<B as CommittedImageStoreV2>::Error>> {
        let (expected_root, genesis) = config
            .installation()
            .map_err(LocalRootTreeOpenErrorV2::InvalidConfig)?;
        let install_request = AccumulateRequestV2::Install(genesis.clone());
        let (install_programs, install_blobs) = installation_availability(&config, &expected_root);
        super::CommittedAccumulateEntryV2::validate_availability(
            &install_request,
            &install_programs,
            &install_blobs,
        )
        .map_err(|_| {
            LocalRootTreeOpenErrorV2::InvalidConfig(LocalRootTreeConfigErrorV2::InvalidGenesis)
        })?;
        let production_proof_verifier = proof_verifier.is_some();
        let mut store =
            DurableJamStoreV2::open(backend).map_err(LocalRootTreeOpenErrorV2::Store)?;
        if let Some(proof_verifier) = proof_verifier {
            store.install_proof_verifier_arc(proof_verifier);
            store
                .ensure_proof_verifier_provenance()
                .map_err(|_| LocalRootTreeOpenErrorV2::ProofHistoryUnavailable)?;
        }
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
            pending_install_availability: Some((install_programs, install_blobs)),
            expected_root,
            expected_external_actors: config.external_actors,
            expected_role_authority: config.role_authority,
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
        if production_proof_verifier {
            root.service
                .refresh_proof_provenance_snapshot()
                .map_err(|error| match error {
                    RootTreeDriverErrorV2::Direct(error) => {
                        LocalRootTreeOpenErrorV2::Service(error)
                    }
                    #[cfg(feature = "storage")]
                    RootTreeDriverErrorV2::Raft(error) => {
                        LocalRootTreeOpenErrorV2::Replication(error)
                    }
                })?;
        }
        Ok(root)
    }

    pub(crate) fn refresh_proof_provenance_snapshot(
        &mut self,
    ) -> Result<(), LocalRootTreeInvokeErrorV2> {
        self.service
            .refresh_proof_provenance_snapshot()
            .map_err(RootTreeDriverErrorV2::into_invoke)
    }

    pub fn identity(&self) -> &ServiceIdentityV2 {
        &self.identity
    }

    pub fn role_authority(&self) -> Option<&RoleAuthorityBindingV2> {
        self.expected_role_authority.as_ref()
    }

    pub const fn root_actor(&self) -> ActorId {
        self.root_actor
    }

    fn target_uses_private_ingress(
        &self,
        actor: ActorId,
    ) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        if !matches!(
            self.consistency,
            ConsistencyModeV2::Local | ConsistencyModeV2::Raft
        ) {
            return Ok(false);
        }
        let header = self
            .service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::ServiceNotInstalled)?;
        let descriptor = self
            .service
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::ActorDescriptor(actor))
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .and_then(|bytes| ActorGenesisV2::decode(&bytes).ok())
            .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        let policies = PackageRolePoliciesV2::decode(&descriptor.role_policies)
            .map_err(|_| LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        Ok(!policies.task_dependencies.is_empty())
    }

    fn request_uses_private_ingress(
        &self,
        request: &LocalWorkRequestV2,
    ) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        if let Some(record) = self
            .service
            .accumulate_host()
            .ingress_record(request.invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
        {
            return Ok(record.ingress.private_arguments.is_some());
        }
        self.target_uses_private_ingress(request.target)
    }

    /// Content address that must be present on every current Raft voter
    /// before this request may enter the replicated log.
    #[cfg(all(feature = "storage", feature = "network"))]
    pub(crate) fn private_ingress_reference_for_request(
        &self,
        request: &LocalWorkRequestV2,
    ) -> Result<Option<BlobRefV2>, LocalRootTreeInvokeErrorV2> {
        if self
            .service
            .accumulate_host()
            .ingress_record(request.invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .is_some_and(|record| record.consumed)
        {
            // Exact committed retries authenticate the supplied plaintext
            // against the permanent content address but never need to
            // recreate a sidecar already retired by every replica.
            return Ok(None);
        }
        self.request_uses_private_ingress(request)
            .map(|required| required.then(|| BlobRefV2::of_bytes(&request.arguments)))
    }

    /// Whether guest-owned state still depends on a private ingress preimage.
    /// Membership promotion uses this while excluding concurrent admissions;
    /// a quiescent join needs no secret-bearing snapshot side channel.
    #[cfg(all(feature = "storage", feature = "network"))]
    pub(crate) fn has_pending_private_ingress(&self) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        self.service
            .accumulate_host()
            .local_store()
            .pending_ingresses()
            .map(|ingresses| {
                ingresses
                    .iter()
                    .any(|ingress| ingress.private_arguments.is_some())
            })
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)
    }

    /// Retry host-only cleanup debt without changing the disposition of an
    /// invocation whose guest transition already committed.
    pub(crate) fn retry_private_ingress_retirement(&mut self) {
        let debt = self
            .service
            .accumulate_host()
            .private_ingress_retirement_debt();
        for invocation in debt {
            self.service
                .accumulate_host_mut()
                .retire_private_ingress_after_commit(invocation);
        }
    }

    pub(crate) fn steady_raft_voters(&self) -> Option<(u16, Vec<u16>)> {
        match &self.service {
            #[cfg(feature = "storage")]
            RootTreeServiceDriverV2::Raft(service) => service.log().steady_leader_voters(),
            RootTreeServiceDriverV2::Direct(_) => None,
        }
    }

    fn owns_actor(&self, actor: ActorId) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        let header = self
            .service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        let directory = self
            .service
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::ActorDirectory)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .map(|bytes| ActorDirectoryV2::decode(&bytes))
            .transpose()
            .map_err(|_| LocalRootTreeInvokeErrorV2::CorruptWorkflow)?
            .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        Ok(directory.actors.binary_search(&actor).is_ok())
    }

    pub const fn consistency(&self) -> ConsistencyModeV2 {
        self.consistency
    }

    pub fn replication_id(&self) -> Option<[u8; 32]> {
        self.service.replication_id()
    }

    /// Proposal/read-barrier liveness budget for a networked Raft host.
    /// Kept crate-private because it is host scheduling metadata, not part of
    /// the guest-owned service identity or canonical request wire.
    #[cfg(all(feature = "storage", feature = "network"))]
    pub(crate) fn raft_propose_timeout_ms(&self) -> Option<u64> {
        self.service.raft_propose_timeout_ms()
    }

    pub fn store(&self) -> &DurableJamStoreV2<B> {
        self.service.accumulate_host()
    }

    pub fn store_mut(&mut self) -> &mut DurableJamStoreV2<B> {
        self.service.accumulate_host_mut()
    }

    /// Persist one authenticated Raft private-ingress preimage outside the
    /// service image. The node performs replication-group/voter
    /// authentication before calling this root-owned boundary; this method
    /// independently pins the content address and the service's private-input
    /// size limit before acknowledging durability.
    #[cfg(all(feature = "storage", feature = "network"))]
    pub(crate) fn stage_replicated_private_ingress(
        &mut self,
        invocation: super::InvocationId,
        reference: &BlobRefV2,
        bytes: &[u8],
    ) -> bool {
        if self.consistency != ConsistencyModeV2::Raft
            || bytes.is_empty()
            || bytes.len() > super::ACTOR_PRIVATE_INPUT_MAX_BYTES
            || !reference.matches(bytes)
        {
            return false;
        }
        self.service
            .accumulate_host_mut()
            .persist_replicated_private_ingress(invocation, bytes)
            .is_ok_and(|persisted| persisted == *reference)
    }

    /// Read one producer-private Task record from this operator's durable
    /// sidecar. This host API is intentionally absent from actor messages,
    /// service snapshots, Raft logs, and replica transport.
    pub fn producer_record(&self, actor: ActorId, tag: &[u8; 32]) -> Option<Vec<u8>> {
        self.service.accumulate_host().producer_record(actor, tag)
    }

    /// Retire one producer-private Task record after proving or expiry.
    pub fn prune_producer_record(&mut self, actor: ActorId, tag: &[u8; 32]) -> bool {
        self.service
            .accumulate_host_mut()
            .prune_producer_record(actor, tag)
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
            self.request_uses_private_ingress(request)?,
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

    fn validate_installed_and_release_availability(
        &mut self,
    ) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        let installed = self.validate_installed()?;
        if installed {
            // The committed store and snapshots now own these bytes. Dropping
            // the sidecar avoids retaining another full actor PVM/genesis
            // image for the lifetime of every root service.
            self.pending_install_availability = None;
        }
        Ok(installed)
    }

    /// Establish the current-term admission barrier and return the durable
    /// service high-water visible after applying through it. Node ingress must
    /// restore and allocate its trusted timeslot from this value, then call
    /// [`Self::invoke_after_admission_barrier`] without another catch-up.
    pub(crate) fn prepare_admission_barrier(&mut self) -> Result<u64, LocalRootTreeInvokeErrorV2> {
        self.service
            .admission_barrier()
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        if !self.validate_installed_and_release_availability()? {
            if !self.service.is_writable() {
                return Err(LocalRootTreeInvokeErrorV2::ServiceNotInstalled);
            }
            // Genesis installation, when this replica has just become the
            // first writable leader, is ordered after the same barrier and
            // before any actor admission slot exists. Use the no-catch-up path
            // so the ordering remains one contiguous critical sequence.
            let (programs, blobs) = self
                .pending_install_availability
                .as_ref()
                .ok_or(LocalRootTreeInvokeErrorV2::ServiceNotInstalled)?;
            let result = self
                .service
                .accumulate_with_availability_after_barrier(
                    &AccumulateRequestV2::Install(self.genesis.clone()),
                    programs,
                    blobs,
                )
                .map_err(RootTreeDriverErrorV2::into_invoke)?;
            match result.result {
                AccumulationResultV2::Installed(_) => {}
                AccumulationResultV2::Rejected(rejection) => {
                    return Err(LocalRootTreeInvokeErrorV2::Rejected(rejection));
                }
                _ => return Err(LocalRootTreeInvokeErrorV2::UnexpectedResult),
            }
            if !self.validate_installed_and_release_availability()? {
                return Err(LocalRootTreeInvokeErrorV2::ServiceNotInstalled);
            }
        }
        debug_assert!(self.pending_install_availability.is_none());
        self.service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .map(|header| header.admission_timeslot_high_water)
            .ok_or(LocalRootTreeInvokeErrorV2::ServiceNotInstalled)
    }

    /// Best authenticated leader hint observed by this root's Raft worker.
    /// Node ingress uses it only after a failed admission barrier to return a
    /// transport-level redirect; it never substitutes for the barrier itself.
    #[cfg(all(feature = "storage", feature = "network"))]
    pub(crate) fn admission_leader_hint(&self) -> Option<u16> {
        self.service.leader_hint()
    }

    fn ensure_installed(&mut self) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        self.service
            .catch_up()
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        if self.validate_installed_and_release_availability()? {
            debug_assert!(self.pending_install_availability.is_none());
            return Ok(true);
        }
        if !self.service.is_writable() {
            return Ok(false);
        }
        let (programs, blobs) = self
            .pending_install_availability
            .as_ref()
            .ok_or(LocalRootTreeInvokeErrorV2::ServiceNotInstalled)?;
        let result = self
            .service
            .accumulate_with_availability(
                &AccumulateRequestV2::Install(self.genesis.clone()),
                programs,
                blobs,
            )
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        match result.result {
            AccumulationResultV2::Installed(_) => {}
            AccumulationResultV2::Rejected(rejection) => {
                return Err(LocalRootTreeInvokeErrorV2::Rejected(rejection));
            }
            _ => return Err(LocalRootTreeInvokeErrorV2::UnexpectedResult),
        }
        if self.validate_installed_and_release_availability()? {
            debug_assert!(self.pending_install_availability.is_none());
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
        let role_authority = self
            .service
            .accumulate_host()
            .state_row(header.service_root, &StateKeyV2::RoleAuthority)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .map(|bytes| RoleAuthorityBindingV2::decode(&bytes))
            .transpose()
            .map_err(|_| LocalRootTreeInvokeErrorV2::ExistingActorMismatch)?;
        let descriptor = descriptor.ok_or(LocalRootTreeInvokeErrorV2::ExistingActorMismatch)?;
        if descriptor != self.expected_root
            || external.as_ref().is_none_or(|directory| {
                directory.actors.as_slice() != self.expected_external_actors.as_slice()
            })
            || role_authority != self.expected_role_authority
        {
            return Err(LocalRootTreeInvokeErrorV2::ExistingActorMismatch);
        }
        let policies = PackageRolePoliciesV2::decode(&descriptor.role_policies)
            .map_err(|_| LocalRootTreeInvokeErrorV2::ExistingActorMismatch)?;
        for dependency in policies.task_dependencies {
            if self
                .service
                .accumulate_host()
                .program(dependency.program)
                .is_none()
            {
                return Err(LocalRootTreeInvokeErrorV2::MissingInstalledProgram(
                    dependency.program,
                ));
            }
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

    /// Recover the exact authorization evidence already admitted for a
    /// direct invocation. This lets a host reattach a lost-result retry
    /// without reinterpreting the actor's *current* package policy after an
    /// upgrade. Every caller-controlled stable field is matched first; a
    /// reused invocation with different input remains divergent.
    pub(crate) fn recover_direct_authorization(
        &self,
        request: &LocalWorkRequestV2,
    ) -> Result<Option<AuthorizationEvidenceV2>, LocalRootTreeInvokeErrorV2> {
        let Some(record) = self
            .service
            .accumulate_host()
            .ingress_record(request.invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
        else {
            return Ok(None);
        };
        let ingress = record.ingress;
        if ingress.service != self.identity
            || ingress.invocation != request.invocation
            || ingress.target != request.target
            || ingress.method != request.method
            || !ingress.matches_arguments(&request.arguments)
            || ingress.origin != request.origin
            || ingress.imported_blobs != request.imported_blobs
            || ingress.proof_requested != request.proof_requested
        {
            return Err(LocalRootTreeInvokeErrorV2::DivergentInvocation);
        }
        Ok(Some(direct_ingress_authorization(
            self.service.accumulate_host().local_store(),
            &ingress,
        )?))
    }

    /// Derive the exact invocation-scoped decision the installed role
    /// authority must finalize before this work can be admitted.
    ///
    /// A fresh claim deliberately uses the same scheduler projection as
    /// Refine. A retry instead recovers the exact admitted credential. Both
    /// paths bind the guest-owned target deployment/program and every stable
    /// caller input without trusting a node-side reconstruction of those
    /// fields.
    pub fn role_authorization_claim(
        &self,
        request: &LocalWorkRequestV2,
        role: crate::SpaceRole,
        policy: &MethodPolicyV2,
    ) -> Result<RoleAuthorizationClaimV2, LocalRootTreeInvokeErrorV2> {
        if self.expected_role_authority.is_none()
            || request.workflow_step != 0
            || request.authorization != AuthorizationEvidenceV2::Public
            || request.proof_requested
            || policy.public
            || policy.attested
            || policy.space_role != Some(role.as_u8())
            || policy.actor_role.is_some()
        {
            return Err(LocalRootTreeInvokeErrorV2::InvalidRoleAssertionPublication);
        }
        if let Some(authorization) = self.recover_direct_authorization(request)? {
            let AuthorizationEvidenceV2::Credential {
                policy: supplied_policy,
                credential_commitment,
                bytes,
            } = authorization
            else {
                return Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow);
            };
            let credential = RoleCredentialV2::decode(&bytes)
                .map_err(|_| LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
            if supplied_policy != policy.policy
                || credential.commitment() != credential_commitment
                || credential.holder != request.origin
                || credential.space_role != Some(role)
                || credential.actor_role.is_some()
            {
                return Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow);
            }
            let assertion = AccumulatedRoleAssertionV2::decode(&credential.authenticator)
                .map_err(|_| LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
            let authority = self
                .expected_role_authority
                .as_ref()
                .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
            let claim = assertion.claim.clone();
            if !assertion.matches_authority(authority)
                || credential.scope != claim.scope
                || claim.space != self.identity.space
                || claim.holder != request.origin
                || claim.role != role
                || claim.audience != self.identity
                || claim.invocation != request.invocation
                || claim.target != request.target
                || claim.method != request.method
                || claim.policy != policy.policy
            {
                return Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow);
            }
            return Ok(claim);
        }
        let private_arguments = self
            .request_uses_private_ingress(request)?
            .then(|| BlobRefV2::of_bytes(&request.arguments));
        let prepared = self.prepare_request(request.clone(), private_arguments)?;
        if prepared.work.service != self.identity
            || prepared.work.target != request.target
            || prepared.work.invocation != request.invocation
            || prepared.work.method != request.method
            || prepared.work.origin != request.origin
        {
            return Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow);
        }
        Ok(RoleAuthorizationClaimV2 {
            space: self.identity.space,
            holder: request.origin,
            role,
            audience: self.identity.clone(),
            invocation: request.invocation,
            scope: prepared.work.authorization_scope(),
            target: request.target,
            method: request.method.clone(),
            policy: policy.policy,
        })
    }

    /// Derive the destination-scoped authority decision for one finalized
    /// cross-root message. Source outbox bytes remain public and immutable;
    /// the resulting credential is carried separately by the delivery and is
    /// committed into the destination inbox only after guest verification.
    pub fn delivery_role_authorization_claim(
        &self,
        message: &MessageRecordV2,
        role: crate::SpaceRole,
        policy: &MethodPolicyV2,
        logical_timeslot: u64,
    ) -> Result<RoleAuthorizationClaimV2, LocalRootTreeInvokeErrorV2> {
        if self.expected_role_authority.is_none()
            || message.to_service != self.identity
            || message.to != self.root_actor
            || message.authorization != AuthorizationEvidenceV2::Public
            || message.proof_requested
            || policy.public
            || policy.attested
            || policy.space_role != Some(role.as_u8())
            || policy.actor_role.is_some()
        {
            return Err(LocalRootTreeInvokeErrorV2::InvalidRoleAssertionPublication);
        }
        let header = self
            .service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        let actor = self
            .service
            .accumulate_host()
            .state_row(
                header.service_root,
                &StateKeyV2::ActorDescriptor(message.to),
            )
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .and_then(|bytes| ActorGenesisV2::decode(&bytes).ok())
            .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        let base = if header.consistency == ConsistencyModeV2::Crdt {
            ConsistencyBaseV2::Crdt {
                heads: header.crdt_heads,
            }
        } else {
            ConsistencyBaseV2::Linear {
                revision: header.revision,
                state_root: header
                    .state_root
                    .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?,
            }
        };
        let work = message
            .authorization_work(
                &self.identity,
                logical_timeslot,
                AuthorizationEvidenceV2::Public,
                header.consistency,
                base,
                &actor,
            )
            .filter(|work| work.method == policy.method)
            .ok_or(LocalRootTreeInvokeErrorV2::InvalidRoleAssertionPublication)?;
        Ok(RoleAuthorizationClaimV2 {
            space: self.identity.space,
            holder: work.origin,
            role,
            audience: self.identity.clone(),
            invocation: work.invocation,
            scope: work.authorization_scope(),
            target: work.target,
            method: work.method,
            policy: policy.policy,
        })
    }

    /// Recover the exact destination authorization of an already committed
    /// delivery before consulting the actor's current package policy. This is
    /// the lost-result/restart path and remains valid across later upgrades.
    pub fn recover_delivery_authorization(
        &self,
        message: &MessageRecordV2,
        source_outbox: &[MessageRecordV2],
        source_receipt: &AccumulationReceiptV2,
    ) -> Result<Option<AuthorizationEvidenceV2>, LocalRootTreeInvokeErrorV2> {
        let Some(bytes) = self
            .service
            .accumulate_host()
            .local_store()
            .row(&delivery_storage_key(message.call_id))
        else {
            return Ok(None);
        };
        let record = DeliveryRecordV2::decode(&bytes)
            .map_err(|_| LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        if record.call_id != message.call_id {
            return Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow);
        }
        let header = self
            .service
            .accumulate_host()
            .header()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        let authorization = if record.retired_at.is_some() {
            let inbox = self
                .service
                .accumulate_host()
                .state_row(header.service_root, &StateKeyV2::Inbox(message.call_id))
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?;
            let workflow = self
                .service
                .accumulate_host()
                .workflow_checkpoint(super::InvocationId::for_call(message.call_id))
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?;
            if record.consumed || inbox.is_some() || workflow.is_some() {
                return Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow);
            }
            record.authorization.clone()
        } else if record.consumed {
            let workflow = self
                .service
                .accumulate_host()
                .workflow_checkpoint(super::InvocationId::for_call(message.call_id))
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
                .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
            let work = workflow.resume_work;
            let method = if message.payload.first() == Some(&crate::value::TAG_DYNAMIC) {
                <crate::value::Msg as crate::Decode>::try_decode(&message.payload[1..])
                    .map(|message| message.name)
            } else {
                None
            };
            if work.service != self.identity
                || work.invocation != super::InvocationId::for_call(message.call_id)
                || work.target != message.to
                || method.as_deref() != Some(work.method.as_str())
                || work.origin != Origin::Actor(message.from)
                || work.causal_parent != Some(message.caller_invocation)
                || work.parent_call != Some(message.call_id)
                || work.causal_context != Some(CausalCallContextV2::from(message))
                || work.proof_requested != message.proof_requested
                || work.authorization != record.authorization
            {
                return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
            }
            work.authorization
        } else {
            let inbox = self
                .service
                .accumulate_host()
                .state_row(header.service_root, &StateKeyV2::Inbox(message.call_id))
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
                .and_then(|bytes| MessageRecordV2::decode(&bytes).ok())
                .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
            let authorization = inbox.authorization.clone();
            if authorization != record.authorization {
                return Err(LocalRootTreeInvokeErrorV2::CorruptWorkflow);
            }
            let mut source_message = inbox;
            source_message.authorization = AuthorizationEvidenceV2::Public;
            if source_message != *message {
                return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
            }
            authorization
        };
        let candidate = LocalWorkSchedulerV2::prepare_authorized_delivery(
            self.service.accumulate_host().local_store(),
            record.logical_timeslot,
            authorization.clone(),
            message.clone(),
            source_outbox.to_vec(),
            source_receipt.clone(),
        )
        .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        if candidate.retry_identity() != record.retry_identity {
            return Err(LocalRootTreeInvokeErrorV2::DivergentReplay);
        }
        Ok(Some(authorization))
    }

    /// Recover an authority decision from guest-owned durable workflow and
    /// receipt rows after its transient publication was acknowledged. This is
    /// the exact-invocation retry path used by platform authorization; it
    /// never re-executes the authority actor or fabricates a receipt.
    pub fn recover_role_assertion(
        &self,
        claim: RoleAuthorizationClaimV2,
        authority: &RoleAuthorityBindingV2,
    ) -> Result<AccumulatedRoleAssertionV2, LocalRootTreeInvokeErrorV2> {
        if authority.service != self.identity || !self.owns_actor(authority.actor)? {
            return Err(LocalRootTreeInvokeErrorV2::InvalidRoleAssertionPublication);
        }
        let input = WorkInputIdV2 {
            invocation: claim.authority_invocation(),
            workflow_step: 0,
        };
        let checkpoint = self
            .service
            .accumulate_host()
            .workflow_checkpoint(input.invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::InvalidRoleAssertionPublication)?;
        let receipt = self
            .service
            .accumulate_host()
            .accumulation_receipt(input)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::InvalidRoleAssertionPublication)?;
        let eligibility = self
            .service
            .accumulate_host()
            .local_store()
            .role_assertion_eligibility(input)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::InvalidRoleAssertionPublication)?;
        let expected_reply = claim.authority_reply(authority.actor);
        let transition_is_bound = if receipt.consistency == ConsistencyModeV2::Crdt {
            self.service
                .accumulate_host()
                .row(&crdt_node_storage_key(checkpoint.transition_hash))
                .and_then(|bytes| CrdtChangeV2::decode(bytes).ok())
                .is_some_and(|change| {
                    change.cid() == checkpoint.transition_hash
                        && change.receipt_commitment() == receipt.accepted_transition
                        && receipt
                            .resulting_crdt_heads
                            .binary_search(&checkpoint.transition_hash)
                            .is_ok()
                })
        } else {
            receipt.accepted_transition == checkpoint.transition_hash
        };
        if checkpoint.input != input
            || checkpoint.resume_work.target != authority.actor
            || checkpoint.resume_work.method != super::ROLE_AUTHORITY_DECISION_METHOD_V2
            || receipt.service != authority.service
            || !transition_is_bound
            || receipt.reply_commitment != Some(expected_reply.commitment())
            || receipt.outbox_commitment.is_some()
            || receipt.checkpoint != 0
            || eligibility.input != input
            || eligibility.transition_commitment != receipt.accepted_transition
            || eligibility.reply_commitment != expected_reply.commitment()
        {
            return Err(LocalRootTreeInvokeErrorV2::InvalidRoleAssertionPublication);
        }
        let assertion = AccumulatedRoleAssertionV2 { claim, receipt };
        if !assertion.matches_authority(authority) {
            return Err(LocalRootTreeInvokeErrorV2::InvalidRoleAssertionPublication);
        }
        Ok(assertion)
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
        self.prepare_admission_barrier()?;
        self.invoke_after_admission_barrier(request)
    }

    /// Admit, prove, and commit one attested direct invocation. Proof
    /// production is read-only; only the final proof-bearing Apply crosses the
    /// durable or replicated commit boundary. An exact retry reattaches the
    /// guest-owned publication without invoking the actor or producer again.
    pub fn invoke_attested<P: AttestationProofProducerV2 + ?Sized>(
        &mut self,
        request: LocalWorkRequestV2,
        producer: &mut P,
    ) -> Result<CommittedRootTreeSliceV2, AttestedRootTreeInvokeErrorV2<P::Error>> {
        if !request.proof_requested {
            return Err(AttestedRootTreeInvokeErrorV2::InvalidPreparation);
        }
        self.prepare_admission_barrier()?;
        self.invoke_attested_after_admission_barrier_with_receipts(request, &[], producer)
    }

    /// Admit and execute ingress after [`Self::prepare_admission_barrier`]
    /// returned and the caller allocated a slot above its high-water.
    pub(crate) fn invoke_after_admission_barrier(
        &mut self,
        request: LocalWorkRequestV2,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        self.invoke_after_admission_barrier_with_receipts(request, &[])
    }

    /// Admit one invocation with exact receipt-verifier decisions already
    /// authenticated by node routing. Raft roots quorum-order those decisions
    /// beside AdmitIngress; Local roots expose them only to the same physical
    /// IC-5 call.
    pub(crate) fn invoke_after_admission_barrier_with_receipts(
        &mut self,
        request: LocalWorkRequestV2,
        receipt_verifications: &[super::ReceiptVerificationRequestV2],
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        if request.proof_requested {
            return Err(LocalRootTreeInvokeErrorV2::ProofProducerRequired);
        }
        if let Some(committed) = self.recover_committed_invocation(&request)? {
            self.retire_consumed_private_ingress(request.invocation)?;
            return Ok(committed);
        }
        let invocation = request.invocation;
        self.admit_ingress_after_barrier_with_receipts(&request, receipt_verifications)?;
        self.invoke_admitted_after_barrier(invocation)
    }

    /// Admit, prove, and commit one attested direct invocation after the
    /// caller established the service barrier. The read-only preparation and
    /// proof production happen only after guest-owned ingress admission; Raft
    /// orders the final proved Apply and its proof artifact.
    pub(crate) fn invoke_attested_after_admission_barrier_with_receipts<
        P: AttestationProofProducerV2 + ?Sized,
    >(
        &mut self,
        request: LocalWorkRequestV2,
        receipt_verifications: &[super::ReceiptVerificationRequestV2],
        producer: &mut P,
    ) -> Result<CommittedRootTreeSliceV2, AttestedRootTreeInvokeErrorV2<P::Error>> {
        if !request.proof_requested {
            return Err(AttestedRootTreeInvokeErrorV2::InvalidPreparation);
        }
        if let Some(committed) = self.recover_committed_invocation(&request)? {
            self.retire_consumed_private_ingress(request.invocation)?;
            return Ok(committed);
        }
        let invocation = request.invocation;
        self.admit_ingress_after_barrier_with_receipts(&request, receipt_verifications)?;
        self.invoke_admitted_attested_after_barrier(invocation, producer)
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
        self.admit_ingress_after_barrier_with_receipts(request, &[])
    }

    pub(crate) fn admit_ingress_after_barrier_with_receipts(
        &mut self,
        request: &LocalWorkRequestV2,
        receipt_verifications: &[super::ReceiptVerificationRequestV2],
    ) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        if self.consistency() == ConsistencyModeV2::Crdt
            && let AuthorizationEvidenceV2::Credential { bytes, .. } = &request.authorization
        {
            self.service
                .accumulate_host_mut()
                .local_store_mut()
                .import_blob(bytes.clone());
        }
        let ingress = direct_ingress_from_request(
            self.service.accumulate_host().local_store(),
            &self.identity,
            request,
            self.request_uses_private_ingress(request)?,
        )?;
        let existing_ingress = self
            .service
            .accumulate_host()
            .ingress_record(request.invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?;
        let mut owns_private_ingress = false;
        if let Some(reference) = ingress.private_arguments.as_ref() {
            match existing_ingress.as_ref() {
                None => {
                    // Raft admission is allowed to consume only a sidecar
                    // already acknowledged by the node's all-voter barrier.
                    // A direct service caller cannot silently downgrade that
                    // protocol to one local write.
                    let persisted = if self.consistency == ConsistencyModeV2::Raft {
                        let existing = self
                            .service
                            .accumulate_host()
                            .private_ingress(request.invocation, reference)
                            .filter(|bytes| bytes == &request.arguments)
                            .map(|_| reference.clone());
                        if let Some(existing) = existing {
                            existing
                        } else if self
                            .steady_raft_voters()
                            .is_some_and(|(me, voters)| voters.as_slice() == [me])
                        {
                            self.service
                                .accumulate_host_mut()
                                .persist_replicated_private_ingress(
                                    request.invocation,
                                    &request.arguments,
                                )
                                .map_err(|_| {
                                    LocalRootTreeInvokeErrorV2::PrivateIngressUnavailable
                                })?
                        } else {
                            return Err(LocalRootTreeInvokeErrorV2::PrivateIngressUnavailable);
                        }
                    } else {
                        owns_private_ingress = true;
                        self.service
                            .accumulate_host_mut()
                            .persist_private_ingress(request.invocation, &request.arguments)
                            .map_err(|_| LocalRootTreeInvokeErrorV2::PrivateIngressUnavailable)?
                    };
                    if persisted != *reference {
                        self.service
                            .accumulate_host_mut()
                            .prune_private_ingress(request.invocation)
                            .map_err(|_| {
                                LocalRootTreeInvokeErrorV2::PrivateIngressRetirementFailed
                            })?;
                        return Err(LocalRootTreeInvokeErrorV2::PrivateIngressUnavailable);
                    }
                }
                Some(record) if !record.consumed && record.ingress.matches_retry(&ingress) => {
                    // The admitted request owns this artifact. An exact retry
                    // may repair a missing process-local copy but must never
                    // acquire cleanup ownership over it.
                    let persisted = self
                        .service
                        .accumulate_host_mut()
                        .persist_private_ingress(request.invocation, &request.arguments)
                        .map_err(|_| LocalRootTreeInvokeErrorV2::PrivateIngressUnavailable)?;
                    if persisted != *reference {
                        return Err(LocalRootTreeInvokeErrorV2::PrivateIngressUnavailable);
                    }
                }
                Some(_) => {}
            }
        }
        let private_ingress = ingress.private_arguments.is_some();
        let accumulated = match self
            .service
            .accumulate_with_receipt_verifications_after_barrier(
                &AccumulateRequestV2::AdmitIngress(ingress),
                receipt_verifications,
            ) {
            Ok(accumulated) => accumulated,
            Err(error) => {
                if owns_private_ingress {
                    self.service
                        .accumulate_host_mut()
                        .prune_private_ingress(request.invocation)
                        .map_err(|_| LocalRootTreeInvokeErrorV2::PrivateIngressRetirementFailed)?;
                }
                return Err(RootTreeDriverErrorV2::into_invoke(error));
            }
        };
        match accumulated.result {
            AccumulationResultV2::IngressAdmitted {
                invocation,
                receipt: _,
                duplicate,
            } if invocation == request.invocation => Ok(duplicate),
            AccumulationResultV2::Rejected(rejection) => {
                if private_ingress && owns_private_ingress {
                    self.service
                        .accumulate_host_mut()
                        .prune_private_ingress(request.invocation)
                        .map_err(|_| LocalRootTreeInvokeErrorV2::PrivateIngressRetirementFailed)?;
                }
                Err(LocalRootTreeInvokeErrorV2::Rejected(rejection))
            }
            _ => {
                if private_ingress && owns_private_ingress {
                    self.service
                        .accumulate_host_mut()
                        .prune_private_ingress(request.invocation)
                        .map_err(|_| LocalRootTreeInvokeErrorV2::PrivateIngressRetirementFailed)?;
                }
                Err(LocalRootTreeInvokeErrorV2::UnexpectedResult)
            }
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
        let consumed = record.consumed;
        let (request, private_arguments) = self.request_from_admitted_ingress(record)?;
        if consumed {
            let committed = self
                .recover_committed_invocation_with_private_reference(
                    &request,
                    private_arguments.as_ref(),
                )?
                .ok_or(LocalRootTreeInvokeErrorV2::DivergentInvocation)?;
            self.retire_consumed_private_ingress(invocation)?;
            return Ok(committed);
        }
        self.execute_admitted_after_barrier(request, private_arguments)
    }

    pub(crate) fn invoke_admitted_attested_after_barrier<P: AttestationProofProducerV2 + ?Sized>(
        &mut self,
        invocation: super::InvocationId,
        producer: &mut P,
    ) -> Result<CommittedRootTreeSliceV2, AttestedRootTreeInvokeErrorV2<P::Error>> {
        let record = self
            .service
            .accumulate_host()
            .ingress_record(invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::CorruptWorkflow)?;
        let consumed = record.consumed;
        let (request, private_arguments) = self.request_from_admitted_ingress(record)?;
        if !request.proof_requested {
            return Err(AttestedRootTreeInvokeErrorV2::InvalidPreparation);
        }
        if let Some(committed) = self.recover_committed_invocation_with_private_reference(
            &request,
            private_arguments.as_ref(),
        )? {
            self.retire_consumed_private_ingress(invocation)?;
            return Ok(committed);
        }
        if consumed {
            return Err(LocalRootTreeInvokeErrorV2::DivergentInvocation.into());
        }
        let prepared = self.prepare_request(request, private_arguments)?;
        self.execute_prepared_attested_after_barrier(prepared, producer)
    }

    /// Prove and execute one previously admitted attested invocation. This is
    /// the restart/retry counterpart of [`Self::invoke_attested`]; admission
    /// remains guest-owned even when no producer was available initially.
    pub fn invoke_admitted_attested<P: AttestationProofProducerV2 + ?Sized>(
        &mut self,
        invocation: super::InvocationId,
        producer: &mut P,
    ) -> Result<CommittedRootTreeSliceV2, AttestedRootTreeInvokeErrorV2<P::Error>> {
        self.prepare_admission_barrier()?;
        self.invoke_admitted_attested_after_barrier(invocation, producer)
    }

    fn execute_admitted_after_barrier(
        &mut self,
        request: LocalWorkRequestV2,
        private_arguments: Option<BlobRefV2>,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        if request.proof_requested {
            return Err(LocalRootTreeInvokeErrorV2::ProofProducerRequired);
        }
        if let Some(committed) = self.recover_committed_invocation(&request)? {
            self.retire_consumed_private_ingress(request.invocation)?;
            return Ok(committed);
        }
        let prepared = self.prepare_request(request, private_arguments)?;
        self.execute_prepared_after_barrier(prepared)
    }

    /// Resume an explicit-yield checkpoint from guest-owned workflow state.
    /// A checkpoint waiting on a durable call remains unavailable until the
    /// authenticated reply/timeout orchestration supplies that outcome.
    pub fn resume_yield(
        &mut self,
        invocation: super::InvocationId,
        logical_timeslot: u64,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        self.prepare_admission_barrier()?;
        let prepared = LocalWorkSchedulerV2::prepare_resume(
            self.service.accumulate_host().local_store(),
            invocation,
            logical_timeslot,
            None,
        )
        .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        self.execute_prepared_after_barrier(prepared)
    }

    /// Make one receipt selected by an authenticated host transport available
    /// to guest verification. This is verifier policy, not service state, and
    /// therefore must only be called after the host has bound the source route
    /// to `receipt.service`. Replicated roots require a consensus finality
    /// verifier rather than this local authority seam.
    pub(crate) fn authorize_finalized_receipt(
        &mut self,
        expected_producer: ActorId,
        receipt: &AccumulationReceiptV2,
    ) -> super::ReceiptVerificationRequestV2 {
        let verification = super::ReceiptVerificationRequestV2 {
            expected_producer,
            receipt: receipt.clone(),
        };
        if self.consistency() == ConsistencyModeV2::Local {
            self.service
                .accumulate_host_mut()
                .local_store_mut()
                .allow_receipt(&verification);
        }
        verification
    }

    /// Admit one authenticated source outbox member after the caller has
    /// established the local admission barrier and allocated a trusted slot.
    pub(crate) fn deliver_finalized_after_barrier(
        &mut self,
        logical_timeslot: u64,
        authorization: AuthorizationEvidenceV2,
        message: super::MessageRecordV2,
        source_outbox: Vec<super::MessageRecordV2>,
        source_receipt: AccumulationReceiptV2,
        receipt_verifications: Vec<super::ReceiptVerificationRequestV2>,
    ) -> Result<super::CommittedDeliveryV2, LocalRootTreeInvokeErrorV2> {
        let call = message.call_id;
        let delivery = LocalWorkSchedulerV2::prepare_authorized_delivery(
            self.service.accumulate_host().local_store(),
            logical_timeslot,
            authorization,
            message,
            source_outbox,
            source_receipt,
        )
        .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        let accumulated = self
            .service
            .accumulate_with_receipt_verifications_after_barrier(
                &AccumulateRequestV2::Deliver(delivery),
                &receipt_verifications,
            )
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        match accumulated.result {
            AccumulationResultV2::Accepted {
                receipt,
                published,
                duplicate,
            } if published == PublishedEffectsV2::default() => Ok(super::CommittedDeliveryV2 {
                call,
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

    /// Execute one already-admitted durable inbox row after a fresh trusted
    /// scheduling barrier. Ordinary transport never invokes attested methods.
    pub(crate) fn invoke_inbox_after_barrier(
        &mut self,
        call: super::CallId,
        logical_timeslot: u64,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        let prepared = LocalWorkSchedulerV2::prepare_inbox(
            self.service.accumulate_host().local_store(),
            call,
            logical_timeslot,
        )
        .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        if prepared.work.proof_requested {
            return Err(LocalRootTreeInvokeErrorV2::ProofProducerRequired);
        }
        self.execute_prepared_after_barrier(prepared)
    }

    /// Prove and execute one already-admitted attested inbox slice. Delivery
    /// authorization and the source receipt were committed before this step;
    /// this method adds the canonical Refine proof before the final Apply.
    pub(crate) fn invoke_attested_inbox_after_barrier<P: AttestationProofProducerV2 + ?Sized>(
        &mut self,
        call: super::CallId,
        logical_timeslot: u64,
        producer: &mut P,
    ) -> Result<CommittedRootTreeSliceV2, AttestedRootTreeInvokeErrorV2<P::Error>> {
        let prepared = LocalWorkSchedulerV2::prepare_inbox(
            self.service.accumulate_host().local_store(),
            call,
            logical_timeslot,
        )
        .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        if !prepared.work.proof_requested {
            return Err(AttestedRootTreeInvokeErrorV2::InvalidPreparation);
        }
        self.execute_prepared_attested_after_barrier(prepared, producer)
    }

    /// Prove and execute one guest-owned durable inbox row. A failed proof or
    /// durable commit leaves the inbox queued, so restart recovery can call
    /// this method again with the same call and trusted admission slot.
    pub fn invoke_attested_inbox<P: AttestationProofProducerV2 + ?Sized>(
        &mut self,
        call: super::CallId,
        logical_timeslot: u64,
        producer: &mut P,
    ) -> Result<CommittedRootTreeSliceV2, AttestedRootTreeInvokeErrorV2<P::Error>> {
        self.prepare_admission_barrier()?;
        self.invoke_attested_inbox_after_barrier(call, logical_timeslot, producer)
    }

    /// Atomically retire one expired linear inbox and release any
    /// deployment-scoped authorization pin. The caller has already
    /// established the service barrier and supplies its trusted slot to the
    /// physical Accumulate host.
    pub(crate) fn retire_inbox_after_barrier(
        &mut self,
        call: super::CallId,
        logical_timeslot: u64,
    ) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        let Some(retirement) = LocalWorkSchedulerV2::prepare_inbox_retirement(
            self.service.accumulate_host().local_store(),
            call,
            logical_timeslot,
        )
        .map_err(LocalRootTreeInvokeErrorV2::Schedule)?
        else {
            return Ok(true);
        };
        let accumulated = self
            .service
            .accumulate_at_after_barrier(
                &AccumulateRequestV2::RetireInbox(retirement),
                logical_timeslot,
            )
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        match accumulated.result {
            AccumulationResultV2::InboxRetired { call_id, duplicate } if call_id == call => {
                Ok(duplicate)
            }
            AccumulationResultV2::Rejected(rejection) => {
                Err(LocalRootTreeInvokeErrorV2::Rejected(rejection))
            }
            _ => Err(LocalRootTreeInvokeErrorV2::UnexpectedResult),
        }
    }

    /// Resume the exact saved machine with one finalized ordinary reply.
    pub(crate) fn resume_reply_after_barrier(
        &mut self,
        caller_invocation: super::InvocationId,
        logical_timeslot: u64,
        awaited_reply: super::AccumulatedReplyV2,
        proof_artifact: Option<ImportedBlobV2>,
        receipt_verification: super::ReceiptVerificationRequestV2,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        match (awaited_reply.attestation.as_ref(), proof_artifact.as_ref()) {
            (None, None) => {}
            (Some(attestation), Some(artifact))
                if artifact.reference == attestation.proof.proof_blob
                    && artifact.reference.matches(&artifact.bytes) =>
            {
                let verification = super::ProofVerificationRequestV2 {
                    actor_program: attestation.statement.actor_program,
                    execution_semantics: attestation
                        .statement
                        .accumulation_receipt
                        .service
                        .execution_semantics,
                    statement: attestation.proof.statement,
                    trace: attestation.proof.trace,
                    proof_blob: attestation.proof.proof_blob.clone(),
                };
                if !self
                    .service
                    .accumulate_host_mut()
                    .make_proof_available(&verification, &artifact.bytes)
                {
                    return Err(LocalRootTreeInvokeErrorV2::ProofUnavailable);
                }
            }
            _ => return Err(LocalRootTreeInvokeErrorV2::ProofUnavailable),
        }
        let prepared = LocalWorkSchedulerV2::prepare_resume(
            self.service.accumulate_host().local_store(),
            caller_invocation,
            logical_timeslot,
            Some(awaited_reply),
        )
        .map_err(LocalRootTreeInvokeErrorV2::Schedule)?;
        if prepared.work.proof_requested {
            return Err(LocalRootTreeInvokeErrorV2::ProofProducerRequired);
        }
        self.execute_prepared_with_receipts_after_barrier(
            prepared,
            &[receipt_verification],
            proof_artifact,
        )
    }

    /// Commit every durable call whose deadline is at or before the trusted
    /// ambient slot. Expiration itself is guest-owned and slot-authenticated;
    /// this host method only discovers due rows and drives physical IC-5.
    pub(crate) fn expire_due_calls_after_barrier(
        &mut self,
        logical_timeslot: u64,
    ) -> Result<Vec<super::AccumulatedTimeoutV2>, LocalRootTreeInvokeErrorV2> {
        let mut expired = Vec::new();
        loop {
            // A linear expiration advances the service revision. Re-read and
            // prepare after every commit so the next envelope binds the fresh
            // base rather than a shared stale snapshot of the due set.
            let Some(expiration) = LocalWorkSchedulerV2::prepare_due_call_expirations(
                self.service.accumulate_host().local_store(),
                logical_timeslot,
            )
            .map_err(LocalRootTreeInvokeErrorV2::Schedule)?
            .into_iter()
            .next() else {
                break;
            };
            let accumulated = self
                .service
                .accumulate_at_after_barrier(
                    &AccumulateRequestV2::ExpireCall(expiration),
                    logical_timeslot,
                )
                .map_err(RootTreeDriverErrorV2::into_invoke)?;
            match accumulated.result {
                AccumulationResultV2::CallExpired { timeout, .. } => expired.push(timeout),
                AccumulationResultV2::Rejected(rejection) => {
                    return Err(LocalRootTreeInvokeErrorV2::Rejected(rejection));
                }
                _ => return Err(LocalRootTreeInvokeErrorV2::UnexpectedResult),
            }
        }
        Ok(expired)
    }

    /// Resume the exact saved machine after a guest-committed timeout.
    pub(crate) fn resume_timeout_after_barrier(
        &mut self,
        invocation: super::InvocationId,
        logical_timeslot: u64,
    ) -> Result<Option<CommittedRootTreeSliceV2>, LocalRootTreeInvokeErrorV2> {
        let Some(prepared) = LocalWorkSchedulerV2::prepare_timeout_resume(
            self.service.accumulate_host().local_store(),
            invocation,
            logical_timeslot,
        )
        .map_err(LocalRootTreeInvokeErrorV2::Schedule)?
        else {
            return Ok(None);
        };
        if prepared.work.proof_requested {
            return Err(LocalRootTreeInvokeErrorV2::ProofProducerRequired);
        }
        self.execute_prepared_after_barrier(prepared).map(Some)
    }

    /// Whether this exact reply already advanced the durable workflow. This
    /// lets a lost transport acknowledgement be replayed without restoring or
    /// executing the actor a second time.
    pub(crate) fn reply_already_accumulated(
        &self,
        invocation: super::InvocationId,
        reply: &super::AccumulatedReplyV2,
    ) -> Result<bool, LocalRootTreeInvokeErrorV2> {
        let admission = self
            .service
            .accumulate_host()
            .reply_admission(reply.reply.call_id)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?;
        Ok(admission.is_some_and(|(admission, _)| {
            admission.input.invocation == invocation
                && admission.awaited_reply.logical_identity() == reply.logical_identity()
        }))
    }

    fn execute_prepared_after_barrier(
        &mut self,
        prepared: PreparedWorkV2,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        self.execute_prepared_with_receipts_after_barrier(prepared, &[], None)
    }

    fn execute_prepared_with_receipts_after_barrier(
        &mut self,
        prepared: PreparedWorkV2,
        receipt_verifications: &[super::ReceiptVerificationRequestV2],
        proof_artifact: Option<ImportedBlobV2>,
    ) -> Result<CommittedRootTreeSliceV2, LocalRootTreeInvokeErrorV2> {
        let refined = self
            .service
            .refine_actor_tree_after_barrier(&prepared.work, &prepared.imports)
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        let PreparedWorkV2 {
            mut work,
            imports: _,
        } = prepared;
        self.service
            .accumulate_host_mut()
            .persist_producer_records(&refined.producer_records)
            .map_err(|_| LocalRootTreeInvokeErrorV2::ProducerRecordUnavailable)?;
        let input = work.input_id();
        if work.private_arguments.is_some() {
            // Refine consumes the hydrated preimage locally. Consensus and
            // the guest Apply boundary carry only its authenticated content
            // address, so plaintext never enters a Raft log entry.
            work.arguments.clear();
        }
        let mut provided_blobs = refined.exported_blobs;
        if let Some(proof) = proof_artifact {
            match provided_blobs
                .binary_search_by_key(&proof.reference.hash, |blob| blob.reference.hash)
            {
                Ok(index) if provided_blobs[index] != proof => {
                    return Err(LocalRootTreeInvokeErrorV2::ProofUnavailable);
                }
                Ok(_) => {}
                Err(index) => provided_blobs.insert(index, proof),
            }
        }
        let accumulated = self
            .service
            .accumulate_with_receipt_verifications_after_barrier(
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work,
                    transition: refined.transition,
                    provided_blobs,
                }),
                receipt_verifications,
            )
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
            role_assertion_eligibility: self
                .service
                .accumulate_host()
                .local_store()
                .role_assertion_eligibility(input)
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?,
            duplicate,
            refine_gas_used: refined.gas_used,
            accumulate_gas_used: accumulated.gas_used,
        })
    }

    fn execute_prepared_attested_after_barrier<P: AttestationProofProducerV2 + ?Sized>(
        &mut self,
        prepared: PreparedWorkV2,
        producer: &mut P,
    ) -> Result<CommittedRootTreeSliceV2, AttestedRootTreeInvokeErrorV2<P::Error>> {
        if !prepared.work.proof_requested {
            return Err(AttestedRootTreeInvokeErrorV2::InvalidPreparation);
        }
        let refined = self
            .service
            .refine_actor_tree_after_barrier(&prepared.work, &prepared.imports)
            .map_err(RootTreeDriverErrorV2::into_invoke)?;
        let PreparedWorkV2 { mut work, imports } = prepared;
        self.service
            .accumulate_host_mut()
            .persist_producer_records(&refined.producer_records)
            .map_err(|_| LocalRootTreeInvokeErrorV2::ProducerRecordUnavailable)?;
        let input = work.input_id();
        if work.private_arguments.is_some() {
            work.arguments.clear();
        }
        let committed = self.service.accumulate_attested_after_barrier(
            AccumulationEnvelopeV2 {
                work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            },
            &imports,
            producer,
        )?;
        let publication = self
            .service
            .accumulate_host()
            .pending_publications()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .into_iter()
            .find(|publication| publication.input == input)
            .ok_or(LocalRootTreeInvokeErrorV2::MissingPublication)?;
        if publication.receipt != committed.preparation.receipt
            || publication.published != committed.published
            || publication.published.proof.as_ref() != Some(&committed.proof)
            || !committed.proof.proof_blob.matches(&committed.proof_bytes)
        {
            return Err(AttestedRootTreeInvokeErrorV2::CommitMismatch);
        }
        Ok(CommittedRootTreeSliceV2 {
            input,
            receipt: committed.preparation.receipt,
            published: committed.published,
            publication: Some(publication),
            role_assertion_eligibility: self
                .service
                .accumulate_host()
                .local_store()
                .role_assertion_eligibility(input)
                .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?,
            duplicate: false,
            refine_gas_used: refined.gas_used,
            accumulate_gas_used: committed.accumulate_gas_used,
        })
    }

    /// Commit only the current canonical head set. The node uses this cheap
    /// identifier to avoid rebuilding the complete O(history) sync envelope
    /// on every transport poll.
    pub(crate) fn crdt_frontier_commitment(
        &self,
    ) -> Result<Option<super::Hash>, LocalRootTreeInvokeErrorV2> {
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
        let mut bytes = Vec::with_capacity(header.crdt_heads.len() * 32);
        for head in header.crdt_heads {
            bytes.extend_from_slice(&head.0);
        }
        Ok(Some(super::artifact_hash(b"crdt-frontier", &bytes)))
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

    /// Import peer nodes only through the canonical guest's SyncCrdt
    /// Accumulate request. Receipt finality must already be available from an
    /// independent verifier configured on the host; the envelope never
    /// authorizes its own receipts.
    pub fn sync_finalized_crdt(
        &mut self,
        envelope: CrdtSyncEnvelopeV2,
    ) -> Result<CommittedCrdtSyncV2, LocalRootTreeInvokeErrorV2> {
        self.sync_crdt_with_verifications(envelope, &[])
    }

    /// Import one CRDT envelope whose exact transport peer was independently
    /// authenticated as an enrolled, sync-floor-authorized replica by the
    /// node. The ordered verifier sidecar is derived here rather than accepted
    /// from the wire, so a peer cannot add, omit, or substitute a
    /// receipt-verification decision.
    pub(crate) fn sync_authenticated_crdt(
        &mut self,
        envelope: CrdtSyncEnvelopeV2,
    ) -> Result<CommittedCrdtSyncV2, LocalRootTreeInvokeErrorV2> {
        let mut verifications = envelope
            .nodes
            .iter()
            .map(|node| {
                node.change.expected_producer().map(|expected_producer| {
                    super::ReceiptVerificationRequestV2 {
                        expected_producer,
                        receipt: node.receipt.clone(),
                    }
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(LocalRootTreeInvokeErrorV2::Rejected(
                AccumulationRejectionV2::InvalidWorkflowTransition,
            ))?;
        verifications.sort_by_key(super::ReceiptVerificationRequestV2::hash);
        verifications.dedup();
        self.sync_crdt_with_verifications(envelope, &verifications)
    }

    fn sync_crdt_with_verifications(
        &mut self,
        envelope: CrdtSyncEnvelopeV2,
        receipt_verifications: &[super::ReceiptVerificationRequestV2],
    ) -> Result<CommittedCrdtSyncV2, LocalRootTreeInvokeErrorV2> {
        self.require_installed()?;
        if self.consistency != ConsistencyModeV2::Crdt || envelope.service != self.identity {
            return Err(LocalRootTreeInvokeErrorV2::Rejected(
                AccumulationRejectionV2::InvalidConsistency,
            ));
        }
        let accumulated = self
            .service
            .accumulate_with_receipt_verifications_after_barrier(
                &AccumulateRequestV2::SyncCrdt(envelope),
                receipt_verifications,
            )
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

    /// Load one content-addressed proof from the durable producer side-CAS.
    /// Proof bytes never enter the recoverable service image, but pending
    /// attested publications keep their reference snapshot-reachable and the
    /// durable/Raft backends preserve the artifact across restart.
    pub fn attestation_proof(&self, reference: &BlobRefV2) -> Option<ImportedBlobV2> {
        AttestationProofHostV2::proof_bytes(self.service.accumulate_host(), reference).map(
            |bytes| ImportedBlobV2 {
                reference: reference.clone(),
                bytes,
            },
        )
    }

    /// Finalized cross-root calls still waiting in the guest-owned inbox.
    pub(crate) fn pending_inbox_calls(
        &self,
    ) -> Result<Vec<(super::CallId, u64)>, LocalRootTreeInvokeErrorV2> {
        self.service
            .accumulate_host()
            .pending_inbox_calls()
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)
    }

    /// Earliest durable call deadline, used only to avoid an unnecessary
    /// consensus barrier on every transport poll. The guest still decides
    /// expiration against the separately authenticated ambient slot.
    pub(crate) fn next_pending_call_deadline(
        &self,
    ) -> Result<Option<u64>, LocalRootTreeInvokeErrorV2> {
        self.service
            .accumulate_host()
            .pending_call_deadlines()
            .map(|deadlines| deadlines.into_iter().map(|row| row.deadline_timeslot).min())
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)
    }

    /// Guest-committed timeout outcomes whose saved workflow still awaits
    /// consumption. Unlike deadline discovery this survives a crash between
    /// ExpireCall and exact continuation resume.
    pub(crate) fn pending_timeout_resumes(
        &self,
    ) -> Result<Vec<super::InvocationId>, LocalRootTreeInvokeErrorV2> {
        LocalWorkSchedulerV2::pending_timeout_resumes(self.service.accumulate_host().local_store())
            .map_err(LocalRootTreeInvokeErrorV2::Schedule)
    }

    /// Recover the durable return route of a pending callee reply without
    /// relying on process-local transport state.
    pub(crate) fn publication_return_target(
        &self,
        publication: &PublicationRecordV2,
    ) -> Result<Option<(ActorId, ServiceIdentityV2, super::InvocationId)>, LocalRootTreeInvokeErrorV2>
    {
        let Some(reply) = publication.published.reply.as_ref() else {
            return Ok(None);
        };
        let checkpoint = self
            .service
            .accumulate_host()
            .workflow_checkpoint(publication.input.invocation)
            .map_err(LocalRootTreeInvokeErrorV2::CorruptStore)?
            .ok_or(LocalRootTreeInvokeErrorV2::DivergentReplay)?;
        let work = &checkpoint.resume_work;
        if checkpoint.input != publication.input || work.invocation != publication.input.invocation
        {
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
        match (
            work.origin,
            work.causal_parent,
            work.causal_context.as_ref(),
        ) {
            (super::Origin::Actor(actor), Some(invocation), Some(context))
                if context.from == actor && context.caller_invocation == invocation =>
            {
                Ok(Some((actor, context.from_service.clone(), invocation)))
            }
            _ => Ok(None),
        }
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

    fn committed_role_decision() -> (
        RoleAuthorizationClaimV2,
        RoleAuthorityBindingV2,
        CommittedRootTreeSliceV2,
    ) {
        let authority = RoleAuthorityBindingV2 {
            service: ServiceIdentityV2 {
                space: super::super::SpaceId([30; 32]),
                root_service: super::super::RootServiceId([31; 32]),
                deployment: super::super::DeploymentId([32; 32]),
                service_program: ProgramId([33; 32]),
                service_abi: super::super::ABI_VERSION,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                gas_schedule: super::super::GasScheduleV2::new(1_000_000_000, 5_000_000_000),
            },
            actor: ActorId([34; 32]),
        };
        let claim = RoleAuthorizationClaimV2 {
            space: authority.service.space,
            holder: super::super::Origin::Member(super::super::SubjectId([35; 32])),
            role: crate::SpaceRole::Member,
            audience: ServiceIdentityV2 {
                root_service: super::super::RootServiceId([36; 32]),
                ..authority.service.clone()
            },
            invocation: InvocationId([37; 32]),
            scope: super::super::Hash([38; 32]),
            target: ActorId([39; 32]),
            method: "restricted".into(),
            policy: super::super::Hash([40; 32]),
        };
        let input = WorkInputIdV2 {
            invocation: claim.authority_invocation(),
            workflow_step: 0,
        };
        let reply = claim.authority_reply(authority.actor);
        let receipt = AccumulationReceiptV2 {
            service: authority.service.clone(),
            accepted_transition: super::super::Hash([41; 32]),
            reply_commitment: Some(reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(super::super::Hash([42; 32])),
            resulting_crdt_heads: vec![],
            sequence: 4,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        };
        let published = PublishedEffectsV2 {
            reply: Some(reply.clone()),
            ..PublishedEffectsV2::default()
        };
        let publication = PublicationRecordV2 {
            input,
            receipt: receipt.clone(),
            published: published.clone(),
        };
        (
            claim,
            authority,
            CommittedRootTreeSliceV2 {
                input,
                role_assertion_eligibility: Some(RoleAssertionEligibilityV2 {
                    input,
                    transition_commitment: receipt.accepted_transition,
                    reply_commitment: reply.commitment(),
                }),
                receipt,
                published,
                publication: Some(publication),
                duplicate: false,
                refine_gas_used: 10,
                accumulate_gas_used: 11,
            },
        )
    }

    #[test]
    fn committed_authority_reply_extracts_a_receipt_bound_assertion() {
        let (claim, authority, committed) = committed_role_decision();
        assert_eq!(
            committed.role_assertion(claim.clone(), &authority).unwrap(),
            AccumulatedRoleAssertionV2 {
                claim,
                receipt: committed.receipt,
            }
        );
    }

    #[test]
    fn role_assertion_rejects_non_atomic_or_unrecoverable_publications() {
        let (claim, authority, committed) = committed_role_decision();

        let mut suspended = committed.clone();
        suspended.receipt.checkpoint = 1;
        assert!(matches!(
            suspended.role_assertion(claim.clone(), &authority),
            Err(LocalRootTreeInvokeErrorV2::InvalidRoleAssertionPublication)
        ));

        let mut side_effecting = committed.clone();
        side_effecting
            .published
            .exported_blobs
            .push(BlobRefV2::of_bytes(b"artifact"));
        assert!(matches!(
            side_effecting.role_assertion(claim.clone(), &authority),
            Err(LocalRootTreeInvokeErrorV2::InvalidRoleAssertionPublication)
        ));

        let mut unrecoverable = committed;
        unrecoverable.publication = None;
        assert!(matches!(
            unrecoverable.role_assertion(claim, &authority),
            Err(LocalRootTreeInvokeErrorV2::InvalidRoleAssertionPublication)
        ));
    }

    #[test]
    fn root_transport_is_canonical_and_carries_no_observation_time() {
        let source = ServiceIdentityV2 {
            space: super::super::SpaceId([1; 32]),
            root_service: super::super::RootServiceId([2; 32]),
            deployment: super::super::DeploymentId([3; 32]),
            service_program: ProgramId([4; 32]),
            service_abi: super::super::ABI_VERSION,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
            gas_schedule: super::super::GasScheduleV2::new(1_000_000_000, 5_000_000_000),
        };
        let destination = ServiceIdentityV2 {
            root_service: super::super::RootServiceId([5; 32]),
            ..source.clone()
        };
        let invocation = InvocationId([6; 32]);
        let message = super::super::MessageRecordV2 {
            call_id: invocation.call_id(0),
            caller_invocation: invocation,
            await_ordinal: 0,
            from_service: source.clone(),
            from: ActorId([7; 32]),
            to_service: destination,
            to: ActorId([8; 32]),
            parent: None,
            payload: vec![crate::value::TAG_DYNAMIC, 1],
            authorization: AuthorizationEvidenceV2::Public,
            proof_requested: false,
            deadline_timeslot: Some(20),
        };
        let receipt = AccumulationReceiptV2 {
            service: source,
            accepted_transition: super::super::Hash([9; 32]),
            reply_commitment: None,
            outbox_commitment: super::super::MessageRecordV2::outbox_commitment(
                core::slice::from_ref(&message),
            ),
            resulting_state_root: Some(super::super::Hash([10; 32])),
            resulting_crdt_heads: Vec::new(),
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        };
        let publication = PublicationRecordV2 {
            input: WorkInputIdV2 {
                invocation,
                workflow_step: 0,
            },
            receipt,
            published: PublishedEffectsV2 {
                outbox: vec![message.clone()],
                ..PublishedEffectsV2::default()
            },
        };
        let delivery = RootTreeTransportV2::OutboxDelivery {
            publication: publication.clone(),
            message: message.clone(),
        };
        assert_eq!(
            RootTreeTransportV2::decode(&delivery.encode()).unwrap(),
            delivery
        );

        let mut replicated = delivery.clone();
        let RootTreeTransportV2::OutboxDelivery {
            publication: replicated_publication,
            ..
        } = &mut replicated
        else {
            unreachable!()
        };
        replicated_publication.receipt.consistency = ConsistencyModeV2::Raft;
        assert_eq!(
            RootTreeTransportV2::decode(&replicated.encode()).unwrap(),
            replicated,
            "quorum-finalized Raft publications use the same canonical transport wire"
        );
        let mut causal = delivery.clone();
        let RootTreeTransportV2::OutboxDelivery {
            publication: causal_publication,
            ..
        } = &mut causal
        else {
            unreachable!()
        };
        causal_publication.receipt.consistency = ConsistencyModeV2::Crdt;
        causal_publication.receipt.resulting_state_root = None;
        causal_publication.receipt.resulting_crdt_heads = vec![super::super::Hash([11; 32])];
        assert_eq!(
            RootTreeTransportV2::decode(&causal.encode()).unwrap(),
            causal,
            "causally finalized CRDT publications use the same authenticated transport wire"
        );

        let crdt_service = ServiceIdentityV2 {
            root_service: super::super::RootServiceId([0x51; 32]),
            ..publication.receipt.service.clone()
        };
        let ingress = super::super::CrdtIngressV2 {
            service: crdt_service.clone(),
            invocation: InvocationId([0x52; 32]),
            logical_timeslot: 3,
            target: ActorId([0x53; 32]),
            method: "increment".into(),
            arguments: vec![crate::value::TAG_DYNAMIC, 1],
            origin: super::super::Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            authorization_blob: None,
            imported_blobs: vec![],
            proof_requested: false,
        };
        let change = super::super::CrdtChangeV2 {
            id: super::super::CrdtChangeV2::derive_ingress_id(&ingress, &[]),
            work_hash: ingress.commitment(),
            causal_dependencies: vec![],
            causal_height: 1,
            operations: vec![],
            workflow: vec![super::super::WorkflowOperationV2::Ingress(ingress)],
            materializations: vec![],
            awaited_reply: None,
            exported_blobs: vec![],
        };
        let cid = change.cid();
        let crdt_envelope = CrdtSyncEnvelopeV2 {
            service: crdt_service.clone(),
            advertised_heads: vec![cid],
            nodes: vec![super::super::CrdtSyncNodeV2 {
                receipt: AccumulationReceiptV2 {
                    service: crdt_service,
                    accepted_transition: change.receipt_commitment(),
                    reply_commitment: None,
                    outbox_commitment: None,
                    resulting_state_root: None,
                    resulting_crdt_heads: vec![cid],
                    sequence: 1,
                    checkpoint: 0,
                    consistency: ConsistencyModeV2::Crdt,
                },
                change,
            }],
            provided_blobs: vec![],
        };
        let crdt = RootTreeTransportV2::CrdtSyncChunk {
            transfer: crdt_envelope.commitment(),
            chunk_index: 0,
            chunk_count: 1,
            envelope: crdt_envelope,
        };
        assert_eq!(RootTreeTransportV2::decode(&crdt.encode()).unwrap(), crdt);
        let RootTreeTransportV2::CrdtSyncChunk { envelope, .. } = &crdt else {
            unreachable!()
        };
        let accepted = RootTreeTransportV2::CrdtSyncAccepted {
            service: envelope.service.clone(),
            transfer: envelope.commitment(),
            next_chunk: 1,
        };
        assert_eq!(
            RootTreeTransportV2::decode(&accepted.encode()).unwrap(),
            accepted
        );
        let request = AccumulateRequestV2::SyncCrdt(envelope.clone());
        let verification = super::super::ReceiptVerificationRequestV2 {
            expected_producer: envelope.nodes[0]
                .change
                .expected_producer()
                .expect("canonical ingress names its producer"),
            receipt: envelope.nodes[0].receipt.clone(),
        };
        assert!(
            super::super::CommittedAccumulateEntryV2::validate_replicated_receipt_verifications(
                &request,
                &[],
            )
            .is_err(),
            "network CRDT sync cannot authorize its own receipt",
        );
        assert!(
            super::super::CommittedAccumulateEntryV2::validate_replicated_receipt_verifications(
                &request,
                std::slice::from_ref(&verification),
            )
            .is_ok(),
        );
        assert!(
            super::super::CommittedAccumulateEntryV2::validate_replicated_receipt_verifications(
                &request,
                &[verification.clone(), verification],
            )
            .is_err(),
            "extra or duplicate verifier decisions are non-canonical",
        );

        let accepted = RootTreeTransportV2::PublicationAccepted {
            acceptor: message.to,
            acceptor_service: message.to_service.clone(),
            service: publication.receipt.service.clone(),
            input: publication.input,
            publication: publication.commitment(),
            call: message.call_id,
        };
        assert_eq!(
            RootTreeTransportV2::decode(&accepted.encode()).unwrap(),
            accepted,
            "an acknowledgement names both the accepting actor and the publication owner"
        );

        let mut mismatched = message;
        mismatched.payload.push(0);
        assert_eq!(
            RootTreeTransportV2::decode(
                &RootTreeTransportV2::OutboxDelivery {
                    publication,
                    message: mismatched,
                }
                .encode()
            ),
            Err(DecodeError::NonCanonical)
        );
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
