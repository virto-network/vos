//! Local conformance harness for the protocol-pinned generic service PVM.
//!
//! There is deliberately no native Refine implementation and no native
//! transition-apply shortcut here. Both paths execute the same canonical PVM
//! that deployment installs; the host supplies only imports and an atomic service platform
//! storage transaction boundary.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::attestation::{
    Attestation, AttestationError, AttestationPreparation, AttestationProofHost,
    AttestationProofProducer, AttestationProofRequest, AttestedMethod,
};

use super::wire::{DecodeError, Decoder, Encoder};
use super::{
    AccumulateProtocolHost, AccumulateRequest, AccumulatedReply, AccumulatedRoleAssertion,
    AccumulationEnvelope, AccumulationReceipt, AccumulationRejection, AccumulationResult,
    AttestationDelivery, AuthorizationEvidence, CommittedServiceImageHost, GasSchedule,
    ImportedBlob, ImportedProgram, MemoryServiceSnapshot, ProgramId, ProofCommitment,
    ProofVerificationRequest, PublishedEffects, ReceiptVerificationHost,
    ReceiptVerificationRequest, RefineImports, RefineOutput, RefineProtocolHost, RefineTrace,
    RoleCredential, ServiceIdentity, ServiceImageInstallError, ServicePvm, ServicePvmError,
    ServicePvmOutput, ServiceWire, SystemCapabilityId, Transition, VosPackage, WorkEnvelope,
};

pub(crate) const ROOT_UPGRADE_REQUEST_MAGIC: [u8; 4] = *b"VRUW";

pub(crate) fn root_upgrade_capability(
    service: &ServiceIdentity,
    actor: super::ActorId,
) -> SystemCapabilityId {
    SystemCapabilityId(
        super::Hash::digest(
            b"vos/root-upgrade-capability/service",
            &[&service.root_service.0, &actor.0],
        )
        .0,
    )
}

pub(crate) fn root_upgrade_authenticator(
    expected_deployment: super::DeploymentId,
    expected_program: ProgramId,
    package_wire: &[u8],
) -> super::Hash {
    let mut request = Vec::new();
    request.extend_from_slice(&ROOT_UPGRADE_REQUEST_MAGIC);
    request.extend_from_slice(&super::PLATFORM_ID.0);
    let mut encoder = Encoder(&mut request);
    encoder.fixed(&expected_deployment.0);
    encoder.fixed(&expected_program.0);
    encoder.bytes(package_wire);
    super::Hash::digest(b"vos/root-upgrade-authenticator/service", &[&request])
}

fn validate_accumulate_availability(
    request: &AccumulateRequest,
    programs: &[ImportedProgram],
    blobs: &[ImportedBlob],
) -> Result<(), DecodeError> {
    if programs
        .windows(2)
        .any(|pair| pair[0].program >= pair[1].program)
        || programs
            .iter()
            .any(|program| ProgramId::of_pvm(&program.pvm) != program.program)
        || blobs
            .windows(2)
            .any(|pair| pair[0].reference.hash >= pair[1].reference.hash)
        || blobs
            .iter()
            .any(|blob| !blob.reference.matches(&blob.bytes))
    {
        return Err(DecodeError::NonCanonical);
    }

    let (mut expected_programs, mut expected_blobs) = match request {
        AccumulateRequest::Install(genesis) => {
            let mut programs = Vec::new();
            for actor in &genesis.actors {
                programs.push(actor.program);
                let policies = super::PackageRolePolicies::decode(&actor.role_policies)?;
                programs.extend(
                    policies
                        .task_dependencies
                        .iter()
                        .map(|dependency| dependency.program),
                );
            }
            (
                programs,
                genesis
                    .actors
                    .iter()
                    .map(|actor| actor.initial_state.clone())
                    .collect::<Vec<_>>(),
            )
        }
        AccumulateRequest::UpgradeActor(upgrade) => {
            let policies = super::PackageRolePolicies::decode(&upgrade.role_policies)?;
            let expected_blobs = match &upgrade.authorization {
                AuthorizationEvidence::SystemCapability {
                    capability,
                    authenticator,
                } if *capability == root_upgrade_capability(&upgrade.service, upgrade.actor) => {
                    let [artifact] = blobs else {
                        return Err(DecodeError::NonCanonical);
                    };
                    let package = VosPackage::decode(&artifact.bytes)?;
                    if package.validate().is_err()
                        || package.encode() != artifact.bytes
                        || package.deployment_id() != upgrade.replacement_deployment
                        || package.manifest.actor_program != upgrade.replacement_program
                        || package.manifest.service_program != upgrade.service.service_program
                        || package.deployment_signature.producer != upgrade.producer
                        || package.role_policies != upgrade.role_policies
                        || authenticator.as_slice()
                            != root_upgrade_authenticator(
                                upgrade.expected_deployment,
                                upgrade.expected_program,
                                &artifact.bytes,
                            )
                            .0
                    {
                        return Err(DecodeError::NonCanonical);
                    }
                    vec![artifact.reference.clone()]
                }
                _ => Vec::new(),
            };
            (
                core::iter::once(upgrade.replacement_program)
                    .chain(
                        policies
                            .task_dependencies
                            .iter()
                            .map(|dependency| dependency.program),
                    )
                    .collect(),
                expected_blobs,
            )
        }
        _ => (Vec::new(), Vec::new()),
    };
    expected_programs.sort();
    expected_programs.dedup();
    expected_blobs.sort_by_key(|reference| reference.hash);
    expected_blobs.dedup();

    if programs
        .iter()
        .map(|program| program.program)
        .ne(expected_programs)
        || blobs
            .iter()
            .map(|blob| blob.reference.clone())
            .ne(expected_blobs)
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

fn validate_receipt_verifications(
    request: &AccumulateRequest,
    verifications: &[ReceiptVerificationRequest],
    require_external_verification: bool,
) -> Result<(), DecodeError> {
    if verifications
        .windows(2)
        .any(|pair| pair[0].hash() >= pair[1].hash())
    {
        return Err(DecodeError::NonCanonical);
    }
    let assertion_for = |authorization: &AuthorizationEvidence| match authorization {
        AuthorizationEvidence::Credential { bytes, .. } => {
            RoleCredential::decode(bytes).ok().and_then(|credential| {
                AccumulatedRoleAssertion::decode(&credential.authenticator).ok()
            })
        }
        _ => None,
    };
    let assertion = match request {
        AccumulateRequest::AdmitIngress(ingress) => match ingress.authorization() {
            AuthorizationEvidence::Credential { bytes, .. } => {
                RoleCredential::decode(bytes).ok().and_then(|credential| {
                    AccumulatedRoleAssertion::decode(&credential.authenticator).ok()
                })
            }
            _ => None,
        },
        _ => None,
    };
    let expected = if let Some(assertion) = assertion {
        let [verification] = verifications else {
            return if verifications.is_empty() && !require_external_verification {
                Ok(())
            } else {
                Err(DecodeError::NonCanonical)
            };
        };
        if verification.receipt != assertion.receipt
            || assertion.receipt.reply_commitment
                != Some(
                    assertion
                        .claim
                        .authority_reply(verification.expected_producer)
                        .commitment(),
                )
        {
            return Err(DecodeError::NonCanonical);
        }
        return Ok(());
    } else if let AccumulateRequest::Deliver(delivery) = request {
        let mut expected = alloc::vec![ReceiptVerificationRequest {
            expected_producer: delivery.message.from,
            receipt: delivery.source_receipt.clone(),
        }];
        if let Some(assertion) = assertion_for(&delivery.authorization) {
            let Some(verification) = verifications
                .iter()
                .find(|verification| verification.receipt == assertion.receipt)
            else {
                return if verifications.is_empty() && !require_external_verification {
                    Ok(())
                } else {
                    Err(DecodeError::NonCanonical)
                };
            };
            if assertion.receipt.reply_commitment
                != Some(
                    assertion
                        .claim
                        .authority_reply(verification.expected_producer)
                        .commitment(),
                )
            {
                return Err(DecodeError::NonCanonical);
            }
            expected.push(verification.clone());
        }
        expected.sort_by_key(ReceiptVerificationRequest::hash);
        expected.dedup();
        if verifications.is_empty() && !require_external_verification {
            return Ok(());
        }
        return (verifications == expected)
            .then_some(())
            .ok_or(DecodeError::NonCanonical);
    } else if let AccumulateRequest::SyncCrdt(envelope) = request {
        let mut expected = envelope
            .nodes
            .iter()
            .map(|node| {
                Some(ReceiptVerificationRequest {
                    expected_producer: node.change.expected_producer()?,
                    receipt: node.receipt.clone(),
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(DecodeError::NonCanonical)?;
        expected.sort_by_key(ReceiptVerificationRequest::hash);
        expected.dedup();
        if verifications.is_empty() && !require_external_verification {
            return Ok(());
        }
        return (verifications == expected)
            .then_some(())
            .ok_or(DecodeError::NonCanonical);
    } else {
        match request {
            AccumulateRequest::Deliver(_) => unreachable!("delivery handled above"),
            AccumulateRequest::Apply(envelope) => {
                envelope
                    .work
                    .awaited_reply
                    .as_ref()
                    .map(|reply| ReceiptVerificationRequest {
                        expected_producer: reply.reply.producer,
                        receipt: reply.receipt.clone(),
                    })
            }
            _ => None,
        }
    };
    let Some(expected) = expected else {
        return verifications
            .is_empty()
            .then_some(())
            .ok_or(DecodeError::NonCanonical);
    };
    if verifications.is_empty() && !require_external_verification {
        return Ok(());
    }
    (verifications == [expected])
        .then_some(())
        .ok_or(DecodeError::NonCanonical)
}

fn requires_logical_timeslot(request: &AccumulateRequest) -> bool {
    matches!(
        request,
        AccumulateRequest::ExpireCall(_) | AccumulateRequest::RetireInbox(_)
    )
}

fn embedded_logical_timeslot(request: &AccumulateRequest) -> Option<u64> {
    match request {
        AccumulateRequest::AdmitIngress(ingress) => Some(ingress.logical_timeslot),
        AccumulateRequest::Apply(envelope) | AccumulateRequest::PrepareAttested(envelope) => {
            Some(envelope.work.logical_timeslot)
        }
        AccumulateRequest::Deliver(delivery) => Some(delivery.logical_timeslot),
        _ => None,
    }
}

fn verify_replayed_logical_timeslots<A: AccumulateProtocolHost>(
    host: &A,
    request: &AccumulateRequest,
    ambient: Option<u64>,
) -> Result<(), ServicePvmError> {
    if let Some(logical_timeslot) = embedded_logical_timeslot(request) {
        host.verify_logical_timeslot(logical_timeslot)?;
    }
    if let Some(logical_timeslot) = ambient
        && Some(logical_timeslot) != embedded_logical_timeslot(request)
    {
        host.verify_logical_timeslot(logical_timeslot)?;
    }
    Ok(())
}

fn verify_admitted_logical_timeslots<A: AccumulateProtocolHost>(
    host: &A,
    request: &AccumulateRequest,
    ambient: Option<u64>,
) -> Result<(), ServicePvmError> {
    let embedded = embedded_logical_timeslot(request);
    if let Some(logical_timeslot) = embedded {
        if matches!(
            request,
            AccumulateRequest::AdmitIngress(_) | AccumulateRequest::Deliver(_)
        ) {
            host.verify_current_logical_timeslot(logical_timeslot)?;
        } else {
            host.verify_logical_timeslot(logical_timeslot)?;
        }
    }
    if let Some(logical_timeslot) = ambient
        && Some(logical_timeslot) != embedded
    {
        host.verify_current_logical_timeslot(logical_timeslot)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefinedServiceOutput {
    pub transition: Transition,
    pub gas_used: u64,
    pub exported_blobs: Vec<ImportedBlob>,
    /// Producer-private records emitted by nested signed Tasks. These are
    /// never encoded into the transition or replicated Accumulate request.
    pub producer_records: Vec<super::ProducedProvableRecord>,
    pub trace: Option<RefineTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulatedServiceOutput {
    pub result: AccumulationResult,
    pub gas_used: u64,
}

/// Proof package released by the service driver only after guest Accumulate
/// accepted the transition and committed its recoverable publication row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedAttestationOutput {
    pub preparation: AttestationPreparation,
    pub proof: ProofCommitment,
    pub proof_bytes: Vec<u8>,
    pub published: PublishedEffects,
    pub prepare_gas_used: u64,
    pub accumulate_gas_used: u64,
}

impl CommittedAttestationOutput {
    /// Build the durable reply input and its separately transported proof
    /// blob. This type can exist only after guest Accumulate committed, so a
    /// caller cannot observe a prepared or merely proved package.
    pub fn into_accumulated_reply(
        self,
    ) -> Result<(AccumulatedReply, ImportedBlob), AttestationError> {
        let reply = self
            .published
            .reply
            .ok_or(AttestationError::InvalidStatement)?;
        let delivery = self
            .published
            .attestation
            .ok_or(AttestationError::InvalidStatement)?;
        if self.published.proof.as_ref() != Some(&self.proof)
            || delivery.statement != self.preparation.statement
            || delivery.proof != self.proof
            || !self.proof.proof_blob.matches(&self.proof_bytes)
        {
            return Err(AttestationError::InvalidProof);
        }
        let proof_blob = ImportedBlob {
            reference: self.proof.proof_blob.clone(),
            bytes: self.proof_bytes,
        };
        let accumulated = AccumulatedReply {
            reply,
            receipt: self.preparation.receipt,
            attestation: Some(delivery),
        };
        accumulated.validate()?;
        Ok((accumulated, proof_blob))
    }

    /// Produce the transport record consumed by macro-generated attested
    /// handles. Only the reply published by successful guest Accumulate is
    /// decoded; prepare/proof output alone cannot construct this record.
    pub fn into_invocation_result(
        self,
    ) -> Result<crate::actors::client::AttestedInvocationResult, AttestationError> {
        let reply = self
            .published
            .reply
            .ok_or(AttestationError::InvalidStatement)?;
        let delivery = self
            .published
            .attestation
            .ok_or(AttestationError::InvalidStatement)?;
        let value = <crate::value::Value as crate::Decode>::try_decode(&reply.result)
            .ok_or(AttestationError::InvalidStatement)?;
        Ok(crate::actors::client::AttestedInvocationResult {
            value,
            producer_name: delivery.producer_name,
            producer: delivery.producer,
            statement: self.preparation.statement,
            trace: self.proof.trace,
            proof: self.proof_bytes,
        })
    }

    /// Turn a committed runtime result into the portable application term.
    /// The generated method marker checks both the method name and the exact
    /// reply wire before the package can leave the runtime boundary.
    pub fn into_attestation<T, M: AttestedMethod<T>>(
        self,
        preview: T,
    ) -> Result<Attestation<T, M>, AttestationError> {
        let delivery = self
            .published
            .attestation
            .as_ref()
            .ok_or(AttestationError::InvalidStatement)?;
        let claim_wire = self
            .published
            .reply
            .ok_or(AttestationError::InvalidStatement)?
            .result;
        Attestation::__from_runtime_wire(
            delivery.producer_name.clone(),
            delivery.producer,
            self.preparation.statement,
            self.proof.trace,
            claim_wire,
            preview,
            self.proof_bytes,
        )
    }
}

struct ProvedAttestation {
    envelope: AccumulationEnvelope,
    preparation: AttestationPreparation,
    proof: ProofCommitment,
    proof_bytes: Vec<u8>,
}

enum AttestationBuildError<P> {
    InvalidPreparation,
    Producer(P),
    InvalidProducedProof,
    ProofUnavailable,
}

#[derive(Debug)]
pub enum AttestedServiceError<E, P> {
    Service(E),
    Rejected(AccumulationRejection),
    InvalidPreparation,
    Producer(P),
    InvalidProducedProof,
    ProofUnavailable,
    CommitMismatch,
}

impl<E: core::fmt::Debug, P: core::fmt::Debug> core::fmt::Display for AttestedServiceError<E, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "attested VOS service accumulation failed: {self:?}")
    }
}

impl<E: core::fmt::Debug, P: core::fmt::Debug> core::error::Error for AttestedServiceError<E, P> {}

/// One canonical Accumulate request whose Raft log position is committed.
/// Time-dependent entries carry the consensus service platform slot observed by the
/// proposer so every follower replays the identical IC-5 ambient input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedAccumulateEntry {
    pub index: u64,
    pub request: Vec<u8>,
    /// Host-owned state-machine identity encoded in this exact log entry.
    /// Replicas reject a mismatch before invoking guest Accumulate.
    pub host_state_machine: Option<super::Hash>,
    pub logical_timeslot: Option<u64>,
    /// Consensus-visible commitment to the production verifier set used for
    /// this root. Every entry carries the same value; conformance groups carry
    /// `None`.
    pub production_trust_policy: Option<super::Hash>,
    /// Canonical content bytes required to make this entry independently
    /// replayable on a replica with an empty node-local cache.
    pub availability_programs: Vec<ImportedProgram>,
    pub availability_blobs: Vec<ImportedBlob>,
    /// Exact positive receipt-verifier decisions ordered beside this request.
    /// Authority ingress and awaited-reply consumption each bind one external
    /// receipt. Durable delivery binds its source receipt plus the authority
    /// assertion receipt when destination authorization is required. CRDT
    /// synchronization binds one decision per distinct causal-node receipt;
    /// requests without an external receipt carry an empty list.
    pub receipt_verifications: Vec<ReceiptVerificationRequest>,
}

impl CommittedAccumulateEntry {
    pub(crate) fn validate_availability(
        request: &AccumulateRequest,
        programs: &[ImportedProgram],
        blobs: &[ImportedBlob],
    ) -> Result<(), DecodeError> {
        validate_accumulate_availability(request, programs, blobs)
    }

    pub(crate) fn validate_receipt_verifications(
        request: &AccumulateRequest,
        verifications: &[ReceiptVerificationRequest],
    ) -> Result<(), DecodeError> {
        validate_receipt_verifications(request, verifications, false)
    }

    pub(crate) fn validate_replicated_receipt_verifications(
        request: &AccumulateRequest,
        verifications: &[ReceiptVerificationRequest],
    ) -> Result<(), DecodeError> {
        validate_receipt_verifications(request, verifications, true)
    }
}

/// Committed application entries after one replica's apply cursor. Raft may
/// have committed configuration/no-op entries between these indices, so the
/// authoritative `committed_index` is carried separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedAccumulateBatch {
    pub entries: Vec<CommittedAccumulateEntry>,
    pub committed_index: u64,
}

/// Exact physical service image represented by one compacted Raft prefix.
/// The image remains the canonical `MemoryServiceSnapshot` wire; this
/// envelope binds it to the log position advertised by InstallSnapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedProofArtifact {
    /// Exact public inputs which the receiving replica must independently
    /// verify before making `bytes` durable or installing the service image.
    pub verification: ProofVerificationRequest,
    pub bytes: Vec<u8>,
}

/// Exact caller-visible response retained outside the consensus service
/// image. The image contains only this content address and a bounded recovery
/// index. Snapshot transfer carries these bounded bytes as a separately
/// validated side-CAS artifact rather than embedding them in actor state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedResultArtifact {
    pub reference: super::BlobRef,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedServiceSnapshot {
    pub applied_index: u64,
    pub service_image: Vec<u8>,
    /// Proof artifacts required by pending publications remain outside the
    /// service image, but must become durable before this snapshot cursor is
    /// installed on another replica. Completed reply admissions do not retain
    /// proof bytes because duplicate routing resolves from the admission row.
    pub proof_artifacts: Vec<CommittedProofArtifact>,
    pub result_artifacts: Vec<CommittedResultArtifact>,
    /// Host-owned state-machine contract used to produce this image. A
    /// snapshot without host mutations uses `None`; newly written snapshots
    /// always carry the current identity.
    pub host_state_machine: Option<super::Hash>,
}

impl ServiceWire for CommittedServiceSnapshot {
    const MAGIC: [u8; 4] = *b"VRSW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.u64(self.applied_index);
        encoder.bytes(&self.service_image);
        encoder.list(&self.proof_artifacts, |encoder, artifact| {
            encoder.bytes(&artifact.verification.encode());
            encoder.bytes(&artifact.bytes);
        });
        encoder.option(&self.host_state_machine, |encoder, identity| {
            encoder.fixed(&identity.0);
        });
        encoder.list(&self.result_artifacts, |encoder, artifact| {
            encoder.fixed(&artifact.reference.hash.0);
            encoder.u64(artifact.reference.len);
            encoder.bytes(&artifact.bytes);
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let applied_index = decoder.u64()?;
        let service_image = decoder.bytes()?;
        let proof_artifacts = decoder.list(|decoder| {
            Ok(CommittedProofArtifact {
                verification: ProofVerificationRequest::decode(&decoder.bytes()?)?,
                bytes: decoder.bytes()?,
            })
        })?;
        let (host_state_machine, result_artifacts) = if decoder.remaining() == 0 {
            (None, Vec::new())
        } else {
            let identity = decoder.option(|decoder| Ok(super::Hash(decoder.fixed()?)))?;
            let artifacts = decoder.list(|decoder| {
                Ok(CommittedResultArtifact {
                    reference: super::BlobRef {
                        hash: super::Hash(decoder.fixed()?),
                        len: decoder.u64()?,
                    },
                    bytes: decoder.bytes()?,
                })
            })?;
            (identity, artifacts)
        };
        let service_snapshot = MemoryServiceSnapshot::decode(&service_image)?;
        if applied_index == 0 {
            return Err(DecodeError::NonCanonical);
        }
        if proof_artifacts
            .windows(2)
            .any(|pair| pair[0].verification.hash() >= pair[1].verification.hash())
            || proof_artifacts
                .iter()
                .any(|artifact| !artifact.verification.proof_blob.matches(&artifact.bytes))
        {
            return Err(DecodeError::NonCanonical);
        }
        let referenced = service_snapshot.referenced_proof_verifications()?;
        if proof_artifacts.len() != referenced.len()
            || proof_artifacts
                .iter()
                .zip(&referenced)
                .any(|(artifact, verification)| artifact.verification != *verification)
        {
            return Err(DecodeError::NonCanonical);
        }
        let result_references = service_snapshot.referenced_invocation_results();
        let result_bytes: alloc::collections::BTreeMap<_, _> = result_artifacts
            .iter()
            .map(|artifact| (artifact.reference.hash.0, artifact.bytes.clone()))
            .collect();
        if host_state_machine.is_some_and(|identity| identity != super::HOST_STATE_MACHINE_ID)
            || host_state_machine.is_none() && !result_references.is_empty()
            || result_artifacts.len() != result_references.len()
            || result_artifacts
                .iter()
                .zip(&result_references)
                .any(|(artifact, reference)| {
                    artifact.reference != *reference || !reference.matches(&artifact.bytes)
                })
            || service_snapshot
                .validate_invocation_result_artifacts(&result_bytes)
                .is_err()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(Self {
            applied_index,
            service_image,
            proof_artifacts,
            result_artifacts,
            host_state_machine,
        })
    }
}

/// Raft boundary for the service service state machine.
///
/// Implementations order the exact canonical request and its optional trusted
/// service platform-slot provenance, and return from `propose_at` only after the named entry
/// is quorum committed. They never apply actor state themselves: leaders and
/// followers pass every returned entry to the same physical service PVM before
/// advancing `applied_index`.
pub trait CommittedAccumulateLog {
    type Error;

    /// Establish a current-leader quorum barrier and return the committed log
    /// index that must be locally applied before admitting new work.
    ///
    /// A multi-node Raft implementation must not implement this as a role
    /// check. Fresh leaders must wait for a current-term entry to commit so a
    /// prior-term application tail cannot become visible after the caller has
    /// already allocated an admission timeslot.
    fn leader_read_index(&mut self) -> Result<u64, Self::Error>;

    fn propose_at_with_availability(
        &mut self,
        request: &[u8],
        logical_timeslot: Option<u64>,
        production_trust_policy: Option<super::Hash>,
        programs: &[ImportedProgram],
        blobs: &[ImportedBlob],
        receipt_verifications: &[ReceiptVerificationRequest],
    ) -> Result<CommittedAccumulateEntry, Self::Error>;

    fn propose_at(
        &mut self,
        request: &[u8],
        logical_timeslot: Option<u64>,
    ) -> Result<CommittedAccumulateEntry, Self::Error> {
        self.propose_at_with_availability(request, logical_timeslot, None, &[], &[], &[])
    }

    fn propose(&mut self, request: &[u8]) -> Result<CommittedAccumulateEntry, Self::Error> {
        self.propose_at(request, None)
    }

    fn committed_after(
        &mut self,
        applied_index: u64,
    ) -> Result<CommittedAccumulateBatch, Self::Error>;

    fn applied_index(&mut self) -> Result<u64, Self::Error>;

    /// Return a Raft-installed service snapshot newer than the local physical
    /// service image. Logs without compaction may keep the default.
    fn installed_snapshot_after(
        &mut self,
        _applied_index: u64,
    ) -> Result<Option<CommittedServiceSnapshot>, Self::Error> {
        Ok(None)
    }

    /// Persist only after the service image for every application entry at or
    /// below `index` has committed locally. Replaying after a failed cursor
    /// write is safe because guest Accumulate deduplicates exact inputs.
    fn mark_applied(
        &mut self,
        index: u64,
        service_image: &[u8],
        proof_artifacts: &[CommittedProofArtifact],
        result_artifacts: &[CommittedResultArtifact],
    ) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceDispatchError {
    Pvm(ServicePvmError),
    ServiceProgramMismatch {
        expected: ProgramId,
        declared: ProgramId,
    },
    ServiceGasScheduleMismatch {
        expected: GasSchedule,
        declared: GasSchedule,
    },
    InvalidGasSchedule(GasSchedule),
    InvalidRefineOutput,
    InvalidAccumulateOutput,
    InvalidAvailabilityArtifacts,
}

impl ServiceDispatchError {
    /// Whether replaying the same committed request against the same service
    /// program and gas schedule must reproduce this failure. This is an
    /// explicit allowlist: new host/PVM failure variants remain retryable until
    /// their determinism is proved. A deterministic guest failure is an
    /// ordered no-op; local allocation, JIT, host, and durable-commit failures
    /// leave the apply cursor untouched.
    fn is_deterministic_accumulate_failure(&self) -> bool {
        match self {
            Self::Pvm(error) => matches!(
                error,
                ServicePvmError::InvalidProgram
                    | ServicePvmError::Panic { .. }
                    | ServicePvmError::OutOfGas { .. }
                    | ServicePvmError::PageFault { .. }
                    | ServicePvmError::UnreadableOutput
                    | ServicePvmError::InvalidAccumulateOutput
                    | ServicePvmError::InvalidProtocolResume
                    | ServicePvmError::InvalidVmLifecycle
            ),
            Self::ServiceProgramMismatch { .. }
            | Self::InvalidAccumulateOutput
            | Self::InvalidAvailabilityArtifacts => true,
            Self::ServiceGasScheduleMismatch { .. }
            | Self::InvalidGasSchedule(_)
            | Self::InvalidRefineOutput => false,
        }
    }
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;

    #[test]
    fn deterministic_accumulate_failures_are_an_explicit_allowlist() {
        assert!(
            ServiceDispatchError::Pvm(ServicePvmError::OutOfGas { vm: 0, pc: 5 })
                .is_deterministic_accumulate_failure()
        );
        assert!(
            !ServiceDispatchError::Pvm(ServicePvmError::KernelResourceUnavailable)
                .is_deterministic_accumulate_failure()
        );
        assert!(
            !ServiceDispatchError::Pvm(ServicePvmError::AccumulateHostRejected(123))
                .is_deterministic_accumulate_failure()
        );
        assert!(
            !ServiceDispatchError::Pvm(ServicePvmError::AccumulateCommitRejected)
                .is_deterministic_accumulate_failure()
        );
        assert!(
            !ServiceDispatchError::ServiceGasScheduleMismatch {
                expected: GasSchedule::new(1, 2),
                declared: GasSchedule::new(1, 3),
            }
            .is_deterministic_accumulate_failure(),
            "a replica configured with a different gas schedule must stop before advancing"
        );
    }
}

#[derive(Debug)]
pub enum ReplicatedServiceError<E> {
    Dispatch(ServiceDispatchError),
    Log(E),
    ServiceImage(ServiceImageInstallError),
    ProofUnavailable,
    ReceiptUnavailable,
    LogicalTimeslotRequired,
    UnexpectedLogicalTimeslot,
    InvalidCommittedLog,
}

impl<E: core::fmt::Debug> core::fmt::Display for ReplicatedServiceError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "replicated VOS service service failed: {self:?}")
    }
}

impl<E: core::fmt::Debug> core::error::Error for ReplicatedServiceError<E> {}

impl core::fmt::Display for ServiceDispatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VOS service dispatch failed: {self:?}")
    }
}

impl core::error::Error for ServiceDispatchError {}

/// Drives the canonical service PVM in a local node or conformance test.
/// `R` is immutable Refine import plumbing; `A` owns the atomic Accumulate
/// transaction. Neither is allowed to implement actor semantics.
pub struct ServiceRuntime<R, A> {
    pvm: ServicePvm,
    refine_host: R,
    accumulate_host: A,
    gas_schedule: GasSchedule,
}

/// Raft orchestration around the canonical generic service PVM.
///
/// The log owns ordering only. It contains `AccumulateRequest` bytes plus the
/// trusted service platform slot required by time-dependent requests, rather than
/// `EffectLog` commands or leader-produced state snapshots. Consequently
/// failover and follower catch-up execute guest validation, deduplication, and
/// storage mutation through the identical IC-5 entry used by the leader.
pub struct ReplicatedServiceRuntime<R, A, L> {
    service: ServiceRuntime<R, A>,
    log: L,
}

impl<R, A> ServiceRuntime<R, A> {
    pub fn new(
        canonical_service_pvm: Vec<u8>,
        expected_program: ProgramId,
        refine_host: R,
        accumulate_host: A,
        refine_gas: u64,
        accumulate_gas: u64,
    ) -> Result<Self, ServiceDispatchError> {
        let gas_schedule = GasSchedule::new(refine_gas, accumulate_gas);
        if !gas_schedule.is_valid() {
            return Err(ServiceDispatchError::InvalidGasSchedule(gas_schedule));
        }
        let pvm = ServicePvm::new(canonical_service_pvm, expected_program)
            .map_err(ServiceDispatchError::Pvm)?;
        Ok(Self {
            pvm,
            refine_host,
            accumulate_host,
            gas_schedule,
        })
    }

    pub const fn program_id(&self) -> ProgramId {
        self.pvm.program_id()
    }

    pub const fn gas_schedule(&self) -> GasSchedule {
        self.gas_schedule
    }

    pub fn accumulate_host(&self) -> &A {
        &self.accumulate_host
    }

    pub fn accumulate_host_mut(&mut self) -> &mut A {
        &mut self.accumulate_host
    }

    pub fn into_hosts(self) -> (R, A) {
        (self.refine_host, self.accumulate_host)
    }
}

impl<R, A, L> ReplicatedServiceRuntime<R, A, L> {
    pub const fn new(service: ServiceRuntime<R, A>, log: L) -> Self {
        Self { service, log }
    }

    pub fn service(&self) -> &ServiceRuntime<R, A> {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut ServiceRuntime<R, A> {
        &mut self.service
    }

    pub fn log(&self) -> &L {
        &self.log
    }

    pub fn log_mut(&mut self) -> &mut L {
        &mut self.log
    }

    pub fn into_parts(self) -> (ServiceRuntime<R, A>, L) {
        (self.service, self.log)
    }
}

impl<R: RefineProtocolHost, A: AccumulateProtocolHost> ServiceRuntime<R, A> {
    pub fn refine_actor_tree(
        &self,
        work: &WorkEnvelope,
        imports: &RefineImports,
    ) -> Result<RefinedServiceOutput, ServiceDispatchError> {
        self.validate_service_identity(&work.service)?;
        let output = self
            .pvm
            .refine_actor_tree(
                &work.encode(),
                imports,
                self.gas_schedule.refine,
                &self.refine_host,
            )
            .map_err(ServiceDispatchError::Pvm)?;
        decode_refined_service_output(output)
    }

    fn refine_actor_tree_traced(
        &self,
        work: &WorkEnvelope,
        imports: &RefineImports,
    ) -> Result<RefinedServiceOutput, ServiceDispatchError> {
        self.validate_service_identity(&work.service)?;
        let output = self
            .pvm
            .refine_actor_tree_traced(
                &work.encode(),
                imports,
                self.gas_schedule.refine,
                &self.refine_host,
            )
            .map_err(ServiceDispatchError::Pvm)?;
        decode_refined_service_output(output)
    }

    pub fn accumulate(
        &mut self,
        request: &AccumulateRequest,
    ) -> Result<AccumulatedServiceOutput, ServiceDispatchError> {
        self.validate_service_identity(request.service())?;
        verify_admitted_logical_timeslots(&self.accumulate_host, request, None)
            .map_err(ServiceDispatchError::Pvm)?;
        let output = self
            .pvm
            .accumulate(
                &request.encode(),
                self.gas_schedule.accumulate,
                &mut self.accumulate_host,
            )
            .map_err(ServiceDispatchError::Pvm)?;
        let result = AccumulationResult::decode(&output.bytes)
            .map_err(|_| ServiceDispatchError::InvalidAccumulateOutput)?;
        Ok(AccumulatedServiceOutput {
            result,
            gas_used: output.gas_used,
        })
    }

    pub fn accumulate_with_availability(
        &mut self,
        request: &AccumulateRequest,
        programs: &[ImportedProgram],
        blobs: &[ImportedBlob],
    ) -> Result<AccumulatedServiceOutput, ServiceDispatchError> {
        self.validate_service_identity(request.service())?;
        validate_accumulate_availability(request, programs, blobs)
            .map_err(|_| ServiceDispatchError::InvalidAvailabilityArtifacts)?;
        verify_admitted_logical_timeslots(&self.accumulate_host, request, None)
            .map_err(ServiceDispatchError::Pvm)?;
        let output = self
            .pvm
            .accumulate_with_availability(
                &request.encode(),
                self.gas_schedule.accumulate,
                &mut self.accumulate_host,
                programs,
                blobs,
            )
            .map_err(ServiceDispatchError::Pvm)?;
        let result = AccumulationResult::decode(&output.bytes)
            .map_err(|_| ServiceDispatchError::InvalidAccumulateOutput)?;
        Ok(AccumulatedServiceOutput {
            result,
            gas_used: output.gas_used,
        })
    }

    /// Accumulate a time-dependent request against a consensus-authenticated
    /// service platform logical timeslot. Ordinary requests should use [`Self::accumulate`].
    pub fn accumulate_at(
        &mut self,
        request: &AccumulateRequest,
        logical_timeslot: u64,
    ) -> Result<AccumulatedServiceOutput, ServiceDispatchError> {
        self.accumulate_at_with_availability(request, logical_timeslot, &[], &[])
    }

    pub fn accumulate_at_with_availability(
        &mut self,
        request: &AccumulateRequest,
        logical_timeslot: u64,
        programs: &[ImportedProgram],
        blobs: &[ImportedBlob],
    ) -> Result<AccumulatedServiceOutput, ServiceDispatchError> {
        self.validate_service_identity(request.service())?;
        validate_accumulate_availability(request, programs, blobs)
            .map_err(|_| ServiceDispatchError::InvalidAvailabilityArtifacts)?;
        verify_admitted_logical_timeslots(&self.accumulate_host, request, Some(logical_timeslot))
            .map_err(ServiceDispatchError::Pvm)?;
        let output = self
            .pvm
            .accumulate_at_with_availability(
                &request.encode(),
                self.gas_schedule.accumulate,
                &mut self.accumulate_host,
                logical_timeslot,
                programs,
                blobs,
            )
            .map_err(ServiceDispatchError::Pvm)?;
        let result = AccumulationResult::decode(&output.bytes)
            .map_err(|_| ServiceDispatchError::InvalidAccumulateOutput)?;
        Ok(AccumulatedServiceOutput {
            result,
            gas_used: output.gas_used,
        })
    }

    /// Execute an already committed entry after its logical time was checked
    /// against consensus history. This deliberately does not require the
    /// slot to remain the provider's current observation: follower replay and
    /// restart catch-up are historical operations.
    fn accumulate_replayed_with_availability(
        &mut self,
        request: &AccumulateRequest,
        logical_timeslot: Option<u64>,
        programs: &[ImportedProgram],
        blobs: &[ImportedBlob],
    ) -> Result<AccumulatedServiceOutput, ServiceDispatchError> {
        self.validate_service_identity(request.service())?;
        validate_accumulate_availability(request, programs, blobs)
            .map_err(|_| ServiceDispatchError::InvalidAvailabilityArtifacts)?;
        let output = match logical_timeslot {
            Some(logical_timeslot) => self.pvm.accumulate_at_with_availability(
                &request.encode(),
                self.gas_schedule.accumulate,
                &mut self.accumulate_host,
                logical_timeslot,
                programs,
                blobs,
            ),
            None => self.pvm.accumulate_with_availability(
                &request.encode(),
                self.gas_schedule.accumulate,
                &mut self.accumulate_host,
                programs,
                blobs,
            ),
        }
        .map_err(ServiceDispatchError::Pvm)?;
        let result = AccumulationResult::decode(&output.bytes)
            .map_err(|_| ServiceDispatchError::InvalidAccumulateOutput)?;
        Ok(AccumulatedServiceOutput {
            result,
            gas_used: output.gas_used,
        })
    }

    fn validate_service_identity(
        &self,
        declared: &ServiceIdentity,
    ) -> Result<(), ServiceDispatchError> {
        let expected = self.program_id();
        if declared.service_program != expected {
            return Err(ServiceDispatchError::ServiceProgramMismatch {
                expected,
                declared: declared.service_program,
            });
        }
        if declared.gas_schedule != self.gas_schedule {
            return Err(ServiceDispatchError::ServiceGasScheduleMismatch {
                expected: self.gas_schedule,
                declared: declared.gas_schedule,
            });
        }
        Ok(())
    }
}

fn decode_refined_service_output(
    output: ServicePvmOutput,
) -> Result<RefinedServiceOutput, ServiceDispatchError> {
    let refined = RefineOutput::decode(&output.bytes)
        .map_err(|_| ServiceDispatchError::InvalidRefineOutput)?;
    let mut exported_blobs = refined.candidate_blobs;
    exported_blobs.extend(output.exported_blobs);
    exported_blobs.sort_by_key(|blob| blob.reference.hash);
    if exported_blobs
        .windows(2)
        .any(|pair| pair[0].reference.hash == pair[1].reference.hash && pair[0] != pair[1])
    {
        return Err(ServiceDispatchError::InvalidRefineOutput);
    }
    exported_blobs.dedup();
    Ok(RefinedServiceOutput {
        transition: refined.transition,
        gas_used: output.gas_used,
        exported_blobs,
        producer_records: output.producer_records,
        trace: output.trace,
    })
}

impl<R, A> ServiceRuntime<R, A>
where
    R: RefineProtocolHost,
    A: AccumulateProtocolHost + AttestationProofHost,
{
    /// Prepare, prove, and commit one single-slice attested transition.
    ///
    /// The proof producer receives the exact service scheduler PVM, canonical
    /// actor imports, and guest-derived statement. Apply is not invoked until
    /// a non-empty proof is available; the returned package is constructed
    /// only from a successful non-duplicate guest commit.
    pub fn accumulate_attested<P: AttestationProofProducer + ?Sized>(
        &mut self,
        envelope: AccumulationEnvelope,
        imports: &RefineImports,
        producer: &mut P,
    ) -> Result<CommittedAttestationOutput, AttestedServiceError<ServiceDispatchError, P::Error>>
    {
        let prepared = self
            .accumulate(&AccumulateRequest::PrepareAttested(envelope.clone()))
            .map_err(AttestedServiceError::Service)?;
        let preparation = match prepared.result {
            AccumulationResult::Prepared(preparation) => preparation,
            AccumulationResult::Rejected(rejection) => {
                return Err(AttestedServiceError::Rejected(rejection));
            }
            _ => return Err(AttestedServiceError::InvalidPreparation),
        };
        if preparation.committed_proof.is_some() {
            return self.recover_prepared_attestation(
                envelope,
                imports,
                preparation,
                producer,
                prepared.gas_used,
            );
        }

        let proved = self
            .prove_prepared_attestation(envelope, imports, preparation, producer)
            .map_err(map_attestation_build_error)?;
        let committed = self
            .accumulate(&AccumulateRequest::Apply(proved.envelope.clone()))
            .map_err(AttestedServiceError::Service)?;
        finish_committed_attestation(proved, prepared.gas_used, committed)
    }

    fn prove_prepared_attestation<P: AttestationProofProducer + ?Sized>(
        &mut self,
        mut envelope: AccumulationEnvelope,
        imports: &RefineImports,
        preparation: AttestationPreparation,
        producer: &mut P,
    ) -> Result<ProvedAttestation, AttestationBuildError<P::Error>> {
        let replay = self
            .refine_actor_tree_traced(&envelope.work, imports)
            .map_err(|_| AttestationBuildError::InvalidPreparation)?;
        if replay.transition != envelope.transition
            || replay.exported_blobs != envelope.provided_blobs
        {
            return Err(AttestationBuildError::InvalidPreparation);
        }
        let refine_trace = replay
            .trace
            .as_ref()
            .ok_or(AttestationBuildError::InvalidPreparation)?
            .commitment;
        let produced = {
            let request = AttestationProofRequest {
                canonical_service_pvm: self.pvm.canonical_pvm(),
                work: &envelope.work,
                imports,
                transition: &envelope.transition,
                preparation: &preparation,
                refine_trace,
            };
            request
                .validate()
                .map_err(|_| AttestationBuildError::InvalidPreparation)?;
            producer
                .prove(&request)
                .map_err(AttestationBuildError::Producer)?
        };
        produced
            .validate_for(refine_trace)
            .map_err(|_| AttestationBuildError::InvalidProducedProof)?;

        let proof_blob = super::BlobRef::of_bytes(&produced.proof);
        let proof = ProofCommitment {
            statement: preparation.statement.commitment(),
            trace: produced.trace,
            proof_blob: proof_blob.clone(),
        };
        let verification = ProofVerificationRequest {
            actor_program: envelope.work.target_program,
            execution_semantics: envelope.work.service.execution_semantics,
            statement: proof.statement,
            trace: proof.trace,
            proof_blob: proof_blob.clone(),
        };
        if !self
            .accumulate_host
            .make_proof_available(&verification, &produced.proof)
        {
            return Err(AttestationBuildError::ProofUnavailable);
        }
        envelope.transition.proof = Some(proof.clone());
        let imported = ImportedBlob {
            reference: proof_blob,
            bytes: produced.proof.clone(),
        };
        match envelope
            .provided_blobs
            .binary_search_by_key(&imported.reference.hash, |blob| blob.reference.hash)
        {
            Ok(index) if envelope.provided_blobs[index] == imported => {}
            Ok(_) => return Err(AttestationBuildError::InvalidProducedProof),
            Err(index) => envelope.provided_blobs.insert(index, imported),
        }

        Ok(ProvedAttestation {
            envelope,
            preparation,
            proof,
            proof_bytes: produced.proof,
        })
    }

    fn recover_prepared_attestation<E, P: AttestationProofProducer + ?Sized>(
        &mut self,
        envelope: AccumulationEnvelope,
        imports: &RefineImports,
        preparation: AttestationPreparation,
        producer: &mut P,
        prepare_gas_used: u64,
    ) -> Result<CommittedAttestationOutput, AttestedServiceError<E, P::Error>> {
        let proof = preparation
            .committed_proof
            .clone()
            .ok_or(AttestedServiceError::InvalidPreparation)?;
        let proof_bytes = if let Some(bytes) = self.accumulate_host.proof_bytes(&proof.proof_blob) {
            bytes
        } else {
            let reproduced = self
                .prove_prepared_attestation(
                    envelope.clone(),
                    imports,
                    preparation.clone(),
                    producer,
                )
                .map_err(map_attestation_build_error)?;
            if reproduced.proof != proof {
                return Err(AttestedServiceError::CommitMismatch);
            }
            reproduced.proof_bytes
        };
        if !proof.proof_blob.matches(&proof_bytes) {
            return Err(AttestedServiceError::CommitMismatch);
        }
        let published = PublishedEffects {
            reply: envelope.transition.reply,
            outbox: envelope.transition.outbox,
            exported_blobs: envelope.transition.exported_blobs,
            proof: Some(proof.clone()),
            attestation: Some(Box::new(AttestationDelivery {
                producer_name: preparation.statement.producer_name.clone(),
                producer: preparation.statement.producer,
                statement: preparation.statement.clone(),
                proof: proof.clone(),
            })),
        };
        validate_committed_attestation(&preparation, &proof, &preparation.receipt, &published)?;
        Ok(CommittedAttestationOutput {
            preparation,
            proof,
            proof_bytes,
            published,
            prepare_gas_used,
            accumulate_gas_used: 0,
        })
    }
}

fn map_attestation_build_error<E, P>(
    error: AttestationBuildError<P>,
) -> AttestedServiceError<E, P> {
    match error {
        AttestationBuildError::InvalidPreparation => AttestedServiceError::InvalidPreparation,
        AttestationBuildError::Producer(error) => AttestedServiceError::Producer(error),
        AttestationBuildError::InvalidProducedProof => AttestedServiceError::InvalidProducedProof,
        AttestationBuildError::ProofUnavailable => AttestedServiceError::ProofUnavailable,
    }
}

fn finish_committed_attestation<E, P>(
    mut proved: ProvedAttestation,
    prepare_gas_used: u64,
    committed: AccumulatedServiceOutput,
) -> Result<CommittedAttestationOutput, AttestedServiceError<E, P>> {
    let (receipt, published) = match committed.result {
        AccumulationResult::Accepted {
            receipt,
            published,
            duplicate: false,
        } => (receipt, published),
        AccumulationResult::Rejected(rejection) => {
            return Err(AttestedServiceError::Rejected(rejection));
        }
        _ => return Err(AttestedServiceError::CommitMismatch),
    };
    validate_committed_attestation(&proved.preparation, &proved.proof, &receipt, &published)?;
    proved.preparation.committed_proof = Some(proved.proof.clone());
    Ok(CommittedAttestationOutput {
        preparation: proved.preparation,
        proof: proved.proof,
        proof_bytes: proved.proof_bytes,
        published,
        prepare_gas_used,
        accumulate_gas_used: committed.gas_used,
    })
}

fn validate_committed_attestation<E, P>(
    preparation: &AttestationPreparation,
    proof: &ProofCommitment,
    committed_receipt: &AccumulationReceipt,
    published: &PublishedEffects,
) -> Result<(), AttestedServiceError<E, P>> {
    let Some(reply) = published.reply.as_ref() else {
        return Err(AttestedServiceError::CommitMismatch);
    };
    if preparation.validate().is_err()
        || committed_receipt != &preparation.receipt
        || published.proof.as_ref() != Some(proof)
        || published.attestation.as_ref().is_none_or(|delivery| {
            delivery.statement != preparation.statement
                || delivery.proof != *proof
                || delivery.producer != preparation.statement.producer
        })
        || committed_receipt.reply_commitment != Some(reply.commitment())
        || preparation.statement.claim_commitment
            != super::Hash::digest(b"vos/attestation-claim", &[&reply.result])
    {
        return Err(AttestedServiceError::CommitMismatch);
    }
    Ok(())
}

impl<R, A, L> ReplicatedServiceRuntime<R, A, L>
where
    R: RefineProtocolHost,
    A: AccumulateProtocolHost
        + AttestationProofHost
        + CommittedServiceImageHost
        + ReceiptVerificationHost,
    L: CommittedAccumulateLog,
{
    /// Rewrite the applied-state snapshot at its existing cursor after a
    /// host-only image envelope change such as production-verifier
    /// provenance. No actor request is applied and the cursor does not move.
    pub(crate) fn refresh_applied_service_snapshot(
        &mut self,
    ) -> Result<(), ReplicatedServiceError<L::Error>> {
        let applied = self
            .log
            .applied_index()
            .map_err(ReplicatedServiceError::Log)?;
        if applied == 0 {
            return Ok(());
        }
        let service_image = self.service.accumulate_host().committed_service_image();
        self.validate_service_image_identity(&service_image)?;
        let proof_artifacts =
            snapshot_proof_artifacts(self.service.accumulate_host(), &service_image)
                .map_err(|_| ReplicatedServiceError::ProofUnavailable)?;
        let result_artifacts =
            snapshot_result_artifacts(self.service.accumulate_host(), &service_image)
                .map_err(|_| ReplicatedServiceError::ProofUnavailable)?;
        self.log
            .mark_applied(applied, &service_image, &proof_artifacts, &result_artifacts)
            .map_err(ReplicatedServiceError::Log)
    }

    fn validate_service_image_identity(
        &self,
        service_image: &[u8],
    ) -> Result<(), ReplicatedServiceError<L::Error>> {
        let snapshot = MemoryServiceSnapshot::decode(service_image).map_err(|_| {
            ReplicatedServiceError::ServiceImage(ServiceImageInstallError::InvalidSnapshot)
        })?;
        if let Some(identity) = snapshot.service_identity().map_err(|_| {
            ReplicatedServiceError::ServiceImage(ServiceImageInstallError::InvalidSnapshot)
        })? {
            self.service
                .validate_service_identity(&identity)
                .map_err(ReplicatedServiceError::Dispatch)?;
        }
        Ok(())
    }

    fn apply_committed_after(
        &mut self,
        applied: u64,
        capture: Option<&CommittedAccumulateEntry>,
    ) -> Result<(usize, Option<AccumulatedServiceOutput>), ReplicatedServiceError<L::Error>> {
        let batch = self
            .log
            .committed_after(applied)
            .map_err(ReplicatedServiceError::Log)?;
        if batch.committed_index < applied
            || batch
                .entries
                .iter()
                .any(|entry| entry.index <= applied || entry.index > batch.committed_index)
            || batch
                .entries
                .windows(2)
                .any(|pair| pair[0].index >= pair[1].index)
        {
            return Err(ReplicatedServiceError::InvalidCommittedLog);
        }

        let mut applied_entries = 0;
        let mut cursor = applied;
        let mut captured = None;
        for entry in batch.entries {
            let is_captured = capture.is_some_and(|target| target.index == entry.index);
            if is_captured
                && capture.is_some_and(|target| {
                    target.request.as_slice() != entry.request.as_slice()
                        || target.host_state_machine != entry.host_state_machine
                        || target.logical_timeslot != entry.logical_timeslot
                        || target.production_trust_policy != entry.production_trust_policy
                        || target.availability_programs != entry.availability_programs
                        || target.availability_blobs != entry.availability_blobs
                        || target.receipt_verifications != entry.receipt_verifications
                })
            {
                return Err(ReplicatedServiceError::InvalidCommittedLog);
            }
            let request = AccumulateRequest::decode(&entry.request)
                .map_err(|_| ReplicatedServiceError::InvalidCommittedLog)?;
            if entry.host_state_machine != Some(super::HOST_STATE_MACHINE_ID) {
                return Err(ReplicatedServiceError::InvalidCommittedLog);
            }
            if entry.production_trust_policy
                != self.service.accumulate_host().production_trust_policy_id()
            {
                return Err(ReplicatedServiceError::InvalidCommittedLog);
            }
            validate_accumulate_availability(
                &request,
                &entry.availability_programs,
                &entry.availability_blobs,
            )
            .map_err(|_| ReplicatedServiceError::InvalidCommittedLog)?;
            validate_receipt_verifications(&request, &entry.receipt_verifications, true)
                .map_err(|_| ReplicatedServiceError::InvalidCommittedLog)?;
            if requires_logical_timeslot(&request) != entry.logical_timeslot.is_some() {
                return Err(ReplicatedServiceError::InvalidCommittedLog);
            }
            verify_replayed_logical_timeslots(
                self.service.accumulate_host(),
                &request,
                entry.logical_timeslot,
            )
            .map_err(|error| ReplicatedServiceError::Dispatch(ServiceDispatchError::Pvm(error)))?;
            // Proof hydration is a durable local precondition, not a guest
            // semantic decision. A failed side-CAS write must leave this entry
            // unapplied so exact catch-up can retry it.
            ensure_request_proof_available(self.service.accumulate_host_mut(), &request)
                .map_err(|_| ReplicatedServiceError::ProofUnavailable)?;
            ensure_request_receipts_available(
                self.service.accumulate_host_mut(),
                &entry.receipt_verifications,
            )
            .map_err(|_| ReplicatedServiceError::ReceiptUnavailable)?;
            let outcome = self.service.accumulate_replayed_with_availability(
                &request,
                entry.logical_timeslot,
                &entry.availability_programs,
                &entry.availability_blobs,
            );
            if let Err(error) = outcome.as_ref()
                && !error.is_deterministic_accumulate_failure()
            {
                return Err(ReplicatedServiceError::Dispatch(error.clone()));
            }
            let service_image = self.service.accumulate_host().committed_service_image();
            let proof_artifacts =
                snapshot_proof_artifacts(self.service.accumulate_host(), &service_image)
                    .map_err(|_| ReplicatedServiceError::ProofUnavailable)?;
            let result_artifacts =
                snapshot_result_artifacts(self.service.accumulate_host(), &service_image)
                    .map_err(|_| ReplicatedServiceError::ProofUnavailable)?;
            self.log
                .mark_applied(
                    entry.index,
                    &service_image,
                    &proof_artifacts,
                    &result_artifacts,
                )
                .map_err(ReplicatedServiceError::Log)?;
            let output = match outcome {
                Ok(output) => Some(output),
                Err(error) if is_captured => {
                    return Err(ReplicatedServiceError::Dispatch(error));
                }
                Err(_) => None,
            };
            if is_captured {
                captured = output;
            }
            cursor = entry.index;
            applied_entries += 1;
        }
        if batch.committed_index > cursor {
            let service_image = self.service.accumulate_host().committed_service_image();
            // Configuration/no-op entries advance only the cursor. They must
            // not bless an image produced under another program or gas
            // schedule merely because no application entry was replayed.
            self.validate_service_image_identity(&service_image)?;
            let proof_artifacts =
                snapshot_proof_artifacts(self.service.accumulate_host(), &service_image)
                    .map_err(|_| ReplicatedServiceError::ProofUnavailable)?;
            let result_artifacts =
                snapshot_result_artifacts(self.service.accumulate_host(), &service_image)
                    .map_err(|_| ReplicatedServiceError::ProofUnavailable)?;
            self.log
                .mark_applied(
                    batch.committed_index,
                    &service_image,
                    &proof_artifacts,
                    &result_artifacts,
                )
                .map_err(ReplicatedServiceError::Log)?;
        }
        if capture.is_some() && captured.is_none() {
            return Err(ReplicatedServiceError::InvalidCommittedLog);
        }
        Ok((applied_entries, captured))
    }

    /// Apply every committed request not yet reflected in this replica's
    /// service image. Effects are recovered as guest-owned publication rows;
    /// followers never publish the returned execution output directly.
    pub fn catch_up(&mut self) -> Result<usize, ReplicatedServiceError<L::Error>> {
        let mut applied = self
            .log
            .applied_index()
            .map_err(ReplicatedServiceError::Log)?;
        if let Some(snapshot) = self
            .log
            .installed_snapshot_after(applied)
            .map_err(ReplicatedServiceError::Log)?
        {
            if snapshot.applied_index <= applied {
                return Err(ReplicatedServiceError::InvalidCommittedLog);
            }
            // Validate before hydrating the proof side-CAS, installing the
            // image, or advancing the applied cursor. A fresh host has no
            // existing header against which install can detect a mismatch.
            self.validate_service_image_identity(&snapshot.service_image)?;
            let service_snapshot = MemoryServiceSnapshot::decode(&snapshot.service_image)
                .map_err(|_| ReplicatedServiceError::InvalidCommittedLog)?;
            if self
                .service
                .accumulate_host()
                .requires_proof_verifier_provenance()
                && !service_snapshot.has_proof_verifier_provenance()
            {
                return Err(ReplicatedServiceError::ProofUnavailable);
            }
            for artifact in &snapshot.proof_artifacts {
                if !self
                    .service
                    .accumulate_host_mut()
                    .make_proof_available(&artifact.verification, &artifact.bytes)
                {
                    return Err(ReplicatedServiceError::ProofUnavailable);
                }
            }
            for artifact in &snapshot.result_artifacts {
                if !self
                    .service
                    .accumulate_host_mut()
                    .make_invocation_result_available(&artifact.reference, &artifact.bytes)
                {
                    return Err(ReplicatedServiceError::ProofUnavailable);
                }
            }
            self.service
                .accumulate_host_mut()
                .install_committed_service_image(&snapshot.service_image)
                .map_err(ReplicatedServiceError::ServiceImage)?;
            self.log
                .mark_applied(
                    snapshot.applied_index,
                    &snapshot.service_image,
                    &snapshot.proof_artifacts,
                    &snapshot.result_artifacts,
                )
                .map_err(ReplicatedServiceError::Log)?;
            applied = snapshot.applied_index;
        }
        self.apply_committed_after(applied, None)
            .map(|(applied_entries, _)| applied_entries)
    }

    /// Confirm current-term leadership, then apply through the certified Raft
    /// read index before the caller observes service state. The caller may
    /// allocate an admission timeslot only after this returns and must use the
    /// `*_after_barrier` methods below so no second catch-up can intervene.
    pub fn leadership_barrier_and_catch_up(
        &mut self,
    ) -> Result<usize, ReplicatedServiceError<L::Error>> {
        let read_index = self
            .log
            .leader_read_index()
            .map_err(ReplicatedServiceError::Log)?;
        let applied_entries = self.catch_up()?;
        let applied = self
            .log
            .applied_index()
            .map_err(ReplicatedServiceError::Log)?;
        if applied < read_index {
            return Err(ReplicatedServiceError::InvalidCommittedLog);
        }
        Ok(applied_entries)
    }

    pub fn refine_actor_tree(
        &mut self,
        work: &WorkEnvelope,
        imports: &RefineImports,
    ) -> Result<RefinedServiceOutput, ReplicatedServiceError<L::Error>> {
        self.catch_up()?;
        self.service
            .refine_actor_tree(work, imports)
            .map_err(ReplicatedServiceError::Dispatch)
    }

    #[cfg(feature = "storage")]
    pub(crate) fn refine_actor_tree_after_barrier(
        &self,
        work: &WorkEnvelope,
        imports: &RefineImports,
    ) -> Result<RefinedServiceOutput, ReplicatedServiceError<L::Error>> {
        self.service
            .refine_actor_tree(work, imports)
            .map_err(ReplicatedServiceError::Dispatch)
    }

    /// Quorum-order one mutating request, then apply that committed entry via
    /// physical IC-5. Attestation preparation is deliberately read-only and
    /// executes against the caught-up local image without entering the log.
    pub fn accumulate(
        &mut self,
        request: &AccumulateRequest,
    ) -> Result<AccumulatedServiceOutput, ReplicatedServiceError<L::Error>> {
        self.accumulate_with_availability(request, &[], &[])
    }

    /// Quorum-order one request together with the exact content-addressed
    /// programs and blobs needed to execute it on an otherwise empty replica.
    pub fn accumulate_with_availability(
        &mut self,
        request: &AccumulateRequest,
        programs: &[ImportedProgram],
        blobs: &[ImportedBlob],
    ) -> Result<AccumulatedServiceOutput, ReplicatedServiceError<L::Error>> {
        self.accumulate_ordered(request, None, programs, blobs, &[])
    }

    /// Quorum-order a time-dependent request together with the
    /// consensus-authenticated service platform slot observed by the leader. The slot is
    /// part of the replicated entry and is replayed identically by followers.
    pub fn accumulate_at(
        &mut self,
        request: &AccumulateRequest,
        logical_timeslot: u64,
    ) -> Result<AccumulatedServiceOutput, ReplicatedServiceError<L::Error>> {
        self.accumulate_ordered(request, Some(logical_timeslot), &[], &[], &[])
    }

    fn accumulate_ordered(
        &mut self,
        request: &AccumulateRequest,
        logical_timeslot: Option<u64>,
        programs: &[ImportedProgram],
        blobs: &[ImportedBlob],
        receipt_verifications: &[ReceiptVerificationRequest],
    ) -> Result<AccumulatedServiceOutput, ReplicatedServiceError<L::Error>> {
        self.catch_up()?;
        self.accumulate_ordered_after_barrier(
            request,
            logical_timeslot,
            programs,
            blobs,
            receipt_verifications,
        )
    }

    #[cfg(feature = "storage")]
    pub(crate) fn accumulate_with_availability_after_barrier(
        &mut self,
        request: &AccumulateRequest,
        programs: &[ImportedProgram],
        blobs: &[ImportedBlob],
    ) -> Result<AccumulatedServiceOutput, ReplicatedServiceError<L::Error>> {
        self.accumulate_ordered_after_barrier(request, None, programs, blobs, &[])
    }

    /// Quorum-order one request together with its exact positive receipt
    /// verification selected by authenticated host routing. Canonical
    /// validation binds the sidecar to authority ingress, durable delivery,
    /// awaited-reply consumption, or every distinct CRDT sync-node receipt,
    /// and rejects it for every other shape.
    #[cfg(feature = "storage")]
    pub(crate) fn accumulate_with_receipt_verifications_after_barrier(
        &mut self,
        request: &AccumulateRequest,
        receipt_verifications: &[ReceiptVerificationRequest],
    ) -> Result<AccumulatedServiceOutput, ReplicatedServiceError<L::Error>> {
        self.accumulate_ordered_after_barrier(request, None, &[], &[], receipt_verifications)
    }

    /// Quorum-order a slot-bound request after the caller has already
    /// established the current-term read barrier and caught up through it.
    #[cfg(feature = "storage")]
    pub(crate) fn accumulate_at_after_barrier(
        &mut self,
        request: &AccumulateRequest,
        logical_timeslot: u64,
    ) -> Result<AccumulatedServiceOutput, ReplicatedServiceError<L::Error>> {
        self.accumulate_ordered_after_barrier(request, Some(logical_timeslot), &[], &[], &[])
    }

    fn accumulate_ordered_after_barrier(
        &mut self,
        request: &AccumulateRequest,
        logical_timeslot: Option<u64>,
        programs: &[ImportedProgram],
        blobs: &[ImportedBlob],
        receipt_verifications: &[ReceiptVerificationRequest],
    ) -> Result<AccumulatedServiceOutput, ReplicatedServiceError<L::Error>> {
        self.service
            .validate_service_identity(request.service())
            .map_err(ReplicatedServiceError::Dispatch)?;
        validate_accumulate_availability(request, programs, blobs).map_err(|_| {
            ReplicatedServiceError::Dispatch(ServiceDispatchError::InvalidAvailabilityArtifacts)
        })?;
        validate_receipt_verifications(request, receipt_verifications, true).map_err(|_| {
            ReplicatedServiceError::Dispatch(ServiceDispatchError::InvalidAvailabilityArtifacts)
        })?;
        let time_dependent = requires_logical_timeslot(request);
        if time_dependent && logical_timeslot.is_none() {
            return Err(ReplicatedServiceError::LogicalTimeslotRequired);
        }
        if !time_dependent && logical_timeslot.is_some() {
            return Err(ReplicatedServiceError::UnexpectedLogicalTimeslot);
        }
        verify_admitted_logical_timeslots(
            self.service.accumulate_host(),
            request,
            logical_timeslot,
        )
        .map_err(|error| ReplicatedServiceError::Dispatch(ServiceDispatchError::Pvm(error)))?;
        if matches!(request, AccumulateRequest::PrepareAttested(_)) {
            return self
                .service
                .accumulate_with_availability(request, programs, blobs)
                .map_err(ReplicatedServiceError::Dispatch);
        }
        ensure_request_proof_available(self.service.accumulate_host_mut(), request)
            .map_err(|_| ReplicatedServiceError::ProofUnavailable)?;
        // A sidecar is consensus input only after the leader's installed
        // production authority has accepted it. Followers repeat this check
        // during replay; doing it here prevents a denied request from becoming
        // a committed poison entry that no replica can advance past.
        ensure_request_receipts_available(
            self.service.accumulate_host_mut(),
            receipt_verifications,
        )
        .map_err(|_| ReplicatedServiceError::ReceiptUnavailable)?;

        let request_bytes = request.encode();
        let production_trust_policy = self.service.accumulate_host().production_trust_policy_id();
        let entry = self
            .log
            .propose_at_with_availability(
                &request_bytes,
                logical_timeslot,
                production_trust_policy,
                programs,
                blobs,
                receipt_verifications,
            )
            .map_err(ReplicatedServiceError::Log)?;
        let applied = self
            .log
            .applied_index()
            .map_err(ReplicatedServiceError::Log)?;
        if entry.index <= applied
            || entry.request != request_bytes
            || entry.logical_timeslot != logical_timeslot
            || entry.production_trust_policy != production_trust_policy
            || entry.availability_programs.as_slice() != programs
            || entry.availability_blobs.as_slice() != blobs
            || entry.receipt_verifications.as_slice() != receipt_verifications
        {
            return Err(ReplicatedServiceError::InvalidCommittedLog);
        }
        self.apply_committed_after(applied, Some(&entry))?
            .1
            .ok_or(ReplicatedServiceError::InvalidCommittedLog)
    }

    /// Produce the proof before proposing the final Apply request. Only the
    /// proved Apply bytes enter Raft; read-only preparation never consumes a
    /// log position. Followers make the same proof artifact available before
    /// executing the committed request through physical IC-5.
    pub fn accumulate_attested<P: AttestationProofProducer + ?Sized>(
        &mut self,
        envelope: AccumulationEnvelope,
        imports: &RefineImports,
        producer: &mut P,
    ) -> Result<
        CommittedAttestationOutput,
        AttestedServiceError<ReplicatedServiceError<L::Error>, P::Error>,
    > {
        let prepared = self
            .accumulate(&AccumulateRequest::PrepareAttested(envelope.clone()))
            .map_err(AttestedServiceError::Service)?;
        let preparation = match prepared.result {
            AccumulationResult::Prepared(preparation) => preparation,
            AccumulationResult::Rejected(rejection) => {
                return Err(AttestedServiceError::Rejected(rejection));
            }
            _ => return Err(AttestedServiceError::InvalidPreparation),
        };
        if preparation.committed_proof.is_some() {
            return self.service.recover_prepared_attestation(
                envelope,
                imports,
                preparation,
                producer,
                prepared.gas_used,
            );
        }
        let proved = self
            .service
            .prove_prepared_attestation(envelope, imports, preparation, producer)
            .map_err(map_attestation_build_error)?;
        let committed = self
            .accumulate(&AccumulateRequest::Apply(proved.envelope.clone()))
            .map_err(AttestedServiceError::Service)?;
        finish_committed_attestation(proved, prepared.gas_used, committed)
    }

    /// Prepare and prove against a caller-established leadership barrier,
    /// then quorum-order the final proved Apply without another intervening
    /// catch-up. This is the attested counterpart of the other
    /// `*_after_barrier` entry points used by the root driver after allocating
    /// consensus-significant admission time.
    #[cfg(feature = "storage")]
    pub(crate) fn accumulate_attested_after_barrier<P: AttestationProofProducer + ?Sized>(
        &mut self,
        envelope: AccumulationEnvelope,
        imports: &RefineImports,
        producer: &mut P,
    ) -> Result<
        CommittedAttestationOutput,
        AttestedServiceError<ReplicatedServiceError<L::Error>, P::Error>,
    > {
        let prepared = self
            .service
            .accumulate(&AccumulateRequest::PrepareAttested(envelope.clone()))
            .map_err(|error| {
                AttestedServiceError::Service(ReplicatedServiceError::Dispatch(error))
            })?;
        let preparation = match prepared.result {
            AccumulationResult::Prepared(preparation) => preparation,
            AccumulationResult::Rejected(rejection) => {
                return Err(AttestedServiceError::Rejected(rejection));
            }
            _ => return Err(AttestedServiceError::InvalidPreparation),
        };
        if preparation.committed_proof.is_some() {
            return self.service.recover_prepared_attestation(
                envelope,
                imports,
                preparation,
                producer,
                prepared.gas_used,
            );
        }
        let proved = self
            .service
            .prove_prepared_attestation(envelope, imports, preparation, producer)
            .map_err(map_attestation_build_error)?;
        let committed = self
            .accumulate_ordered_after_barrier(
                &AccumulateRequest::Apply(proved.envelope.clone()),
                None,
                &[],
                &[],
                &[],
            )
            .map_err(AttestedServiceError::Service)?;
        finish_committed_attestation(proved, prepared.gas_used, committed)
    }
}

fn snapshot_proof_artifacts<A: AttestationProofHost>(
    host: &A,
    service_image: &[u8],
) -> Result<Vec<CommittedProofArtifact>, ()> {
    let snapshot = MemoryServiceSnapshot::decode(service_image).map_err(|_| ())?;
    snapshot
        .referenced_proof_verifications()
        .map_err(|_| ())?
        .into_iter()
        .map(|verification| {
            let bytes = host.proof_bytes(&verification.proof_blob).ok_or(())?;
            if !verification.proof_blob.matches(&bytes) {
                return Err(());
            }
            Ok(CommittedProofArtifact {
                verification,
                bytes,
            })
        })
        .collect()
}

fn snapshot_result_artifacts<A: CommittedServiceImageHost>(
    host: &A,
    service_image: &[u8],
) -> Result<Vec<CommittedResultArtifact>, ()> {
    let snapshot = MemoryServiceSnapshot::decode(service_image).map_err(|_| ())?;
    snapshot
        .referenced_invocation_results()
        .into_iter()
        .map(|reference| {
            let bytes = host.invocation_result_bytes(&reference).ok_or(())?;
            if !reference.matches(&bytes) {
                return Err(());
            }
            Ok(CommittedResultArtifact { reference, bytes })
        })
        .collect()
}

fn ensure_request_proof_available<A: AttestationProofHost>(
    host: &mut A,
    request: &AccumulateRequest,
) -> Result<(), ()> {
    let AccumulateRequest::Apply(envelope) = request else {
        return Ok(());
    };
    let (actor_program, execution_semantics, proof) =
        if let Some(proof) = envelope.transition.proof.as_ref() {
            (
                envelope.work.target_program,
                envelope.work.service.execution_semantics,
                proof,
            )
        } else if let Some(attestation) = envelope
            .work
            .awaited_reply
            .as_ref()
            .and_then(|reply| reply.attestation.as_ref())
        {
            (
                attestation.statement.actor_program,
                attestation
                    .statement
                    .accumulation_receipt
                    .service
                    .execution_semantics,
                &attestation.proof,
            )
        } else {
            return Ok(());
        };
    let Some(imported) = envelope
        .provided_blobs
        .iter()
        .find(|blob| blob.reference == proof.proof_blob)
    else {
        // The proof may already be present in a production verifier/CAS. In
        // that case guest Accumulate decides availability through IC-5.
        return Ok(());
    };
    let verification = ProofVerificationRequest {
        actor_program,
        execution_semantics,
        statement: proof.statement,
        trace: proof.trace,
        proof_blob: proof.proof_blob.clone(),
    };
    if !proof.proof_blob.matches(&imported.bytes)
        || !host.make_proof_available(&verification, &imported.bytes)
    {
        return Err(());
    }
    Ok(())
}

fn ensure_request_receipts_available<A: ReceiptVerificationHost>(
    host: &mut A,
    verifications: &[ReceiptVerificationRequest],
) -> Result<(), ()> {
    for verification in verifications {
        if !host.make_receipt_available(verification) {
            return Err(());
        }
    }
    Ok(())
}
