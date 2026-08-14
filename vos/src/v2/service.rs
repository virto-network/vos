//! Local conformance harness for the protocol-pinned generic service PVM.
//!
//! There is deliberately no native Refine implementation and no native
//! transition-apply shortcut here. Both paths execute the same canonical PVM
//! that deployment installs; the host supplies only imports and an atomic JAM
//! storage transaction boundary.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::attestation::{
    Attestation, AttestationError, AttestationPreparationV2, AttestationProofHostV2,
    AttestationProofProducerV2, AttestationProofRequestV2, AttestedMethod,
};

use super::wire::{DecodeError, Decoder, Encoder};
use super::{
    AccumulateProtocolHostV2, AccumulateRequestV2, AccumulatedReplyV2, AccumulatedRoleAssertionV2,
    AccumulationEnvelopeV2, AccumulationReceiptV2, AccumulationRejectionV2, AccumulationResultV2,
    AttestationDeliveryV2, AuthorizationEvidenceV2, CommittedServiceImageHostV2, GasScheduleV2,
    ImportedBlobV2, ImportedProgramV2, LocalJamStoreSnapshotV2, ProgramId, ProofCommitmentV2,
    ProofVerificationRequestV2, PublishedEffectsV2, ReceiptVerificationHostV2,
    ReceiptVerificationRequestV2, RefineImportsV2, RefineOutputV2, RefineProtocolHostV2,
    RefineTraceV2, RoleCredentialV2, ServiceIdentityV2, ServiceImageInstallErrorV2,
    ServicePvmErrorV2, ServicePvmOutputV2, ServicePvmV2, TransitionV2, V2Wire, WorkEnvelopeV2,
};

fn validate_accumulate_availability(
    request: &AccumulateRequestV2,
    programs: &[ImportedProgramV2],
    blobs: &[ImportedBlobV2],
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
        AccumulateRequestV2::Install(genesis) => (
            genesis
                .actors
                .iter()
                .map(|actor| actor.program)
                .collect::<Vec<_>>(),
            genesis
                .actors
                .iter()
                .map(|actor| actor.initial_state.clone())
                .collect::<Vec<_>>(),
        ),
        AccumulateRequestV2::UpgradeActor(upgrade) => {
            (alloc::vec![upgrade.replacement_program], Vec::new())
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
    request: &AccumulateRequestV2,
    verifications: &[ReceiptVerificationRequestV2],
    require_external_verification: bool,
) -> Result<(), DecodeError> {
    if verifications
        .windows(2)
        .any(|pair| pair[0].hash() >= pair[1].hash())
    {
        return Err(DecodeError::NonCanonical);
    }
    let assertion_for = |authorization: &AuthorizationEvidenceV2| match authorization {
        AuthorizationEvidenceV2::Credential { bytes, .. } => {
            RoleCredentialV2::decode(bytes).ok().and_then(|credential| {
                AccumulatedRoleAssertionV2::decode(&credential.authenticator).ok()
            })
        }
        _ => None,
    };
    let assertion = match request {
        AccumulateRequestV2::AdmitIngress(ingress) => match ingress.authorization() {
            AuthorizationEvidenceV2::Credential { bytes, .. } => {
                RoleCredentialV2::decode(bytes).ok().and_then(|credential| {
                    AccumulatedRoleAssertionV2::decode(&credential.authenticator).ok()
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
    } else if let AccumulateRequestV2::Deliver(delivery) = request {
        let mut expected = alloc::vec![ReceiptVerificationRequestV2 {
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
        expected.sort_by_key(ReceiptVerificationRequestV2::hash);
        expected.dedup();
        if verifications.is_empty() && !require_external_verification {
            return Ok(());
        }
        return (verifications == expected)
            .then_some(())
            .ok_or(DecodeError::NonCanonical);
    } else if let AccumulateRequestV2::SyncCrdt(envelope) = request {
        let mut expected = envelope
            .nodes
            .iter()
            .map(|node| {
                Some(ReceiptVerificationRequestV2 {
                    expected_producer: node.change.expected_producer()?,
                    receipt: node.receipt.clone(),
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(DecodeError::NonCanonical)?;
        expected.sort_by_key(ReceiptVerificationRequestV2::hash);
        expected.dedup();
        if verifications.is_empty() && !require_external_verification {
            return Ok(());
        }
        return (verifications == expected)
            .then_some(())
            .ok_or(DecodeError::NonCanonical);
    } else {
        match request {
            AccumulateRequestV2::Deliver(_) => unreachable!("delivery handled above"),
            AccumulateRequestV2::Apply(envelope) => {
                envelope
                    .work
                    .awaited_reply
                    .as_ref()
                    .map(|reply| ReceiptVerificationRequestV2 {
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

fn requires_logical_timeslot(request: &AccumulateRequestV2) -> bool {
    matches!(
        request,
        AccumulateRequestV2::ExpireCall(_) | AccumulateRequestV2::RetireInbox(_)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefinedServiceOutputV2 {
    pub transition: TransitionV2,
    pub gas_used: u64,
    pub exported_blobs: Vec<ImportedBlobV2>,
    pub trace: Option<RefineTraceV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulatedServiceOutputV2 {
    pub result: AccumulationResultV2,
    pub gas_used: u64,
}

/// Proof package released by the service driver only after guest Accumulate
/// accepted the transition and committed its recoverable publication row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedAttestationOutputV2 {
    pub preparation: AttestationPreparationV2,
    pub proof: ProofCommitmentV2,
    pub proof_bytes: Vec<u8>,
    pub published: PublishedEffectsV2,
    pub prepare_gas_used: u64,
    pub accumulate_gas_used: u64,
}

impl CommittedAttestationOutputV2 {
    /// Build the durable reply input and its separately transported proof
    /// blob. This type can exist only after guest Accumulate committed, so a
    /// caller cannot observe a prepared or merely proved package.
    pub fn into_accumulated_reply(
        self,
    ) -> Result<(AccumulatedReplyV2, ImportedBlobV2), AttestationError> {
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
        let proof_blob = ImportedBlobV2 {
            reference: self.proof.proof_blob.clone(),
            bytes: self.proof_bytes,
        };
        let accumulated = AccumulatedReplyV2 {
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

struct ProvedAttestationV2 {
    envelope: AccumulationEnvelopeV2,
    preparation: AttestationPreparationV2,
    proof: ProofCommitmentV2,
    proof_bytes: Vec<u8>,
}

enum AttestationBuildErrorV2<P> {
    InvalidPreparation,
    Producer(P),
    InvalidProducedProof,
    ProofUnavailable,
}

#[derive(Debug)]
pub enum AttestedServiceErrorV2<E, P> {
    Service(E),
    Rejected(AccumulationRejectionV2),
    InvalidPreparation,
    Producer(P),
    InvalidProducedProof,
    ProofUnavailable,
    CommitMismatch,
}

impl<E: core::fmt::Debug, P: core::fmt::Debug> core::fmt::Display for AttestedServiceErrorV2<E, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "attested VOS v2 accumulation failed: {self:?}")
    }
}

impl<E: core::fmt::Debug, P: core::fmt::Debug> core::error::Error for AttestedServiceErrorV2<E, P> {}

/// One canonical Accumulate request whose Raft log position is committed.
/// Time-dependent entries carry the consensus JAM slot observed by the
/// proposer so every follower replays the identical IC-5 ambient input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedAccumulateEntryV2 {
    pub index: u64,
    pub request: Vec<u8>,
    pub logical_timeslot: Option<u64>,
    /// Canonical content bytes required to make this entry independently
    /// replayable on a replica with an empty node-local cache.
    pub availability_programs: Vec<ImportedProgramV2>,
    pub availability_blobs: Vec<ImportedBlobV2>,
    /// Exact positive receipt-verifier decisions ordered beside this request.
    /// Authority ingress and awaited-reply consumption each bind one external
    /// receipt. Durable delivery binds its source receipt plus the authority
    /// assertion receipt when destination authorization is required. CRDT
    /// synchronization binds one decision per distinct causal-node receipt;
    /// requests without an external receipt carry an empty list.
    pub receipt_verifications: Vec<ReceiptVerificationRequestV2>,
}

impl CommittedAccumulateEntryV2 {
    pub(crate) fn validate_availability(
        request: &AccumulateRequestV2,
        programs: &[ImportedProgramV2],
        blobs: &[ImportedBlobV2],
    ) -> Result<(), DecodeError> {
        validate_accumulate_availability(request, programs, blobs)
    }

    pub(crate) fn validate_receipt_verifications(
        request: &AccumulateRequestV2,
        verifications: &[ReceiptVerificationRequestV2],
    ) -> Result<(), DecodeError> {
        validate_receipt_verifications(request, verifications, false)
    }

    pub(crate) fn validate_replicated_receipt_verifications(
        request: &AccumulateRequestV2,
        verifications: &[ReceiptVerificationRequestV2],
    ) -> Result<(), DecodeError> {
        validate_receipt_verifications(request, verifications, true)
    }
}

/// Committed application entries after one replica's apply cursor. Raft may
/// have committed configuration/no-op entries between these indices, so the
/// authoritative `committed_index` is carried separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedAccumulateBatchV2 {
    pub entries: Vec<CommittedAccumulateEntryV2>,
    pub committed_index: u64,
}

/// Exact physical service image represented by one compacted Raft prefix.
/// The image remains the canonical `LocalJamStoreSnapshotV2` wire; this
/// envelope binds it to the log position advertised by InstallSnapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedProofArtifactV2 {
    /// Exact public inputs which the receiving replica must independently
    /// verify before making `bytes` durable or installing the service image.
    pub verification: ProofVerificationRequestV2,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedServiceSnapshotV2 {
    pub applied_index: u64,
    pub service_image: Vec<u8>,
    /// Proof artifacts required by pending publications remain outside the
    /// service image, but must become durable before this snapshot cursor is
    /// installed on another replica. Completed reply admissions do not retain
    /// proof bytes because duplicate routing resolves from the admission row.
    pub proof_artifacts: Vec<CommittedProofArtifactV2>,
}

impl V2Wire for CommittedServiceSnapshotV2 {
    const MAGIC: [u8; 4] = *b"VRS3";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.u64(self.applied_index);
        encoder.bytes(&self.service_image);
        encoder.list(&self.proof_artifacts, |encoder, artifact| {
            encoder.bytes(&artifact.verification.encode());
            encoder.bytes(&artifact.bytes);
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let applied_index = decoder.u64()?;
        let service_image = decoder.bytes()?;
        let proof_artifacts = decoder.list(|decoder| {
            Ok(CommittedProofArtifactV2 {
                verification: ProofVerificationRequestV2::decode(&decoder.bytes()?)?,
                bytes: decoder.bytes()?,
            })
        })?;
        let service_snapshot = LocalJamStoreSnapshotV2::decode(&service_image)?;
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
        Ok(Self {
            applied_index,
            service_image,
            proof_artifacts,
        })
    }
}

/// Raft boundary for the v2 service state machine.
///
/// Implementations order the exact canonical request and its optional trusted
/// JAM-slot provenance, and return from `propose_at` only after the named entry
/// is quorum committed. They never apply actor state themselves: leaders and
/// followers pass every returned entry to the same physical service PVM before
/// advancing `applied_index`.
pub trait CommittedAccumulateLogV2 {
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
        programs: &[ImportedProgramV2],
        blobs: &[ImportedBlobV2],
        receipt_verifications: &[ReceiptVerificationRequestV2],
    ) -> Result<CommittedAccumulateEntryV2, Self::Error>;

    fn propose_at(
        &mut self,
        request: &[u8],
        logical_timeslot: Option<u64>,
    ) -> Result<CommittedAccumulateEntryV2, Self::Error> {
        self.propose_at_with_availability(request, logical_timeslot, &[], &[], &[])
    }

    fn propose(&mut self, request: &[u8]) -> Result<CommittedAccumulateEntryV2, Self::Error> {
        self.propose_at(request, None)
    }

    fn committed_after(
        &mut self,
        applied_index: u64,
    ) -> Result<CommittedAccumulateBatchV2, Self::Error>;

    fn applied_index(&mut self) -> Result<u64, Self::Error>;

    /// Return a Raft-installed service snapshot newer than the local physical
    /// service image. Logs without compaction may keep the default.
    fn installed_snapshot_after(
        &mut self,
        _applied_index: u64,
    ) -> Result<Option<CommittedServiceSnapshotV2>, Self::Error> {
        Ok(None)
    }

    /// Persist only after the service image for every application entry at or
    /// below `index` has committed locally. Replaying after a failed cursor
    /// write is safe because guest Accumulate deduplicates exact inputs.
    fn mark_applied(
        &mut self,
        index: u64,
        service_image: &[u8],
        proof_artifacts: &[CommittedProofArtifactV2],
    ) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceDispatchError {
    Pvm(ServicePvmErrorV2),
    ServiceProgramMismatch {
        expected: ProgramId,
        declared: ProgramId,
    },
    ServiceGasScheduleMismatch {
        expected: GasScheduleV2,
        declared: GasScheduleV2,
    },
    InvalidGasSchedule(GasScheduleV2),
    InvalidRefineOutput,
    InvalidAccumulateOutput,
    InvalidAvailabilityArtifacts,
}

impl ServiceDispatchError {
    /// Whether replaying the same committed request against the same service
    /// program and gas schedule must reproduce this failure. This is an
    /// explicit allowlist: new host/JAR failure variants remain retryable until
    /// their determinism is proved. A deterministic guest failure is an
    /// ordered no-op; local allocation, JIT, host, and durable-commit failures
    /// leave the apply cursor untouched.
    fn is_deterministic_accumulate_failure(&self) -> bool {
        match self {
            Self::Pvm(error) => matches!(
                error,
                ServicePvmErrorV2::InvalidProgram
                    | ServicePvmErrorV2::Panic { .. }
                    | ServicePvmErrorV2::OutOfGas { .. }
                    | ServicePvmErrorV2::PageFault { .. }
                    | ServicePvmErrorV2::UnreadableOutput
                    | ServicePvmErrorV2::InvalidAccumulateOutput
                    | ServicePvmErrorV2::InvalidProtocolResume
                    | ServicePvmErrorV2::InvalidVmLifecycle
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
            ServiceDispatchError::Pvm(ServicePvmErrorV2::OutOfGas { vm: 0, pc: 5 })
                .is_deterministic_accumulate_failure()
        );
        assert!(
            !ServiceDispatchError::Pvm(ServicePvmErrorV2::KernelResourceUnavailable)
                .is_deterministic_accumulate_failure()
        );
        assert!(
            !ServiceDispatchError::Pvm(ServicePvmErrorV2::AccumulateHostRejected(123))
                .is_deterministic_accumulate_failure()
        );
        assert!(
            !ServiceDispatchError::Pvm(ServicePvmErrorV2::AccumulateCommitRejected)
                .is_deterministic_accumulate_failure()
        );
        assert!(
            !ServiceDispatchError::ServiceGasScheduleMismatch {
                expected: GasScheduleV2::new(1, 2),
                declared: GasScheduleV2::new(1, 3),
            }
            .is_deterministic_accumulate_failure(),
            "a replica configured with a different gas schedule must stop before advancing"
        );
    }
}

#[derive(Debug)]
pub enum ReplicatedServiceErrorV2<E> {
    Dispatch(ServiceDispatchError),
    Log(E),
    ServiceImage(ServiceImageInstallErrorV2),
    ProofUnavailable,
    ReceiptUnavailable,
    LogicalTimeslotRequired,
    UnexpectedLogicalTimeslot,
    InvalidCommittedLog,
}

impl<E: core::fmt::Debug> core::fmt::Display for ReplicatedServiceErrorV2<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "replicated VOS v2 service failed: {self:?}")
    }
}

impl<E: core::fmt::Debug> core::error::Error for ReplicatedServiceErrorV2<E> {}

impl core::fmt::Display for ServiceDispatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VOS service dispatch failed: {self:?}")
    }
}

impl core::error::Error for ServiceDispatchError {}

/// Drives the canonical service PVM in a local node or conformance test.
/// `R` is immutable Refine import plumbing; `A` owns the atomic Accumulate
/// transaction. Neither is allowed to implement actor semantics.
pub struct JamServiceV2<R, A> {
    pvm: ServicePvmV2,
    refine_host: R,
    accumulate_host: A,
    gas_schedule: GasScheduleV2,
}

/// Raft orchestration around the canonical generic service PVM.
///
/// The log owns ordering only. It contains `AccumulateRequestV2` bytes plus the
/// trusted JAM slot required by time-dependent requests, rather than
/// `EffectLog` commands or leader-produced state snapshots. Consequently
/// failover and follower catch-up execute guest validation, deduplication, and
/// storage mutation through the identical IC-5 entry used by the leader.
pub struct ReplicatedJamServiceV2<R, A, L> {
    service: JamServiceV2<R, A>,
    log: L,
}

impl<R, A> JamServiceV2<R, A> {
    pub fn new(
        canonical_service_pvm: Vec<u8>,
        expected_program: ProgramId,
        refine_host: R,
        accumulate_host: A,
        refine_gas: u64,
        accumulate_gas: u64,
    ) -> Result<Self, ServiceDispatchError> {
        let gas_schedule = GasScheduleV2::new(refine_gas, accumulate_gas);
        if !gas_schedule.is_valid() {
            return Err(ServiceDispatchError::InvalidGasSchedule(gas_schedule));
        }
        let pvm = ServicePvmV2::new(canonical_service_pvm, expected_program)
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

    pub const fn gas_schedule(&self) -> GasScheduleV2 {
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

impl<R, A, L> ReplicatedJamServiceV2<R, A, L> {
    pub const fn new(service: JamServiceV2<R, A>, log: L) -> Self {
        Self { service, log }
    }

    pub fn service(&self) -> &JamServiceV2<R, A> {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut JamServiceV2<R, A> {
        &mut self.service
    }

    pub fn log(&self) -> &L {
        &self.log
    }

    pub fn log_mut(&mut self) -> &mut L {
        &mut self.log
    }

    pub fn into_parts(self) -> (JamServiceV2<R, A>, L) {
        (self.service, self.log)
    }
}

impl<R: RefineProtocolHostV2, A: AccumulateProtocolHostV2> JamServiceV2<R, A> {
    pub fn refine_actor_tree(
        &self,
        work: &WorkEnvelopeV2,
        imports: &RefineImportsV2,
    ) -> Result<RefinedServiceOutputV2, ServiceDispatchError> {
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
        work: &WorkEnvelopeV2,
        imports: &RefineImportsV2,
    ) -> Result<RefinedServiceOutputV2, ServiceDispatchError> {
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
        request: &AccumulateRequestV2,
    ) -> Result<AccumulatedServiceOutputV2, ServiceDispatchError> {
        self.validate_service_identity(request.service())?;
        let output = self
            .pvm
            .accumulate(
                &request.encode(),
                self.gas_schedule.accumulate,
                &mut self.accumulate_host,
            )
            .map_err(ServiceDispatchError::Pvm)?;
        let result = AccumulationResultV2::decode(&output.bytes)
            .map_err(|_| ServiceDispatchError::InvalidAccumulateOutput)?;
        Ok(AccumulatedServiceOutputV2 {
            result,
            gas_used: output.gas_used,
        })
    }

    pub fn accumulate_with_availability(
        &mut self,
        request: &AccumulateRequestV2,
        programs: &[ImportedProgramV2],
        blobs: &[ImportedBlobV2],
    ) -> Result<AccumulatedServiceOutputV2, ServiceDispatchError> {
        self.validate_service_identity(request.service())?;
        validate_accumulate_availability(request, programs, blobs)
            .map_err(|_| ServiceDispatchError::InvalidAvailabilityArtifacts)?;
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
        let result = AccumulationResultV2::decode(&output.bytes)
            .map_err(|_| ServiceDispatchError::InvalidAccumulateOutput)?;
        Ok(AccumulatedServiceOutputV2 {
            result,
            gas_used: output.gas_used,
        })
    }

    /// Accumulate a time-dependent request against a consensus-authenticated
    /// JAM logical timeslot. Ordinary requests should use [`Self::accumulate`].
    pub fn accumulate_at(
        &mut self,
        request: &AccumulateRequestV2,
        logical_timeslot: u64,
    ) -> Result<AccumulatedServiceOutputV2, ServiceDispatchError> {
        self.accumulate_at_with_availability(request, logical_timeslot, &[], &[])
    }

    pub fn accumulate_at_with_availability(
        &mut self,
        request: &AccumulateRequestV2,
        logical_timeslot: u64,
        programs: &[ImportedProgramV2],
        blobs: &[ImportedBlobV2],
    ) -> Result<AccumulatedServiceOutputV2, ServiceDispatchError> {
        self.validate_service_identity(request.service())?;
        validate_accumulate_availability(request, programs, blobs)
            .map_err(|_| ServiceDispatchError::InvalidAvailabilityArtifacts)?;
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
        let result = AccumulationResultV2::decode(&output.bytes)
            .map_err(|_| ServiceDispatchError::InvalidAccumulateOutput)?;
        Ok(AccumulatedServiceOutputV2 {
            result,
            gas_used: output.gas_used,
        })
    }

    fn validate_service_identity(
        &self,
        declared: &ServiceIdentityV2,
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
    output: ServicePvmOutputV2,
) -> Result<RefinedServiceOutputV2, ServiceDispatchError> {
    let refined = RefineOutputV2::decode(&output.bytes)
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
    Ok(RefinedServiceOutputV2 {
        transition: refined.transition,
        gas_used: output.gas_used,
        exported_blobs,
        trace: output.trace,
    })
}

impl<R, A> JamServiceV2<R, A>
where
    R: RefineProtocolHostV2,
    A: AccumulateProtocolHostV2 + AttestationProofHostV2,
{
    /// Prepare, prove, and commit one single-slice attested transition.
    ///
    /// The proof producer receives the exact service scheduler PVM, canonical
    /// actor imports, and guest-derived statement. Apply is not invoked until
    /// a non-empty proof is available; the returned package is constructed
    /// only from a successful non-duplicate guest commit.
    pub fn accumulate_attested<P: AttestationProofProducerV2 + ?Sized>(
        &mut self,
        envelope: AccumulationEnvelopeV2,
        imports: &RefineImportsV2,
        producer: &mut P,
    ) -> Result<CommittedAttestationOutputV2, AttestedServiceErrorV2<ServiceDispatchError, P::Error>>
    {
        let prepared = self
            .accumulate(&AccumulateRequestV2::PrepareAttested(envelope.clone()))
            .map_err(AttestedServiceErrorV2::Service)?;
        let preparation = match prepared.result {
            AccumulationResultV2::Prepared(preparation) => preparation,
            AccumulationResultV2::Rejected(rejection) => {
                return Err(AttestedServiceErrorV2::Rejected(rejection));
            }
            _ => return Err(AttestedServiceErrorV2::InvalidPreparation),
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
            .accumulate(&AccumulateRequestV2::Apply(proved.envelope.clone()))
            .map_err(AttestedServiceErrorV2::Service)?;
        finish_committed_attestation(proved, prepared.gas_used, committed)
    }

    fn prove_prepared_attestation<P: AttestationProofProducerV2 + ?Sized>(
        &mut self,
        mut envelope: AccumulationEnvelopeV2,
        imports: &RefineImportsV2,
        preparation: AttestationPreparationV2,
        producer: &mut P,
    ) -> Result<ProvedAttestationV2, AttestationBuildErrorV2<P::Error>> {
        let replay = self
            .refine_actor_tree_traced(&envelope.work, imports)
            .map_err(|_| AttestationBuildErrorV2::InvalidPreparation)?;
        if replay.transition != envelope.transition
            || replay.exported_blobs != envelope.provided_blobs
        {
            return Err(AttestationBuildErrorV2::InvalidPreparation);
        }
        let refine_trace = replay
            .trace
            .as_ref()
            .ok_or(AttestationBuildErrorV2::InvalidPreparation)?
            .commitment;
        let produced = {
            let request = AttestationProofRequestV2 {
                canonical_service_pvm: self.pvm.canonical_pvm(),
                work: &envelope.work,
                imports,
                transition: &envelope.transition,
                preparation: &preparation,
                refine_trace,
            };
            request
                .validate()
                .map_err(|_| AttestationBuildErrorV2::InvalidPreparation)?;
            producer
                .prove(&request)
                .map_err(AttestationBuildErrorV2::Producer)?
        };
        produced
            .validate_for(refine_trace)
            .map_err(|_| AttestationBuildErrorV2::InvalidProducedProof)?;

        let proof_blob = super::BlobRefV2::of_bytes(&produced.proof);
        let proof = ProofCommitmentV2 {
            statement: preparation.statement.commitment(),
            trace: produced.trace,
            proof_blob: proof_blob.clone(),
            statement_version: super::ATTESTATION_STATEMENT_VERSION,
        };
        let verification = ProofVerificationRequestV2 {
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
            return Err(AttestationBuildErrorV2::ProofUnavailable);
        }
        envelope.transition.proof = Some(proof.clone());
        let imported = ImportedBlobV2 {
            reference: proof_blob,
            bytes: produced.proof.clone(),
        };
        match envelope
            .provided_blobs
            .binary_search_by_key(&imported.reference.hash, |blob| blob.reference.hash)
        {
            Ok(index) if envelope.provided_blobs[index] == imported => {}
            Ok(_) => return Err(AttestationBuildErrorV2::InvalidProducedProof),
            Err(index) => envelope.provided_blobs.insert(index, imported),
        }

        Ok(ProvedAttestationV2 {
            envelope,
            preparation,
            proof,
            proof_bytes: produced.proof,
        })
    }

    fn recover_prepared_attestation<E, P: AttestationProofProducerV2 + ?Sized>(
        &mut self,
        envelope: AccumulationEnvelopeV2,
        imports: &RefineImportsV2,
        preparation: AttestationPreparationV2,
        producer: &mut P,
        prepare_gas_used: u64,
    ) -> Result<CommittedAttestationOutputV2, AttestedServiceErrorV2<E, P::Error>> {
        let proof = preparation
            .committed_proof
            .clone()
            .ok_or(AttestedServiceErrorV2::InvalidPreparation)?;
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
                return Err(AttestedServiceErrorV2::CommitMismatch);
            }
            reproduced.proof_bytes
        };
        if !proof.proof_blob.matches(&proof_bytes) {
            return Err(AttestedServiceErrorV2::CommitMismatch);
        }
        let published = PublishedEffectsV2 {
            reply: envelope.transition.reply,
            outbox: envelope.transition.outbox,
            exported_blobs: envelope.transition.exported_blobs,
            proof: Some(proof.clone()),
            attestation: Some(Box::new(AttestationDeliveryV2 {
                producer_name: preparation.statement.producer_name.clone(),
                producer: preparation.statement.producer,
                statement: preparation.statement.clone(),
                proof: proof.clone(),
            })),
        };
        validate_committed_attestation(&preparation, &proof, &preparation.receipt, &published)?;
        Ok(CommittedAttestationOutputV2 {
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
    error: AttestationBuildErrorV2<P>,
) -> AttestedServiceErrorV2<E, P> {
    match error {
        AttestationBuildErrorV2::InvalidPreparation => AttestedServiceErrorV2::InvalidPreparation,
        AttestationBuildErrorV2::Producer(error) => AttestedServiceErrorV2::Producer(error),
        AttestationBuildErrorV2::InvalidProducedProof => {
            AttestedServiceErrorV2::InvalidProducedProof
        }
        AttestationBuildErrorV2::ProofUnavailable => AttestedServiceErrorV2::ProofUnavailable,
    }
}

fn finish_committed_attestation<E, P>(
    mut proved: ProvedAttestationV2,
    prepare_gas_used: u64,
    committed: AccumulatedServiceOutputV2,
) -> Result<CommittedAttestationOutputV2, AttestedServiceErrorV2<E, P>> {
    let (receipt, published) = match committed.result {
        AccumulationResultV2::Accepted {
            receipt,
            published,
            duplicate: false,
        } => (receipt, published),
        AccumulationResultV2::Rejected(rejection) => {
            return Err(AttestedServiceErrorV2::Rejected(rejection));
        }
        _ => return Err(AttestedServiceErrorV2::CommitMismatch),
    };
    validate_committed_attestation(&proved.preparation, &proved.proof, &receipt, &published)?;
    proved.preparation.committed_proof = Some(proved.proof.clone());
    Ok(CommittedAttestationOutputV2 {
        preparation: proved.preparation,
        proof: proved.proof,
        proof_bytes: proved.proof_bytes,
        published,
        prepare_gas_used,
        accumulate_gas_used: committed.gas_used,
    })
}

fn validate_committed_attestation<E, P>(
    preparation: &AttestationPreparationV2,
    proof: &ProofCommitmentV2,
    committed_receipt: &AccumulationReceiptV2,
    published: &PublishedEffectsV2,
) -> Result<(), AttestedServiceErrorV2<E, P>> {
    let Some(reply) = published.reply.as_ref() else {
        return Err(AttestedServiceErrorV2::CommitMismatch);
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
            != super::Hash::digest(b"vos/attestation-claim/v3", &[&reply.result])
    {
        return Err(AttestedServiceErrorV2::CommitMismatch);
    }
    Ok(())
}

impl<R, A, L> ReplicatedJamServiceV2<R, A, L>
where
    R: RefineProtocolHostV2,
    A: AccumulateProtocolHostV2
        + AttestationProofHostV2
        + CommittedServiceImageHostV2
        + ReceiptVerificationHostV2,
    L: CommittedAccumulateLogV2,
{
    fn validate_service_image_identity(
        &self,
        service_image: &[u8],
    ) -> Result<(), ReplicatedServiceErrorV2<L::Error>> {
        let snapshot = LocalJamStoreSnapshotV2::decode(service_image).map_err(|_| {
            ReplicatedServiceErrorV2::ServiceImage(ServiceImageInstallErrorV2::InvalidSnapshot)
        })?;
        if let Some(identity) = snapshot.service_identity().map_err(|_| {
            ReplicatedServiceErrorV2::ServiceImage(ServiceImageInstallErrorV2::InvalidSnapshot)
        })? {
            self.service
                .validate_service_identity(&identity)
                .map_err(ReplicatedServiceErrorV2::Dispatch)?;
        }
        Ok(())
    }

    fn apply_committed_after(
        &mut self,
        applied: u64,
        capture: Option<&CommittedAccumulateEntryV2>,
    ) -> Result<(usize, Option<AccumulatedServiceOutputV2>), ReplicatedServiceErrorV2<L::Error>>
    {
        let batch = self
            .log
            .committed_after(applied)
            .map_err(ReplicatedServiceErrorV2::Log)?;
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
            return Err(ReplicatedServiceErrorV2::InvalidCommittedLog);
        }

        let mut applied_entries = 0;
        let mut cursor = applied;
        let mut captured = None;
        for entry in batch.entries {
            let is_captured = capture.is_some_and(|target| target.index == entry.index);
            if is_captured
                && capture.is_some_and(|target| {
                    target.request.as_slice() != entry.request.as_slice()
                        || target.logical_timeslot != entry.logical_timeslot
                        || target.availability_programs != entry.availability_programs
                        || target.availability_blobs != entry.availability_blobs
                        || target.receipt_verifications != entry.receipt_verifications
                })
            {
                return Err(ReplicatedServiceErrorV2::InvalidCommittedLog);
            }
            let request = AccumulateRequestV2::decode(&entry.request)
                .map_err(|_| ReplicatedServiceErrorV2::InvalidCommittedLog)?;
            validate_accumulate_availability(
                &request,
                &entry.availability_programs,
                &entry.availability_blobs,
            )
            .map_err(|_| ReplicatedServiceErrorV2::InvalidCommittedLog)?;
            validate_receipt_verifications(&request, &entry.receipt_verifications, true)
                .map_err(|_| ReplicatedServiceErrorV2::InvalidCommittedLog)?;
            if requires_logical_timeslot(&request) != entry.logical_timeslot.is_some() {
                return Err(ReplicatedServiceErrorV2::InvalidCommittedLog);
            }
            // Proof hydration is a durable local precondition, not a guest
            // semantic decision. A failed side-CAS write must leave this entry
            // unapplied so exact catch-up can retry it.
            ensure_request_proof_available(self.service.accumulate_host_mut(), &request)
                .map_err(|_| ReplicatedServiceErrorV2::ProofUnavailable)?;
            ensure_request_receipts_available(
                self.service.accumulate_host_mut(),
                &entry.receipt_verifications,
            )
            .map_err(|_| ReplicatedServiceErrorV2::ReceiptUnavailable)?;
            let outcome = match entry.logical_timeslot {
                Some(logical_timeslot) => self.service.accumulate_at_with_availability(
                    &request,
                    logical_timeslot,
                    &entry.availability_programs,
                    &entry.availability_blobs,
                ),
                None => self.service.accumulate_with_availability(
                    &request,
                    &entry.availability_programs,
                    &entry.availability_blobs,
                ),
            };
            if let Err(error) = outcome.as_ref()
                && !error.is_deterministic_accumulate_failure()
            {
                return Err(ReplicatedServiceErrorV2::Dispatch(*error));
            }
            let service_image = self.service.accumulate_host().committed_service_image();
            let proof_artifacts =
                snapshot_proof_artifacts(self.service.accumulate_host(), &service_image)
                    .map_err(|_| ReplicatedServiceErrorV2::ProofUnavailable)?;
            self.log
                .mark_applied(entry.index, &service_image, &proof_artifacts)
                .map_err(ReplicatedServiceErrorV2::Log)?;
            let output = match outcome {
                Ok(output) => Some(output),
                Err(error) if is_captured => {
                    return Err(ReplicatedServiceErrorV2::Dispatch(error));
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
                    .map_err(|_| ReplicatedServiceErrorV2::ProofUnavailable)?;
            self.log
                .mark_applied(batch.committed_index, &service_image, &proof_artifacts)
                .map_err(ReplicatedServiceErrorV2::Log)?;
        }
        if capture.is_some() && captured.is_none() {
            return Err(ReplicatedServiceErrorV2::InvalidCommittedLog);
        }
        Ok((applied_entries, captured))
    }

    /// Apply every committed request not yet reflected in this replica's
    /// service image. Effects are recovered as guest-owned publication rows;
    /// followers never publish the returned execution output directly.
    pub fn catch_up(&mut self) -> Result<usize, ReplicatedServiceErrorV2<L::Error>> {
        let mut applied = self
            .log
            .applied_index()
            .map_err(ReplicatedServiceErrorV2::Log)?;
        if let Some(snapshot) = self
            .log
            .installed_snapshot_after(applied)
            .map_err(ReplicatedServiceErrorV2::Log)?
        {
            if snapshot.applied_index <= applied {
                return Err(ReplicatedServiceErrorV2::InvalidCommittedLog);
            }
            // Validate before hydrating the proof side-CAS, installing the
            // image, or advancing the applied cursor. A fresh host has no
            // existing header against which install can detect a mismatch.
            self.validate_service_image_identity(&snapshot.service_image)?;
            for artifact in &snapshot.proof_artifacts {
                if !self
                    .service
                    .accumulate_host_mut()
                    .make_proof_available(&artifact.verification, &artifact.bytes)
                {
                    return Err(ReplicatedServiceErrorV2::ProofUnavailable);
                }
            }
            self.service
                .accumulate_host_mut()
                .install_committed_service_image(&snapshot.service_image)
                .map_err(ReplicatedServiceErrorV2::ServiceImage)?;
            self.log
                .mark_applied(
                    snapshot.applied_index,
                    &snapshot.service_image,
                    &snapshot.proof_artifacts,
                )
                .map_err(ReplicatedServiceErrorV2::Log)?;
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
    ) -> Result<usize, ReplicatedServiceErrorV2<L::Error>> {
        let read_index = self
            .log
            .leader_read_index()
            .map_err(ReplicatedServiceErrorV2::Log)?;
        let applied_entries = self.catch_up()?;
        let applied = self
            .log
            .applied_index()
            .map_err(ReplicatedServiceErrorV2::Log)?;
        if applied < read_index {
            return Err(ReplicatedServiceErrorV2::InvalidCommittedLog);
        }
        Ok(applied_entries)
    }

    pub fn refine_actor_tree(
        &mut self,
        work: &WorkEnvelopeV2,
        imports: &RefineImportsV2,
    ) -> Result<RefinedServiceOutputV2, ReplicatedServiceErrorV2<L::Error>> {
        self.catch_up()?;
        self.service
            .refine_actor_tree(work, imports)
            .map_err(ReplicatedServiceErrorV2::Dispatch)
    }

    #[cfg(feature = "storage")]
    pub(crate) fn refine_actor_tree_after_barrier(
        &self,
        work: &WorkEnvelopeV2,
        imports: &RefineImportsV2,
    ) -> Result<RefinedServiceOutputV2, ReplicatedServiceErrorV2<L::Error>> {
        self.service
            .refine_actor_tree(work, imports)
            .map_err(ReplicatedServiceErrorV2::Dispatch)
    }

    /// Quorum-order one mutating request, then apply that committed entry via
    /// physical IC-5. Attestation preparation is deliberately read-only and
    /// executes against the caught-up local image without entering the log.
    pub fn accumulate(
        &mut self,
        request: &AccumulateRequestV2,
    ) -> Result<AccumulatedServiceOutputV2, ReplicatedServiceErrorV2<L::Error>> {
        self.accumulate_with_availability(request, &[], &[])
    }

    /// Quorum-order one request together with the exact content-addressed
    /// programs and blobs needed to execute it on an otherwise empty replica.
    pub fn accumulate_with_availability(
        &mut self,
        request: &AccumulateRequestV2,
        programs: &[ImportedProgramV2],
        blobs: &[ImportedBlobV2],
    ) -> Result<AccumulatedServiceOutputV2, ReplicatedServiceErrorV2<L::Error>> {
        self.accumulate_ordered(request, None, programs, blobs, &[])
    }

    /// Quorum-order a time-dependent request together with the
    /// consensus-authenticated JAM slot observed by the leader. The slot is
    /// part of the replicated entry and is replayed identically by followers.
    pub fn accumulate_at(
        &mut self,
        request: &AccumulateRequestV2,
        logical_timeslot: u64,
    ) -> Result<AccumulatedServiceOutputV2, ReplicatedServiceErrorV2<L::Error>> {
        self.accumulate_ordered(request, Some(logical_timeslot), &[], &[], &[])
    }

    fn accumulate_ordered(
        &mut self,
        request: &AccumulateRequestV2,
        logical_timeslot: Option<u64>,
        programs: &[ImportedProgramV2],
        blobs: &[ImportedBlobV2],
        receipt_verifications: &[ReceiptVerificationRequestV2],
    ) -> Result<AccumulatedServiceOutputV2, ReplicatedServiceErrorV2<L::Error>> {
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
        request: &AccumulateRequestV2,
        programs: &[ImportedProgramV2],
        blobs: &[ImportedBlobV2],
    ) -> Result<AccumulatedServiceOutputV2, ReplicatedServiceErrorV2<L::Error>> {
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
        request: &AccumulateRequestV2,
        receipt_verifications: &[ReceiptVerificationRequestV2],
    ) -> Result<AccumulatedServiceOutputV2, ReplicatedServiceErrorV2<L::Error>> {
        self.accumulate_ordered_after_barrier(request, None, &[], &[], receipt_verifications)
    }

    /// Quorum-order a slot-bound request after the caller has already
    /// established the current-term read barrier and caught up through it.
    #[cfg(feature = "storage")]
    pub(crate) fn accumulate_at_after_barrier(
        &mut self,
        request: &AccumulateRequestV2,
        logical_timeslot: u64,
    ) -> Result<AccumulatedServiceOutputV2, ReplicatedServiceErrorV2<L::Error>> {
        self.accumulate_ordered_after_barrier(request, Some(logical_timeslot), &[], &[], &[])
    }

    fn accumulate_ordered_after_barrier(
        &mut self,
        request: &AccumulateRequestV2,
        logical_timeslot: Option<u64>,
        programs: &[ImportedProgramV2],
        blobs: &[ImportedBlobV2],
        receipt_verifications: &[ReceiptVerificationRequestV2],
    ) -> Result<AccumulatedServiceOutputV2, ReplicatedServiceErrorV2<L::Error>> {
        self.service
            .validate_service_identity(request.service())
            .map_err(ReplicatedServiceErrorV2::Dispatch)?;
        validate_accumulate_availability(request, programs, blobs).map_err(|_| {
            ReplicatedServiceErrorV2::Dispatch(ServiceDispatchError::InvalidAvailabilityArtifacts)
        })?;
        validate_receipt_verifications(request, receipt_verifications, true).map_err(|_| {
            ReplicatedServiceErrorV2::Dispatch(ServiceDispatchError::InvalidAvailabilityArtifacts)
        })?;
        let time_dependent = requires_logical_timeslot(request);
        if time_dependent && logical_timeslot.is_none() {
            return Err(ReplicatedServiceErrorV2::LogicalTimeslotRequired);
        }
        if !time_dependent && logical_timeslot.is_some() {
            return Err(ReplicatedServiceErrorV2::UnexpectedLogicalTimeslot);
        }
        if matches!(request, AccumulateRequestV2::PrepareAttested(_)) {
            return self
                .service
                .accumulate_with_availability(request, programs, blobs)
                .map_err(ReplicatedServiceErrorV2::Dispatch);
        }
        ensure_request_proof_available(self.service.accumulate_host_mut(), request)
            .map_err(|_| ReplicatedServiceErrorV2::ProofUnavailable)?;

        let request_bytes = request.encode();
        let entry = self
            .log
            .propose_at_with_availability(
                &request_bytes,
                logical_timeslot,
                programs,
                blobs,
                receipt_verifications,
            )
            .map_err(ReplicatedServiceErrorV2::Log)?;
        let applied = self
            .log
            .applied_index()
            .map_err(ReplicatedServiceErrorV2::Log)?;
        if entry.index <= applied
            || entry.request != request_bytes
            || entry.logical_timeslot != logical_timeslot
            || entry.availability_programs.as_slice() != programs
            || entry.availability_blobs.as_slice() != blobs
            || entry.receipt_verifications.as_slice() != receipt_verifications
        {
            return Err(ReplicatedServiceErrorV2::InvalidCommittedLog);
        }
        self.apply_committed_after(applied, Some(&entry))?
            .1
            .ok_or(ReplicatedServiceErrorV2::InvalidCommittedLog)
    }

    /// Produce the proof before proposing the final Apply request. Only the
    /// proved Apply bytes enter Raft; read-only preparation never consumes a
    /// log position. Followers make the same proof artifact available before
    /// executing the committed request through physical IC-5.
    pub fn accumulate_attested<P: AttestationProofProducerV2 + ?Sized>(
        &mut self,
        envelope: AccumulationEnvelopeV2,
        imports: &RefineImportsV2,
        producer: &mut P,
    ) -> Result<
        CommittedAttestationOutputV2,
        AttestedServiceErrorV2<ReplicatedServiceErrorV2<L::Error>, P::Error>,
    > {
        let prepared = self
            .accumulate(&AccumulateRequestV2::PrepareAttested(envelope.clone()))
            .map_err(AttestedServiceErrorV2::Service)?;
        let preparation = match prepared.result {
            AccumulationResultV2::Prepared(preparation) => preparation,
            AccumulationResultV2::Rejected(rejection) => {
                return Err(AttestedServiceErrorV2::Rejected(rejection));
            }
            _ => return Err(AttestedServiceErrorV2::InvalidPreparation),
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
            .accumulate(&AccumulateRequestV2::Apply(proved.envelope.clone()))
            .map_err(AttestedServiceErrorV2::Service)?;
        finish_committed_attestation(proved, prepared.gas_used, committed)
    }

    /// Prepare and prove against a caller-established leadership barrier,
    /// then quorum-order the final proved Apply without another intervening
    /// catch-up. This is the attested counterpart of the other
    /// `*_after_barrier` entry points used by the root driver after allocating
    /// consensus-significant admission time.
    #[cfg(feature = "storage")]
    pub(crate) fn accumulate_attested_after_barrier<P: AttestationProofProducerV2 + ?Sized>(
        &mut self,
        envelope: AccumulationEnvelopeV2,
        imports: &RefineImportsV2,
        producer: &mut P,
    ) -> Result<
        CommittedAttestationOutputV2,
        AttestedServiceErrorV2<ReplicatedServiceErrorV2<L::Error>, P::Error>,
    > {
        let prepared = self
            .service
            .accumulate(&AccumulateRequestV2::PrepareAttested(envelope.clone()))
            .map_err(|error| {
                AttestedServiceErrorV2::Service(ReplicatedServiceErrorV2::Dispatch(error))
            })?;
        let preparation = match prepared.result {
            AccumulationResultV2::Prepared(preparation) => preparation,
            AccumulationResultV2::Rejected(rejection) => {
                return Err(AttestedServiceErrorV2::Rejected(rejection));
            }
            _ => return Err(AttestedServiceErrorV2::InvalidPreparation),
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
                &AccumulateRequestV2::Apply(proved.envelope.clone()),
                None,
                &[],
                &[],
                &[],
            )
            .map_err(AttestedServiceErrorV2::Service)?;
        finish_committed_attestation(proved, prepared.gas_used, committed)
    }
}

fn snapshot_proof_artifacts<A: AttestationProofHostV2>(
    host: &A,
    service_image: &[u8],
) -> Result<Vec<CommittedProofArtifactV2>, ()> {
    let snapshot = LocalJamStoreSnapshotV2::decode(service_image).map_err(|_| ())?;
    snapshot
        .referenced_proof_verifications()
        .map_err(|_| ())?
        .into_iter()
        .map(|verification| {
            let bytes = host.proof_bytes(&verification.proof_blob).ok_or(())?;
            if !verification.proof_blob.matches(&bytes) {
                return Err(());
            }
            Ok(CommittedProofArtifactV2 {
                verification,
                bytes,
            })
        })
        .collect()
}

fn ensure_request_proof_available<A: AttestationProofHostV2>(
    host: &mut A,
    request: &AccumulateRequestV2,
) -> Result<(), ()> {
    let AccumulateRequestV2::Apply(envelope) = request else {
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
    let verification = ProofVerificationRequestV2 {
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

fn ensure_request_receipts_available<A: ReceiptVerificationHostV2>(
    host: &mut A,
    verifications: &[ReceiptVerificationRequestV2],
) -> Result<(), ()> {
    for verification in verifications {
        if !host.make_receipt_available(verification) {
            return Err(());
        }
    }
    Ok(())
}
