//! Local conformance harness for the protocol-pinned generic service PVM.
//!
//! There is deliberately no native Refine implementation and no native
//! transition-apply shortcut here. Both paths execute the same canonical PVM
//! that deployment installs; the host supplies only imports and an atomic JAM
//! storage transaction boundary.

use alloc::boxed::Box;
use alloc::{string::String, vec::Vec};

use crate::attestation::{
    Attestation, AttestationError, AttestationPreparationV2, AttestationProofHostV2,
    AttestationProofProducerV2, AttestationProofRequestV2, AttestedMethod,
};

use super::wire::{DecodeError, Decoder, Encoder};
use super::{
    AccumulateProtocolHostV2, AccumulateRequestV2, AccumulatedReplyV2, AccumulationEnvelopeV2,
    AccumulationReceiptV2, AccumulationRejectionV2, AccumulationResultV2, AttestationDeliveryV2,
    CommittedServiceImageHostV2, ImportedBlobV2, LocalJamStoreSnapshotV2, ProducerId, ProgramId,
    ProofCommitmentV2, ProofVerificationRequestV2, PublishedEffectsV2, RefineImportsV2,
    RefineOutputV2, RefineProtocolHostV2, RefineTraceV2, ServiceImageInstallErrorV2,
    ServicePvmErrorV2, ServicePvmOutputV2, ServicePvmV2, TransitionV2, V2Wire, WorkEnvelopeV2,
};

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
        producer_name: String,
        producer: ProducerId,
    ) -> Result<(AccumulatedReplyV2, ImportedBlobV2), AttestationError> {
        let reply = self
            .published
            .reply
            .ok_or(AttestationError::InvalidStatement)?;
        if self.published.proof.as_ref() != Some(&self.proof)
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
            attestation: Some(Box::new(AttestationDeliveryV2 {
                producer_name,
                producer,
                statement: self.preparation.statement,
                proof: self.proof,
            })),
        };
        accumulated.validate()?;
        Ok((accumulated, proof_blob))
    }

    /// Produce the transport record consumed by macro-generated attested
    /// handles. Only the reply published by successful guest Accumulate is
    /// decoded; prepare/proof output alone cannot construct this record.
    pub fn into_invocation_result(
        self,
        producer_name: String,
        producer: ProducerId,
    ) -> Result<crate::actors::client::AttestedInvocationResult, AttestationError> {
        let reply = self
            .published
            .reply
            .ok_or(AttestationError::InvalidStatement)?;
        let value = <crate::value::Value as crate::Decode>::try_decode(&reply.result)
            .ok_or(AttestationError::InvalidStatement)?;
        Ok(crate::actors::client::AttestedInvocationResult {
            value,
            producer_name,
            producer,
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
        producer_name: String,
        producer: ProducerId,
        preview: T,
    ) -> Result<Attestation<T, M>, AttestationError> {
        Attestation::__from_runtime(
            producer_name,
            producer,
            self.preparation.statement,
            self.proof.trace,
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
    Attestation(AttestationError),
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

fn require_single_slice_attestation<E, P>(
    envelope: &AccumulationEnvelopeV2,
) -> Result<(), AttestedServiceErrorV2<E, P>> {
    if !envelope.transition.continuations.is_empty()
        || !envelope.transition.outbox.is_empty()
        || envelope.transition.reply.is_none()
    {
        return Err(AttestedServiceErrorV2::Attestation(
            AttestationError::CannotSuspend,
        ));
    }
    Ok(())
}

/// One canonical Accumulate request whose Raft log position is committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedAccumulateEntryV2 {
    pub index: u64,
    pub request: Vec<u8>,
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
pub struct CommittedServiceSnapshotV2 {
    pub applied_index: u64,
    pub service_image: Vec<u8>,
}

impl V2Wire for CommittedServiceSnapshotV2 {
    const MAGIC: [u8; 4] = *b"VRS2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.u64(self.applied_index);
        encoder.bytes(&self.service_image);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let applied_index = decoder.u64()?;
        let service_image = decoder.bytes()?;
        if applied_index == 0 || LocalJamStoreSnapshotV2::decode(&service_image).is_err() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(Self {
            applied_index,
            service_image,
        })
    }
}

/// Raft boundary for the v2 service state machine.
///
/// Implementations order the exact canonical request bytes and return from
/// `propose` only after the named entry is quorum committed. They never apply
/// actor state themselves: leaders and followers pass every returned entry to
/// the same physical service PVM before advancing `applied_index`.
pub trait CommittedAccumulateLogV2 {
    type Error;

    fn propose(&mut self, request: &[u8]) -> Result<CommittedAccumulateEntryV2, Self::Error>;

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
    fn mark_applied(&mut self, index: u64, service_image: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceDispatchError {
    Pvm(ServicePvmErrorV2),
    InvalidRefineOutput,
    InvalidAccumulateOutput,
}

#[derive(Debug)]
pub enum ReplicatedServiceErrorV2<E> {
    Dispatch(ServiceDispatchError),
    Log(E),
    ServiceImage(ServiceImageInstallErrorV2),
    ProofUnavailable,
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
    refine_gas: u64,
    accumulate_gas: u64,
}

/// Raft orchestration around the canonical generic service PVM.
///
/// The log owns ordering only. It contains `AccumulateRequestV2` bytes rather
/// than `EffectLog` commands or leader-produced state snapshots. Consequently
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
        let pvm = ServicePvmV2::new(canonical_service_pvm, expected_program)
            .map_err(ServiceDispatchError::Pvm)?;
        Ok(Self {
            pvm,
            refine_host,
            accumulate_host,
            refine_gas,
            accumulate_gas,
        })
    }

    pub const fn program_id(&self) -> ProgramId {
        self.pvm.program_id()
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
        let output = self
            .pvm
            .refine_actor_tree(&work.encode(), imports, self.refine_gas, &self.refine_host)
            .map_err(ServiceDispatchError::Pvm)?;
        decode_refined_service_output(output)
    }

    fn refine_actor_tree_traced(
        &self,
        work: &WorkEnvelopeV2,
        imports: &RefineImportsV2,
    ) -> Result<RefinedServiceOutputV2, ServiceDispatchError> {
        let output = self
            .pvm
            .refine_actor_tree_traced(&work.encode(), imports, self.refine_gas, &self.refine_host)
            .map_err(ServiceDispatchError::Pvm)?;
        decode_refined_service_output(output)
    }

    pub fn accumulate(
        &mut self,
        request: &AccumulateRequestV2,
    ) -> Result<AccumulatedServiceOutputV2, ServiceDispatchError> {
        let output = self
            .pvm
            .accumulate(
                &request.encode(),
                self.accumulate_gas,
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
    pub fn accumulate_attested<P: AttestationProofProducerV2>(
        &mut self,
        envelope: AccumulationEnvelopeV2,
        imports: &RefineImportsV2,
        producer: &mut P,
    ) -> Result<CommittedAttestationOutputV2, AttestedServiceErrorV2<ServiceDispatchError, P::Error>>
    {
        // Reject a multi-slice attested execution before proof construction or
        // any Accumulate call. Inline nested actors leave no continuation or
        // durable outbox and therefore remain valid single-slice proofs.
        require_single_slice_attestation(&envelope)?;
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

        let proved = self
            .prove_prepared_attestation(envelope, imports, preparation, producer)
            .map_err(map_attestation_build_error)?;
        let committed = self
            .accumulate(&AccumulateRequestV2::Apply(proved.envelope.clone()))
            .map_err(AttestedServiceErrorV2::Service)?;
        finish_committed_attestation(proved, prepared.gas_used, committed)
    }

    fn prove_prepared_attestation<P: AttestationProofProducerV2>(
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
            .ok_or(AttestationBuildErrorV2::InvalidPreparation)?;
        let canonical_actor_pvm = imports
            .programs
            .binary_search_by_key(&envelope.work.target_program, |program| program.program)
            .ok()
            .map(|index| imports.programs[index].pvm.as_slice())
            .ok_or(AttestationBuildErrorV2::InvalidPreparation)?;
        let produced = {
            let request = AttestationProofRequestV2 {
                canonical_service_pvm: self.pvm.canonical_pvm(),
                canonical_actor_pvm,
                work: &envelope.work,
                imports,
                transition: &envelope.transition,
                preparation: &preparation,
                refine_trace: refine_trace.commitment,
                refine_instruction_count: refine_trace.instruction_count,
                refine_protocol_call_count: refine_trace.protocol_call_count,
                refine_vm_switch_count: refine_trace.vm_switch_count,
                refine_code_hashes: &refine_trace.code_hashes,
            };
            request
                .validate()
                .map_err(|_| AttestationBuildErrorV2::InvalidPreparation)?;
            producer
                .prove(&request)
                .map_err(AttestationBuildErrorV2::Producer)?
        };
        produced
            .validate_for(refine_trace.commitment)
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
    proved: ProvedAttestationV2,
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
        || published.statement.as_ref() != Some(&preparation.statement)
        || published.proof.as_ref() != Some(proof)
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
    A: AccumulateProtocolHostV2 + AttestationProofHostV2 + CommittedServiceImageHostV2,
    L: CommittedAccumulateLogV2,
{
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
            self.service
                .accumulate_host_mut()
                .install_committed_service_image(&snapshot.service_image)
                .map_err(ReplicatedServiceErrorV2::ServiceImage)?;
            self.log
                .mark_applied(snapshot.applied_index, &snapshot.service_image)
                .map_err(ReplicatedServiceErrorV2::Log)?;
            applied = snapshot.applied_index;
        }
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
        for entry in batch.entries {
            let request = AccumulateRequestV2::decode(&entry.request)
                .map_err(|_| ReplicatedServiceErrorV2::InvalidCommittedLog)?;
            ensure_request_proof_available(self.service.accumulate_host_mut(), &request)
                .map_err(|_| ReplicatedServiceErrorV2::ProofUnavailable)?;
            self.service
                .accumulate(&request)
                .map_err(ReplicatedServiceErrorV2::Dispatch)?;
            let service_image = self.service.accumulate_host().committed_service_image();
            self.log
                .mark_applied(entry.index, &service_image)
                .map_err(ReplicatedServiceErrorV2::Log)?;
            cursor = entry.index;
            applied_entries += 1;
        }
        if batch.committed_index > cursor {
            let service_image = self.service.accumulate_host().committed_service_image();
            self.log
                .mark_applied(batch.committed_index, &service_image)
                .map_err(ReplicatedServiceErrorV2::Log)?;
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

    /// Quorum-order one mutating request, then apply that committed entry via
    /// physical IC-5. Attestation preparation is deliberately read-only and
    /// executes against the caught-up local image without entering the log.
    pub fn accumulate(
        &mut self,
        request: &AccumulateRequestV2,
    ) -> Result<AccumulatedServiceOutputV2, ReplicatedServiceErrorV2<L::Error>> {
        self.catch_up()?;
        if matches!(request, AccumulateRequestV2::PrepareAttested(_)) {
            return self
                .service
                .accumulate(request)
                .map_err(ReplicatedServiceErrorV2::Dispatch);
        }
        ensure_request_proof_available(self.service.accumulate_host_mut(), request)
            .map_err(|_| ReplicatedServiceErrorV2::ProofUnavailable)?;

        let request_bytes = request.encode();
        let entry = self
            .log
            .propose(&request_bytes)
            .map_err(ReplicatedServiceErrorV2::Log)?;
        let applied = self
            .log
            .applied_index()
            .map_err(ReplicatedServiceErrorV2::Log)?;
        if entry.index <= applied || entry.request != request_bytes {
            return Err(ReplicatedServiceErrorV2::InvalidCommittedLog);
        }
        let committed = AccumulateRequestV2::decode(&entry.request)
            .map_err(|_| ReplicatedServiceErrorV2::InvalidCommittedLog)?;
        if committed != *request {
            return Err(ReplicatedServiceErrorV2::InvalidCommittedLog);
        }
        ensure_request_proof_available(self.service.accumulate_host_mut(), &committed)
            .map_err(|_| ReplicatedServiceErrorV2::ProofUnavailable)?;
        let output = self
            .service
            .accumulate(&committed)
            .map_err(ReplicatedServiceErrorV2::Dispatch)?;
        let service_image = self.service.accumulate_host().committed_service_image();
        self.log
            .mark_applied(entry.index, &service_image)
            .map_err(ReplicatedServiceErrorV2::Log)?;
        Ok(output)
    }

    /// Produce the proof before proposing the final Apply request. Only the
    /// proved Apply bytes enter Raft; read-only preparation never consumes a
    /// log position. Followers make the same proof artifact available before
    /// executing the committed request through physical IC-5.
    pub fn accumulate_attested<P: AttestationProofProducerV2>(
        &mut self,
        envelope: AccumulationEnvelopeV2,
        imports: &RefineImportsV2,
        producer: &mut P,
    ) -> Result<
        CommittedAttestationOutputV2,
        AttestedServiceErrorV2<ReplicatedServiceErrorV2<L::Error>, P::Error>,
    > {
        // Keep the same preflight on the replicated driver so a suspending
        // transition cannot invoke a producer or enter the Raft log.
        require_single_slice_attestation(&envelope)?;
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
        let proved = self
            .service
            .prove_prepared_attestation(envelope, imports, preparation, producer)
            .map_err(map_attestation_build_error)?;
        let committed = self
            .accumulate(&AccumulateRequestV2::Apply(proved.envelope.clone()))
            .map_err(AttestedServiceErrorV2::Service)?;
        finish_committed_attestation(proved, prepared.gas_used, committed)
    }
}

fn ensure_request_proof_available<A: AttestationProofHostV2>(
    host: &mut A,
    request: &AccumulateRequestV2,
) -> Result<(), ()> {
    let AccumulateRequestV2::Apply(envelope) = request else {
        return Ok(());
    };
    let Some(proof) = envelope.transition.proof.as_ref() else {
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
        actor_program: envelope.work.target_program,
        execution_semantics: envelope.work.service.execution_semantics,
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
