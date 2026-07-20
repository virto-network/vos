//! Local conformance harness for the protocol-pinned generic service PVM.
//!
//! There is deliberately no native Refine implementation and no native
//! transition-apply shortcut here. Both paths execute the same canonical PVM
//! that deployment installs; the host supplies only imports and an atomic JAM
//! storage transaction boundary.

use alloc::vec::Vec;

use super::wire::{DecodeError, Decoder, Encoder};
use super::{
    AccumulateProtocolHostV2, AccumulateRequestV2, AccumulationResultV2,
    CommittedServiceImageHostV2, ImportedBlobV2, LocalJamStoreSnapshotV2, ProgramId,
    RefineImportsV2, RefineOutputV2, RefineProtocolHostV2, ServiceImageInstallErrorV2,
    ServicePvmErrorV2, ServicePvmV2, TransitionV2, V2Wire, WorkEnvelopeV2,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefinedServiceOutputV2 {
    pub transition: TransitionV2,
    pub gas_used: u64,
    pub exported_blobs: Vec<ImportedBlobV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulatedServiceOutputV2 {
    pub result: AccumulationResultV2,
    pub gas_used: u64,
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
        })
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

impl<R, A, L> ReplicatedJamServiceV2<R, A, L>
where
    R: RefineProtocolHostV2,
    A: AccumulateProtocolHostV2 + CommittedServiceImageHostV2,
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
}
