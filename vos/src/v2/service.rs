//! Local conformance harness for the protocol-pinned generic service PVM.
//!
//! There is deliberately no native Refine implementation and no native
//! transition-apply shortcut here. Both paths execute the same canonical PVM
//! that deployment installs; the host supplies only imports and an atomic JAM
//! storage transaction boundary.

use alloc::vec::Vec;

use super::{
    AccumulateProtocolHostV2, AccumulateRequestV2, AccumulationResultV2, ImportedBlobV2, ProgramId,
    RefineImportsV2, RefineProtocolHostV2, ServicePvmErrorV2, ServicePvmV2, TransitionV2, V2Wire,
    WorkEnvelopeV2,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceDispatchError {
    Pvm(ServicePvmErrorV2),
    InvalidRefineOutput,
    InvalidAccumulateOutput,
}

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
        let transition = TransitionV2::decode(&output.bytes)
            .map_err(|_| ServiceDispatchError::InvalidRefineOutput)?;
        Ok(RefinedServiceOutputV2 {
            transition,
            gas_used: output.gas_used,
            exported_blobs: output.exported_blobs,
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
