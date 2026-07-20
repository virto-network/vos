//! VOS binding envelope for the canonical JAR invocation snapshot.
//!
//! JAR owns the portable machine format and its interpreter/recompiler restore
//! semantics. VOS does not mirror PC, registers, capabilities, memory, or the
//! nested call stack in a second structure. It binds the exact JAR snapshot
//! bytes to the actor workflow and verifies those bytes against the canonical
//! service/actor PVM layout when restoring on the host.

use alloc::vec::Vec;

use super::contracts::{ServiceIdentityV2, WorkEnvelopeV2};
use super::identity::{ActorId, CallId, InvocationId, ProgramId};
use super::wire::{DecodeError, Decoder, Encoder, V2Wire};

/// Durable actor-tree checkpoint. `kernel_snapshot` is the canonical
/// `javm::snapshot::KernelSnapshot::to_bytes()` representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationSnapshotV2 {
    pub snapshot_version: u16,
    pub jar_semantics: super::Hash,
    pub vos_abi: u16,
    pub service: ServiceIdentityV2,
    pub invocation: InvocationId,
    /// Work slice whose mutations are committed alongside this checkpoint.
    pub checkpoint_step: u64,
    pub actor: ActorId,
    pub actor_program: ProgramId,
    /// Ordinal used to derive a stable `CallId` for an awaited call.
    pub await_ordinal: u64,
    /// `None` for an explicit scheduler yield; `Some` for an awaited call.
    pub pending_call: Option<CallId>,
    pub kernel_snapshot: Vec<u8>,
}

impl ContinuationSnapshotV2 {
    pub fn hash(&self) -> super::Hash {
        super::Hash::digest(b"vos/continuation/v2", &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.snapshot_version != super::SNAPSHOT_VERSION
            || self.vos_abi != super::ABI_VERSION
            || self.jar_semantics != super::EXECUTION_SEMANTICS_ID
            || self.service.service_abi != super::ABI_VERSION
            || self.service.execution_semantics != super::EXECUTION_SEMANTICS_ID
        {
            return Err(DecodeError::InvalidVersion);
        }
        if self.kernel_snapshot.is_empty()
            || self
                .pending_call
                .is_some_and(|call| call != self.invocation.call_id(self.await_ordinal))
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    /// Bind a newly emitted checkpoint to the slice which produced it. This
    /// is the Accumulate-side counterpart to [`Self::validate_resume_for`].
    pub fn validate_checkpoint_for(&self, work: &WorkEnvelopeV2) -> Result<(), DecodeError> {
        self.validate()?;
        if self.service != work.service
            || self.invocation != work.invocation
            || self.checkpoint_step != work.workflow_step
            || self.actor != work.target
            || self.actor_program != work.target_program
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    /// Check the VOS workflow binding before JAR parses or restores the inner
    /// machine snapshot. A continuation always resumes in the next slice.
    pub fn validate_resume_for(&self, work: &WorkEnvelopeV2) -> Result<(), DecodeError> {
        self.validate()?;
        if self.service != work.service
            || self.invocation != work.invocation
            || self.checkpoint_step.checked_add(1) != Some(work.workflow_step)
            || self.actor != work.target
            || self.actor_program != work.target_program
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl V2Wire for ContinuationSnapshotV2 {
    const MAGIC: [u8; 4] = *b"VCS2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.u16(self.snapshot_version);
        e.fixed(&self.jar_semantics.0);
        e.u16(self.vos_abi);
        encode_service(&mut e, &self.service);
        e.fixed(&self.invocation.0);
        e.u64(self.checkpoint_step);
        e.fixed(&self.actor.0);
        e.fixed(&self.actor_program.0);
        e.u64(self.await_ordinal);
        e.option(&self.pending_call, |e, call| e.fixed(&call.0));
        e.bytes(&self.kernel_snapshot);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            snapshot_version: d.u16()?,
            jar_semantics: super::Hash(d.fixed()?),
            vos_abi: d.u16()?,
            service: decode_service(d)?,
            invocation: InvocationId(d.fixed()?),
            checkpoint_step: d.u64()?,
            actor: ActorId(d.fixed()?),
            actor_program: ProgramId(d.fixed()?),
            await_ordinal: d.u64()?,
            pending_call: d.option(|d| d.fixed().map(CallId))?,
            kernel_snapshot: d.bytes()?,
        };
        value.validate()?;
        Ok(value)
    }
}

fn encode_service(e: &mut Encoder<'_>, value: &ServiceIdentityV2) {
    e.fixed(&value.space.0);
    e.fixed(&value.root_service.0);
    e.fixed(&value.deployment.0);
    e.fixed(&value.service_program.0);
    e.u16(value.service_abi);
    e.fixed(&value.execution_semantics.0);
}

fn decode_service(d: &mut Decoder<'_>) -> Result<ServiceIdentityV2, DecodeError> {
    Ok(ServiceIdentityV2 {
        space: super::SpaceId(d.fixed()?),
        root_service: super::RootServiceId(d.fixed()?),
        deployment: super::DeploymentId(d.fixed()?),
        service_program: ProgramId(d.fixed()?),
        service_abi: d.u16()?,
        execution_semantics: super::Hash(d.fixed()?),
    })
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;
    use crate::v2::{
        AuthorizationEvidenceV2, ConsistencyBaseV2, ConsistencyModeV2, DeploymentId, Hash,
        ImportedActorV2, Origin, RootServiceId,
    };

    fn service() -> ServiceIdentityV2 {
        ServiceIdentityV2 {
            space: crate::v2::SpaceId([0; 32]),
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: ProgramId([3; 32]),
            service_abi: crate::v2::ABI_VERSION,
            execution_semantics: crate::v2::EXECUTION_SEMANTICS_ID,
        }
    }

    fn snapshot() -> ContinuationSnapshotV2 {
        let invocation = InvocationId([4; 32]);
        ContinuationSnapshotV2 {
            snapshot_version: crate::v2::SNAPSHOT_VERSION,
            jar_semantics: crate::v2::EXECUTION_SEMANTICS_ID,
            vos_abi: crate::v2::ABI_VERSION,
            service: service(),
            invocation,
            checkpoint_step: 7,
            actor: ActorId([5; 32]),
            actor_program: ProgramId([6; 32]),
            await_ordinal: 3,
            pending_call: Some(invocation.call_id(3)),
            kernel_snapshot: b"canonical JAR kernel snapshot".to_vec(),
        }
    }

    fn resume_work() -> WorkEnvelopeV2 {
        let snapshot = snapshot();
        WorkEnvelopeV2 {
            service: snapshot.service,
            invocation: snapshot.invocation,
            workflow_step: snapshot.checkpoint_step + 1,
            logical_timeslot: 9,
            target: snapshot.actor,
            target_program: snapshot.actor_program,
            method: "resume".to_string(),
            arguments: vec![],
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: snapshot.pending_call,
            awaited_reply: None,
            consistency: ConsistencyModeV2::Local,
            base: ConsistencyBaseV2::Linear {
                revision: 8,
                state_root: Hash([8; 32]),
            },
            base_causal_height: None,
            imported_actors: vec![ImportedActorV2 {
                actor: snapshot.actor,
                name: "root".into(),
                parent: None,
                program: snapshot.actor_program,
                state: crate::v2::BlobRefV2 {
                    hash: Hash([9; 32]),
                    len: 1,
                },
                causal_states: vec![],
                continuation: None,
            }],
            imported_blobs: vec![],
            proof_requested: false,
        }
    }

    #[test]
    fn canonical_jar_snapshot_envelope_roundtrips() {
        let value = snapshot();
        assert_eq!(
            ContinuationSnapshotV2::decode(&value.encode()).unwrap(),
            value
        );
        value.validate_resume_for(&resume_work()).unwrap();
    }

    #[test]
    fn resume_binding_rejects_pc_zero_reconstruction_and_wrong_slice() {
        let value = snapshot();
        let mut work = resume_work();
        work.workflow_step = value.checkpoint_step;
        assert_eq!(
            value.validate_resume_for(&work),
            Err(DecodeError::NonCanonical)
        );

        let mut empty_kernel = value;
        empty_kernel.kernel_snapshot.clear();
        assert_eq!(empty_kernel.validate(), Err(DecodeError::NonCanonical));

        let mut forged_call = snapshot();
        forged_call.pending_call = Some(CallId([7; 32]));
        assert_eq!(
            ContinuationSnapshotV2::decode(&forged_call.encode()),
            Err(DecodeError::NonCanonical)
        );
    }
}
