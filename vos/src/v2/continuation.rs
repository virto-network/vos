//! VOS binding envelope for the canonical JAR invocation snapshot.
//!
//! JAR owns the portable machine format and its interpreter/recompiler restore
//! semantics. VOS does not mirror PC, registers, capabilities, memory, or the
//! nested call stack in a second structure. It binds the exact JAR snapshot
//! bytes to the actor workflow and verifies those bytes against the canonical
//! service/actor PVM layout when restoring on the host.

use alloc::vec::Vec;

use super::contracts::{ServiceIdentityV2, WorkEnvelopeV2};
use super::identity::{ActorId, CallId, DeploymentId, InvocationId, ProgramId};
use super::wire::{DecodeError, Decoder, Encoder, V2Wire};

/// Exact package/program layout from which a suspended invocation kernel was
/// constructed. The list in a continuation is sorted by `actor` and remains
/// authoritative even if the owned tree later gains more actors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuationProgramV2 {
    pub actor: ActorId,
    pub deployment: DeploymentId,
    pub program: ProgramId,
}

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
    pub actor_deployment: DeploymentId,
    pub actor_program: ProgramId,
    /// Complete actor-program layout present when this kernel was created.
    /// New actors may be added to the service while it is suspended, but an
    /// existing binding cannot change until this continuation drains.
    pub programs: Vec<ContinuationProgramV2>,
    /// Ordinal used to derive a stable `CallId` for an awaited call.
    pub await_ordinal: u64,
    /// `None` for an explicit scheduler yield; `Some` for an awaited call.
    pub pending_call: Option<CallId>,
    /// Exact actors whose machines are running or waiting on the nested JAR
    /// call stack. Each is non-reentrant until this continuation is replaced
    /// by a snapshot that omits it or is deleted on completion.
    pub suspended_actors: Vec<ActorId>,
    pub kernel_snapshot: Vec<u8>,
}

/// Allocation-bounded view used by guest Accumulate. The inner JAR snapshot
/// remains opaque and content-addressed there; only Refine restore needs to
/// allocate and parse its complete machine bytes.
pub(crate) struct ContinuationMetadataV2 {
    snapshot_version: u16,
    jar_semantics: super::Hash,
    vos_abi: u16,
    service: ServiceIdentityV2,
    invocation: InvocationId,
    checkpoint_step: u64,
    actor: ActorId,
    actor_deployment: DeploymentId,
    actor_program: ProgramId,
    pub(crate) programs: Vec<ContinuationProgramV2>,
    pub(crate) await_ordinal: u64,
    pub pending_call: Option<CallId>,
    pub suspended_actors: Vec<ActorId>,
    kernel_snapshot_len: usize,
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
            || !valid_program_layout(
                &self.programs,
                self.actor,
                self.actor_deployment,
                self.actor_program,
            )
            || self.suspended_actors.is_empty()
            || self.suspended_actors.binary_search(&self.actor).is_err()
            || self
                .suspended_actors
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
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
            || self.actor_deployment != work.target_deployment
            || self.actor_program != work.target_program
            || !program_layout_matches_checkpoint(&self.programs, work)
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
            || self.actor_deployment != work.target_deployment
            || self.actor_program != work.target_program
            || !program_layout_matches_resume(&self.programs, work)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    pub(crate) fn decode_metadata(bytes: &[u8]) -> Result<ContinuationMetadataV2, DecodeError> {
        let mut d = Decoder::new(bytes);
        if d.take(4)? != Self::MAGIC {
            return Err(DecodeError::InvalidTag);
        }
        if d.u16()? != super::ABI_VERSION {
            return Err(DecodeError::InvalidVersion);
        }
        let value = ContinuationMetadataV2 {
            snapshot_version: d.u16()?,
            jar_semantics: super::Hash(d.fixed()?),
            vos_abi: d.u16()?,
            service: decode_service(&mut d)?,
            invocation: InvocationId(d.fixed()?),
            checkpoint_step: d.u64()?,
            actor: ActorId(d.fixed()?),
            actor_deployment: DeploymentId(d.fixed()?),
            actor_program: ProgramId(d.fixed()?),
            programs: decode_programs(&mut d)?,
            await_ordinal: d.u64()?,
            pending_call: d.option(|d| d.fixed().map(CallId))?,
            suspended_actors: d.list(|d| d.fixed().map(ActorId))?,
            kernel_snapshot_len: d.bytes_ref()?.len(),
        };
        if !d.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        value.validate()?;
        Ok(value)
    }
}

impl ContinuationMetadataV2 {
    fn validate(&self) -> Result<(), DecodeError> {
        if self.snapshot_version != super::SNAPSHOT_VERSION
            || self.vos_abi != super::ABI_VERSION
            || self.jar_semantics != super::EXECUTION_SEMANTICS_ID
            || self.service.service_abi != super::ABI_VERSION
            || self.service.execution_semantics != super::EXECUTION_SEMANTICS_ID
        {
            return Err(DecodeError::InvalidVersion);
        }
        if self.kernel_snapshot_len == 0
            || !valid_program_layout(
                &self.programs,
                self.actor,
                self.actor_deployment,
                self.actor_program,
            )
            || self.suspended_actors.is_empty()
            || self.suspended_actors.binary_search(&self.actor).is_err()
            || self
                .suspended_actors
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self
                .pending_call
                .is_some_and(|call| call != self.invocation.call_id(self.await_ordinal))
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    pub(crate) fn validate_checkpoint_for(&self, work: &WorkEnvelopeV2) -> Result<(), DecodeError> {
        self.validate()?;
        if self.service != work.service
            || self.invocation != work.invocation
            || self.checkpoint_step != work.workflow_step
            || self.actor != work.target
            || self.actor_deployment != work.target_deployment
            || self.actor_program != work.target_program
            || !program_layout_matches_checkpoint(&self.programs, work)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    pub(crate) fn validate_resume_for(&self, work: &WorkEnvelopeV2) -> Result<(), DecodeError> {
        self.validate()?;
        if self.service != work.service
            || self.invocation != work.invocation
            || self.checkpoint_step.checked_add(1) != Some(work.workflow_step)
            || self.actor != work.target
            || self.actor_deployment != work.target_deployment
            || self.actor_program != work.target_program
            || !program_layout_matches_resume(&self.programs, work)
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
        e.fixed(&self.actor_deployment.0);
        e.fixed(&self.actor_program.0);
        encode_programs(&mut e, &self.programs);
        e.u64(self.await_ordinal);
        e.option(&self.pending_call, |e, call| e.fixed(&call.0));
        e.list(&self.suspended_actors, |e, actor| e.fixed(&actor.0));
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
            actor_deployment: DeploymentId(d.fixed()?),
            actor_program: ProgramId(d.fixed()?),
            programs: decode_programs(d)?,
            await_ordinal: d.u64()?,
            pending_call: d.option(|d| d.fixed().map(CallId))?,
            suspended_actors: d.list(|d| d.fixed().map(ActorId))?,
            kernel_snapshot: d.bytes()?,
        };
        value.validate()?;
        Ok(value)
    }
}

fn valid_program_layout(
    programs: &[ContinuationProgramV2],
    actor: ActorId,
    deployment: DeploymentId,
    program: ProgramId,
) -> bool {
    !programs.is_empty()
        && programs.len() <= super::MAX_ROOT_TREE_ACTORS
        && !programs
            .windows(2)
            .any(|pair| pair[0].actor >= pair[1].actor)
        && programs
            .binary_search_by_key(&actor, |binding| binding.actor)
            .ok()
            .is_some_and(|index| {
                programs[index].deployment == deployment && programs[index].program == program
            })
}

fn program_layout_matches_checkpoint(
    programs: &[ContinuationProgramV2],
    work: &WorkEnvelopeV2,
) -> bool {
    programs.len() == work.imported_actors.len()
        && programs
            .iter()
            .zip(&work.imported_actors)
            .all(|(binding, actor)| {
                binding.actor == actor.actor
                    && binding.deployment == actor.deployment
                    && binding.program == actor.program
            })
}

fn program_layout_matches_resume(
    programs: &[ContinuationProgramV2],
    work: &WorkEnvelopeV2,
) -> bool {
    programs.iter().all(|binding| {
        work.imported_actors
            .binary_search_by_key(&binding.actor, |actor| actor.actor)
            .ok()
            .is_some_and(|index| {
                work.imported_actors[index].deployment == binding.deployment
                    && work.imported_actors[index].program == binding.program
            })
    })
}

fn encode_programs(e: &mut Encoder<'_>, programs: &[ContinuationProgramV2]) {
    e.list(programs, |e, binding| {
        e.fixed(&binding.actor.0);
        e.fixed(&binding.deployment.0);
        e.fixed(&binding.program.0);
    });
}

fn decode_programs(d: &mut Decoder<'_>) -> Result<Vec<ContinuationProgramV2>, DecodeError> {
    let len = d.u32()? as usize;
    if len > super::MAX_ROOT_TREE_ACTORS {
        return Err(DecodeError::LimitExceeded);
    }
    let mut programs = Vec::with_capacity(len);
    for _ in 0..len {
        programs.push(ContinuationProgramV2 {
            actor: ActorId(d.fixed()?),
            deployment: DeploymentId(d.fixed()?),
            program: ProgramId(d.fixed()?),
        });
    }
    Ok(programs)
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
            actor_deployment: DeploymentId([7; 32]),
            actor_program: ProgramId([6; 32]),
            programs: vec![ContinuationProgramV2 {
                actor: ActorId([5; 32]),
                deployment: DeploymentId([7; 32]),
                program: ProgramId([6; 32]),
            }],
            await_ordinal: 3,
            pending_call: Some(invocation.call_id(3)),
            suspended_actors: vec![ActorId([5; 32])],
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
            target_deployment: snapshot.actor_deployment,
            target_program: snapshot.actor_program,
            method: "resume".to_string(),
            arguments: vec![],
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: snapshot.pending_call,
            awaited_reply: None,
            awaited_timeout: None,
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
                deployment: snapshot.actor_deployment,
                program: snapshot.actor_program,
                state: crate::v2::BlobRefV2 {
                    hash: Hash([9; 32]),
                    len: 1,
                },
                causal_states: vec![],
                continuation: None,
            }],
            external_actors: vec![],
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
    fn allocation_bounded_metadata_validates_the_same_envelope() {
        let value = snapshot();
        let encoded = value.encode();
        let metadata = ContinuationSnapshotV2::decode_metadata(&encoded).unwrap();
        assert_eq!(metadata.pending_call, value.pending_call);
        assert_eq!(metadata.suspended_actors, value.suspended_actors);
        assert_eq!(metadata.await_ordinal, value.await_ordinal);
        assert_eq!(metadata.kernel_snapshot_len, value.kernel_snapshot.len());
        metadata.validate_resume_for(&resume_work()).unwrap();

        let mut truncated = encoded;
        truncated.pop();
        assert!(matches!(
            ContinuationSnapshotV2::decode_metadata(&truncated),
            Err(DecodeError::Truncated)
        ));
    }

    #[test]
    fn resume_keeps_the_captured_layout_but_allows_new_tree_members() {
        let snapshot = snapshot();
        let mut work = resume_work();
        work.imported_actors.push(ImportedActorV2 {
            actor: ActorId([8; 32]),
            name: "new-child".into(),
            parent: Some(snapshot.actor),
            deployment: DeploymentId([9; 32]),
            program: ProgramId([10; 32]),
            state: crate::v2::BlobRefV2 {
                hash: Hash([11; 32]),
                len: 1,
            },
            causal_states: vec![],
            continuation: None,
        });
        snapshot.validate_resume_for(&work).unwrap();

        work.imported_actors[0].program = ProgramId([12; 32]);
        assert_eq!(
            snapshot.validate_resume_for(&work),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn emitted_checkpoint_must_bind_every_imported_actor_program() {
        let snapshot = snapshot();
        let mut work = resume_work();
        work.workflow_step = snapshot.checkpoint_step;
        snapshot.validate_checkpoint_for(&work).unwrap();

        work.imported_actors.push(ImportedActorV2 {
            actor: ActorId([8; 32]),
            name: "omitted-child".into(),
            parent: Some(snapshot.actor),
            deployment: DeploymentId([9; 32]),
            program: ProgramId([10; 32]),
            state: crate::v2::BlobRefV2 {
                hash: Hash([11; 32]),
                len: 1,
            },
            causal_states: vec![],
            continuation: None,
        });
        assert_eq!(
            snapshot.validate_checkpoint_for(&work),
            Err(DecodeError::NonCanonical)
        );
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

        let mut oversized = snapshot();
        oversized.programs = vec![oversized.programs[0]; crate::v2::MAX_ROOT_TREE_ACTORS + 1];
        assert_eq!(
            ContinuationSnapshotV2::decode(&oversized.encode()),
            Err(DecodeError::LimitExceeded)
        );
    }
}
