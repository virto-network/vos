//! VOS binding envelope for the canonical JAR invocation snapshot.
//!
//! JAR owns the portable machine format and its interpreter/recompiler restore
//! semantics. VOS does not mirror PC, registers, capabilities, memory, or the
//! nested call stack in a second structure. It binds the exact JAR snapshot
//! bytes to the actor workflow and verifies those bytes against the canonical
//! service/actor PVM layout when restoring on the host.

use alloc::vec::Vec;

use super::contracts::{CausalCallContext, ServiceIdentity, WorkEnvelope};
use super::identity::{ActorId, CallId, DeploymentId, InvocationId, ProgramId};
use super::wire::{DecodeError, Decoder, Encoder, ServiceWire};

/// Exact package/program layout from which a suspended invocation kernel was
/// constructed. The list in a continuation is sorted by `actor` and remains
/// authoritative even if the owned tree later gains more actors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuationProgram {
    pub actor: ActorId,
    pub deployment: DeploymentId,
    pub program: ProgramId,
}

/// Durable actor-tree checkpoint. `kernel_snapshot` is the canonical
/// `vos_pvm::snapshot::KernelSnapshot::to_bytes()` representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationSnapshot {
    pub snapshot_version: u16,
    pub jar_semantics: super::Hash,
    pub vos_abi: u16,
    pub service: ServiceIdentity,
    pub invocation: InvocationId,
    /// Work slice whose mutations are committed alongside this checkpoint.
    pub checkpoint_step: u64,
    pub actor: ActorId,
    pub actor_deployment: DeploymentId,
    pub actor_program: ProgramId,
    /// Complete actor-program layout present when this kernel was created.
    /// New actors may be added to the service while it is suspended, but an
    /// existing binding cannot change until this continuation drains.
    pub programs: Vec<ContinuationProgram>,
    /// Ordinal used to derive a stable `CallId` for an awaited call.
    pub await_ordinal: u64,
    /// `None` for an explicit scheduler yield; `Some` for an awaited call.
    pub pending_call: Option<CallId>,
    /// Exact actor VM which issued `pending_call`. Derived from JAR's active
    /// machine at snapshot time, never from actor-provided IPC.
    pub pending_actor: Option<ActorId>,
    /// Durable causal authority retained after the step-0 inbox row is
    /// consumed. Every resumed slice must carry this exact context.
    pub causal_context: Option<CausalCallContext>,
    /// Exact actors whose machines are running or waiting on the nested JAR
    /// call stack. Each is non-reentrant until this continuation is replaced
    /// by a snapshot that omits it or is deleted on completion.
    pub suspended_actors: Vec<ActorId>,
    pub kernel_snapshot: Vec<u8>,
}

/// Allocation-bounded view used by guest Accumulate. The inner JAR snapshot
/// remains opaque and content-addressed there; only Refine restore needs to
/// allocate and parse its complete machine bytes.
pub(crate) struct ContinuationMetadata {
    snapshot_version: u16,
    jar_semantics: super::Hash,
    vos_abi: u16,
    service: ServiceIdentity,
    invocation: InvocationId,
    checkpoint_step: u64,
    actor: ActorId,
    actor_deployment: DeploymentId,
    actor_program: ProgramId,
    pub(crate) programs: Vec<ContinuationProgram>,
    pub(crate) await_ordinal: u64,
    pub pending_call: Option<CallId>,
    pub pending_actor: Option<ActorId>,
    causal_context: Option<CausalCallContext>,
    pub suspended_actors: Vec<ActorId>,
    kernel_snapshot_len: usize,
}

impl ContinuationSnapshot {
    pub fn hash(&self) -> super::Hash {
        super::Hash::digest(b"vos/continuation/service", &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.snapshot_version != super::SNAPSHOT_VERSION
            || self.vos_abi != super::ABI_VERSION
            || self.jar_semantics != super::EXECUTION_SEMANTICS_ID
            || self.service.service_abi != super::ABI_VERSION
            || self.service.execution_semantics != super::EXECUTION_SEMANTICS_ID
            || !self.service.gas_schedule.is_valid()
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
            || self.pending_call.is_some() != self.pending_actor.is_some()
            || self
                .pending_actor
                .is_some_and(|actor| self.suspended_actors.binary_search(&actor).is_err())
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    /// Bind a newly emitted checkpoint to the slice which produced it. This
    /// is the Accumulate-side counterpart to [`Self::validate_resume_for`].
    pub fn validate_checkpoint_for(&self, work: &WorkEnvelope) -> Result<(), DecodeError> {
        self.validate()?;
        if self.service != work.service
            || self.invocation != work.invocation
            || self.checkpoint_step != work.workflow_step
            || self.actor != work.target
            || self.actor_deployment != work.target_deployment
            || self.actor_program != work.target_program
            || self.causal_context != work.causal_context
            || !program_layout_matches_emitted_checkpoint(&self.programs, work)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    /// Check the VOS workflow binding before JAR parses or restores the inner
    /// machine snapshot. A continuation always resumes in the next slice.
    pub fn validate_resume_for(&self, work: &WorkEnvelope) -> Result<(), DecodeError> {
        self.validate()?;
        if self.service != work.service
            || self.invocation != work.invocation
            || self.checkpoint_step.checked_add(1) != Some(work.workflow_step)
            || self.actor != work.target
            || self.actor_deployment != work.target_deployment
            || self.actor_program != work.target_program
            || self.causal_context != work.causal_context
            || !program_layout_matches_resume(&self.programs, work)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    pub(crate) fn decode_metadata(bytes: &[u8]) -> Result<ContinuationMetadata, DecodeError> {
        let mut d = Decoder::new(bytes);
        if d.take(4)? != Self::MAGIC {
            return Err(DecodeError::InvalidTag);
        }
        if d.u16()? != super::ABI_VERSION {
            return Err(DecodeError::InvalidVersion);
        }
        let value = ContinuationMetadata {
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
            pending_actor: d.option(|d| d.fixed().map(ActorId))?,
            causal_context: d.option(decode_causal_context)?,
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

impl ContinuationMetadata {
    fn validate(&self) -> Result<(), DecodeError> {
        if self.snapshot_version != super::SNAPSHOT_VERSION
            || self.vos_abi != super::ABI_VERSION
            || self.jar_semantics != super::EXECUTION_SEMANTICS_ID
            || self.service.service_abi != super::ABI_VERSION
            || self.service.execution_semantics != super::EXECUTION_SEMANTICS_ID
            || !self.service.gas_schedule.is_valid()
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
            || self.pending_call.is_some() != self.pending_actor.is_some()
            || self
                .pending_actor
                .is_some_and(|actor| self.suspended_actors.binary_search(&actor).is_err())
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    pub(crate) fn validate_checkpoint_for(&self, work: &WorkEnvelope) -> Result<(), DecodeError> {
        self.validate()?;
        if self.service != work.service
            || self.invocation != work.invocation
            || self.checkpoint_step != work.workflow_step
            || self.actor != work.target
            || self.actor_deployment != work.target_deployment
            || self.actor_program != work.target_program
            || self.causal_context != work.causal_context
            || !program_layout_matches_emitted_checkpoint(&self.programs, work)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    pub(crate) fn validate_resume_for(&self, work: &WorkEnvelope) -> Result<(), DecodeError> {
        self.validate()?;
        if self.service != work.service
            || self.invocation != work.invocation
            || self.checkpoint_step.checked_add(1) != Some(work.workflow_step)
            || self.actor != work.target
            || self.actor_deployment != work.target_deployment
            || self.actor_program != work.target_program
            || self.causal_context != work.causal_context
            || !program_layout_matches_resume(&self.programs, work)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl ServiceWire for ContinuationSnapshot {
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
        e.option(&self.pending_actor, |e, actor| e.fixed(&actor.0));
        e.option(&self.causal_context, encode_causal_context);
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
            pending_actor: d.option(|d| d.fixed().map(ActorId))?,
            causal_context: d.option(decode_causal_context)?,
            suspended_actors: d.list(|d| d.fixed().map(ActorId))?,
            kernel_snapshot: d.bytes()?,
        };
        value.validate()?;
        Ok(value)
    }
}

fn encode_causal_context(e: &mut Encoder<'_>, value: &CausalCallContext) {
    e.fixed(&value.call_id.0);
    e.fixed(&value.caller_invocation.0);
    encode_service(e, &value.from_service);
    e.fixed(&value.from.0);
    e.fixed(&value.to.0);
    e.option(&value.parent, |e, call| e.fixed(&call.0));
    e.option(&value.deadline_timeslot, |e, deadline| e.u64(*deadline));
}

fn decode_causal_context(d: &mut Decoder<'_>) -> Result<CausalCallContext, DecodeError> {
    Ok(CausalCallContext {
        call_id: CallId(d.fixed()?),
        caller_invocation: InvocationId(d.fixed()?),
        from_service: decode_service(d)?,
        from: ActorId(d.fixed()?),
        to: ActorId(d.fixed()?),
        parent: d.option(|d| d.fixed().map(CallId))?,
        deadline_timeslot: d.option(Decoder::u64)?,
    })
}

fn valid_program_layout(
    programs: &[ContinuationProgram],
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
    programs: &[ContinuationProgram],
    work: &WorkEnvelope,
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

fn program_layout_matches_emitted_checkpoint(
    programs: &[ContinuationProgram],
    work: &WorkEnvelope,
) -> bool {
    if work.workflow_step == 0 {
        program_layout_matches_checkpoint(programs, work)
    } else {
        // A resumed kernel retains the layout from its first checkpoint even
        // if the current complete service directory gained actors meanwhile.
        program_layout_matches_resume(programs, work)
    }
}

fn program_layout_matches_resume(programs: &[ContinuationProgram], work: &WorkEnvelope) -> bool {
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

fn encode_programs(e: &mut Encoder<'_>, programs: &[ContinuationProgram]) {
    e.list(programs, |e, binding| {
        e.fixed(&binding.actor.0);
        e.fixed(&binding.deployment.0);
        e.fixed(&binding.program.0);
    });
}

fn decode_programs(d: &mut Decoder<'_>) -> Result<Vec<ContinuationProgram>, DecodeError> {
    let len = d.u32()? as usize;
    if len > super::MAX_ROOT_TREE_ACTORS {
        return Err(DecodeError::LimitExceeded);
    }
    let mut programs = Vec::with_capacity(len);
    for _ in 0..len {
        programs.push(ContinuationProgram {
            actor: ActorId(d.fixed()?),
            deployment: DeploymentId(d.fixed()?),
            program: ProgramId(d.fixed()?),
        });
    }
    Ok(programs)
}

fn encode_service(e: &mut Encoder<'_>, value: &ServiceIdentity) {
    e.fixed(&value.space.0);
    e.fixed(&value.root_service.0);
    e.fixed(&value.deployment.0);
    e.fixed(&value.service_program.0);
    e.u16(value.service_abi);
    e.fixed(&value.execution_semantics.0);
    e.u64(value.gas_schedule.refine);
    e.u64(value.gas_schedule.accumulate);
}

fn decode_service(d: &mut Decoder<'_>) -> Result<ServiceIdentity, DecodeError> {
    let service = ServiceIdentity {
        space: super::SpaceId(d.fixed()?),
        root_service: super::RootServiceId(d.fixed()?),
        deployment: super::DeploymentId(d.fixed()?),
        service_program: ProgramId(d.fixed()?),
        service_abi: d.u16()?,
        execution_semantics: super::Hash(d.fixed()?),
        gas_schedule: super::GasSchedule::new(d.u64()?, d.u64()?),
    };
    if service.service_abi != super::ABI_VERSION || !service.gas_schedule.is_valid() {
        return Err(DecodeError::InvalidVersion);
    }
    Ok(service)
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;
    use crate::service::{
        AuthorizationEvidence, ConsistencyBase, ConsistencyMode, DeploymentId, Hash, ImportedActor,
        Origin, RootServiceId,
    };

    fn service() -> ServiceIdentity {
        ServiceIdentity {
            space: crate::service::SpaceId([0; 32]),
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: ProgramId([3; 32]),
            service_abi: crate::service::ABI_VERSION,
            execution_semantics: crate::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: crate::service::GasSchedule::new(1_000_000_000, 5_000_000_000),
        }
    }

    fn snapshot() -> ContinuationSnapshot {
        let invocation = InvocationId([4; 32]);
        ContinuationSnapshot {
            snapshot_version: crate::service::SNAPSHOT_VERSION,
            jar_semantics: crate::service::EXECUTION_SEMANTICS_ID,
            vos_abi: crate::service::ABI_VERSION,
            service: service(),
            invocation,
            checkpoint_step: 7,
            actor: ActorId([5; 32]),
            actor_deployment: DeploymentId([7; 32]),
            actor_program: ProgramId([6; 32]),
            programs: vec![ContinuationProgram {
                actor: ActorId([5; 32]),
                deployment: DeploymentId([7; 32]),
                program: ProgramId([6; 32]),
            }],
            await_ordinal: 3,
            pending_call: Some(invocation.call_id(3)),
            pending_actor: Some(ActorId([5; 32])),
            causal_context: None,
            suspended_actors: vec![ActorId([5; 32])],
            kernel_snapshot: b"canonical JAR kernel snapshot".to_vec(),
        }
    }

    fn resume_work() -> WorkEnvelope {
        let snapshot = snapshot();
        WorkEnvelope {
            service: snapshot.service,
            invocation: snapshot.invocation,
            workflow_step: snapshot.checkpoint_step + 1,
            logical_timeslot: 9,
            target: snapshot.actor,
            target_deployment: snapshot.actor_deployment,
            target_program: snapshot.actor_program,
            method: "resume".to_string(),
            arguments: vec![],
            private_arguments: None,
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidence::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            consistency: ConsistencyMode::Local,
            base: ConsistencyBase::Linear {
                revision: 8,
                state_root: Hash([8; 32]),
            },
            base_causal_height: None,
            imported_actors: vec![ImportedActor {
                actor: snapshot.actor,
                name: "root".into(),
                parent: None,
                deployment: snapshot.actor_deployment,
                program: snapshot.actor_program,
                task_dependencies: vec![],
                state: crate::service::BlobRef {
                    hash: Hash([9; 32]),
                    len: 1,
                },
                causal_states: vec![],
                continuation: None,
                storage_rows: vec![],
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
            ContinuationSnapshot::decode(&value.encode()).unwrap(),
            value
        );
        value.validate_resume_for(&resume_work()).unwrap();
    }

    #[test]
    fn allocation_bounded_metadata_validates_the_same_envelope() {
        let value = snapshot();
        let encoded = value.encode();
        let metadata = ContinuationSnapshot::decode_metadata(&encoded).unwrap();
        assert_eq!(metadata.pending_call, value.pending_call);
        assert_eq!(metadata.pending_actor, value.pending_actor);
        assert_eq!(metadata.suspended_actors, value.suspended_actors);
        assert_eq!(metadata.await_ordinal, value.await_ordinal);
        assert_eq!(metadata.kernel_snapshot_len, value.kernel_snapshot.len());
        metadata.validate_resume_for(&resume_work()).unwrap();

        let mut truncated = encoded;
        truncated.pop();
        assert!(matches!(
            ContinuationSnapshot::decode_metadata(&truncated),
            Err(DecodeError::Truncated)
        ));
    }

    #[test]
    fn resume_keeps_the_captured_layout_but_allows_new_tree_members() {
        let snapshot = snapshot();
        let mut work = resume_work();
        work.imported_actors.push(ImportedActor {
            actor: ActorId([8; 32]),
            name: "new-child".into(),
            parent: Some(snapshot.actor),
            deployment: DeploymentId([9; 32]),
            program: ProgramId([10; 32]),
            task_dependencies: vec![],
            state: crate::service::BlobRef {
                hash: Hash([11; 32]),
                len: 1,
            },
            causal_states: vec![],
            continuation: None,
            storage_rows: vec![],
        });
        snapshot.validate_resume_for(&work).unwrap();

        let mut next_checkpoint = snapshot.clone();
        next_checkpoint.checkpoint_step = work.workflow_step;
        next_checkpoint.validate_checkpoint_for(&work).unwrap();

        work.imported_actors[0].program = ProgramId([12; 32]);
        assert_eq!(
            snapshot.validate_resume_for(&work),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn emitted_checkpoint_must_bind_every_imported_actor_program() {
        let mut snapshot = snapshot();
        snapshot.checkpoint_step = 0;
        let mut work = resume_work();
        work.workflow_step = 0;
        snapshot.validate_checkpoint_for(&work).unwrap();

        work.imported_actors.push(ImportedActor {
            actor: ActorId([8; 32]),
            name: "omitted-child".into(),
            parent: Some(snapshot.actor),
            deployment: DeploymentId([9; 32]),
            program: ProgramId([10; 32]),
            task_dependencies: vec![],
            state: crate::service::BlobRef {
                hash: Hash([11; 32]),
                len: 1,
            },
            causal_states: vec![],
            continuation: None,
            storage_rows: vec![],
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
            ContinuationSnapshot::decode(&forged_call.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut oversized = snapshot();
        oversized.programs = vec![oversized.programs[0]; crate::service::MAX_ROOT_TREE_ACTORS + 1];
        assert_eq!(
            ContinuationSnapshot::decode(&oversized.encode()),
            Err(DecodeError::LimitExceeded)
        );
    }
}
