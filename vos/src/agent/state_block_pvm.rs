//! Experimental physical block-fetch boundary. No production driver selects
//! this runner yet. The owner must authenticate the program/root snapshot and
//! the guest must traverse/verify references from that root. Host verification
//! below is defense in depth, not permission to omit guest verification.

use super::journal::CanonicalJournalRecord;
use crate::agent_sdk::{
    Hash,
    state_blocks::{
        BlockRef, BlockScope, MAX_STATE_BLOCK_BYTES, ReadBudget, STATE_BLOCK_FETCH_CALL,
    },
    state_tree::{BlockReader, TreeError},
};
use vos_pvm::{ExitReason, Gas, refine::Machine, refine_host::RefineContext};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BlockPvmError {
    Load,
    InvalidRequest,
    ProgramMismatch,
    UnsupportedCall(u64),
    Block(TreeError),
    OutOfGas,
    Exit { reason: ExitReason, pc: u32 },
    Output,
}

pub(crate) struct StateBlockHost<'a, R: ?Sized> {
    pub scope: BlockScope,
    pub reader: &'a mut R,
    pub budget: &'a mut ReadBudget,
}

impl<R: BlockReader + ?Sized> StateBlockHost<'_, R> {
    /// Execute an explicitly admitted journal runtime and capture its exact
    /// response. The caller supplies authenticated predecessor manifests and
    /// position; this does not admit a runtime upgrade or publish any head.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_admitted_journal(
        &mut self,
        runtime: &super::package_admission::AdmittedStateRuntimePackage,
        genesis: &super::journal::AgentJournalGenesis,
        input: &super::journal::ReplayInput,
        before: &super::wire::RuntimeState,
        position: super::replay::ReplayPosition,
        lanes: &[(
            super::journal::LaneStateManifest,
            super::journal::LaneCursor,
        )],
        gas: Gas,
    ) -> Result<super::replay::ReplayExternalExecution, BlockPvmError> {
        let binding = runtime
            .binding(input.runtime.space, input.runtime.agent)
            .map_err(|_| BlockPvmError::InvalidRequest)?;
        if binding != input.runtime {
            return Err(BlockPvmError::ProgramMismatch);
        }
        let work = Self::journal_work(
            genesis,
            input,
            before,
            position,
            lanes,
            runtime.external_state_limits(),
        )?;
        let output = self.execute_admitted_state(runtime, &work, gas)?;
        super::replay::ReplayExternalExecution::from_physical_response(
            input, before, position, &work, output,
        )
        .map_err(|_| BlockPvmError::Output)
    }

    /// Execute the exact signed experimental package, not caller-selected raw
    /// bytes. Root authority, actor authorization and journal position remain
    /// the owner's responsibility. Resume requires retained-owner admission;
    /// management/bootstrap/upgrade are deliberately not supported here yet.
    pub(crate) fn execute_admitted_state(
        &mut self,
        runtime: &super::package_admission::AdmittedStateRuntimePackage,
        work: &crate::agent_sdk::state_execution::StateExecutionWork,
        gas: Gas,
    ) -> Result<crate::agent_sdk::state_execution::StateExecutionOutput, BlockPvmError> {
        use crate::agent_sdk::RuntimeWork;
        let (deployment, state) = match work.work() {
            RuntimeWork::Invoke {
                invocation, state, ..
            } => (invocation.runtime_deployment, state),
            RuntimeWork::Acknowledge {
                invocation, state, ..
            } => (invocation.runtime_deployment, state),
            RuntimeWork::Manage { .. } | RuntimeWork::Resume { .. } => {
                return Err(BlockPvmError::InvalidRequest);
            }
            RuntimeWork::InspectInvocation { .. } => {
                return Err(BlockPvmError::InvalidRequest);
            }
        };
        let manifest = runtime.manifest();
        let limit = manifest.contract.resources.max_runtime_state_bytes as usize;
        if deployment != runtime.deployment()
            || work.limits() != runtime.external_state_limits()
            || work.lanes().iter().any(|lane| {
                !manifest
                    .capabilities
                    .lanes
                    .contains(lane.base.context().scope().lane())
            })
            || state.encoded_len().is_none_or(|bytes| bytes > limit)
            || runtime.program_bytes().len() > super::execution::MAX_EXECUTION_PROGRAM_BYTES
        {
            return Err(BlockPvmError::InvalidRequest);
        }
        let output = self.execute_state_bytes(runtime.program_bytes(), work, gas)?;
        if output
            .transition()
            .state
            .encoded_len()
            .is_none_or(|bytes| bytes > limit)
        {
            return Err(BlockPvmError::Output);
        }
        Ok(output)
    }

    /// Synthetic journal fixture bridge, deliberately unavailable to production
    /// callers. Its r19-shaped test binding is not experimental package admission.
    /// Real journal dispatch must consume the distinct admitted package and
    /// authenticate root provenance/availability before publication.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_journal(
        &mut self,
        program: &[u8],
        genesis: &super::journal::AgentJournalGenesis,
        input: &super::journal::ReplayInput,
        before: &super::wire::RuntimeState,
        position: super::replay::ReplayPosition,
        lanes: &[(
            super::journal::LaneStateManifest,
            super::journal::LaneCursor,
        )],
        gas: Gas,
    ) -> Result<super::replay::ReplayExternalExecution, BlockPvmError> {
        let work = Self::journal_work(
            genesis,
            input,
            before,
            position,
            lanes,
            super::package_admission::tests::STATE_FIXTURE_LIMITS,
        )?;
        if program.len() > super::execution::MAX_EXECUTION_PROGRAM_BYTES {
            return Err(BlockPvmError::InvalidRequest);
        }
        if crate::service::ProgramId::of_pvm(program) != input.runtime.program {
            return Err(BlockPvmError::ProgramMismatch);
        }
        let output = self.execute_state(program, &work, gas)?;
        super::replay::ReplayExternalExecution::from_physical_response(
            input, before, position, &work, output,
        )
        .map_err(|_| BlockPvmError::Output)
    }

    fn journal_work(
        genesis: &super::journal::AgentJournalGenesis,
        input: &super::journal::ReplayInput,
        before: &super::wire::RuntimeState,
        position: super::replay::ReplayPosition,
        lanes: &[(
            super::journal::LaneStateManifest,
            super::journal::LaneCursor,
        )],
        limits: crate::agent_sdk::contract::ExternalStateResourceLimits,
    ) -> Result<crate::agent_sdk::state_execution::StateExecutionWork, BlockPvmError> {
        if matches!(
            &input.operation,
            super::journal::ReplayOperation::CleanManage {
                request: crate::agent_sdk::ManagementRequest::Install(_),
                ..
            }
        ) {
            // The journal owner must authenticate the fence itself. This shape
            // check cannot turn an unfenced invocation into management work.
            if !matches!(
                position,
                super::replay::ReplayPosition::Ordered {
                    merge_seal: Some(_),
                    ..
                }
            ) || lanes.iter().any(|(manifest, next)| {
                manifest
                    .external_root
                    .as_ref()
                    .is_none_or(|root| &root.cursor != next)
            }) {
                return Err(BlockPvmError::InvalidRequest);
            }
            return super::state_block_store::journal_state_work_with_limits(
                genesis, input, before, lanes, limits,
            )
            .map_err(|_| BlockPvmError::InvalidRequest);
        }
        if !matches!(
            input.operation,
            super::journal::ReplayOperation::CleanInvoke { .. }
                | super::journal::ReplayOperation::CleanResume { .. }
                | super::journal::ReplayOperation::CleanAcknowledge { .. }
        ) {
            return Err(BlockPvmError::InvalidRequest);
        }
        // One writable Ordered/Local domain, plus explicit read-only bases.
        // Merge mutation still needs its replay-derived successor frontier.
        let owner = lanes
            .iter()
            .find(|(manifest, _)| manifest.lane == input.persisted_lane())
            .ok_or(BlockPvmError::InvalidRequest)?;
        if lanes.iter().any(|(manifest, next)| {
            manifest.lane != input.persisted_lane()
                && manifest
                    .external_root
                    .as_ref()
                    .is_none_or(|root| &root.cursor != next)
        }) || !match (&owner.1, position) {
            (
                super::journal::LaneCursor::Ordered { base },
                super::replay::ReplayPosition::Ordered {
                    id,
                    index,
                    merge_seal: None,
                    ..
                },
            ) => base.index == index && base.head == Some(id),
            (
                super::journal::LaneCursor::Local {
                    node,
                    revision,
                    head,
                },
                super::replay::ReplayPosition::Local {
                    id,
                    node: owner,
                    revision: next,
                    ..
                },
            ) => *node == owner && *revision == next && *head == Some(id),
            _ => false,
        } {
            return Err(BlockPvmError::InvalidRequest);
        }
        super::state_block_store::journal_state_work_with_limits(
            genesis, input, before, lanes, limits,
        )
        .map_err(|_| BlockPvmError::InvalidRequest)
    }

    /// Raw framing hook for fixture/negative tests only. Production callers
    /// must supply an admitted package through execute_admitted_state.
    #[cfg(test)]
    pub(crate) fn execute_state(
        &mut self,
        program: &[u8],
        work: &crate::agent_sdk::state_execution::StateExecutionWork,
        gas: Gas,
    ) -> Result<crate::agent_sdk::state_execution::StateExecutionOutput, BlockPvmError> {
        self.execute_state_bytes(program, work, gas)
    }

    fn execute_state_bytes(
        &mut self,
        program: &[u8],
        work: &crate::agent_sdk::state_execution::StateExecutionWork,
        gas: Gas,
    ) -> Result<crate::agent_sdk::state_execution::StateExecutionOutput, BlockPvmError> {
        use crate::agent_sdk::state_execution::{
            MAX_STATE_EXECUTION_OUTPUT_BYTES, StateExecutionOutput,
        };
        if work.lanes().len() != 1 || work.lanes()[0].base.context().scope() != self.scope {
            return Err(BlockPvmError::InvalidRequest);
        }
        let input = work.encode().map_err(|_| BlockPvmError::InvalidRequest)?;
        let output = self.execute_bytes(program, &input, gas, MAX_STATE_EXECUTION_OUTPUT_BYTES)?;
        StateExecutionOutput::decode_for(&output, work).map_err(|_| BlockPvmError::Output)
    }

    fn fetch(&mut self, id: u64, machine: &mut Machine) -> Result<(), BlockPvmError> {
        if id != u64::from(STATE_BLOCK_FETCH_CALL) {
            return Err(BlockPvmError::UnsupportedCall(id));
        }
        let registers = machine.registers();
        if registers[11] != self.scope.lane() as u64 {
            return Err(BlockPvmError::InvalidRequest);
        }
        let hash_address =
            u32::try_from(registers[7]).map_err(|_| BlockPvmError::InvalidRequest)?;
        let len = u32::try_from(registers[8]).map_err(|_| BlockPvmError::InvalidRequest)?;
        let output = u32::try_from(registers[9]).map_err(|_| BlockPvmError::InvalidRequest)?;
        if len == 0
            || len as usize > MAX_STATE_BLOCK_BYTES
            || registers[10] != u64::from(len)
            || !machine.memory().is_writable(output, len as usize)
        {
            return Err(BlockPvmError::InvalidRequest);
        }
        // Provisional deterministic pricing. Freeze/version it with the new
        // admitted ABI; do not mistake this for measured production pricing.
        if !machine.charge(100 + u64::from(len)) {
            return Err(BlockPvmError::OutOfGas);
        }
        let mut hash = [0; 32];
        if !machine.memory().read_bytes_checked(hash_address, &mut hash) {
            return Err(BlockPvmError::InvalidRequest);
        }
        let reference =
            BlockRef::new(Hash(hash), len).map_err(|e| BlockPvmError::Block(e.into()))?;
        let permit = self
            .budget
            .begin_fetch(self.scope, reference)
            .map_err(|e| BlockPvmError::Block(e.into()))?;
        let mut bytes = vec![0; len as usize];
        let available = self
            .reader
            .read(reference, &mut bytes)
            .map_err(BlockPvmError::Block)?;
        permit
            .verify(available.then_some(bytes.as_slice()))
            .map_err(|e| BlockPvmError::Block(e.into()))?;
        if !machine.memory_mut().write_bytes_checked(output, &bytes) {
            return Err(BlockPvmError::InvalidRequest);
        }
        machine.registers_mut()[7] = 0;
        machine.registers_mut()[8] = u64::from(len);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn execute(
        &mut self,
        program: &[u8],
        input: &[u8],
        gas: Gas,
        max_output: usize,
    ) -> Result<Vec<u8>, BlockPvmError> {
        self.execute_bytes(program, input, gas, max_output)
    }

    fn execute_bytes(
        &mut self,
        program: &[u8],
        input: &[u8],
        gas: Gas,
        max_output: usize,
    ) -> Result<Vec<u8>, BlockPvmError> {
        run_block_program(program, input, gas, max_output, |id, machine| {
            self.fetch(id, machine)
        })
    }
}

fn run_block_program(
    program: &[u8],
    input: &[u8],
    gas: Gas,
    max_output: usize,
    mut fetch: impl FnMut(u64, &mut Machine) -> Result<(), BlockPvmError>,
) -> Result<Vec<u8>, BlockPvmError> {
    let mut failure = None;
    let invocation = RefineContext::load(program, input, gas)
        .map_err(|_| BlockPvmError::Load)?
        .run_with_host(|id, machine| match fetch(id, machine) {
            Ok(()) => Ok(()),
            Err(error) => {
                failure = Some(error);
                Err(ExitReason::Panic)
            }
        });
    if let Some(error) = failure {
        return Err(error);
    }
    if invocation.exit != ExitReason::Halt {
        return Err(BlockPvmError::Exit {
            reason: invocation.exit,
            pc: invocation.pc,
        });
    }
    invocation
        .output_bounded(max_output)
        .ok_or(BlockPvmError::Output)
}

/// Bounded declared-lane dispatch over one store and one aggregate read budget.
/// The guest selects a lane, never an arbitrary scope or storage namespace.
pub(crate) struct MultiLaneStateBlockHost<'a, S: ?Sized> {
    pub store: &'a S,
    pub budget: &'a mut ReadBudget,
}

/// Actual admitted Create response, retaining the exact initial lane declarations.
/// Private construction keeps a caller-supplied response out of this handoff.
/// This is execution evidence only: receipt authentication, root availability,
/// finality and a root-bearing genesis seal are still required before publication.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ExternalCreateExecution {
    create: super::journal::ReplayInputId,
    replica: crate::agent_sdk::AgentReplica,
    work: crate::agent_sdk::state_execution::StateExecutionWork,
    output: crate::agent_sdk::state_execution::StateExecutionOutput,
}

impl ExternalCreateExecution {
    fn from_response(
        runtime: &super::package_admission::AdmittedStateRuntimePackage,
        create: &super::journal::ReplayInput,
        replica: crate::agent_sdk::AgentReplica,
        work: crate::agent_sdk::state_execution::StateExecutionWork,
        output: crate::agent_sdk::state_execution::StateExecutionOutput,
    ) -> Result<Self, BlockPvmError> {
        use crate::agent_sdk::{ManagementReply, ManagementRequest, RuntimeOutcome};
        let super::journal::ReplayOperation::CleanManage {
            request: ManagementRequest::Create(descriptor),
            ..
        } = &create.operation
        else {
            return Err(BlockPvmError::InvalidRequest);
        };
        if super::state_block_store::journal_create_state_work(runtime, create, replica).as_ref()
            != Ok(&work)
            || output.validate_for(&work).is_err()
            || !matches!(&output.transition().outcome,
                RuntimeOutcome::Management(Ok(ManagementReply::Created(identity)))
                    if identity == &descriptor.identity)
        {
            return Err(BlockPvmError::Output);
        }
        Ok(Self {
            create: create.id(),
            replica,
            work,
            output,
        })
    }

    pub(crate) fn matches(
        &self,
        create: &super::journal::ReplayInput,
        replica: crate::agent_sdk::AgentReplica,
    ) -> bool {
        self.create == create.id() && self.replica == replica
    }

    pub(crate) fn work(&self) -> &crate::agent_sdk::state_execution::StateExecutionWork {
        &self.work
    }

    pub(crate) fn output(&self) -> &crate::agent_sdk::state_execution::StateExecutionOutput {
        &self.output
    }
}

impl<S: super::replay::ScopedBlockReader + ?Sized> MultiLaneStateBlockHost<'_, S> {
    /// Multi-lane read selection with one journal-owned writable lane. Replay
    /// validates every supplied base against its pinned materialization before
    /// publication; this method alone provides neither freshness nor a seal.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_admitted_journal(
        &mut self,
        runtime: &super::package_admission::AdmittedStateRuntimePackage,
        genesis: &super::journal::AgentJournalGenesis,
        input: &super::journal::ReplayInput,
        before: &super::wire::RuntimeState,
        position: super::replay::ReplayPosition,
        lanes: &[(
            super::journal::LaneStateManifest,
            super::journal::LaneCursor,
        )],
        gas: Gas,
    ) -> Result<super::replay::ReplayExternalExecution, BlockPvmError> {
        if runtime
            .binding(input.runtime.space, input.runtime.agent)
            .map_err(|_| BlockPvmError::InvalidRequest)?
            != input.runtime
        {
            return Err(BlockPvmError::ProgramMismatch);
        }
        let work =
            StateBlockHost::<super::state_block_store::JournalBlockReader<'_, S>>::journal_work(
                genesis,
                input,
                before,
                position,
                lanes,
                runtime.external_state_limits(),
            )?;
        let output = self.execute_admitted_work(runtime, &work, gas)?;
        super::replay::ReplayExternalExecution::from_physical_response(
            input, before, position, &work, output,
        )
        .map_err(|_| BlockPvmError::Output)
    }

    /// Management, invocation, resume and retirement under an admitted package.
    /// The caller must select
    /// authoritative, revision-consistent roots; this does not mint freshness
    /// evidence, publish state, or infer any private runtime representation.
    pub(crate) fn execute_admitted_work(
        &mut self,
        runtime: &super::package_admission::AdmittedStateRuntimePackage,
        work: &crate::agent_sdk::state_execution::StateExecutionWork,
        gas: Gas,
    ) -> Result<crate::agent_sdk::state_execution::StateExecutionOutput, BlockPvmError> {
        use crate::agent_sdk::{
            ManagementReply, ManagementRequest, RuntimeOutcome, RuntimeWork,
            state_execution::{MAX_STATE_EXECUTION_OUTPUT_BYTES, StateExecutionOutput},
        };
        let (request, runtime_deployment, state) = match work.work() {
            RuntimeWork::Manage {
                request,
                runtime_deployment,
                state,
                ..
            } => (Some(request.as_ref()), *runtime_deployment, state),
            RuntimeWork::Acknowledge {
                invocation, state, ..
            } => (None, invocation.runtime_deployment, state),
            RuntimeWork::Invoke {
                invocation, state, ..
            } => (None, invocation.runtime_deployment, state),
            RuntimeWork::InspectInvocation {
                invocation, state, ..
            } => (None, invocation.runtime_deployment, state),
            // Resume carries only the retained continuation tuple. The
            // admitted package supplies its deployment; journal replay must
            // separately authenticate the original invocation and yield.
            RuntimeWork::Resume { state, .. } => (None, runtime.deployment(), state),
        };
        if !matches!(
            request,
            Some(
                ManagementRequest::InspectActors { .. }
                    | ManagementRequest::InspectResources
                    | ManagementRequest::InspectManagementHistory
                    | ManagementRequest::Install(_)
            ) | None
        ) {
            return Err(BlockPvmError::InvalidRequest);
        }
        let manifest = runtime.manifest();
        let limit = manifest.contract.resources.max_runtime_state_bytes as usize;
        if runtime_deployment != runtime.deployment()
            || work.limits() != runtime.external_state_limits()
            || work.lanes().iter().any(|lane| {
                !manifest
                    .capabilities
                    .lanes
                    .contains(lane.base.context().scope().lane())
            })
            || state.encoded_len().is_none_or(|bytes| bytes > limit)
            || runtime.program_bytes().len() > super::execution::MAX_EXECUTION_PROGRAM_BYTES
        {
            return Err(BlockPvmError::InvalidRequest);
        }
        let input = work.encode().map_err(|_| BlockPvmError::InvalidRequest)?;
        let scopes = work
            .lanes()
            .iter()
            .map(|lane| lane.base.context().scope())
            .collect::<Vec<_>>();
        let bytes = self.execute_scoped_bytes(
            runtime.program_bytes(),
            &input,
            &scopes,
            gas,
            MAX_STATE_EXECUTION_OUTPUT_BYTES,
        )?;
        let output =
            StateExecutionOutput::decode_for(&bytes, work).map_err(|_| BlockPvmError::Output)?;
        if let (
            Some(ManagementRequest::Install(install)),
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(entry))),
        ) = (request, &output.transition().outcome)
        {
            if entry != &install.entry {
                return Err(BlockPvmError::Output);
            }
        }
        if !matches!(
            (work.work(), &output.transition().outcome),
            (
                RuntimeWork::Invoke { .. } | RuntimeWork::Resume { .. },
                RuntimeOutcome::Completed(_) | RuntimeOutcome::Yielded(_)
            ) | (
                RuntimeWork::Acknowledge { .. },
                RuntimeOutcome::Acknowledged(_)
            ) | (
                RuntimeWork::InspectInvocation { .. },
                RuntimeOutcome::Completed(_) | RuntimeOutcome::Acknowledged(_)
            ) | (RuntimeWork::Manage { .. }, RuntimeOutcome::Management(_))
        ) {
            return Err(BlockPvmError::Output);
        }
        if let (RuntimeWork::Invoke { invocation, .. }, RuntimeOutcome::Completed(Ok(reply))) =
            (work.work(), &output.transition().outcome)
        {
            if reply.invocation != invocation.invocation
                || reply.actor != invocation.actor
                || reply.incarnation != invocation.incarnation
                || reply.deployment != invocation.deployment
                || reply.mode != invocation.mode
            {
                return Err(BlockPvmError::Output);
            }
        }
        if let (
            RuntimeWork::InspectInvocation { invocation, .. },
            RuntimeOutcome::Completed(Ok(reply)),
        ) = (work.work(), &output.transition().outcome)
        {
            if reply.invocation != invocation.invocation
                || reply.actor != invocation.actor
                || reply.incarnation != invocation.incarnation
                || reply.deployment != invocation.deployment
                || reply.mode != invocation.mode
            {
                return Err(BlockPvmError::Output);
            }
        }
        if let (
            RuntimeWork::InspectInvocation {
                invocation,
                authorization,
                ..
            },
            RuntimeOutcome::Acknowledged(Ok(reply)),
        ) = (work.work(), &output.transition().outcome)
        {
            if reply.invocation != invocation.invocation
                || reply.actor != invocation.actor
                || reply.incarnation != invocation.incarnation
                || reply.deployment != invocation.deployment
                || reply.mode != invocation.mode
                || reply.work != invocation.commitment()
                || reply.authorization != authorization.commitment()
            {
                return Err(BlockPvmError::Output);
            }
        }
        if let (
            RuntimeWork::Acknowledge {
                invocation,
                authorization,
                ..
            },
            RuntimeOutcome::Acknowledged(Ok(reply)),
        ) = (work.work(), &output.transition().outcome)
        {
            if reply.invocation != invocation.invocation
                || reply.actor != invocation.actor
                || reply.incarnation != invocation.incarnation
                || reply.deployment != invocation.deployment
                || reply.mode != invocation.mode
                || reply.work != invocation.commitment()
                || reply.authorization != authorization.commitment()
            {
                return Err(BlockPvmError::Output);
            }
        }
        if output
            .transition()
            .state
            .encoded_len()
            .is_none_or(|bytes| bytes > limit)
            || !matches!(
                (request, &output.transition().outcome),
                (Some(_), RuntimeOutcome::Management(Err(_)))
                    | (None, RuntimeOutcome::Acknowledged(_))
                    | (None, RuntimeOutcome::Completed(_))
                    | (None, RuntimeOutcome::Yielded(_))
                    | (
                        Some(ManagementRequest::InspectActors { .. }),
                        RuntimeOutcome::Management(Ok(ManagementReply::Actors(_)))
                    )
                    | (
                        Some(ManagementRequest::InspectResources),
                        RuntimeOutcome::Management(Ok(ManagementReply::Resources(_)))
                    )
                    | (
                        Some(ManagementRequest::InspectManagementHistory),
                        RuntimeOutcome::Management(Ok(ManagementReply::ManagementHistory(_)))
                    )
                    | (
                        Some(ManagementRequest::Install(_)),
                        RuntimeOutcome::Management(Ok(ManagementReply::Installed(_)))
                    )
            )
        {
            return Err(BlockPvmError::Output);
        }
        Ok(output)
    }

    /// Execute initial framing only. The lifecycle owner must authenticate the
    /// Create receipt and seal all returned roots before publishing genesis.
    pub(crate) fn execute_admitted_create(
        &mut self,
        runtime: &super::package_admission::AdmittedStateRuntimePackage,
        create: &super::journal::ReplayInput,
        replica: crate::agent_sdk::AgentReplica,
        gas: Gas,
    ) -> Result<ExternalCreateExecution, BlockPvmError> {
        use crate::agent_sdk::state_execution::{
            MAX_STATE_EXECUTION_OUTPUT_BYTES, StateExecutionOutput,
        };
        let work = super::state_block_store::journal_create_state_work(runtime, create, replica)
            .map_err(|_| BlockPvmError::InvalidRequest)?;
        let crate::agent_sdk::RuntimeWork::Manage { state, .. } = work.work() else {
            return Err(BlockPvmError::InvalidRequest);
        };
        if state.encoded_len().is_none_or(|size| {
            size > runtime
                .manifest()
                .contract
                .resources
                .max_runtime_state_bytes as usize
        }) || runtime.program_bytes().len() > super::execution::MAX_EXECUTION_PROGRAM_BYTES
        {
            return Err(BlockPvmError::InvalidRequest);
        }
        let scopes = work
            .lanes()
            .iter()
            .map(|lane| lane.base.context().scope())
            .collect::<Vec<_>>();
        let input = work.encode().map_err(|_| BlockPvmError::InvalidRequest)?;
        let bytes = self.execute_scoped_bytes(
            runtime.program_bytes(),
            &input,
            &scopes,
            gas,
            MAX_STATE_EXECUTION_OUTPUT_BYTES,
        )?;
        let output =
            StateExecutionOutput::decode_for(&bytes, &work).map_err(|_| BlockPvmError::Output)?;
        if output.transition().state.encoded_len().is_none_or(|size| {
            size > runtime
                .manifest()
                .contract
                .resources
                .max_runtime_state_bytes as usize
        }) {
            return Err(BlockPvmError::Output);
        }
        ExternalCreateExecution::from_response(runtime, create, replica, work, output)
    }

    fn execute_scoped_bytes(
        &mut self,
        program: &[u8],
        input: &[u8],
        scopes: &[BlockScope],
        gas: Gas,
        max_output: usize,
    ) -> Result<Vec<u8>, BlockPvmError> {
        if scopes.is_empty()
            || scopes.len() > 3
            || scopes
                .windows(2)
                .any(|pair| pair[0].lane() as u8 >= pair[1].lane() as u8)
            || scopes.iter().any(|scope| {
                (scope.space(), scope.agent()) != (scopes[0].space(), scopes[0].agent())
            })
        {
            return Err(BlockPvmError::InvalidRequest);
        }
        run_block_program(program, input, gas, max_output, |id, machine| {
            let scope = scopes
                .iter()
                .find(|scope| scope.lane() as u64 == machine.registers()[11])
                .copied()
                .ok_or(BlockPvmError::InvalidRequest)?;
            let mut reader = super::state_block_store::JournalBlockReader {
                store: self.store,
                scope,
            };
            StateBlockHost {
                scope,
                reader: &mut reader,
                budget: self.budget,
            }
            .fetch(id, machine)
        })
    }
}

#[cfg(test)]
#[path = "state_block_pvm_lifecycle_tests.rs"]
pub(crate) mod lifecycle_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_sdk::{AgentId, SpaceId, StateLane, state_blocks::BlockError};
    use vos_pvm_compiler::assembler::{Assembler, Reg};
    const BASE: u64 = 2 * vos_pvm::PVM_ZONE_SIZE as u64;
    #[test]
    fn multi_lane_dispatch_scopes_reads_and_shares_one_budget() {
        use super::super::journal_store::{
            AgentJournalStore, JournalBlobClass, MemoryAgentJournalStore,
        };
        let mut store = MemoryAgentJournalStore::new(
            crate::service::AgentId([2; 32]),
            crate::service::NodeId([6; 32]),
        )
        .unwrap();
        let scopes = [StateLane::Linear, StateLane::Merge, StateLane::Local].map(|lane| {
            BlockScope::new(SpaceId([1; 32]), AgentId([2; 32]), Hash([3; 32]), lane).unwrap()
        });
        let payload = b"shared";
        let mut hashes = Vec::new();
        for scope in scopes {
            let (reference, bytes) = scope.encode_block(payload).unwrap();
            store
                .put_blob(
                    JournalBlobClass::StateBlock,
                    &crate::service::BlobRef::of_bytes(&bytes),
                    &bytes,
                )
                .unwrap();
            hashes.extend_from_slice(reference.hash().as_bytes());
        }
        let program = |wrong_lane: bool| {
            let mut asm = Assembler::new();
            let mut data = hashes.clone();
            data.resize(96 + payload.len(), 0);
            asm.set_rw_data(data);
            for (index, scope) in scopes.iter().enumerate() {
                asm.load_imm_64(Reg::A0, BASE + (index * 32) as u64)
                    .load_imm_64(Reg::A1, payload.len() as u64)
                    .load_imm_64(Reg::A2, BASE + 96)
                    .load_imm_64(Reg::A3, payload.len() as u64)
                    .load_imm_64(
                        Reg::A4,
                        if wrong_lane && index == 2 {
                            StateLane::Linear as u64
                        } else {
                            scope.lane() as u64
                        },
                    )
                    .ecalli(STATE_BLOCK_FETCH_CALL);
            }
            asm.load_imm_64(Reg::A0, BASE + 96)
                .load_imm_64(Reg::A1, payload.len() as u64)
                .jump_ind(Reg::RA, 0);
            asm.build_standard()
        };
        let run = |program: &[u8], scopes: &[BlockScope], fetches, bytes| {
            MultiLaneStateBlockHost {
                store: &store,
                budget: &mut ReadBudget::new(fetches, bytes),
            }
            .execute_scoped_bytes(program, &[], scopes, 100000, 100)
        };
        assert_eq!(run(&program(false), &scopes, 3, 18).unwrap(), payload);
        assert!(matches!(
            run(&program(false), &scopes, 2, 18),
            Err(BlockPvmError::Block(TreeError::Block(
                BlockError::BudgetExceeded
            )))
        ));
        assert!(matches!(
            run(&program(false), &scopes, 3, 17),
            Err(BlockPvmError::Block(TreeError::Block(
                BlockError::BudgetExceeded
            )))
        ));
        assert!(run(&program(true), &scopes, 3, 18).is_err());
        assert!(matches!(
            run(&program(false), &scopes[..2], 3, 18),
            Err(BlockPvmError::InvalidRequest)
        ));
        assert!(matches!(
            run(&program(false), &[scopes[0], scopes[0]], 3, 18),
            Err(BlockPvmError::InvalidRequest)
        ));
    }

    #[test]
    #[ignore = "requires build-agent-state-probe"]
    fn compiled_create_initializes_all_declared_lanes_without_publishing_genesis() {
        use super::super::{
            journal_store::{AgentJournalStore, MemoryAgentJournalStore},
            state_block_store::{StateBlockStaging, journal_create_state_work},
        };
        let admitted =
            super::super::package_admission::tests::admitted_state_fixture(compiled_program());
        let (create, replica, _) = super::super::replay::tests::external_create_fixture(&admitted);
        let mut store = MemoryAgentJournalStore::new(
            create.runtime.agent,
            crate::service::NodeId(replica.node.0),
        )
        .unwrap();
        let work = journal_create_state_work(&admitted, &create, replica).unwrap();
        assert!(
            MultiLaneStateBlockHost {
                store: &store,
                budget: &mut ReadBudget::new(0, 0)
            }
            .execute_admitted_create(&admitted, &create, replica, 0)
            .is_err()
        );
        // Empty Create input consumes zero state bytes; positive limits are
        // enforced against the produced state, not framing overhead.
        for limit in [1, 32] {
            let limited = super::super::package_admission::tests::admitted_state_fixture_limits(
                admitted.program_bytes().to_vec(),
                crate::agent_sdk::LaneSet::ALL,
                limit,
            );
            let (limited_create, limited_replica, _) =
                super::super::replay::tests::external_create_fixture(&limited);
            assert_eq!(
                MultiLaneStateBlockHost {
                    store: &store,
                    budget: &mut ReadBudget::new(0, 0)
                }
                .execute_admitted_create(
                    &limited,
                    &limited_create,
                    limited_replica,
                    1_000_000_000
                ),
                Err(BlockPvmError::Output)
            );
        }
        let captured = MultiLaneStateBlockHost {
            store: &store,
            budget: &mut ReadBudget::new(0, 0),
        }
        .execute_admitted_create(&admitted, &create, replica, 1_000_000_000)
        .unwrap();
        assert!(captured.matches(&create, replica));
        assert_eq!(captured.work(), &work);
        let mut other_replica = replica;
        other_replica.node.0[0] ^= 1;
        assert!(!captured.matches(&create, other_replica));
        let mut other_create = create.clone();
        other_create.runtime.program.0[0] ^= 1;
        assert!(!captured.matches(&other_create, replica));
        let output = captured.output();
        // Framing alone permits a structurally valid reply naming another
        // identity. The physical Create handoff must reject that reply.
        let mut wrong_transition = output.transition().clone();
        let crate::agent_sdk::RuntimeOutcome::Management(Ok(
            crate::agent_sdk::ManagementReply::Created(identity),
        )) = &mut wrong_transition.outcome
        else {
            panic!("expected Create reply");
        };
        identity.agent.0[0] ^= 1;
        let wrong_output = crate::agent_sdk::state_execution::StateExecutionOutput::new(
            &work,
            wrong_transition,
            output.changes().to_vec(),
        )
        .unwrap();
        assert_eq!(
            ExternalCreateExecution::from_response(
                &admitted,
                &create,
                replica,
                work.clone(),
                wrong_output
            ),
            Err(BlockPvmError::Output)
        );
        assert_eq!(
            ExternalCreateExecution::from_response(
                &admitted,
                &other_create,
                replica,
                work.clone(),
                output.clone(),
            ),
            Err(BlockPvmError::Output)
        );
        assert_eq!(output.changes().len(), 3);
        assert!(matches!(
            output.transition().outcome,
            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::Created(_)
            ))
        ));
        for (lane, change) in work.lanes().iter().zip(output.changes()) {
            let mut session = StateBlockStaging::audit_base(
                &mut store,
                lane.base,
                lane.base.context(),
                lane.base.commitment(),
                &mut ReadBudget::new(0, 0),
            )
            .unwrap();
            session
                .stage_next(change, lane.next, &mut ReadBudget::new(100, 100000))
                .unwrap();
            assert_eq!(session.available(), change.next());
            let descriptor = change.next();
            let tree = descriptor
                .bind(descriptor.context(), descriptor.commitment())
                .unwrap();
            let mut reader = super::super::state_block_store::JournalBlockReader {
                store: &store,
                scope: tree.scope(),
            };
            assert_eq!(
                crate::agent_sdk::state_rows::lane_row_usage(
                    tree,
                    &mut reader,
                    &mut ReadBudget::new(100, 100000),
                )
                .unwrap(),
                crate::agent_sdk::state_rows::RowUsage { rows: 1, bytes: 14 }
            );
        }
        assert!(store.heads().unwrap().is_none());
        assert!(store.genesis().unwrap().is_none());
    }
    #[derive(Default)]
    struct Store {
        blocks: std::collections::BTreeMap<[u8; 32], Vec<u8>>,
        calls: u32,
        bytes: u64,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum PhysicalStateSize {
        Ordinary,
        ExactSignedLimit,
        NearCeiling,
    }

    #[test]
    #[ignore = "requires just build-agent-standard-state-guest"]
    fn compiled_standard_ack_retires_metadata_without_changing_rows() {
        standard_external_execution_fixture(false, false, PhysicalStateSize::Ordinary);
    }

    #[test]
    #[ignore = "requires just build-agent-standard-state-guest"]
    fn compiled_standard_ack_at_exact_signed_state_limit() {
        standard_external_execution_fixture(false, false, PhysicalStateSize::ExactSignedLimit);
    }

    #[test]
    #[ignore = "requires just build-agent-standard-state-guest"]
    fn compiled_standard_ack_near_signed_state_limit() {
        standard_external_execution_fixture(false, false, PhysicalStateSize::NearCeiling);
    }

    #[test]
    #[ignore = "requires just build-agent-standard-state-guest"]
    fn compiled_standard_invoke_reads_and_commits_external_rows() {
        standard_external_execution_fixture(true, false, PhysicalStateSize::Ordinary);
    }

    #[test]
    #[ignore = "requires just build-agent-standard-state-guest"]
    fn compiled_standard_external_yield_publishes_neither_rows_nor_continuation() {
        standard_external_execution_fixture(true, true, PhysicalStateSize::Ordinary);
    }

    fn standard_external_execution_fixture(invoke: bool, yielded: bool, size: PhysicalStateSize) {
        use super::super::{
            actor_storage::tests::TestBlocks,
            journal_store::{AgentJournalStore, MemoryAgentJournalStore},
            state_block_store::{JournalBlockReader, StateBlockStaging},
        };
        use crate::agent_sdk::{
            Hash, RuntimeExecutionContext, RuntimeOutcome, RuntimeWork, StateLane,
            state_blocks::BlockScope,
            state_change::StateChange,
            state_execution::{ExternalLaneWork, StateExecutionWork},
            state_metadata::{RuntimeMetadataUpdate, read_runtime_metadata},
            state_root::{RootContext, StateRootDescriptor},
            state_rows::{ActorRows, RowUsage, lane_row_usage},
            state_tree::{StateTree, WriteBudget},
        };
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"));
        let program = vos_pvm_compiler::link_elf_spi(
            &std::fs::read(
                target.join("agent-state-standard/riscv64em-vos/release/agent_runtime.elf"),
            )
            .expect("build experimental standard guest first"),
        )
        .unwrap();
        let mut admitted =
            super::super::package_admission::tests::admitted_state_fixture(program.clone());
        // Synthetic installed-state seed, not authenticated genesis/recovery.
        let mut inner = if invoke {
            super::super::wire::tests::external_invocation_fixture(&admitted, yielded)
        } else {
            let (state, retirement, authorization) = if size == PhysicalStateSize::NearCeiling {
                super::super::wire::tests::external_retirement_fixture_near_state_limit(&admitted)
            } else {
                super::super::wire::tests::external_retirement_fixture(&admitted)
            };
            RuntimeWork::Acknowledge {
                context: RuntimeExecutionContext::Direct,
                state,
                invocation: alloc::boxed::Box::new(retirement),
                authorization: alloc::boxed::Box::new(authorization),
            }
        };
        let mut native = super::super::wire::apply_standard_runtime_work(inner.clone()).unwrap();
        if size == PhysicalStateSize::ExactSignedLimit {
            assert!(!invoke && !yielded);
            let RuntimeWork::Acknowledge { state, .. } = &inner else {
                unreachable!()
            };
            let limit = state
                .encoded_len()
                .unwrap()
                .max(native.state.encoded_len().unwrap());
            admitted = super::super::package_admission::tests::admitted_state_fixture_limits(
                program,
                crate::agent_sdk::LaneSet::ALL,
                limit as u32,
            );
            let (state, retirement, authorization) =
                super::super::wire::tests::external_retirement_fixture(&admitted);
            inner = RuntimeWork::Acknowledge {
                context: RuntimeExecutionContext::Direct,
                state,
                invocation: alloc::boxed::Box::new(retirement),
                authorization: alloc::boxed::Box::new(authorization),
            };
            native = super::super::wire::apply_standard_runtime_work(inner.clone()).unwrap();
            let RuntimeWork::Acknowledge { state, .. } = &inner else {
                unreachable!()
            };
            assert_eq!(
                admitted
                    .manifest()
                    .contract
                    .resources
                    .max_runtime_state_bytes as usize,
                state
                    .encoded_len()
                    .unwrap()
                    .max(native.state.encoded_len().unwrap())
            );
        }
        assert!(matches!(
            native.outcome,
            RuntimeOutcome::Completed(Ok(_))
                | RuntimeOutcome::Acknowledged(Ok(_))
                | RuntimeOutcome::Yielded(_)
        ));
        native.state = super::super::wire::tests::external_test_metadata_only(&native.state);
        let (original, retirement) = match &inner {
            RuntimeWork::Invoke {
                state, invocation, ..
            } => (
                state,
                crate::agent_sdk::InvocationRetirement::from_work(invocation),
            ),
            RuntimeWork::Acknowledge {
                state, invocation, ..
            } => (state, invocation.as_ref().clone()),
            _ => unreachable!(),
        };
        let native_state = super::super::wire::tests::external_test_metadata_only(original);
        let key: &[u8] = if invoke { b"s/rows/value" } else { b"row" };
        let before_row = if invoke { vec![9; 8] } else { vec![9] };
        let after_row = if invoke { vec![7; 8] } else { vec![9] };
        let mut store = MemoryAgentJournalStore::new(
            crate::agent::AgentId(retirement.agent.0),
            crate::service::NodeId([0x51; 32]),
        )
        .unwrap();
        let mut state = native_state.clone();
        let mut lanes = Vec::new();
        for lane in [StateLane::Linear, StateLane::Merge, StateLane::Local] {
            let scope = BlockScope::new(retirement.space, retirement.agent, Hash([0x52; 32]), lane)
                .unwrap();
            let context = RootContext::new(scope, Hash([0x53; 32]), Hash([0x54; 32])).unwrap();
            let base = StateRootDescriptor::new(context, None);
            let batch = ActorRows::new(
                StateTree::empty(scope),
                retirement.actor,
                retirement.incarnation,
            )
            .unwrap()
            .update_accounted_with_metadata(
                &if !invoke || lane == StateLane::Linear {
                    vec![(key.to_vec(), Some(before_row.clone()))]
                } else {
                    Vec::new()
                },
                admitted.external_state_limits(),
                RuntimeMetadataUpdate::new(
                    native_state.component(lane),
                    crate::agent_sdk::MAX_RUNTIME_STATE_BYTES,
                )
                .unwrap(),
                &mut TestBlocks::default(),
                (
                    &mut ReadBudget::new(10000, 10000000),
                    &mut WriteBudget::new(10000, 10000000),
                ),
            )
            .unwrap();
            let change =
                StateChange::from_update(base.commitment(), context, batch.update).unwrap();
            let mut staging = StateBlockStaging::audit_base(
                &mut store,
                base,
                context,
                base.commitment(),
                &mut ReadBudget::new(0, 0),
            )
            .unwrap();
            staging
                .stage_next(&change, context, &mut ReadBudget::new(10000, 10000000))
                .unwrap();
            let base = change.next();
            match lane {
                StateLane::Linear => state.linear = base.encode(),
                StateLane::Merge => state.merge = base.encode(),
                StateLane::Local => state.local = base.encode(),
            }
            lanes.push(ExternalLaneWork {
                base,
                next: RootContext::new(scope, Hash([0x53; 32]), Hash([0x55; 32])).unwrap(),
            });
        }
        match &mut inner {
            RuntimeWork::Invoke { state: target, .. }
            | RuntimeWork::Acknowledge { state: target, .. } => *target = state.clone(),
            _ => unreachable!(),
        }
        let work = StateExecutionWork::new(inner, lanes, admitted.external_state_limits()).unwrap();
        // Qualify a near-ceiling ACK against the currently configured
        // management budget, not an arbitrarily generous test allowance.
        let gas = if size == PhysicalStateSize::NearCeiling {
            super::super::driver::DEFAULT_MANAGEMENT_GAS
        } else {
            1_000_000_000
        };
        let started = std::time::Instant::now();
        let acknowledged = MultiLaneStateBlockHost {
            store: &store,
            budget: &mut ReadBudget::new(10000, 10000000),
        }
        .execute_admitted_work(&admitted, &work, gas)
        .unwrap();
        if size == PhysicalStateSize::NearCeiling {
            let RuntimeWork::Acknowledge { state, .. } = work.work() else {
                unreachable!()
            };
            eprintln!(
                "near-ceiling external ACK: root_frame_bytes={} gas_budget={} physical_elapsed_ms={}",
                state.encoded_len().unwrap(),
                gas,
                started.elapsed().as_millis(),
            );
        }
        if yielded {
            let RuntimeOutcome::Yielded(prior) = &native.outcome else {
                panic!("native fixture did not yield");
            };
            // A Resume without the retained guest continuation must fail
            // without publication, but it must reach the physical guest. This
            // guards the host's Resume admission separately from the journal's
            // stronger retained-yield and authorization checks.
            let RuntimeWork::Invoke { invocation, .. } = work.work() else {
                unreachable!()
            };
            let resume = crate::agent_sdk::ResumeWork {
                invocation: prior.invocation,
                actor: prior.actor,
                incarnation: prior.incarnation,
                deployment: prior.deployment,
                program: prior.program,
                mode: prior.mode,
                continuation: prior.continuation.clone(),
                ready_sequence: prior.ready_sequence,
                installation_data: prior.installation_data.clone(),
                availability: invocation.availability.clone(),
                input: None,
            };
            let read_only_lanes = work
                .lanes()
                .iter()
                .map(|lane| ExternalLaneWork {
                    base: lane.base,
                    next: lane.base.context(),
                })
                .collect();
            let resume = StateExecutionWork::new(
                RuntimeWork::Resume {
                    context: RuntimeExecutionContext::Direct,
                    state: state.clone(),
                    resume: Box::new(resume),
                },
                read_only_lanes,
                admitted.external_state_limits(),
            )
            .unwrap();
            let missing = MultiLaneStateBlockHost {
                store: &store,
                budget: &mut ReadBudget::new(10000, 10000000),
            }
            .execute_admitted_work(&admitted, &resume, gas)
            .unwrap();
            assert!(matches!(
                missing.transition().outcome,
                RuntimeOutcome::Completed(Err(_))
            ));
            assert_eq!(missing.transition().state, state);
            assert!(missing.changes().is_empty());
            assert_eq!(
                acknowledged.transition().outcome,
                RuntimeOutcome::Completed(Err(
                    crate::agent_sdk::InvocationError::InvalidAvailability
                ))
            );
            assert_eq!(acknowledged.transition().state, state);
            assert!(acknowledged.changes().is_empty());
            assert!(store.heads().unwrap().is_none());
            assert!(store.genesis().unwrap().is_none());
            return;
        }
        assert_eq!(acknowledged.transition().outcome, native.outcome);
        assert_eq!(acknowledged.changes().len(), 1);
        assert_eq!(
            acknowledged.changes()[0].next().context().scope().lane(),
            StateLane::Linear
        );
        assert!(
            MultiLaneStateBlockHost {
                store: &store,
                budget: &mut ReadBudget::new(0, 0),
            }
            .execute_admitted_work(&admitted, &work, gas)
            .is_err()
        );
        let mut bad = work.work().clone();
        match &mut bad {
            RuntimeWork::Invoke { invocation, .. } => invocation.message.push(0),
            RuntimeWork::Acknowledge { invocation, .. } => invocation.message.push(0),
            _ => unreachable!(),
        }
        assert!(
            StateExecutionWork::new(bad, work.lanes().to_vec(), admitted.external_state_limits())
                .is_err()
        );
        let mut bad = work.work().clone();
        let (RuntimeWork::Acknowledge { authorization, .. }
        | RuntimeWork::Invoke { authorization, .. }) = &mut bad
        else {
            unreachable!()
        };
        let crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(receipt) =
            authorization.as_mut()
        else {
            unreachable!()
        };
        receipt.signature[0] ^= 1;
        let bad =
            StateExecutionWork::new(bad, work.lanes().to_vec(), admitted.external_state_limits())
                .unwrap();
        let denied = MultiLaneStateBlockHost {
            store: &store,
            budget: &mut ReadBudget::new(10000, 10000000),
        }
        .execute_admitted_work(&admitted, &bad, gas)
        .unwrap();
        assert!(matches!(
            denied.transition().outcome,
            RuntimeOutcome::Acknowledged(Err(_)) | RuntimeOutcome::Completed(Err(_))
        ));
        assert_eq!(denied.transition().state, state);
        assert!(denied.changes().is_empty());
        let mut restored = acknowledged.transition().state.clone();
        let mut retry_lanes = Vec::new();
        for lane in work.lanes() {
            let root = if let Some(change) = acknowledged.changes().iter().find(|change| {
                change.next().context().scope().lane() == lane.base.context().scope().lane()
            }) {
                let mut staging = StateBlockStaging::audit_base(
                    &mut store,
                    lane.base,
                    lane.base.context(),
                    lane.base.commitment(),
                    &mut ReadBudget::new(10000, 10000000),
                )
                .unwrap();
                staging
                    .stage_next(change, lane.next, &mut ReadBudget::new(10000, 10000000))
                    .unwrap();
                change.next()
            } else {
                lane.base
            };
            let tree = root.bind(root.context(), root.commitment()).unwrap();
            let mut reader = JournalBlockReader {
                store: &store,
                scope: tree.scope(),
            };
            assert_eq!(
                lane_row_usage(tree, &mut reader, &mut ReadBudget::new(10000, 10000000)).unwrap(),
                if !invoke || tree.scope().lane() == StateLane::Linear {
                    RowUsage {
                        rows: 1,
                        bytes: (key.len() + after_row.len()) as u64,
                    }
                } else {
                    RowUsage::default()
                }
            );
            assert_eq!(
                ActorRows::new(tree, retirement.actor, retirement.incarnation)
                    .unwrap()
                    .get(key, &mut reader, &mut ReadBudget::new(10000, 10000000))
                    .unwrap(),
                if !invoke || tree.scope().lane() == StateLane::Linear {
                    Some(after_row.clone())
                } else {
                    None
                }
            );
            let metadata = read_runtime_metadata(
                tree,
                crate::agent_sdk::MAX_RUNTIME_STATE_BYTES,
                &mut reader,
                &mut ReadBudget::new(10000, 10000000),
            )
            .unwrap()
            .unwrap();
            match tree.scope().lane() {
                StateLane::Linear => restored.linear = metadata,
                StateLane::Merge => restored.merge = metadata,
                StateLane::Local => restored.local = metadata,
            }
            retry_lanes.push(ExternalLaneWork {
                base: root,
                next: root.context(),
            });
        }
        assert_eq!(restored, native.state);
        let mut retry = work.work().clone();
        let (RuntimeWork::Acknowledge { state, .. } | RuntimeWork::Invoke { state, .. }) =
            &mut retry
        else {
            unreachable!()
        };
        *state = acknowledged.transition().state.clone();
        let retry =
            StateExecutionWork::new(retry, retry_lanes, admitted.external_state_limits()).unwrap();
        let repeated = MultiLaneStateBlockHost {
            store: &store,
            budget: &mut ReadBudget::new(10000, 10000000),
        }
        .execute_admitted_work(&admitted, &retry, gas)
        .unwrap();
        assert_eq!(repeated.transition(), acknowledged.transition());
        assert!(repeated.changes().is_empty());
        assert!(store.heads().unwrap().is_none());
        assert!(store.genesis().unwrap().is_none());
    }

    #[test]
    #[ignore = "requires just build-agent-standard-state-guest"]
    fn compiled_standard_create_owns_metadata_and_checks_real_authority() {
        use super::super::{
            journal_store::{AgentJournalStore, MemoryAgentJournalStore},
            state_block_store::{JournalBlockReader, StateBlockStaging, journal_create_state_work},
        };
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"));
        let path = target.join("agent-state-standard/riscv64em-vos/release/agent_runtime.elf");
        let program = vos_pvm_compiler::link_elf_spi(
            &std::fs::read(&path).expect("build experimental standard guest first"),
        )
        .unwrap();
        let admitted = super::super::package_admission::tests::admitted_state_fixture(program);
        let (create, replica, _) = super::super::replay::tests::external_create_fixture(&admitted);
        let work = journal_create_state_work(&admitted, &create, replica).unwrap();
        let expected =
            super::super::wire::apply_standard_runtime_work(work.work().clone()).unwrap();
        assert!(matches!(
            expected.outcome,
            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::Created(_)
            ))
        ));
        let expected_frame =
            super::super::wire::apply_standard_external_runtime_input(&work.encode().unwrap())
                .unwrap();
        let mut store = MemoryAgentJournalStore::new(
            create.runtime.agent,
            crate::service::NodeId(replica.node.0),
        )
        .unwrap();
        let capture = MultiLaneStateBlockHost {
            store: &store,
            budget: &mut ReadBudget::new(0, 0),
        }
        .execute_admitted_create(&admitted, &create, replica, 1_000_000_000)
        .unwrap();
        assert_eq!(capture.output().encode().unwrap(), expected_frame);
        let mut restored = capture.output().transition().state.clone();
        for (lane, change) in work.lanes().iter().zip(capture.output().changes()) {
            let mut staging = StateBlockStaging::audit_base(
                &mut store,
                lane.base,
                lane.base.context(),
                lane.base.commitment(),
                &mut ReadBudget::new(0, 0),
            )
            .unwrap();
            staging
                .stage_next(change, lane.next, &mut ReadBudget::new(1000, 1000000))
                .unwrap();
            drop(staging);
            let root = change.next();
            let tree = root.bind(root.context(), root.commitment()).unwrap();
            let mut reader = JournalBlockReader {
                store: &store,
                scope: tree.scope(),
            };
            let metadata = crate::agent_sdk::state_metadata::read_runtime_metadata(
                tree,
                crate::agent_sdk::MAX_RUNTIME_STATE_BYTES,
                &mut reader,
                &mut ReadBudget::new(1000, 1000000),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                crate::agent_sdk::state_rows::lane_row_usage(
                    tree,
                    &mut reader,
                    &mut ReadBudget::new(1000, 1000000)
                )
                .unwrap(),
                crate::agent_sdk::state_rows::RowUsage::default()
            );
            match tree.scope().lane() {
                crate::agent_sdk::StateLane::Linear => restored.linear = metadata,
                crate::agent_sdk::StateLane::Merge => restored.merge = metadata,
                crate::agent_sdk::StateLane::Local => restored.local = metadata,
            }
        }
        assert_eq!(restored, expected.state);
        let decoded =
            super::super::wire::decode_standard_runtime_state(&super::super::wire::RuntimeState {
                control: restored.control,
                linear: restored.linear,
                merge: restored.merge,
                local: restored.local,
            })
            .unwrap();
        assert!(decoded.clean_descriptor.is_some());
        // Reopen all lane metadata in the actual standard guest, with no host
        // decode/restore fallback and no mutable publication path.
        for request in [
            crate::agent_sdk::ManagementRequest::InspectResources,
            crate::agent_sdk::ManagementRequest::InspectActors {
                after: None,
                limit: 16,
            },
            crate::agent_sdk::ManagementRequest::InspectManagementHistory,
        ] {
            let mut inner = work.work().clone();
            let crate::agent_sdk::RuntimeWork::Manage {
                request: selected,
                state,
                authority,
                ..
            } = &mut inner
            else {
                unreachable!()
            };
            *selected = alloc::boxed::Box::new(request);
            *state = expected.state.clone();
            *authority = None;
            let native = super::super::wire::apply_standard_runtime_work(inner.clone()).unwrap();
            let crate::agent_sdk::RuntimeWork::Manage { state, .. } = &mut inner else {
                unreachable!()
            };
            *state = capture.output().transition().state.clone();
            let inspection = crate::agent_sdk::state_execution::StateExecutionWork::new(
                inner,
                capture
                    .output()
                    .changes()
                    .iter()
                    .map(
                        |change| crate::agent_sdk::state_execution::ExternalLaneWork {
                            base: change.next(),
                            next: change.next().context(),
                        },
                    )
                    .collect(),
                admitted.external_state_limits(),
            )
            .unwrap();
            let mut budget = ReadBudget::new(1000, 1000000);
            let result = MultiLaneStateBlockHost {
                store: &store,
                budget: &mut budget,
            }
            .execute_admitted_work(&admitted, &inspection, 1_000_000_000)
            .unwrap();
            assert!(budget.remaining().0 < 1000);
            assert_eq!(result.transition().outcome, native.outcome);
            assert_eq!(
                result.transition().state,
                capture.output().transition().state
            );
            assert!(result.changes().is_empty());
            assert!(
                MultiLaneStateBlockHost {
                    store: &store,
                    budget: &mut ReadBudget::new(0, 0)
                }
                .execute_admitted_work(&admitted, &inspection, 1_000_000_000)
                .is_err()
            );
            let unavailable = MemoryAgentJournalStore::new(
                create.runtime.agent,
                crate::service::NodeId(replica.node.0),
            )
            .unwrap();
            assert!(
                MultiLaneStateBlockHost {
                    store: &unavailable,
                    budget: &mut ReadBudget::new(1000, 1000000)
                }
                .execute_admitted_work(&admitted, &inspection, 1_000_000_000)
                .is_err()
            );
            let mut limits = admitted.external_state_limits();
            limits.max_rows_per_lane += 1;
            let substituted = crate::agent_sdk::state_execution::StateExecutionWork::new(
                inspection.work().clone(),
                inspection.lanes().to_vec(),
                limits,
            )
            .unwrap();
            assert_eq!(
                MultiLaneStateBlockHost {
                    store: &store,
                    budget: &mut ReadBudget::new(0, 0)
                }
                .execute_admitted_work(&admitted, &substituted, 0),
                Err(BlockPvmError::InvalidRequest)
            );
        }
        // Install through the physical standard guest, then reload its metadata
        // and retry the exact signed decision. These are fixture-selected roots,
        // not a journal seal or a production Authority admission.
        let descriptor = decoded.clean_descriptor.as_ref().unwrap();
        let install = super::super::wire::tests::clean_install_request(
            descriptor,
            "external-install",
            None,
            0x72,
            descriptor.capabilities.lanes,
        );
        let request = crate::agent_sdk::ManagementRequest::Install(alloc::boxed::Box::new(install));
        let authority = super::super::replay::tests::signed_opaque_clean_receipt(
            descriptor,
            &request,
            descriptor.identity.runtime_deployment,
            2,
            &ed25519_dalek::SigningKey::from_bytes(&[0x31; 32]),
        );
        let mut inner = work.work().clone();
        let crate::agent_sdk::RuntimeWork::Manage {
            request: selected,
            state,
            authority: receipt,
            observed_slot,
            ..
        } = &mut inner
        else {
            unreachable!()
        };
        *selected = alloc::boxed::Box::new(request);
        *receipt = Some(alloc::boxed::Box::new(authority));
        *observed_slot = 11;
        *state = expected.state.clone();
        let native = super::super::wire::apply_standard_runtime_work(inner.clone()).unwrap();
        assert!(matches!(
            native.outcome,
            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::Installed(_)
            ))
        ));
        let crate::agent_sdk::RuntimeWork::Manage { state, .. } = &mut inner else {
            unreachable!()
        };
        *state = capture.output().transition().state.clone();
        let lanes = capture
            .output()
            .changes()
            .iter()
            .map(|change| {
                let base = change.next();
                crate::agent_sdk::state_execution::ExternalLaneWork {
                    base,
                    next: crate::agent_sdk::state_root::RootContext::new(
                        base.context().scope(),
                        crate::agent_sdk::Hash([0x81; 32]),
                        crate::agent_sdk::Hash([0x82; 32]),
                    )
                    .unwrap(),
                }
            })
            .collect::<Vec<_>>();
        let install_work = crate::agent_sdk::state_execution::StateExecutionWork::new(
            inner,
            lanes,
            admitted.external_state_limits(),
        )
        .unwrap();
        let installed = MultiLaneStateBlockHost {
            store: &store,
            budget: &mut ReadBudget::new(10000, 10000000),
        }
        .execute_admitted_work(&admitted, &install_work, 1_000_000_000)
        .unwrap();
        assert_eq!(installed.transition().outcome, native.outcome);
        assert!(installed.changes().is_empty());
        assert_ne!(
            installed.transition().state.control,
            capture.output().transition().state.control
        );
        let mut recovered = installed.transition().state.clone();
        for lane in install_work.lanes() {
            let root = lane.base;
            let tree = root.bind(root.context(), root.commitment()).unwrap();
            let mut reader = JournalBlockReader {
                store: &store,
                scope: tree.scope(),
            };
            let metadata = crate::agent_sdk::state_metadata::read_runtime_metadata(
                tree,
                crate::agent_sdk::MAX_RUNTIME_STATE_BYTES,
                &mut reader,
                &mut ReadBudget::new(10000, 10000000),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                crate::agent_sdk::state_rows::lane_row_usage(
                    tree,
                    &mut reader,
                    &mut ReadBudget::new(10000, 10000000),
                )
                .unwrap(),
                crate::agent_sdk::state_rows::RowUsage::default()
            );
            match tree.scope().lane() {
                crate::agent_sdk::StateLane::Linear => recovered.linear = metadata,
                crate::agent_sdk::StateLane::Merge => recovered.merge = metadata,
                crate::agent_sdk::StateLane::Local => recovered.local = metadata,
            }
        }
        assert_eq!(recovered, native.state);
        let mut retry = install_work.work().clone();
        let crate::agent_sdk::RuntimeWork::Manage { state, .. } = &mut retry else {
            unreachable!()
        };
        *state = installed.transition().state.clone();
        let retry_lanes = install_work
            .lanes()
            .iter()
            .map(|lane| {
                let base = installed
                    .changes()
                    .iter()
                    .find(|change| {
                        change.next().context().scope().lane() == lane.base.context().scope().lane()
                    })
                    .map_or(lane.base, |change| change.next());
                crate::agent_sdk::state_execution::ExternalLaneWork {
                    base,
                    next: base.context(),
                }
            })
            .collect();
        let retry = crate::agent_sdk::state_execution::StateExecutionWork::new(
            retry,
            retry_lanes,
            admitted.external_state_limits(),
        )
        .unwrap();
        let retried = MultiLaneStateBlockHost {
            store: &store,
            budget: &mut ReadBudget::new(10000, 10000000),
        }
        .execute_admitted_work(&admitted, &retry, 1_000_000_000)
        .unwrap();
        assert_eq!(retried.transition(), installed.transition());
        assert!(retried.changes().is_empty());
        let mut inspect = retry.work().clone();
        let crate::agent_sdk::RuntimeWork::Manage {
            request, authority, ..
        } = &mut inspect
        else {
            unreachable!()
        };
        *request = alloc::boxed::Box::new(crate::agent_sdk::ManagementRequest::InspectActors {
            after: None,
            limit: 16,
        });
        *authority = None;
        let inspect = crate::agent_sdk::state_execution::StateExecutionWork::new(
            inspect,
            retry.lanes().to_vec(),
            admitted.external_state_limits(),
        )
        .unwrap();
        let directory = MultiLaneStateBlockHost {
            store: &store,
            budget: &mut ReadBudget::new(10000, 10000000),
        }
        .execute_admitted_work(&admitted, &inspect, 1_000_000_000)
        .unwrap();
        let crate::agent_sdk::RuntimeOutcome::Management(Ok(
            crate::agent_sdk::ManagementReply::Actors(page),
        )) = &directory.transition().outcome
        else {
            panic!("installed actor must be visible through the standard guest directory");
        };
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].entry.name, "external-install");
        assert_eq!(directory.transition().state, installed.transition().state);
        assert!(directory.changes().is_empty());
        let mut bad_install = install_work.work().clone();
        let crate::agent_sdk::RuntimeWork::Manage { authority, .. } = &mut bad_install else {
            unreachable!()
        };
        authority.as_mut().unwrap().signature[0] ^= 1;
        let bad_install = crate::agent_sdk::state_execution::StateExecutionWork::new(
            bad_install,
            install_work.lanes().to_vec(),
            admitted.external_state_limits(),
        )
        .unwrap();
        let denied = MultiLaneStateBlockHost {
            store: &store,
            budget: &mut ReadBudget::new(10000, 10000000),
        }
        .execute_admitted_work(&admitted, &bad_install, 1_000_000_000)
        .unwrap();
        assert!(matches!(
            denied.transition().outcome,
            crate::agent_sdk::RuntimeOutcome::Management(Err(_))
        ));
        assert_eq!(
            denied.transition().state,
            capture.output().transition().state
        );
        assert!(denied.changes().is_empty());
        assert!(store.heads().unwrap().is_none());
        assert!(store.genesis().unwrap().is_none());
        let mut unauthorized = create.clone();
        let super::super::journal::ReplayOperation::CleanManage { authority, .. } =
            &mut unauthorized.operation
        else {
            unreachable!()
        };
        authority.signature[0] ^= 1;
        assert!(matches!(
            MultiLaneStateBlockHost {
                store: &store,
                budget: &mut ReadBudget::new(0, 0)
            }
            .execute_admitted_create(&admitted, &unauthorized, replica, 1_000_000_000),
            Err(BlockPvmError::Exit {
                reason: ExitReason::Panic,
                ..
            })
        ));
        assert!(store.heads().unwrap().is_none());
    }
    impl BlockReader for Store {
        fn read(&mut self, reference: BlockRef, output: &mut [u8]) -> Result<bool, TreeError> {
            self.calls += 1;
            self.bytes += output.len() as u64;
            let Some(bytes) = self.blocks.get(&reference.hash().0) else {
                return Ok(false);
            };
            if output.len() != bytes.len() {
                return Err(TreeError::Storage);
            }
            output.copy_from_slice(bytes);
            Ok(true)
        }
    }
    fn compiled_program() -> Vec<u8> {
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"));
        let elf_path = target.join("agent-state-probe/riscv64em-vos/release/state_tree_probe.elf");
        let elf = std::fs::read(&elf_path)
            .unwrap_or_else(|error| panic!("build probe first: {}: {error}", elf_path.display()));
        let program = vos_pvm_compiler::link_elf_spi(&elf).expect("link probe as standard PVM");
        // Test-only signing identity, not installed lifecycle authority. Even
        // raw fixture protocols must qualify their compiled executable against
        // the explicit experimental package/host-call admission boundary.
        let admitted = super::super::package_admission::tests::admitted_state_fixture(program);
        admitted.program_bytes().to_vec()
    }
    struct Reader {
        reference: BlockRef,
        bytes: Option<Vec<u8>>,
        calls: usize,
    }
    impl BlockReader for Reader {
        fn read(&mut self, reference: BlockRef, output: &mut [u8]) -> Result<bool, TreeError> {
            self.calls += 1;
            assert_eq!(reference, self.reference);
            let Some(bytes) = &self.bytes else {
                return Ok(false);
            };
            output.copy_from_slice(bytes);
            Ok(true)
        }
    }
    fn scope() -> BlockScope {
        BlockScope::new(
            SpaceId([1; 32]),
            AgentId([2; 32]),
            Hash([3; 32]),
            StateLane::Linear,
        )
        .unwrap()
    }
    fn fixture(calls: usize, output: u64, capacity: u64, id: u32) -> (Vec<u8>, Reader) {
        let bytes = b"physical block bytes".to_vec();
        let reference = scope().reference(&bytes).unwrap();
        let mut data = reference.hash().0.to_vec();
        data.resize(32 + bytes.len(), 0);
        let mut asm = Assembler::new();
        asm.set_rw_data(data);
        for _ in 0..calls {
            asm.load_imm_64(Reg::A0, BASE)
                .load_imm_64(Reg::A1, bytes.len() as u64)
                .load_imm_64(Reg::A2, output)
                .load_imm_64(Reg::A3, capacity)
                .load_imm_64(Reg::A4, scope().lane() as u64)
                .ecalli(id);
        }
        asm.load_imm_64(Reg::A0, BASE + 32)
            .load_imm_64(Reg::A1, bytes.len() as u64)
            .jump_ind(Reg::RA, 0);
        (
            asm.build_standard(),
            Reader {
                reference,
                bytes: Some(bytes),
                calls: 0,
            },
        )
    }
    fn run(
        program: &[u8],
        reader: &mut Reader,
        fetches: u32,
        gas: Gas,
    ) -> Result<Vec<u8>, BlockPvmError> {
        StateBlockHost {
            scope: scope(),
            reader,
            budget: &mut ReadBudget::new(fetches, 1024),
        }
        .execute(program, &[], gas, 1024)
    }
    #[test]
    fn execution_boundary_rejects_wrong_scope_and_replayed_response() {
        use crate::agent_sdk::{
            DeploymentId, ManagementReply, ManagementRequest, RuntimeExecutionContext,
            RuntimeOutcome, RuntimeState, RuntimeTransition, RuntimeWork,
            state_execution::{ExternalLaneWork, StateExecutionOutput, StateExecutionWork},
            state_root::{RootContext, StateRootDescriptor},
        };
        let context = RootContext::new(scope(), Hash([4; 32]), Hash([5; 32])).unwrap();
        let base = StateRootDescriptor::new(context, None);
        let state = RuntimeState {
            linear: base.encode(),
            ..Default::default()
        };
        let inner = RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space: SpaceId([1; 32]),
            agent: AgentId([2; 32]),
            runtime_deployment: DeploymentId([1; 32]),
            state: state.clone(),
            request: Box::new(ManagementRequest::InspectResources),
            authority: None,
            observed_slot: 0,
        };
        let lanes = vec![ExternalLaneWork {
            base,
            next: context,
        }];
        let work = StateExecutionWork::new(
            inner.clone(),
            lanes.clone(),
            super::super::package_admission::tests::STATE_FIXTURE_LIMITS,
        )
        .unwrap();
        let response = StateExecutionOutput::new(
            &work,
            RuntimeTransition {
                state,
                outcome: RuntimeOutcome::Management(Ok(ManagementReply::Resources(
                    Default::default(),
                ))),
            },
            Vec::new(),
        )
        .unwrap();
        // A physical program returning a valid response is still insufficient
        // when that response belongs to another exact work item.
        let bytes = response.encode().unwrap();
        let mut asm = Assembler::new();
        asm.set_rw_data(bytes.clone());
        asm.load_imm_64(Reg::A0, BASE)
            .load_imm_64(Reg::A1, bytes.len() as u64)
            .jump_ind(Reg::RA, 0);
        let program = asm.build_standard();
        let (_, mut reader) = fixture(0, BASE + 32, 20, STATE_BLOCK_FETCH_CALL);
        let mut budget = ReadBudget::new(0, 0);
        let mut host = StateBlockHost {
            scope: scope(),
            reader: &mut reader,
            budget: &mut budget,
        };
        assert_eq!(host.execute_state(&program, &work, 1_000_000), Ok(response));
        let mut different = inner;
        let RuntimeWork::Manage { observed_slot, .. } = &mut different else {
            unreachable!()
        };
        *observed_slot = 1;
        let different = StateExecutionWork::new(different, lanes, work.limits()).unwrap();
        assert_eq!(
            host.execute_state(&program, &different, 1_000_000),
            Err(BlockPvmError::Output)
        );
        host.scope = BlockScope::new(
            SpaceId([9; 32]),
            AgentId([2; 32]),
            Hash([3; 32]),
            StateLane::Linear,
        )
        .unwrap();
        // Reject before loading even a malformed program or accessing storage.
        assert_eq!(
            host.execute_state(&[], &work, 0),
            Err(BlockPvmError::InvalidRequest)
        );
        assert_eq!(reader.calls, 0);
    }

    #[test]
    fn physical_program_fetches_verified_blocks_in_one_run() {
        let (program, mut reader) = fixture(2, BASE + 32, 20, STATE_BLOCK_FETCH_CALL);
        assert_eq!(
            run(&program, &mut reader, 2, 100_000).unwrap(),
            b"physical block bytes"
        );
        assert_eq!(reader.calls, 2);
        assert_eq!(
            RefineContext::load(&program, &[], 100_000)
                .unwrap()
                .run()
                .exit,
            ExitReason::HostCall(u64::from(STATE_BLOCK_FETCH_CALL)),
            "released runner must not admit the experimental call"
        );
    }
    #[test]
    fn missing_and_corrupt_blocks_terminate_without_output() {
        let (program, mut reader) = fixture(1, BASE + 32, 20, STATE_BLOCK_FETCH_CALL);
        reader.bytes = None;
        assert_eq!(
            run(&program, &mut reader, 1, 100_000),
            Err(BlockPvmError::Block(TreeError::Block(
                BlockError::Unavailable
            )))
        );
        reader.bytes = Some(vec![0; 20]);
        assert_eq!(
            run(&program, &mut reader, 1, 100_000),
            Err(BlockPvmError::Block(TreeError::Block(
                BlockError::HashMismatch
            )))
        );
    }
    #[test]
    fn invalid_pointers_capacity_calls_and_budgets_do_not_reach_storage() {
        for (output, capacity, id, fetches) in [
            (u64::MAX, 20, STATE_BLOCK_FETCH_CALL, 1),
            (0, 20, STATE_BLOCK_FETCH_CALL, 1),
            (BASE + 32, 21, STATE_BLOCK_FETCH_CALL, 1),
            (BASE + 32, 20, 77, 1),
            (BASE + 32, 20, STATE_BLOCK_FETCH_CALL, 0),
        ] {
            let (program, mut reader) = fixture(1, output, capacity, id);
            assert!(run(&program, &mut reader, fetches, 100_000).is_err());
            assert_eq!(reader.calls, 0);
        }
    }
    #[test]
    fn gas_and_later_fetch_exhaustion_do_not_return_partial_success() {
        let (program, mut reader) = fixture(2, BASE + 32, 20, STATE_BLOCK_FETCH_CALL);
        assert!(run(&program, &mut reader, 2, 100).is_err());
        assert_eq!(reader.calls, 0);
        assert_eq!(
            run(&program, &mut reader, 1, 100_000),
            Err(BlockPvmError::Block(TreeError::Block(
                BlockError::BudgetExceeded
            )))
        );
        assert_eq!(reader.calls, 1);
    }

    #[test]
    #[ignore = "requires just build-agent-state-probe; signed package execution"]
    fn compiled_admitted_execution_enforces_deployment_lanes_and_state_limits() {
        use super::super::package_admission::tests::admitted_state_fixture_limits;
        use crate::agent_sdk::{
            ActorId, DeploymentId, InvocationAuthorization, InvocationId, InvocationOrigin,
            InvocationRoleClaims, InvocationWork, LaneSet, MethodMode, ProgramId, PublicPreflight,
            RuntimeExecutionContext, RuntimeState, RuntimeWork,
            state_execution::{ExternalLaneWork, StateExecutionWork},
            state_root::{RootContext, StateRootDescriptor},
        };
        let program = compiled_program();
        let context = RootContext::new(scope(), Hash([4; 32]), Hash([5; 32])).unwrap();
        let base = StateRootDescriptor::new(context, None);
        let next = RootContext::new(scope(), Hash([4; 32]), Hash([6; 32])).unwrap();
        let request = |deployment| {
            let invocation = InvocationWork {
                space: SpaceId([1; 32]),
                agent: AgentId([2; 32]),
                runtime_deployment: deployment,
                invocation: InvocationId([1; 32]),
                actor: ActorId([1; 32]),
                incarnation: Hash([1; 32]),
                deployment: DeploymentId([1; 32]),
                program: ProgramId([1; 32]),
                mode: MethodMode::Linear,
                origin: InvocationOrigin::anonymous(),
                roles: InvocationRoleClaims::none(),
                message: b"signed execution".to_vec(),
                installation_data: None,
                availability: Vec::new(),
                gas: 1_000_000,
                recovery_only: false,
            };
            let authorization =
                InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&invocation, 1));
            StateExecutionWork::new(
                RuntimeWork::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    state: RuntimeState {
                        linear: base.encode(),
                        ..Default::default()
                    },
                    invocation: Box::new(invocation),
                    authorization: Box::new(authorization),
                    observed_slot: 1,
                },
                vec![ExternalLaneWork { base, next }],
                super::super::package_admission::tests::STATE_FIXTURE_LIMITS,
            )
            .unwrap()
        };
        let runtime = admitted_state_fixture_limits(program.clone(), LaneSet::ALL, 1024);
        let mut store = Store::default();
        let mut budget = ReadBudget::new(0, 0);
        let mut host = StateBlockHost {
            scope: scope(),
            reader: &mut store,
            budget: &mut budget,
        };
        let work = request(runtime.deployment());
        let output = host
            .execute_admitted_state(&runtime, &work, 1_000_000_000)
            .unwrap();
        assert_eq!(output.changes().len(), 1);
        assert_eq!(output.changes()[0].next().context(), next);
        assert!(
            host.reader.blocks.is_empty(),
            "execution must not publish candidates"
        );
        for limits in [
            crate::agent_sdk::contract::ExternalStateResourceLimits {
                max_rows_per_lane: 1,
                max_row_bytes_per_lane: 64,
            },
            crate::agent_sdk::contract::ExternalStateResourceLimits {
                max_rows_per_lane: 2,
                max_row_bytes_per_lane: 1,
            },
            crate::agent_sdk::contract::ExternalStateResourceLimits {
                max_rows_per_lane: 2,
                max_row_bytes_per_lane: 64,
            },
        ] {
            let limited = super::super::package_admission::tests::admitted_state_fixture_row_limits(
                program.clone(),
                limits,
            );
            let substituted = request(limited.deployment());
            let before_calls = host.reader.calls;
            assert_eq!(
                host.execute_admitted_state(&limited, &substituted, 0),
                Err(BlockPvmError::InvalidRequest)
            );
            assert_eq!(host.reader.calls, before_calls);
            let exact = StateExecutionWork::new(
                substituted.work().clone(),
                substituted.lanes().to_vec(),
                limits,
            )
            .unwrap();
            let result = host.execute_admitted_state(&limited, &exact, 1_000_000_000);
            if limits.max_rows_per_lane == 2 && limits.max_row_bytes_per_lane == 64 {
                let output = result.unwrap();
                assert_eq!(output.changes().len(), 1);
                assert!(output.validate_for(&exact).is_ok());
            } else {
                assert!(
                    result.is_err(),
                    "signed quota must be enforced by physical guest"
                );
            }
            assert!(host.reader.blocks.is_empty());
        }
        assert_eq!(
            host.execute_admitted_state(&runtime, &request(DeploymentId([9; 32])), 0),
            Err(BlockPvmError::InvalidRequest)
        );
        let no_lanes = admitted_state_fixture_limits(program.clone(), LaneSet::NONE, 1024);
        assert_eq!(
            host.execute_admitted_state(&no_lanes, &request(no_lanes.deployment()), 0),
            Err(BlockPvmError::InvalidRequest)
        );
        let small = admitted_state_fixture_limits(program.clone(), LaneSet::ALL, 1);
        assert_eq!(
            host.execute_admitted_state(&small, &request(small.deployment()), 0),
            Err(BlockPvmError::InvalidRequest)
        );
        // Empty descriptor fits, but the returned nonempty descriptor does not.
        let output_limited =
            admitted_state_fixture_limits(program, LaneSet::ALL, base.encode().len() as u32);
        assert_eq!(
            host.execute_admitted_state(
                &output_limited,
                &request(output_limited.deployment()),
                1_000_000_000
            ),
            Err(BlockPvmError::Output)
        );
        assert!(host.reader.blocks.is_empty());
    }

    #[test]
    #[ignore = "requires just build-agent-state-probe; 100k physical growth qualification"]
    fn compiled_fixed_work_tracks_paths_not_retained_rows() {
        use crate::agent_sdk::{
            ActorId,
            state_change::StateChange,
            state_root::{RootContext, StateRootDescriptor},
            state_rows::ActorRows,
            state_tree::{StateTree, WriteBudget},
        };
        let program = compiled_program();
        let mut store = Store::default();
        let mut tree = StateTree::empty(scope());
        let actor = ActorId([1; 32]);
        let incarnation = Hash([1; 32]);
        let context = RootContext::new(scope(), Hash([4; 32]), Hash([5; 32])).unwrap();
        let next = RootContext::new(scope(), Hash([4; 32]), Hash([6; 32])).unwrap();
        let mut inserted = 0u32;
        let mut initial_gas = [0; 3];
        for rows in [16, 256, 4096, 100_000] {
            // Setup is native and excluded from measurements. Retain immutable
            // old blocks so neither setup nor measurement can mask a stale read.
            while inserted < rows {
                let key = if inserted == 0 {
                    b"key".to_vec()
                } else {
                    format!("unrelated/{inserted}").into_bytes()
                };
                let update = ActorRows::new(tree, actor, incarnation)
                    .unwrap()
                    .update(
                        &key,
                        Some(&inserted.to_le_bytes()),
                        &mut store,
                        &mut ReadBudget::new(300, 1024 * 1024),
                        &mut WriteBudget::new(300, 1024 * 1024),
                    )
                    .unwrap();
                store.blocks.extend(
                    update
                        .blocks
                        .into_iter()
                        .map(|(reference, bytes)| (reference.hash().0, bytes)),
                );
                tree = update.tree;
                inserted += 1;
            }
            let base = StateRootDescriptor::new(context, tree.root());
            let descriptor = base.encode();
            for mode in 0..=2u8 {
                let mut input = vec![mode];
                input.extend_from_slice(base.commitment().as_bytes());
                input.extend_from_slice(&(descriptor.len() as u32).to_le_bytes());
                input.extend_from_slice(&descriptor);
                if mode == 1 {
                    input.extend_from_slice(b"edit");
                }
                let before = (store.calls, store.bytes, store.blocks.len());
                let started = std::time::Instant::now();
                let mut budget = ReadBudget::new(32, 8192);
                let mut host = StateBlockHost {
                    scope: scope(),
                    reader: &mut store,
                    budget: &mut budget,
                };
                // Same physical loader, dispatcher and authenticated fetch as
                // execute(); retain the invocation here to measure actual gas.
                let loaded = RefineContext::load(&program, &input, 1_000_000_000).unwrap();
                let load_elapsed = started.elapsed();
                let run_started = std::time::Instant::now();
                let invocation = loaded.run_with_host(|id, machine| {
                    host.fetch(id, machine).expect("bounded physical fetch");
                    Ok(())
                });
                assert_eq!(invocation.exit, ExitReason::Halt);
                let output = invocation.output_bounded(8192).expect("path-sized output");
                let run_elapsed = run_started.elapsed();
                let reads = store.calls - before.0;
                let read_bytes = store.bytes - before.1;
                assert_eq!(store.blocks.len(), before.2, "execution is read-only");
                let mut verify_elapsed = std::time::Duration::ZERO;
                let (write_blocks, write_bytes, verification_reads, verification_bytes) = if mode
                    == 0
                {
                    assert_eq!(output, [1, 0, 0, 0, 0]);
                    (0, 0, 0, 0)
                } else {
                    assert_eq!(output[0], 2);
                    let change = StateChange::decode(&output[1..]).unwrap();
                    let native = ActorRows::new(tree, actor, incarnation)
                        .unwrap()
                        .update(
                            b"key",
                            (mode == 1).then_some(b"edit".as_slice()),
                            &mut store,
                            &mut ReadBudget::new(32, 8192),
                            &mut WriteBudget::new(32, 8192),
                        )
                        .unwrap();
                    assert_eq!(
                        change,
                        StateChange::from_update(base.commitment(), next, native).unwrap()
                    );
                    let before_verify = (store.calls, store.bytes);
                    // Setup establishes availability; this checks incremental
                    // reuse without turning verification into a full-tree audit.
                    let verify_started = std::time::Instant::now();
                    change
                        .verify_reuse(base, next, &mut store, &mut ReadBudget::new(512, 64 * 1024))
                        .unwrap();
                    verify_elapsed = verify_started.elapsed();
                    let written: usize = change.blocks().iter().map(|(_, bytes)| bytes.len()).sum();
                    assert!(change.blocks().len() <= 32 && written <= 8192);
                    (
                        change.blocks().len(),
                        written,
                        store.calls - before_verify.0,
                        store.bytes - before_verify.1,
                    )
                };
                let baseline = &mut initial_gas[mode as usize];
                if rows == 16 {
                    *baseline = invocation.gas_used;
                }
                // Fixture-specific regression bound, not an adversarial-key
                // worst-case or a production throughput/latency requirement.
                assert!(
                    invocation.gas_used <= *baseline * 4,
                    "rows={rows} mode={mode} gas={} baseline={baseline}",
                    invocation.gas_used
                );
                eprintln!(
                    "physical growth rows={rows} mode={mode} read_blocks={reads} read_bytes={read_bytes} write_blocks={write_blocks} write_bytes={write_bytes} verify_blocks={verification_reads} verify_bytes={verification_bytes} gas={} load={load_elapsed:?} run={run_elapsed:?} verify={verify_elapsed:?}",
                    invocation.gas_used
                );
            }
        }
    }

    #[test]
    #[ignore = "requires just build-agent-state-probe; physical experimental Rust guest"]
    fn compiled_guest_authenticates_tree_rows_and_absence() {
        use crate::agent_sdk::{
            ActorId,
            state_root::{RootContext, StateRootDescriptor},
            state_rows::ActorRows,
            state_tree::{StateTree, WriteBudget},
        };
        let program = compiled_program();
        let mut store = Store::default();
        let mut tree = StateTree::empty(scope());
        for index in 0u32..1024 {
            let key = format!("unrelated/{index}");
            let update = ActorRows::new(tree, ActorId([1; 32]), Hash([1; 32]))
                .unwrap()
                .update(
                    key.as_bytes(),
                    Some(&index.to_le_bytes()),
                    &mut store,
                    &mut ReadBudget::new(300, 1024 * 1024),
                    &mut WriteBudget::new(300, 1024 * 1024),
                )
                .unwrap();
            for (reference, bytes) in update.blocks {
                store.blocks.insert(reference.hash().0, bytes);
            }
            tree = update.tree;
        }
        let absent_root = tree.root().unwrap();
        let context = RootContext::new(scope(), Hash([4; 32]), Hash([5; 32])).unwrap();
        let input = |tree: StateTree| {
            let descriptor = StateRootDescriptor::new(context, tree.root());
            let encoded = descriptor.encode();
            let mut bytes = vec![0];
            bytes.extend_from_slice(descriptor.commitment().as_bytes());
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&encoded);
            bytes
        };
        let large_value = vec![0x5a; crate::agent_sdk::state_rows::MAX_ROW_VALUE_BYTES];
        for value in [
            None,
            Some(b"compiled guest verified tree".as_slice()),
            Some(large_value.as_slice()),
        ] {
            if let Some(value) = value {
                let update = ActorRows::new(tree, ActorId([1; 32]), Hash([1; 32]))
                    .unwrap()
                    .update(
                        b"key",
                        Some(value),
                        &mut store,
                        &mut ReadBudget::new(300, 1024 * 1024),
                        &mut WriteBudget::new(300, 1024 * 1024),
                    )
                    .unwrap();
                for (reference, bytes) in update.blocks {
                    store.blocks.insert(reference.hash().0, bytes);
                }
                tree = update.tree;
            }
            let before = (store.calls, store.bytes);
            let started = std::time::Instant::now();
            let output = StateBlockHost {
                scope: scope(),
                reader: &mut store,
                budget: &mut ReadBudget::new(300, 1024 * 1024),
            }
            .execute(&program, &input(tree), 1_000_000_000, 65537)
            .expect("compiled guest executes authenticated lookup");
            let mut expected = vec![u8::from(value.is_some())];
            if let Some(value) = value {
                expected.extend_from_slice(value);
            }
            assert_eq!(output, expected);
            assert!(store.calls - before.0 < 32);
            eprintln!(
                "compiled tree lookup: value_bytes={} blocks={} bytes={} elapsed={:?}",
                value.map_or(0, <[u8]>::len),
                store.calls - before.0,
                store.bytes - before.1,
                started.elapsed()
            );
        }
        let mut substituted = input(tree);
        substituted[1] ^= 1;
        let before = store.calls;
        assert!(
            StateBlockHost {
                scope: scope(),
                reader: &mut store,
                budget: &mut ReadBudget::new(300, 1024 * 1024)
            }
            .execute(&program, &substituted, 1_000_000_000, 65537)
            .is_err()
        );
        assert_eq!(
            store.calls, before,
            "guest must reject substituted root before fetching"
        );
        // Deliberately bypass host hash verification in this test ONLY. Return
        // an authentic but stale root block as if it were the requested current
        // one. Both are canonical branch nodes of the same length, so a guest
        // that checked only node syntax could incorrectly accept stale absence.
        let stale = store.blocks[&absent_root.hash().0].clone();
        assert_ne!(Some(absent_root), tree.root());
        assert_eq!(stale.len(), tree.root().unwrap().byte_len() as usize);
        let mut calls = 0;
        let invocation = RefineContext::load(&program, &input(tree), 1_000_000_000)
            .unwrap()
            .run_with_host(|id, machine| {
                assert_eq!(id, u64::from(STATE_BLOCK_FETCH_CALL));
                calls += 1;
                assert_eq!(machine.registers()[8] as usize, stale.len());
                let output = u32::try_from(machine.registers()[9]).unwrap();
                assert!(machine.memory_mut().write_bytes_checked(output, &stale));
                machine.registers_mut()[7] = 0;
                machine.registers_mut()[8] = stale.len() as u64;
                Ok(())
            });
        assert_eq!(
            calls, 1,
            "guest must reject stale bytes before following their children"
        );
        assert_eq!(invocation.exit, ExitReason::Panic);
        // Compare complete compiled candidates with native SDK execution. The
        // host is read-only until the caller explicitly stages validated data.
        // Each case is an independent fixture snapshot, not a journal commit.
        use crate::agent_sdk::state_change::{MAX_STATE_CHANGE_BYTES, StateChange};
        let old_value = ActorRows::new(tree, ActorId([1; 32]), Hash([1; 32]))
            .unwrap()
            .get(b"key", &mut store, &mut ReadBudget::new(300, 1024 * 1024))
            .unwrap();
        for (mode, value) in [(1, Some(b"compiled mutation".as_slice())), (2, None)] {
            let base = StateRootDescriptor::new(context, tree.root()).commitment();
            let next_context = RootContext::new(scope(), Hash([4; 32]), Hash([6; 32])).unwrap();
            let native = ActorRows::new(tree, ActorId([1; 32]), Hash([1; 32]))
                .unwrap()
                .update(
                    b"key",
                    value,
                    &mut store,
                    &mut ReadBudget::new(300, 1024 * 1024),
                    &mut WriteBudget::new(300, 1024 * 1024),
                )
                .unwrap();
            let expected = StateChange::from_update(base, next_context, native).unwrap();
            let mut request = input(tree);
            request[0] = mode;
            if let Some(value) = value {
                request.extend_from_slice(value);
            }
            let before_blocks = store.blocks.len();
            let output = StateBlockHost {
                scope: scope(),
                reader: &mut store,
                budget: &mut ReadBudget::new(300, 1024 * 1024),
            }
            .execute(
                &program,
                &request,
                1_000_000_000,
                MAX_STATE_CHANGE_BYTES + 1,
            )
            .unwrap();
            assert_eq!(output[0], 2);
            assert_eq!(
                store.blocks.len(),
                before_blocks,
                "physical execution must not write its provider"
            );
            let change = StateChange::decode(&output[1..]).unwrap();
            change.validate_context(base, next_context).unwrap();
            assert_eq!(
                change, expected,
                "physical and native candidates must match byte for byte"
            );
            assert!(
                StateBlockHost {
                    scope: scope(),
                    reader: &mut store,
                    budget: &mut ReadBudget::new(300, 1024 * 1024)
                }
                .execute(&program, &request, 1_000_000_000, 1)
                .is_err()
            );
            assert_eq!(
                store.blocks.len(),
                before_blocks,
                "bounded-output failure cannot publish data"
            );
            assert!(change.blocks().len() < 32);
            for (reference, bytes) in change.blocks() {
                store.blocks.insert(reference.hash().0, bytes.clone());
            }
            let candidate = change
                .next()
                .bind(next_context, expected.next().commitment())
                .unwrap();
            let actual = ActorRows::new(candidate, ActorId([1; 32]), Hash([1; 32]))
                .unwrap()
                .get(b"key", &mut store, &mut ReadBudget::new(300, 1024 * 1024))
                .unwrap();
            assert_eq!(actual.as_deref(), value);
            let original = ActorRows::new(tree, ActorId([1; 32]), Hash([1; 32]))
                .unwrap()
                .get(b"key", &mut store, &mut ReadBudget::new(300, 1024 * 1024))
                .unwrap();
            assert_eq!(
                original, old_value,
                "staging candidates must preserve the old snapshot"
            );
        }
    }
}
