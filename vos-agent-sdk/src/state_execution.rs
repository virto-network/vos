//! Experimental external-state execution framing, distinct from r19 dispatch.
//!
//! A response commits to the exact work AND independently selected root
//! contexts, then binds its candidate changes to the returned runtime state.
//! This is transport/structural validation, not authentication, execution
//! evidence, availability, finality or a replay seal. Only the admitted guest's
//! actual response may enter replay. Attested execution is unsupported until
//! external reads are part of its proof contract.

use crate::{
    Hash, ManagementRequest, RuntimeState, RuntimeTransition, RuntimeWork, StateLane,
    contract::ExternalStateResourceLimits,
    protocol::wire::{DecodeError, Decoder, Encoder},
    state_change::{MAX_STATE_CHANGE_BYTES, StateChange},
    state_root::{MAX_STATE_ROOT_BYTES, RootContext, StateRootDescriptor},
    wire::{CanonicalWire, MAX_RUNTIME_TRANSITION_WIRE_BYTES, MAX_RUNTIME_WORK_WIRE_BYTES},
};
use alloc::vec::Vec;

/// Signed opt-in identity for this experimental framing and block-fetch
/// contract. Not the released ABI, nor a promise of compatibility with a
/// future production revision (resource pricing is still provisional).
pub const STATE_EXECUTION_ABI_ID: Hash = Hash(*b"vos-agent-state-experimental-004");
/// Experimental execution semantics, including the provisional fetch tariff.
/// Never pair this with the released ABI or reuse released replay semantics.
pub const STATE_EXECUTION_SEMANTICS_ID: Hash = Hash(*b"vos-agent-state-experimental-s04");

/// Admission headroom for a metadata rewrite under the 4-MiB single-change
/// envelope. The released image runtime retains its separate 4-MiB ceiling.
/// A future increase needs publication-budget and retirement qualification.
pub const MAX_ADMITTED_EXTERNAL_RUNTIME_STATE_BYTES: usize = 3 * 1024 * 1024;

pub const MAX_STATE_EXECUTION_WORK_BYTES: usize = MAX_RUNTIME_WORK_WIRE_BYTES + 2048;
pub const MAX_STATE_EXECUTION_OUTPUT_BYTES: usize =
    MAX_RUNTIME_TRANSITION_WIRE_BYTES + MAX_STATE_CHANGE_BYTES + 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalLaneWork {
    pub base: StateRootDescriptor,
    pub next: RootContext,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateExecutionWork {
    work: RuntimeWork,
    lanes: Vec<ExternalLaneWork>,
    limits: ExternalStateResourceLimits,
}

fn state(work: &RuntimeWork) -> &RuntimeState {
    match work {
        RuntimeWork::Manage { state, .. }
        | RuntimeWork::Invoke { state, .. }
        | RuntimeWork::Resume { state, .. }
        | RuntimeWork::Acknowledge { state, .. } => state,
        #[cfg(feature = "experimental-state-blocks")]
        RuntimeWork::InspectInvocation { state, .. } => state,
    }
}

fn bootstrap(work: &RuntimeWork) -> bool {
    matches!(work, RuntimeWork::Manage { request, state, .. }
        if matches!(request.as_ref(), ManagementRequest::Create(_)) && state.is_empty())
}

fn inspection(work: &RuntimeWork) -> bool {
    #[cfg(feature = "experimental-state-blocks")]
    if matches!(work, RuntimeWork::InspectInvocation { .. }) {
        return true;
    }
    matches!(work, RuntimeWork::Manage { request, .. } if matches!(request.as_ref(),
        ManagementRequest::InspectActors { .. } | ManagementRequest::InspectResources
        | ManagementRequest::InspectManagementHistory))
}

fn bounded<'a>(decoder: &mut Decoder<'a>, maximum: usize) -> Result<&'a [u8], DecodeError> {
    let bytes = decoder.bytes_ref()?;
    if bytes.len() > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(bytes)
}

impl StateExecutionWork {
    pub fn new(
        work: RuntimeWork,
        lanes: Vec<ExternalLaneWork>,
        limits: ExternalStateResourceLimits,
    ) -> Result<Self, DecodeError> {
        if !limits.is_valid() {
            return Err(DecodeError::NonCanonical);
        }
        if !work.execution_context().is_direct() {
            return Err(DecodeError::InvalidPlatform);
        }
        if !work.validate_wire() {
            return Err(DecodeError::NonCanonical);
        }
        if lanes.is_empty() || lanes.len() > 3 {
            return Err(DecodeError::LimitExceeded);
        }
        let identity = match &work {
            RuntimeWork::Manage { space, agent, .. } => Some((*space, *agent)),
            RuntimeWork::Invoke { invocation, .. } => Some((invocation.space, invocation.agent)),
            RuntimeWork::Acknowledge { invocation, .. } => {
                Some((invocation.space, invocation.agent))
            }
            #[cfg(feature = "experimental-state-blocks")]
            RuntimeWork::InspectInvocation { invocation, .. } => {
                Some((invocation.space, invocation.agent))
            }
            // Resume identity comes from the independently authenticated retained
            // invocation. It is not available in this finite resume tuple.
            RuntimeWork::Resume { .. } => None,
        };
        let first = lanes[0].base.context().scope();
        let mut previous = None;
        for lane in &lanes {
            let scope = lane.base.context().scope();
            if previous.is_some_and(|p| p >= scope.lane() as u8)
                || scope != lane.next.scope()
                || (scope.space(), scope.agent()) != (first.space(), first.agent())
                || identity.is_some_and(|id| id != (scope.space(), scope.agent()))
            {
                return Err(DecodeError::NonCanonical);
            }
            previous = Some(scope.lane() as u8);
            if inspection(&work) && lane.next != lane.base.context() {
                return Err(DecodeError::NonCanonical);
            }
            if bootstrap(&work) {
                if lane.base != StateRootDescriptor::new(lane.base.context(), None) {
                    return Err(DecodeError::NonCanonical);
                }
            } else if state(&work).component(scope.lane()) != lane.base.encode() {
                return Err(DecodeError::NonCanonical);
            }
        }
        let value = Self {
            work,
            lanes,
            limits,
        };
        value.encode()?;
        Ok(value)
    }

    pub fn work(&self) -> &RuntimeWork {
        &self.work
    }
    /// Transported policy is authoritative only when the executor independently
    /// matches it to the admitted package. Decoding alone grants no authority.
    pub fn limits(&self) -> ExternalStateResourceLimits {
        self.limits
    }
    pub fn lanes(&self) -> &[ExternalLaneWork] {
        &self.lanes
    }

    pub fn encode(&self) -> Result<Vec<u8>, DecodeError> {
        let work = self.work.encode().map_err(|_| DecodeError::NonCanonical)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"XSW2");
        let mut encoder = Encoder(&mut bytes);
        encoder.u64(self.limits.max_rows_per_lane);
        encoder.u64(self.limits.max_row_bytes_per_lane);
        encoder.bytes(&work);
        encoder.u8(self.lanes.len() as u8);
        for lane in &self.lanes {
            encoder.bytes(&lane.base.encode());
            // A canonical empty descriptor is the existing context-only wire;
            // its root MUST be absent, not a prediction of guest output.
            encoder.bytes(&StateRootDescriptor::new(lane.next, None).encode());
        }
        if bytes.len() > MAX_STATE_EXECUTION_WORK_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_STATE_EXECUTION_WORK_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4)? != b"XSW2" {
            return Err(DecodeError::InvalidTag);
        }
        let limits = ExternalStateResourceLimits {
            max_rows_per_lane: decoder.u64()?,
            max_row_bytes_per_lane: decoder.u64()?,
        };
        let work = RuntimeWork::decode(bounded(&mut decoder, MAX_RUNTIME_WORK_WIRE_BYTES)?)
            .map_err(|_| DecodeError::NonCanonical)?;
        let count = decoder.u8()?;
        if count == 0 || count > 3 {
            return Err(DecodeError::LimitExceeded);
        }
        let mut lanes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let base = StateRootDescriptor::decode(bounded(&mut decoder, MAX_STATE_ROOT_BYTES)?)
                .map_err(|_| DecodeError::NonCanonical)?;
            let next = StateRootDescriptor::decode(bounded(&mut decoder, MAX_STATE_ROOT_BYTES)?)
                .map_err(|_| DecodeError::NonCanonical)?;
            if next != StateRootDescriptor::new(next.context(), None) {
                return Err(DecodeError::NonCanonical);
            }
            lanes.push(ExternalLaneWork {
                base,
                next: next.context(),
            });
        }
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        Self::new(work, lanes, limits)
    }

    pub fn commitment(&self) -> Result<Hash, DecodeError> {
        Ok(Hash::digest(
            b"vos/experimental/state-execution-work/v2",
            &[&self.encode()?],
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateExecutionOutput {
    work: Hash,
    transition: RuntimeTransition,
    changes: Vec<StateChange>,
}

impl StateExecutionOutput {
    /// Construct a guest response. Hosts must decode AND bind it to the exact
    /// request they executed; this constructor is not proof of execution.
    pub fn new(
        work: &StateExecutionWork,
        transition: RuntimeTransition,
        changes: Vec<StateChange>,
    ) -> Result<Self, DecodeError> {
        let value = Self {
            work: work.commitment()?,
            transition,
            changes,
        };
        value.validate_for(work)?;
        value.encode()?;
        Ok(value)
    }

    pub fn transition(&self) -> &RuntimeTransition {
        &self.transition
    }
    pub fn changes(&self) -> &[StateChange] {
        &self.changes
    }

    pub fn validate_for(&self, work: &StateExecutionWork) -> Result<(), DecodeError> {
        if self.changes.len() > 3 || self.work != work.commitment()? || !self.transition.validate()
        {
            return Err(DecodeError::NonCanonical);
        }
        use crate::RuntimeOutcome;
        #[cfg(feature = "experimental-state-blocks")]
        let retained_inspection_shape = matches!(
            (&work.work, &self.transition.outcome),
            (
                RuntimeWork::InspectInvocation { .. },
                RuntimeOutcome::Completed(_) | RuntimeOutcome::Acknowledged(_)
            )
        );
        #[cfg(not(feature = "experimental-state-blocks"))]
        let retained_inspection_shape = false;
        if !(retained_inspection_shape
            || matches!(
                (&work.work, &self.transition.outcome),
                (RuntimeWork::Manage { .. }, RuntimeOutcome::Management(_))
                    | (
                        RuntimeWork::Invoke { .. } | RuntimeWork::Resume { .. },
                        RuntimeOutcome::Completed(_) | RuntimeOutcome::Yielded(_)
                    )
                    | (
                        RuntimeWork::Acknowledge { .. },
                        RuntimeOutcome::Acknowledged(_)
                    )
            ))
            || (inspection(&work.work)
                && (self.transition.state != *state(&work.work) || !self.changes.is_empty()))
        {
            return Err(DecodeError::NonCanonical);
        }
        let mut previous = None;
        for change in &self.changes {
            let lane = change.next().context().scope().lane();
            if previous.is_some_and(|p| p >= lane as u8) {
                return Err(DecodeError::NonCanonical);
            }
            previous = Some(lane as u8);
            let expected = work
                .lanes
                .iter()
                .find(|l| l.base.context().scope().lane() == lane)
                .ok_or(DecodeError::NonCanonical)?;
            change.validate_context(expected.base.commitment(), expected.next)?;
        }
        for lane in [StateLane::Linear, StateLane::Merge, StateLane::Local] {
            let before = state(&work.work).component(lane);
            let after = self.transition.state.component(lane);
            if let Some(expected) = work
                .lanes
                .iter()
                .find(|l| l.base.context().scope().lane() == lane)
            {
                let target = if let Some(change) = self
                    .changes
                    .iter()
                    .find(|c| c.next().context().scope().lane() == lane)
                {
                    change.next()
                } else {
                    // A selected successor context permits a change; it does
                    // not force one. Exact retries/no-ops retain the original
                    // descriptor and its root-producing provenance verbatim.
                    expected.base
                };
                if after != target.encode() {
                    return Err(DecodeError::NonCanonical);
                }
            } else if before != after {
                return Err(DecodeError::NonCanonical);
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, DecodeError> {
        if self.work == Hash::ZERO || self.changes.len() > 3 {
            return Err(DecodeError::NonCanonical);
        }
        let transition = self
            .transition
            .encode()
            .map_err(|_| DecodeError::NonCanonical)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"XST1");
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(self.work.as_bytes());
        encoder.bytes(&transition);
        encoder.u8(self.changes.len() as u8);
        let mut size = 0usize;
        for change in &self.changes {
            let encoded = change.encode();
            size = size
                .checked_add(encoded.len())
                .filter(|n| *n <= MAX_STATE_CHANGE_BYTES)
                .ok_or(DecodeError::LimitExceeded)?;
            encoder.bytes(&encoded);
        }
        if bytes.len() > MAX_STATE_EXECUTION_OUTPUT_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        Ok(bytes)
    }

    /// Decode only. Always call `validate_for` with the independently retained
    /// request before using this response, and establish block availability
    /// separately before any replay-sealed publication.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_STATE_EXECUTION_OUTPUT_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4)? != b"XST1" {
            return Err(DecodeError::InvalidTag);
        }
        let work = Hash(decoder.fixed()?);
        if work == Hash::ZERO {
            return Err(DecodeError::NonCanonical);
        }
        let transition =
            RuntimeTransition::decode(bounded(&mut decoder, MAX_RUNTIME_TRANSITION_WIRE_BYTES)?)
                .map_err(|_| DecodeError::NonCanonical)?;
        let count = decoder.u8()?;
        if count > 3 {
            return Err(DecodeError::LimitExceeded);
        }
        let mut changes = Vec::with_capacity(count as usize);
        let mut remaining = MAX_STATE_CHANGE_BYTES;
        let mut previous = None;
        for _ in 0..count {
            let bytes = bounded(&mut decoder, remaining)?;
            remaining -= bytes.len();
            let change = StateChange::decode(bytes)?;
            let lane = change.next().context().scope().lane() as u8;
            if previous.is_some_and(|p| p >= lane) {
                return Err(DecodeError::NonCanonical);
            }
            previous = Some(lane);
            changes.push(change);
        }
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(Self {
            work,
            transition,
            changes,
        })
    }

    pub fn decode_for(bytes: &[u8], work: &StateExecutionWork) -> Result<Self, DecodeError> {
        let response = Self::decode(bytes)?;
        response.validate_for(work)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActorId, AgentId, BlobRef, DeploymentId, InvocationError, InvocationId, ManagementReply,
        MethodMode, ProgramId, ResumeWork, RuntimeExecutionContext, RuntimeOutcome, SpaceId,
        state_blocks::{BlockRef, BlockScope, ReadBudget},
        state_tree::{BlockReader, StateTree, TreeError, WriteBudget},
    };
    use alloc::{boxed::Box, vec};

    fn fixture_work(
        work: RuntimeWork,
        lanes: Vec<ExternalLaneWork>,
    ) -> Result<StateExecutionWork, DecodeError> {
        StateExecutionWork::new(
            work,
            lanes,
            ExternalStateResourceLimits {
                max_rows_per_lane: 1_000_000,
                max_row_bytes_per_lane: 1 << 30,
            },
        )
    }

    struct Empty;
    impl BlockReader for Empty {
        fn read(&mut self, _: BlockRef, _: &mut [u8]) -> Result<bool, TreeError> {
            panic!("empty tree must not fetch")
        }
    }
    fn fixture() -> (StateExecutionWork, StateExecutionOutput) {
        let scope = BlockScope::new(
            SpaceId([1; 32]),
            AgentId([2; 32]),
            Hash([3; 32]),
            StateLane::Linear,
        )
        .unwrap();
        let before = RootContext::new(scope, Hash([4; 32]), Hash([5; 32])).unwrap();
        let next = RootContext::new(scope, Hash([4; 32]), Hash([6; 32])).unwrap();
        let base = StateRootDescriptor::new(before, None);
        let work = RuntimeWork::Resume {
            context: RuntimeExecutionContext::Direct,
            state: RuntimeState {
                linear: base.encode(),
                ..RuntimeState::default()
            },
            resume: Box::new(ResumeWork {
                invocation: InvocationId([1; 32]),
                actor: ActorId([1; 32]),
                incarnation: Hash([1; 32]),
                deployment: DeploymentId([1; 32]),
                program: ProgramId([1; 32]),
                mode: MethodMode::Linear,
                continuation: BlobRef::of_bytes(b"continuation"),
                ready_sequence: 1,
                installation_data: None,
                availability: Vec::new(),
                input: None,
            }),
        };
        let work = fixture_work(work, vec![ExternalLaneWork { base, next }]).unwrap();
        let update = StateTree::empty(scope)
            .update(
                [7; 32],
                Some(b"state"),
                &mut Empty,
                &mut ReadBudget::new(0, 0),
                &mut WriteBudget::new(10, 10000),
            )
            .unwrap();
        let change = StateChange::from_update(base.commitment(), next, update).unwrap();
        let transition = RuntimeTransition {
            state: RuntimeState {
                linear: change.next().encode(),
                control: b"opaque runtime metadata".to_vec(),
                ..RuntimeState::default()
            },
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
        };
        let response = StateExecutionOutput::new(&work, transition, vec![change]).unwrap();
        (work, response)
    }

    #[test]
    fn quota_policy_is_required_canonical_and_response_bound() {
        let (work, output) = fixture();
        let bytes = work.encode().unwrap();
        assert_eq!(
            StateExecutionWork::decode(&bytes).unwrap().limits(),
            work.limits()
        );
        for offset in [4, 12] {
            let mut zero = bytes.clone();
            zero[offset..offset + 8].fill(0);
            assert!(StateExecutionWork::decode(&zero).is_err());
            let mut substituted = bytes.clone();
            substituted[offset] ^= 1;
            let substituted = StateExecutionWork::decode(&substituted).unwrap();
            assert_ne!(substituted.commitment(), work.commitment());
            assert!(
                StateExecutionOutput::decode_for(&output.encode().unwrap(), &substituted).is_err()
            );
        }
        let mut legacy = bytes;
        legacy[..4].copy_from_slice(b"XSW1");
        legacy.drain(4..20);
        assert_eq!(
            StateExecutionWork::decode(&legacy),
            Err(DecodeError::InvalidTag)
        );
    }

    #[test]
    fn unchanged_root_can_retain_provenance_at_a_new_execution_position() {
        let (work, _) = fixture();
        assert_ne!(work.lanes[0].base.context(), work.lanes[0].next);
        let transition = RuntimeTransition {
            state: state(&work.work).clone(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
        };
        let response = StateExecutionOutput::new(&work, transition, Vec::new()).unwrap();
        assert_eq!(
            StateExecutionOutput::decode_for(&response.encode().unwrap(), &work),
            Ok(response.clone())
        );
        let mut forged = response;
        forged.transition.state.linear =
            StateRootDescriptor::new(work.lanes[0].next, None).encode();
        assert!(
            forged.validate_for(&work).is_err(),
            "a changed descriptor still needs its exact candidate"
        );
    }

    #[test]
    fn execution_frame_roundtrips_and_is_not_r19_dispatch() {
        let (work, response) = fixture();
        let input = work.encode().unwrap();
        let output = response.encode().unwrap();
        assert_eq!(StateExecutionWork::decode(&input), Ok(work.clone()));
        assert_eq!(
            StateExecutionOutput::decode_for(&output, &work),
            Ok(response)
        );
        assert!(RuntimeWork::decode(&input).is_err());
        assert!(RuntimeTransition::decode(&output).is_err());
        assert!(StateExecutionWork::decode(&work.work.encode().unwrap()).is_err());
    }

    #[test]
    fn execution_frame_binds_exact_work_context_outcome_shape_and_output_roots() {
        let (work, response) = fixture();
        let mut other = work.work.clone();
        let RuntimeWork::Resume { resume, .. } = &mut other else {
            unreachable!()
        };
        resume.ready_sequence += 1;
        let other = fixture_work(other, work.lanes.clone()).unwrap();
        assert!(response.validate_for(&other).is_err());
        let mut other = work.lanes.clone();
        other[0].next =
            RootContext::new(other[0].next.scope(), Hash([4; 32]), Hash([9; 32])).unwrap();
        let other = fixture_work(work.work.clone(), other).unwrap();
        assert!(response.validate_for(&other).is_err());
        let mut bad = response.clone();
        bad.transition.state.linear = work.lanes[0].base.encode();
        assert!(bad.validate_for(&work).is_err());
        let mut bad = response.clone();
        bad.transition.state.local = vec![1];
        assert!(bad.validate_for(&work).is_err());
        let mut bad = response.clone();
        bad.changes.clear();
        assert!(bad.validate_for(&work).is_err());
        let mut bad = response;
        bad.transition.outcome =
            RuntimeOutcome::Management(Ok(ManagementReply::Resources(Default::default())));
        assert!(bad.validate_for(&work).is_err());
    }

    #[test]
    fn execution_frame_rejects_noncanonical_lanes_attested_and_truncated_wires() {
        let (work, response) = fixture();
        assert!(fixture_work(work.work.clone(), vec![work.lanes[0]; 2]).is_err());
        let mut attested = work.work.clone();
        let RuntimeWork::Resume { context, .. } = &mut attested else {
            unreachable!()
        };
        *context = RuntimeExecutionContext::Attested {
            proof_system: Hash([1; 32]),
        };
        assert_eq!(
            fixture_work(attested, work.lanes.clone()),
            Err(DecodeError::InvalidPlatform)
        );
        for bytes in [work.encode().unwrap(), response.encode().unwrap()] {
            for end in 0..bytes.len() {
                let result = if bytes.starts_with(b"XSW2") {
                    StateExecutionWork::decode(&bytes[..end]).map(|_| ())
                } else {
                    StateExecutionOutput::decode(&bytes[..end]).map(|_| ())
                };
                assert!(result.is_err());
            }
        }
        let mut bytes = response.encode().unwrap();
        bytes.push(0);
        assert_eq!(
            StateExecutionOutput::decode(&bytes),
            Err(DecodeError::TrailingBytes)
        );
        let mut duplicate = response.clone();
        duplicate.changes.push(duplicate.changes[0].clone());
        assert!(StateExecutionOutput::decode(&duplicate.encode().unwrap()).is_err());
        let mut input = work.encode().unwrap();
        input[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(StateExecutionWork::decode(&input).is_err());
    }

    #[test]
    fn inspection_cannot_mutate_even_opaque_control_or_advance_root_context() {
        let (original, _) = fixture();
        let base = original.lanes[0].base;
        let work = RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space: SpaceId([1; 32]),
            agent: AgentId([2; 32]),
            runtime_deployment: DeploymentId([1; 32]),
            state: state(&original.work).clone(),
            request: Box::new(ManagementRequest::InspectResources),
            authority: None,
            observed_slot: 0,
        };
        assert!(fixture_work(work.clone(), original.lanes.clone()).is_err());
        let work = fixture_work(
            work,
            vec![ExternalLaneWork {
                base,
                next: base.context(),
            }],
        )
        .unwrap();
        let transition = RuntimeTransition {
            state: state(&work.work).clone(),
            outcome: RuntimeOutcome::Management(Ok(ManagementReply::Resources(Default::default()))),
        };
        let output = StateExecutionOutput::new(&work, transition, Vec::new()).unwrap();
        let mut bad = output.clone();
        bad.transition.state.control.push(1);
        assert!(bad.validate_for(&work).is_err());
        assert!(StateExecutionOutput::decode_for(&output.encode().unwrap(), &work).is_ok());
    }

    #[cfg(feature = "experimental-state-blocks")]
    #[test]
    fn retained_invocation_inspection_is_distinct_and_read_only() {
        use crate::{
            InvocationAuthorization, InvocationOrigin, InvocationRetirement, InvocationRoleClaims,
            PublicPreflight,
        };
        let (original, _) = fixture();
        let base = original.lanes[0].base;
        let invocation = InvocationRetirement {
            space: SpaceId([1; 32]),
            agent: AgentId([2; 32]),
            runtime_deployment: DeploymentId([1; 32]),
            invocation: InvocationId([3; 32]),
            actor: ActorId([4; 32]),
            incarnation: Hash([5; 32]),
            deployment: DeploymentId([6; 32]),
            program: ProgramId([7; 32]),
            mode: MethodMode::Linear,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            gas: 100,
            recovery_only: false,
            message: vec![],
            installation_data: None,
            required: vec![],
        };
        let authorization = InvocationAuthorization::PublicPreflight(PublicPreflight {
            work: invocation.commitment(),
            origin: invocation.origin,
            observed_slot: 1,
        });
        let work = RuntimeWork::InspectInvocation {
            context: RuntimeExecutionContext::Direct,
            state: state(&original.work).clone(),
            invocation: Box::new(invocation),
            authorization: Box::new(authorization),
            observed_slot: 2,
        };
        assert_eq!(RuntimeWork::decode(&work.encode().unwrap()).unwrap(), work);
        assert!(fixture_work(work.clone(), original.lanes.clone()).is_err());
        let framed = fixture_work(
            work,
            vec![ExternalLaneWork {
                base,
                next: base.context(),
            }],
        )
        .unwrap();
        let output = StateExecutionOutput::new(
            &framed,
            RuntimeTransition {
                state: state(framed.work()).clone(),
                outcome: RuntimeOutcome::Completed(Err(InvocationError::NotReady)),
            },
            vec![],
        )
        .unwrap();
        assert_eq!(
            StateExecutionOutput::decode_for(&output.encode().unwrap(), &framed).unwrap(),
            output,
        );
        let mut mutated = output;
        mutated.transition.state.control.push(1);
        assert!(mutated.validate_for(&framed).is_err());
    }

    #[test]
    fn output_limits_are_aggregate_across_external_lanes() {
        use crate::state_blocks::MAX_STATE_BLOCK_BYTES;
        use crate::state_tree::TreeUpdate;
        let (original, _) = fixture();
        let merge_scope = BlockScope::new(
            SpaceId([1; 32]),
            AgentId([2; 32]),
            Hash([3; 32]),
            StateLane::Merge,
        )
        .unwrap();
        let merge_context = RootContext::new(merge_scope, Hash([4; 32]), Hash([5; 32])).unwrap();
        let merge_base = StateRootDescriptor::new(merge_context, None);
        let mut inner = original.work.clone();
        let RuntimeWork::Resume { state: before, .. } = &mut inner else {
            unreachable!()
        };
        before.merge = merge_base.encode();
        let mut lanes = original.lanes.clone();
        lanes.push(ExternalLaneWork {
            base: merge_base,
            next: merge_context,
        });
        let work = fixture_work(inner, lanes).unwrap();
        let mut changes = Vec::new();
        let mut transition = RuntimeTransition {
            state: state(&work.work).clone(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
        };
        for lane in &work.lanes {
            // Opaque payloads deliberately test framing only. They are not
            // valid tree nodes and could not pass incremental availability.
            let scope = lane.next.scope();
            let blocks: Vec<_> = (0..33u8)
                .map(|i| {
                    let bytes = vec![i; MAX_STATE_BLOCK_BYTES];
                    (scope.reference(&bytes).unwrap(), bytes)
                })
                .collect();
            let tree = StateTree::from_root(scope, Some(blocks[0].0));
            let change = StateChange::from_update(
                lane.base.commitment(),
                lane.next,
                TreeUpdate { tree, blocks },
            )
            .unwrap();
            match scope.lane() {
                StateLane::Linear => transition.state.linear = change.next().encode(),
                StateLane::Merge => transition.state.merge = change.next().encode(),
                StateLane::Local => unreachable!(),
            }
            changes.push(change);
        }
        assert_eq!(
            StateExecutionOutput::new(&work, transition.clone(), changes.clone()),
            Err(DecodeError::LimitExceeded)
        );
        let mut wire = b"XST1".to_vec();
        let mut encoder = Encoder(&mut wire);
        encoder.fixed(work.commitment().unwrap().as_bytes());
        encoder.bytes(&transition.encode().unwrap());
        encoder.u8(2);
        for change in changes {
            encoder.bytes(&change.encode());
        }
        assert_eq!(
            StateExecutionOutput::decode(&wire),
            Err(DecodeError::LimitExceeded)
        );
    }
}
