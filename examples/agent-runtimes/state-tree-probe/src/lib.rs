//! Test-only physical tree reader/writer; not a released AgentRuntime package.
//! Input: mode, expected commitment, descriptor length/bytes, optional value.
//! Output: 0 for absence, 1 + value, or 2 + uncommitted StateChange.
#![no_std]
#![cfg(target_arch = "riscv64")]
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use vos_agent_runtime_guest as _;
use vos_agent_sdk::{
    ActorId, AgentId, Hash, SpaceId, StateLane,
    state_blocks::{BlockScope, ReadBudget},
    state_change::StateChange,
    state_guest::PvmBlockReader,
    state_root::{RootContext, StateRootDescriptor},
    state_rows::ActorRows,
    state_tree::WriteBudget,
};

fn legacy_probe(input: &[u8]) -> Vec<u8> {
    let length = input.len();
    assert!(
        length >= 37
            && length
                <= 37
                    + vos_agent_sdk::state_root::MAX_STATE_ROOT_BYTES
                    + vos_agent_sdk::state_rows::MAX_ROW_VALUE_BYTES
    );
    let mode = input[0];
    assert!(mode <= 2);
    let expected = Hash(input[1..33].try_into().unwrap());
    let descriptor_len = u32::from_le_bytes(input[33..37].try_into().unwrap()) as usize;
    assert!(
        descriptor_len <= vos_agent_sdk::state_root::MAX_STATE_ROOT_BYTES
            && length >= 37 + descriptor_len
    );
    let descriptor = StateRootDescriptor::decode(&input[37..37 + descriptor_len]).unwrap();
    let value = &input[37 + descriptor_len..];
    // Fixture identity; production obtains this from admitted execution work.
    let scope = BlockScope::new(
        SpaceId([1; 32]),
        AgentId([2; 32]),
        Hash([3; 32]),
        StateLane::Linear,
    )
    .unwrap();
    let context = RootContext::new(scope, Hash([4; 32]), Hash([5; 32])).unwrap();
    let tree = descriptor.bind(context, expected).unwrap();
    let rows = ActorRows::new(tree, ActorId([1; 32]), Hash([1; 32])).unwrap();
    if mode == 0 {
        assert!(value.is_empty());
        let value = rows
            .get(
                b"key",
                &mut PvmBlockReader::new(scope.lane()),
                &mut ReadBudget::new(300, 1024 * 1024),
            )
            .unwrap();
        let mut output = vec![u8::from(value.is_some())];
        if let Some(value) = value {
            output.extend_from_slice(&value);
        }
        output
    } else {
        if mode == 2 {
            assert!(value.is_empty());
        }
        let update = rows
            .update(
                b"key",
                (mode == 1).then_some(value),
                &mut PvmBlockReader::new(scope.lane()),
                &mut ReadBudget::new(300, 1024 * 1024),
                &mut WriteBudget::new(300, 1024 * 1024),
            )
            .unwrap();
        let next = RootContext::new(scope, Hash([4; 32]), Hash([6; 32])).unwrap();
        let change = StateChange::from_update(expected, next, update).unwrap();
        let mut output = vec![2];
        output.extend_from_slice(&change.encode());
        output
    }
}

fn execution_probe(input: &[u8]) -> Vec<u8> {
    use vos_agent_sdk::{
        InvocationObservation, InvocationReply, InvocationStatus, MethodMode, RuntimeOutcome,
        RuntimeTransition, RuntimeWork,
        state_execution::{StateExecutionOutput, StateExecutionWork},
    };
    let work = StateExecutionWork::decode(input).unwrap();
    if let RuntimeWork::Manage { request, state, .. } = work.work() {
        let vos_agent_sdk::ManagementRequest::Create(descriptor) = request.as_ref() else {
            panic!("fixture supports Create only");
        };
        let mut state = state.clone();
        state.control = b"probe-created".to_vec();
        let mut changes = Vec::new();
        let mut reads = ReadBudget::new(900, 3 * 1024 * 1024);
        let mut writes = WriteBudget::new(900, 3 * 1024 * 1024);
        for lane in work.lanes() {
            let scope = lane.base.context().scope();
            let tree = lane
                .base
                .bind(lane.base.context(), lane.base.commitment())
                .unwrap();
            let update = ActorRows::new(tree, ActorId([1; 32]), Hash([1; 32]))
                .unwrap()
                .update_accounted_batch(
                    &[(b"initial".to_vec(), Some(b"created".to_vec()))],
                    work.limits(),
                    &mut PvmBlockReader::new(scope.lane()),
                    &mut reads,
                    &mut writes,
                )
                .unwrap()
                .update;
            let change =
                StateChange::from_update(lane.base.commitment(), lane.next, update).unwrap();
            match scope.lane() {
                StateLane::Linear => state.linear = change.next().encode(),
                StateLane::Merge => state.merge = change.next().encode(),
                StateLane::Local => state.local = change.next().encode(),
            }
            changes.push(change);
        }
        return StateExecutionOutput::new(
            &work,
            RuntimeTransition {
                state,
                outcome: RuntimeOutcome::Management(Ok(vos_agent_sdk::ManagementReply::Created(
                    descriptor.identity.clone(),
                ))),
            },
            changes,
        )
        .unwrap()
        .encode()
        .unwrap();
    }
    let mode = match work.work() {
        RuntimeWork::Invoke { invocation, .. } => invocation.mode,
        RuntimeWork::Acknowledge { invocation, .. } => invocation.mode,
        _ => panic!("unsupported probe operation"),
    };
    let owner = match mode {
        MethodMode::Linear => StateLane::Linear,
        MethodMode::Local => StateLane::Local,
        _ => panic!("unsupported probe mode"),
    };
    let lane = *work
        .lanes()
        .iter()
        .find(|lane| lane.base.context().scope().lane() == owner)
        .unwrap();
    // Exercise read-only roots during fresh replay as well as live execution.
    // The probe must not silently ignore missing secondary-lane availability.
    for selected in work
        .lanes()
        .iter()
        .filter(|lane| lane.base.context().scope().lane() != owner)
    {
        assert_eq!(selected.next, selected.base.context());
        let tree = selected
            .base
            .bind(selected.base.context(), selected.base.commitment())
            .unwrap();
        vos_agent_sdk::state_rows::lane_row_usage(
            tree,
            &mut PvmBlockReader::new(selected.base.context().scope().lane()),
            &mut ReadBudget::new(300, 1024 * 1024),
        )
        .unwrap();
    }
    if let RuntimeWork::Acknowledge {
        state,
        invocation,
        authorization,
        ..
    } = work.work()
    {
        assert!(matches!(
            invocation.mode,
            MethodMode::Linear | MethodMode::Local
        ));
        let tree = lane
            .base
            .bind(lane.base.context(), lane.base.commitment())
            .unwrap();
        // Test-only mutation marker: this exercises journal retirement and
        // state publication, not a production runtime's retained-result store.
        let update = ActorRows::new(tree, invocation.actor, invocation.incarnation)
            .unwrap()
            .update_accounted_batch(
                &[(
                    invocation.invocation.0.to_vec(),
                    Some(b"acknowledged".to_vec()),
                )],
                work.limits(),
                &mut PvmBlockReader::new(lane.base.context().scope().lane()),
                &mut ReadBudget::new(300, 1024 * 1024),
                &mut WriteBudget::new(300, 1024 * 1024),
            )
            .unwrap()
            .update;
        let mut state = state.clone();
        let changes = if update.tree.root() == tree.root() {
            assert!(update.blocks.is_empty());
            Vec::new()
        } else {
            let change =
                StateChange::from_update(lane.base.commitment(), lane.next, update).unwrap();
            match lane.base.context().scope().lane() {
                StateLane::Linear => state.linear = change.next().encode(),
                StateLane::Local => state.local = change.next().encode(),
                StateLane::Merge => panic!("Merge is not supported"),
            }
            vec![change]
        };
        return StateExecutionOutput::new(
            &work,
            RuntimeTransition {
                state,
                outcome: RuntimeOutcome::Acknowledged(Ok(
                    vos_agent_sdk::InvocationAcknowledgement {
                        invocation: invocation.invocation,
                        actor: invocation.actor,
                        incarnation: invocation.incarnation,
                        deployment: invocation.deployment,
                        mode: invocation.mode,
                        work: invocation.commitment(),
                        authorization: authorization.commitment(),
                    },
                )),
            },
            changes,
        )
        .unwrap()
        .encode()
        .unwrap();
    }
    // Test-only row updater, not an authorization/runtime implementation. The
    // journal adapter selects these contexts independently of this response.
    let (invocation, actor, incarnation, deployment, mode, value, state) = match work.work() {
        RuntimeWork::Invoke {
            invocation: work,
            state,
            ..
        } => (
            work.invocation,
            work.actor,
            work.incarnation,
            work.deployment,
            work.mode,
            &work.message,
            state,
        ),
        _ => panic!("fixture supports Invoke only"),
    };
    assert!(matches!(mode, MethodMode::Linear | MethodMode::Local));
    let tree = lane
        .base
        .bind(lane.base.context(), lane.base.commitment())
        .unwrap();
    let update = ActorRows::new(tree, actor, incarnation)
        .unwrap()
        .update_accounted_batch(
            &[
                (b"key".to_vec(), Some(value.to_vec())),
                (b"mirror".to_vec(), Some(value.to_vec())),
            ],
            work.limits(),
            &mut PvmBlockReader::new(lane.base.context().scope().lane()),
            &mut ReadBudget::new(300, 1024 * 1024),
            &mut WriteBudget::new(300, 1024 * 1024),
        )
        .unwrap()
        .update;
    let mut state = state.clone();
    let changes = if update.tree.root() == tree.root() {
        assert!(update.blocks.is_empty());
        Vec::new()
    } else {
        let change = StateChange::from_update(lane.base.commitment(), lane.next, update).unwrap();
        match lane.base.context().scope().lane() {
            StateLane::Linear => state.linear = change.next().encode(),
            StateLane::Local => state.local = change.next().encode(),
            StateLane::Merge => panic!("Merge is not supported"),
        }
        vec![change]
    };
    let transition = RuntimeTransition {
        state,
        outcome: RuntimeOutcome::Completed(Ok(InvocationReply {
            invocation,
            actor,
            incarnation,
            deployment,
            mode,
            lane: Some(lane.base.context().scope().lane()),
            status: InvocationStatus::Done,
            reply: b"updated".to_vec(),
            gas_remaining: 0,
            observation: InvocationObservation::default(),
        })),
    };
    StateExecutionOutput::new(&work, transition, changes)
        .unwrap()
        .encode()
        .unwrap()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start(arguments: *const u8, length: usize) -> ! {
    assert!(length <= vos_agent_sdk::state_execution::MAX_STATE_EXECUTION_WORK_BYTES);
    // SAFETY: the physical loader supplies the immutable argument mapping.
    let input = unsafe { core::slice::from_raw_parts(arguments, length) };
    // Explicit experimental framing, not a fallback for an r19 runtime input.
    let output = if input.starts_with(b"XSW2") {
        execution_probe(input)
    } else {
        legacy_probe(input)
    };
    // SAFETY: terminal PVM halt; the output allocation stays live until the
    // host has copied a0/a1. This is a probe, not the runtime transition ABI.
    unsafe {
        core::arch::asm!("jr t0", in("a0") output.as_ptr() as u64,
        in("a1") output.len() as u64, in("t0") 0xffff_0000u64,
        options(noreturn, nostack));
    }
}
