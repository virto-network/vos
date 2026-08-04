//! Generic VOS v2 JAM service guest.
//!
//! The ELF exports the Gray Paper's two physical entries. `_start` is Refine
//! (IC 0 after transpilation) and `accumulate` is Accumulate (IC 5). Registers
//! `a0`/`a1` remain the standard argument pointer/length window; no register is
//! used as a VOS phase selector.

#[cfg(target_arch = "riscv64")]
mod guest {

    extern crate alloc;

    use alloc::collections::BTreeMap;
    use core::arch::global_asm;

    use vos::abi::pvm::ecall;
    use vos::abi::{error, pvm::hostcalls};
    use vos::v2::{
        AccumulateRequestV2, AccumulationRejectionV2, AccumulationResultV2, ActorCallResultV2,
        ActorEffectBatchV2, ActorSliceOutputV2, BlobRefV2, ConsistencyBaseV2, ContinuationChangeV2,
        CrdtChangeV2, CrdtDispatchV2, CrdtMaterializationV2, GasAccountingV2,
        GuestAccumulateStoreV2, ImportedBlobV2, MessageRecordV2, ProgramId, RefineOutputV2,
        ReplyRecordV2, StateTreeStore, TransitionV2, V2Wire, WorkEnvelopeV2,
        execute_canonical_guest_accumulate,
    };

    /// Upper bound for one nested actor transition in this foundation guest. This
    /// lives in zero-initialized guest memory rather than the small application
    /// allocator. Oversize output fails the work item; it is never truncated.
    const TRANSITION_CAPACITY: usize = 4 * 1024 * 1024;
    #[unsafe(link_section = ".bss.vos_service_transition")]
    static mut TRANSITION_BUFFER: [u8; TRANSITION_CAPACITY] = [0; TRANSITION_CAPACITY];
    #[unsafe(link_section = ".bss.vos_actor_effects")]
    static mut ACTOR_EFFECT_BUFFER: [u8; vos::v2::ACTOR_EFFECT_BATCH_MAX_BYTES] =
        [0; vos::v2::ACTOR_EFFECT_BATCH_MAX_BYTES];

    #[repr(C)]
    struct OutputWindow {
        address: u64,
        len: u64,
    }

    // The transpiler emits the physical two-jump GP prologue from these exported
    // ELF symbols. The host installs the halt address in `ra`; each successful
    // entry returns to it after its Rust body produces the output window.
    global_asm!(
        ".global _start",
        ".type _start, @function",
        "_start:",
        "mv s0, ra",
        "jal ra, vos_service_refine",
        "mv ra, s0",
        "ret",
        ".global accumulate",
        ".type accumulate, @function",
        "accumulate:",
        "mv s0, ra",
        "jal ra, vos_service_accumulate",
        "mv ra, s0",
        "ret",
    );

    /// Run one pure actor-tree slice through the target actor's owning JAR
    /// HANDLE. Slot 144 is supplied at invocation setup; it is not a JAM
    /// protocol capability and no host callback performs the actor execution.
    #[unsafe(no_mangle)]
    extern "C" fn vos_service_refine(
        arguments: *const u8,
        arguments_len: usize,
        actor_input_len: usize,
        actor_ipc_capacity: usize,
    ) -> OutputWindow {
        // SAFETY: JAM initializes a readable argument window at (a0, a1).
        let input = unsafe { core::slice::from_raw_parts(arguments, arguments_len) };
        let mut work = WorkEnvelopeV2::decode(input).unwrap_or_else(|_| fail_closed());
        if work.service.service_abi != vos::v2::ABI_VERSION
            || work.service.execution_semantics != vos::v2::EXECUTION_SEMANTICS_ID
            || !work.base.mode_compatible(work.consistency)
        {
            fail_closed();
        }

        if actor_input_len > actor_ipc_capacity
            || actor_input_len > vos::v2::ACTOR_SLICE_INPUT_MAX_BYTES
            || actor_ipc_capacity == 0
        {
            fail_closed();
        }

        prepare_actor_cnodes(&work);

        let actor_output_len = ecall::call_cap(
            ecall::local_cap_ref(vos::v2::TARGET_ACTOR_HANDLE_SLOT),
            vos::v2::ACTOR_IPC_CAP_SLOT,
            vos::v2::ACTOR_IPC_BASE_PAGE as u64 * 4096,
            actor_input_len as u64,
            actor_ipc_capacity as u64,
            vos::v2::NESTED_ACTOR_CALL_MAGIC,
        ) as usize;
        restore_actor_cnodes(&work);
        if actor_output_len == 0 || actor_output_len > actor_ipc_capacity {
            fail_closed();
        }
        let actor_output_address = vos::v2::ACTOR_IPC_BASE_PAGE as usize * 4096usize;
        // SAFETY: JAR returned and remapped the same invocation-owned DATA cap
        // after REPLY; the returned length is bounded by its capacity.
        let actor_output_bytes = unsafe {
            core::slice::from_raw_parts(actor_output_address as *const u8, actor_output_len)
        };
        let call_result =
            ActorCallResultV2::decode(actor_output_bytes).unwrap_or_else(|_| fail_closed());
        if call_result.actor != work.target
            || call_result.first_await_ordinal != 0
            || call_result.forbidden
        {
            fail_closed();
        }
        // SAFETY: Refine is single-threaded and this invocation owns the
        // infrastructure guest's static scheduler buffer.
        let effect_buffer = unsafe {
            core::slice::from_raw_parts_mut(
                core::ptr::addr_of_mut!(ACTOR_EFFECT_BUFFER).cast::<u8>(),
                vos::v2::ACTOR_EFFECT_BATCH_MAX_BYTES,
            )
        };
        let effect_len = hostcalls::actor_private_fetch(effect_buffer) as usize;
        if effect_len == 0 || effect_len > effect_buffer.len() {
            fail_closed();
        }
        let effects = ActorEffectBatchV2::decode(&effect_buffer[..effect_len])
            .unwrap_or_else(|_| fail_closed());
        let actor_output = aggregate_actor_effects(&work, &call_result, effects);
        if let Some(checkpoint) = actor_output.checkpoint.as_ref() {
            if checkpoint.input != work.input_id() {
                work = checkpoint
                    .resume_work
                    .clone()
                    .unwrap_or_else(|| fail_closed());
            } else if checkpoint
                .resume_work
                .as_ref()
                .is_some_and(|resume_work| resume_work != &work)
            {
                fail_closed();
            }
            if checkpoint.input != work.input_id()
                || checkpoint.base != work.base
                || checkpoint.work_hash != work.hash()
                || checkpoint.base_causal_height != work.base_causal_height
                || checkpoint.change.map(|dispatch| dispatch.change)
                    != CrdtChangeV2::derive_operation_scope(&work)
            {
                fail_closed();
            }
        }
        let imported = |actor: vos::v2::ActorId| {
            work.imported_actors
                .binary_search_by_key(&actor, |candidate| candidate.actor)
                .is_ok()
        };
        if actor_output
            .writes
            .iter()
            .any(|write| !imported(write.actor))
            || actor_output.spawns.iter().any(|spawn| {
                !imported(spawn.parent)
                    || imported(spawn.actor)
                    || work.imported_actors.iter().any(|actor| {
                        actor.parent == Some(spawn.parent) && actor.name == spawn.name
                    })
            })
            || actor_output.outbox.iter().any(|call| !imported(call.from))
        {
            fail_closed();
        }

        let outbox = actor_output
            .outbox
            .iter()
            .map(|call| MessageRecordV2 {
                call_id: work.invocation.call_id(call.await_ordinal),
                caller_invocation: work.invocation,
                await_ordinal: call.await_ordinal,
                from: call.from,
                to_service: call.to_service.clone(),
                to: call.to,
                parent: work.parent_call,
                payload: call.payload.clone(),
                authorization: call.authorization.clone(),
                proof_requested: call.proof_requested,
                deadline_timeslot: call.deadline_timeslot,
            })
            .collect::<alloc::vec::Vec<_>>();
        match actor_output.checkpoint.as_ref() {
            Some(checkpoint) if checkpoint.replacement.is_some() => {
                if !actor_output.yielded {
                    fail_closed();
                }
                match checkpoint.pending_call {
                    Some(pending)
                        if outbox.len() == 1
                            && outbox[0].call_id == pending
                            && Some(outbox[0].from) == checkpoint.pending_actor => {}
                    None if outbox.is_empty() => {}
                    _ => fail_closed(),
                }
            }
            Some(_) => {
                if actor_output.yielded || !outbox.is_empty() {
                    fail_closed();
                }
            }
            None => {
                if actor_output.yielded || !outbox.is_empty() {
                    fail_closed();
                }
            }
        }
        // Consuming the reply which resumed this slice is independent of what
        // the slice does next. It may complete, explicitly yield, or suspend
        // at another await; all three must consume the incoming call exactly
        // once.
        let consumed_outbox = work
            .awaited_reply
            .as_ref()
            .map(|reply| reply.reply.call_id)
            .or_else(|| {
                work.awaited_timeout
                    .as_ref()
                    .map(|timeout| timeout.expiration.timeout.call_id)
            });

        let mut consumed_input = work.input_id();
        let mut base = work.base.clone();
        let mut work_hash = work.hash();
        let mut base_causal_height = work.base_causal_height;
        let mut change = CrdtChangeV2::derive_operation_scope(&work)
            .map(|change| CrdtDispatchV2 { change, ordinal: 0 });
        let mut continuations = alloc::vec::Vec::new();
        let mut exported_blobs = alloc::vec::Vec::new();
        if let Some(checkpoint) = actor_output.checkpoint {
            if checkpoint.input.invocation != work.invocation {
                fail_closed();
            }
            if !checkpoint.base.mode_compatible(work.consistency) {
                fail_closed();
            }
            let is_crdt = matches!(checkpoint.base, ConsistencyBaseV2::Crdt { .. });
            if checkpoint.change.is_some() != is_crdt
                || checkpoint.base_causal_height.is_some() != is_crdt
                || checkpoint
                    .change
                    .is_some_and(|dispatch| dispatch.ordinal != 0)
            {
                fail_closed();
            }
            consumed_input = checkpoint.input;
            base = checkpoint.base;
            work_hash = checkpoint.work_hash;
            base_causal_height = checkpoint.base_causal_height;
            change = checkpoint.change;
            if let Some(replacement) = checkpoint.replacement.as_ref() {
                exported_blobs.push(replacement.clone());
            }
            if checkpoint
                .previously_suspended
                .binary_search(&work.target)
                .is_err()
                && checkpoint.suspended.binary_search(&work.target).is_err()
            {
                fail_closed();
            }
            let mut changed = checkpoint.previously_suspended.clone();
            changed.extend(checkpoint.suspended.iter().copied());
            changed.sort_unstable();
            changed.dedup();
            for actor in changed {
                if !work
                    .imported_actors
                    .iter()
                    .any(|candidate| candidate.actor == actor)
                {
                    fail_closed();
                }
                continuations.push(ContinuationChangeV2 {
                    actor,
                    expected: checkpoint
                        .previously_suspended
                        .binary_search(&actor)
                        .ok()
                        .and(checkpoint.expected),
                    replacement: checkpoint
                        .suspended
                        .binary_search(&actor)
                        .ok()
                        .and_then(|_| checkpoint.replacement.clone()),
                });
            }
        } else if actor_output.yielded {
            fail_closed();
        }

        let reply = (!actor_output.yielded).then(|| ReplyRecordV2 {
            call_id: work
                .parent_call
                .unwrap_or_else(|| work.invocation.root_reply_id()),
            producer: work.target,
            result: actor_output.reply,
        });
        let (writes, crdt_change, mut candidate_blobs) = match (&base, base_causal_height) {
            (ConsistencyBaseV2::Linear { .. }, None) => {
                if !actor_output.crdt_operations.is_empty() || !actor_output.crdt_states.is_empty()
                {
                    fail_closed();
                }
                (actor_output.writes, None, alloc::vec::Vec::new())
            }
            (ConsistencyBaseV2::Crdt { heads }, Some(base_height)) => {
                if !actor_output.writes.is_empty()
                    || !actor_output.spawns.is_empty()
                    || actor_output.crdt_states.is_empty()
                    || actor_output
                        .crdt_states
                        .iter()
                        .any(|state| !imported(state.actor))
                {
                    fail_closed();
                }
                let operation_scope = change
                    .map(|dispatch| dispatch.change)
                    .unwrap_or_else(|| fail_closed());
                if actor_output.crdt_operations.iter().any(|operation| {
                    !imported(operation.actor)
                        || operation.id
                            != operation_scope.operation(
                                operation.actor,
                                operation.dispatch_ordinal,
                                operation.field,
                                operation.ordinal,
                            )
                }) {
                    fail_closed();
                }
                let causal_height = base_height.checked_add(1).unwrap_or_else(|| fail_closed());
                let mut candidates = BTreeMap::new();
                let materializations = actor_output
                    .crdt_states
                    .into_iter()
                    .map(|state| {
                        let reference = BlobRefV2::of_bytes(&state.state);
                        candidates
                            .entry(reference.hash)
                            .or_insert_with(|| ImportedBlobV2 {
                                reference: reference.clone(),
                                bytes: state.state,
                            });
                        CrdtMaterializationV2 {
                            actor: state.actor,
                            state: reference,
                        }
                    })
                    .collect();
                (
                    alloc::vec::Vec::new(),
                    Some(CrdtChangeV2 {
                        id: CrdtChangeV2::derive_id_from_work_hash(work_hash),
                        work_hash,
                        causal_dependencies: heads.clone(),
                        causal_height,
                        operations: actor_output.crdt_operations,
                        workflow: alloc::vec::Vec::new(),
                        materializations,
                    }),
                    candidates.into_values().collect(),
                )
            }
            _ => fail_closed(),
        };
        let spawns = actor_output
            .spawns
            .into_iter()
            .map(|spawn| {
                let reference = BlobRefV2::of_bytes(&spawn.initial_state);
                if !candidate_blobs
                    .iter()
                    .any(|candidate| candidate.reference == reference)
                {
                    candidate_blobs.push(ImportedBlobV2 {
                        reference: reference.clone(),
                        bytes: spawn.initial_state,
                    });
                }
                vos::v2::ActorSpawnV2 {
                    actor: spawn.actor,
                    name: spawn.name,
                    parent: spawn.parent,
                    initial_state: reference,
                }
            })
            .collect();
        candidate_blobs.sort_by_key(|blob| blob.reference.hash);
        if candidate_blobs
            .windows(2)
            .any(|pair| pair[0].reference.hash >= pair[1].reference.hash)
        {
            fail_closed();
        }
        let mut transition = TransitionV2 {
            service: work.service.clone(),
            consumed_input,
            target_deployment: work.target_deployment,
            target_program: work.target_program,
            base: base.clone(),
            writes,
            spawns,
            crdt_change,
            continuations,
            inbox: alloc::vec::Vec::new(),
            outbox,
            reply,
            exported_blobs,
            gas: GasAccountingV2::default(),
            proof: None,
        };
        let workflow = transition.workflow_operations_with_consumed_outbox(&work, consumed_outbox);
        if let Some(change) = transition.crdt_change.as_mut() {
            change.workflow = workflow;
        }
        let encoded = RefineOutputV2 {
            transition,
            candidate_blobs,
        }
        .encode();
        if encoded.len() > TRANSITION_CAPACITY {
            fail_closed();
        }
        let output_address = core::ptr::addr_of_mut!(TRANSITION_BUFFER).cast::<u8>();
        // SAFETY: the PVM is single-threaded and the static output buffer is
        // exclusively owned until the terminal halt reads it.
        unsafe {
            core::ptr::copy_nonoverlapping(encoded.as_ptr(), output_address, encoded.len());
        }

        OutputWindow {
            address: output_address as u64,
            len: encoded.len() as u64,
        }
    }

    fn aggregate_actor_effects(
        work: &WorkEnvelopeV2,
        call_result: &ActorCallResultV2,
        batch: ActorEffectBatchV2,
    ) -> ActorSliceOutputV2 {
        let imported = |actor: vos::v2::ActorId| {
            work.imported_actors
                .binary_search_by_key(&actor, |candidate| candidate.actor)
                .is_ok()
        };
        let mut root = None;
        let mut writes = BTreeMap::new();
        let mut crdt_operations = alloc::vec::Vec::new();
        let mut crdt_states = BTreeMap::new();
        let mut next_crdt_dispatch = BTreeMap::new();
        let mut spawns = BTreeMap::new();
        let mut outbox = alloc::vec::Vec::new();
        let mut checkpoints = alloc::vec::Vec::new();

        for output in batch.outputs {
            if !imported(output.actor) {
                fail_closed();
            }
            if output.forbidden {
                if output.actor == work.target
                    || !output.writes.is_empty()
                    || !output.crdt_operations.is_empty()
                    || !output.crdt_states.is_empty()
                    || !output.spawns.is_empty()
                    || !output.outbox.is_empty()
                    || !output.reply.is_empty()
                    || output.yielded
                    || output.checkpoint.is_some()
                {
                    fail_closed();
                }
                continue;
            }
            match work.consistency {
                vos::v2::ConsistencyModeV2::Crdt => {
                    let [state] = output.crdt_states.as_slice() else {
                        fail_closed();
                    };
                    let expected_next = next_crdt_dispatch.entry(output.actor).or_insert(1u32);
                    if !output.writes.is_empty()
                        || state.actor != output.actor
                        || state.next_dispatch_ordinal != *expected_next
                        || output.crdt_operations.iter().any(|operation| {
                            operation.dispatch_ordinal.checked_add(1) != Some(*expected_next)
                        })
                    {
                        fail_closed();
                    }
                    *expected_next = expected_next
                        .checked_add(1)
                        .unwrap_or_else(|| fail_closed());
                    crdt_operations.extend(output.crdt_operations.iter().cloned());
                    crdt_states.insert(output.actor, state.clone());
                }
                _ => {
                    if !output.crdt_operations.is_empty() || !output.crdt_states.is_empty() {
                        fail_closed();
                    }
                }
            }
            if let Some(checkpoint) = output.checkpoint.as_ref() {
                checkpoints.push(checkpoint.clone());
            }
            for spawn in &output.spawns {
                if spawn.parent != output.actor
                    || spawns.insert(spawn.actor, spawn.clone()).is_some()
                {
                    fail_closed();
                }
            }
            for write in &output.writes {
                writes.insert((write.actor, write.key.clone()), write.value.clone());
            }
            outbox.extend(output.outbox.iter().cloned());
            if output.actor == work.target {
                if root.replace(output).is_some() {
                    fail_closed();
                }
            } else if !output.reply.is_empty() {
                // Nested replies are delivered only through the direct CALL
                // result and are never promoted to the root transition reply.
            }
        }

        let mut root = root.unwrap_or_else(|| fail_closed());
        if root.reply != call_result.reply
            || root.first_await_ordinal != call_result.first_await_ordinal
            || root.next_await_ordinal != call_result.next_await_ordinal
            || root.yielded != call_result.yielded
            || root.forbidden != call_result.forbidden
            || root.checkpoint != call_result.checkpoint
            || checkpoints
                .iter()
                .any(|checkpoint| Some(checkpoint) != root.checkpoint.as_ref())
        {
            fail_closed();
        }
        outbox.sort_by_key(|call| call.await_ordinal);
        if outbox
            .windows(2)
            .any(|pair| pair[0].await_ordinal >= pair[1].await_ordinal)
        {
            fail_closed();
        }
        root.writes = writes
            .into_iter()
            .map(|((actor, key), value)| vos::v2::ActorWriteV2 { actor, key, value })
            .collect();
        crdt_operations.sort_by_key(|operation| {
            (
                operation.actor,
                operation.dispatch_ordinal,
                operation.ordinal,
            )
        });
        if crdt_operations.windows(2).any(|pair| {
            (pair[0].actor, pair[0].dispatch_ordinal, pair[0].ordinal)
                >= (pair[1].actor, pair[1].dispatch_ordinal, pair[1].ordinal)
        }) {
            fail_closed();
        }
        root.crdt_operations = crdt_operations;
        root.crdt_states = crdt_states.into_values().collect();
        root.spawns = spawns.into_values().collect();
        root.outbox = outbox;
        root
    }

    /// Give every actor a directory-indexed CALLABLE for each other idle actor
    /// in its owned tree. The generic service retains the HANDLEs; DOWNGRADE
    /// is the ordinary JAM/JAR authority-narrowing operation and does not add
    /// a VOS-specific kernel call surface.
    fn prepare_actor_cnodes(work: &WorkEnvelopeV2) {
        if work.imported_actors.len() > vos::v2::MAX_ROOT_TREE_ACTORS {
            fail_closed();
        }
        // Every canonical actor manifest owns slot 0 for standalone args, but
        // JAR CALL reserves it for the move-only IPC cap. Preserve all actor
        // arg caps up front so arbitrary main→child→peer nesting sees an empty
        // IPC slot in every dormant callee.
        for actor in &work.imported_actors {
            let handle = actor_handle_slot(work, actor.actor);
            if !ecall::move_cap(
                ecall::cap_ref_through_handle(handle, 0),
                ecall::cap_ref_through_handle(handle, vos::v2::ACTOR_SAVED_ARGS_CAP_SLOT),
            ) {
                fail_closed();
            }
        }
        for destination in &work.imported_actors {
            let destination_handle = actor_handle_slot(work, destination.actor);
            for (source_index, source) in work.imported_actors.iter().enumerate() {
                if source.actor == destination.actor || source.continuation.is_some() {
                    continue;
                }
                let source_handle = actor_handle_slot(work, source.actor);
                let callable_slot = vos::v2::ACTOR_CALLABLE_BASE_SLOT
                    .checked_add(source_index as u8)
                    .unwrap_or_else(|| fail_closed());
                if !ecall::downgrade_cap(
                    ecall::local_cap_ref(source_handle),
                    ecall::cap_ref_through_handle(destination_handle, callable_slot),
                ) {
                    fail_closed();
                }
            }
        }
    }

    fn restore_actor_cnodes(work: &WorkEnvelopeV2) {
        for actor in &work.imported_actors {
            let handle = actor_handle_slot(work, actor.actor);
            if !ecall::move_cap(
                ecall::cap_ref_through_handle(handle, vos::v2::ACTOR_SAVED_ARGS_CAP_SLOT),
                ecall::cap_ref_through_handle(handle, 0),
            ) {
                fail_closed();
            }
        }
    }

    /// `ServicePvmV2` installs the target first and the remaining canonical
    /// actor-ID order after it. Recompute that physical HANDLE slot from the
    /// consensus work directory without trusting a native routing table.
    fn actor_handle_slot(work: &WorkEnvelopeV2, actor: vos::v2::ActorId) -> u8 {
        if actor == work.target {
            return vos::v2::TARGET_ACTOR_HANDLE_SLOT;
        }
        let ordinal = work
            .imported_actors
            .iter()
            .filter(|candidate| candidate.actor != work.target)
            .position(|candidate| candidate.actor == actor)
            .unwrap_or_else(|| fail_closed());
        vos::v2::TARGET_ACTOR_HANDLE_SLOT
            .checked_add(1)
            .and_then(|slot| slot.checked_add(ordinal as u8))
            .unwrap_or_else(|| fail_closed())
    }

    /// Validate and stage one v2 install/transition using only standard JAM
    /// service storage and preimage capabilities. The outer JAR driver owns the
    /// transaction: returning successfully commits all calls atomically, while
    /// `fail_closed` makes it discard the entire staging area.
    #[unsafe(no_mangle)]
    extern "C" fn vos_service_accumulate(
        arguments: *const u8,
        arguments_len: usize,
    ) -> OutputWindow {
        // SAFETY: JAM initializes a readable argument window at (a0, a1).
        let input = unsafe { core::slice::from_raw_parts(arguments, arguments_len) };
        let result = match AccumulateRequestV2::decode(input) {
            Ok(request) => {
                // The physical service VM is invocation-scoped; its complete
                // memory image is discarded at HALT. Keep the large decoded
                // request alive until that boundary instead of running deep
                // Rust collection drop glue after the result is finalized.
                let request = core::mem::ManuallyDrop::new(request);
                // Authenticate the already-canonical physical request bytes.
                // This avoids re-encoding a large decoded package merely to
                // present the same commitment to platform authority.
                let install_authorized = matches!(&*request, AccumulateRequestV2::Install(_))
                    && hostcalls::verify_install_authorization(input) == error::HOST_OK;
                let upgrade_authorized =
                    matches!(&*request, AccumulateRequestV2::UpgradeActor(_))
                    && hostcalls::verify_upgrade_authorization(input) == error::HOST_OK;
                execute_canonical_guest_accumulate(
                    &mut JamAccumulateStore {
                        install_authorized,
                        upgrade_authorized,
                    },
                    &request,
                )
                .unwrap_or_else(|_| fail_closed())
            }
            Err(_) => AccumulationResultV2::Rejected(AccumulationRejectionV2::NonCanonical),
        };
        output(&result.encode())
    }

    const STORAGE_PROBE_CAPACITY: usize = 4096;
    const MAX_STORAGE_VALUE: usize = 64 * 1024 * 1024;

    struct JamAccumulateStore {
        install_authorized: bool,
        upgrade_authorized: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum JamStoreError {
        ValueTooLarge,
        ReadFailed,
        WriteFailed,
        ProvideFailed,
    }

    impl StateTreeStore for JamAccumulateStore {
        type Error = JamStoreError;

        fn read(&self, key: &[u8]) -> Result<Option<alloc::vec::Vec<u8>>, Self::Error> {
            let mut probe = [0u8; STORAGE_PROBE_CAPACITY];
            let len = hostcalls::read(key, &mut probe);
            if len == error::HOST_NONE {
                return Ok(None);
            }
            let len = usize::try_from(len).map_err(|_| JamStoreError::ValueTooLarge)?;
            if len <= probe.len() {
                return Ok(Some(probe[..len].to_vec()));
            }
            if len > MAX_STORAGE_VALUE {
                return Err(JamStoreError::ValueTooLarge);
            }
            let mut value = alloc::vec![0u8; len];
            if hostcalls::read(key, &mut value) != len as u64 {
                return Err(JamStoreError::ReadFailed);
            }
            Ok(Some(value))
        }

        fn write(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<(), Self::Error> {
            // JAM's zero-length STORAGE_W deletes the key. Logical empty
            // values are wrapped in non-empty service-tree leaves.
            let value = value.unwrap_or_default();
            if hostcalls::write(key, value) == error::HOST_OK {
                Ok(())
            } else {
                Err(JamStoreError::WriteFailed)
            }
        }
    }

    impl GuestAccumulateStoreV2 for JamAccumulateStore {
        fn logical_timeslot(&self) -> Result<Option<u64>, Self::Error> {
            let timeslot = hostcalls::accumulation_timeslot();
            Ok((timeslot != error::HOST_NONE).then_some(timeslot))
        }

        fn authorize_install(
            &self,
            _genesis: &vos::v2::ServiceGenesisV2,
        ) -> Result<bool, Self::Error> {
            Ok(self.install_authorized)
        }

        fn authorize_upgrade(
            &self,
            _upgrade: &vos::v2::ActorUpgradeV2,
        ) -> Result<bool, Self::Error> {
            Ok(self.upgrade_authorized)
        }

        fn blob_available(&self, reference: &BlobRefV2) -> Result<bool, Self::Error> {
            let mut probe = [0u8; 1];
            let available = hostcalls::preimage_lookup(&reference.hash.0, &mut probe);
            Ok(available != error::HOST_NONE && available == reference.len)
        }

        fn load_blob(
            &self,
            reference: &BlobRefV2,
        ) -> Result<Option<alloc::vec::Vec<u8>>, Self::Error> {
            let mut probe = [0u8; STORAGE_PROBE_CAPACITY];
            let len = hostcalls::preimage_lookup(&reference.hash.0, &mut probe);
            if len == error::HOST_NONE {
                return Ok(None);
            }
            if len != reference.len {
                return Err(JamStoreError::ReadFailed);
            }
            let len = usize::try_from(len).map_err(|_| JamStoreError::ValueTooLarge)?;
            let bytes = if len <= probe.len() {
                probe[..len].to_vec()
            } else {
                if len > MAX_STORAGE_VALUE {
                    return Err(JamStoreError::ValueTooLarge);
                }
                let mut bytes = alloc::vec![0u8; len];
                if hostcalls::preimage_lookup(&reference.hash.0, &mut bytes) != len as u64 {
                    return Err(JamStoreError::ReadFailed);
                }
                bytes
            };
            if BlobRefV2::of_bytes(&bytes) != *reference {
                return Err(JamStoreError::ReadFailed);
            }
            Ok(Some(bytes))
        }

        fn provide_blob(&mut self, bytes: &[u8]) -> Result<BlobRefV2, Self::Error> {
            let reference = BlobRefV2::of_bytes(bytes);
            if hostcalls::provide(&reference.hash.0, bytes) == error::HOST_OK {
                Ok(reference)
            } else {
                Err(JamStoreError::ProvideFailed)
            }
        }

        fn verify_proof(
            &self,
            request: &vos::v2::ProofVerificationRequestV2,
        ) -> Result<vos::v2::ProofVerificationV2, Self::Error> {
            Ok(match hostcalls::verify_proof(&request.encode()) {
                error::HOST_OK => vos::v2::ProofVerificationV2::Valid,
                error::HOST_NONE => vos::v2::ProofVerificationV2::Unavailable,
                _ => vos::v2::ProofVerificationV2::Invalid,
            })
        }

        fn verify_role_credential(
            &self,
            request: &vos::v2::RoleCredentialVerificationRequestV2,
        ) -> Result<bool, Self::Error> {
            Ok(hostcalls::verify_role_credential(&request.encode()) == error::HOST_OK)
        }

        fn program_available(&self, program: ProgramId) -> Result<bool, Self::Error> {
            Ok(hostcalls::program_available(&program.0) == error::HOST_OK)
        }

        fn verify_receipt(
            &self,
            request: &vos::v2::ReceiptVerificationRequestV2,
        ) -> Result<vos::v2::ReceiptVerificationV2, Self::Error> {
            Ok(match hostcalls::verify_receipt(&request.encode()) {
                error::HOST_OK => vos::v2::ReceiptVerificationV2::Valid,
                error::HOST_NONE => vos::v2::ReceiptVerificationV2::Unavailable,
                _ => vos::v2::ReceiptVerificationV2::Invalid,
            })
        }
    }

    fn output(encoded: &[u8]) -> OutputWindow {
        if encoded.len() > TRANSITION_CAPACITY {
            fail_closed();
        }
        let output_address = core::ptr::addr_of_mut!(TRANSITION_BUFFER).cast::<u8>();
        // SAFETY: the PVM is single-threaded and the static output buffer is
        // exclusively owned until the terminal halt reads it.
        unsafe {
            core::ptr::copy_nonoverlapping(encoded.as_ptr(), output_address, encoded.len());
        }
        OutputWindow {
            address: output_address as u64,
            len: encoded.len() as u64,
        }
    }

    #[cold]
    fn fail_closed() -> ! {
        // The transpiler maps RISC-V EBREAK to the GP trap instruction, so an
        // invalid work item fails immediately instead of burning its gas in a
        // loop or accidentally returning an empty successful transition.
        unsafe {
            core::arch::asm!("ebreak", options(noreturn, nostack));
        }
    }
}
