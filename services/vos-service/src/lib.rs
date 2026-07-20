//! Generic VOS v2 JAM service guest.
//!
//! The ELF exports the Gray Paper's two physical entries. `_start` is Refine
//! (IC 0 after transpilation) and `accumulate` is Accumulate (IC 5). Registers
//! `a0`/`a1` remain the standard argument pointer/length window; no register is
//! used as a VOS phase selector.

#[cfg(target_arch = "riscv64")]
mod guest {

    extern crate alloc;

    use core::arch::global_asm;

    use vos::abi::pvm::ecall;
    use vos::abi::{error, pvm::hostcalls};
    use vos::v2::{
        AccumulateRequestV2, AccumulationRejectionV2, AccumulationResultV2, ActorSliceOutputV2,
        BlobRefV2, ConsistencyBaseV2, ContinuationChangeV2, CrdtChangeV2, CrdtMaterializationV2,
        GasAccountingV2, GuestAccumulateStoreV2, ImportedBlobV2, MessageRecordV2, RefineOutputV2,
        ReplyRecordV2, StateTreeStore, TransitionV2, V2Wire, WorkEnvelopeV2,
        execute_guest_accumulate,
    };

    /// Upper bound for one nested actor transition in this foundation guest. This
    /// lives in zero-initialized guest memory rather than the small application
    /// allocator. Oversize output fails the work item; it is never truncated.
    const TRANSITION_CAPACITY: usize = 4 * 1024 * 1024;
    #[unsafe(link_section = ".bss.vos_service_transition")]
    static mut TRANSITION_BUFFER: [u8; TRANSITION_CAPACITY] = [0; TRANSITION_CAPACITY];

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

        if actor_input_len > actor_ipc_capacity || actor_ipc_capacity == 0 {
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
        let actor_output =
            ActorSliceOutputV2::decode(actor_output_bytes).unwrap_or_else(|_| fail_closed());
        if actor_output.actor != work.target
            || actor_output.first_await_ordinal != 0
            || actor_output.forbidden
        {
            fail_closed();
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
                    Some(pending) if outbox.len() == 1 && outbox[0].call_id == pending => {}
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
        let consumed_outbox = actor_output.checkpoint.as_ref().and_then(|checkpoint| {
            checkpoint
                .replacement
                .is_none()
                .then_some(checkpoint.pending_call)
                .flatten()
        });

        let mut consumed_input = work.input_id();
        let mut base = work.base.clone();
        let mut continuations = alloc::vec::Vec::new();
        let mut exported_blobs = alloc::vec::Vec::new();
        if let Some(checkpoint) = actor_output.checkpoint {
            consumed_input = checkpoint.input;
            base = checkpoint.base.clone();
            // The service VM is itself part of the exact nested snapshot and
            // therefore retains its pre-suspension WorkEnvelope. The
            // post-snapshot token is the scheduler's handoff for consensus
            // inputs that advance between slices; Accumulate independently
            // checks all of them against the admitted current work.
            work.invocation = checkpoint.input.invocation;
            work.workflow_step = checkpoint.input.workflow_step;
            work.base = checkpoint.base;
            work.base_causal_height = checkpoint.base_causal_height;
            if checkpoint.change != CrdtChangeV2::derive_id(&work) {
                fail_closed();
            }
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
        let (writes, crdt_change, candidate_blobs) = match (&work.base, work.base_causal_height) {
            (ConsistencyBaseV2::Linear { .. }, None) => {
                if !actor_output.crdt_operations.is_empty() || !actor_output.crdt_states.is_empty()
                {
                    fail_closed();
                }
                (actor_output.writes, None, alloc::vec::Vec::new())
            }
            (ConsistencyBaseV2::Crdt { heads }, Some(base_height)) => {
                if !actor_output.writes.is_empty() {
                    fail_closed();
                }
                if actor_output.crdt_states.is_empty()
                    || actor_output
                        .crdt_states
                        .iter()
                        .any(|state| !imported(state.actor))
                {
                    fail_closed();
                }
                let id = CrdtChangeV2::derive_id(&work).unwrap_or_else(|| fail_closed());
                if actor_output.crdt_operations.iter().any(|operation| {
                    !imported(operation.actor)
                        || operation.id
                            != id.operation(operation.actor, operation.field, operation.ordinal)
                }) {
                    fail_closed();
                }
                let causal_height = base_height.checked_add(1).unwrap_or_else(|| fail_closed());
                let mut candidates = alloc::collections::BTreeMap::new();
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
                        id,
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
        let mut transition = TransitionV2 {
            service: work.service.clone(),
            consumed_input,
            target_program: work.target_program,
            base,
            writes,
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
            Ok(request) => execute_guest_accumulate(&mut JamAccumulateStore, &request)
                .unwrap_or_else(|_| fail_closed()),
            Err(_) => AccumulationResultV2::Rejected(AccumulationRejectionV2::NonCanonical),
        };
        output(&result.encode())
    }

    const STORAGE_PROBE_CAPACITY: usize = 4096;
    const MAX_STORAGE_VALUE: usize = 64 * 1024 * 1024;

    struct JamAccumulateStore;

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
        fn authorize_install(
            &self,
            genesis: &vos::v2::ServiceGenesisV2,
        ) -> Result<bool, Self::Error> {
            Ok(hostcalls::verify_install_authorization(&genesis.encode()) == error::HOST_OK)
        }

        fn blob_available(&self, reference: &BlobRefV2) -> Result<bool, Self::Error> {
            let mut probe = [0u8; 1];
            Ok(hostcalls::preimage_lookup(&reference.hash.0, &mut probe) == reference.len)
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
