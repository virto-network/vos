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
        GasAccountingV2, GuestAccumulateStoreV2, ImportedBlobV2, RefineOutputV2, ReplyRecordV2,
        StateTreeStore, TransitionV2, V2Wire, WorkEnvelopeV2, execute_guest_accumulate,
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
    /// HANDLE. Slot 80 is supplied at invocation setup; it is not a JAM
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
        let work = WorkEnvelopeV2::decode(input).unwrap_or_else(|_| fail_closed());
        if work.service.service_abi != vos::v2::ABI_VERSION
            || work.service.execution_semantics != vos::v2::EXECUTION_SEMANTICS_ID
            || !work.base.mode_compatible(work.consistency)
        {
            fail_closed();
        }

        if actor_input_len > actor_ipc_capacity || actor_ipc_capacity == 0 {
            fail_closed();
        }

        // Actor manifests use slot 0 for their standalone argument window,
        // while JAR reserves slot 0 as the callee IPC slot. Preserve that
        // canonical manifest capability in a spare slot for the duration of
        // CALL; this is VOS policy expressed with ordinary JAR MOVE, not a
        // kernel special case.
        let actor_args = ecall::cap_ref_through_handle(vos::v2::TARGET_ACTOR_HANDLE_SLOT, 0);
        let saved_actor_args = ecall::cap_ref_through_handle(
            vos::v2::TARGET_ACTOR_HANDLE_SLOT,
            vos::v2::ACTOR_SAVED_ARGS_CAP_SLOT,
        );
        if !ecall::move_cap(actor_args, saved_actor_args) {
            fail_closed();
        }

        let actor_output_len = ecall::ecall6(
            vos::v2::TARGET_ACTOR_HANDLE_SLOT as u32,
            vos::v2::ACTOR_IPC_BASE_PAGE as u64 * 4096,
            actor_input_len as u64,
            actor_ipc_capacity as u64,
            vos::v2::NESTED_ACTOR_CALL_MAGIC,
            0,
            vos::v2::ACTOR_IPC_CAP_SLOT as u64,
        ) as usize;
        if !ecall::move_cap(saved_actor_args, actor_args)
            || actor_output_len == 0
            || actor_output_len > actor_ipc_capacity
        {
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
        if actor_output.actor != work.target || actor_output.forbidden {
            fail_closed();
        }

        let mut consumed_input = work.input_id();
        let mut base = work.base.clone();
        let mut continuations = alloc::vec::Vec::new();
        let mut exported_blobs = alloc::vec::Vec::new();
        if let Some(checkpoint) = actor_output.checkpoint {
            if checkpoint.input != work.input_id() || checkpoint.base != work.base {
                fail_closed();
            }
            consumed_input = checkpoint.input;
            base = checkpoint.base;
            if let Some(replacement) = checkpoint.replacement.as_ref() {
                exported_blobs.push(replacement.clone());
            }
            continuations.push(ContinuationChangeV2 {
                actor: work.target,
                expected: checkpoint.expected,
                replacement: checkpoint.replacement,
            });
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
                if !actor_output.crdt_operations.is_empty()
                    || actor_output.crdt_materialization.is_some()
                {
                    fail_closed();
                }
                (actor_output.writes, None, alloc::vec::Vec::new())
            }
            (ConsistencyBaseV2::Crdt { heads }, Some(base_height)) => {
                if !actor_output.writes.is_empty() {
                    fail_closed();
                }
                let materialized = actor_output
                    .crdt_materialization
                    .unwrap_or_else(|| fail_closed());
                let id = CrdtChangeV2::derive_id(&work).unwrap_or_else(|| fail_closed());
                if actor_output.crdt_operations.iter().any(|operation| {
                    operation.actor != work.target
                        || operation.id
                            != id.operation(operation.actor, operation.field, operation.ordinal)
                }) {
                    fail_closed();
                }
                let causal_height = base_height.checked_add(1).unwrap_or_else(|| fail_closed());
                let reference = BlobRefV2::of_bytes(&materialized);
                (
                    alloc::vec::Vec::new(),
                    Some(CrdtChangeV2 {
                        id,
                        causal_dependencies: heads.clone(),
                        causal_height,
                        operations: actor_output.crdt_operations,
                        workflow: alloc::vec::Vec::new(),
                        materializations: alloc::vec![CrdtMaterializationV2 {
                            actor: work.target,
                            state: reference.clone(),
                        }],
                    }),
                    alloc::vec![ImportedBlobV2 {
                        reference,
                        bytes: materialized,
                    }],
                )
            }
            _ => fail_closed(),
        };
        let mut transition = TransitionV2 {
            service: work.service,
            consumed_input,
            target_program: work.target_program,
            base,
            writes,
            crdt_change,
            continuations,
            inbox: alloc::vec::Vec::new(),
            outbox: alloc::vec::Vec::new(),
            reply,
            exported_blobs,
            gas: GasAccountingV2::default(),
            proof: None,
        };
        let workflow = transition.workflow_operations();
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
