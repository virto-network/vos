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
    use vos::v2::{
        ActorSliceOutputV2, ContinuationChangeV2, GasAccountingV2, ReplyRecordV2, TransitionV2,
        V2Wire, WorkEnvelopeV2,
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
            if checkpoint.input.invocation != work.invocation
                || !checkpoint.base.mode_compatible(work.consistency)
            {
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
        let transition = TransitionV2 {
            service: work.service,
            consumed_input,
            target_program: work.target_program,
            base,
            writes: actor_output.writes,
            crdt_operations: alloc::vec::Vec::new(),
            resulting_crdt_heads: alloc::vec::Vec::new(),
            continuations,
            inbox: alloc::vec::Vec::new(),
            outbox: alloc::vec::Vec::new(),
            reply,
            exported_blobs,
            gas: GasAccountingV2::default(),
            proof: None,
        };
        let encoded = transition.encode();
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

    /// Accumulate remains fail-closed until the guest storage transaction logic is
    /// implemented. Keeping the physical symbol present lets every build verify
    /// the IC-5 entry without ever treating a no-op as a successful commit.
    #[unsafe(no_mangle)]
    extern "C" fn vos_service_accumulate(
        _arguments: *const u8,
        _arguments_len: usize,
    ) -> OutputWindow {
        fail_closed()
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
