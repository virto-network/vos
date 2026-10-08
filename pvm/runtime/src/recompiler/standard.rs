//! Standard-machine bridge. Native code and interpreter share architectural
//! state and the same memory pages; only the boundary register state is copied.

use super::{CompiledCode, JitContext, prepare_external_entry, signal};
use crate::{ExitReason, Interpreter, IsaMode, PendingHostCall};

pub(crate) fn run_standard(
    compiled: &CompiledCode,
    vm: &mut Interpreter,
) -> Result<ExitReason, String> {
    let window = vm.memory_mut().native_window()?;
    let context_pointer = window.ctx_ptr().cast::<JitContext>();
    let flat_buf = window.base();
    let flat_perms = window.perms();
    let pending = vm.pending_host_call();
    let context = JitContext {
        regs: vm.registers,
        gas: vm.gas,
        gas_charged: u32::from(vm.gas_charged),
        host_pending: u32::from(pending.is_some()),
        host_resume_pc: pending.map_or(0, |call| call.resume_pc),
        dispatch_len: compiled.dispatch_table.len() as u32,
        exit_reason: 0,
        exit_arg: pending.map_or(0, |call| call.id),
        heap_base: vm.heap_base,
        heap_top: vm.heap_top,
        jt_ptr: vm.jump_table.as_ptr(),
        jt_len: vm.jump_table.len() as u32,
        _pad0: 0,
        bb_starts: compiled.block_starts.as_ptr(),
        bb_len: compiled.block_starts.len() as u32,
        _pad1: 0,
        entry_pc: vm.pc,
        pc: vm.pc,
        dispatch_table: compiled.dispatch_table.as_ptr(),
        code_base: compiled.native_code.ptr as u64,
        flat_buf,
        flat_perms,
        fast_reentry: 0,
        _pad2: 0,
        max_heap_pages: vm.max_heap_pages,
        _pad3: 0,
        original_bitmap: [0; 32],
    };
    // SAFETY: native_window reserves an aligned, writable context page; the
    // guest alias excludes it. All metadata pointers remain owned throughout
    // this synchronous execution and host access holds exclusive ownership.
    let context = unsafe {
        context_pointer.write(context);
        &mut *context_pointer
    };
    if prepare_external_entry(
        context,
        &compiled.fault_resume_offsets,
        &compiled.gas_block_start_by_pc,
        &compiled.block_gas_costs,
        IsaMode::Conformance,
    )
    .is_none()
    {
        signal::ensure_installed();
        let mut state = signal::SignalState {
            code_start: compiled.native_code.ptr as usize,
            code_end: compiled.native_code.ptr as usize + compiled.native_code.len,
            exit_label_addr: compiled.native_code.ptr as usize
                + compiled.exit_label_offset as usize,
            ctx_ptr: context_pointer,
            trap_table_ptr: compiled.trap_table.as_ptr(),
            trap_table_len: compiled.trap_table.len(),
            fault_resume_offsets_ptr: compiled.fault_resume_offsets.as_ptr(),
            fault_resume_offsets_len: compiled.fault_resume_offsets.len(),
        };
        // Preserve a prior owner even when embedders nest native execution.
        let previous = signal::SIGNAL_STATE.with(|cell| cell.replace(&mut state));
        // SAFETY: code is immutable executable preparation; context and guest
        // mapping follow the existing recompiler ABI and signal-state lifetime.
        unsafe {
            compiled.native_code.entry()(context_pointer);
        }
        signal::SIGNAL_STATE.with(|cell| cell.set(previous));
    }
    vm.registers = context.regs;
    vm.gas = context.gas;
    vm.pc = context.pc;
    vm.heap_base = context.heap_base;
    vm.heap_top = context.heap_top;
    vm.restore_boundary_state(
        context.gas_charged != 0,
        (context.host_pending != 0).then_some(PendingHostCall {
            id: context.exit_arg,
            cause_pc: context.pc,
            resume_pc: context.host_resume_pc,
        }),
    );
    Ok(match context.exit_reason {
        0 => ExitReason::Halt,
        1 => ExitReason::Panic,
        2 => ExitReason::OutOfGas,
        3 => ExitReason::PageFault(
            u32::try_from(context.exit_arg)
                .expect("native page-fault argument is a 32-bit address"),
        ),
        4 => ExitReason::HostCall(context.exit_arg),
        6 => ExitReason::Ecall,
        7 => ExitReason::Trap,
        _ => return Err("invalid native exit reason".into()),
    })
}
