//! Standard-machine bridge. Native code and interpreter share architectural
//! state and the same memory pages; only the boundary register state is copied.

use super::{CompiledCode, JitContext, prepare_external_entry, signal};
use crate::{ExitReason, Interpreter, PendingHostCall};

/// Run one slice of `vm` natively: `None` where its memory runs on the
/// interpreter, which then runs the slice over the same state.
pub(crate) fn run_standard(
    compiled: &CompiledCode,
    vm: &mut Interpreter,
) -> Result<Option<ExitReason>, String> {
    let Some((window, activation)) = vm.memory_mut().native_window()? else {
        return Ok(None);
    };
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
    )
    .is_none()
    {
        if let Err(error) = signal::ensure_installed() {
            // Nothing native ran: the interpreter takes the slice.
            tracing::debug!(%error, "interpreting without a fault handler");
            return Ok(None);
        }
        let code_start = compiled.native_code.ptr as usize;
        let mut state = signal::SignalState {
            code_start,
            code_end: code_start + compiled.native_code.len,
            exit_label_addr: code_start + compiled.exit_label_offset as usize,
            abort_label_addr: code_start + compiled.abort_label_offset as usize,
            window_base: flat_buf as usize,
            ctx_ptr: context_pointer,
            trap_table_ptr: compiled.trap_table.as_ptr(),
            trap_table_len: compiled.trap_table.len(),
            fault_resume_offsets_ptr: compiled.fault_resume_offsets.as_ptr(),
            fault_resume_offsets_len: compiled.fault_resume_offsets.len(),
            activation,
            entry_rsp: 0,
            backend_fault: Default::default(),
        };
        // The handler and native code reach the state only through this
        // pointer while native code runs.
        let state_pointer = &raw mut state;
        // SAFETY: a field of the live state, through its one pointer.
        let entry_rsp = unsafe { &raw mut (*state_pointer).entry_rsp };
        // Preserve a prior owner even when embedders nest native execution.
        let previous = signal::SIGNAL_STATE.with(|cell| cell.replace(state_pointer));
        // SAFETY: code is immutable executable preparation; context and guest
        // mapping follow the existing recompiler ABI and signal-state lifetime.
        unsafe {
            compiled.native_code.entry()(context_pointer, entry_rsp);
        }
        signal::SIGNAL_STATE.with(|cell| cell.set(previous));
        if state.backend_faulted() {
            // The machine's state is not meaningful: its memory reports
            // every page from now on, and it is never run again.
            // SAFETY: the activation belongs to the window, live here.
            unsafe { (*activation).fail() };
            return Err("native code faulted outside a guest access".into());
        }
    }
    vm.registers = context.regs;
    vm.gas = context.gas;
    vm.pc = context.pc;
    vm.restore_boundary_state(
        context.gas_charged != 0,
        (context.host_pending != 0).then_some(PendingHostCall {
            id: context.exit_arg,
            cause_pc: context.pc,
            resume_pc: context.host_resume_pc,
        }),
    );
    Ok(Some(match context.exit_reason {
        0 => ExitReason::Halt,
        1 => ExitReason::Panic,
        2 => ExitReason::OutOfGas,
        3 => ExitReason::PageFault(
            u32::try_from(context.exit_arg)
                .expect("native page-fault argument is a 32-bit address"),
        ),
        4 => ExitReason::HostCall(context.exit_arg),
        super::codegen::EXIT_TRACKING_FAILED => {
            return Err("native write tracking failed".into());
        }
        super::codegen::EXIT_INVALID_ENTRY => {
            return Err("native entry past the dispatch table".into());
        }
        _ => return Err("invalid native exit reason".into()),
    }))
}
