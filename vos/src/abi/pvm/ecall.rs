//! Raw ecall interface.
//!
//! On RISC-V, loads the hostcall ID into `t0` and executes `ecall`.
//! The grey-transpiler converts this to a PVM `ecalli` instruction.
//!
//! Per JAR spec `Capability.lean:169-182`, the ecalli calling convention is:
//!
//! - `imm`            = subject cap (the hostcall identity, spec slot 1..=28)
//! - `phi[7..=11]`    = 5 data arguments
//! - `phi[12]`        = **object cap** (u32, byte-packed indirection encoding)
//!
//! The grey-transpiler maps RISC-V `a0..=a4` (`x10..=x14`) → PVM `phi[7..=11]`
//! and RISC-V `a5` (`x15`) → PVM `phi[12]` (see
//! `grey-transpiler/src/riscv.rs`).
//!
//! For a direct reference to a local cap slot (no indirection), the object
//! cap is just `(slot as u32)` — per spec `Capability.lean:109`:
//! "`(u8 as u32)` zero-extended = local slot, backward compatible".
//!
//! VOS uses the **stack cap** (slot 65, emitted by `grey-transpiler`) as the
//! default object cap for every hostcall. The rationale: hostcall argument
//! buffers typically live in stack frames, and the kernel's Linux backend
//! reads guest memory via a flat 4GB window so the declared cap is mostly
//! ceremonial for reads. Writes via `kernel.write_data_cap` do honor the
//! declared cap, so any hostcall that takes an out-buffer must ensure the
//! buffer actually lives in cap 65 (i.e. on the stack).

/// VOS convention: the PVM cap slot used as the default object cap for
/// every hostcall. Matches the stack DATA cap emitted by
/// `grey-transpiler/src/emitter.rs`. Direct reference, no indirection.
pub const VOS_OBJECT_CAP: u64 = 65;
const RESULT_WHAT: u64 = u64::MAX - 1;

/// Invoke a hostcall with no arguments.
#[inline(always)]
pub fn ecall0(id: u32) -> u64 {
    _ecall(id as u64, 0, 0, 0, 0, 0, VOS_OBJECT_CAP)
}

/// Invoke a hostcall with one argument.
#[inline(always)]
pub fn ecall1(id: u32, a0: u64) -> u64 {
    _ecall(id as u64, a0, 0, 0, 0, 0, VOS_OBJECT_CAP)
}

/// Invoke a hostcall with two arguments.
#[inline(always)]
pub fn ecall2(id: u32, a0: u64, a1: u64) -> u64 {
    _ecall(id as u64, a0, a1, 0, 0, 0, VOS_OBJECT_CAP)
}

/// Invoke a hostcall with three arguments.
#[inline(always)]
pub fn ecall3(id: u32, a0: u64, a1: u64, a2: u64) -> u64 {
    _ecall(id as u64, a0, a1, a2, 0, 0, VOS_OBJECT_CAP)
}

/// Invoke a hostcall with four arguments.
#[inline(always)]
pub fn ecall4(id: u32, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    _ecall(id as u64, a0, a1, a2, a3, 0, VOS_OBJECT_CAP)
}

/// Invoke a hostcall with five arguments.
#[inline(always)]
pub fn ecall5(id: u32, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    _ecall(id as u64, a0, a1, a2, a3, a4, VOS_OBJECT_CAP)
}

/// Invoke a hostcall with five arguments and an explicit object cap in
/// `phi[12]`. Use this when the buffers passed via `a0..=a4` live in a
/// non-default cap (e.g. the RO data cap or the heap cap). For the common
/// case where args live on the stack, prefer [`ecall5`].
#[inline(always)]
pub fn ecall6(id: u32, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, obj_cap: u64) -> u64 {
    _ecall(id as u64, a0, a1, a2, a3, a4, obj_cap)
}

/// Invoke a two-argument hostcall and preserve both result registers.
#[inline(always)]
pub fn ecall2_pair(id: u32, a0: u64, a1: u64) -> [u64; 2] {
    _ecall_pair(id as u64, a0, a1, 0, 0, 0, VOS_OBJECT_CAP)
}

/// Reference a slot in the current CNode for a dynamic JAR management call.
pub const fn local_cap_ref(slot: u8) -> u32 {
    slot as u32
}

/// Reference `slot` in the CNode owned through a local HANDLE.
pub const fn cap_ref_through_handle(handle_slot: u8, slot: u8) -> u32 {
    slot as u32 | ((handle_slot as u32) << 8)
}

/// Map every page of a DATA capability read/write at `base_page`.
#[inline(always)]
pub fn map_cap_rw(cap_slot: u8, base_page: u32, page_count: u32) -> bool {
    _management_ecall(
        base_page as u64,
        0,
        page_count as u64,
        1,
        0x02,
        (local_cap_ref(cap_slot) as u64) << 32,
    ) != RESULT_WHAT
}

/// Move a capability between CNodes using ordinary JAR cap references.
#[inline(always)]
pub fn move_cap(subject: u32, object: u32) -> bool {
    _management_ecall(0, 0, 0, 0, 0x06, ((subject as u64) << 32) | object as u64) != RESULT_WHAT
}

/// Return from a nested JAR CALL through the reserved IPC capability slot.
#[cfg(target_arch = "riscv64")]
#[inline(always)]
pub fn reply(value: u64) -> ! {
    // SAFETY: ecalli(0) is JAR REPLY for a nested VM. The kernel transfers
    // control to the waiting caller, so this actor invocation never resumes.
    unsafe {
        core::arch::asm!(
            "csrw 0x801, zero",
            "ecall",
            in("t0") 0u64,
            in("a0") value,
            in("a1") 0u64,
            in("a2") 0u64,
            in("a3") 0u64,
            in("a4") 0u64,
            in("a5") 0u64,
            options(noreturn, nostack),
        );
    }
}

#[cfg(not(target_arch = "riscv64"))]
#[inline(always)]
pub fn reply(_value: u64) -> ! {
    panic!("vos-abi JAR reply requires RISC-V target")
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn _management_ecall(a0: u64, a1: u64, a2: u64, a3: u64, op: u64, refs: u64) -> u64 {
    let ret: u64;
    // SAFETY: CSR 0x800 is the transpiler marker for the GP dynamic `ecall`
    // form. phi[11] carries the operation and phi[12] the subject/object refs.
    unsafe {
        core::arch::asm!(
            "csrw 0x800, zero",
            "ecall",
            inlateout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") op,
            in("a5") refs,
            options(nostack),
        );
    }
    ret
}

#[cfg(not(target_arch = "riscv64"))]
#[inline(always)]
fn _management_ecall(_a0: u64, _a1: u64, _a2: u64, _a3: u64, op: u64, _refs: u64) -> u64 {
    panic!("vos-abi JAR management ecalls require RISC-V target (op={op})")
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn _ecall(id: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let ret: u64;
    let discarded_result1: u64;
    // SAFETY: this is the PVM hostcall trap. The asm! block has no
    // memory operands; the host reads guest memory through caps. The
    // `nostack` option promises we don't touch the stack pointer.
    // The hostcall ID + arg semantics are defined by VOS ABI; the
    // host validates each ID before acting.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") id,
            inlateout("a0") a0 => ret,
            // JAR protocol calls inject their two-word result into phi[7]/
            // phi[8] (a0/a1). Even hostcalls whose public wrapper returns one
            // word therefore clobber a1 at the suspension boundary.
            inlateout("a1") a1 => discarded_result1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a5") a5,
            options(nostack),
        );
    }
    let _ = discarded_result1;
    ret
}

#[cfg(not(target_arch = "riscv64"))]
#[inline(always)]
fn _ecall(id: u64, _a0: u64, _a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> u64 {
    panic!("vos-abi ecalls require RISC-V target (id={id})")
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn _ecall_pair(id: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> [u64; 2] {
    let ret0: u64;
    let ret1: u64;
    // SAFETY: same hostcall boundary as `_ecall`; JAR injects the one
    // suspension result into phi[7]/phi[8] before execution resumes.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") id,
            inlateout("a0") a0 => ret0,
            inlateout("a1") a1 => ret1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a5") a5,
            options(nostack),
        );
    }
    [ret0, ret1]
}

#[cfg(not(target_arch = "riscv64"))]
#[inline(always)]
fn _ecall_pair(id: u64, _a0: u64, _a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> [u64; 2] {
    panic!("vos-abi ecalls require RISC-V target (id={id})")
}
