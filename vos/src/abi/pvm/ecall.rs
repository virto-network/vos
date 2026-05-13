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

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn _ecall(id: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let ret: u64;
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
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a5") a5,
            options(nostack),
        );
    }
    ret
}

#[cfg(not(target_arch = "riscv64"))]
#[inline(always)]
fn _ecall(id: u64, _a0: u64, _a1: u64, _a2: u64, _a3: u64, _a4: u64, _a5: u64) -> u64 {
    panic!("vos-abi ecalls require RISC-V target (id={id})")
}
