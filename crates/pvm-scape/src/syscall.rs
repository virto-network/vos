//! Raw syscall interface.
//!
//! On RISC-V, loads the syscall number into `t0` and executes `ecall`.
//! The grey-transpiler converts this to a PVM `ecalli` instruction
//! with the syscall number as the host-call ID.
//!
//! The executor traps the `ecalli`, reads arguments from registers
//! `a0`–`a5`, dispatches through `SyscallHandler`, and writes the
//! return value back into `a0`.

use pvm_abi::syscall::Syscall;

/// Invoke a syscall with no arguments.
#[inline(always)]
pub fn syscall0(nr: Syscall) -> i64 {
    _syscall(nr as u64, 0, 0, 0, 0)
}

/// Invoke a syscall with one argument.
#[inline(always)]
pub fn syscall1(nr: Syscall, a0: i64) -> i64 {
    _syscall(nr as u64, a0 as u64, 0, 0, 0)
}

/// Invoke a syscall with two arguments.
#[inline(always)]
pub fn syscall2(nr: Syscall, a0: i64, a1: i64) -> i64 {
    _syscall(nr as u64, a0 as u64, a1 as u64, 0, 0)
}

/// Invoke a syscall with three arguments.
#[inline(always)]
pub fn syscall3(nr: Syscall, a0: i64, a1: i64, a2: i64) -> i64 {
    _syscall(nr as u64, a0 as u64, a1 as u64, a2 as u64, 0)
}

/// Invoke a syscall with four arguments.
#[inline(always)]
pub fn syscall4(nr: Syscall, a0: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    _syscall(nr as u64, a0 as u64, a1 as u64, a2 as u64, a3 as u64)
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn _syscall(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") nr,
            inlateout("a0") a0 as i64 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            options(nostack),
        );
    }
    ret
}

#[cfg(not(target_arch = "riscv64"))]
#[inline(always)]
fn _syscall(nr: u64, _a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    panic!("pvm-scape syscalls require RISC-V target (nr={nr})")
}
