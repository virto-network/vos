//! Raw ecall interface.
//!
//! On RISC-V, loads the hostcall ID into `t0` and executes `ecall`.
//! The grey-transpiler converts this to a PVM `ecalli` instruction.
//! The host reads arguments from `a0`–`a5` and writes the return value to `a0`.

/// Invoke a hostcall with no arguments.
#[inline(always)]
pub fn ecall0(id: u32) -> u64 {
    _ecall(id as u64, 0, 0, 0, 0, 0)
}

/// Invoke a hostcall with one argument.
#[inline(always)]
pub fn ecall1(id: u32, a0: u64) -> u64 {
    _ecall(id as u64, a0, 0, 0, 0, 0)
}

/// Invoke a hostcall with two arguments.
#[inline(always)]
pub fn ecall2(id: u32, a0: u64, a1: u64) -> u64 {
    _ecall(id as u64, a0, a1, 0, 0, 0)
}

/// Invoke a hostcall with three arguments.
#[inline(always)]
pub fn ecall3(id: u32, a0: u64, a1: u64, a2: u64) -> u64 {
    _ecall(id as u64, a0, a1, a2, 0, 0)
}

/// Invoke a hostcall with four arguments.
#[inline(always)]
pub fn ecall4(id: u32, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    _ecall(id as u64, a0, a1, a2, a3, 0)
}

/// Invoke a hostcall with five arguments.
#[inline(always)]
pub fn ecall5(id: u32, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    _ecall(id as u64, a0, a1, a2, a3, a4)
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn _ecall(id: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") id,
            inlateout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            options(nostack),
        );
    }
    ret
}

#[cfg(not(target_arch = "riscv64"))]
#[inline(always)]
fn _ecall(id: u64, _a0: u64, _a1: u64, _a2: u64, _a3: u64, _a4: u64) -> u64 {
    panic!("vos-abi ecalls require RISC-V target (id={id})")
}
