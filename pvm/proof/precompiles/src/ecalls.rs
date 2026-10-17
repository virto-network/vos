//! Host-call identifiers — the wire ABI between guest precompile shims
//! and the prover's `Blake2bChip`. Mirrors the corresponding constants in
//! `vos_pvm_proof::core::ecall`.

/// One blake2b compression per call.
/// Mirrors `vos_pvm_proof::core::ecall::ECALL_BLAKE2B_COMPRESS`.
/// Convention: φ\[7\]=h_ptr (64B in/out), φ\[8\]=m_ptr (128B in),
/// φ\[9\]=t_low (counter low 64 bits), φ\[10\]=f (finalize flag).
pub const ECALL_BLAKE2B_COMPRESS: u32 = 0x400;

/// Gray Paper `WHAT`: the host does not know this call.
#[cfg(target_arch = "riscv64")]
pub(crate) const WHAT: u64 = u64::MAX - 1;

/// Call precompile `ID` with arguments in a0..a3 (φ[7..10]). Returns `false`
/// when the host answered `WHAT`, as a JAM node does for an id it does not
/// assign; the caller then computes in software. A serving host leaves every
/// register unchanged, so φ[7] still holds the first argument, a pointer.
///
/// The id is loaded with `li` inside the block so the transpiler always sees
/// it immediately before the call.
#[cfg(target_arch = "riscv64")]
#[inline(always)]
pub(crate) fn call<const ID: u32>(a0: u64, a1: u64, a2: u64, a3: u64) -> bool {
    let answer: u64;
    // SAFETY: the arguments name buffers the caller keeps live for the call;
    // the host writes only the output buffer they describe and φ[7] on WHAT.
    unsafe {
        core::arch::asm!(
            "li t0, {id}",
            "csrw 0x801, zero",
            "ecall",
            id = const ID,
            out("t0") _,
            inlateout("a0") a0 => answer,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            options(nostack),
        );
    }
    answer != WHAT
}
