//! Precompile host-call identifiers shared between the always-compiled chip
//! surface and the prover-only tracer. Identifiers are pure data — no
//! execution semantics live here — so a no_std verifier can classify them
//! without pulling in `core::tracing`.
//!
//! The wire identifier is what a program's `ecalli` names; the CPU chip
//! selects each precompile relation by a separate internal dispatch code
//! ([`proof_precompile_dispatch_id`]).

/// Hostcall ID for blake2b_compress precompile: the VOS precompile id,
/// outside every id JAM assigns (`vos_pvm::precompile::BLAKE2B_COMPRESS`).
/// The CPU chip selects the BLAKE2b relation by the internal dispatch code
/// `DISPATCH_BLAKE2B_COMPRESS`, not by this wire id.
/// Convention: φ\[7\] = h pointer, φ\[8\] = m pointer, φ\[9\] = counter low 64
/// bits, φ\[10\] = finalize flag. h is read (64 bytes), m is read (128 bytes).
/// The result overwrites h.
pub const ECALL_BLAKE2B_COMPRESS: u32 = 0x400;
/// CPU-chip dispatch code for the BLAKE2b relation.
pub(crate) const DISPATCH_BLAKE2B_COMPRESS: u8 = 100;

/// Hostcall ID for a kernel's witness input (`vos_pvm::precompile::WITNESS_INPUT`):
/// φ\[7\] the destination, φ\[8\] the capacity. It writes the next
/// `min(capacity, remaining)` bytes of the run's input at the destination
/// and returns their count in φ\[7\]. The bytes are free witness; the
/// CPU chip selects the call by `DISPATCH_WITNESS_INPUT` and binds its
/// registers, its count and the range it writes
/// (`chips::WitnessInputChip`).
pub const ECALL_WITNESS_INPUT: u32 = 0x401;
/// CPU-chip dispatch code for the witness input.
pub(crate) const DISPATCH_WITNESS_INPUT: u8 = 101;

/// Whether the proof runtime has a deterministic handler for this `ecalli`
/// identifier: exactly the calls [`crate::core::tracing::TracingPvm`]
/// serves.
///
/// This is a kernel's calls, the runtime's precompile set and the witness
/// input. Any other id, 110 to 114 included, has no handler: a program
/// reaching one does not trace.
///
/// ProgramMemory commits the dispatch identifier, which is non-zero exactly
/// for these calls, so an untrusted prover cannot mark an unknown call as
/// acknowledged and continue execution past it.
pub(crate) const fn is_proof_host_call_allowed(id: u64) -> bool {
    proof_precompile_dispatch_id(id) != 0
}

/// Exact proof-chip dispatch identifier for a precompile or the witness
/// input, or
/// zero for any other identifier. A non-zero value is committed by
/// ProgramMemory and binds a continued host-call row to the matching CPU
/// selector (and therefore to that selector's call relation).
pub const fn proof_precompile_dispatch_id(id: u64) -> u8 {
    match id {
        id if id == ECALL_BLAKE2B_COMPRESS as u64 => DISPATCH_BLAKE2B_COMPRESS,
        id if id == ECALL_WITNESS_INPUT as u64 => DISPATCH_WITNESS_INPUT,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tracer serves exactly the calls a kernel may make, the refine
    /// host's precompiles and the witness input; 110 to 114 are none.
    #[test]
    fn tracer_serves_exactly_the_kernel_calls() {
        assert_eq!(
            u64::from(ECALL_WITNESS_INPUT),
            vos_pvm::precompile::WITNESS_INPUT
        );
        for id in 0..0x1000u64 {
            assert_eq!(
                is_proof_host_call_allowed(id),
                vos_pvm::precompile::is_kernel_call(id),
                "id {id:#x}"
            );
        }
        for id in 110..=114 {
            assert_eq!(proof_precompile_dispatch_id(id), 0, "id {id}");
        }
    }
}
