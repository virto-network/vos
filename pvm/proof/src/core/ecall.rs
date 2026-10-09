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
/// [`DISPATCH_BLAKE2B_COMPRESS`], not by this wire id.
/// Convention: φ[7] = h pointer, φ[8] = m pointer, φ[9] = counter low 64
/// bits, φ[10] = finalize flag. h is read (64 bytes), m is read (128 bytes).
/// The result overwrites h.
pub const ECALL_BLAKE2B_COMPRESS: u32 = 0x400;
/// CPU-chip dispatch code for the BLAKE2b relation.
pub(crate) const DISPATCH_BLAKE2B_COMPRESS: u8 = 100;

/// Hostcall ID for Ristretto255 scalar multiplication precompile.
///
/// Convention:
///   φ[7] = scalar_ptr  (32 canonical bytes, scalar mod ℓ)
///   φ[8] = point_ptr   (32 bytes, compressed Ristretto encoding)
///   φ[9] = output_ptr  (32 bytes, compressed Ristretto, written by the call)
///
/// scalar_ptr (32B read) and point_ptr (32B read) are inputs;
/// output_ptr (32B write) receives the compressed encoding of `k * P`.
/// All three buffers must lie in flat_mem; they may alias subject to
/// the read-before-write ordering the MemoryChip ledger enforces (the
/// 64 reads at the call's timestamp are inserted before the 32 writes).
///
/// On non-canonical scalar bytes or an invalid point encoding the
/// precompile writes the empty-result sentinel `[0u8; 32]` (which is
/// the canonical compressed Ristretto identity, so callers must
/// validate against expected output rather than treating zeros as
/// "ok").  The chip's constraints will accept this output as the
/// canonical "input was malformed" branch.
pub const ECALL_RISTRETTO_SCALAR_MULT: u32 = 110;

/// Hostcall ID for Ristretto255 compressed-point addition precompile.
///
/// Convention:
///   φ[7] = p_ptr      (32 bytes, compressed Ristretto)
///   φ[8] = q_ptr      (32 bytes, compressed Ristretto)
///   φ[9] = output_ptr (32 bytes, compressed Ristretto, written by call)
///
/// Decompresses both operands, adds them as Ristretto group elements,
/// recompresses, and writes the result.  On non-canonical or invalid
/// input encodings, writes the canonical compressed identity
/// (`[0u8; 32]`).  Used by callers to compose Pedersen commits like
/// `v·G + b·H` as one scalar-mult ECALL + one scalar-mult ECALL +
/// one add ECALL — all the curve arithmetic happens host-side
/// (chip-side under R1f-bis), no PVM-level field ops.
pub const ECALL_RISTRETTO_POINT_ADD: u32 = 111;

/// Hostcall ID for the Ristretto255 wide-scalar reduction precompile.
///
/// Convention:
///   φ[7] = wide_ptr   (64 bytes input — the uniform-random source)
///   φ[8] = output_ptr (32 bytes — canonical scalar mod ℓ, written)
///
/// Replaces dalek's `Scalar::from_bytes_mod_order_wide` (which on
/// PVM expands into ~60% of an `Amount::commit` trace via the
/// u64-backend's `montgomery_mul / sub / pack` chain).  Output is
/// always a canonical 32-byte scalar in [0, ℓ); the host-side
/// reference goes through `curve25519-dalek` so the result agrees
/// bit-for-bit with the dalek reference values.
pub const ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE: u32 = 112;

/// Hostcall ID for scalar multiplication mod ℓ (Schnorr/Ristretto
/// scalar field).  Mirrors dalek's `Scalar * Scalar` public API.
///
/// Convention:
///   φ[7] = a_ptr      (32 canonical bytes — Scalar mod ℓ)
///   φ[8] = b_ptr      (32 canonical bytes)
///   φ[9] = output_ptr (32 bytes — `(a * b) mod ℓ`, written)
pub const ECALL_SCALAR_MUL_MOD_L: u32 = 113;

/// Hostcall ID for scalar addition mod ℓ.  Mirrors dalek's
/// `Scalar + Scalar` public API.  Same convention as MUL above.
pub const ECALL_SCALAR_ADD_MOD_L: u32 = 114;

/// Whether the proof runtime has a deterministic handler for this `ecalli`
/// identifier: exactly the cryptographic precompiles handled by
/// [`crate::core::tracing::TracingPvm`].
///
/// This is the runtime's precompile set plus the Ristretto and scalar ids
/// 110–114, which only this tracer serves: the refine host answers them with
/// `WHAT`, and the guest computes in software. A program using them
/// therefore traces differently here than it runs on VOS. Step 5 moves these
/// ids into the VOS range and serves them on the refine host as well.
///
/// ProgramMemory commits the dispatch identifier, which is non-zero exactly
/// for these calls, so an untrusted prover cannot mark an unknown call as
/// acknowledged and continue execution past it.
pub(crate) const fn is_proof_host_call_allowed(id: u64) -> bool {
    proof_precompile_dispatch_id(id) != 0
}

/// Exact proof-chip dispatch identifier for a cryptographic precompile, or
/// zero for any other identifier. A non-zero value is committed by
/// ProgramMemory and binds a continued host-call row to the matching CPU
/// selector (and therefore to that selector's call relation).
pub const fn proof_precompile_dispatch_id(id: u64) -> u8 {
    match id {
        id if id == ECALL_BLAKE2B_COMPRESS as u64 => DISPATCH_BLAKE2B_COMPRESS,
        id if id == ECALL_RISTRETTO_SCALAR_MULT as u64 => ECALL_RISTRETTO_SCALAR_MULT as u8,
        id if id == ECALL_RISTRETTO_POINT_ADD as u64 => ECALL_RISTRETTO_POINT_ADD as u8,
        id if id == ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE as u64 => {
            ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE as u8
        }
        id if id == ECALL_SCALAR_MUL_MOD_L as u64 => ECALL_SCALAR_MUL_MOD_L as u8,
        id if id == ECALL_SCALAR_ADD_MOD_L as u64 => ECALL_SCALAR_ADD_MOD_L as u8,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tracer serves exactly the refine host's precompiles plus the
    /// Ristretto and scalar ids 110–114. When step 5 serves those on the
    /// refine host, this becomes plain equality.
    #[test]
    fn tracer_serves_the_runtime_precompiles_plus_the_ristretto_ids() {
        for id in 0..0x1000u64 {
            let ristretto = (110..=114).contains(&id);
            assert_eq!(
                is_proof_host_call_allowed(id),
                vos_pvm::precompile::is_precompile(id) || ristretto,
                "id {id:#x}"
            );
        }
    }
}
