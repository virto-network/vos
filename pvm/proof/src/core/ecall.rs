//! ECALL identifiers shared between the always-compiled chip surface and the
//! prover-only tracer.  Hostcall IDs are pure data — no execution semantics
//! live here — so a no_std verifier can still classify them without pulling
//! in `core::tracing`.
//!
//! **Slot range**: vos_pvm's `dispatch_ecalli` rejects `imm > 127` with a fault,
//! so every precompile ID must fit in `0..=127`. The original layout used
//! "categories by hundreds" (1xx hash, 2xx asymmetric crypto) but that
//! exceeded the imm budget; everything is now packed into the contiguous
//! `100..=114` block within vos_pvm's program-cap range (slots 64..=127). The
//! categorisation is recoverable in comments — the wire ID is the only thing
//! that matters for the chip surface.

/// Hostcall ID for blake2b_compress precompile.
/// Convention: φ[10]=ptr_h, φ[11]=ptr_m, φ[12]=t_low (counter bytes in message).
/// h is read (64 bytes), m is read (128 bytes). Result overwrites h.
pub const ECALL_BLAKE2B_COMPRESS: u32 = 100;

/// Hostcall ID for Ristretto255 scalar multiplication precompile.
///
/// Convention:
///   φ[10] = scalar_ptr  (32 canonical bytes, scalar mod ℓ)
///   φ[11] = point_ptr   (32 bytes, compressed Ristretto encoding)
///   φ[12] = output_ptr  (32 bytes, compressed Ristretto, written by the call)
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
///   φ[10] = p_ptr      (32 bytes, compressed Ristretto)
///   φ[11] = q_ptr      (32 bytes, compressed Ristretto)
///   φ[12] = output_ptr (32 bytes, compressed Ristretto, written by call)
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
///   φ[10] = wide_ptr   (64 bytes input — the uniform-random source)
///   φ[11] = output_ptr (32 bytes — canonical scalar mod ℓ, written)
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
///   φ[10] = a_ptr      (32 canonical bytes — Scalar mod ℓ)
///   φ[11] = b_ptr      (32 canonical bytes)
///   φ[12] = output_ptr (32 bytes — `(a * b) mod ℓ`, written)
pub const ECALL_SCALAR_MUL_MOD_L: u32 = 113;

/// Hostcall ID for scalar addition mod ℓ.  Mirrors dalek's
/// `Scalar + Scalar` public API.  Same convention as MUL above.
pub const ECALL_SCALAR_ADD_MOD_L: u32 = 114;

/// VOS scheduler-supplied guest allocator capability. This is deliberately
/// outside JAM's reserved protocol range 10..=14.
pub const ECALL_VOS_GROW_HEAP: u32 = 117;
/// VOS scheduler-supplied diagnostic output capability.
pub const ECALL_VOS_DEBUG_WRITE: u32 = 118;
/// VOS scheduler-supplied nested actor invocation capability.
pub const ECALL_VOS_INVOKE: u32 = 119;

/// Whether the proof runtime has a deterministic handler for this Standard
/// `ecalli` identifier. This is the union of the cryptographic precompiles
/// and the lifecycle stubs exposed by [`crate::core::tracing::TracingPvm`].
///
/// The result is committed into ProgramMemory so an untrusted prover cannot
/// mark an unknown call as acknowledged and continue execution past it.
pub(crate) const fn is_proof_host_call_allowed(id: u64) -> bool {
    matches!(id, 1 | 2 | 4 | 5 | 6 | 26)
        || id == ECALL_BLAKE2B_COMPRESS as u64
        || id == ECALL_RISTRETTO_SCALAR_MULT as u64
        || id == ECALL_RISTRETTO_POINT_ADD as u64
        || id == ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE as u64
        || id == ECALL_SCALAR_MUL_MOD_L as u64
        || id == ECALL_SCALAR_ADD_MOD_L as u64
        || id == ECALL_VOS_DEBUG_WRITE as u64
}

/// Exact proof-chip dispatch identifier for a cryptographic precompile.
///
/// Lifecycle/VOS stubs deliberately return zero: they may acknowledge and
/// continue without emitting a cryptographic call relation. A non-zero value
/// is committed by ProgramMemory and binds a continued host-call row to the
/// matching CPU selector (and therefore to that selector's call relation).
pub(crate) const fn proof_precompile_dispatch_id(id: u64) -> u8 {
    match id {
        id if id == ECALL_BLAKE2B_COMPRESS as u64 => ECALL_BLAKE2B_COMPRESS as u8,
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
