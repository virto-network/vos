//! ECALL identifiers shared between the always-compiled chip surface and the
//! prover-only tracer.  Hostcall IDs are pure data — no execution semantics
//! live here — so a no_std verifier can still classify them without pulling
//! in `core::tracing`.

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
pub const ECALL_RISTRETTO_SCALAR_MULT: u32 = 200;
