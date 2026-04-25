//! ECALL identifiers shared between the always-compiled chip surface and the
//! prover-only tracer.  Hostcall IDs are pure data — no execution semantics
//! live here — so a no_std verifier can still classify them without pulling
//! in `core::tracing`.

/// Hostcall ID for blake2b_compress precompile.
/// Convention: φ[10]=ptr_h, φ[11]=ptr_m, φ[12]=t_low (counter bytes in message).
/// h is read (64 bytes), m is read (128 bytes). Result overwrites h.
pub const ECALL_BLAKE2B_COMPRESS: u32 = 100;
