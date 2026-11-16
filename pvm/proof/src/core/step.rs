/// Number of PVM registers: 13, φ0..φ12 (Gray Paper Appendix A / §I.4.4).
///
/// Defined locally so the verifier-only build (no `prover` feature) does not
/// pull `vos_pvm` — the register count is a protocol constant, not an
/// implementation detail of the interpreter.  The prover build cross-checks
/// it against the reference interpreter (`step/trace.rs`).
pub const PVM_REGISTER_COUNT: usize = 13;

/// Number of PVM registers.
pub const NUM_REGS: usize = PVM_REGISTER_COUNT;
/// 64-bit values decomposed as 8 × 8-bit limbs.
pub const WORD_SIZE: usize = 8;

#[cfg(feature = "prover")]
mod trace;
#[cfg(feature = "prover")]
pub use trace::{CompactStep, MemAccess, PvmStep, RegWrite, WitnessWrite, expand_steps};
