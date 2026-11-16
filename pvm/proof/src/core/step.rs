/// Number of PVM registers: 13, φ0..φ12 (Gray Paper Appendix A / §I.4.4).
///
/// Defined locally so the verifier-only build (no `prover` feature) does not
/// pull `vos_pvm` — the register count is a protocol constant, not an
/// implementation detail of the interpreter.  The prover build cross-checks
/// it against the reference interpreter below.
pub const PVM_REGISTER_COUNT: usize = 13;

// Prover builds carry the vos_pvm reference interpreter; assert at compile time
// that our local protocol constant agrees with it so the two can never drift.

/// Number of PVM registers.
pub const NUM_REGS: usize = PVM_REGISTER_COUNT;
/// 64-bit values decomposed as 8 × 8-bit limbs.
pub const WORD_SIZE: usize = 8;

/// A memory access record.
#[derive(Clone, Debug, PartialEq)]
pub struct MemAccess {
    pub address: u32,
    pub value: u64,
    pub size: u8,
}

/// The one register write a step performed: file index + written value.
/// A PVM instruction writes at most one register (every interpreter opcode
/// arm is a single `registers[x] = …` assignment), so this pair is the
/// entire register-file delta of a step — `None` when the step wrote no
/// register. An executed instruction that writes one records the write even
/// when it wrote the value already held (the proof fixes each instruction's
/// write); a conditional move that does not move records none.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RegWrite {
    pub index: u8,
    pub value: u64,
}

#[cfg(feature = "prover")]
mod trace;
#[cfg(feature = "prover")]
pub use trace::{CompactStep, PvmStep, WitnessWrite, expand_steps};
