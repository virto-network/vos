// Re-export javm's Opcode directly.  Prover-only: `javm` (the reference
// interpreter) is gated behind the `prover` feature — the standalone
// verifier never decodes opcodes (per-row opcode/flag data reaches it as
// committed trace columns, not as `Opcode` values).
#[cfg(feature = "prover")]
pub use javm::instruction::{InstructionCategory, Opcode};
