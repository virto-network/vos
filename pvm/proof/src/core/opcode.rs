// Re-export vos_pvm's Opcode directly.  Prover-only: `vos_pvm` (the reference
// interpreter) is gated behind the `prover` feature — the standalone
// verifier never decodes opcodes (per-row opcode/flag data reaches it as
// committed trace columns, not as `Opcode` values).
#[cfg(feature = "prover")]
pub use vos_pvm::instruction::{InstructionCategory, Opcode};
