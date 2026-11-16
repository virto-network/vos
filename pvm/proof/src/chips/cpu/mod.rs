use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use crate::trace::eval::TraceEval;

use crate::framework::BuiltInComponent;

// Opcode classification + register-access derivation consume `vos_pvm`
// types (`Opcode`, `InstructionCategory`) and `PvmStep` witnesses, all of
// which exist only at trace-fill time — prover-only, like the fill code
// that calls them.  The AIR (`add_constraints`) never classifies opcodes:
// at verify time the per-row flags are committed columns.
#[cfg(feature = "prover")]
pub(crate) mod classify;
mod columns;
mod constraints;
mod cut;
#[cfg(feature = "prover")]
mod reg_access;
// trace fill + interaction-trace generation live in their own files;
// add_constraints (the AIR) stays in mod.rs.
#[cfg(feature = "prover")]
mod interaction;
#[cfg(feature = "prover")]
mod trace_fill;
mod tuples;

#[cfg(feature = "prover")]
pub(crate) use classify::classify_opcode_for_program_memory;
pub use columns::Column;
use columns::PreprocessedColumn;
pub use cut::{CPU_COLUMN_WORDS, CpuColumns, ProgramCpuChip};
#[cfg(feature = "prover")]
pub(crate) use reg_access::{static_destination, step_reg_accesses};

/// The CPU, a row a step. Its host calls are the BLAKE2b precompile, the
/// witness input and the Poseidon2 call, whose
/// row hands `(ts, φ7, φ8)` to `Poseidon2Chip` (the `Poseidon2Call`
/// relation). The node's segments and the device shape share it.
#[derive(Clone, Copy)]
pub struct CpuChip;

impl BuiltInComponent for CpuChip {
    /// Bound 1 admits algebraic degree ≤ 3, which the paired logup
    /// constraints use (see `CONSTRAINTS.md`). The body constraints stay
    /// at degree ≤ 2: multi-flag selector chains and quadratic bodies are
    /// routed through the helper columns declared at the end of `Column`,
    /// as on the Blake2b, Mul and DivRem chips.
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 1;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = constraints::Lookups;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookups: &constraints::Lookups,
    ) {
        constraints::all(eval, &columns::Row::new(&trace_eval), lookups);
    }
}

#[cfg(feature = "prover")]
mod fill;
