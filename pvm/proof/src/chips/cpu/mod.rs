use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use stwo_constraint_framework::EvalAtRow;

use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{builder::FinalizedTrace, component::ComponentTrace};

use crate::framework::BuiltInComponent;
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::AllLookupElements;
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

// Opcode classification + register-access derivation consume `vos_pvm`
// types (`Opcode`, `InstructionCategory`) and `PvmStep` witnesses, all of
// which exist only at trace-fill time — prover-only, like the fill code
// that calls them.  The AIR (`add_constraints`) never classifies opcodes:
// at verify time the per-row flags are committed columns.
#[cfg(feature = "prover")]
pub(crate) mod classify;
mod columns;
mod constraints;
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
#[cfg(feature = "prover")]
pub(crate) use reg_access::{static_destination, step_reg_accesses};

pub struct CpuChip;

// ── Trace generation ───────────────────────────────────────────────────────

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
        constraints_of(eval, &columns::Row::new(&trace_eval), lookups, None);
    }
}

/// The CPU's constraints and relation entries in the AIR's order; `p2` the
/// shared chip set's Poseidon2 selector, which the host-call continuation
/// counts among the precompile selectors (`None` for format 35's CPU, whose
/// constraints are then exactly its own).
fn constraints_of<E: EvalAtRow>(
    eval: &mut E,
    row: &columns::Row<E::F>,
    lookups: &constraints::Lookups,
    p2: Option<&E::F>,
) {
    constraints::row::padding(eval, row);
    constraints::row::timestamp_chain(eval, row);
    constraints::memory::address_validity(eval, row);
    constraints::alu::selector_helpers(eval, row);
    constraints::compare::compare_and_divrem_helpers(eval, row);
    constraints::divrem::zero_divisor_helpers(eval, row);
    constraints::bitmanip::msb_helpers(eval, row);
    constraints::alu::add(eval, row);
    constraints::alu::sub(eval, row);
    constraints::alu::mul(eval, row);
    constraints::alu::imm_alt_operands(eval, row);
    constraints::compare::compare(eval, row);
    constraints::divrem::divrem(eval, row);
    constraints::divrem::zero_divisor(eval, row);
    constraints::divrem::remainder_sign(eval, row);
    constraints::alu::move_reg(eval, row);
    constraints::bitmanip::byte_ops(eval, row);
    constraints::bitmanip::count_set_bits(eval, row);
    constraints::bitmanip::leading_trailing_zeros_helpers(eval, row);
    constraints::control::branch_helpers(eval, row);
    constraints::control::control_flow_helpers(eval, row);
    constraints::registers::register_helpers(eval, row);
    constraints::row::shared_helpers(eval, row);
    constraints::bitmanip::leading_trailing_zeros(eval, row);
    constraints::control::next_pc(eval, row);
    constraints::control::branch_conditions(eval, row);
    constraints::host_call::host_call_continuation(eval, row, p2);
    constraints::memory::result_bytes(eval, row, lookups);
    constraints::memory::memory_access(eval, row, lookups);
    constraints::memory::active_bytes(eval, row);
    constraints::control::program_execution(eval, row, lookups);
    constraints::lookups::table_lookups(eval, row, lookups);
    constraints::registers::register_accesses(eval, row, lookups);
    constraints::host_call::blake2b_call(eval, row, lookups);
    constraints::host_call::witness_input_reads(eval, row, lookups);
    constraints::bitmanip::sign_extend_nibbles(eval, row, lookups);
    constraints::program::program_memory(eval, row, lookups);
    constraints::program::flag_bits(eval, row, lookups);
    constraints::control::trap_terminal(eval, row);
    constraints::control::jump_ind(eval, row, lookups);
    constraints::control::load_imm_jump_ind(eval, row, lookups);
    constraints::memory::load_result(eval, row);
    constraints::memory::direct_store_value(eval, row);
    constraints::memory::indirect_store_value(eval, row);
    constraints::memory::direct_address(eval, row);
    constraints::memory::immediate_store_value(eval, row);
    constraints::memory::indirect_address(eval, row);
    constraints::memory::signed_load_extension(eval, row);
    constraints::signs::sign_sources(eval, row);
    constraints::signs::sign_nibbles(eval, row, lookups);
    constraints::lookups::mul_lookup(eval, row, lookups);
    constraints::lookups::divrem_lookup(eval, row, lookups);
    constraints::lookups::compare_lookup(eval, row, lookups);
    constraints::lookups::bitwise_lookup(eval, row, lookups);
    constraints::host_call::witness_input(eval, row, lookups);
    constraints::row::next_timestamp_bytes(eval, row, lookups);
}

/// The shared chip set's CPU (`slice-7-mobile.md`, pin H): format 35's CPU
/// and the Poseidon2 call. One more main column after format 35's,
/// `IsP2Ecall`, the call's selector: an acknowledged `ecalli` of dispatch 102
/// selects it as the host-call continuation selects the other precompiles;
/// its row reads φ7 and φ8, the input and output pointers, below 2^32, and
/// hands `(ts, φ7, φ8)` to `Poseidon2Chip` (the `Poseidon2Call` relation),
/// three fractions after format 35's. Formats 41 and 43 take it; format 35
/// keeps [`CpuChip`].
pub struct CpuP2Chip;

impl BuiltInComponent for CpuP2Chip {
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 1;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        constraints::Lookups,
        crate::lookups::Poseidon2CallLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        (lookups, p2_call): &Self::LookupElements,
    ) {
        let row = &columns::Row::new(&trace_eval);
        let is_p2 = eval.next_trace_mask();
        constraints_of(eval, row, lookups, Some(&is_p2));
        constraints::host_call::poseidon2_call(eval, row, lookups, p2_call, is_p2);
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for CpuChip {
    fn generate_main_trace_min(
        &self,
        side_note: &mut SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        trace_fill::generate_main_trace(side_note, min_log_size)
    }

    fn generate_interaction_trace(
        &self,
        component_trace: &ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        interaction::generate_interaction_trace(component_trace, lookup_elements)
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for CpuP2Chip {
    fn generate_main_trace_min(
        &self,
        side_note: &mut SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let mut trace = trace_fill::generate_main_trace(side_note, min_log_size);
        trace
            .cols
            .push(trace_fill::poseidon2_selector(side_note, trace.log_size));
        trace
    }

    fn generate_interaction_trace(
        &self,
        component_trace: &ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        interaction::generate_p2_interaction_trace(component_trace, lookup_elements)
    }
}
