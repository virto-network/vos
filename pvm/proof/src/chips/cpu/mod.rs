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

#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::AllLookupElements;
#[cfg(feature = "prover")]
use crate::side_note::SideNote;
use crate::{
    framework::BuiltInComponent,
    lookups::{
        BitcountLookupElements, BitwiseAndLookupElements, BitwiseLookupElements,
        Blake2bCallLookupElements, ByteToBitsLookupElements, CompareLookupElements,
        DivRemLookupElements, JumpTableLookupElements, MemoryAccessLookupElements,
        MultiplicationLookupElements, PopcountLookupElements, PowerOfTwoLookupElements,
        ProgramExecutionLookupElements, ProgramMemoryLookupElements, Range256LookupElements,
        RegisterMemoryLookupElements, WitnessCallLookupElements,
    },
};

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
    type LookupElements = (
        Range256LookupElements,
        MemoryAccessLookupElements,
        ProgramExecutionLookupElements,
        BitwiseAndLookupElements,
        PowerOfTwoLookupElements,
        Blake2bCallLookupElements,
        RegisterMemoryLookupElements,
        ProgramMemoryLookupElements,
        (
            JumpTableLookupElements,
            PopcountLookupElements,
            BitcountLookupElements,
            MultiplicationLookupElements,
            BitwiseLookupElements,
            CompareLookupElements,
            DivRemLookupElements,
            ByteToBitsLookupElements,
            WitnessCallLookupElements,
        ),
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            Range256LookupElements,
            MemoryAccessLookupElements,
            ProgramExecutionLookupElements,
            BitwiseAndLookupElements,
            PowerOfTwoLookupElements,
            Blake2bCallLookupElements,
            RegisterMemoryLookupElements,
            ProgramMemoryLookupElements,
            (
                JumpTableLookupElements,
                PopcountLookupElements,
                BitcountLookupElements,
                MultiplicationLookupElements,
                BitwiseLookupElements,
                CompareLookupElements,
                DivRemLookupElements,
                ByteToBitsLookupElements,
                WitnessCallLookupElements,
            ),
        ),
    ) {
        let (
            range256_lookup,
            mem_lookup,
            prog_exec_lookup,
            bitwise_and_lookup,
            pow2_lookup,
            blake2b_call_lookup,
            reg_lookup,
            prog_mem_lookup,
            (
                jump_table_lookup,
                popcount_lookup,
                bitcount_lookup,
                mul_lookup,
                bitwise_lookup,
                compare_lookup,
                divrem_lookup,
                byte_to_bits_lookup,
                witness_call_lookup,
            ),
        ) = lookup_elements;
        let lookups = constraints::Lookups {
            range256_lookup,
            mem_lookup,
            prog_exec_lookup,
            bitwise_and_lookup,
            pow2_lookup,
            blake2b_call_lookup,
            reg_lookup,
            prog_mem_lookup,
            jump_table_lookup,
            popcount_lookup,
            bitcount_lookup,
            mul_lookup,
            bitwise_lookup,
            compare_lookup,
            divrem_lookup,
            byte_to_bits_lookup,
            witness_call_lookup,
        };
        let row = &columns::Row::new(&trace_eval);
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
        constraints::host_call::host_call_continuation(eval, row);
        constraints::memory::result_bytes(eval, row, &lookups);
        constraints::memory::memory_access(eval, row, &lookups);
        constraints::memory::active_bytes(eval, row);
        constraints::control::program_execution(eval, row, &lookups);
        constraints::lookups::table_lookups(eval, row, &lookups);
        constraints::registers::register_accesses(eval, row, &lookups);
        constraints::host_call::blake2b_call(eval, row, &lookups);
        constraints::host_call::witness_input_reads(eval, row, &lookups);
        constraints::bitmanip::sign_extend_nibbles(eval, row, &lookups);
        constraints::program::program_memory(eval, row, &lookups);
        constraints::program::flag_bits(eval, row, &lookups);
        constraints::control::trap_terminal(eval, row);
        constraints::control::jump_ind(eval, row, &lookups);
        constraints::control::load_imm_jump_ind(eval, row, &lookups);
        constraints::memory::load_result(eval, row);
        constraints::memory::direct_store_value(eval, row);
        constraints::memory::indirect_store_value(eval, row);
        constraints::memory::direct_address(eval, row);
        constraints::memory::immediate_store_value(eval, row);
        constraints::memory::indirect_address(eval, row);
        constraints::memory::signed_load_extension(eval, row);
        constraints::signs::sign_sources(eval, row);
        constraints::signs::sign_nibbles(eval, row, &lookups);
        constraints::lookups::mul_lookup(eval, row, &lookups);
        constraints::lookups::divrem_lookup(eval, row, &lookups);
        constraints::lookups::compare_lookup(eval, row, &lookups);
        constraints::lookups::bitwise_lookup(eval, row, &lookups);
        constraints::host_call::witness_input(eval, row, &lookups);
        constraints::row::next_timestamp_bytes(eval, row, &lookups);

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for CpuChip {
    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        trace_fill::generate_main_trace(side_note, 0)
    }

    fn generate_main_trace_min(
        &self,
        side_note: &mut SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        trace_fill::generate_main_trace(side_note, min_log_size)
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        interaction::generate_interaction_trace(component_trace, lookup_elements)
    }
}
