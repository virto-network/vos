//! The CPU chip's constraints, by instruction class.
//!
//! `CpuChip::add_constraints` calls these functions in a fixed order: the
//! order of the constraints and of the relation entries is the AIR's, and
//! the interaction trace pairs the entries in it. Each function reads the
//! columns it needs from the row.

pub(super) mod alu;
pub(super) mod bitmanip;
pub(super) mod compare;
pub(super) mod control;
pub(super) mod divrem;
pub(super) mod host_call;
pub(super) mod lookups;
pub(super) mod memory;
pub(super) mod program;
pub(super) mod registers;
pub(super) mod row;
pub(super) mod signs;

use alloc::vec::Vec;
use core::ops::Add;

use stwo_constraint_framework::EvalAtRow;

use crate::chips::cpu::columns::Column;
pub(super) use crate::chips::cpu::columns::Row;
use crate::chips::cpu::tuples::{BITWISE_FLAGS, BRANCH_FLAGS, COMPARE_FLAGS, STORE_FLAGS};
use crate::lookups::{
    AllLookupElements, BitcountLookupElements, BitwiseAndLookupElements, BitwiseLookupElements,
    Blake2bCallLookupElements, ByteToBitsLookupElements, CompareLookupElements,
    ComponentLookupElements, DivRemLookupElements, JumpTableLookupElements,
    MemoryAccessLookupElements, MultiplicationLookupElements, PopcountLookupElements,
    Poseidon2CallLookupElements, PowerOfTwoLookupElements, ProgramExecutionLookupElements,
    ProgramMemoryLookupElements, Range256LookupElements, RegisterMemoryLookupElements,
    WitnessCallLookupElements,
};

/// The relations the CPU chip's rows enter, drawn in field order: the
/// order is the transcript's, so it is part of every program id.
macro_rules! lookups {
    ($($field:ident: $relation:ty,)*) => {
        /// The relations the CPU chip's rows enter.
        pub struct Lookups {
            $(pub $field: $relation,)*
        }

        impl crate::lookups::private::Sealed for Lookups {}

        impl ComponentLookupElements for Lookups {
            fn dummy() -> Self {
                Self { $($field: <$relation as ComponentLookupElements>::dummy(),)* }
            }

            fn get(lookup_elements: &AllLookupElements) -> Self {
                Self { $($field: <$relation as ComponentLookupElements>::get(lookup_elements),)* }
            }

            fn draw(
                lookup_elements: &mut AllLookupElements,
                channel: &mut impl stwo::core::channel::Channel,
            ) {
                $(<$relation as ComponentLookupElements>::draw(lookup_elements, channel);)*
            }
        }
    };
}

lookups! {
    range256_lookup: Range256LookupElements,
    mem_lookup: MemoryAccessLookupElements,
    prog_exec_lookup: ProgramExecutionLookupElements,
    bitwise_and_lookup: BitwiseAndLookupElements,
    pow2_lookup: PowerOfTwoLookupElements,
    blake2b_call_lookup: Blake2bCallLookupElements,
    reg_lookup: RegisterMemoryLookupElements,
    prog_mem_lookup: ProgramMemoryLookupElements,
    jump_table_lookup: JumpTableLookupElements,
    popcount_lookup: PopcountLookupElements,
    bitcount_lookup: BitcountLookupElements,
    mul_lookup: MultiplicationLookupElements,
    bitwise_lookup: BitwiseLookupElements,
    compare_lookup: CompareLookupElements,
    divrem_lookup: DivRemLookupElements,
    byte_to_bits_lookup: ByteToBitsLookupElements,
    witness_call_lookup: WitnessCallLookupElements,
    p2_call_lookup: Poseidon2CallLookupElements,
}

/// Every constraint and relation entry of the CPU chip, in the AIR's order.
pub(super) fn all<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>, lookups: &Lookups) {
    row::padding(eval, row);
    row::timestamp_chain(eval, row);
    memory::address_validity(eval, row);
    alu::selector_helpers(eval, row);
    compare::compare_and_divrem_helpers(eval, row);
    divrem::zero_divisor_helpers(eval, row);
    bitmanip::msb_helpers(eval, row);
    alu::add(eval, row);
    alu::sub(eval, row);
    alu::mul(eval, row);
    alu::imm_alt_operands(eval, row);
    compare::compare(eval, row);
    divrem::divrem(eval, row);
    divrem::zero_divisor(eval, row);
    divrem::remainder_sign(eval, row);
    alu::move_reg(eval, row);
    bitmanip::byte_ops(eval, row);
    bitmanip::count_set_bits(eval, row);
    bitmanip::leading_trailing_zeros_helpers(eval, row);
    control::branch_helpers(eval, row);
    control::control_flow_helpers(eval, row);
    registers::register_helpers(eval, row);
    row::shared_helpers(eval, row);
    bitmanip::leading_trailing_zeros(eval, row);
    control::next_pc(eval, row);
    control::branch_conditions(eval, row);
    host_call::host_call_continuation(eval, row);
    memory::result_bytes(eval, row, lookups);
    memory::memory_access(eval, row, lookups);
    memory::active_bytes(eval, row);
    control::program_execution(eval, row, lookups);
    lookups::table_lookups(eval, row, lookups);
    registers::register_accesses(eval, row, lookups);
    host_call::blake2b_call(eval, row, lookups);
    host_call::witness_input_reads(eval, row, lookups);
    bitmanip::sign_extend_nibbles(eval, row, lookups);
    program::program_memory(eval, row, lookups);
    program::flag_bits(eval, row, lookups);
    control::trap_terminal(eval, row);
    control::jump_ind(eval, row, lookups);
    control::load_imm_jump_ind(eval, row, lookups);
    memory::load_result(eval, row);
    memory::direct_store_value(eval, row);
    memory::indirect_store_value(eval, row);
    memory::direct_address(eval, row);
    memory::immediate_store_value(eval, row);
    memory::indirect_address(eval, row);
    memory::signed_load_extension(eval, row);
    signs::sign_sources(eval, row);
    signs::sign_nibbles(eval, row, lookups);
    lookups::mul_lookup(eval, row, lookups);
    lookups::divrem_lookup(eval, row, lookups);
    lookups::compare_lookup(eval, row, lookups);
    lookups::bitwise_lookup(eval, row, lookups);
    host_call::witness_input(eval, row, lookups);
    row::next_timestamp_bytes(eval, row, lookups);
    host_call::poseidon2_call(eval, row, lookups);
}

/// The values of `columns`, in order: a tuple of [`tuples`](super::tuples).
pub(super) fn values<F: Clone>(row: &Row<F>, columns: &[Column]) -> Vec<F> {
    columns
        .iter()
        .flat_map(|&column| row.column(column).iter().cloned())
        .collect()
}

/// The sum of the flags `columns`, left to right.
pub(super) fn sum<F: Clone + Add<Output = F>>(row: &Row<F>, columns: &[Column]) -> F {
    columns
        .iter()
        .map(|&column| row.column(column)[0].clone())
        .reduce(|sum, flag| sum + flag)
        .expect("a sum of flags names at least one")
}

/// IsBranch: the sum of the ten branch flags.
pub(super) fn is_branch<F: Clone + Add<Output = F>>(row: &Row<F>) -> F {
    sum(row, &BRANCH_FLAGS)
}

/// IsStore: the sum of the three store-class flags.
pub(super) fn is_store<F: Clone + Add<Output = F>>(row: &Row<F>) -> F {
    sum(row, &STORE_FLAGS)
}

/// IsCompare: the sum of the eight compare flags.
pub(super) fn is_compare<F: Clone + Add<Output = F>>(row: &Row<F>) -> F {
    sum(row, &COMPARE_FLAGS)
}

/// IsBitwise: the sum of the six bitwise flags.
pub(super) fn is_bitwise<F: Clone + Add<Output = F>>(row: &Row<F>) -> F {
    sum(row, &BITWISE_FLAGS)
}
