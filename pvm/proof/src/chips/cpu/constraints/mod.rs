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

use crate::chips::cpu::columns::Column;
pub(super) use crate::chips::cpu::columns::Row;
use crate::chips::cpu::tuples::{BITWISE_FLAGS, BRANCH_FLAGS, COMPARE_FLAGS, STORE_FLAGS};
use crate::lookups::{
    BitcountLookupElements, BitwiseAndLookupElements, BitwiseLookupElements,
    Blake2bCallLookupElements, ByteToBitsLookupElements, CompareLookupElements,
    DivRemLookupElements, JumpTableLookupElements, MemoryAccessLookupElements,
    MultiplicationLookupElements, PopcountLookupElements, PowerOfTwoLookupElements,
    ProgramExecutionLookupElements, ProgramMemoryLookupElements, Range256LookupElements,
    RegisterMemoryLookupElements, WitnessCallLookupElements,
};

/// The relations the CPU chip's rows enter.
pub(super) struct Lookups<'a> {
    pub range256_lookup: &'a Range256LookupElements,
    pub mem_lookup: &'a MemoryAccessLookupElements,
    pub prog_exec_lookup: &'a ProgramExecutionLookupElements,
    pub bitwise_and_lookup: &'a BitwiseAndLookupElements,
    pub pow2_lookup: &'a PowerOfTwoLookupElements,
    pub blake2b_call_lookup: &'a Blake2bCallLookupElements,
    pub reg_lookup: &'a RegisterMemoryLookupElements,
    pub prog_mem_lookup: &'a ProgramMemoryLookupElements,
    pub jump_table_lookup: &'a JumpTableLookupElements,
    pub popcount_lookup: &'a PopcountLookupElements,
    pub bitcount_lookup: &'a BitcountLookupElements,
    pub mul_lookup: &'a MultiplicationLookupElements,
    pub bitwise_lookup: &'a BitwiseLookupElements,
    pub compare_lookup: &'a CompareLookupElements,
    pub divrem_lookup: &'a DivRemLookupElements,
    pub byte_to_bits_lookup: &'a ByteToBitsLookupElements,
    pub witness_call_lookup: &'a WitnessCallLookupElements,
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
