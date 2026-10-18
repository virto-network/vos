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

use core::ops::Add;

use crate::chips::cpu::columns::Column;
pub(super) use crate::chips::cpu::columns::Row;
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

/// IsBranch: the sum of the ten branch flags.
pub(super) fn is_branch<F: Clone + Add<Output = F>>(row: &Row<F>) -> F {
    let flag = |column| row.column(column)[0].clone();
    flag(Column::IsBrEq)
        + flag(Column::IsBrNe)
        + flag(Column::IsBrLtU)
        + flag(Column::IsBrGeU)
        + flag(Column::IsBrLeU)
        + flag(Column::IsBrGtU)
        + flag(Column::IsBrLtS)
        + flag(Column::IsBrGeS)
        + flag(Column::IsBrLeS)
        + flag(Column::IsBrGtS)
}

/// IsStore: the sum of the three store-class flags.
pub(super) fn is_store<F: Clone + Add<Output = F>>(row: &Row<F>) -> F {
    let flag = |column| row.column(column)[0].clone();
    flag(Column::IsStoreDirect) + flag(Column::IsStoreImmAny) + flag(Column::IsStoreInd)
}

/// IsCompare: the sum of the eight compare flags.
pub(super) fn is_compare<F: Clone + Add<Output = F>>(row: &Row<F>) -> F {
    let flag = |column| row.column(column)[0].clone();
    flag(Column::IsSetLtU)
        + flag(Column::IsSetLtS)
        + flag(Column::IsCmovIz)
        + flag(Column::IsCmovNz)
        + flag(Column::IsMinS)
        + flag(Column::IsMinU)
        + flag(Column::IsMaxS)
        + flag(Column::IsMaxU)
}
