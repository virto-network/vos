//! CpuChip interaction-trace generation.
//!
//! Mirror of `CpuChip::add_constraints` (`cpu/constraints/`) on the prover side: every
//! lookup the verifier's `add_constraints` consumes/produces gets a
//! corresponding `logup.add_to_relation_with` here.  Multiplicities
//! and tuple shapes must match the constraint side byte-for-byte —
//! if the two diverge, the per-component logup sum is non-zero and
//! verification fails with "claimed logup sum is not zero".
//!
//! Adding a new lookup means: add the verifier-side emission in
//! cpu/constraints/, then add the prover-side emission here, then run
//! the minimum sweep (CONSTRAINTS.md rule 6).

#![cfg(feature = "prover")]

use num_traits::One;
use stwo::{
    core::{ColumnVec, fields::m31::BaseField, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

use crate::core::step::WORD_SIZE;
use crate::lookups::{
    AllLookupElements, BitcountLookupElements, BitwiseAndLookupElements, BitwiseLookupElements,
    Blake2bCallLookupElements, ByteToBitsLookupElements, CompareLookupElements,
    DivRemLookupElements, JumpTableLookupElements, LogupTraceBuilder, MemoryAccessLookupElements,
    MultiplicationLookupElements, PopcountLookupElements, PowerOfTwoLookupElements,
    ProgramExecutionLookupElements, ProgramMemoryLookupElements, Range256LookupElements,
    RegisterMemoryLookupElements, WitnessCallLookupElements,
};
use crate::trace::component::ComponentTrace;

use super::columns::{Column, RowTrace};

use stwo::prover::backend::simd::m31::PackedBaseField;

mod control;
mod lookups;
mod memory;
mod program;
mod registers;
mod signs;

pub(super) fn generate_interaction_trace(
    component_trace: &ComponentTrace,
    lookup_elements: &AllLookupElements,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let mut logup = LogupTraceBuilder::new(component_trace.log_size());
    fractions(&mut logup, &RowTrace::new(component_trace), lookup_elements);
    logup.finalize()
}

/// The CPU's fractions, in the AIR's order.
fn fractions(
    logup: &mut LogupTraceBuilder,
    row: &RowTrace<'_>,
    lookup_elements: &AllLookupElements,
) {
    result_bytes(logup, row, lookup_elements);
    memory::memory_access(logup, row, lookup_elements);
    control::program_execution(logup, row, lookup_elements);
    lookups::table_lookups(logup, row, lookup_elements);
    registers::registers(logup, row, lookup_elements);
    signs::sign_extension(logup, row, lookup_elements);
    program::program_memory(logup, row, lookup_elements);
    program::flag_bits(logup, row, lookup_elements);
    control::jump_table(logup, row, lookup_elements);
    signs::sign_nibbles(logup, row, lookup_elements);
    lookups::arithmetic(logup, row, lookup_elements);
    registers::witness_input(logup, row, lookup_elements);
    next_timestamp(logup, row, lookup_elements);
    registers::poseidon2_call(logup, row, lookup_elements);
}

/// The result's bytes, range-checked on every real row.
fn result_bytes(
    logup: &mut LogupTraceBuilder,
    row: &RowTrace<'_>,
    lookup_elements: &AllLookupElements,
) {
    let is_pad = &row.is_padding;
    let range256: &Range256LookupElements = lookup_elements.as_ref();
    // Range256 lookups for result bytes
    let result = &row.result;
    for col in result {
        logup.add_to_relation_with(
            range256,
            [is_pad[0].clone()],
            |[pad]| (PackedBaseField::one() - pad).into(),
            std::slice::from_ref(col),
        );
    }
}

/// The next timestamp's bytes, range-checked; kept last.
fn next_timestamp(
    logup: &mut LogupTraceBuilder,
    row: &RowTrace<'_>,
    lookup_elements: &AllLookupElements,
) {
    let is_pad = &row.is_padding;
    let range256: &Range256LookupElements = lookup_elements.as_ref();
    // ── NextTimestamp Range256 lookups (8, kept last) ──
    {
        let next_ts = &row.next_timestamp;
        for col in next_ts {
            logup.add_to_relation_with(
                range256,
                [is_pad[0].clone()],
                |[pad]| (PackedBaseField::one() - pad).into(),
                std::slice::from_ref(col),
            );
        }
    }
}
