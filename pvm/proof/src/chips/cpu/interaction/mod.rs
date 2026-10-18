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

use super::columns::Column;

use stwo::prover::backend::simd::m31::PackedBaseField;

mod control;
mod lookups;
mod memory;
mod program;
mod registers;
mod signs;

pub(super) fn generate_interaction_trace(
    component_trace: ComponentTrace,
    lookup_elements: &AllLookupElements,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let log_size = component_trace.log_size();
    let mut logup = LogupTraceBuilder::new(log_size);
    result_bytes(&mut logup, &component_trace, lookup_elements);
    memory::memory_access(&mut logup, &component_trace, lookup_elements);
    control::program_execution(&mut logup, &component_trace, lookup_elements);
    lookups::table_lookups(&mut logup, &component_trace, lookup_elements);
    registers::registers(&mut logup, &component_trace, lookup_elements);
    signs::sign_extension(&mut logup, &component_trace, lookup_elements);
    program::program_memory(&mut logup, &component_trace, lookup_elements);
    program::flag_bits(&mut logup, &component_trace, lookup_elements);
    control::jump_table(&mut logup, &component_trace, lookup_elements);
    signs::sign_nibbles(&mut logup, &component_trace, lookup_elements);
    lookups::arithmetic(&mut logup, &component_trace, lookup_elements);
    registers::witness_input(&mut logup, &component_trace, lookup_elements);
    next_timestamp(&mut logup, &component_trace, lookup_elements);
    logup.finalize()
}

/// The result's bytes, range-checked on every real row.
fn result_bytes(
    logup: &mut LogupTraceBuilder,
    component_trace: &ComponentTrace,
    lookup_elements: &AllLookupElements,
) {
    let is_pad = crate::trace::original_base_column!(component_trace, Column::IsPadding);
    let range256: &Range256LookupElements = lookup_elements.as_ref();
    // Range256 lookups for result bytes
    let result = crate::trace::original_base_column!(component_trace, Column::Result);
    for col in &result {
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
    component_trace: &ComponentTrace,
    lookup_elements: &AllLookupElements,
) {
    let is_pad = crate::trace::original_base_column!(component_trace, Column::IsPadding);
    let range256: &Range256LookupElements = lookup_elements.as_ref();
    // ── NextTimestamp Range256 lookups (8, kept last) ──
    {
        let next_ts = crate::trace::original_base_column!(component_trace, Column::NextTimestamp);
        for col in &next_ts {
            logup.add_to_relation_with(
                range256,
                [is_pad[0].clone()],
                |[pad]| (PackedBaseField::one() - pad).into(),
                std::slice::from_ref(col),
            );
        }
    }
}
