#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::{SimdBackend, m31::LOG_N_LANES},
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;
use crate::{framework::BuiltInComponent, lookups::PowerOfTwoLookupElements};

/// PowerOfTwoChip: 64-row lookup table proving val_d = 2^shift_amount.
///
/// Each row i provides (shift_amount=i, power_val=2^i as 8 LE bytes).
/// The CpuChip produces positive entries when is_shift=1 and shift_op ∈ {0,1}.
/// This chip consumes them with negative multiplicity.
pub struct PowerOfTwoChip;

const POW2_LOG_SIZE: u32 = 6; // 2^6 = 64 rows

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Shift amount (0-63)
    #[size = 1]
    ShiftAmount,
    /// 2^shift_amount as 8 LE bytes
    #[size = 8]
    PowerVal,
    /// Multiplicity: how many times this entry was used
    #[size = 1]
    Multiplicity,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "pow2"]
pub enum PreprocessedColumn {
    /// Shift amount (preprocessed, known)
    #[size = 1]
    ShiftAmount,
    /// Power value (preprocessed, known)
    #[size = 8]
    PowerVal,
}

impl BuiltInComponent for PowerOfTwoChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = PowerOfTwoLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &PowerOfTwoLookupElements,
    ) {
        let shift_amount = crate::trace::trace_eval!(trace_eval, Column::ShiftAmount);
        let power_val = crate::trace::trace_eval!(trace_eval, Column::PowerVal);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        let mut tuple: Vec<E::F> = vec![shift_amount[0].clone()];
        tuple.extend_from_slice(&power_val);

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for PowerOfTwoChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let log_size = POW2_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);

        for row in 0..64usize {
            let power: u64 = 1u64 << row;
            trace.fill_columns(row, row as u8, PreprocessedColumn::ShiftAmount);
            trace.fill_columns(row, power, PreprocessedColumn::PowerVal);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let log_size = POW2_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        // Count shift usage: the CpuChip stores ShiftAmount for shift ops.
        // We count how many times each shift_amount value (0-63) is used.
        let mut counts = [0u32; 64];
        for &count in side_note.power_of_two_counts.iter() {
            // Already accumulated by CpuChip trace gen
            let _ = count;
        }
        // Use pre-accumulated counts from SideNote
        for (i, &c) in side_note.power_of_two_counts.iter().enumerate() {
            if i < 64 {
                counts[i] = c;
            }
        }

        for row in 0..64usize {
            let power: u64 = 1u64 << row;
            trace.fill_columns(row, row as u8, Column::ShiftAmount);
            trace.fill_columns(row, power, Column::PowerVal);
            trace.fill_columns(row, BaseField::from(counts[row]), Column::Multiplicity);
        }

        trace.finalize_bit_reversed()
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
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let pow2_lookup: &PowerOfTwoLookupElements = lookup_elements.as_ref();
        let shift_amount =
            crate::trace::original_base_column!(component_trace, Column::ShiftAmount);
        let power_val = crate::trace::original_base_column!(component_trace, Column::PowerVal);
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        // Consumer side (negative multiplicity)
        let mut tuple: Vec<_> = vec![shift_amount[0].clone()];
        tuple.extend_from_slice(&power_val);

        logup.add_to_relation_with(pow2_lookup, [mult[0].clone()], |[m]| (-m).into(), &tuple);

        logup.finalize()
    }
}
