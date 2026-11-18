//! The chip's trace generation, the prover's half.

use super::*;
use crate::framework::BuiltInProverComponent;
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
use crate::side_note::SideNote;
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

impl BuiltInProverComponent for DeviceWordMemoryChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        self.preprocessed_trace(log_size, side_note)
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let run = crate::chips::device_run(side_note);
        let log_size =
            crate::trace::utils::ceil_log2_at_least_lanes(run.words.len()).max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let closing_ts = crate::chips::register_memory_closing::closing_ts_for(side_note);
        let bits = |value: u32, low: usize, n: usize| -> Vec<BaseField> {
            (low..low + n)
                .map(|k| BaseField::from((value >> k) & 1))
                .collect()
        };
        for (row, word) in run.words.iter().enumerate() {
            trace.fill_columns_base_field(
                row,
                &bits(word.address, WORD_BITS, ADDRESS_BITS),
                Column::AddressBits,
            );
            trace.fill_columns_bytes(row, &word.initial, Column::Initial);
            trace.fill_columns_bytes(row, &word.last, Column::Last);
            trace.fill_columns(row, closing_ts, Column::ClosingTs);
            trace.fill_columns(row, true, Column::IsReal);
            // A run's every access is in a region (the machine faults
            // elsewhere); a row with none leaves its selectors zero, which
            // the AIR refuses.
            let Some(k) = run.layout.region_of(word.address) else {
                continue;
            };
            let range = run.layout.regions[k];
            let page = word.address / vos_pvm_program::PAGE_SIZE;
            let select: [BaseField; region::COUNT] =
                core::array::from_fn(|i| BaseField::from(u32::from(i == k)));
            trace.fill_columns_base_field(row, &select, Column::RegionSelect);
            trace.fill_columns(row, BaseField::from(range.first), Column::RegionFirstH);
            trace.fill_columns(row, BaseField::from(range.end), Column::RegionEndH);
            trace.fill_columns_base_field(
                row,
                &bits(page - range.first, 0, PAGE_BITS),
                Column::FromFirstBits,
            );
            trace.fill_columns_base_field(
                row,
                &bits(range.end - 1 - page, 0, PAGE_BITS),
                Column::ToEndBits,
            );
        }
        trace.finalize_bit_reversed()
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
        use stwo::prover::backend::simd::m31::PackedBaseField;

        let mut logup = LogupTraceBuilder::new(component_trace.log_size());
        let memory: &MemoryWordLookupElements = lookup_elements.as_ref();
        let data: &DataWordLookupElements = lookup_elements.as_ref();
        let bits = crate::trace::original_base_column!(component_trace, Column::AddressBits);
        let initial = crate::trace::original_base_column!(component_trace, Column::Initial);
        let last = crate::trace::original_base_column!(component_trace, Column::Last);
        let closing_ts = crate::trace::original_base_column!(component_trace, Column::ClosingTs);
        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);
        let select = crate::trace::original_base_column!(component_trace, Column::RegionSelect);

        let constant = |value: u32| PackedBaseField::broadcast(BaseField::from(value));
        let limbs = {
            let bits = bits.clone();
            move |v: usize| -> [PackedBaseField; 4] {
                core::array::from_fn(|k| {
                    (8 * k..8 * k + 8).filter(|&bit| bit >= WORD_BITS).fold(
                        PackedBaseField::zero(),
                        |limb, bit| {
                            limb + bits[bit - WORD_BITS].at(v) * constant(1 << (bit - 8 * k))
                        },
                    )
                })
            }
        };
        let tuple_len = 4 + WORD_BYTES + 8 + 2;
        {
            let (limbs, initial, select) = (limbs.clone(), initial.clone(), select.clone());
            logup.add_to_relation_computed(
                memory,
                [is_real[0].clone()],
                |[real]| real.into(),
                tuple_len,
                move |v| {
                    let mut tuple = limbs(v).to_vec();
                    tuple.extend(initial.iter().map(|byte| byte.at(v)));
                    tuple.extend((0..8).map(|_| PackedBaseField::zero()));
                    tuple.push(PackedBaseField::one());
                    let permission = (0..region::COUNT).fold(PackedBaseField::zero(), |sum, k| {
                        let code = if region::READABLE_ONLY[k] { 1 } else { 2 };
                        sum + select[k].at(v) * constant(code)
                    });
                    tuple.push(permission * constant(2));
                    tuple
                },
            );
        }
        {
            let (limbs, last, closing_ts) = (limbs.clone(), last.clone(), closing_ts.clone());
            logup.add_to_relation_computed(
                memory,
                [is_real[0].clone()],
                |[real]| real.into(),
                tuple_len,
                move |v| {
                    let mut tuple = limbs(v).to_vec();
                    tuple.extend(last.iter().map(|byte| byte.at(v)));
                    tuple.extend(closing_ts.iter().map(|limb| limb.at(v)));
                    tuple.push(PackedBaseField::zero());
                    tuple.push(PackedBaseField::one());
                    tuple
                },
            );
        }
        let data_select = [select[region::RO].clone(), select[region::RW_DATA].clone()];
        logup.add_to_relation_computed(
            data,
            data_select,
            |[ro, rw]| (ro + rw).into(),
            4 + WORD_BYTES,
            move |v| {
                let mut tuple = limbs(v).to_vec();
                tuple.extend(initial.iter().map(|byte| byte.at(v)));
                tuple
            },
        );
        logup.finalize()
    }
}
