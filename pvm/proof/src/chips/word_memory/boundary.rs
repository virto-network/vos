//! DeviceWordMemoryChip — a device run's memory boundary under the word
//! ledger, a row a word the run touches a byte of: `DeviceMemoryChip`'s
//! row a byte, a word at a time.
//!
//! A row PRODUCES the word's `ts = 0` write into the `MemoryWord` relation,
//! its bytes the word's first touch and its last field `2·permission`, and
//! its closing read at the row's closing timestamp; `WordMemoryChip` binds
//! both to the word's accesses.
//!
//! **The address** is 29 boolean columns, its bits 3..32, so it is a
//! multiple of [`WORD_BYTES`] and its four limbs are bytes, the low one at
//! most 248, and its page index (bits 12..32) below 2^20. **Its region** is
//! proved as `DeviceMemoryChip` proves a byte's (regions are whole pages,
//! so a word lies in one). **The first touch** of a data region's word is
//! the data table's word (`DataWord` relation, `DataWordTableChip`), of any
//! other region's eight zeros. **The permission** is the region's.
//!
//! Two rows for one word put two `ts = 0` writes for one group, which takes
//! one: their proof does not balance (the ledger's real rows are one sorted
//! run, so a word has one group).

use crate::prelude::*;
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::device::{WORD_BYTES, region};
use crate::framework::{BuiltInComponent, Logup};
use crate::lookups::{DataWordLookupElements, MemoryWordLookupElements};
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

#[derive(Clone, Copy)]
pub struct DeviceWordMemoryChip;

/// The address bits below a word's.
const WORD_BITS: usize = WORD_BYTES.trailing_zeros() as usize;
/// The bits of a word's address above them.
const ADDRESS_BITS: usize = 32 - WORD_BITS;
/// The bits of a page index, and of a page's distance to its region's ends.
const PAGE_BITS: usize = 20;
/// The address bits below a page's.
const OFFSET_BITS: usize = 12;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The word's address bits 3..32, least significant first.
    #[size = 29]
    AddressBits,
    /// The bytes its first touch reads.
    #[size = 8]
    Initial,
    /// The bytes it holds at the halt.
    #[size = 8]
    Last,
    /// The closing read's timestamp, 8 LE limbs.
    #[size = 8]
    ClosingTs,
    /// 1 on a word's row, 0 on padding.
    #[size = 1]
    IsReal,
    /// 1 on the region the address lies in: exactly one on a real row.
    #[size = 5]
    RegionSelect,
    /// The selected region's first page.
    #[size = 1]
    RegionFirstH,
    /// The selected region's end page.
    #[size = 1]
    RegionEndH,
    /// `page − first`, as 20 bits.
    #[size = 20]
    FromFirstBits,
    /// `end − 1 − page`, as 20 bits.
    #[size = 20]
    ToEndBits,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "devwmem"]
pub enum PreprocessedColumn {
    /// The layout's regions' first pages, constant on every row.
    #[size = 5]
    RegionFirst,
    /// The layout's regions' end pages (exclusive), constant on every row.
    #[size = 5]
    RegionEnd,
}

const _: () = assert!(region::COUNT == 5 && ADDRESS_BITS == 29 && WORD_BYTES == 8);

impl BuiltInComponent for DeviceWordMemoryChip {
    const LOGUP: Logup = Logup::Pairs;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (MemoryWordLookupElements, DataWordLookupElements);

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        (memory, data): &(MemoryWordLookupElements, DataWordLookupElements),
    ) {
        let bits = crate::trace::trace_eval!(trace_eval, Column::AddressBits);
        let initial = crate::trace::trace_eval!(trace_eval, Column::Initial);
        let last = crate::trace::trace_eval!(trace_eval, Column::Last);
        let closing_ts = crate::trace::trace_eval!(trace_eval, Column::ClosingTs);
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let select = crate::trace::trace_eval!(trace_eval, Column::RegionSelect);
        let first_h = crate::trace::trace_eval!(trace_eval, Column::RegionFirstH);
        let end_h = crate::trace::trace_eval!(trace_eval, Column::RegionEndH);
        let from_first = crate::trace::trace_eval!(trace_eval, Column::FromFirstBits);
        let to_end = crate::trace::trace_eval!(trace_eval, Column::ToEndBits);
        let region_first =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RegionFirst);
        let region_end =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RegionEnd);

        let one = E::F::one();
        let boolean = |eval: &mut E, bit: &E::F| {
            eval.add_constraint(bit.clone() * (bit.clone() - E::F::one()));
        };
        for bit in bits.iter().chain(&from_first).chain(&to_end) {
            boolean(eval, bit);
        }
        boolean(eval, &is_real[0]);
        // The value of `bits` as the address bits from `low` on.
        let value = |bits: &[E::F], low: usize| {
            let mut value = E::F::zero();
            let mut weight = E::F::from(BaseField::from(1u32 << low));
            for bit in bits {
                value += bit.clone() * weight.clone();
                weight = weight.clone() + weight;
            }
            value
        };
        // Address bit `k` is `bits[k − WORD_BITS]`, the low ones zero.
        let limbs: [E::F; 4] = core::array::from_fn(|k| {
            let low = (8 * k).max(WORD_BITS);
            value(&bits[low - WORD_BITS..8 * k + 8 - WORD_BITS], low - 8 * k)
        });
        let page = value(
            &bits[OFFSET_BITS - WORD_BITS..OFFSET_BITS - WORD_BITS + PAGE_BITS],
            0,
        );

        let mut selected = E::F::zero();
        let mut first = E::F::zero();
        let mut end = E::F::zero();
        let mut readable_only = E::F::zero();
        let mut writable = E::F::zero();
        let mut data_region = E::F::zero();
        let mut zero_region = E::F::zero();
        for k in 0..region::COUNT {
            boolean(eval, &select[k]);
            selected += select[k].clone();
            first += select[k].clone() * region_first[k].clone();
            end += select[k].clone() * region_end[k].clone();
            if region::READABLE_ONLY[k] {
                readable_only += select[k].clone();
            } else {
                writable += select[k].clone();
            }
            if region::DATA[k] {
                data_region += select[k].clone();
            } else {
                zero_region += select[k].clone();
            }
        }
        eval.add_constraint(selected.clone() - is_real[0].clone());
        eval.add_constraint(first_h[0].clone() - first);
        eval.add_constraint(end_h[0].clone() - end);
        eval.add_constraint(
            value(&from_first, 0) - (selected.clone() * page.clone() - first_h[0].clone()),
        );
        eval.add_constraint(
            value(&to_end, 0) - (end_h[0].clone() - selected.clone() - selected * page),
        );

        // A first touch outside the data regions reads zeros.
        for byte in &initial {
            eval.add_constraint(zero_region.clone() * byte.clone());
        }

        // The ts = 0 write, its last field 2·permission (1 readable, 2
        // writable); the closing read; the data table's word.
        let two = one.clone() + one.clone();
        let permission = readable_only + writable.clone() + writable;
        let mut write: Vec<E::F> = limbs.to_vec();
        write.extend_from_slice(&initial);
        write.extend((0..8).map(|_| E::F::zero()));
        write.push(one.clone());
        write.push(two * permission);
        eval.add_to_relation(RelationEntry::new(
            memory,
            is_real[0].clone().into(),
            &write,
        ));
        let mut close: Vec<E::F> = limbs.to_vec();
        close.extend_from_slice(&last);
        close.extend(closing_ts.iter().cloned());
        close.push(E::F::zero());
        close.push(one);
        eval.add_to_relation(RelationEntry::new(
            memory,
            is_real[0].clone().into(),
            &close,
        ));
        let mut word: Vec<E::F> = limbs.to_vec();
        word.extend_from_slice(&initial);
        eval.add_to_relation(RelationEntry::new(data, data_region.into(), &word));
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for DeviceWordMemoryChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let regions = crate::chips::device_memory::device_run(side_note)
            .layout
            .regions;
        let firsts = regions.map(|range| BaseField::from(range.first));
        let ends = regions.map(|range| BaseField::from(range.end));
        for row in 0..trace.num_rows() {
            trace.fill_columns_base_field(row, &firsts, PreprocessedColumn::RegionFirst);
            trace.fill_columns_base_field(row, &ends, PreprocessedColumn::RegionEnd);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let run = crate::chips::device_memory::device_run(side_note);
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
