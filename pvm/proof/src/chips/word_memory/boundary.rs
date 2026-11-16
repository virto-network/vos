//! DeviceWordMemoryChip — a device run's memory boundary under the word
//! ledger, a row a word the run touches a byte of, in place of the
//! page-Merkle boundary.
//!
//! A row PRODUCES the word's `ts = 0` write into the `MemoryWord` relation,
//! its bytes the word's first touch and its last field `2·permission`, and
//! its closing read at the row's closing timestamp; `WordMemoryChip` binds
//! both to the word's accesses.
//!
//! **The address** is 29 boolean columns, its bits 3..32, so it is a
//! multiple of [`WORD_BYTES`] and its four limbs are bytes, the low one at
//! most 248, and its page index (bits 12..32) below 2^20. **Its region** is
//! selected among the layout's (`device::region`), preprocessed constants
//! of the program's identity, and proved by two 20-bit distances,
//! `page − first` and `end − 1 − page`, as MemoryPageChip proves a page's;
//! a real row selects exactly one, so an address outside every region has
//! no row and no first touch (regions are whole pages, so a word lies in
//! one). **The first touch** of a data region's word is
//! the data table's word (`DataWord` relation, `DataWordTableChip`), of any
//! other region's eight zeros. **The permission** is the region's.
//!
//! Two rows for one word put two `ts = 0` writes for one group, which takes
//! one: their proof does not balance (the ledger's real rows are one sorted
//! run, so a word has one group).

use crate::prelude::*;
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::device::{WORD_BYTES, region};
use crate::framework::{BuiltInComponent, Logup};
use crate::lookups::{DataWordLookupElements, MemoryWordLookupElements};
use crate::trace::eval::TraceEval;

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
mod fill;
