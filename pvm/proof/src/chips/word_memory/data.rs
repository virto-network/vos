//! DataWordTableChip — a device program's data under the word ledger: a row
//! a word of its read-only and read-write data pages, `(address, bytes)`
//! preprocessed, so part of the program's identity; its main column how
//! many first touches read the word (`DataWord` relation), which
//! DeviceWordMemoryChip's rows in a data region consume.
//!
//! Past its entries the table repeats them with no multiplicity; with none,
//! its rows name address 0, which lies in no region.

use crate::prelude::*;
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
use crate::device::WORD_BYTES;
use crate::framework::{BuiltInComponent, Logup};
use crate::lookups::DataWordLookupElements;
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
pub struct DataWordTableChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The first touches that read the row's word.
    #[size = 1]
    Multiplicity,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "devdataw"]
pub enum PreprocessedColumn {
    /// The word's address, four LE limbs.
    #[size = 4]
    Address,
    /// The word's bytes.
    #[size = 8]
    Value,
}

impl BuiltInComponent for DataWordTableChip {
    const LOGUP: Logup = Logup::Single;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = DataWordLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &DataWordLookupElements,
    ) {
        let address =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Address);
        let value = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Value);
        let multiplicity = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);
        let mut tuple: Vec<E::F> = address.to_vec();
        tuple.extend_from_slice(&value);
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-multiplicity[0].clone()).into(),
            &tuple,
        ));
    }
}

/// The table's entries: the data's words, or address 0's zeros when there
/// is none.
#[cfg(feature = "prover")]
fn entries(side_note: &SideNote) -> Vec<(u32, [u8; WORD_BYTES])> {
    let layout = &crate::chips::device_run(side_note).layout;
    let entries: Vec<(u32, [u8; WORD_BYTES])> = layout
        .data
        .iter()
        .flat_map(|(base, bytes)| {
            bytes
                .chunks_exact(WORD_BYTES)
                .enumerate()
                .map(move |(word, chunk)| {
                    (
                        base + (word * WORD_BYTES) as u32,
                        chunk.try_into().expect("a word"),
                    )
                })
        })
        .collect();
    if entries.is_empty() {
        vec![(0, [0; WORD_BYTES])]
    } else {
        entries
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for DataWordTableChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        let entries = entries(side_note);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        for row in 0..trace.num_rows() {
            let (address, value) = entries[row % entries.len()];
            trace.fill_columns(row, address.to_le_bytes(), PreprocessedColumn::Address);
            trace.fill_columns_bytes(row, &value, PreprocessedColumn::Value);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let entries = entries(side_note);
        let natural = crate::trace::utils::ceil_log2_at_least_lanes(entries.len());
        let log_size = crate::chips::table_log_size(natural, min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let run = crate::chips::device_run(side_note);
        let row_of: alloc::collections::BTreeMap<u32, usize> = entries
            .iter()
            .enumerate()
            .map(|(row, &(address, _))| (address, row))
            .collect();
        let mut counts = vec![0u32; trace.num_rows()];
        for word in &run.words {
            let in_data = run
                .layout
                .region_of(word.address)
                .is_some_and(|region| crate::device::region::DATA[region]);
            if in_data && let Some(&row) = row_of.get(&word.address) {
                counts[row] += 1;
            }
        }
        for (row, &count) in counts.iter().enumerate() {
            trace.fill_columns(row, BaseField::from(count), Column::Multiplicity);
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
        let mut logup = LogupTraceBuilder::new(component_trace.log_size());
        let data: &DataWordLookupElements = lookup_elements.as_ref();
        let address =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Address);
        let value =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Value);
        let multiplicity =
            crate::trace::original_base_column!(component_trace, Column::Multiplicity);
        let mut tuple: Vec<_> = address.to_vec();
        tuple.extend(value.iter().cloned());
        logup.add_to_relation_with(data, [multiplicity[0].clone()], |[m]| (-m).into(), &tuple);
        logup.finalize()
    }
}
