//! DataTableChip — a device program's data (`crate::device`): a row a byte
//! of its read-only and read-write data pages, `(address, byte)`
//! preprocessed, so part of the program's identity; its main column how
//! many first touches read the byte (`DataTable` relation), which
//! DeviceMemoryChip's rows in a data region consume.
//!
//! Past its entries the table repeats them with no multiplicity, so a padded
//! table holds the same entries; with none, its rows name address 0, which
//! lies in no region, so no first touch reads them.

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
use crate::framework::{BuiltInComponent, Logup};
use crate::lookups::DataTableLookupElements;
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

pub struct DataTableChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The first touches that read the row's byte.
    #[size = 1]
    Multiplicity,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "devdata"]
pub enum PreprocessedColumn {
    /// The byte's address, four LE limbs.
    #[size = 4]
    Address,
    /// The byte.
    #[size = 1]
    Value,
}

impl BuiltInComponent for DataTableChip {
    const LOGUP: Logup = Logup::Single;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = DataTableLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &DataTableLookupElements,
    ) {
        let address =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Address);
        let value = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Value);
        let multiplicity = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);
        let mut tuple: Vec<E::F> = address.to_vec();
        tuple.push(value[0].clone());
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-multiplicity[0].clone()).into(),
            &tuple,
        ));
    }
}

/// The table's entries at `log_size` rows: the data's, repeated to the
/// rows, or address 0's zero when there is none.
#[cfg(feature = "prover")]
fn entries(side_note: &SideNote) -> Vec<(u32, u8)> {
    let entries: Vec<(u32, u8)> = super::device_memory::device_run(side_note)
        .layout
        .data_entries()
        .collect();
    if entries.is_empty() {
        vec![(0, 0)]
    } else {
        entries
    }
}

/// The table's natural log size: its entries'.
#[cfg(feature = "prover")]
fn natural_log_size(side_note: &SideNote) -> u32 {
    crate::trace::utils::ceil_log2_at_least_lanes(entries(side_note).len())
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for DataTableChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        let entries = entries(side_note);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        for row in 0..trace.num_rows() {
            let (address, value) = entries[row % entries.len()];
            trace.fill_columns(row, address.to_le_bytes(), PreprocessedColumn::Address);
            trace.fill_columns(row, value, PreprocessedColumn::Value);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size = super::table_log_size(natural_log_size(side_note), min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let run = super::device_memory::device_run(side_note);
        let mut row_of = alloc::collections::BTreeMap::new();
        for (row, (address, _)) in run.layout.data_entries().enumerate() {
            row_of.insert(address, row);
        }
        let mut counts = vec![0u32; trace.num_rows()];
        for touched in &run.touched {
            let in_data = run
                .layout
                .region_of(touched.address)
                .is_some_and(|region| crate::device::region::DATA[region]);
            if in_data && let Some(&row) = row_of.get(&touched.address) {
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
        let data: &DataTableLookupElements = lookup_elements.as_ref();
        let address =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Address);
        let value =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Value);
        let multiplicity =
            crate::trace::original_base_column!(component_trace, Column::Multiplicity);
        let mut tuple: Vec<_> = address.to_vec();
        tuple.push(value[0].clone());
        logup.add_to_relation_with(data, [multiplicity[0].clone()], |[m]| (-m).into(), &tuple);
        logup.finalize()
    }
}
