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
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::device::WORD_BYTES;
use crate::framework::{BuiltInComponent, Logup};
use crate::lookups::DataWordLookupElements;
use crate::trace::eval::TraceEval;

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

#[cfg(feature = "prover")]
mod fill;
