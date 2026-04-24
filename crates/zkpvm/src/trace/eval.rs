use std::{array, marker::PhantomData};

use num_traits::Zero;
use stwo_constraint_framework::{preprocessed_columns::PreProcessedColumnId, EvalAtRow};

use crate::air_column::{AirColumn, PreprocessedAirColumn};

pub use stwo_constraint_framework::{
    INTERACTION_TRACE_IDX, ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX,
};

/// Trace evaluation at the current and next rows.
pub struct TraceEval<P, C, E: EvalAtRow> {
    evals: Vec<[E::F; 2]>,
    preprocessed_evals: Vec<E::F>,
    _phantom_data: PhantomData<(P, C)>,
}

impl<P: PreprocessedAirColumn, C: AirColumn, E: EvalAtRow> TraceEval<P, C, E> {
    pub fn new(eval: &mut E) -> Self {
        let preprocessed_evals = <P as PreprocessedAirColumn>::PREPROCESSED_IDS
            .iter()
            .map(|&id| eval.get_preprocessed_column(PreProcessedColumnId { id: id.to_owned() }))
            .collect();
        let evals = <C as AirColumn>::ALL_VARIANTS
            .iter()
            .flat_map(|col| std::iter::repeat_n(col, col.size()))
            .map(|col| {
                if col.mask_next_row() {
                    eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1])
                } else {
                    [
                        eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0])[0].clone(),
                        <E::F as Zero>::zero(),
                    ]
                }
            })
            .collect();
        Self {
            evals,
            preprocessed_evals,
            _phantom_data: PhantomData,
        }
    }

    pub fn column_eval<const N: usize>(&self, col: C) -> [E::F; N] {
        assert_eq!(col.size(), N, "column size mismatch");
        let offset = col.offset();
        array::from_fn(|i| self.evals[offset + i][0].clone())
    }

    pub fn column_eval_next_row<const N: usize>(&self, col: C) -> [E::F; N] {
        assert_eq!(col.size(), N, "column size mismatch");
        assert!(
            col.mask_next_row(),
            "{col:?} isn't allowed to read next row"
        );
        let offset = col.offset();
        array::from_fn(|i| self.evals[offset + i][1].clone())
    }

    pub fn preprocessed_column_eval<const N: usize>(&self, col: P) -> [E::F; N] {
        assert_eq!(col.size(), N, "preprocessed column size mismatch");
        let offset = col.offset();
        array::from_fn(|i| self.preprocessed_evals[offset + i].clone())
    }
}

pub fn shared_preprocessed_column<const N: usize, E: EvalAtRow, P: PreprocessedAirColumn>(
    eval: &mut E,
    col: P,
) -> [E::F; N] {
    assert_eq!(col.size(), N, "preprocessed column size mismatch");
    let offset = col.offset();
    array::from_fn(|i| {
        let id = <P as PreprocessedAirColumn>::PREPROCESSED_IDS[offset + i].to_owned();
        eval.get_preprocessed_column(PreProcessedColumnId { id })
    })
}

/// Returns evaluations for a given column.
#[macro_export]
macro_rules! trace_eval {
    ($traces:expr, $col:expr) => {{
        $traces.column_eval::<{ $col.const_size() }>($col)
    }};
}

/// Returns evaluations for a given column on the next row.
#[macro_export]
macro_rules! trace_eval_next_row {
    ($traces:expr, $col:expr) => {{
        $traces.column_eval_next_row::<{ $col.const_size() }>($col)
    }};
}

/// Returns evaluations for a given column in preprocessed trace.
#[macro_export]
macro_rules! preprocessed_trace_eval {
    ($traces:expr, $col:expr) => {{
        $traces.preprocessed_column_eval::<{ $col.const_size() }>($col)
    }};
}
