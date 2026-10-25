//! A component's evaluation bound to drawn challenges ([`Rebound`]), and its
//! columns committed one level up ([`MaskedComponent`]).

use alloc::vec::Vec;

use stwo::core::ColumnVec;
use stwo::core::air::Component;
use stwo::core::air::accumulation::PointEvaluationAccumulator;
use stwo::core::circle::CirclePoint;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::TreeVec;
use stwo::core::poly::circle::CanonicCoset;
use stwo_constraint_framework::{
    FrameworkComponent, FrameworkEval, PREPROCESSED_TRACE_IDX, PointEvaluator,
};

use super::MASKED_COLUMN_EXPANSION;

/// A component laid out once, its constraints evaluated by another
/// evaluation of the same layout: the verifier lays its set out before the
/// relations are drawn, and evaluates it under the drawn relations and the
/// proof's claimed sums. A layout (the columns, masks and preprocessed
/// columns `FrameworkComponent::new` reads off an evaluation) depends on
/// neither, so `eval`, differing from `layout`'s only in them, reads the
/// columns `layout` lays out. Its evaluation at a point is
/// `FrameworkComponent`'s, everything else `layout`'s.
pub struct Rebound<'a, E: FrameworkEval> {
    layout: &'a FrameworkComponent<E>,
    eval: E,
    claimed_sum: SecureField,
}

impl<'a, E: FrameworkEval> Rebound<'a, E> {
    /// `layout` evaluated by `eval` with `claimed_sum`; `None` unless `eval`
    /// is at `layout`'s log size and constraint bound.
    pub fn new(
        layout: &'a FrameworkComponent<E>,
        eval: E,
        claimed_sum: SecureField,
    ) -> Option<Self> {
        (eval.log_size() == layout.log_size()
            && eval.max_constraint_log_degree_bound()
                == Component::max_constraint_log_degree_bound(layout))
        .then_some(Self {
            layout,
            eval,
            claimed_sum,
        })
    }
}

impl<E: FrameworkEval> Component for Rebound<'_, E> {
    fn n_constraints(&self) -> usize {
        self.layout.n_constraints()
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.layout.max_constraint_log_degree_bound()
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<ColumnVec<u32>> {
        self.layout.trace_log_degree_bounds()
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        max_log_degree_bound: u32,
    ) -> TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>> {
        self.layout.mask_points(point, max_log_degree_bound)
    }

    fn preprocessed_column_indices(&self) -> ColumnVec<usize> {
        Component::preprocessed_column_indices(self.layout)
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        point: CirclePoint<SecureField>,
        mask: &TreeVec<ColumnVec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) {
        let preprocessed = self
            .layout
            .preprocessed_column_indices()
            .iter()
            .map(|&index| &mask[PREPROCESSED_TRACE_IDX][index])
            .collect();
        let mut columns = mask.sub_tree(self.layout.trace_locations());
        columns[PREPROCESSED_TRACE_IDX] = preprocessed;
        self.eval.evaluate(PointEvaluator::new(
            columns,
            evaluation_accumulator,
            coset_vanishing(CanonicCoset::new(max_log_degree_bound).coset, point).inverse(),
            self.eval.log_size(),
            self.claimed_sum,
        ));
    }
}

/// A component whose main and interaction columns, and the preprocessed
/// columns it reads, are committed at `log_size + 1`; everything else is the
/// inner component's.
pub struct MaskedComponent<'a, C: ?Sized> {
    pub inner: &'a C,
}

impl<C: Component + ?Sized> Component for MaskedComponent<'_, C> {
    fn n_constraints(&self) -> usize {
        self.inner.n_constraints()
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.inner.max_constraint_log_degree_bound()
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<ColumnVec<u32>> {
        self.inner
            .trace_log_degree_bounds()
            .map_cols(|log_size| log_size + MASKED_COLUMN_EXPANSION)
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        max_log_degree_bound: u32,
    ) -> TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>> {
        self.inner.mask_points(point, max_log_degree_bound)
    }

    fn preprocessed_column_indices(&self) -> ColumnVec<usize> {
        self.inner.preprocessed_column_indices()
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        point: CirclePoint<SecureField>,
        mask: &TreeVec<ColumnVec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) {
        self.inner.evaluate_constraint_quotients_at_point(
            point,
            mask,
            evaluation_accumulator,
            max_log_degree_bound,
        )
    }
}
