//! The per-program CPU's trace, cut: the prover's half.

use super::*;

impl ProgramCpuChip {
    /// `trace`, a run's full CPU trace, with its cut columns zeroed: what
    /// the per-program CPU commits of it (its columns in [`Self::committed`]).
    pub fn cut(&self, trace: &mut crate::trace::component::ComponentTrace) {
        for (offset, column) in trace.original_trace.iter_mut().enumerate() {
            if !self.columns.holds_offset(offset) {
                column.data.fill(Zero::zero());
            }
        }
    }

    /// The columns of `trace` the per-program CPU commits, in order.
    pub fn committed<'a>(
        &self,
        trace: &'a crate::trace::component::ComponentTrace,
    ) -> impl Iterator<Item = &'a stwo::prover::backend::simd::column::BaseColumn> {
        let columns = self.columns;
        trace
            .original_trace
            .iter()
            .enumerate()
            .filter(move |(offset, _)| columns.holds_offset(*offset))
            .map(|(_, column)| column)
    }

    /// Its interaction trace and claimed sum over `trace` (cut,
    /// [`Self::cut`]): the kept relation entries', in the AIR's order.
    pub fn interaction_trace(
        &self,
        trace: &crate::trace::component::ComponentTrace,
        lookup_elements: &crate::lookups::AllLookupElements,
    ) -> (
        stwo::core::ColumnVec<
            stwo::prover::poly::circle::CircleEvaluation<
                stwo::prover::backend::simd::SimdBackend,
                BaseField,
                stwo::prover::poly::BitReversedOrder,
            >,
        >,
        SecureField,
    ) {
        super::super::interaction::interaction_trace(trace, lookup_elements, self.fractions)
    }
}
