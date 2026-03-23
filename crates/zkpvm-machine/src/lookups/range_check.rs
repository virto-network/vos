use num_traits::One;
use stwo::prover::backend::simd::m31::PackedBaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use zkpvm_trace::component::FinalizedColumn;

use super::{private, AllLookupElements, ComponentLookupElements};
use crate::lookups::{LogupTraceBuilder, RegisteredLookupBound};

const RANGE_CHECK_LOOKUP_SIZE: usize = 1;

stwo_constraint_framework::relation!(Range256LookupElements, RANGE_CHECK_LOOKUP_SIZE);

pub struct RangeCheckLookupElements {
    pub range256: Range256LookupElements,
}

impl private::Sealed for RangeCheckLookupElements {}

impl ComponentLookupElements for RangeCheckLookupElements {
    fn dummy() -> Self {
        Self {
            range256: Range256LookupElements::dummy(),
        }
    }

    fn get(lookup_elements: &AllLookupElements) -> Self {
        let range256: &Range256LookupElements = lookup_elements.as_ref();
        Self {
            range256: range256.to_owned(),
        }
    }

    fn draw(_: &mut AllLookupElements, _: &mut impl stwo::core::channel::Channel) {
        // handled by the range multiplicity component
    }
}

pub trait RangeLookupBound: RegisteredLookupBound {
    fn constrain<E: EvalAtRow>(&self, eval: &mut E, is_local_pad: E::F, value: E::F) {
        eval.add_to_relation(RelationEntry::new(
            self.as_relation_ref(),
            (E::F::one() - is_local_pad).into(),
            &[value],
        ));
    }

    fn generate_logup_col(
        &self,
        logup_trace_builder: &mut LogupTraceBuilder,
        is_local_pad: FinalizedColumn,
        value: FinalizedColumn,
    ) {
        logup_trace_builder.add_to_relation_with(
            self,
            [is_local_pad],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[value],
        );
    }
}

impl RangeLookupBound for Range256LookupElements {}
