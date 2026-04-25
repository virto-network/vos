use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::{
    air::Component,
    channel::Blake2sChannel,
    fields::qm31::SecureField,
    pcs::TreeVec,
};
use stwo_constraint_framework::{FrameworkEval, InfoEvaluator, TraceLocationAllocator};

use crate::air_column::AirColumn;

use super::builtin::BuiltInComponent;
use crate::{
    framework::eval::{BuiltInComponentEval, FrameworkComponent},
    lookups::{AllLookupElements, ComponentLookupElements},
};

#[cfg(feature = "prover")]
use stwo::{
    core::{
        fields::m31::BaseField,
        poly::circle::CanonicCoset,
        ColumnVec,
    },
    prover::{
        backend::simd::SimdBackend,
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ComponentProver,
    },
};
#[cfg(feature = "prover")]
use crate::trace::component::ComponentTrace;
#[cfg(feature = "prover")]
use super::builtin::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

/// Verifier-side dyn-safe wrapper around `BuiltInComponent`.  All methods
/// here are verifier-side: column-size queries, lookup drawing, and the
/// `Component` instantiation used by `core::verifier::verify`.
pub trait MachineComponent {
    fn max_constraint_log_degree_bound(&self, log_size: u32) -> u32;
    fn trace_sizes(&self, log_size: u32) -> TreeVec<Vec<u32>>;
    fn preprocessed_trace_sizes(&self, log_size: u32) -> Vec<u32>;

    fn draw_lookup_elements(
        &self,
        lookup_elements: &mut AllLookupElements,
        channel: &mut Blake2sChannel,
    );

    fn to_component<'a>(
        &'a self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn Component + 'a>;
}

/// Prover-side dyn-safe wrapper, extending `MachineComponent` with the
/// trace-materialisation methods.  Behind the `prover` feature gate.
/// Trait upcasting (`&dyn MachineProverComponent` → `&dyn MachineComponent`)
/// lets prover-only consumers iterate one component list and verifier
/// consumers reach the same list via the parent trait.
#[cfg(feature = "prover")]
pub trait MachineProverComponent: MachineComponent {
    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        side_note: &SideNote,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>;

    fn generate_component_trace(&self, side_note: &mut SideNote) -> ComponentTrace;

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    );

    fn to_component_prover<'a>(
        &'a self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn ComponentProver<SimdBackend> + 'a>;
}

impl<C: BuiltInComponent> MachineComponent for C
where
    C: 'static + Sync,
    C::LookupElements: Sync + 'static,
{
    fn max_constraint_log_degree_bound(&self, log_size: u32) -> u32 {
        BuiltInComponentEval::<C>::max_constraint_log_degree_bound(log_size)
    }

    fn trace_sizes(&self, log_size: u32) -> TreeVec<Vec<u32>> {
        BuiltInComponentEval::<C> {
            component: self,
            log_size: 0,
            lookup_elements: C::LookupElements::dummy(),
        }
        .evaluate(InfoEvaluator::empty())
        .mask_offsets
        .as_cols_ref()
        .map_cols(|_| log_size)
    }

    fn preprocessed_trace_sizes(&self, log_size: u32) -> Vec<u32> {
        vec![log_size; C::PreprocessedColumn::COLUMNS_NUM]
    }

    fn draw_lookup_elements(
        &self,
        lookup_elements: &mut AllLookupElements,
        channel: &mut Blake2sChannel,
    ) {
        C::LookupElements::draw(lookup_elements, channel);
    }

    fn to_component<'a>(
        &'a self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn Component + 'a> {
        let lookup_elements = C::LookupElements::get(lookup_elements);
        Box::new(FrameworkComponent::new(
            tree_span_provider,
            BuiltInComponentEval::<C> {
                component: self,
                log_size,
                lookup_elements,
            },
            claimed_sum,
        ))
    }
}

#[cfg(feature = "prover")]
impl<C: BuiltInProverComponent> MachineProverComponent for C
where
    C: 'static + Sync,
    C::LookupElements: Sync + 'static,
{
    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        side_note: &SideNote,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let preprocessed_columns =
            <C as BuiltInProverComponent>::generate_preprocessed_trace(self, log_size, side_note);
        let domain = CanonicCoset::new(log_size).circle_domain();
        preprocessed_columns
            .cols
            .into_iter()
            .map(|col| CircleEvaluation::new(domain, col))
            .collect()
    }

    fn generate_component_trace(&self, side_note: &mut SideNote) -> ComponentTrace {
        let original_trace = <C as BuiltInProverComponent>::generate_main_trace(self, side_note);

        let log_size = original_trace.log_size;
        let preprocessed_trace = <C as BuiltInProverComponent>::generate_preprocessed_trace(
            self,
            log_size,
            side_note,
        );

        ComponentTrace {
            log_size,
            preprocessed_trace: preprocessed_trace.cols,
            original_trace: original_trace.cols,
        }
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        <C as BuiltInProverComponent>::generate_interaction_trace(
            self,
            component_trace,
            side_note,
            lookup_elements,
        )
    }

    fn to_component_prover<'a>(
        &'a self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn ComponentProver<SimdBackend> + 'a> {
        let lookup_elements = C::LookupElements::get(lookup_elements);
        Box::new(FrameworkComponent::new(
            tree_span_provider,
            BuiltInComponentEval::<C> {
                component: self,
                log_size,
                lookup_elements,
            },
            claimed_sum,
        ))
    }
}
