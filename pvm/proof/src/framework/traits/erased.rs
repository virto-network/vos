use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::{air::Component, fields::qm31::SecureField, pcs::TreeVec};
use stwo_constraint_framework::{FrameworkEval, InfoEvaluator, TraceLocationAllocator};

use crate::pcs::ChannelRef;

use crate::air_column::AirColumn;

use super::builtin::BuiltInComponent;
use crate::{
    framework::eval::{BuiltInComponentEval, FrameworkComponent},
    lookups::{AllLookupElements, ComponentLookupElements},
};

/// Verifier-side dyn-safe wrapper around `BuiltInComponent`.  All methods
/// here are verifier-side: column-size queries, lookup drawing, and the
/// `Component` instantiation used by `core::verifier::verify`.
///
/// `Sync` is required so `&dyn MachineComponent` / `&dyn
/// MachineProverComponent` can be sent into rayon parallel iterators
/// (used by `prove_on` to parallelize per-chip
/// interaction-trace generation).  Every concrete impl in
/// `crate::chips` is already `Sync` — adding the supertrait just makes
/// it expressible at the trait-object level.
pub trait MachineComponent: Sync {
    fn max_constraint_log_degree_bound(&self, log_size: u32) -> u32;
    fn trace_sizes(&self, log_size: u32) -> TreeVec<Vec<u32>>;
    fn preprocessed_trace_sizes(&self, log_size: u32) -> Vec<u32>;

    fn draw_lookup_elements(
        &self,
        lookup_elements: &mut AllLookupElements,
        channel: ChannelRef<'_>,
    );

    fn to_component<'a>(
        &'a self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn Component + 'a>;
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
        channel: ChannelRef<'_>,
    ) {
        match channel {
            ChannelRef::Poseidon2M31(channel) => C::LookupElements::draw(lookup_elements, channel),
            ChannelRef::Blake2sM31(channel) => C::LookupElements::draw(lookup_elements, channel),
        }
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
mod prover;
#[cfg(feature = "prover")]
pub use prover::MachineProverComponent;
