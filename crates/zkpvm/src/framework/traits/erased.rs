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
///
/// `Sync` is required so `&dyn MachineComponent` / `&dyn
/// MachineProverComponent` can be sent into rayon parallel iterators
/// (used by `prove_impl_with_components` to parallelize per-chip
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

    /// Whether this chip mutates `side_note` during trace generation.
    /// Drives the producer/consumer split in `prove_impl_with_components`.
    fn is_producer(&self) -> bool;

    fn generate_component_trace(&self, side_note: &mut SideNote) -> ComponentTrace;

    /// Trace-gen path that doesn't mutate `side_note`.  Only valid for
    /// `is_producer() == false` chips; producers panic via the default in
    /// `BuiltInProverComponent::generate_main_trace_immut`.  Used by the
    /// parallel consumer pass in `prove_impl_with_components`.
    fn generate_component_trace_immut(&self, side_note: &SideNote) -> ComponentTrace;

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

    /// Phase I.0 debug: pinpoint failing constraint by row + constraint #.
    /// Drives Stwo's `AssertEvaluator` over this chip's main + interaction
    /// trace.  When prove fails with `ConstraintsNotSatisfied` and the
    /// `CPU_DUMP` diagnostic isn't enough to localise the bug, this helper
    /// panics with `row: #X, constraint #Y` — much faster than a wave-by-
    /// wave bisection.
    #[cfg(feature = "debug-internals")]
    fn debug_assert_constraints(
        &self,
        component_trace: &ComponentTrace,
        interaction_trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
        lookup_elements: &AllLookupElements,
        claimed_sum: SecureField,
    );
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

    fn is_producer(&self) -> bool {
        <C as BuiltInProverComponent>::IS_PRODUCER
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

    fn generate_component_trace_immut(&self, side_note: &SideNote) -> ComponentTrace {
        let original_trace =
            <C as BuiltInProverComponent>::generate_main_trace_immut(self, side_note);
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

    #[cfg(feature = "debug-internals")]
    fn debug_assert_constraints(
        &self,
        component_trace: &ComponentTrace,
        interaction_trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
        lookup_elements: &AllLookupElements,
        claimed_sum: SecureField,
    ) {
        use stwo_constraint_framework::assert_constraints_on_polys;
        let log_size = component_trace.log_size;
        let preprocessed_polys: Vec<_> = component_trace
            .preprocessed_trace
            .iter()
            .map(|col| {
                let domain = CanonicCoset::new(log_size).circle_domain();
                CircleEvaluation::<SimdBackend, BaseField, BitReversedOrder>::new(domain, col.clone())
                    .interpolate()
            })
            .collect();
        let original_polys: Vec<_> = component_trace
            .original_trace
            .iter()
            .map(|col| {
                let domain = CanonicCoset::new(log_size).circle_domain();
                CircleEvaluation::<SimdBackend, BaseField, BitReversedOrder>::new(domain, col.clone())
                    .interpolate()
            })
            .collect();
        let interaction_polys: Vec<_> = interaction_trace
            .iter()
            .map(|eval| eval.clone().interpolate())
            .collect();
        let trace_polys = TreeVec::new(vec![preprocessed_polys, original_polys, interaction_polys]);
        let lookup_elements_ce = C::LookupElements::get(lookup_elements);
        let component_eval = BuiltInComponentEval::<C> {
            component: self,
            log_size,
            lookup_elements: lookup_elements_ce,
        };

        // Optional symbolic dump of all constraint expressions: when the
        // env var `CPU_EXPR_DUMP` is set, run an `ExprEvaluator` pass and
        // print every constraint's symbolic form indexed by counter.
        // Lets us identify constraint #N when AssertEvaluator panics with
        // `row #X, constraint #N`.
        if std::env::var("CPU_EXPR_DUMP").is_ok() {
            let expr_eval = stwo_constraint_framework::expr::ExprEvaluator::default();
            let component_eval_for_expr = BuiltInComponentEval::<C> {
                component: self,
                log_size,
                lookup_elements: C::LookupElements::get(lookup_elements),
            };
            let result = component_eval_for_expr.evaluate(expr_eval);
            // Column offset → variant name table (helps decode trace_1_column_NNN).
            for v in <C::MainColumn as crate::air_column::AirColumn>::ALL_VARIANTS {
                let off = v.offset();
                let sz = v.size();
                if sz == 1 {
                    eprintln!("col_{off:>3} = {v:?}");
                } else {
                    for k in 0..sz {
                        eprintln!("col_{:>3} = {v:?}[{k}]", off + k);
                    }
                }
            }
            for (i, c) in result.constraints.iter().enumerate() {
                eprintln!("constraint #{i} = {}", c.simplify_and_format());
            }
        }

        assert_constraints_on_polys(
            &trace_polys,
            CanonicCoset::new(log_size),
            |assert_eval| {
                let _ = component_eval.evaluate(assert_eval);
            },
            claimed_sum,
        );
    }
}
