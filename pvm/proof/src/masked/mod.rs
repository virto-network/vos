//! The segment AIR masked: variant (c) (`docs/design/proving.md` §5) over
//! the segment's chips, a component set the masked prover and verifier take
//! (`vos_pvm_recair_air::masked::MaskedComponents`).
//!
//! - **A chip masked** ([`MaskedChipEval`]): its constraints and fractions,
//!   then its blinding columns `b` (one QM31) and their fraction
//!   `b / combine_B(1)`, joined to the chip's last batch of fractions, so the
//!   blinding adds neither an interaction column nor a degree; the chip's own
//!   batching (its `Logup`) otherwise. The constraints are bounded at
//!   `log_size + 2`.
//! - **The set** ([`SegmentComponents`]): the chips its active-chip mask
//!   names, in chip order, each at its log size; the relations drawn chip by
//!   chip in that order, as the unmasked segment draws them.
//! - **The public sums:** the boundary chips' claimed sums, which the
//!   verifier recomputes from the boundary states ([`bound_sums`]), stay
//!   unblinded; the other chips' are blinded.
//!
//! Every chip pads to its masking's floor (four times its `h`): the fixed
//! tables repeat their entries with no multiplicity, the boundaries add rows
//! that claim nothing. The unmasked segment formats never read this module.
//!
//! **The node's shape, assumed:** [`bound_sums`] and the public sums take the
//! four boundary chips (the registers in and out, the program's boundary,
//! the memory roots), and a mask without one is refused. Pin J's device
//! shape drops the memory roots and outputs the io-hash in φ9..12, so both
//! are generalized there (`slice-7-mobile.md`, 7.15). Nor is the shape
//! pinned yet: the chips (`active`) and their sizes are the run's, above the
//! floors, so they depend on the witness until the device program id pins
//! them and the prover pads to them (7.15).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::array::from_fn;

use num_traits::{One, Zero};
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, InfoEvaluator, RelationEntry,
    TraceLocationAllocator,
};
use vos_pvm_recair_air::masked::{
    BLIND_COLUMNS, BlindRelation, MASKED_LOG_CONSTRAINT_EXPANSION, MaskedComponents,
};

use crate::boundary_binding::{
    BOUNDARY_STATE_BYTES, boundary_positions_in_mask, boundary_state_bytes,
    check_boundary_claimed_sums,
};
use crate::framework::{BuiltInComponent, MachineComponent};
use crate::lookups::{AllLookupElements, ComponentLookupElements};
use crate::proof::SegmentState;
use crate::trace::eval::TraceEval;
use crate::{BASE_COMPONENTS, ChipVisitor, chip_idx, chips_of_mask, visit_chip};

#[cfg(feature = "prover")]
mod trace;
#[cfg(feature = "prover")]
pub use trace::{Evaluations, MaskedSegmentTrace, masked_segment_trace};

/// A chip's evaluation as the masked segment proves it: the chip's
/// constraints and fractions, its blinding columns and their fraction joined
/// to its last batch, at the bound `log_size + 2`.
pub struct MaskedChipEval<C: BuiltInComponent + 'static> {
    chip: &'static C,
    log_size: u32,
    lookup_elements: C::LookupElements,
    blind: BlindRelation,
    /// The batch of each of the chip's fractions a row, then of the
    /// blinding's, joined to the last.
    batching: Vec<usize>,
}

impl<C: BuiltInComponent + 'static> MaskedChipEval<C> {
    fn new(
        chip: &'static C,
        log_size: u32,
        lookup_elements: C::LookupElements,
        blind: &BlindRelation,
    ) -> Self {
        Self {
            chip,
            log_size,
            lookup_elements,
            blind: blind.clone(),
            batching: C::LOGUP.batches(fractions(chip), 1),
        }
    }
}

/// The fractions `chip` adds a row: at least one for every segment chip,
/// each reading a relation (`Logup::batches` and the interaction's blinding
/// both take the last batch to exist).
fn fractions<C: BuiltInComponent>(chip: &C) -> usize {
    let mut info = InfoEvaluator::empty();
    let trace_eval = TraceEval::new(&mut info);
    chip.add_constraints(&mut info, trace_eval, &C::LookupElements::dummy());
    let n = info.logup.fracs.len();
    C::LOGUP.finalize(&mut info);
    n
}

impl<C: BuiltInComponent + 'static> FrameworkEval for MaskedChipEval<C> {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + MASKED_LOG_CONSTRAINT_EXPANSION
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let trace_eval = TraceEval::new(&mut eval);
        self.chip
            .add_constraints(&mut eval, trace_eval, &self.lookup_elements);
        let b: [E::F; BLIND_COLUMNS] = from_fn(|_| eval.next_trace_mask());
        eval.add_to_relation(RelationEntry::new(
            &self.blind,
            E::combine_ef(b),
            &[E::F::one()],
        ));
        eval.finalize_logup_batched(&self.batching);
        eval
    }
}

#[cfg(feature = "prover")]
type Boxed = Box<dyn stwo::prover::ComponentProver<stwo::prover::backend::simd::SimdBackend>>;
#[cfg(not(feature = "prover"))]
type Boxed = Box<dyn Component>;

/// The segment AIR's chips an active-chip mask names, masked, at their log
/// sizes, in chip order.
pub struct SegmentComponents {
    active: u32,
    log_sizes: Vec<u32>,
    components: Vec<Boxed>,
}

/// A chip masked, its columns allocated after those before it.
struct Build<'a> {
    allocator: &'a mut TraceLocationAllocator,
    relations: &'a AllLookupElements,
    blind: &'a BlindRelation,
    log_size: u32,
    claimed_sum: SecureField,
}

impl ChipVisitor for Build<'_> {
    type Output = Boxed;

    fn visit<C>(self, chip: &'static C) -> Boxed
    where
        C: BuiltInComponent + Sync + 'static,
        C::LookupElements: Sync + 'static,
    {
        Box::new(FrameworkComponent::new(
            self.allocator,
            MaskedChipEval::new(
                chip,
                self.log_size,
                C::LookupElements::get(self.relations),
                self.blind,
            ),
            self.claimed_sum,
        ))
    }
}

/// A chip's relations drawn from a channel, those already drawn kept.
struct Draw<'a, Ch> {
    relations: &'a mut AllLookupElements,
    channel: &'a mut Ch,
}

impl<Ch: Channel> ChipVisitor for Draw<'_, Ch> {
    type Output = ();

    fn visit<C>(self, _: &'static C)
    where
        C: BuiltInComponent + Sync + 'static,
        C::LookupElements: Sync + 'static,
    {
        C::LookupElements::draw(self.relations, self.channel);
    }
}

/// Whether `active` names chips of the segment AIR, `n` of them.
fn names(active: u32, n: usize) -> bool {
    active & !chip_idx::ALL == 0 && active.count_ones() as usize == n
}

impl SegmentComponents {
    /// The chips `active` names under `relations` and `blind`, at
    /// `log_sizes` with `claimed_sums`; `None` unless each count is the
    /// mask's.
    pub fn build(
        active: u32,
        relations: &AllLookupElements,
        blind: &BlindRelation,
        log_sizes: &[u32],
        claimed_sums: &[SecureField],
    ) -> Option<Self> {
        if !names(active, log_sizes.len()) || claimed_sums.len() != log_sizes.len() {
            return None;
        }
        let allocator = &mut TraceLocationAllocator::default();
        let components = chips_of_mask(active)
            .zip(log_sizes)
            .zip(claimed_sums)
            .map(|((chip, &log_size), &claimed_sum)| {
                visit_chip(
                    chip,
                    Build {
                        allocator,
                        relations,
                        blind,
                        log_size,
                        claimed_sum,
                    },
                )
            })
            .collect();
        Some(Self {
            active,
            log_sizes: log_sizes.to_vec(),
            components,
        })
    }

    /// The chips' provers, in chip order.
    #[cfg(feature = "prover")]
    pub fn provers(
        &self,
    ) -> Vec<&dyn stwo::prover::ComponentProver<stwo::prover::backend::simd::SimdBackend>> {
        self.components
            .iter()
            .map(|component| &**component)
            .collect()
    }
}

impl MaskedComponents for SegmentComponents {
    type Relations = AllLookupElements;
    type Active = u32;

    fn draw_relations(active: u32, channel: &mut impl Channel) -> AllLookupElements {
        let mut relations = AllLookupElements::default();
        for chip in chips_of_mask(active & chip_idx::ALL) {
            visit_chip(
                chip,
                Draw {
                    relations: &mut relations,
                    channel: &mut *channel,
                },
            );
        }
        relations
    }

    fn new(
        active: u32,
        relations: &AllLookupElements,
        blind: &BlindRelation,
        log_sizes: &[u32],
        claimed_sums: &[SecureField],
    ) -> Option<Self> {
        Self::build(active, relations, blind, log_sizes, claimed_sums)
    }

    fn layout(active: u32, log_sizes: &[u32]) -> Option<Self> {
        let channel = &mut Blake2sChannel::default();
        let relations = Self::draw_relations(active, channel);
        let blind = BlindRelation::draw(channel);
        Self::build(
            active,
            &relations,
            &blind,
            log_sizes,
            &alloc::vec![SecureField::zero(); log_sizes.len()],
        )
    }

    fn active(&self) -> u32 {
        self.active
    }

    fn log_sizes(&self) -> &[u32] {
        &self.log_sizes
    }

    fn public_sums(&self) -> Vec<usize> {
        boundary_positions_in_mask(self.active).map_or_else(Vec::new, |at| {
            alloc::vec![
                at.register_boundary,
                at.register_closing,
                at.program_boundary,
                at.memory_root_boundary,
            ]
        })
    }

    fn preprocessed_log_sizes(&self) -> Vec<u32> {
        chips_of_mask(self.active)
            .zip(&self.log_sizes)
            .flat_map(|(chip, &log_size)| {
                MachineComponent::preprocessed_trace_sizes(BASE_COMPONENTS[chip], log_size)
            })
            .collect()
    }

    fn components(&self) -> Vec<&dyn Component> {
        self.components
            .iter()
            .map(|component| &**component as &dyn Component)
            .collect()
    }

    fn bind<'a>(
        &'a self,
        relations: &AllLookupElements,
        blind: &BlindRelation,
        claimed_sums: &[SecureField],
    ) -> Option<Vec<Box<dyn Component + 'a>>> {
        let set = Self::build(self.active, relations, blind, &self.log_sizes, claimed_sums)?;
        Some(
            set.components
                .into_iter()
                .map(|component| component as Box<dyn Component + 'a>)
                .collect(),
        )
    }
}

/// The boundary states as the masked transcript mixes them, after the main
/// tree's root: one M31 a byte of [`boundary_state_bytes`], four a QM31.
pub fn public_values(initial: &SegmentState, final_state: &SegmentState) -> Vec<SecureField> {
    boundary_state_bytes(initial, final_state)
        .chunks(4)
        .map(|bytes| {
            SecureField::from_m31_array(from_fn(|i| {
                BaseField::from(u32::from(bytes.get(i).copied().unwrap_or(0)))
            }))
        })
        .collect()
}

/// The QM31s [`public_values`] gives.
pub const PUBLIC_VALUES: usize = BOUNDARY_STATE_BYTES.div_ceil(4);

/// Whether the boundary chips' claimed sums, among `claimed_sums` in the
/// order of `active`'s chips, are those the boundary states fix under
/// `relations`: the four boundary chips present and each sum its own.
pub fn bound_sums(
    active: u32,
    initial: &SegmentState,
    final_state: &SegmentState,
    relations: &AllLookupElements,
    claimed_sums: &[SecureField],
) -> bool {
    boundary_positions_in_mask(active).is_some_and(|positions| {
        check_boundary_claimed_sums(initial, final_state, relations, claimed_sums, &positions)
            .is_ok()
    })
}

/// A chip of the masked segment driven at `log_size` through `eval`, under
/// `relations` and `blind`: the masked evaluation, which the degree audit
/// walks. `chip` is its index ([`chip_idx`]).
pub fn drive_masked_chip<E: EvalAtRow>(
    chip: usize,
    log_size: u32,
    relations: &AllLookupElements,
    blind: &BlindRelation,
    eval: E,
) -> E {
    struct Drive<'a, E> {
        log_size: u32,
        relations: &'a AllLookupElements,
        blind: &'a BlindRelation,
        eval: E,
    }

    impl<E: EvalAtRow> ChipVisitor for Drive<'_, E> {
        type Output = E;

        fn visit<C>(self, chip: &'static C) -> E
        where
            C: BuiltInComponent + Sync + 'static,
            C::LookupElements: Sync + 'static,
        {
            MaskedChipEval::new(
                chip,
                self.log_size,
                C::LookupElements::get(self.relations),
                self.blind,
            )
            .evaluate(self.eval)
        }
    }

    visit_chip(
        chip,
        Drive {
            log_size,
            relations,
            blind,
            eval,
        },
    )
}
