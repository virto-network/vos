//! The device's segment AIR masked: variant (c) (`docs/design/proving.md`
//! §5) over the device's chips (`crate::device`), a component set the
//! masked prover and verifier take
//! (`vos_pvm_recair_air::masking::MaskedComponents`).
//!
//! - **A chip masked** ([`MaskedChipEval`]): its constraints and fractions,
//!   then its blinding columns `b` (one QM31) and their fraction
//!   `b / combine_B(1)`, joined to the chip's last batch of fractions, so the
//!   blinding adds neither an interaction column nor a degree; the chip's own
//!   batching (its `Logup`) otherwise. The constraints are bounded at
//!   `log_size + 2`.
//! - **The set** ([`DeviceComponents`]): the chips a device shape names, in
//!   [`DEVICE_ORDER`](crate::device::DEVICE_ORDER), each at its log size;
//!   the relations drawn chip by chip in that order.
//! - **The public sum:** the claimed sum the public values fix stays
//!   unblinded, every other is blinded. It is DeviceIoChip's alone,
//!   recomputed from the io-hash ([`device_bound_sums`]): the run's entry is
//!   the program's and its exit hidden but for φ9..12.
//!
//! Every chip pads to a floor of at least four times its `h`: the fixed
//! tables repeat their entries with no multiplicity, the boundaries add rows
//! that claim nothing. Each chip is at its program's log size
//! ([`DeviceSizes::Pinned`]), never the run's, so the shape does not depend
//! on the witness. The unmasked segment formats never read this module.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::array::from_fn;

use num_traits::{One, Zero};
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, InfoEvaluator, RelationEntry,
    TraceLocationAllocator,
};
use vos_pvm_recair_air::masking::{
    BLIND_COLUMNS, BlindRelation, MASKED_LOG_CONSTRAINT_EXPANSION, MaskedComponents,
};

use crate::device::DeviceShape;
use crate::framework::{BuiltInComponent, MachineComponent};
use crate::lookups::{AllLookupElements, ComponentLookupElements};
use crate::{ChipVisitor, chip_idx};

#[cfg(feature = "prover")]
mod trace;
#[cfg(feature = "prover")]
pub use trace::{
    ChipTraces, DeviceSizes, Evaluations, MaskedDeviceTrace, device_preprocessed,
    masked_device_trace,
};

/// A chip's evaluation as the masked segment proves it: the chip's
/// constraints and fractions, its blinding columns and their fraction joined
/// to its last batch, at the bound `log_size + 2`.
pub struct MaskedChipEval<C: BuiltInComponent + 'static> {
    chip: C,
    log_size: u32,
    lookup_elements: C::LookupElements,
    blind: BlindRelation,
    /// The batch of each of the chip's fractions a row, then of the
    /// blinding's, joined to the last.
    batching: Vec<usize>,
}

impl<C: BuiltInComponent + Copy + 'static> MaskedChipEval<C> {
    fn new(
        chip: &C,
        log_size: u32,
        lookup_elements: C::LookupElements,
        blind: &BlindRelation,
    ) -> Self {
        Self {
            chip: *chip,
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
    let trace_eval = chip.trace_eval(&mut info);
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
        let trace_eval = self.chip.trace_eval(&mut eval);
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

type Boxed = Box<crate::DynComponent>;

/// DeviceIoChip's position among `active`'s chips, a device mask's.
pub fn device_io_position(active: u32) -> Option<usize> {
    crate::device::is_device_mask(active)
        .then(|| {
            crate::device::device_chips_of_mask(active)
                .position(|chip| chip == crate::device::device_chip::DEVICE_IO)
        })
        .flatten()
}

/// The device profile's masked segment (`crate::device`): the chips a
/// device shape names, masked, at their log sizes, in
/// [`DEVICE_ORDER`](crate::device::DEVICE_ORDER); its CPU the program's
/// ([`DeviceShape`]), its memory ledger a row a word, the io-hash's claimed
/// sum (DeviceIoChip's) its one public sum.
pub struct DeviceComponents {
    active: DeviceShape,
    log_sizes: Vec<u32>,
    components: Vec<Boxed>,
}

impl DeviceComponents {
    /// The chips `active` names, in commitment order; `None` when it is not
    /// a device mask.
    pub fn chips(active: DeviceShape) -> Option<Vec<usize>> {
        crate::device::is_device_mask(active.chips)
            .then(|| crate::device::device_chips_of_mask(active.chips).collect())
    }
}

/// Calls `visitor` with the chip at `index`, as `active` holds it.
fn visit<V: ChipVisitor>(active: DeviceShape, index: usize, visitor: V) -> V::Output {
    match active.program_cpu() {
        Some(cpu) if index == chip_idx::CPU => visitor.visit(&cpu),
        _ => crate::visit_device_chip(index, visitor),
    }
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

    fn visit<C>(self, chip: &C) -> Boxed
    where
        C: BuiltInComponent + Copy + Sync + 'static,
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

    fn visit<C>(self, _: &C)
    where
        C: BuiltInComponent + Copy + Sync + 'static,
        C::LookupElements: Sync + 'static,
    {
        C::LookupElements::draw(self.relations, self.channel);
    }
}

impl DeviceComponents {
    /// The chips `active` names under `relations` and `blind`, at
    /// `log_sizes` with `claimed_sums`; `None` unless each count is the
    /// mask's.
    pub fn build(
        active: DeviceShape,
        relations: &AllLookupElements,
        blind: &BlindRelation,
        log_sizes: &[u32],
        claimed_sums: &[SecureField],
    ) -> Option<Self> {
        let chips = Self::chips(active)?;
        if chips.len() != log_sizes.len() || claimed_sums.len() != log_sizes.len() {
            return None;
        }
        let allocator = &mut TraceLocationAllocator::default();
        let components = chips
            .into_iter()
            .zip(log_sizes)
            .zip(claimed_sums)
            .map(|((chip, &log_size), &claimed_sum)| {
                visit(
                    active,
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
}

impl MaskedComponents for DeviceComponents {
    type Relations = AllLookupElements;
    type Active = DeviceShape;

    fn draw_relations(active: DeviceShape, channel: &mut impl Channel) -> AllLookupElements {
        let mut relations = AllLookupElements::default();
        for chip in Self::chips(active).unwrap_or_default() {
            visit(
                active,
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
        active: DeviceShape,
        relations: &AllLookupElements,
        blind: &BlindRelation,
        log_sizes: &[u32],
        claimed_sums: &[SecureField],
    ) -> Option<Self> {
        Self::build(active, relations, blind, log_sizes, claimed_sums)
    }

    fn layout(active: DeviceShape, log_sizes: &[u32]) -> Option<Self> {
        let channel = &mut Blake2sM31Channel::default();
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

    fn active(&self) -> DeviceShape {
        self.active
    }

    fn log_sizes(&self) -> &[u32] {
        &self.log_sizes
    }

    fn public_sums(&self) -> Vec<usize> {
        device_io_position(self.active.chips).into_iter().collect()
    }

    fn preprocessed_log_sizes(&self) -> Vec<u32> {
        Self::chips(self.active)
            .unwrap_or_default()
            .into_iter()
            .zip(&self.log_sizes)
            .flat_map(|(chip, &log_size)| {
                MachineComponent::preprocessed_trace_sizes(crate::device_component(chip), log_size)
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

/// The values a device proof's transcript mixes after the main tree's
/// root: its io-hash (φ9..12 at the halt, 32 LE bytes), one M31 a byte,
/// four a QM31. Nothing else of the run is public.
pub fn device_public_values(io: &[u8; 32]) -> Vec<SecureField> {
    io.chunks(4)
        .map(|bytes| SecureField::from_m31_array(from_fn(|i| BaseField::from(u32::from(bytes[i])))))
        .collect()
}

/// Whether DeviceIoChip's claimed sum, among `claimed_sums` in the order of
/// `active`'s chips, is the one io-hash `io` fixes under `relations`.
pub fn device_bound_sums(
    active: u32,
    io: &[u8; 32],
    relations: &AllLookupElements,
    claimed_sums: &[SecureField],
) -> bool {
    device_io_position(active)
        .and_then(|at| claimed_sums.get(at))
        .is_some_and(|&sum| {
            let io_relation: &crate::lookups::IoHashLookupElements = relations.as_ref();
            sum == crate::chips::device_boundary::io_claimed_sum(io_relation, io)
        })
}

/// A chip of the device's masked segment of shape `shape` driven at
/// `log_size` through `eval`, under `relations` and `blind`: the masked
/// evaluation, which the degree audit walks. `chip` is its shared index
/// (`device::device_chip`).
pub fn drive_masked_device_chip<E: EvalAtRow>(
    shape: DeviceShape,
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

        fn visit<C>(self, chip: &C) -> E
        where
            C: BuiltInComponent + Copy + Sync + 'static,
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

    visit(
        shape,
        chip,
        Drive {
            log_size,
            relations,
            blind,
            eval,
        },
    )
}
