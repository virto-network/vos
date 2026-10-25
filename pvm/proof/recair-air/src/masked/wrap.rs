//! The recursion AIR's three components as the masked wrap proves them.

use alloc::boxed::Box;
use alloc::vec::Vec;

use stwo::core::air::Component;
use stwo::core::channel::Channel;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use super::{BlindRelation, MaskedComponents, MaskedEval, Rebound};
use crate::{GateRelation, LogSizes, evals, h8, p2, preprocessed_ids, qm31};

/// The recursion AIR masked: [`p2`], [`qm31`] and [`h8`], each a
/// [`MaskedEval`], their columns allocated in the trees' order.
pub struct WrapComponents {
    pub p2: FrameworkComponent<MaskedEval<p2::P2Eval>>,
    pub qm31: FrameworkComponent<MaskedEval<qm31::Qm31Eval>>,
    pub h8: FrameworkComponent<MaskedEval<h8::H8Eval>>,
    log_sizes: LogSizes,
}

impl WrapComponents {
    pub fn build(
        relation: &GateRelation,
        blind: &BlindRelation,
        log_sizes: &LogSizes,
        claimed_sums: &[SecureField; 3],
    ) -> Self {
        let (p2, qm31, h8) = evals(relation, log_sizes);
        let [p2_sum, qm31_sum, h8_sum] = *claimed_sums;
        let allocator =
            &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_ids());
        Self {
            p2: FrameworkComponent::new(allocator, MaskedEval::new(p2, blind), p2_sum),
            qm31: FrameworkComponent::new(allocator, MaskedEval::new(qm31, blind), qm31_sum),
            h8: FrameworkComponent::new(allocator, MaskedEval::new(h8, blind), h8_sum),
            log_sizes: *log_sizes,
        }
    }

    /// The set at `log_sizes` under dummy relations and zero sums: its trees'
    /// layout, which neither changes. [`MaskedComponents::bind`] evaluates
    /// it under the drawn ones.
    pub fn layout(log_sizes: &LogSizes) -> Self {
        Self::build(
            &GateRelation::dummy(),
            &BlindRelation::dummy(),
            log_sizes,
            &[SecureField::default(); 3],
        )
    }
}

impl MaskedComponents for WrapComponents {
    type Relations = GateRelation;
    type Active = ();

    fn draw_relations((): (), channel: &mut impl Channel) -> GateRelation {
        GateRelation::draw(channel)
    }

    fn new(
        (): (),
        relation: &GateRelation,
        blind: &BlindRelation,
        log_sizes: &[u32],
        claimed_sums: &[SecureField],
    ) -> Option<Self> {
        Some(Self::build(
            relation,
            blind,
            log_sizes.try_into().ok()?,
            claimed_sums.try_into().ok()?,
        ))
    }

    fn layout((): (), log_sizes: &[u32]) -> Option<Self> {
        Some(Self::layout(log_sizes.try_into().ok()?))
    }

    fn active(&self) {}

    fn log_sizes(&self) -> &[u32] {
        &self.log_sizes
    }

    fn preprocessed_log_sizes(&self) -> Vec<u32> {
        crate::preprocessed_log_sizes(&self.log_sizes)
    }

    fn components(&self) -> Vec<&dyn Component> {
        alloc::vec![&self.p2, &self.qm31, &self.h8]
    }

    fn bind<'a>(
        &'a self,
        relation: &GateRelation,
        blind: &BlindRelation,
        claimed_sums: &[SecureField],
    ) -> Option<Vec<Box<dyn Component + 'a>>> {
        let &[p2_sum, qm31_sum, h8_sum] = claimed_sums else {
            return None;
        };
        let (p2, qm31, h8) = evals(relation, &self.log_sizes);
        let p2 = Rebound::new(&self.p2, MaskedEval::new(p2, blind), p2_sum)?;
        let qm31 = Rebound::new(&self.qm31, MaskedEval::new(qm31, blind), qm31_sum)?;
        let h8 = Rebound::new(&self.h8, MaskedEval::new(h8, blind), h8_sum)?;
        Some(alloc::vec![Box::new(p2), Box::new(qm31), Box::new(h8)])
    }
}
