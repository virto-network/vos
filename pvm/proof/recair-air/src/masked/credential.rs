//! The credential AIR's component set: the recursion AIR's `p2` and `qm31`,
//! masked, without `h8` (`docs/design/proving.md` §8).
//!
//! Two components, so the claimed sums are blinded: each is drawn uniform
//! but for their sum, the one value the logup total fixes. A set of one
//! blinded component would carry its claimed sum in the clear.

use alloc::boxed::Box;
use alloc::vec::Vec;

use stwo::core::air::Component;
use stwo::core::channel::Channel;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use super::{BlindRelation, MaskedComponents, MaskedEval, Rebound};
use crate::{GateRelation, p2, qm31};

/// The credential AIR's log sizes: `p2`, `qm31`.
pub type CredentialLogSizes = [u32; 2];

/// Every preprocessed column's id, in commitment order: `p2`'s, then
/// `qm31`'s.
pub fn credential_preprocessed_ids() -> Vec<PreProcessedColumnId> {
    p2::PREPROCESSED
        .iter()
        .chain(&qm31::PREPROCESSED)
        .map(|&id| PreProcessedColumnId { id: id.into() })
        .collect()
}

/// [`p2`] and [`qm31`], each a [`MaskedEval`], their columns allocated in
/// the trees' order.
pub struct CredentialComponents {
    pub p2: FrameworkComponent<MaskedEval<p2::P2Eval>>,
    pub qm31: FrameworkComponent<MaskedEval<qm31::Qm31Eval>>,
    log_sizes: CredentialLogSizes,
}

/// The two evaluations at `log_sizes` under `relation`.
fn evals(relation: &GateRelation, log_sizes: &CredentialLogSizes) -> (p2::P2Eval, qm31::Qm31Eval) {
    let [p2, qm31] = *log_sizes;
    (
        p2::P2Eval {
            log_size: p2,
            relation: relation.clone(),
        },
        qm31::Qm31Eval {
            log_size: qm31,
            relation: relation.clone(),
        },
    )
}

impl CredentialComponents {
    pub fn build(
        relation: &GateRelation,
        blind: &BlindRelation,
        log_sizes: &CredentialLogSizes,
        claimed_sums: &[SecureField; 2],
    ) -> Self {
        let (p2, qm31) = evals(relation, log_sizes);
        let [p2_sum, qm31_sum] = *claimed_sums;
        let allocator = &mut TraceLocationAllocator::new_with_preprocessed_columns(
            &credential_preprocessed_ids(),
        );
        Self {
            p2: FrameworkComponent::new(allocator, MaskedEval::new(p2, blind), p2_sum),
            qm31: FrameworkComponent::new(allocator, MaskedEval::new(qm31, blind), qm31_sum),
            log_sizes: *log_sizes,
        }
    }

    /// The set at `log_sizes` under dummy relations and zero sums: its trees'
    /// layout, which neither changes.
    pub fn layout(log_sizes: &CredentialLogSizes) -> Self {
        Self::build(
            &GateRelation::dummy(),
            &BlindRelation::dummy(),
            log_sizes,
            &[SecureField::default(); 2],
        )
    }
}

impl MaskedComponents for CredentialComponents {
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
        let [p2, qm31] = self.log_sizes;
        core::iter::repeat_n(p2, p2::PREPROCESSED.len())
            .chain(core::iter::repeat_n(qm31, qm31::PREPROCESSED.len()))
            .collect()
    }

    fn components(&self) -> Vec<&dyn Component> {
        alloc::vec![&self.p2, &self.qm31]
    }

    fn bind<'a>(
        &'a self,
        relation: &GateRelation,
        blind: &BlindRelation,
        claimed_sums: &[SecureField],
    ) -> Option<Vec<Box<dyn Component + 'a>>> {
        let &[p2_sum, qm31_sum] = claimed_sums else {
            return None;
        };
        let (p2, qm31) = evals(relation, &self.log_sizes);
        let p2 = Rebound::new(&self.p2, MaskedEval::new(p2, blind), p2_sum)?;
        let qm31 = Rebound::new(&self.qm31, MaskedEval::new(qm31, blind), qm31_sum)?;
        Some(alloc::vec![Box::new(p2), Box::new(qm31)])
    }
}
