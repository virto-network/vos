//! The recursion AIR as the masked wrap proves it: masking variant (c)
//! (`docs/design/proving.md` §5; `research/slice-5/masking-review.md`), the
//! AIR of format 39 in `vos_pvm_proof::format`'s registry.
//!
//! - **Constraint bound `log_size + 2`**
//!   ([`MASKED_LOG_CONSTRAINT_EXPANSION`]): every main and interaction
//!   column is committed as `f + v_H·r`, of degree bound twice its rows, and
//!   the composition is committed whole at `4N`, so a cubic constraint over
//!   the masked columns fits.
//! - **Claimed-sum blinding (R2):** each component reads [`BLIND_COLUMNS`]
//!   more main columns `b` (one QM31) after its own, and adds one fraction
//!   `b / combine_B(1)` on [`BlindRelation`], a relation nothing else uses,
//!   before its fractions are finalized in pairs ([`MaskedEval`]).
//! - **Committed degree bounds `log_size + 1`** ([`MaskedComponent`]): the
//!   main and interaction columns masked, the preprocessed columns extended
//!   to the same level, unmasked.
//! - **The composition sampled at `π(z)`** ([`composition_point`]): its
//!   quotients lift one doubling less than the masked columns'.
//!
//! The masking is the wrap's alone: leaves and folds never read this module,
//! and their components keep [`crate::LOG_CONSTRAINT_EXPANSION`]. Everything
//! here is generic over the component set ([`MaskedComponents`]);
//! [`WrapComponents`] is the recursion AIR's.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::array::from_fn;

use num_traits::One;
use stwo::core::ColumnVec;
use stwo::core::air::accumulation::PointEvaluationAccumulator;
use stwo::core::air::{Component, Components};
use stwo::core::channel::Channel;
use stwo::core::circle::CirclePoint;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::TreeVec;
use stwo::core::poly::circle::CanonicCoset;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, PREPROCESSED_TRACE_IDX, PointEvaluator,
    RelationEntry, TraceLocationAllocator, relation,
};

use crate::{Body, GateRelation, LogSizes, h8, p2, preprocessed_ids, qm31};

/// The constraint bound over the log size: `4N`, the composition whole.
pub const MASKED_LOG_CONSTRAINT_EXPANSION: u32 = 2;

/// The committed degree bound over the log size: `2N`, a column `f + v_H·r`
/// (the preprocessed ones extended to the same level, unmasked).
pub const MASKED_COLUMN_EXPANSION: u32 = 1;

/// A component's blinding columns: one QM31.
pub const BLIND_COLUMNS: usize = SECURE_EXTENSION_DEGREE;

/// The composition's coordinate columns, committed whole.
pub const COMPOSITION_COLUMNS: usize = SECURE_EXTENSION_DEGREE;

relation!(BlindRelation, 1);

/// What a masked format commits beside the AIR's columns: the trees' layout
/// its masking pins (`vos_pvm_proof::format::Masking`, whose entry for
/// format 39 `vos-pvm-recair` reads as `MASKED_WRAP_PINS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaskPins {
    /// The salt columns at the end of each salted tree (main, interaction,
    /// composition), never sampled.
    pub salt_columns: usize,
    /// The FRI mask `R`'s uniform base columns, in the composition tree after
    /// the composition's own.
    pub fri_mask_columns: usize,
}

/// A component masked: its body, then its blinding columns and their one
/// fraction on [`BlindRelation`], then its fractions finalized in pairs, at
/// the bound `log_size + 2`. The only evaluation that reads the blinding.
#[derive(Clone)]
pub struct MaskedEval<B> {
    pub inner: B,
    pub blind: BlindRelation,
}

impl<B> MaskedEval<B> {
    pub fn new(inner: B, blind: &BlindRelation) -> Self {
        Self {
            inner,
            blind: blind.clone(),
        }
    }
}

impl<B: Body> FrameworkEval for MaskedEval<B> {
    fn log_size(&self) -> u32 {
        self.inner.log_size()
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.inner.log_size() + MASKED_LOG_CONSTRAINT_EXPANSION
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        self.inner.body(&mut eval);
        let b: [E::F; BLIND_COLUMNS] = from_fn(|_| eval.next_trace_mask());
        eval.add_to_relation(RelationEntry::new(
            &self.blind,
            E::combine_ef(b),
            &[E::F::one()],
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

/// A component set the masked wrap proves: its components, each a
/// [`MaskedEval`], at their log sizes.
pub trait MaskedComponents: Sized {
    /// The relations the bodies read, drawn right before [`BlindRelation`].
    type Relations;

    fn draw_relations(channel: &mut impl Channel) -> Self::Relations;

    /// Pin B's fifth step, the masked transcript's challenges: the set's
    /// relations, then [`BlindRelation`].
    fn draw(channel: &mut impl Channel) -> (Self::Relations, BlindRelation) {
        let relations = Self::draw_relations(channel);
        let blind = BlindRelation::draw(channel);
        (relations, blind)
    }

    /// The set at `log_sizes` with its claimed sums, `None` when either
    /// count is not the set's.
    fn new(
        relations: &Self::Relations,
        blind: &BlindRelation,
        log_sizes: &[u32],
        claimed_sums: &[SecureField],
    ) -> Option<Self>;

    /// Each component's log size, in commitment order.
    fn log_sizes(&self) -> &[u32];

    /// The preprocessed tree's column log sizes, in commitment order, at the
    /// rows' level (unextended).
    fn preprocessed_log_sizes(&self) -> Vec<u32>;

    /// The components in commitment order, their bounds at their rows'
    /// level: wrap each in [`MaskedComponent`] for the committed levels.
    fn components(&self) -> Vec<&dyn Component>;

    /// The components laid out as `self`, their constraints evaluated under
    /// `relations`, `blind` and `claimed_sums` ([`Rebound`]): the verifier's
    /// set once the challenges are drawn, without laying it out again. `None`
    /// when the count of claimed sums is not the set's, or an evaluation is
    /// not at its layout's log size ([`Rebound::new`]).
    fn bind<'a>(
        &'a self,
        relations: &Self::Relations,
        blind: &BlindRelation,
        claimed_sums: &[SecureField],
    ) -> Option<Vec<Box<dyn Component + 'a>>>;
}

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

/// The level the AIR is evaluated at, its tallest masked column's: `m + 1`.
pub fn air_log_size(set: &impl MaskedComponents) -> Option<u32> {
    set.components()
        .into_iter()
        .flat_map(|inner| {
            MaskedComponent { inner }
                .trace_log_degree_bounds()
                .0
                .into_iter()
                .flatten()
        })
        .max()
}

/// The composition's degree bound, FRI's `k`: `m + 2`.
pub fn composition_log_degree_bound(set: &impl MaskedComponents) -> Option<u32> {
    set.components()
        .iter()
        .map(|component| component.max_constraint_log_degree_bound())
        .max()
}

/// Each committed tree's column degree bounds: the preprocessed tree's at
/// `log_size + 1`, unsalted; the main and interaction trees' columns at
/// `log_size + 1` ([`MaskedComponent`]), then their salt columns; the
/// composition tree's coordinates, `R` and salts. Salts, `R` and the
/// composition at the composition's bound, so every salted tree reaches the
/// lifting height. `None` for an empty set or a level past `u32`.
pub fn committed_log_sizes(
    set: &impl MaskedComponents,
    pins: &MaskPins,
) -> Option<TreeVec<Vec<u32>>> {
    let composition = composition_log_degree_bound(set)?;
    let preprocessed = set
        .preprocessed_log_sizes()
        .into_iter()
        .map(|log_size| log_size.checked_add(MASKED_COLUMN_EXPANSION))
        .collect::<Option<Vec<u32>>>()?;
    let mut trace = [Vec::new(), Vec::new()];
    for inner in set.components() {
        let bounds = MaskedComponent { inner }.trace_log_degree_bounds();
        for (tree, columns) in trace.iter_mut().zip(1..) {
            tree.extend(bounds.get(columns).into_iter().flatten());
        }
    }
    let [mut main, mut interaction] = trace;
    for tree in [&mut main, &mut interaction] {
        tree.extend(core::iter::repeat_n(composition, pins.salt_columns));
    }
    let composition_tree = core::iter::repeat_n(
        composition,
        COMPOSITION_COLUMNS + pins.fri_mask_columns + pins.salt_columns,
    )
    .collect();
    Some(TreeVec(alloc::vec![
        preprocessed,
        main,
        interaction,
        composition_tree
    ]))
}

/// Where the whole composition is sampled: `π(z)`, `z` doubled once for each
/// level the composition's bound stands above the AIR's.
pub fn composition_point(
    set: &impl MaskedComponents,
    oods_point: CirclePoint<SecureField>,
) -> Option<CirclePoint<SecureField>> {
    let doublings = composition_log_degree_bound(set)?.checked_sub(air_log_size(set)?)?;
    Some(oods_point.repeated_double(doublings))
}

/// The sample points, tree by tree: the components' masks at the AIR's level
/// (none for a salt column); the composition's coordinates at
/// [`composition_point`], `R`'s columns at `z`, none for the composition
/// tree's salts. `None` when the set's masks do not fit its trees.
pub fn sample_points(
    set: &impl MaskedComponents,
    oods_point: CirclePoint<SecureField>,
    pins: &MaskPins,
) -> Option<TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>> {
    let committed = committed_log_sizes(set, pins)?;
    let air_level = air_log_size(set)?;
    let at_composition = composition_point(set, oods_point)?;
    let n_preprocessed = committed[0].len();
    let components = set.components();
    let indexed = components.iter().all(|component| {
        component
            .preprocessed_column_indices()
            .iter()
            .all(|&index| index < n_preprocessed)
    });
    if !indexed {
        return None;
    }
    let mut points = Components {
        components,
        n_preprocessed_columns: n_preprocessed,
    }
    .mask_points(oods_point, air_level, false);
    if points.len() > 3 {
        return None;
    }
    points.resize(3, Vec::new());
    for (tree, width) in points.iter_mut().zip(committed.iter().map(Vec::len)) {
        if tree.len() > width {
            return None;
        }
        tree.resize(width, Vec::new());
    }
    let composition = core::iter::repeat_n(at_composition, COMPOSITION_COLUMNS)
        .chain(core::iter::repeat_n(oods_point, pins.fri_mask_columns))
        .map(|point| alloc::vec![point])
        .chain(core::iter::repeat_n(Vec::new(), pins.salt_columns))
        .collect();
    points.push(composition);
    Some(points)
}

/// [`sample_points`] at `oods_point` made from `points`, the set's sample
/// points at `CirclePoint::zero()`, in place. Each point at zero is its
/// mask's offset from it, the group's identity: `oods_point` added to it,
/// and [`composition_point`] to the composition's coordinates', gives each
/// point exactly, without laying the masks out again. `None` where
/// [`sample_points`] is.
pub fn sample_points_from_zero(
    points: &mut TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>,
    set: &impl MaskedComponents,
    oods_point: CirclePoint<SecureField>,
) -> Option<()> {
    let at_composition = composition_point(set, oods_point)?;
    let composition_tree = points.len().checked_sub(1)?;
    for (tree, columns) in points.iter_mut().enumerate() {
        for (column, column_points) in columns.iter_mut().enumerate() {
            let base = if tree == composition_tree && column < COMPOSITION_COLUMNS {
                at_composition
            } else {
                oods_point
            };
            for point in column_points {
                *point = base + *point;
            }
        }
    }
    Some(())
}

/// The composition's value at its point, from its coordinates' samples, the
/// first [`COMPOSITION_COLUMNS`] of the last tree. `None` unless each holds
/// exactly one.
pub fn composition_oods_eval(
    sampled_values: &TreeVec<ColumnVec<Vec<SecureField>>>,
) -> Option<SecureField> {
    let tree = sampled_values.last()?;
    let mut coordinates = [SecureField::default(); COMPOSITION_COLUMNS];
    for (coordinate, column) in coordinates.iter_mut().zip(tree.get(..COMPOSITION_COLUMNS)?) {
        let [value] = column[..] else {
            return None;
        };
        *coordinate = value;
    }
    Some(SecureField::from_partial_evals(coordinates))
}

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
        let allocator =
            &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_ids());
        let p2 = FrameworkComponent::new(
            allocator,
            MaskedEval::new(
                p2::P2Eval {
                    log_size: log_sizes[0],
                    relation: relation.clone(),
                },
                blind,
            ),
            claimed_sums[0],
        );
        let qm31 = FrameworkComponent::new(
            allocator,
            MaskedEval::new(
                qm31::Qm31Eval {
                    log_size: log_sizes[1],
                    relation: relation.clone(),
                },
                blind,
            ),
            claimed_sums[1],
        );
        let h8 = FrameworkComponent::new(
            allocator,
            MaskedEval::new(
                h8::H8Eval {
                    log_size: log_sizes[2],
                    relation: relation.clone(),
                },
                blind,
            ),
            claimed_sums[2],
        );
        Self {
            p2,
            qm31,
            h8,
            log_sizes: *log_sizes,
        }
    }
}

impl MaskedComponents for WrapComponents {
    type Relations = GateRelation;

    fn draw_relations(channel: &mut impl Channel) -> GateRelation {
        GateRelation::draw(channel)
    }

    fn new(
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
        let [p2_size, qm31_size, h8_size] = self.log_sizes;
        let p2 = Rebound::new(
            &self.p2,
            MaskedEval::new(
                p2::P2Eval {
                    log_size: p2_size,
                    relation: relation.clone(),
                },
                blind,
            ),
            p2_sum,
        )?;
        let qm31 = Rebound::new(
            &self.qm31,
            MaskedEval::new(
                qm31::Qm31Eval {
                    log_size: qm31_size,
                    relation: relation.clone(),
                },
                blind,
            ),
            qm31_sum,
        )?;
        let h8 = Rebound::new(
            &self.h8,
            MaskedEval::new(
                h8::H8Eval {
                    log_size: h8_size,
                    relation: relation.clone(),
                },
                blind,
            ),
            h8_sum,
        )?;
        Some(alloc::vec![Box::new(p2), Box::new(qm31), Box::new(h8)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;

    /// Format 28's and 39's log sizes.
    const LOG_SIZES: LogSizes = [14, 15, 11];

    /// Pin A's: 8 salt columns a tree and an `R` of 8.
    const MASKED_WRAP_PINS: MaskPins = MaskPins {
        salt_columns: 8,
        fri_mask_columns: 8,
    };

    fn wrap() -> WrapComponents {
        WrapComponents::build(
            &GateRelation::dummy(),
            &BlindRelation::dummy(),
            &LOG_SIZES,
            &[SecureField::default(); 3],
        )
    }

    /// Pin A's trees: 57 preprocessed columns at `n + 1`, unsalted; 373
    /// main and 40 interaction columns at `n + 1`, each tree with 8 salts at
    /// `m + 2`; the composition's 4 coordinates, `R`'s 8 and 8 salts at
    /// `m + 2`. The main and interaction levels are the components' own,
    /// lifted one level ([`MaskedComponent`]).
    #[test]
    fn the_masked_trees_match_pin_a() {
        let wrap = wrap();
        let trees = committed_log_sizes(&wrap, &MASKED_WRAP_PINS).unwrap();
        assert_eq!(
            trees.iter().map(Vec::len).collect::<Vec<_>>(),
            [57, 381, 48, 20]
        );
        assert_eq!(
            [
                p2::N_MAIN + BLIND_COLUMNS,
                qm31::N_MAIN + BLIND_COLUMNS,
                h8::N_MAIN + BLIND_COLUMNS
            ]
            .iter()
            .sum::<usize>(),
            373
        );
        assert_eq!(air_log_size(&wrap), Some(16));
        assert_eq!(composition_log_degree_bound(&wrap), Some(17));
        assert_eq!(
            trees[0],
            crate::preprocessed_log_sizes(&LOG_SIZES)
                .iter()
                .map(|n| n + 1)
                .collect::<Vec<_>>()
        );
        let lifted: Vec<MaskedComponent<'_, dyn Component>> = wrap
            .components()
            .into_iter()
            .map(|inner| MaskedComponent { inner })
            .collect();
        let own = Components {
            components: lifted.iter().map(|c| c as &dyn Component).collect(),
            n_preprocessed_columns: trees[0].len(),
        }
        .column_log_sizes();
        assert_eq!(own[0], trees[0]);
        for tree in 1..3 {
            let (columns, salts) = trees[tree].split_at(trees[tree].len() - 8);
            assert_eq!(columns, own[tree], "tree {tree}");
            assert!(salts.iter().all(|&level| level == 17));
        }
        assert!(trees[3].iter().all(|&level| level == 17));
        assert_eq!(
            wrap.components()
                .iter()
                .map(|c| c.n_constraints())
                .collect::<Vec<_>>(),
            [
                p2::N_CONSTRAINTS,
                qm31::N_CONSTRAINTS + 1,
                h8::N_CONSTRAINTS + 1
            ]
        );
    }

    /// The blinding's one fraction a row is the masked evaluation's alone:
    /// no component's own evaluation adds to [`BlindRelation`], and each
    /// masked one adds exactly one fraction a row to it (`vos-pvm-recair`'s
    /// circuit tests check that no other source names it).
    #[test]
    fn only_the_masked_evaluation_uses_the_blinding_relation() {
        let blind = BlindRelation::dummy();
        let name = <BlindRelation as stwo_constraint_framework::Relation<
            stwo::core::fields::m31::BaseField,
            SecureField,
        >>::get_name(&blind);
        let unmasked = crate::Components::new(
            &GateRelation::dummy(),
            &LOG_SIZES,
            &[SecureField::default(); 3],
        );
        for counts in [
            unmasked.p2.logup_counts(),
            unmasked.qm31.logup_counts(),
            unmasked.h8.logup_counts(),
        ] {
            assert!(!counts.contains_key(name));
            assert_eq!(counts.len(), 1);
        }
        let wrap = wrap();
        for (counts, &log_size) in [
            wrap.p2.logup_counts(),
            wrap.qm31.logup_counts(),
            wrap.h8.logup_counts(),
        ]
        .iter()
        .zip(&LOG_SIZES)
        {
            assert_eq!(counts.get(name), Some(&(1 << log_size)));
            assert_eq!(counts.len(), 2);
        }
    }

    /// The masks at the AIR's level, the composition's coordinates at
    /// `π(z)`, `R` at `z`, no salt sampled; a column at most twice.
    #[test]
    fn the_sample_points_match_pin_b() {
        let wrap = wrap();
        let z = SECURE_FIELD_CIRCLE_GEN.mul(7);
        let points = sample_points(&wrap, z, &MASKED_WRAP_PINS).unwrap();
        let trees = committed_log_sizes(&wrap, &MASKED_WRAP_PINS).unwrap();
        assert_eq!(
            points.iter().map(Vec::len).collect::<Vec<_>>(),
            trees.iter().map(Vec::len).collect::<Vec<_>>()
        );
        assert!(points[0].iter().all(|column| column[..] == [z]));
        for tree in 1..3 {
            let (columns, salts) = points[tree].split_at(points[tree].len() - 8);
            assert!(columns.iter().all(|c| (1..=2).contains(&c.len())));
            assert!(columns.iter().all(|c| c.last() == Some(&z)));
            assert!(salts.iter().all(Vec::is_empty));
        }
        assert_eq!(composition_point(&wrap, z), Some(z.double()));
        let composition = &points[3];
        assert!(composition[..4].iter().all(|c| c[..] == [z.double()]));
        assert!(composition[4..12].iter().all(|c| c[..] == [z]));
        assert!(composition[12..].iter().all(Vec::is_empty));
        // `p2`'s last round read at the previous row, and each component's
        // running sum.
        let twice = points.iter().flatten().filter(|c| c.len() == 2).count();
        assert_eq!(twice, 16 + 3 * 4);
    }

    /// The sample points at `z` made from those at zero are
    /// [`sample_points`]' at `z`, point for point.
    #[test]
    fn the_sample_points_from_zero_are_the_sample_points() {
        let wrap = wrap();
        for z in [
            SECURE_FIELD_CIRCLE_GEN.mul(7),
            SECURE_FIELD_CIRCLE_GEN.mul(0x1234_5678_9abc),
        ] {
            let mut points = sample_points(&wrap, CirclePoint::zero(), &MASKED_WRAP_PINS).unwrap();
            sample_points_from_zero(&mut points, &wrap, z).unwrap();
            assert_eq!(
                points.0,
                sample_points(&wrap, z, &MASKED_WRAP_PINS).unwrap().0
            );
        }
    }

    /// The wrap laid out under dummy relations and bound to drawn ones
    /// evaluates its composition at a point as the set built under them:
    /// the same value for the same samples, and the same metadata.
    #[test]
    fn a_bound_layout_evaluates_as_the_set_built_anew() {
        let mut channel = stwo::core::channel::Blake2bChannel::default();
        let (relation, blind) = WrapComponents::draw(&mut channel);
        let claimed_sums = [
            channel.draw_secure_felt(),
            channel.draw_secure_felt(),
            channel.draw_secure_felt(),
        ];
        let layout = wrap();
        let bound = layout.bind(&relation, &blind, &claimed_sums).unwrap();
        assert!(layout.bind(&relation, &blind, &claimed_sums[..2]).is_none());
        let other_size = MaskedEval::new(
            p2::P2Eval {
                log_size: LOG_SIZES[0] + 1,
                relation: relation.clone(),
            },
            &blind,
        );
        assert!(Rebound::new(&layout.p2, other_size, claimed_sums[0]).is_none());
        let built = WrapComponents::build(&relation, &blind, &LOG_SIZES, &claimed_sums);
        let z = SECURE_FIELD_CIRCLE_GEN.mul(11);
        let points = sample_points(&layout, z, &MASKED_WRAP_PINS).unwrap();
        let samples = TreeVec(
            points
                .iter()
                .map(|columns| {
                    columns
                        .iter()
                        .map(|column| {
                            column
                                .iter()
                                .map(|_| channel.draw_secure_felt())
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        );
        let coefficient = channel.draw_secure_felt();
        let air_level = air_log_size(&layout).unwrap();
        let evaluate = |components: Vec<&dyn Component>| {
            let lifted: Vec<MaskedComponent<'_, dyn Component>> = components
                .into_iter()
                .map(|inner| MaskedComponent { inner })
                .collect();
            Components {
                components: lifted.iter().map(|c| c as &dyn Component).collect(),
                n_preprocessed_columns: points[0].len(),
            }
            .eval_composition_polynomial_at_point(z, &samples, coefficient, air_level)
        };
        let rebound = evaluate(bound.iter().map(|c| &**c).collect());
        assert_eq!(rebound, evaluate(built.components()));
        assert_ne!(rebound, evaluate(layout.components()));
        for (bound, built) in bound.iter().zip(built.components()) {
            assert_eq!(bound.n_constraints(), built.n_constraints());
            assert_eq!(
                bound.max_constraint_log_degree_bound(),
                built.max_constraint_log_degree_bound()
            );
            assert_eq!(
                bound.trace_log_degree_bounds().0,
                built.trace_log_degree_bounds().0
            );
            assert_eq!(bound.mask_points(z, 16).0, built.mask_points(z, 16).0);
            assert_eq!(
                bound.preprocessed_column_indices(),
                built.preprocessed_column_indices()
            );
        }
    }

    /// The composition's value from exactly one sample a coordinate.
    #[test]
    fn the_composition_is_read_from_its_four_coordinates() {
        let value = |i: u32| SecureField::from_u32_unchecked(i, 2 * i, 3 * i, 5 * i);
        let mut sampled = TreeVec(alloc::vec![
            alloc::vec![],
            (1..=6).map(|i| alloc::vec![value(i)]).collect(),
        ]);
        assert_eq!(
            composition_oods_eval(&sampled),
            Some(SecureField::from_partial_evals(from_fn(|i| value(
                i as u32 + 1
            ))))
        );
        sampled[1][2].push(value(9));
        assert_eq!(composition_oods_eval(&sampled), None);
        sampled[1].truncate(3);
        assert_eq!(composition_oods_eval(&sampled), None);
        assert_eq!(composition_oods_eval(&TreeVec(alloc::vec![])), None);
    }
}
