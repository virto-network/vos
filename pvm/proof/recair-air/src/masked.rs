//! The recursion AIR as the masked wrap proves it: masking variant (c)
//! (`research/slice-5/spike2-masking.md` §3b; format 39, `slice-6-on-chain.md`
//! pin A).
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

use alloc::vec::Vec;
use core::array::from_fn;

use num_traits::One;
use stwo::core::ColumnVec;
use stwo::core::air::accumulation::PointEvaluationAccumulator;
use stwo::core::air::{Component, Components};
use stwo::core::channel::Channel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::TreeVec;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, RelationEntry, TraceLocationAllocator, relation,
};

use crate::{Body, GateRelation, LogSizes, h8, p2, preprocessed_ids, qm31};

/// The constraint bound over the log size: `4N`, the composition whole.
pub const MASKED_LOG_CONSTRAINT_EXPANSION: u32 = 2;

/// A component's blinding columns: one QM31.
pub const BLIND_COLUMNS: usize = SECURE_EXTENSION_DEGREE;

/// The composition's coordinate columns, committed whole.
pub const COMPOSITION_COLUMNS: usize = SECURE_EXTENSION_DEGREE;

relation!(BlindRelation, 1);

/// What a masked format commits beside the AIR's columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaskPins {
    /// The salt columns at the end of each salted tree (main, interaction,
    /// composition), never sampled.
    pub salt_columns: usize,
    /// The FRI mask `R`'s uniform base columns, in the composition tree after
    /// the composition's own.
    pub fri_mask_columns: usize,
}

/// Format 39's: 8 salt columns (248 bits) a tree, and an `R` of 8 columns,
/// whose 8 independent DEEP coefficients span QM31 over M31 but with
/// probability about `p^-5` (R3 by construction).
pub const MASKED_WRAP_PINS: MaskPins = MaskPins {
    salt_columns: 8,
    fri_mask_columns: 8,
};

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
            .map_cols(|log_size| log_size + 1)
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
        .iter()
        .flat_map(|component| component.trace_log_degree_bounds().0.into_iter().flatten())
        .max()?
        .checked_add(1)
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
        .map(|log_size| log_size.checked_add(1))
        .collect::<Option<Vec<u32>>>()?;
    let components = set.components();
    let mut trace = [Vec::new(), Vec::new()];
    for component in &components {
        let bounds = component.trace_log_degree_bounds();
        for (tree, columns) in trace.iter_mut().zip(1..) {
            for &log_size in bounds.get(columns).map(Vec::as_slice).unwrap_or(&[]) {
                tree.push(log_size.checked_add(1)?);
            }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;

    /// Format 28's and 39's log sizes.
    const LOG_SIZES: LogSizes = [14, 15, 11];

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
    fn the_masked_trees_are_pin_as() {
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
    /// masked one adds exactly one fraction a row to it; no other module of
    /// the crate names it, and this one adds to it in [`MaskedEval`] only.
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

        let relation = ["Blind", "Relation"].concat();
        for (module, source) in [
            ("lib", include_str!("lib.rs")),
            ("gate", include_str!("gate.rs")),
            ("p2", include_str!("p2.rs")),
            ("qm31", include_str!("qm31.rs")),
            ("h8", include_str!("h8.rs")),
            ("transcript", include_str!("transcript.rs")),
        ] {
            assert!(!source.contains(&relation), "{module} names it");
        }
        let own = include_str!("masked.rs");
        let body = own.split("#[cfg(test)]").next().unwrap();
        let entry = ["RelationEntry::new(\n", "            &self.", "blind"].concat();
        assert_eq!(body.matches(&entry).count(), 1);
        assert_eq!(body.matches("add_to_relation").count(), 1);
    }

    /// The masks at the AIR's level, the composition's coordinates at
    /// `π(z)`, `R` at `z`, no salt sampled; a column at most twice.
    #[test]
    fn the_sample_points_are_pin_bs() {
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
