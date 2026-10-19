//! R1 (`masking-review.md` §1.1, pin C): the randomizer's revealed
//! functionals have full row rank over M31, checked on the transcript.
//!
//! A masked column `f + v_H·r` reveals linear functionals of `r`'s `h`
//! coefficients: four M31 rows for each out-of-domain sample, one for each
//! decommitted query, and one for each of the composition's shifted reads at
//! a query. When they are independent, the revealed values are uniform and
//! independent of `f`, which the simulator rests on. Columns of one class
//! (their level, their quotient's lift and their offsets) reveal the same
//! functionals, so one check a class covers them.

use num_traits::{One, Zero};
use rayon::prelude::*;
use stwo::core::ColumnVec;
use stwo::core::air::Components;
use stwo::core::circle::CirclePoint;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::TreeVec;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_index;
use stwo::core::verifier::PREPROCESSED_TRACE_IDX;
use vos_pvm_recair_air::masked::MASKED_COLUMN_EXPANSION;

/// What R1 found: the column classes it checked, the most functionals one
/// class revealed, and whether every class's had full row rank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Revealed {
    pub classes: usize,
    pub rows: usize,
    pub independent: bool,
}

/// A column class's points: where its randomizer is revealed out of the
/// domain (four M31 functionals each) and on it (one each).
struct Class {
    /// The class's columns' rows' level.
    log_size: u32,
    secure: Vec<CirclePoint<SecureField>>,
    base: Vec<CirclePoint<BaseField>>,
}

/// R1 over `components` (their bounds the committed ones), sampled at
/// `points` around `oods_point`, queried at `query_positions` of the
/// lifting domain. `None` when the points do not fit the components.
pub(crate) fn revealed_functionals(
    components: &Components<'_>,
    points: &TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>,
    oods_point: CirclePoint<SecureField>,
    query_positions: &[usize],
    lifting_log_size: u32,
    log_mask_rows: u32,
) -> Option<Revealed> {
    let composition = components
        .components
        .iter()
        .map(|component| component.max_constraint_log_degree_bound())
        .max()?;
    let air_level = components
        .components
        .iter()
        .flat_map(|component| {
            let bounds = component.trace_log_degree_bounds();
            bounds.0.into_iter().flatten()
        })
        .max()?;
    let lifting_domain = CanonicCoset::new(lifting_log_size).circle_domain();
    let mut positions = query_positions.to_vec();
    positions.sort_unstable();
    positions.dedup();
    let queries: Vec<CirclePoint<BaseField>> = positions
        .into_iter()
        .map(|position| lifting_domain.at(bit_reverse_index(position, lifting_log_size)))
        .collect();
    let to_base = |point: CirclePoint<SecureField>| CirclePoint {
        x: point.x.to_m31_array()[0],
        y: point.y.to_m31_array()[0],
    };

    // A class: its level, its quotient's lift and its offsets.
    type Key = (u32, u32, Vec<(u32, u32)>);
    let mut seen: Vec<Key> = Vec::new();
    let mut tree_offsets = vec![0usize; points.len()];
    let mut classes: Vec<Class> = Vec::new();
    for component in &components.components {
        let bounds = component.trace_log_degree_bounds();
        let quotient_lift = composition.checked_sub(component.max_constraint_log_degree_bound())?;
        for (tree, tree_bounds) in bounds.iter().enumerate() {
            let start = *tree_offsets.get(tree)?;
            tree_offsets[tree] += tree_bounds.len();
            if tree == PREPROCESSED_TRACE_IDX {
                continue;
            }
            for (i, &level) in tree_bounds.iter().enumerate() {
                let column_points = points.get(tree)?.get(start + i)?;
                if column_points.is_empty() {
                    continue;
                }
                let log_size = level.checked_sub(MASKED_COLUMN_EXPANSION)?;
                let shifts: Vec<CirclePoint<BaseField>> = column_points
                    .iter()
                    .map(|&point| to_base(point - oods_point))
                    .collect();
                let mut offsets: Vec<(u32, u32)> =
                    shifts.iter().map(|shift| (shift.x.0, shift.y.0)).collect();
                offsets.sort_unstable();
                let class = (level, quotient_lift, offsets);
                if seen.contains(&class) {
                    continue;
                }
                seen.push(class);

                let column_lift = composition.checked_sub(level)?;
                let shift_lift = air_level.checked_sub(log_size)?;
                let mut secure: Vec<CirclePoint<SecureField>> = Vec::new();
                for point in column_points {
                    let lifted = point.repeated_double(column_lift);
                    if !secure.contains(&lifted) {
                        secure.push(lifted);
                    }
                }
                let mut base: Vec<CirclePoint<BaseField>> = Vec::new();
                let mut push = |point: CirclePoint<BaseField>| {
                    if !base.contains(&point) {
                        base.push(point);
                    }
                };
                for query in &queries {
                    push(query.repeated_double(column_lift));
                    let read = query.repeated_double(quotient_lift);
                    for shift in &shifts {
                        push(read + shift.repeated_double(shift_lift));
                    }
                }
                classes.push(Class {
                    log_size,
                    secure,
                    base,
                });
            }
        }
    }
    let rows = classes
        .iter()
        .map(|class| SECURE_EXTENSION_DEGREE * class.secure.len() + class.base.len())
        .max()
        .unwrap_or(0);
    let independent = classes
        .par_iter()
        .all(|class| full_rank(class.log_size, log_mask_rows, &class.secure, &class.base));
    Some(Revealed {
        classes: classes.len(),
        rows,
        independent,
    })
}

/// Whether the functionals `r ↦ (v_H·r)(p)` at `secure` (four M31 rows a
/// point) and `base` (one) are independent over `r`'s `h` coefficients.
fn full_rank(
    log_size: u32,
    log_mask_rows: u32,
    secure: &[CirclePoint<SecureField>],
    base: &[CirclePoint<BaseField>],
) -> bool {
    let h = 1usize << log_mask_rows;
    let coset = CanonicCoset::new(log_size).coset;
    let mut rows: Vec<Vec<BaseField>> = Vec::new();
    for &point in secure {
        let vanishing = coset_vanishing(coset, point);
        let basis = basis_at(point, log_mask_rows);
        for k in 0..SECURE_EXTENSION_DEGREE {
            rows.push(
                basis
                    .iter()
                    .map(|&b| (vanishing * b).to_m31_array()[k])
                    .collect(),
            );
        }
    }
    for point in base {
        let point = point.into_ef::<SecureField>();
        let vanishing = coset_vanishing(coset, point);
        rows.push(
            basis_at(point, log_mask_rows)
                .iter()
                .map(|&b| (vanishing * b).to_m31_array()[0])
                .collect(),
        );
    }
    let n_rows = rows.len();
    n_rows <= h && rank_m31(rows) == n_rows
}

/// The circle FFT basis of `2^log_size` elements at `point`: the products of
/// `y`, `x`, `π(x)`, … by the bits of each index.
fn basis_at(point: CirclePoint<SecureField>, log_size: u32) -> Vec<SecureField> {
    let mut factors = vec![point.y];
    let mut x = point.x;
    for _ in 1..log_size {
        factors.push(x);
        x = CirclePoint::double_x(x);
    }
    let mut values = vec![SecureField::one()];
    for factor in factors.into_iter().take(log_size as usize) {
        let upper: Vec<SecureField> = values.iter().map(|&value| value * factor).collect();
        values.extend(upper);
    }
    values
}

/// The rank of a matrix over M31, by forward elimination.
pub fn rank_m31(mut rows: Vec<Vec<BaseField>>) -> usize {
    let n_columns = rows.first().map_or(0, Vec::len);
    let mut rank = 0;
    for column in 0..n_columns {
        if rank == rows.len() {
            break;
        }
        let Some(pivot) = (rank..rows.len()).find(|&row| !rows[row][column].is_zero()) else {
            continue;
        };
        rows.swap(rank, pivot);
        let (done, below) = rows.split_at_mut(rank + 1);
        let pivot_row = &done[rank];
        let inverse = pivot_row[column].inverse();
        for row in below {
            if !row[column].is_zero() {
                let factor = row[column] * inverse;
                for (value, &p) in row[column..].iter_mut().zip(&pivot_row[column..]) {
                    *value -= factor * p;
                }
            }
        }
        rank += 1;
    }
    rank
}

#[cfg(test)]
mod tests {
    use stwo::core::circle::M31_CIRCLE_GEN;

    use super::*;

    const LOG_SIZE: u32 = 9;
    const LOG_MASK_ROWS: u32 = 4;

    /// The `h` points of the circle's subgroup of order `h`: a degenerate
    /// set, on which the size-`h` basis satisfies a relation, so `h`
    /// functionals there have rank below `h`.
    #[test]
    fn the_subgroup_of_order_h_is_dependent() {
        let generator = M31_CIRCLE_GEN.repeated_double(31 - LOG_MASK_ROWS);
        let points: Vec<CirclePoint<BaseField>> = (0..1usize << LOG_MASK_ROWS)
            .map(|k| generator.mul(k as u128))
            .collect();
        assert!(!full_rank(LOG_SIZE, LOG_MASK_ROWS, &[], &points));
    }

    /// The `h` points of a coset off the trace domain, on which the size-`h`
    /// basis interpolates: full rank; and one more point is one row too many.
    #[test]
    fn a_coset_of_h_points_is_independent() {
        let coset = CanonicCoset::new(LOG_MASK_ROWS).coset;
        let mut points: Vec<CirclePoint<BaseField>> = coset.iter().collect();
        assert!(full_rank(LOG_SIZE, LOG_MASK_ROWS, &[], &points));
        points.truncate(points.len() - 1);
        let z = CirclePoint::<SecureField>::get_point(98_765);
        assert!(!full_rank(LOG_SIZE, LOG_MASK_ROWS, &[z], &points));
        points.truncate(points.len() - 3);
        assert!(full_rank(LOG_SIZE, LOG_MASK_ROWS, &[z], &points));
    }

    #[test]
    fn rank_m31_counts_independent_rows() {
        let row = |values: [u32; 3]| values.map(BaseField::from).to_vec();
        assert_eq!(
            rank_m31(vec![row([1, 2, 3]), row([2, 4, 6]), row([0, 1, 1])]),
            2
        );
        assert_eq!(
            rank_m31(vec![row([1, 0, 0]), row([0, 1, 0]), row([0, 0, 1])]),
            3
        );
        assert_eq!(rank_m31(vec![row([0, 0, 0])]), 0);
    }
}
