//! A column masked: `f' = f + v_H·r`, `r` of `h` uniform coefficients, so
//! `f'` equals `f` on the trace domain `H` and has twice its degree bound.
//!
//! [`MaskLayout`] reads off the backend, once a column size, where `f`'s
//! coefficients land when `f` is extended one level, and the `h` basis
//! elements `v_H·r` spans there; masking a column then writes `f`'s
//! coefficients and `h` random ones into one vector, with no product taken.

use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rayon::prelude::*;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_index;
use stwo::prover::backend::Column;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleCoefficients, CircleEvaluation};

use crate::prove::ProveError;

/// Where `f + v_H·r` puts its coefficients for a column of `2^log_size`
/// rows, masked by `2^log_mask_rows` random coefficients.
#[derive(Clone, Debug)]
pub(crate) struct MaskLayout {
    log_size: u32,
    log_mask_rows: u32,
    /// `f`'s `i`-th coefficient's position at `log_size + 1`.
    lower: Vec<usize>,
    /// The `h` positions `v_H·r` spans at `log_size + 1`, none of `lower`'s.
    upper: Vec<usize>,
}

impl MaskLayout {
    /// The layout at `log_size`, refused unless `h ≤ N/4`: the masked
    /// columns' constraints must stay inside the composition's bound
    /// (`MASKED_LOG_CONSTRAINT_EXPANSION`).
    pub fn new(log_size: u32, log_mask_rows: u32) -> Result<Self, ProveError> {
        if log_mask_rows + 2 > log_size || log_size >= usize::BITS - 2 {
            return Err(ProveError::Masking(
                "h exceeds a quarter of a component's rows",
            ));
        }
        let n = 1usize << log_size;
        let extended = CircleCoefficients::<SimdBackend>::new(
            (1..=n as u32).map(BaseField::from).collect::<BaseColumn>(),
        )
        .extend(log_size + 1)
        .coeffs
        .to_cpu();
        let mut lower = vec![usize::MAX; n];
        for (position, value) in extended.iter().enumerate() {
            if let Some(slot) = (value.0 as usize)
                .checked_sub(1)
                .and_then(|i| lower.get_mut(i))
            {
                *slot = position;
            }
        }
        if lower.contains(&usize::MAX) {
            return Err(ProveError::Masking(
                "a coefficient is lost in the extension",
            ));
        }

        let h = 1usize << log_mask_rows;
        let domain = CanonicCoset::new(log_size + 1).circle_domain();
        let r = CircleCoefficients::<SimdBackend>::new(
            (1..=h as u32).map(BaseField::from).collect::<BaseColumn>(),
        )
        .extend(log_size + 1)
        .evaluate(domain)
        .values
        .to_cpu();
        let trace_coset = CanonicCoset::new(log_size).coset;
        let product = (0..2 * n)
            .map(|i| {
                let point = domain.at(bit_reverse_index(i, log_size + 1));
                coset_vanishing(trace_coset, point) * r[i]
            })
            .collect::<BaseColumn>();
        let upper: Vec<usize> =
            CircleEvaluation::<SimdBackend, BaseField, BitReversedOrder>::new(domain, product)
                .interpolate()
                .coeffs
                .to_cpu()
                .iter()
                .enumerate()
                .filter(|(_, value)| !value.is_zero())
                .map(|(position, _)| position)
                .collect();
        if upper.len() != h {
            return Err(ProveError::Masking(
                "v_H·r spans other than h basis elements",
            ));
        }
        let mut taken = vec![false; 2 * n];
        for &position in &lower {
            taken[position] = true;
        }
        if upper.iter().any(|&position| taken[position]) {
            return Err(ProveError::Masking(
                "v_H·r overlaps the column's coefficients",
            ));
        }
        Ok(Self {
            log_size,
            log_mask_rows,
            lower,
            upper,
        })
    }

    /// `poly + v_H·r` at `log_size + 1`, `r`'s `h` coefficients from `rng`.
    pub fn mask(
        &self,
        poly: &CircleCoefficients<SimdBackend>,
        rng: &mut impl Rng,
    ) -> Result<CircleCoefficients<SimdBackend>, ProveError> {
        if poly.log_size() != self.log_size {
            return Err(ProveError::Masking(
                "a column of another size than its layout",
            ));
        }
        let mut column = BaseColumn::zeros(2 << self.log_size);
        let coefficients = column.as_mut_slice();
        for (value, &position) in poly.coeffs.as_slice().iter().zip(&self.lower) {
            coefficients[position] = *value;
        }
        for &position in &self.upper {
            coefficients[position] = rng.r#gen::<BaseField>();
        }
        Ok(CircleCoefficients::new(column))
    }
}

/// The layouts for every component's size and `h` among `classes`, each a
/// `(log_size, log_mask_rows)`, built in parallel.
pub(crate) fn layouts(classes: &[(u32, u32)]) -> Result<Vec<MaskLayout>, ProveError> {
    let mut classes = classes.to_vec();
    classes.sort_unstable();
    classes.dedup();
    classes
        .into_par_iter()
        .map(|(log_size, log_mask_rows)| MaskLayout::new(log_size, log_mask_rows))
        .collect()
}

/// Each of `polys`, with its `log2 h`, masked by its size's layout at that
/// `h`, in parallel, one 32-byte seed a column drawn from `rng` in order.
pub(crate) fn mask_columns(
    polys: &[(&CircleCoefficients<SimdBackend>, u32)],
    layouts: &[MaskLayout],
    rng: &mut ChaCha20Rng,
) -> Result<Vec<CircleCoefficients<SimdBackend>>, ProveError> {
    let seeds: Vec<[u8; 32]> = polys.iter().map(|_| rng.r#gen()).collect();
    for seed in &seeds {
        super::drawn::note("a mask column's seed", seed);
    }
    polys
        .par_iter()
        .zip(seeds)
        .map(|(&(poly, log_mask_rows), seed)| {
            let layout = layouts
                .iter()
                .find(|layout| {
                    layout.log_size == poly.log_size() && layout.log_mask_rows == log_mask_rows
                })
                .ok_or(ProveError::Masking("a column of a size with no layout"))?;
            layout.mask(poly, &mut ChaCha20Rng::from_seed(seed))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `f' = f + v_H·r`: `(f' − f)/v_H`, taken on `2N` points off the trace
    /// domain, is a polynomial of exactly `h` coefficients, at every size from
    /// `2^6` to `2^17` rows. Of degree below `N + h ≤ 2N`, `v_H` times it agrees
    /// with `f' − f` everywhere, so `f'` equals `f` on the trace domain.
    #[test]
    fn the_mask_keeps_the_column_on_its_domain() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for log_size in 6..=17u32 {
            let log_mask_rows = (log_size - 2).min(8);
            let h = 1usize << log_mask_rows;
            let layout = MaskLayout::new(log_size, log_mask_rows).unwrap();
            let values: Vec<BaseField> = (0..1u32 << log_size)
                .map(|i| BaseField::from(i.wrapping_mul(2_654_435_761) % 1_000_003))
                .collect();
            let domain = CanonicCoset::new(log_size).circle_domain();
            let f = CircleEvaluation::<SimdBackend, BaseField, BitReversedOrder>::new(
                domain,
                BaseColumn::from_cpu(&values),
            )
            .interpolate();
            let masked = layout.mask(&f, &mut rng).unwrap();
            assert_eq!(masked.log_size(), log_size + 1);
            let wide = CanonicCoset::new(log_size + 1).circle_domain();
            let difference = masked.evaluate(wide).values.to_cpu();
            let original = f.extend(log_size + 1).evaluate(wide).values.to_cpu();
            let trace_coset = CanonicCoset::new(log_size).coset;
            let quotient: Vec<BaseField> = (0..wide.size())
                .map(|i| {
                    let point = wide.at(bit_reverse_index(i, log_size + 1));
                    let vanishing = coset_vanishing(trace_coset, point);
                    (difference[i] - original[i]) / vanishing
                })
                .collect();
            let quotient = CircleEvaluation::<SimdBackend, BaseField, BitReversedOrder>::new(
                wide,
                BaseColumn::from_cpu(&quotient),
            )
            .interpolate();
            // The size-`h` basis at `2^(log_size + 1)`: where an `h`-coefficient
            // polynomial's coefficients land when extended.
            let probe: Vec<BaseField> = (1..=h as u32).map(BaseField::from).collect();
            let span: Vec<bool> =
                CircleCoefficients::<SimdBackend>::new(BaseColumn::from_cpu(&probe))
                    .extend(log_size + 1)
                    .coeffs
                    .to_cpu()
                    .iter()
                    .map(|c| !c.is_zero())
                    .collect();
            let quotient = quotient.coeffs.to_cpu();
            assert!(
                quotient
                    .iter()
                    .zip(&span)
                    .all(|(c, &spanned)| spanned || c.is_zero()),
                "2^{log_size}: (f' − f)/v_H of degree below h"
            );
            let nonzero = quotient.iter().filter(|c| !c.is_zero()).count();
            assert_eq!(nonzero, h, "2^{log_size}");
        }
        assert!(matches!(MaskLayout::new(9, 8), Err(ProveError::Masking(_))));
    }
}
