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
pub struct MaskLayout {
    log_size: u32,
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
            lower,
            upper,
        })
    }

    pub fn log_size(&self) -> u32 {
        self.log_size
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

/// The layouts for every size among `log_sizes`, built in parallel.
pub(crate) fn layouts(
    log_sizes: &[u32],
    log_mask_rows: u32,
) -> Result<Vec<MaskLayout>, ProveError> {
    let mut sizes = log_sizes.to_vec();
    sizes.sort_unstable();
    sizes.dedup();
    sizes
        .into_par_iter()
        .map(|log_size| MaskLayout::new(log_size, log_mask_rows))
        .collect()
}

/// Each of `polys` masked by its size's layout, in parallel, one 32-byte
/// seed a column drawn from `rng` in order.
pub(crate) fn mask_columns(
    polys: &[&CircleCoefficients<SimdBackend>],
    layouts: &[MaskLayout],
    rng: &mut ChaCha20Rng,
) -> Result<Vec<CircleCoefficients<SimdBackend>>, ProveError> {
    let seeds: Vec<[u8; 32]> = polys.iter().map(|_| rng.r#gen()).collect();
    polys
        .par_iter()
        .zip(seeds)
        .map(|(poly, seed)| {
            let layout = layouts
                .iter()
                .find(|layout| layout.log_size == poly.log_size())
                .ok_or(ProveError::Masking("a column of a size with no layout"))?;
            layout.mask(poly, &mut ChaCha20Rng::from_seed(seed))
        })
        .collect()
}
