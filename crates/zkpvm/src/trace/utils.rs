use num_traits::Zero;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use stwo::{
    core::fields::m31::BaseField,
    prover::backend::simd::{SimdBackend, column::BaseColumn, m31::LOG_N_LANES},
};

pub use stwo::prover::backend::ColumnOps;
use stwo_constraint_framework::EvalAtRow;

use crate::core::step::WORD_SIZE;

use super::utils_external::coset_order_to_circle_domain_order;

/// Pick a `log_size` that covers `num_entries` real rows and is at least
/// `LOG_N_LANES` (SIMD pack width).  Every chip with a dynamically sized
/// trace uses this pattern; centralising here avoids the
/// `((n as f64).log2().ceil() as u32).max(LOG_N_LANES)` incantation.
pub fn ceil_log2_at_least_lanes(num_entries: usize) -> u32 {
    if num_entries == 0 {
        LOG_N_LANES
    } else {
        ((num_entries as f64).log2().ceil() as u32).max(LOG_N_LANES)
    }
}

/// Trait for BaseField representation.
pub trait IntoBaseFields<const N: usize> {
    fn into_base_fields(self) -> [BaseField; N];
}

impl IntoBaseFields<1> for bool {
    fn into_base_fields(self) -> [BaseField; 1] {
        [BaseField::from(self as u32)]
    }
}

impl IntoBaseFields<1> for u8 {
    fn into_base_fields(self) -> [BaseField; 1] {
        [BaseField::from(self as u32)]
    }
}

impl<const N: usize> IntoBaseFields<N> for [bool; N] {
    fn into_base_fields(self) -> [BaseField; N] {
        std::array::from_fn(|i| BaseField::from(self[i] as u32))
    }
}

impl<const N: usize> IntoBaseFields<N> for [u8; N] {
    fn into_base_fields(self) -> [BaseField; N] {
        std::array::from_fn(|i| BaseField::from(self[i] as u32))
    }
}

impl<const N: usize> IntoBaseFields<N> for [u16; N] {
    fn into_base_fields(self) -> [BaseField; N] {
        std::array::from_fn(|i| BaseField::from(self[i] as u32))
    }
}

impl<const N: usize> IntoBaseFields<N> for [BaseField; N] {
    fn into_base_fields(self) -> [BaseField; N] {
        self
    }
}

impl IntoBaseFields<1> for BaseField {
    fn into_base_fields(self) -> [BaseField; 1] {
        [self]
    }
}

/// 64-bit value as 8 × 8-bit limbs (little-endian).
pub type Word64 = [u8; WORD_SIZE];

impl IntoBaseFields<WORD_SIZE> for u64 {
    fn into_base_fields(self) -> [BaseField; WORD_SIZE] {
        let bytes = self.to_le_bytes();
        std::array::from_fn(|i| BaseField::from(bytes[i] as u32))
    }
}

/// 32-bit value as 4 × 8-bit limbs for addresses.
impl IntoBaseFields<4> for u32 {
    fn into_base_fields(self) -> [BaseField; 4] {
        let bytes = self.to_le_bytes();
        std::array::from_fn(|i| BaseField::from(bytes[i] as u32))
    }
}

/// Trait for reading BaseFields back to values.
pub trait FromBaseFields<const N: usize> {
    fn from_base_fields(elms: [BaseField; N]) -> Self;
}

impl FromBaseFields<WORD_SIZE> for Word64 {
    fn from_base_fields(elms: [BaseField; WORD_SIZE]) -> Self {
        let mut ret = Word64::default();
        for (i, b) in elms.iter().enumerate() {
            let read = b.0;
            assert!(read < 256, "invalid byte value");
            ret[i] = read as u8;
        }
        ret
    }
}

impl FromBaseFields<WORD_SIZE> for u64 {
    fn from_base_fields(elms: [BaseField; WORD_SIZE]) -> Self {
        let bytes = Word64::from_base_fields(elms);
        u64::from_le_bytes(bytes)
    }
}

pub fn finalize_columns(columns: Vec<Vec<BaseField>>) -> Vec<BaseColumn> {
    let mut ret = Vec::with_capacity(columns.len());
    columns
        .into_par_iter()
        .map(|col| {
            let eval = coset_order_to_circle_domain_order(col.as_slice());
            let mut base_column = BaseColumn::from_iter(eval);
            <SimdBackend as ColumnOps<BaseField>>::bit_reverse_column(&mut base_column);
            base_column
        })
        .collect_into_vec(&mut ret);
    ret
}

pub fn zero_array<const N: usize, E: EvalAtRow>() -> [E::F; N] {
    std::array::from_fn(|_i| E::F::zero())
}
