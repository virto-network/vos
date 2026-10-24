//! The memory and register ledgers' ordering delta: the gap between a row's
//! sort key and the next one's, range-checked non-negative by its
//! decomposition into [`ORDER_DELTA_BITS`] bits.

use num_traits::{One, Zero};
#[cfg(feature = "prover")]
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

/// Ordering deltas must fit below this bit width. Twenty-eight bits cover
/// the canonical actor-proof budget (<100M steps), a register's
/// `2·ts_diff + is_write_diff` left untouched for 2^27 steps among them,
/// while staying far enough below the M31 modulus (`2^28 < p/4`) to reject
/// a field-wrapped negative as an alleged positive.
pub(crate) const ORDER_DELTA_BITS: usize = 28;

/// Constrains each of `bits` boolean and returns their little-endian
/// recomposition, `two` the field's 2.
pub(crate) fn recompose<E: EvalAtRow>(eval: &mut E, bits: &[E::F], two: E::F) -> E::F {
    let mut recomposed = E::F::zero();
    let mut pow2 = E::F::one();
    for bit in bits {
        eval.add_constraint(bit.clone() * (bit.clone() - E::F::one()));
        recomposed += bit.clone() * pow2.clone();
        pow2 *= two.clone();
    }
    recomposed
}

/// The bits of `ledger`'s ordering delta `delta`.
///
/// # Panics
/// When `delta` does not fit [`ORDER_DELTA_BITS`]: no proof binds it.
#[cfg(feature = "prover")]
pub(crate) fn bits(ledger: &str, delta: u64) -> [BaseField; ORDER_DELTA_BITS] {
    assert!(
        delta < 1 << ORDER_DELTA_BITS,
        "{ledger} ordering delta {delta} exceeds the {ORDER_DELTA_BITS}-bit proof bound"
    );
    core::array::from_fn(|bit| BaseField::from(((delta >> bit) & 1) as u32))
}
