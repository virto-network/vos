//! The ordering delta's bits, the prover's half.

use super::*;
use stwo::core::fields::m31::BaseField;

/// The bits of `ledger`'s ordering delta `delta`.
///
/// # Panics
/// When `delta` does not fit [`ORDER_DELTA_BITS`]: no proof binds it.
pub(crate) fn bits(ledger: &str, delta: u64) -> [BaseField; ORDER_DELTA_BITS] {
    assert!(
        delta < 1 << ORDER_DELTA_BITS,
        "{ledger} ordering delta {delta} exceeds the {ORDER_DELTA_BITS}-bit proof bound"
    );
    core::array::from_fn(|bit| BaseField::from(((delta >> bit) & 1) as u32))
}
