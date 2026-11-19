//! The ordering delta's bits, the prover's half.

use super::*;
use stwo::core::fields::m31::BaseField;

// A run within the prover's bound orders within the bits: its widest gap,
// from a `ts = 0` write to the closing read after its last step, is
// `2(MAX_RUN_STEPS + 1) − 1`; one step more and it would not.
const WIDEST: u64 = 2 * (crate::prove::MAX_RUN_STEPS as u64 + 1) - 1;
const _: () = assert!(WIDEST < 1 << ORDER_DELTA_BITS);
const _: () = assert!(WIDEST + 2 >= 1 << ORDER_DELTA_BITS);

/// The bits of `ledger`'s ordering delta `delta`.
///
/// # Panics
/// When `delta` does not fit [`ORDER_DELTA_BITS`]: no proof binds it. A run
/// within `MAX_RUN_STEPS` never reaches it (`crate::prove`); the message
/// names the ledger alone, no value of the run.
pub(crate) fn bits(ledger: &str, delta: u64) -> [BaseField; ORDER_DELTA_BITS] {
    assert!(
        delta < 1 << ORDER_DELTA_BITS,
        "a {ledger} ordering delta past the {ORDER_DELTA_BITS}-bit proof bound"
    );
    core::array::from_fn(|bit| BaseField::from(((delta >> bit) & 1) as u32))
}
