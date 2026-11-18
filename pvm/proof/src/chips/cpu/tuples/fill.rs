//! A tuple's width in limbs, which the trace fill reads.

use super::*;

/// The number of limbs `columns` hold.
pub(in crate::chips::cpu) fn width(columns: &[Column]) -> usize {
    columns.iter().map(|column| column.const_size()).sum()
}
