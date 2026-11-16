//! The chips' shared trace-generation helpers, the prover's half.

/// The least log size of the arithmetic chips' traces (multiplication,
/// division, comparison and the bitwise operations).
pub(super) const MIN_ARITHMETIC_LOG_SIZE: u32 = 5;

/// The device run a device chip's trace is generated from.
///
/// # Panics
/// On a side note of no device run: the device chips are in no node shape.
pub(crate) fn device_run(side_note: &crate::side_note::SideNote) -> &crate::device::DeviceRun {
    side_note
        .device
        .as_deref()
        .expect("a device chip's trace needs the device run")
}

/// A fixed table's log size: its entries' `natural`, or `floor` when that
/// is larger, its rows past the entries repeating them with no
/// multiplicity, so a padded table holds the same entries.
pub(crate) fn table_log_size(natural: u32, floor: u32) -> u32 {
    natural
        .max(stwo::prover::backend::simd::m31::LOG_N_LANES)
        .max(floor)
}
