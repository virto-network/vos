//! The wrap circuit's constants, pinned: `vos-pvm-recair`'s wrap test computes
//! them from the circuit and refuses a change here that is not the
//! circuit's.

/// The wrap circuit's components' log sizes: `p2`, `qm31`, `h8`.
pub const LOG_SIZES: [u32; 3] = [14, 15, 11];

/// The wrap circuit's preprocessed tree's root on the Blake2b-256 Merkle
/// trees, format 28's.
pub const PREPROCESSED_ROOT: [u8; 32] = [
    242, 222, 64, 119, 8, 117, 210, 231, 91, 134, 186, 46, 66, 17, 191, 228, 202, 180, 196, 8, 255,
    79, 80, 233, 170, 53, 248, 208, 10, 0, 176, 135,
];
