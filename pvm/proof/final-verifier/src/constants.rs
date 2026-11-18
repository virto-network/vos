//! The wrap circuit's constants, pinned: `vos-pvm-recair`'s wrap tests
//! compute them from the circuit and the registry, and refuse a change here
//! that is not theirs.

/// The wrap circuit's components' log sizes: `p2`, `qm31`, `h8`.
pub const LOG_SIZES: [u32; 3] = [14, 15, 11];

/// The wrap circuit's preprocessed tree's root on the Blake2b-256 Merkle
/// trees, as `format::MASKED_WRAP` commits it: its columns one level up
/// (`n + 1`), under blowup 32.
pub const PREPROCESSED_ROOT_39: [u8; 32] = [
    235, 181, 144, 217, 124, 170, 219, 26, 45, 153, 22, 7, 5, 112, 52, 14, 196, 20, 210, 130, 185,
    148, 36, 99, 250, 170, 77, 242, 141, 133, 217, 224,
];

/// `format::MASKED_WRAP`'s trees' widths: preprocessed 57; main 381 (373
/// and 8 salts); interaction 48 (40 and 8 salts); composition 20 (its 4
/// coordinates, `R`'s 8 and 8 salts).
pub const TREE_WIDTHS: [usize; 4] = [57, 381, 48, 20];

/// The longest wrap proof a decode reads, in bytes: a bound on a venue's
/// decode and verify work, which a weight is charged by. The layout's
/// longest, every witness at its bound, is 140,356 bytes; a
/// `format::MASKED_WRAP` proof is about 100 KB.
pub const MAX_PROOF_BYTES: usize = 140 << 10;
