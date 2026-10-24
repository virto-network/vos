//! The wrap circuit's constants, pinned: `vos-pvm-recair`'s wrap tests
//! compute them from the circuit and the registry, and refuse a change here
//! that is not theirs.

/// The wrap circuit's components' log sizes: `p2`, `qm31`, `h8`. Formats 28
/// and 39 alike.
pub const LOG_SIZES: [u32; 3] = [14, 15, 11];

/// The wrap circuit's preprocessed tree's root on the Blake2b-256 Merkle
/// trees, `format::WRAP`'s: its columns at their rows' level, under blowup 64.
pub const PREPROCESSED_ROOT: [u8; 32] = [
    242, 222, 64, 119, 8, 117, 210, 231, 91, 134, 186, 46, 66, 17, 191, 228, 202, 180, 196, 8, 255,
    79, 80, 233, 170, 53, 248, 208, 10, 0, 176, 135,
];

/// `format::MASKED_WRAP`'s: its columns one level up (`n + 1`), under
/// blowup 32. Their evaluations are `format::WRAP`'s at `n + 6`, so the
/// root is `format::WRAP`'s; pinned on its own, and its equality a test.
pub const PREPROCESSED_ROOT_39: [u8; 32] = [
    242, 222, 64, 119, 8, 117, 210, 231, 91, 134, 186, 46, 66, 17, 191, 228, 202, 180, 196, 8, 255,
    79, 80, 233, 170, 53, 248, 208, 10, 0, 176, 135,
];

/// `format::MASKED_WRAP`'s trees' widths: preprocessed 57; main 381 (373
/// and 8 salts); interaction 48 (40 and 8 salts); composition 20 (its 4
/// coordinates, `R`'s 8 and 8 salts).
pub const TREE_WIDTHS: [usize; 4] = [57, 381, 48, 20];

/// The longest wrap proof a decode reads, in bytes: a bound on a venue's
/// decode and verify work, which a weight is charged by. A `format::WRAP` proof
/// is 122–125 KB, a `format::MASKED_WRAP` proof about 150 KB.
pub const MAX_PROOF_BYTES: usize = 256 << 10;
