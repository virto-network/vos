//! The known programs' constants, pinned in the repository: the program
//! ids of the kernels the slice's statements are made by, the fold
//! circuit's hash `H_fold` (every node's fold word) and the final wrap's
//! preprocessed roots, unmasked (`format::WRAP`) and masked (39).
//!
//! `test-proof` recomputes each from its source under both of the
//! prover's feature sets (with and without `debug-internals`), and `just
//! repro-aarch64` recomputes the program ids from the built ELFs by `vos
//! program-id` on aarch64: a change of the derivation, a shape, a circuit
//! or a hash that moves one fails there, not at a venue.
//!
//! **What they do not do:** they pin the known programs' ids; they do not
//! make a submitted id trustworthy. A venue or an installer trusts a
//! program id only by recomputing it from the kernel's blob (an id
//! computed over an unchecked wiring is a malicious verifying key for that
//! id).

/// The window kernel's program id: the `window` test actor's `settle`,
/// eight M31 words.
pub const WINDOW_PROGRAM: [u32; 8] = [
    515351771, 841583046, 174446322, 797390972, 792657034, 173551488, 1946997483, 1614247775,
];

/// The balance kernel's: the `balance` test actor's `at_least`.
pub const BALANCE_PROGRAM: [u32; 8] = [
    443485157, 1204456927, 1094383154, 1890108077, 636016353, 2029741006, 694353007, 1965577679,
];

/// The solvency predicate's: the `kernels` test actor's `areas`.
pub const PREDICATE_PROGRAM: [u32; 8] = [
    1154433713, 1437729230, 1367093833, 1695803357, 1237315789, 560757801, 99882617, 2013259593,
];

/// `H_fold`: the fold circuit's hash over the padded shape, the fold word
/// every node of a tree carries and the wrap checks.
pub const H_FOLD: [u32; 8] = [
    1926018953, 708720600, 521533944, 511795374, 1724860191, 691497565, 1028082666, 1483953229,
];

/// The final wrap's preprocessed root under `format::WRAP`, unmasked, on the
/// Blake2b-256 trees.
pub const WRAP_ROOT_28: [u8; 32] = [
    242, 222, 64, 119, 8, 117, 210, 231, 91, 134, 186, 46, 66, 17, 191, 228, 202, 180, 196, 8, 255,
    79, 80, 233, 170, 53, 248, 208, 10, 0, 176, 135,
];

/// The final wrap's preprocessed root under `format::MASKED_WRAP`, masked: its columns
/// one level up under blowup 32, so equal to `format::WRAP`'s.
pub const WRAP_ROOT_39: [u8; 32] = [
    242, 222, 64, 119, 8, 117, 210, 231, 91, 134, 186, 46, 66, 17, 191, 228, 202, 180, 196, 8, 255,
    79, 80, 233, 170, 53, 248, 208, 10, 0, 176, 135,
];
