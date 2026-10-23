//! The known programs' constants, pinned in the repository: the program
//! ids of the kernels the slice's statements are made by, the fold
//! circuit's hash `H_fold` (every node's fold word) and the final wrap's
//! preprocessed roots, unmasked (format 28) and masked (39).
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
    78599581, 838564090, 1652218571, 616929652, 105556363, 1590117205, 993656914, 511957845,
];

/// The balance kernel's: the `balance` test actor's `at_least`.
pub const BALANCE_PROGRAM: [u32; 8] = [
    2138763073, 1583761847, 703805682, 1398107483, 579051229, 1648017018, 285859894, 1294321447,
];

/// The solvency predicate's: the `kernels` test actor's `areas`.
pub const PREDICATE_PROGRAM: [u32; 8] = [
    1237444788, 2027797525, 2010929086, 1198475079, 1410019032, 1597179871, 1528723176, 1470493247,
];

/// `H_fold`: the fold circuit's hash over the padded shape, the fold word
/// every node of a tree carries and the wrap checks.
pub const H_FOLD: [u32; 8] = [
    1926018953, 708720600, 521533944, 511795374, 1724860191, 691497565, 1028082666, 1483953229,
];

/// The final wrap's preprocessed root under format 28, unmasked, on the
/// Blake2b-256 trees.
pub const WRAP_ROOT_28: [u8; 32] = [
    242, 222, 64, 119, 8, 117, 210, 231, 91, 134, 186, 46, 66, 17, 191, 228, 202, 180, 196, 8, 255,
    79, 80, 233, 170, 53, 248, 208, 10, 0, 176, 135,
];

/// The final wrap's preprocessed root under format 39, masked: its columns
/// one level up under blowup 32, so equal to format 28's.
pub const WRAP_ROOT_39: [u8; 32] = [
    242, 222, 64, 119, 8, 117, 210, 231, 91, 134, 186, 46, 66, 17, 191, 228, 202, 180, 196, 8, 255,
    79, 80, 233, 170, 53, 248, 208, 10, 0, 176, 135,
];
