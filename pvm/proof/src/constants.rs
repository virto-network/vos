//! The known programs' constants, pinned in the repository: the program
//! ids of the test actors' kernels the known statements are made by, the
//! fold circuit's hash `H_fold` (every node's fold word), and the final
//! wrap's preprocessed root (`format::MASKED_WRAP`), the final verifier's
//! constant re-exported: `just repin` writes the others, and a circuit
//! change that moves the root is written into `vos-pvm-final-verifier` by
//! hand (a venue's verifying key).
//!
//! `test-proof` recomputes each from its source under both of the
//! prover's feature sets (with and without `debug-internals`): `H_fold`
//! and the root by this crate's `kernel` test, the program ids, from the
//! test actors' ELFs, by `vos-kernel-tests`' on the node side, where `just
//! repro-aarch64` also recomputes them by `vos program-id` on aarch64. A
//! change of the derivation, a shape, a circuit or a hash that moves one
//! fails there, not at a venue.
//!
//! **What they do not do:** they pin the known programs' ids; they do not
//! make a submitted id trustworthy. A venue or an installer trusts a
//! program id only by recomputing it from the kernel's blob (an id
//! computed over an unchecked wiring is a malicious verifying key for that
//! id).

/// The window kernel's program id: the `window` test actor's `settle`,
/// eight M31 words.
pub const WINDOW_PROGRAM: [u32; 8] = [
    1134855099, 747866561, 671088315, 1522360042, 805738041, 1419018115, 1475238648, 353450360,
];

/// The balance kernel's: the `balance` test actor's `at_least`.
pub const BALANCE_PROGRAM: [u32; 8] = [
    993526642, 1755187750, 435712459, 1991305185, 601016329, 1668991450, 1492866769, 221165399,
];

/// The solvency predicate's: the `kernels` test actor's `areas`.
pub const PREDICATE_PROGRAM: [u32; 8] = [
    930763808, 801961563, 2115120588, 814325023, 166596691, 1827530137, 800015836, 2074849052,
];

/// `H_fold`: the fold circuit's hash over the padded shape, the fold word
/// every node of a tree carries and the wrap checks.
pub const H_FOLD: [u32; 8] = [
    1926018953, 708720600, 521533944, 511795374, 1724860191, 691497565, 1028082666, 1483953229,
];

/// The final wrap's preprocessed root under `format::MASKED_WRAP`, on the
/// Blake2b-256 trees: the final verifier's, the one copy a venue holds.
pub use vos_pvm_final_verifier::PREPROCESSED_ROOT_39;
