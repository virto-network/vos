//! The known programs' constants, pinned in the repository: the program
//! ids of the test actors' kernels the known statements are made by, the
//! fold circuit's hash `H_fold` (every node's fold word), and the final
//! wrap's preprocessed root (`format::MASKED_WRAP`), the final verifier's
//! constant re-exported. `just repin` writes `H_fold` by this crate's
//! `kernel` test and, on the node side, the program ids by
//! `vos-kernel-tests`' (from the test actors, which a tree of `pvm/`
//! alone does not hold: there the ids are neither written nor checked); a
//! circuit change that moves the root is written into
//! `vos-pvm-final-verifier` by hand (a venue's verifying key).
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
    43922483, 1455855420, 2075933358, 1490516833, 9660867, 318469979, 1097228064, 2067528727,
];

/// The balance kernel's: the `balance` test actor's `at_least`.
pub const BALANCE_PROGRAM: [u32; 8] = [
    833663641, 226608902, 906295176, 1130958995, 386497667, 1859356479, 1406878438, 2146833784,
];

/// The solvency predicate's: the `kernels` test actor's `areas`.
pub const PREDICATE_PROGRAM: [u32; 8] = [
    1977351319, 1745859382, 1637071766, 176096193, 440117373, 809283512, 467617939, 1128946568,
];

/// `H_fold`: the fold circuit's hash over the padded shape, the fold word
/// every node of a tree carries and the wrap checks.
pub const H_FOLD: [u32; 8] = [
    432279264, 1157161350, 1252342881, 268022195, 1782745271, 1221220570, 741909909, 271327132,
];

/// The final wrap's preprocessed root under `format::MASKED_WRAP`, on the
/// Blake2b-256 trees: the final verifier's, the one copy a venue holds.
pub use vos_pvm_final_verifier::PREPROCESSED_ROOT_39;
