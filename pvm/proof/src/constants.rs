//! The known programs' constants, pinned in the repository: the program
//! ids of the kernels the slice's statements are made by, the fold
//! circuit's hash `H_fold` (every node's fold word), and the final wrap's
//! preprocessed root (`format::MASKED_WRAP`), the final verifier's constant
//! re-exported: `just repin` writes the others, and a circuit change that
//! moves the root is written into `vos-pvm-final-verifier` by hand (a
//! venue's verifying key).
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
    669263016, 2062130135, 486182989, 487937710, 1729962557, 1359418688, 1982199217, 1400886892,
];

/// The balance kernel's: the `balance` test actor's `at_least`.
pub const BALANCE_PROGRAM: [u32; 8] = [
    54088335, 1223015997, 1289224373, 1714354632, 1311890151, 1140654484, 551315295, 419728885,
];

/// The solvency predicate's: the `kernels` test actor's `areas`.
pub const PREDICATE_PROGRAM: [u32; 8] = [
    901840774, 504072782, 1334161016, 1917377011, 2072527272, 1352940115, 1217929938, 2139199218,
];

/// `H_fold`: the fold circuit's hash over the padded shape, the fold word
/// every node of a tree carries and the wrap checks.
pub const H_FOLD: [u32; 8] = [
    1926018953, 708720600, 521533944, 511795374, 1724860191, 691497565, 1028082666, 1483953229,
];

/// The final wrap's preprocessed root under `format::MASKED_WRAP`, on the
/// Blake2b-256 trees: the final verifier's, the one copy a venue holds.
pub use vos_pvm_final_verifier::PREPROCESSED_ROOT_39;
