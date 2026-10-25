//! The recursion AIR's constraint bodies (`docs/design/recursion-air.md` §1).
//!
//! Three components, wired by one relation:
//! - [`p2`]: a Poseidon2-M31 permutation a row, with the sponge, Merkle and
//!   transcript modes that chain rows instead of wiring them;
//! - [`qm31`]: the QM31 gate
//!   `out = k_m·a·b + k_p·(a⊙b) + k_a·a + k_b·b + k_c·c + Σ_j λ_j·c_j`;
//! - [`h8`]: the DEEP accumulator over eight M31 samples;
//! - [`gate`]: the `Gate` relation `(address, l0, l1, l2, l3)` that wires
//!   them, with signed, preprocessed multiplicities, and why it is sound;
//! - [`masked`]: the three as the masked wrap proves them, masked, blinded
//!   and at a constraint bound of `4N`; leaves and folds never use it.
//!
//! A circuit is the components' preprocessed columns: its coefficients,
//! selectors, addresses and multiplicities. Every constraint is of degree at
//! most 3, and each component finalizes its fractions in pairs.
//!
//! The crate is `no_std` and depends on no prover: the prover (`vos-pvm-recair`)
//! and the final verifier (`vos-pvm-final-verifier`) share it.

#![no_std]

extern crate alloc;

pub mod gate;
pub mod h8;
pub mod masked;
pub mod p2;
pub mod qm31;
pub mod transcript;

use alloc::vec::Vec;

use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

pub use gate::GateRelation;
use vos_pvm_poseidon2::{Digest, M31, Transcript, u32_limbs, u64_limbs};

/// The components' log sizes, in the order [`p2`], [`qm31`], [`h8`].
pub type LogSizes = [u32; 3];

/// A constraint's degree is at most 3, so its quotient's is at most twice
/// the trace's: one more than the log size.
pub const LOG_CONSTRAINT_EXPANSION: u32 = 1;

/// A component's body: its columns, constraints and relation entries, its
/// fractions not yet finalized. A component's own `evaluate` finalizes them
/// in pairs; the masked wrap's ([`masked::MaskedEval`]) adds its blinding
/// fraction first.
pub trait Body: FrameworkEval + Sync {
    fn body<E: EvalAtRow>(&self, eval: &mut E);
}

/// The circuit hash's domain: "VOS/RECA", "IR/CIRCT" as little-endian
/// u64s.
const CIRCUIT_HASH_DOMAIN: [u64; 2] = [
    u64::from_le_bytes(*b"VOS/RECA"),
    u64::from_le_bytes(*b"IR/CIRCT"),
];

/// The circuit hash (`recursion-air.md` §2): one Poseidon2-M31 absorption,
/// from the zero digest, of a domain, the format's number and its parameters
/// (log blowup, queries, PoW, fold step, log last layer, interaction PoW),
/// the components' log sizes, and the preprocessed tree's root. Every
/// integer enters as 16-bit limbs.
///
/// A circuit is its preprocessed wiring, and its tree's root commits to it;
/// the hash also binds the sizes the root's columns are read at and the
/// parameters the proof is checked under.
pub fn circuit_hash(
    format: u32,
    params: [u32; 6],
    log_sizes: &LogSizes,
    preprocessed_root: &Digest,
) -> Digest {
    let mut words = circuit_hash_prefix(format, params, log_sizes);
    words.extend(preprocessed_root);
    let mut transcript = Transcript::default();
    transcript.absorb(&words, &mut ());
    *transcript.digest()
}

/// The words [`circuit_hash`] absorbs before the preprocessed root: the
/// domain, the format, its parameters and the log sizes, 28 of them.
pub fn circuit_hash_prefix(format: u32, params: [u32; 6], log_sizes: &LogSizes) -> Vec<M31> {
    let mut words = Vec::new();
    for word in CIRCUIT_HASH_DOMAIN {
        words.extend(u64_limbs(word));
    }
    for value in core::iter::once(format)
        .chain(params)
        .chain(log_sizes.iter().copied())
    {
        words.extend(u32_limbs(value));
    }
    words
}

/// Every column's id in the preprocessed tree, in commitment order: [`p2`]'s,
/// [`qm31`]'s, then [`h8`]'s.
pub fn preprocessed_ids() -> Vec<PreProcessedColumnId> {
    p2::PREPROCESSED
        .iter()
        .chain(&qm31::PREPROCESSED)
        .chain(&h8::PREPROCESSED)
        .map(|&id| PreProcessedColumnId { id: id.into() })
        .collect()
}

/// Every preprocessed column's log size, in commitment order.
pub fn preprocessed_log_sizes(log_sizes: &LogSizes) -> Vec<u32> {
    [
        (p2::PREPROCESSED.len(), log_sizes[0]),
        (qm31::PREPROCESSED.len(), log_sizes[1]),
        (h8::PREPROCESSED.len(), log_sizes[2]),
    ]
    .into_iter()
    .flat_map(|(count, log_size)| core::iter::repeat_n(log_size, count))
    .collect()
}

/// Each committed tree's column log sizes at `log_sizes`: the preprocessed
/// tree's (in commitment order), the main trace's and the interaction
/// trace's, each component's columns at its log size, in the components'
/// order. What the components' `trace_log_degree_bounds` give, without
/// building them.
pub fn committed_log_sizes(log_sizes: &LogSizes) -> [Vec<u32>; 3] {
    let columns = |counts: [usize; 3]| -> Vec<u32> {
        counts
            .into_iter()
            .zip(log_sizes)
            .flat_map(|(count, &log_size)| core::iter::repeat_n(log_size, count))
            .collect()
    };
    [
        preprocessed_log_sizes(log_sizes),
        columns([p2::N_MAIN, qm31::N_MAIN, h8::N_MAIN]),
        columns([p2::N_INTERACTION, qm31::N_INTERACTION, h8::N_INTERACTION]),
    ]
}

/// The three components' evaluations at `log_sizes` under `relation`, in
/// commitment order: [`p2`], [`qm31`], [`h8`].
pub fn evals(
    relation: &GateRelation,
    log_sizes: &LogSizes,
) -> (p2::P2Eval, qm31::Qm31Eval, h8::H8Eval) {
    let [p2, qm31, h8] = *log_sizes;
    (
        p2::P2Eval {
            log_size: p2,
            relation: relation.clone(),
        },
        qm31::Qm31Eval {
            log_size: qm31,
            relation: relation.clone(),
        },
        h8::H8Eval {
            log_size: h8,
            relation: relation.clone(),
        },
    )
}

/// The three components at `log_sizes` and their claimed sums, their
/// columns allocated in the trees' order.
pub struct Components {
    pub p2: FrameworkComponent<p2::P2Eval>,
    pub qm31: FrameworkComponent<qm31::Qm31Eval>,
    pub h8: FrameworkComponent<h8::H8Eval>,
}

impl Components {
    pub fn new(
        relation: &GateRelation,
        log_sizes: &LogSizes,
        claimed_sums: &[SecureField; 3],
    ) -> Self {
        let (p2, qm31, h8) = evals(relation, log_sizes);
        let [p2_sum, qm31_sum, h8_sum] = *claimed_sums;
        let allocator =
            &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_ids());
        Self {
            p2: FrameworkComponent::new(allocator, p2, p2_sum),
            qm31: FrameworkComponent::new(allocator, qm31, qm31_sum),
            h8: FrameworkComponent::new(allocator, h8, h8_sum),
        }
    }

    /// The components as Stwo's verifier takes them.
    pub fn as_dyn(&self) -> [&dyn stwo::core::air::Component; 3] {
        [&self.p2, &self.qm31, &self.h8]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use stwo_constraint_framework::expr::ExprEvaluator;

    /// Each component's evaluation is its body and its fractions finalized
    /// in pairs, expression for expression: what the masked evaluation
    /// builds on.
    #[test]
    fn each_evaluation_is_its_body_and_its_pairs() {
        fn check<B: Body>(name: &str, component: B) {
            let evaluated = component.evaluate(ExprEvaluator::new());
            let mut split = ExprEvaluator::new();
            component.body(&mut split);
            split.finalize_logup_in_pairs();
            assert!(!split.constraints.is_empty(), "{name}");
            assert_eq!(evaluated.constraints, split.constraints, "{name}");
            assert_eq!(evaluated.intermediates, split.intermediates, "{name}");
            assert_eq!(
                evaluated.ext_intermediates, split.ext_intermediates,
                "{name}"
            );
        }
        let relation = GateRelation::dummy();
        check(
            "p2",
            p2::P2Eval {
                log_size: 4,
                relation: relation.clone(),
            },
        );
        check(
            "qm31",
            qm31::Qm31Eval {
                log_size: 4,
                relation: relation.clone(),
            },
        );
        check(
            "h8",
            h8::H8Eval {
                log_size: 4,
                relation,
            },
        );
    }

    /// The column counts of `recursion-air.md` §1.2: 57 preprocessed, 361
    /// main and 32 interaction columns.
    #[test]
    fn the_components_have_the_designed_widths() {
        assert_eq!(
            [
                p2::PREPROCESSED.len(),
                qm31::PREPROCESSED.len(),
                h8::PREPROCESSED.len()
            ],
            [33, 17, 7]
        );
        assert_eq!([p2::N_MAIN, qm31::N_MAIN, h8::N_MAIN], [309, 16, 36]);
        assert_eq!(
            [p2::N_INTERACTION, qm31::N_INTERACTION, h8::N_INTERACTION],
            [12, 8, 12]
        );
        let ids = preprocessed_ids();
        assert!(stwo::core::utils::all_unique(&ids));
        assert_eq!(preprocessed_log_sizes(&[4, 5, 6]).len(), ids.len());

        let components = Components::new(
            &GateRelation::dummy(),
            &[4, 5, 6],
            &[SecureField::default(); 3],
        );
        for (component, (main, interaction)) in components.as_dyn().into_iter().zip([
            (p2::N_MAIN, p2::N_INTERACTION),
            (qm31::N_MAIN, qm31::N_INTERACTION),
            (h8::N_MAIN, h8::N_INTERACTION),
        ]) {
            let sizes = component.trace_log_degree_bounds();
            assert_eq!([sizes[1].len(), sizes[2].len()], [main, interaction]);
        }
        let committed = committed_log_sizes(&[4, 5, 6]);
        for tree in 1..3 {
            let bounds: Vec<u32> = components
                .as_dyn()
                .iter()
                .flat_map(|component| component.trace_log_degree_bounds()[tree].clone())
                .collect();
            assert_eq!(committed[tree], bounds, "tree {tree}");
        }
        assert_eq!(
            components.as_dyn().map(|c| c.n_constraints()),
            [p2::N_CONSTRAINTS, qm31::N_CONSTRAINTS, h8::N_CONSTRAINTS]
        );
    }
}
