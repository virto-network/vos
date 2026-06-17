//! Recursion build P3 — **the make-or-break log_size measurement (dominant cost)**.
//!
//! The in-AIR verifier-AIR is ~99.5% Poseidon2-M31 permutations (~16K per
//! inner-proof verify — FRI Merkle paths dominate). Its natural log_size is
//! therefore set by the perm count: a one-perm-per-row perm chip has
//! `log_size = ceil(log2(#perms))`. This test proves that perm chip — the exact
//! workhorse the verifier-AIR reuses — at a configurable scale through the lifted
//! Poseidon2-M31 protocol on a clean build, confirming (a) it proves at the
//! make-or-break scale and (b) the resulting log_size.
//!
//! GATE: ~16K perms ⇒ log_size ≈ 14 ≤ the canonical ~19 ⇒ the recursion fixed
//! point is reachable (the verifier-AIR's proof pads up to the canonical shape).
//! Validated terms (config-derived, exact at trace log 19): FRI Merkle auth =
//! 38 queries × Σ(layer heights 21..3) = 38 × 228 = 8,664; trace-tree auth =
//! 4 trees × 38 × 21 = 3,192; + ~3,040 leaf-absorb + ~397 transcript ≈ 15.3K.
//!
//! The default test runs log 10 (light). The heavier scales — log 12 (~145s) and
//! log 14 (the real ~16K count, the verifier-AIR's natural log_size) — run via
//! `perm_scale_large` with `SCALE_LOG` (default 14):
//!   `SCALE_LOG=14 cargo test -p zkpvm --test perm_scale -- --ignored --nocapture`

mod recursion_common;

use num_traits::Zero;
use recursion_common::*;
use stwo::core::air::Component;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::verifier::verify;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

/// One Poseidon2 permutation per row — the verifier-AIR's shared workhorse.
#[derive(Clone)]
struct PermChipEval {
    log_n_rows: u32,
}
impl FrameworkEval for PermChipEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let _ = eval_permutation(&mut eval);
        eval
    }
}

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

fn run_scale(log_size: u32) {
    let config: PcsConfig = mobile_config();
    let n = 1usize << log_size;

    // One distinct permutation per row.
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..N_PERM_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    for row in 0..n {
        let s = storage_index(row, log_size);
        let init: [BaseField; N_STATE] = std::array::from_fn(|i| {
            BaseField::from_u32_unchecked(
                ((row.wrapping_mul(N_STATE) + i + 1) % 0x7fff_ffff) as u32,
            )
        });
        for (c, v) in record_permutation(init).into_iter().enumerate() {
            cols[c].set(s, v);
        }
    }
    let domain = CanonicCoset::new(log_size).circle_domain();
    let trace: Vec<_> = cols
        .into_iter()
        .map(|col| CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, col))
        .collect();

    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);
    let mut tb = cs.tree_builder();
    tb.extend_evals(Vec::new());
    tb.commit(channel);
    let mut tb = cs.tree_builder();
    tb.extend_evals(trace);
    tb.commit(channel);
    let component = FrameworkComponent::<PermChipEval>::new(
        &mut TraceLocationAllocator::default(),
        PermChipEval {
            log_n_rows: log_size,
        },
        SecureField::zero(),
    );
    let proof = prove::<CpuBackend, P2MerkleChannel>(&[&component], channel, cs)
        .expect("prove perm chip at scale");

    let vch = &mut Poseidon2M31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    vs.commit(proof.commitments[0], &sizes[0], vch);
    vs.commit(proof.commitments[1], &sizes[1], vch);
    verify(&[&component as &dyn Component], vch, &mut vs, proof)
        .expect("verify perm chip at scale");

    eprintln!(
        "perm_scale GREEN: {n} Poseidon2-M31 perms (one/row) = log_size {log_size}, \
         {N_PERM_COLS} cols/row, proved+verified through the lifted protocol. \
         (real per-inner-proof verify ≈ 16K perms = log_size ~14; canonical ~19 ⇒ \
         fixed point reachable.)"
    );
}

fn scale_log() -> u32 {
    std::env::var("SCALE_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(14)
}

/// Light default (log 10, ~15s): the perm chip proves+verifies at scale through
/// the lifted protocol on a clean build. log 12 (~145s) and log 14 (the real
/// ~16K-perm count) are validated via `perm_scale_large`.
#[test]
fn perm_scale_default() {
    run_scale(10);
}

/// Push toward the real ~16K-perm scale (log 14 ≈ the per-inner-proof perm count,
/// the verifier-AIR's natural log_size). Slow / memory-heavy with the scalar
/// custom hasher — run explicitly: `SCALE_LOG=14 cargo test … -- --ignored`.
#[test]
#[ignore = "heavy (scalar hasher); set SCALE_LOG (default 14) and run with --ignored"]
fn perm_scale_large() {
    run_scale(scale_log());
}
