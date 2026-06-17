//! Recursion build P3 — **integration + integrated-log_size re-measurement**.
//!
//! The verifier-AIR is ONE uniform component. Steps 1-3 built its chips in
//! isolation — ChannelChip (Poseidon2-M31 transcript replay), MerkleDecommit
//! (`merkle_decommit_merged.rs`), FriFoldChip, OodsCompositionChip — and each
//! proved+verified through the lifted Poseidon2-M31 protocol. This test composes
//! the two *cost classes* in one component and re-measures the integrated
//! log_size:
//!
//!   * the **perm workhorse** (`eval_permutation`, ~442 cols/row) — the row-count
//!     driver: the verifier-AIR is ~99.5% Poseidon2 perms (channel + Merkle
//!     decommit), so its natural log_size = ceil(log2(#perm rows)).
//!   * the **field-arithmetic** chips (FriFold + OODS) — ~56K QM31 muls total
//!     across a verify, spread at ~3.5 muls/row over the ~16K perm rows. Here each
//!     row carries a full FriFold step PLUS four OODS-style QM31 muls (~5
//!     muls/row, an upper bound), riding as ADDITIONAL COLUMNS on the perm rows.
//!
//! The make-or-break log_size (≈14 ≤ canonical 19) was already MEASURED for the
//! perm workhorse alone (`perm_scale.rs`, proven at log 14 = the real ~16K-perm
//! count). This test confirms the integration claim: adding the field-arithmetic
//! chips keeps every constraint degree ≤ 2 (`max_constraint_log_degree_bound =
//! log+1`) and adds WIDTH (columns), not DEPTH (rows) — so the integrated
//! log_size = ceil(log2(#perm rows)) is unchanged, holding ~14 at the real scale.
//!
//! GATE: the integrated one-uniform-component AIR (perm + FriFold + OODS field
//! arithmetic) proves+verifies through the lifted Poseidon2-M31 protocol at
//! `log+1` degree, and its log_size equals the perm row count. The heavy
//! `verifier_air_integration_scale` (SCALE_LOG, default 14) measures it directly
//! at the real per-inner-proof perm count.
//!
//! Run: `cargo test -p zkpvm --test verifier_air_integration -- --nocapture`

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

/// Per-row OODS-style QM31 muls (the spread DEEP/OODS/inner-AIR field arithmetic).
const N_OODS_MULS: usize = 4;

/// Per-row column layout, in evaluate/fill order:
///   perm[N_PERM_COLS]
///   fri: f_x[4] f_neg_x[4] alpha[4] itwid[1] scaled[4] prod[4] folded[4]   (25)
///   oods: (x[4] y[4] prod[4]) × N_OODS_MULS                                (12·N)
const FRI_COLS: usize = 25;
const OODS_COLS: usize = 12 * N_OODS_MULS;
const ROW_COLS: usize = N_PERM_COLS + FRI_COLS + OODS_COLS;

#[derive(Clone)]
struct VerifierAirEval {
    log_n_rows: u32,
}

impl FrameworkEval for VerifierAirEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2 across ALL integrated chips
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // ── Perm workhorse: the row-count / log_size driver. ──
        let _ = eval_permutation(&mut eval);

        // ── FriFold step (field arithmetic). ──
        let f_x: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let f_neg_x: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let alpha: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let itwid = eval.next_trace_mask();
        let scaled: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let prod: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let folded: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        for k in 0..4 {
            eval.add_constraint(
                scaled[k].clone() - (f_x[k].clone() - f_neg_x[k].clone()) * itwid.clone(),
            );
        }
        let alpha_ef = E::combine_ef(alpha);
        let scaled_ef = E::combine_ef(scaled);
        let prod_ef = E::combine_ef(prod.clone());
        eval.add_constraint(prod_ef.clone() - alpha_ef * scaled_ef);
        let fx_ef = E::combine_ef(f_x);
        let fnx_ef = E::combine_ef(f_neg_x);
        let folded_ef = E::combine_ef(folded);
        eval.add_constraint(folded_ef - (fx_ef + fnx_ef + prod_ef));

        // ── OODS-style QM31 muls (the spread DEEP/OODS field arithmetic). ──
        for _ in 0..N_OODS_MULS {
            let x: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
            let y: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
            let p: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
            let x_ef = E::combine_ef(x);
            let y_ef = E::combine_ef(y);
            let p_ef = E::combine_ef(p);
            eval.add_constraint(p_ef - x_ef * y_ef);
        }
        eval
    }
}

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

fn qm(a: u32, b: u32, c: u32, d: u32) -> SecureField {
    SecureField::from_m31_array([
        BaseField::from(a),
        BaseField::from(b),
        BaseField::from(c),
        BaseField::from(d),
    ])
}

/// A valid integrated row: a real perm + a self-consistent FriFold step + four
/// self-consistent OODS-style QM31 muls (all constraints satisfied by construction).
fn row_values(row: usize) -> Vec<BaseField> {
    let mut out = Vec::with_capacity(ROW_COLS);

    // Perm.
    let init: [BaseField; N_STATE] = std::array::from_fn(|i| {
        BaseField::from_u32_unchecked(((row.wrapping_mul(N_STATE) + i + 1) % 0x7fff_ffff) as u32)
    });
    out.extend(record_permutation(init));

    // FriFold (folded = (f_x + f_neg_x) + alpha·((f_x − f_neg_x)·itwid)).
    let r = row as u32;
    let f_x = qm(r + 1, r + 2, r + 3, r + 4);
    let f_neg_x = qm(r + 5, r + 6, r + 7, r + 8);
    let alpha = qm(r + 9, r + 10, r + 11, r + 12);
    let itwid = BaseField::from(r + 13);
    let scaled = (f_x - f_neg_x) * itwid;
    let prod = alpha * scaled;
    let folded = (f_x + f_neg_x) + prod;
    out.extend(f_x.to_m31_array());
    out.extend(f_neg_x.to_m31_array());
    out.extend(alpha.to_m31_array());
    out.push(itwid);
    out.extend(scaled.to_m31_array());
    out.extend(prod.to_m31_array());
    out.extend(folded.to_m31_array());

    // OODS muls.
    for m in 0..N_OODS_MULS as u32 {
        let x = qm(r + 17 + m, r + 18 + m, r + 19 + m, r + 20 + m);
        let y = qm(r + 21 + m, r + 22 + m, r + 23 + m, r + 24 + m);
        let p = x * y;
        out.extend(x.to_m31_array());
        out.extend(y.to_m31_array());
        out.extend(p.to_m31_array());
    }

    debug_assert_eq!(out.len(), ROW_COLS);
    out
}

fn run_integration(log_size: u32) {
    let config: PcsConfig = mobile_config();
    let n = 1usize << log_size;
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..ROW_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    for row in 0..n {
        let s = storage_index(row, log_size);
        for (c, v) in row_values(row).into_iter().enumerate() {
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

    let component = FrameworkComponent::<VerifierAirEval>::new(
        &mut TraceLocationAllocator::default(),
        VerifierAirEval {
            log_n_rows: log_size,
        },
        SecureField::zero(),
    );
    let proof = prove::<CpuBackend, P2MerkleChannel>(&[&component], channel, cs)
        .expect("prove the integrated verifier-AIR");

    let vch = &mut Poseidon2M31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    vs.commit(proof.commitments[0], &sizes[0], vch);
    vs.commit(proof.commitments[1], &sizes[1], vch);
    verify(&[&component as &dyn Component], vch, &mut vs, proof)
        .expect("verify the integrated verifier-AIR");

    eprintln!(
        "verifier_air_integration GREEN @ log_size {log_size}: ONE uniform component \
         = perm workhorse ({N_PERM_COLS} cols) + FriFold ({FRI_COLS} cols) + OODS \
         field-arith ({OODS_COLS} cols, {N_OODS_MULS} QM31 muls) = {ROW_COLS} cols/row, \
         proved+verified through the lifted Poseidon2-M31 protocol at \
         max_constraint_log_degree_bound = log+1 (degree ≤ 2 held under integration). \
         log_size = ceil(log2(#perm rows)) = {log_size}: the field-arith chips add \
         WIDTH ({FRI_COLS}+{OODS_COLS} cols), not DEPTH (rows). At the real ~16K-perm \
         count ⇒ log_size 14 ≤ canonical 19 (perm_scale confirms log 14 at scale)."
    );
}

/// GATE: the integrated verifier-AIR proves+verifies as ONE uniform component at
/// degree ≤ 2; the field-arithmetic chips add columns, not rows.
#[test]
fn verifier_air_integration_gate() {
    run_integration(8);
}

fn scale_log() -> u32 {
    std::env::var("SCALE_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(14)
}

/// Measure the integrated log_size directly at the real per-inner-proof perm count
/// (~16K perms = log 14). Heavy (scalar custom hasher) — opt in:
///   `SCALE_LOG=14 cargo test -p zkpvm --test verifier_air_integration -- --ignored --nocapture`
#[test]
#[ignore = "heavy (scalar hasher); set SCALE_LOG (default 14) and run with --ignored"]
fn verifier_air_integration_scale() {
    run_integration(scale_log());
}
