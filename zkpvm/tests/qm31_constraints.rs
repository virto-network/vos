//! Constrain explicit **QM31 (SecureField) arithmetic** in-AIR as 4×M31 (mul +
//! inverse) — the idiom any in-AIR extension-field arithmetic builds on (e.g.
//! FRI-fold / OODS-composition constraints). No other zkpvm chip constrains
//! explicit extension-field ops: SecureField otherwise appears only in
//! prover-side interaction-trace return types.
//!
//! ## Approach
//!
//! `EvalAtRow` exposes the extension field as `Self::EF` and `combine_ef([F;4])
//! -> EF`, and `add_constraint<G>` accepts an EF-valued constraint. A QM31 value
//! is 4 witnessed M31 columns lifted via `combine_ef` (degree-1 in the masks), so:
//!   out = a·b      → witness out[4], constrain `out − a·b == 0` (degree 2)
//!   inv = a⁻¹      → witness inv[4], constrain `a·inv − 1 == 0` (degree 2)
//! Each is a single EF constraint at `LOG_CONSTRAINT_DEGREE_BOUND=1`. No
//! hand-derived multiplication formula is needed — the framework's EF type does
//! the extension arithmetic; we only witness the result and assert equality.
//!
//! GREEN here = QM31 mul + inverse relations prove+verify through the lifted
//! protocol, and a corrupted product is rejected. Establishes the QM31-in-
//! constraints convention the FRI-fold / OODS chips build on.
//!
//! Run: `cargo test -p zkpvm --test qm31_constraints -- --nocapture`

use num_traits::{One, Zero};
use stwo::core::air::Component;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::core::verifier::verify;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

/// Columns per row: a[4], b[4], out=a·b [4], inv=a⁻¹ [4].
const N_COLS: usize = 16;

#[derive(Clone)]
struct Qm31Eval {
    log_n_rows: u32,
}

impl FrameworkEval for Qm31Eval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        // QM31 mul/inverse are degree-2 in the witnessed M31 coords.
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let a_arr: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let b_arr: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let out_arr: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let inv_arr: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());

        let a = E::combine_ef(a_arr);
        let b = E::combine_ef(b_arr);
        let out = E::combine_ef(out_arr);
        let inv = E::combine_ef(inv_arr);

        // out == a · b
        eval.add_constraint(out - a.clone() * b);
        // a · a⁻¹ == 1
        eval.add_constraint(a * inv - E::EF::one());
        eval
    }
}

fn gen_cols(log_size: u32) -> Vec<Col<CpuBackend, BaseField>> {
    let n_rows = 1usize << log_size;
    let mut trace: Vec<Col<CpuBackend, BaseField>> = (0..N_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n_rows))
        .collect();
    for row in 0..n_rows {
        // `a` is nonzero (a[0] = row+1) so it is invertible.
        let a = SecureField::from_m31_array([
            BaseField::from_u32_unchecked(row as u32 + 1),
            BaseField::from_u32_unchecked(row as u32 + 7),
            BaseField::from_u32_unchecked(row as u32 + 13),
            BaseField::from_u32_unchecked(row as u32 + 23),
        ]);
        let b = SecureField::from_m31_array([
            BaseField::from_u32_unchecked(row as u32 + 2),
            BaseField::from_u32_unchecked(row as u32 + 3),
            BaseField::from_u32_unchecked(row as u32 + 5),
            BaseField::from_u32_unchecked(row as u32 + 11),
        ]);
        let out = a * b;
        let inv = a.inverse();
        let vals: Vec<BaseField> = a
            .to_m31_array()
            .into_iter()
            .chain(b.to_m31_array())
            .chain(out.to_m31_array())
            .chain(inv.to_m31_array())
            .collect();
        for (c, v) in vals.into_iter().enumerate() {
            trace[c].set(row, v);
        }
    }
    trace
}

fn wrap_cols(
    cols: Vec<Col<CpuBackend, BaseField>>,
    log_size: u32,
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let domain = CanonicCoset::new(log_size).circle_domain();
    cols.into_iter()
        .map(|col| CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, col))
        .collect()
}

#[test]
fn qm31_mul_inverse_constraints() {
    const LOG_N_ROWS: u32 = 5;
    let config = PcsConfig::default();

    let prove_once = |trace: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>| {
        let twiddles = CpuBackend::precompute_twiddles(
            CanonicCoset::new(LOG_N_ROWS + 1 + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );
        let channel = &mut Blake2sM31Channel::default();
        let mut cs =
            CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
        let mut tb = cs.tree_builder();
        tb.extend_evals(Vec::new());
        tb.commit(channel);
        let mut tb = cs.tree_builder();
        tb.extend_evals(trace);
        tb.commit(channel);
        let component = FrameworkComponent::<Qm31Eval>::new(
            &mut TraceLocationAllocator::default(),
            Qm31Eval {
                log_n_rows: LOG_N_ROWS,
            },
            SecureField::zero(),
        );
        let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, cs);
        (component, proof)
    };

    // Positive.
    let (component, proof) = prove_once(wrap_cols(gen_cols(LOG_N_ROWS), LOG_N_ROWS));
    let proof = proof.expect("prove QM31 mul/inverse constraints (lifted)");
    let channel = &mut Blake2sM31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    vs.commit(proof.commitments[0], &sizes[0], channel);
    vs.commit(proof.commitments[1], &sizes[1], channel);
    verify(&[&component], channel, &mut vs, proof).expect("verify QM31 constraints");

    // Negative: corrupt one coordinate of the product `out` (col 8) → out != a·b.
    let mut bad = gen_cols(LOG_N_ROWS);
    let orig = bad[8].at(0);
    bad[8].set(0, orig + BaseField::one());
    let (bad_c, bad_p) = prove_once(wrap_cols(bad, LOG_N_ROWS));
    let rejected = match bad_p {
        Err(_) => true,
        Ok(p) => {
            let ch = &mut Blake2sM31Channel::default();
            let mut vs = CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
            let sizes = bad_c.trace_log_degree_bounds();
            vs.commit(p.commitments[0], &sizes[0], ch);
            vs.commit(p.commitments[1], &sizes[1], ch);
            verify(&[&bad_c], ch, &mut vs, p).is_err()
        }
    };
    assert!(rejected, "a corrupted QM31 product must be rejected");

    eprintln!(
        "qm31_mul_inverse_constraints GREEN: explicit QM31 mul + inverse constrained in-AIR \
         (4×M31, degree-2 via combine_ef) prove+verify through the lifted protocol; corrupted \
         product rejected. The QM31-in-constraints idiom for FriFold/OODS holds."
    );
}
