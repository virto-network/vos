//! Recursion build P5.2a — de-risk the **auto-witnessing OODS evaluator** on the
//! small inner AIR (`a·b == out`, `a·a⁻¹ == 1`) before scaling to CpuChip.
//!
//! `oods_composition_chip.rs` (GATE 4) re-evaluates this same inner AIR's OODS
//! composition in-AIR with a **hand-written** witnessed-product chip. This gate
//! proves the *automation*: driving the inner AIR's own generic `evaluate<E>`
//! through [`recursion_common::oods_auto`] re-derives the identical witnessing —
//! five degree-2 products (`a·b`, `a·inv`, the Horner `acc·rc`, the denominator
//! scaling `dinv·acc`, and the composition recombination `ox·right`) over 32
//! committed QM31 columns — with no hand-port.
//!
//! GREEN GATE:
//!   * the recorder re-derives the same witnessing structure (5 products, 32
//!     QM31 columns) the hand-written chip uses;
//!   * the in-AIR composition value matches stwo's own
//!     `eval_composition_polynomial_at_point` (the verifier's DEEP-ALI ground
//!     truth);
//!   * the auto-generated join AIR proves+verifies at degree ≤ 2 through the
//!     lifted Poseidon2-M31 protocol, and a perturbed committed column is
//!     rejected.
//!
//! Run: `cargo test -p zkpvm --test oods_auto_chip -- --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::oods_auto::{OodsInputs, OodsJoinEval, RecordBackend, drive};
use recursion_common::{P2MerkleChannel, P2MerkleHasher, Poseidon2M31Channel, mobile_config};
use std::cell::RefCell;
use std::rc::Rc;
use stwo::core::air::{Component, Components};
use stwo::core::channel::Channel;
use stwo::core::circle::CirclePoint;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::{BaseField, M31};
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::utils::try_get_lifting_log_size;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::verifier::{COMPOSITION_LOG_SPLIT, verify};
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
    assert_constraints_on_trace,
};

// ── The inner AIR whose composition we re-evaluate (16 cols, 2 constraints) ─
//
// Identical to GATE 4's `InnerQm31Eval`: this is the shape each of the 31
// canonical components contributes, and the chip whose `evaluate` the
// auto-witnessing evaluator walks unchanged.

#[derive(Clone)]
struct InnerQm31Eval {
    log_n_rows: u32,
}
impl FrameworkEval for InnerQm31Eval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let a: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let b: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let out: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let inv: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let a = E::combine_ef(a);
        let b = E::combine_ef(b);
        let out = E::combine_ef(out);
        let inv = E::combine_ef(inv);
        eval.add_constraint(out - a.clone() * b); // c0
        eval.add_constraint(a * inv - E::EF::one()); // c1
        eval
    }
}

const INNER_LOG: u32 = 5;
const INNER_MAIN_COLS: usize = 16;
const N_COMPOSITION_COLS: usize = 2 * SECURE_EXTENSION_DEGREE; // 8

fn inner_trace() -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let n = 1usize << INNER_LOG;
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..INNER_MAIN_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    for row in 0..n {
        let a = SecureField::from_m31_array([
            BaseField::from(row as u32 + 1),
            BaseField::from(row as u32 + 7),
            BaseField::from(row as u32 + 13),
            BaseField::from(row as u32 + 23),
        ]);
        let b = SecureField::from_m31_array([
            BaseField::from(row as u32 + 2),
            BaseField::from(row as u32 + 3),
            BaseField::from(row as u32 + 5),
            BaseField::from(row as u32 + 11),
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
            cols[c].set(row, v);
        }
    }
    let domain = CanonicCoset::new(INNER_LOG).circle_domain();
    cols.into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect()
}

struct InnerProof {
    component: FrameworkComponent<InnerQm31Eval>,
    proof: stwo::core::proof::StarkProof<P2MerkleHasher>,
}

fn prove_inner(config: PcsConfig) -> InnerProof {
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(INNER_LOG + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);
    let mut tb = cs.tree_builder();
    tb.extend_evals(Vec::new());
    tb.commit(channel);
    let mut tb = cs.tree_builder();
    tb.extend_evals(inner_trace());
    tb.commit(channel);
    let component = FrameworkComponent::<InnerQm31Eval>::new(
        &mut TraceLocationAllocator::default(),
        InnerQm31Eval {
            log_n_rows: INNER_LOG,
        },
        SecureField::zero(),
    );
    let proof = prove::<CpuBackend, P2MerkleChannel>(&[&component], channel, cs)
        .expect("prove the inner AIR");
    InnerProof { component, proof }
}

// ── Extract the real OODS inputs by replicating the verifier transcript ────

/// Replicates the verifier up to the DEEP-ALI check, returning the
/// auto-evaluator's [`OodsInputs`] plus the ground-truth composition value
/// (the verifier's `eval_composition_polynomial_at_point`).
fn extract_inputs(inner: &InnerProof, config: PcsConfig) -> (OodsInputs, SecureField) {
    let component = &inner.component;
    let proof = &inner.proof;

    let channel = &mut Poseidon2M31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    vs.commit(proof.commitments[0], &sizes[0], channel); // preprocessed (empty)
    vs.commit(proof.commitments[1], &sizes[1], channel); // main

    let components = Components {
        components: vec![component as &dyn Component],
        n_preprocessed_columns: 0,
    };
    let split = components.composition_log_degree_bound() - COMPOSITION_LOG_SPLIT;
    let lifting_log_size =
        try_get_lifting_log_size(&config, split + config.fri_config.log_blowup_factor).unwrap();
    let mlbd = lifting_log_size - config.fri_config.log_blowup_factor;

    let random_coeff = channel.draw_secure_felt();
    vs.commit(
        *proof.commitments.last().unwrap(),
        &[mlbd; N_COMPOSITION_COLS],
        channel,
    ); // composition
    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

    let comp_mask = proof.sampled_values.last().unwrap();
    let comp: [SecureField; N_COMPOSITION_COLS] = std::array::from_fn(|i| comp_mask[i][0]);

    // The verifier's own DEEP-ALI ground truth.
    let composition_value = components.eval_composition_polynomial_at_point(
        oods_point,
        &proof.sampled_values,
        random_coeff,
        mlbd,
    );

    let denom_inverse = coset_vanishing(CanonicCoset::new(mlbd).coset, oods_point).inverse();
    let oods_x_doubled = oods_point.repeated_double(mlbd - 1).x;

    // The mask the chip's `evaluate` reads (preprocessed/main/composition trees);
    // the chip only reads the main tree, but the cursor indexes by interaction.
    let mask: Vec<Vec<Vec<SecureField>>> = proof.sampled_values.0.clone();

    (
        OodsInputs {
            mask,
            random_coeff,
            denom_inverse,
            oods_x_doubled,
            comp,
        },
        composition_value,
    )
}

// ── Host trace generation from the recorded column schedule ────────────────

const TRACE_LOG: u32 = 5;

/// Run the recorder, returning the ordered QM31 column schedule (the join's
/// host trace) plus the recorder for its diagnostics.
fn record(inputs: OodsInputs) -> RecordBackend {
    let chip = InnerQm31Eval {
        log_n_rows: INNER_LOG,
    };
    let ctx = Rc::new(RefCell::new(RecordBackend::new(inputs)));
    drive(&ctx, &chip);
    Rc::try_unwrap(ctx)
        .unwrap_or_else(|_| panic!("a Handle outlived the recorder walk"))
        .into_inner()
}

fn gen_trace(
    schedule: &[SecureField],
    tamper_col: Option<usize>,
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let n_cols = schedule.len() * SECURE_EXTENSION_DEGREE;
    let n = 1usize << TRACE_LOG;
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..n_cols)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    let row: Vec<BaseField> = schedule.iter().flat_map(|q| q.to_m31_array()).collect();
    for (c, v) in row.into_iter().enumerate() {
        cols[c].set(0, v);
    }
    if let Some(c) = tamper_col {
        let orig = cols[c].at(0);
        cols[c].set(0, orig + BaseField::one());
    }
    let domain = CanonicCoset::new(TRACE_LOG).circle_domain();
    cols.into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect()
}

fn prove_and_verify(schedule: &[SecureField], tamper_col: Option<usize>) -> Result<(), String> {
    let config = mobile_config();
    let trace = gen_trace(schedule, tamper_col);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(TRACE_LOG + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let join = OodsJoinEval {
        chip: InnerQm31Eval {
            log_n_rows: INNER_LOG,
        },
        log_size: TRACE_LOG,
    };
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);
    let mut tb = cs.tree_builder();
    tb.extend_evals(Vec::new());
    tb.commit(channel);
    let mut tb = cs.tree_builder();
    tb.extend_evals(trace);
    tb.commit(channel);
    let component = FrameworkComponent::<OodsJoinEval<InnerQm31Eval>>::new(
        &mut TraceLocationAllocator::default(),
        join,
        SecureField::zero(),
    );
    let proof = prove::<CpuBackend, P2MerkleChannel>(&[&component], channel, cs)
        .map_err(|e| format!("prove: {e:?}"))?;

    let vch = &mut Poseidon2M31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    vs.commit(proof.commitments[0], &sizes[0], vch);
    vs.commit(proof.commitments[1], &sizes[1], vch);
    verify(&[&component as &dyn Component], vch, &mut vs, proof)
        .map_err(|e| format!("verify: {e:?}"))
}

// ── Gates ──────────────────────────────────────────────────────────────────

/// FAST: the recorder re-derives the expected witnessing structure and matches
/// stwo's composition ground truth; the generated trace drives `AssertEvaluator`.
#[test]
fn oods_auto_air_satisfied() {
    let config = mobile_config();
    let inner = prove_inner(config);
    let (inputs, composition_value) = extract_inputs(&inner, config);

    let rec = record(inputs);

    // The five degree-2 products the hand-written GATE 4 chip witnesses:
    //   a·b, a·inv, the Horner acc·rc, dinv·acc, ox·right.
    assert_eq!(rec.witnessed, 5, "auto-derived witnessed-product count");
    // 16 main samples + 8 composition samples + rc + dinv + ox + 5 witnesses.
    assert_eq!(
        rec.schedule.len(),
        32,
        "auto-derived committed QM31 column count"
    );

    // The in-AIR composition value matches the verifier's DEEP-ALI ground truth.
    let lhs = rec.final_lhs.expect("final equality discharged");
    let rhs = rec.final_rhs.expect("final equality discharged");
    assert_eq!(lhs, rhs, "recorder's comp == recombined composition mask");
    assert_eq!(
        lhs, composition_value,
        "recorder's composition value == eval_composition_polynomial_at_point"
    );

    // Drive the auto-generated join AIR through AssertEvaluator.
    let trace = gen_trace(&rec.schedule, None);
    let main: Vec<Vec<M31>> = trace.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], main.iter().collect(), vec![]]);
    let join = OodsJoinEval {
        chip: InnerQm31Eval {
            log_n_rows: INNER_LOG,
        },
        log_size: TRACE_LOG,
    };
    assert_constraints_on_trace(
        &tv,
        TRACE_LOG,
        |e| {
            join.evaluate(e);
        },
        SecureField::zero(),
    );

    eprintln!(
        "oods_auto_air_satisfied: auto-witnessing evaluator re-derived 5 products / \
         32 QM31 columns; composition value {composition_value:?} matches \
         eval_composition; trace satisfies the auto-generated AIR."
    );
}

/// THE GATE: the auto-generated OODS join AIR proves+verifies through the lifted
/// Poseidon2-M31 protocol, and a perturbed committed column is rejected.
#[test]
fn oods_auto_gate() {
    let config = mobile_config();
    let inner = prove_inner(config);
    let (inputs, _composition_value) = extract_inputs(&inner, config);
    let rec = record(inputs);

    prove_and_verify(&rec.schedule, None).expect("honest OODS re-eval must prove+verify");

    // The column schedule (QM31 indices): rc · 16 samples · {ab, a_inv, t} · dinv ·
    // comp · 8 composition-mask · ox · oxr. Perturb the first composition-mask
    // sample (a LHS recombination input) ⇒ the re-evaluated RHS no longer matches
    // ⇒ the DEEP-ALI equality rejects.
    let first_comp_mask = 1 + INNER_MAIN_COLS + 3 + 1 + 1; // == 22
    let comp0_col = first_comp_mask * SECURE_EXTENSION_DEGREE;
    assert!(
        prove_and_verify(&rec.schedule, Some(comp0_col)).is_err(),
        "a perturbed committed column must be rejected"
    );

    eprintln!(
        "oods_auto_gate GREEN: the auto-witnessing OODS evaluator's join AIR \
         (driven from the inner AIR's own evaluate, no hand-port) proves+verifies \
         at degree ≤ 2 through the lifted Poseidon2-M31 protocol; a perturbed \
         committed column is rejected."
    );
}
