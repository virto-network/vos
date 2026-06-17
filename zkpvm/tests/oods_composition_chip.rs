//! Recursion build P3 — the **OodsCompositionChip**: re-evaluate the inner AIR's
//! composition at the OODS point, in-AIR.
//!
//! The stwo verifier's DEEP-ALI check (`core/verifier.rs:111-120`) is the equality
//!
//! ```text
//!   composition_oods_eval  ==  eval_composition_polynomial_at_point(
//!                                  oods_point, sampled_values, random_coeff, …)
//! ```
//!
//! The RHS re-evaluates EVERY inner-AIR constraint at the sampled OODS mask
//! values, Horner-combines them with `random_coeff`, and scales by the
//! OODS-point vanishing-quotient denominator `denom_inverse`. The LHS recombines
//! the composition mask into one value. The OodsCompositionChip arithmetizes this
//! equality in-AIR (QM31-over-4×M31, the `qm31_constraints.rs`/`fri_fold_chip.rs`
//! idiom).
//!
//! This gate demonstrates the mechanism faithfully on a real, small inner AIR
//! (`a·b == out`, `a·a⁻¹ == 1`), the same shape every one of the 31 canonical
//! components contributes to the full verifier-AIR. For each, the chip:
//!   * combines each main column's 4 OODS coordinate-evals into its QM31 mask
//!     value (`combine_ef`), then the inner AIR's masks via `from_partial_evals`
//!     (a linear EF combine);
//!   * re-evaluates the inner constraints `c0 = out − a·b`, `c1 = a·inv − 1`;
//!   * forms `rhs = denom_inverse · (random_coeff·c0 + c1)` (the accumulator's
//!     Horner recurrence);
//!   * recombines the composition mask `lhs = left + oods_x_doubled · right`;
//!   * asserts `rhs == lhs`.
//! All QM31 muls are witnessed (degree ≤ 2).
//!
//! GREEN GATE: the OODS data is EXTRACTED from a real inner proof (by replicating
//! the verifier's transcript to draw `random_coeff`/`oods_point`, then reading the
//! proof's `sampled_values`), the in-AIR re-evaluation matches the proof's
//! composition value, proves+verifies through the lifted Poseidon2-M31 protocol,
//! and a perturbed sampled value is rejected.
//!
//! Run: `cargo test -p zkpvm --test oods_composition_chip -- --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::{P2MerkleChannel, Poseidon2M31Channel, mobile_config};
use stwo::core::air::{Component, Components};
use stwo::core::channel::Channel;
use stwo::core::circle::CirclePoint;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::utils::try_get_lifting_log_size;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::verifier::{COMPOSITION_LOG_SPLIT, verify};
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

// ── The inner AIR whose composition we re-evaluate (16 cols, 2 constraints) ─

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
const N_COMPOSITION_COLS: usize = 8; // 2 * SECURE_EXTENSION_DEGREE

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
    proof: stwo::core::proof::StarkProof<recursion_common::P2MerkleHasher>,
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

// ── Extract the real OODS data by replicating the verifier transcript ──────

struct OodsData {
    s: [SecureField; INNER_MAIN_COLS], // main-trace OODS samples (one QM31 / column)
    comp: [SecureField; N_COMPOSITION_COLS], // composition mask samples
    random_coeff: SecureField,
    denom_inverse: SecureField,
    oods_x_doubled: SecureField, // oods_point.repeated_double(mlbd-1).x
    composition_value: SecureField, // the proof's composition_oods_eval (LHS)
}

/// Replicates `verify_ex` up to (and including) the OODS DEEP-ALI check, returning
/// the intermediate values the OodsCompositionChip re-derives. Also asserts the
/// verifier's own equality (`composition_oods_eval == eval_composition_…`) and
/// that the chip's closed form reproduces it.
fn extract_oods(inner: &InnerProof, config: PcsConfig) -> OodsData {
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

    // LHS — replicate `extract_composition_oods_eval` (pub(crate) in stwo).
    let comp_mask = proof.sampled_values.last().unwrap();
    let comp: [SecureField; N_COMPOSITION_COLS] = std::array::from_fn(|i| comp_mask[i][0]);
    let left = SecureField::from_partial_evals([comp[0], comp[1], comp[2], comp[3]]);
    let right = SecureField::from_partial_evals([comp[4], comp[5], comp[6], comp[7]]);
    let oods_x_doubled = oods_point.repeated_double(mlbd - 1).x;
    let composition_value = left + oods_x_doubled * right;

    // The verifier's own DEEP-ALI equality (the ground truth).
    let rhs = components.eval_composition_polynomial_at_point(
        oods_point,
        &proof.sampled_values,
        random_coeff,
        mlbd,
    );
    assert_eq!(
        composition_value, rhs,
        "extracted composition value must equal eval_composition (the verifier's check)"
    );

    let s: [SecureField; INNER_MAIN_COLS] = std::array::from_fn(|i| proof.sampled_values[1][i][0]);
    let denom_inverse = coset_vanishing(CanonicCoset::new(mlbd).coset, oods_point).inverse();

    // The chip's closed form must reproduce the same value.
    let a = SecureField::from_partial_evals([s[0], s[1], s[2], s[3]]);
    let b = SecureField::from_partial_evals([s[4], s[5], s[6], s[7]]);
    let out = SecureField::from_partial_evals([s[8], s[9], s[10], s[11]]);
    let inv = SecureField::from_partial_evals([s[12], s[13], s[14], s[15]]);
    let c0 = out - a * b;
    let c1 = a * inv - SecureField::one();
    let my_rhs = denom_inverse * (random_coeff * c0 + c1);
    assert_eq!(
        my_rhs, composition_value,
        "the chip's closed-form OODS re-eval must match the proof's composition value"
    );

    OodsData {
        s,
        comp,
        random_coeff,
        denom_inverse,
        oods_x_doubled,
        composition_value,
    }
}

// ── The OodsCompositionChip AIR ────────────────────────────────────────────

/// Column groups (each QM31 = 4 M31), in [`OodsCompositionEval::evaluate`] order:
/// s[16] · comp[8] · random_coeff · denom_inverse · oods_x_doubled ·
/// (witnessed) ab · a_inv · t · p · oxr.
const N_QM31: usize = INNER_MAIN_COLS + N_COMPOSITION_COLS + 3 + 5;
const N_COLS: usize = N_QM31 * 4;

#[derive(Clone)]
struct OodsCompositionEval {
    log_n_rows: u32,
}

impl FrameworkEval for OodsCompositionEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let read_ef = |eval: &mut E| -> E::EF {
            let m: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
            E::combine_ef(m)
        };

        let s: [E::EF; INNER_MAIN_COLS] = std::array::from_fn(|_| read_ef(&mut eval));
        let comp: [E::EF; N_COMPOSITION_COLS] = std::array::from_fn(|_| read_ef(&mut eval));
        let rc = read_ef(&mut eval);
        let dinv = read_ef(&mut eval);
        let ox = read_ef(&mut eval);
        let ab = read_ef(&mut eval);
        let a_inv = read_ef(&mut eval);
        let t = read_ef(&mut eval);
        let p = read_ef(&mut eval);
        let oxr = read_ef(&mut eval);

        // QM31 basis units for `from_partial_evals` (combine 4 QM31 coordinate
        // evals into one EF mask value — a linear EF combine).
        let u1 = E::EF::from(SecureField::from_m31_array(
            [0u32, 1, 0, 0].map(BaseField::from),
        ));
        let u2 = E::EF::from(SecureField::from_m31_array(
            [0u32, 0, 1, 0].map(BaseField::from),
        ));
        let u3 = E::EF::from(SecureField::from_m31_array(
            [0u32, 0, 0, 1].map(BaseField::from),
        ));
        let partial = |q: [E::EF; 4]| -> E::EF {
            q[0].clone()
                + q[1].clone() * u1.clone()
                + q[2].clone() * u2.clone()
                + q[3].clone() * u3.clone()
        };

        let a = partial([s[0].clone(), s[1].clone(), s[2].clone(), s[3].clone()]);
        let b = partial([s[4].clone(), s[5].clone(), s[6].clone(), s[7].clone()]);
        let out = partial([s[8].clone(), s[9].clone(), s[10].clone(), s[11].clone()]);
        let inv = partial([s[12].clone(), s[13].clone(), s[14].clone(), s[15].clone()]);

        // Witnessed QM31 products (degree-2 each): ab = a·b, a_inv = a·inv.
        eval.add_constraint(ab.clone() - a.clone() * b);
        eval.add_constraint(a_inv.clone() - a * inv);

        // Inner-AIR constraints at the OODS samples (c0 added first ⇒ higher
        // Horner power, matching the accumulator's add order).
        let c0 = out - ab;
        let c1 = a_inv - E::EF::from(SecureField::one());

        eval.add_constraint(t.clone() - rc * c0);
        let inner = t + c1;
        eval.add_constraint(p.clone() - dinv * inner);

        // LHS recombination of the composition mask.
        let left = partial([
            comp[0].clone(),
            comp[1].clone(),
            comp[2].clone(),
            comp[3].clone(),
        ]);
        let right = partial([
            comp[4].clone(),
            comp[5].clone(),
            comp[6].clone(),
            comp[7].clone(),
        ]);
        eval.add_constraint(oxr.clone() - ox * right);
        let lhs = left + oxr;

        // The DEEP-ALI equality the verifier checks.
        eval.add_constraint(p - lhs);

        eval
    }
}

// ── Host trace generation from the extracted OODS data ─────────────────────

/// Witnessed-product values the chip needs, computed host-side from `OodsData`.
fn oods_row_values(d: &OodsData) -> Vec<BaseField> {
    let a = SecureField::from_partial_evals([d.s[0], d.s[1], d.s[2], d.s[3]]);
    let b = SecureField::from_partial_evals([d.s[4], d.s[5], d.s[6], d.s[7]]);
    let out = SecureField::from_partial_evals([d.s[8], d.s[9], d.s[10], d.s[11]]);
    let inv = SecureField::from_partial_evals([d.s[12], d.s[13], d.s[14], d.s[15]]);
    let ab = a * b;
    let a_inv = a * inv;
    let c0 = out - ab;
    let c1 = a_inv - SecureField::one();
    let t = d.random_coeff * c0;
    let inner = t + c1;
    let p = d.denom_inverse * inner;
    let right = SecureField::from_partial_evals([d.comp[4], d.comp[5], d.comp[6], d.comp[7]]);
    let oxr = d.oods_x_doubled * right;

    let mut row: Vec<BaseField> = Vec::with_capacity(N_COLS);
    for q in d.s.iter().chain(d.comp.iter()).copied().chain([
        d.random_coeff,
        d.denom_inverse,
        d.oods_x_doubled,
        ab,
        a_inv,
        t,
        p,
        oxr,
    ]) {
        row.extend(q.to_m31_array());
    }
    debug_assert_eq!(row.len(), N_COLS);
    row
}

const TRACE_LOG: u32 = 5;

fn gen_trace(
    d: &OodsData,
    tamper_col: Option<usize>,
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let n = 1usize << TRACE_LOG;
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..N_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    let row = oods_row_values(d);
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

fn prove_and_verify_oods(d: &OodsData, tamper_col: Option<usize>) -> Result<(), String> {
    let config = mobile_config();
    let trace = gen_trace(d, tamper_col);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(TRACE_LOG + 1 + config.fri_config.log_blowup_factor)
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
    let component = FrameworkComponent::<OodsCompositionEval>::new(
        &mut TraceLocationAllocator::default(),
        OodsCompositionEval {
            log_n_rows: TRACE_LOG,
        },
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

/// FAST: the OODS re-eval trace satisfies the AIR (drives `AssertEvaluator`).
#[test]
fn oods_composition_air_satisfied() {
    use stwo::core::fields::m31::M31;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    let config = mobile_config();
    let inner = prove_inner(config);
    let d = extract_oods(&inner, config);
    let trace = gen_trace(&d, None);
    let main: Vec<Vec<M31>> = trace.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], main.iter().collect(), vec![]]);
    let eval = OodsCompositionEval {
        log_n_rows: TRACE_LOG,
    };
    assert_constraints_on_trace(
        &tv,
        TRACE_LOG,
        |e| {
            eval.evaluate(e);
        },
        SecureField::zero(),
    );
    eprintln!(
        "oods_composition_air_satisfied: real OODS data (composition value \
         {:?}) re-evaluated in-AIR; trace satisfies the AIR.",
        d.composition_value
    );
}

/// THE GATE: re-evaluate a real inner proof's OODS composition in-AIR, match the
/// proof's composition value, prove+verify through the lifted Poseidon2-M31
/// protocol, and reject a perturbed sampled value.
#[test]
fn oods_composition_gate() {
    let config = mobile_config();
    let inner = prove_inner(config);
    let d = extract_oods(&inner, config);

    prove_and_verify_oods(&d, None).expect("honest OODS re-eval must prove+verify");

    // Perturb a committed sampled value (composition mask col 0) ⇒ the LHS
    // recombination diverges from the re-evaluated RHS ⇒ rejected.
    let comp0_col = INNER_MAIN_COLS * 4; // first M31 of comp[0]
    assert!(
        prove_and_verify_oods(&d, Some(comp0_col)).is_err(),
        "a perturbed sampled value must be rejected"
    );

    eprintln!(
        "oods_composition_gate GREEN: a real inner proof's OODS composition \
         (extracted by replicating the verifier transcript) is re-evaluated in-AIR \
         and matches the proof's composition value; proves+verifies through the \
         lifted Poseidon2-M31 protocol; a perturbed sampled value is rejected."
    );
}
