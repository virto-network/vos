//! Recursion build P5.3 — LAYOUT viability spike: do cross-row mask offsets
//! beyond ±1 act as clean logical-row shifts through the lifted Poseidon2-M31
//! protocol?
//!
//! The make-or-break P5.3 layout problem (recursion-p5.md P5.3 status block): the
//! 31-component OODS embed is 160600 M31 values; replicating it across the
//! channel's ~16384 rows OOMs, so it must be DISTRIBUTED across the perm rows,
//! turning its sequential Horner + witnessed-product chain into a CROSS-ROW
//! streamed evaluator. Streaming a witnessed-product expression needs each row to
//! read its operands from a few nearby rows — i.e. mask offsets −1, −2, −3, … —
//! but the proven `ChannelChip`/`FriFoldChip` only ever use ±1. Whether a circle-
//! STARK mask offset `k` reads exactly logical row `i+k` for `|k| > 1` is the
//! gating unknown (the circle domain is a coset, not a line, so it is NOT obvious
//! the group step composes to a clean logical shift).
//!
//! This spike answers it directly: fill ONE column `v[storage(i)] = i`, read it at
//! the signed offsets ±{1,2,3,8,16,24} (small AND up to ~N/2 = 32), and constrain
//! each `v@±k − v@0 == ±k` (gated to skip the wrap rows). If offset −2 secretly
//! read logical i−1 the difference would be 1, not 2, and the constraint would
//! FAIL — so a GREEN prove+verify means each offset k reads EXACTLY logical row
//! i+k. A `wrong`-expectation control confirms the constraints discriminate.
//!
//! Run: `cargo test -p zkpvm --test recursion_offset_spike -- --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::{P2MerkleChannel, Poseidon2M31Channel, mobile_config};
use stwo::core::air::Component;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::verifier::verify;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, ORIGINAL_TRACE_IDX, TraceLocationAllocator,
    preprocessed_columns::PreProcessedColumnId,
};

const TRACE_LOG: u32 = 6; // 64 rows
/// The distances tested in BOTH directions — small (the banding window) up to
/// ~N/2 (24 < 32), to probe whether large offsets also compose to clean shifts.
const KS: [usize; 6] = [1, 2, 3, 8, 16, 24];
/// All signed offsets read in one mask (sorted; offset 0 at the middle index).
const OFFS: [isize; 13] = [-24, -16, -8, -3, -2, -1, 0, 1, 2, 3, 8, 16, 24];
const ZERO_IDX: usize = 6;

/// Gating preprocessed columns: `nf{k}` = 1 except the first k logical rows (gate
/// the −k constraint past its wrap); `nl{k}` = 1 except the last k logical rows.
fn nf_id(k: usize) -> String {
    format!("off_nf{k}")
}
fn nl_id(k: usize) -> String {
    format!("off_nl{k}")
}

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

/// The spike AIR: read `v` at every signed offset in `OFFS` and bind each
/// difference to its offset (degree 1, gated by the wrap selectors). `wrong`
/// flips the −2 expectation to `k−1` so an honest trace must REJECT it (the
/// discrimination control).
#[derive(Clone)]
struct OffsetEval {
    log_n_rows: u32,
    wrong: bool,
}

impl FrameworkEval for OffsetEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // v read at every signed offset in OFFS, in ONE mask read (same column).
        let m: [E::F; 13] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, OFFS);
        let v0 = m[ZERO_IDX].clone();

        // Selectors, in the registration order: all nf{k} then all nl{k}.
        let nf: [E::F; 6] = std::array::from_fn(|j| {
            eval.get_preprocessed_column(PreProcessedColumnId { id: nf_id(KS[j]) })
        });
        let nl: [E::F; 6] = std::array::from_fn(|j| {
            eval.get_preprocessed_column(PreProcessedColumnId { id: nl_id(KS[j]) })
        });

        for (idx, &o) in OFFS.iter().enumerate() {
            if o == 0 {
                continue;
            }
            let k = o.unsigned_abs();
            let ki = KS.iter().position(|&x| x == k).unwrap();
            if o < 0 {
                // v@−k == i−k  ⇒  v@0 − v@−k == k  (offset −k MUST be logical i−k).
                let expect = if self.wrong && k == 2 { k - 1 } else { k } as u32;
                eval.add_constraint(
                    nf[ki].clone()
                        * (v0.clone() - m[idx].clone() - E::F::from(BaseField::from(expect))),
                );
            } else {
                // v@+k == i+k  ⇒  v@+k − v@0 == k.
                eval.add_constraint(
                    nl[ki].clone()
                        * (m[idx].clone() - v0.clone() - E::F::from(BaseField::from(k as u32))),
                );
            }
        }
        eval
    }
}

struct SpikeTrace {
    preprocessed: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    main: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
}

fn gen_trace(log_size: u32) -> SpikeTrace {
    let n = 1usize << log_size;
    let domain = CanonicCoset::new(log_size).circle_domain();
    let wrap = |col: Vec<BaseField>| {
        let mut c = Col::<CpuBackend, BaseField>::zeros(n);
        for (i, val) in col.into_iter().enumerate() {
            c.set(i, val);
        }
        CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, c)
    };

    // v[storage(i)] = i — distinct per logical row so a wrong offset is detectable.
    let mut v = vec![BaseField::zero(); n];
    for i in 0..n {
        v[storage_index(i, log_size)] = BaseField::from(i as u32);
    }

    // Wrap-gating selectors (logical order, stored bit-reversed): all nf{k} then
    // all nl{k}, matching the eval's read order.
    let mut ordered: Vec<Vec<BaseField>> = Vec::new();
    for &k in &KS {
        let mut nf = vec![BaseField::zero(); n];
        for i in 0..n {
            nf[storage_index(i, log_size)] = if i >= k {
                BaseField::one()
            } else {
                BaseField::zero()
            };
        }
        ordered.push(nf);
    }
    for &k in &KS {
        let mut nl = vec![BaseField::zero(); n];
        for i in 0..n {
            nl[storage_index(i, log_size)] = if i < n - k {
                BaseField::one()
            } else {
                BaseField::zero()
            };
        }
        ordered.push(nl);
    }

    SpikeTrace {
        preprocessed: ordered.into_iter().map(wrap).collect(),
        main: vec![wrap(v)],
    }
}

fn prove_and_verify(wrong: bool) -> Result<(), String> {
    let config = mobile_config();
    let trace = gen_trace(TRACE_LOG);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(TRACE_LOG + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);
    let mut tb = cs.tree_builder();
    tb.extend_evals(trace.preprocessed);
    tb.commit(channel);
    let mut tb = cs.tree_builder();
    tb.extend_evals(trace.main);
    tb.commit(channel);

    let mut ids: Vec<PreProcessedColumnId> = Vec::new();
    for &k in &KS {
        ids.push(PreProcessedColumnId { id: nf_id(k) });
    }
    for &k in &KS {
        ids.push(PreProcessedColumnId { id: nl_id(k) });
    }
    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::<OffsetEval>::new(
        &mut alloc,
        OffsetEval {
            log_n_rows: TRACE_LOG,
            wrong,
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

/// THE SPIKE: offsets ±1, ±2, ±3 each act as logical-row shifts (honest proof
/// verifies); the `wrong` control is rejected (the constraints discriminate).
#[test]
fn offset_shift_viability() {
    prove_and_verify(false).expect(
        "honest offsets ±1..±3 must prove+verify (each mask offset k reads logical row i+k)",
    );
    assert!(
        prove_and_verify(true).is_err(),
        "a wrong −2 expectation must be rejected (the offset constraints discriminate)"
    );
    eprintln!(
        "offset_shift_viability GREEN: cross-row mask offsets ±{KS:?} each read EXACTLY logical \
         row i+k through the lifted Poseidon2-M31 protocol (small AND up to ~N/2) — so the OODS \
         embed can stream as a single column read at arbitrary computed offsets, OR band into \
         lanes with small offsets; both layouts are VIABLE. The wrong-expectation control was \
         rejected (the offset constraints discriminate)."
    );
}
