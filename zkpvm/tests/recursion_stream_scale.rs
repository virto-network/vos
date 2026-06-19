//! Recursion build P5.3 — STREAMED OODS-embed layout, scale measurement.
//!
//! The P5.3 layout (recursion-p5.md P5.3 block): the 31-component OODS embed is
//! ~40150 QM31 nodes (mask samples + aux + witnessed products) folded into one
//! Horner accumulator. The proven single-row layout commits them all as WIDTH
//! (160600 M31 cols) — replicating that across the channel's ~16384 rows OOMs. The
//! streamed layout DISTRIBUTES the nodes down the rows: each row computes a bundle
//! of `L` witnessed products + `L` Horner-fold steps, the accumulator chained
//! across rows (the offset viability spike proved cross-row offsets work). Rows ≈
//! 40150 / L, width ≈ L · (a few QM31). This file MEASURES that streamed shape at
//! the embed's scale, so the design can pick `L` (ops/row) vs the row count (which
//! must stay ≤ the channel's log to share its rows).
//!
//! The AIR is representative of the embed's structure — a cross-row Horner whose
//! per-row contributions are WITNESSED QM31 products — at a configurable density,
//! NOT the real chip constraints (that is the general `OodsEval` streaming refactor
//! this measurement de-risks). It proves+verifies through the lifted Poseidon2-M31
//! protocol and matches a host-computed composition value.
//!
//! Fast gate (default suite): `assert_constraints` at log 6.
//! Heavy measurement (`#[ignore]`, release): prove+verify at the embed scale.
//! Run: `cargo test -p zkpvm --release --test recursion_stream_scale -- --ignored --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::{P2MerkleChannel, Poseidon2M31Channel, mobile_config};
use stwo::core::air::Component;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::verifier::verify;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, ORIGINAL_TRACE_IDX, TraceLocationAllocator,
    assert_constraints_on_trace, preprocessed_columns::PreProcessedColumnId,
};

/// Ops (witnessed product + Horner fold) per row — the embed-density knob.
const L: usize = 3;

const IS_FIRST: &str = "stream_is_first";
const NOT_LAST: &str = "stream_not_last";
const IS_LAST: &str = "stream_is_last";

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

/// A fixed `rc` (the Horner base, the composition `random_coeff` analog).
fn rc_oracle() -> SecureField {
    SecureField::from_u32_unchecked(0x4321, 0x1234, 7, 9)
}

// ───────────────────────────────────────────────────────────────────────────
// The streamed AIR: a cross-row Horner of L witnessed QM31 products per row.
// ───────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct StreamEval {
    log_n_rows: u32,
    comp: SecureField, // host-computed final accumulator (a public input)
}

impl FrameworkEval for StreamEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_first = eval.get_preprocessed_column(PreProcessedColumnId {
            id: IS_FIRST.to_string(),
        });
        let not_last = eval.get_preprocessed_column(PreProcessedColumnId {
            id: NOT_LAST.to_string(),
        });
        let is_last = eval.get_preprocessed_column(PreProcessedColumnId {
            id: IS_LAST.to_string(),
        });

        // Lift a base selector to the extension field (for EF-valued gated
        // constraints): combine_ef([f,0,0,0]) — degree-preserving.
        let lift =
            |f: E::F| -> E::EF { E::combine_ef([f, E::F::zero(), E::F::zero(), E::F::zero()]) };
        let read4 = |eval: &mut E| -> [E::F; 4] { std::array::from_fn(|_| eval.next_trace_mask()) };
        // acc_in / rc read across rows: [cur, next].
        let acc_in: [[E::F; 2]; 4] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
        let rc: [[E::F; 2]; 4] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
        let acc_in_cur = E::combine_ef(std::array::from_fn(|c| acc_in[c][0].clone()));
        let acc_in_next = E::combine_ef(std::array::from_fn(|c| acc_in[c][1].clone()));
        let rc_cur = E::combine_ef(std::array::from_fn(|c| rc[c][0].clone()));
        let rc_next = E::combine_ef(std::array::from_fn(|c| rc[c][1].clone()));

        // rc held constant across rows + bound at row 0 to the oracle constant.
        eval.add_constraint(lift(not_last.clone()) * (rc_next - rc_cur.clone()));
        for (c, rc_c) in rc.iter().enumerate() {
            eval.add_constraint(
                is_first.clone() * (rc_c[0].clone() - E::F::from(rc_oracle().to_m31_array()[c])),
            );
        }
        // acc_in anchored to 0 at row 0 (the Horner starts fresh).
        for acc_c in acc_in.iter() {
            eval.add_constraint(is_first.clone() * acc_c[0].clone());
        }

        // The L-lane bundle: each lane is a witnessed product folded into the acc.
        let mut acc = acc_in_cur;
        for _ in 0..L {
            let inp = E::combine_ef(read4(&mut eval));
            let t = E::combine_ef(read4(&mut eval));
            let w = E::combine_ef(read4(&mut eval));
            let m = E::combine_ef(read4(&mut eval));
            let partial = E::combine_ef(read4(&mut eval));
            // w = inp · t  (the witnessed product = this lane's constraint value).
            eval.add_constraint(w.clone() - inp * t);
            // m = acc · rc  (the Horner multiply, witnessed).
            eval.add_constraint(m.clone() - acc * rc_cur.clone());
            // partial = m + w  (the Horner add).
            eval.add_constraint(partial.clone() - (m + w));
            acc = partial;
        }
        // acc is now acc_out. Chain it into the next row's acc_in; bind the last.
        eval.add_constraint(lift(not_last.clone()) * (acc_in_next - acc.clone()));
        eval.add_constraint(lift(is_last) * (acc - E::EF::from(self.comp)));
        eval
    }
}

const fn main_cols() -> usize {
    4 /* acc_in */ + 4 /* rc */ + L * (4 * 5)
}

struct StreamTrace {
    preprocessed: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    main: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    comp: SecureField,
    log_size: u32,
}

/// Host-fill the streamed Horner; returns the trace + the final composition value.
fn gen_trace(log_size: u32, tamper: Option<usize>) -> StreamTrace {
    let n = 1usize << log_size;
    let rc = rc_oracle();
    let mut main: Vec<Vec<BaseField>> = vec![vec![BaseField::zero(); n]; main_cols()];
    let mut is_first = vec![BaseField::zero(); n];
    let mut not_last = vec![BaseField::zero(); n];
    let mut is_last = vec![BaseField::zero(); n];

    let mut acc_in = SecureField::zero();
    let mut comp = SecureField::zero();

    // A cheap deterministic value stream (no Math.random in this env): a small LCG.
    let mut seed = 0x1234_5678u64;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let a = (seed >> 33) as u32;
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let b = (seed >> 33) as u32;
        SecureField::from_u32_unchecked(a, b, a ^ 0x55, b ^ 0xAA)
    };

    for row in 0..n {
        let s = storage_index(row, log_size);

        // acc_in column (cur). The "next" sample is read from row+1's acc_in by the
        // framework's [0,1] offset, so we only fill the cur value here.
        let mut col = 0usize;
        let put4 = |main: &mut Vec<Vec<BaseField>>, q: SecureField, col: &mut usize, s: usize| {
            for v in q.to_m31_array() {
                main[*col][s] = v;
                *col += 1;
            }
        };
        put4(&mut main, acc_in, &mut col, s);
        put4(&mut main, rc, &mut col, s);

        let mut acc = acc_in;
        for _ in 0..L {
            let inp = next();
            let t = next();
            let w = inp * t;
            let m = acc * rc;
            let partial = m + w;
            put4(&mut main, inp, &mut col, s);
            put4(&mut main, t, &mut col, s);
            put4(&mut main, w, &mut col, s);
            put4(&mut main, m, &mut col, s);
            put4(&mut main, partial, &mut col, s);
            acc = partial;
        }
        debug_assert_eq!(col, main_cols());

        if row == 0 {
            is_first[s] = BaseField::one();
        }
        not_last[s] = if row == n - 1 {
            BaseField::zero()
        } else {
            BaseField::one()
        };
        if row == n - 1 {
            is_last[s] = BaseField::one();
            comp = acc;
        }
        acc_in = acc; // next row's starting acc
    }

    if let Some(c) = tamper {
        let s0 = storage_index(0, log_size);
        let orig = main[c][s0];
        main[c][s0] = orig + BaseField::one();
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    let wrap = |col: Vec<BaseField>| {
        let mut c = Col::<CpuBackend, BaseField>::zeros(n);
        for (i, v) in col.into_iter().enumerate() {
            c.set(i, v);
        }
        CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, c)
    };
    StreamTrace {
        preprocessed: vec![wrap(is_first), wrap(not_last), wrap(is_last)],
        main: main.into_iter().map(wrap).collect(),
        comp,
        log_size,
    }
}

fn alloc() -> TraceLocationAllocator {
    TraceLocationAllocator::new_with_preprocessed_columns(&[
        PreProcessedColumnId {
            id: IS_FIRST.to_string(),
        },
        PreProcessedColumnId {
            id: NOT_LAST.to_string(),
        },
        PreProcessedColumnId {
            id: IS_LAST.to_string(),
        },
    ])
}

fn prove_and_verify(trace: StreamTrace) -> Result<(), String> {
    let config = mobile_config();
    let log_size = trace.log_size;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
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

    let component = FrameworkComponent::<StreamEval>::new(
        &mut alloc(),
        StreamEval {
            log_n_rows: log_size,
            comp: trace.comp,
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

/// FAST: the streamed trace satisfies the AIR (AssertEvaluator), at log 6.
#[test]
fn stream_scale_air_satisfied() {
    use stwo::core::fields::m31::M31;
    let log_size = 6;
    let trace = gen_trace(log_size, None);
    let pre: Vec<Vec<M31>> = trace
        .preprocessed
        .iter()
        .map(|e| e.values.to_cpu())
        .collect();
    let main: Vec<Vec<M31>> = trace.main.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> =
        TreeVec::new(vec![pre.iter().collect(), main.iter().collect(), vec![]]);
    let comp = trace.comp;
    assert_constraints_on_trace(
        &tv,
        log_size,
        |e| {
            StreamEval {
                log_n_rows: log_size,
                comp,
            }
            .evaluate(e);
        },
        SecureField::zero(),
    );
    eprintln!(
        "stream_scale_air_satisfied: streamed Horner of {} witnessed QM31 products/row over \
         {} rows (log {log_size}) satisfies the AIR; {} main M31 cols.",
        L,
        1 << log_size,
        main_cols(),
    );
}

/// THE MEASUREMENT (heavy): prove+verify the streamed embed at the canonical
/// node scale and report the shape; a tampered column is rejected.
#[test]
#[ignore = "heavy: streamed embed at canonical node scale (release)"]
fn stream_scale_gate() {
    // log 14 × L=3 = 49152 nodes ≈ the embed's ~40150; the channel is also ~log 14,
    // so this is the row count the streamed embed must share with it.
    let log_size = 14;
    let n_nodes = L * (1usize << log_size);

    prove_and_verify(gen_trace(log_size, None)).expect("honest streamed embed must prove+verify");
    assert!(
        prove_and_verify(gen_trace(log_size, Some(0))).is_err(),
        "a tampered committed column must be rejected"
    );

    eprintln!(
        "stream_scale_gate GREEN @ log_size {log_size}, L={L}: a streamed cross-row Horner of \
         {n_nodes} witnessed QM31 products proves+verifies through the lifted Poseidon2-M31 \
         protocol; {} main M31 cols/row; a tampered column is rejected. This is the streamed \
         OODS-embed shape at the canonical node scale (≈40150) — measure the prove time + peak \
         memory from this run to confirm the streamed layout is tractable and pick L vs rows.",
        main_cols(),
    );
}
