//! Recursion build P5.3 — **step 4c crux de-risk: the flat↔sorted leaf↔c logup
//! permutation in ONE uniform component.**
//!
//! The DEEP numerator's leaf term `Σ_col leaf[col]·c[col]` (step 4) couples two
//! quantities living in DIFFERENT column orders:
//!   * `c[col]` — derived from the OODS sample `v` + the DEEP `α^i` power chain,
//!     which runs in the GLOBAL FLAT (commit) column order (the `α^i` index);
//!   * `leaf[col]` — the trace-decommit chunk, streamed in the lifted Merkle leaf
//!     order = each tree's columns sorted ASCENDING by log size.
//!
//! For a real canonical segment the trace columns have MIXED log sizes
//! ([6,7,8,10,12,16]) ⇒ sorted ≠ commit, so the two orders genuinely differ and a
//! per-leaf `c` cannot be read at a fixed cross-row offset. The sound, tractable
//! bridge is a **logup permutation**: a PRODUCER presents `(col_index, c)` in flat
//! order (+1), a CONSUMER drains `(col_index, c)` in sorted order (−1) while
//! accumulating `leaf·c`, and the claimed-sum balance forces the consumer's `c`
//! at each sorted slot to equal the producer's `c` for that `col_index`
//! (Schwartz-Zippel over the relation challenge). This is the analog of step 3b's
//! co-location decision — the LAYOUT crux of step 4c — and it must work in ONE
//! uniform component (no producer/consumer split, the proven residual-bug shape).
//!
//! This gate de-risks exactly that, standalone, at small log:
//!   * ONE `FrameworkEval` emits BOTH the +1 (producer) and −1 (consumer) logup
//!     fractions, sign = a preprocessed row-type selector — the single-component
//!     self-balancing logup (cf. the per-component logup the real 31-chip segment
//!     uses), built on the `cross_chip_logup` keystone's SIMD→Cpu transplant;
//!   * `col_index` is pinned to a PREPROCESSED routing (flat order on producer
//!     rows, the fixed sorted→flat permutation on consumer rows — segment-invariant,
//!     so preprocessable);
//!   * the consumer accumulates `leaf·c` across its rows into a carry-latched `S`,
//!     bound to the host total (the stand-in for one batch's `Σ_col leaf·c` the
//!     integration feeds into `denom_inv·(cprime·S − p.y·A − B)`).
//!
//! GREEN GATE: honest prove+verify (claimed-sum balances to 0); a producer `c`
//! tamper (an unmatched `(col_index, c)` ⇒ imbalance) AND a consumer `leaf` tamper
//! (`S ≠ host total`) are each rejected.
//!
//! Run: `cargo test -p zkpvm --test recursion_deep_couple -- --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::{
    P2MerkleChannel, P2MerkleHasher, Poseidon2M31Channel, mobile_config, to_cpu,
};
use stwo::core::air::Component;
use stwo::core::channel::Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{LOG_N_LANES, PackedM31};
use stwo::prover::backend::simd::qm31::PackedQM31;
use stwo::prover::backend::{Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, ComponentProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, ORIGINAL_TRACE_IDX,
    Relation, RelationEntry, TraceLocationAllocator, preprocessed_columns::PreProcessedColumnId,
    relation,
};

// The logup tuple is (col_index, c[4]) — a column's flat index + its derived c.
const TUPLE_LEN: usize = 1 + SECURE_EXTENSION_DEGREE;
relation!(DeepCoupleRelation, TUPLE_LEN);

const N_COLS: usize = 32;
const LOG_SIZE: u32 = 6; // n = 64 ≥ 2·N_COLS, ≥ LOG_N_LANES.

// Preprocessed column ids (registration order == read order).
const IS_PROD: &str = "dc_is_prod";
const IS_CONS: &str = "dc_is_cons";
const ROUTE: &str = "dc_route";
const NOT_FIRST: &str = "dc_not_first";
const IS_LAST: &str = "dc_is_last";

fn preproc_ids() -> Vec<PreProcessedColumnId> {
    [IS_PROD, IS_CONS, ROUTE, NOT_FIRST, IS_LAST]
        .into_iter()
        .map(|id| PreProcessedColumnId { id: id.to_string() })
        .collect()
}

// Main columns: col_idx(1), c(4), leaf(1), lc(4), inc(4), S(4).
const N_MAIN: usize = 1 + 4 + 1 + 4 + 4 + 4;

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

/// The sorted→flat permutation the consumer rows route through (a non-trivial
/// fixed shuffle standing in for the lifted Merkle leaf order vs commit order).
fn perm(j: usize) -> usize {
    (j * 7 + 3) % N_COLS
}

// ── The single-component leaf↔c logup AIR ────────────────────────────────────

#[derive(Clone)]
struct DeepCoupleEval {
    log_n_rows: u32,
    host_s: SecureField,
    rel: DeepCoupleRelation,
}

impl FrameworkEval for DeepCoupleEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let rel = &self.rel;
        let pre = |eval: &mut E, id: &str| {
            eval.get_preprocessed_column(PreProcessedColumnId { id: id.to_string() })
        };
        let is_prod = pre(&mut eval, IS_PROD);
        let is_cons = pre(&mut eval, IS_CONS);
        let route = pre(&mut eval, ROUTE);
        let not_first = pre(&mut eval, NOT_FIRST);
        let is_last = pre(&mut eval, IS_LAST);

        let col_idx = eval.next_trace_mask();
        let c: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let leaf = eval.next_trace_mask();
        let lc: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let inc: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let s: [[E::F; 2]; 4] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [-1, 0]));

        // col_idx pinned to the preprocessed routing (flat | sorted→flat).
        eval.add_constraint((is_prod.clone() + is_cons.clone()) * (col_idx.clone() - route));
        for k in 0..4 {
            // lc = leaf·c (witnessed, degree 2); inc = is_cons·lc (the consumer's
            // contribution to S); S carry: S_cur = inc + not_first·S_prev.
            eval.add_constraint(lc[k].clone() - c[k].clone() * leaf.clone());
            eval.add_constraint(inc[k].clone() - is_cons.clone() * lc[k].clone());
            eval.add_constraint(
                s[k][1].clone() - inc[k].clone() - not_first.clone() * s[k][0].clone(),
            );
            // Final consumer row: the accumulated S equals the host total.
            eval.add_constraint(
                is_last.clone() * (s[k][1].clone() - E::F::from(self.host_s.to_m31_array()[k])),
            );
        }

        // The logup fraction: +1 on producer rows, −1 on consumer rows, 0 padding.
        let lift =
            |f: E::F| -> E::EF { E::combine_ef([f, E::F::zero(), E::F::zero(), E::F::zero()]) };
        let mult = lift(is_prod) - lift(is_cons);
        let tuple = [
            col_idx,
            c[0].clone(),
            c[1].clone(),
            c[2].clone(),
            c[3].clone(),
        ];
        eval.add_to_relation(RelationEntry::new(rel, mult, &tuple));
        eval.finalize_logup_in_pairs();
        eval
    }
}

// ── Trace generation (SIMD, then to_cpu-transplanted) ────────────────────────

type SimdEvals = Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>;
type CpuEvals = Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>;

/// A column's derived `c` (a synthetic QM31 stand-in for `α^i·cprime·…`) + leaf.
fn c_of(col: usize) -> SecureField {
    SecureField::from_m31_array([
        BaseField::from((col * 5 + 1) as u32),
        BaseField::from((col * 3 + 7) as u32),
        BaseField::from((col * 11 + 2) as u32),
        BaseField::from((col * 13 + 4) as u32),
    ])
}
fn leaf_of(col: usize) -> BaseField {
    BaseField::from((col * 17 + 9) as u32)
}

fn host_s() -> SecureField {
    (0..N_COLS)
        .map(|col| c_of(col) * SecureField::from(leaf_of(col)))
        .sum()
}

#[derive(Clone, Copy)]
enum Tamper {
    None,
    ProducerC,    // corrupt a producer's c ⇒ logup imbalance
    ConsumerLeaf, // corrupt a consumer's leaf ⇒ S ≠ host total
}

fn gen_traces(tamper: Tamper) -> (SimdEvals, SimdEvals) {
    let n = 1usize << LOG_SIZE;
    let mut pre: Vec<Vec<BaseField>> = vec![vec![BaseField::zero(); n]; 5];
    let mut main: Vec<Vec<BaseField>> = vec![vec![BaseField::zero(); n]; N_MAIN];

    let mut s_run = SecureField::zero();
    for logical in 0..n {
        let st = storage_index(logical, LOG_SIZE);
        let (is_prod, is_cons, col, route) = if logical < N_COLS {
            (1u32, 0u32, logical, logical) // producer: flat order
        } else if logical < 2 * N_COLS {
            let j = logical - N_COLS;
            (0, 1, perm(j), perm(j)) // consumer: sorted→flat routing
        } else {
            (0, 0, 0, 0) // padding
        };

        let mut c = if is_prod == 1 || is_cons == 1 {
            c_of(col)
        } else {
            SecureField::zero()
        };
        let mut leaf = if is_cons == 1 {
            leaf_of(col)
        } else {
            BaseField::zero()
        };
        if let Tamper::ProducerC = tamper {
            if is_prod == 1 && col == 0 {
                c += SecureField::one();
            }
        }
        if let Tamper::ConsumerLeaf = tamper {
            if is_cons == 1 && col == perm(0) {
                leaf += BaseField::one();
            }
        }
        let lc = c * SecureField::from(leaf);
        let inc = if is_cons == 1 {
            lc
        } else {
            SecureField::zero()
        };
        s_run += inc;

        // Preprocessed.
        pre[0][st] = BaseField::from(is_prod);
        pre[1][st] = BaseField::from(is_cons);
        pre[2][st] = BaseField::from(route as u32);
        pre[3][st] = if logical > 0 {
            BaseField::one()
        } else {
            BaseField::zero()
        };
        pre[4][st] = if logical == 2 * N_COLS - 1 {
            BaseField::one()
        } else {
            BaseField::zero()
        };

        // Main (in evaluate read order).
        let mut col_vals = vec![BaseField::from(col as u32)];
        col_vals.extend(c.to_m31_array());
        col_vals.push(leaf);
        col_vals.extend(lc.to_m31_array());
        col_vals.extend(inc.to_m31_array());
        col_vals.extend(s_run.to_m31_array());
        debug_assert_eq!(col_vals.len(), N_MAIN);
        for (cidx, v) in col_vals.into_iter().enumerate() {
            main[cidx][st] = v;
        }
    }

    let domain = CanonicCoset::new(LOG_SIZE).circle_domain();
    let wrap = |cols: Vec<Vec<BaseField>>| -> SimdEvals {
        cols.into_iter()
            .map(|v| {
                CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(
                    domain,
                    BaseColumn::from_iter(v),
                )
            })
            .collect()
    };
    (wrap(pre), wrap(main))
}

/// One logup interaction column + its claimed sum: per row, `num = is_prod −
/// is_cons` (the ±1/0 multiplicity), `denom = rel.combine((col_idx, c))`.
fn gen_interaction(
    pre: &SimdEvals,
    main: &SimdEvals,
    rel: &DeepCoupleRelation,
) -> (CpuEvals, SecureField) {
    let mut logup = LogupTraceGenerator::new(LOG_SIZE);
    let mut col = logup.new_col();
    for vec_row in 0..(1usize << (LOG_SIZE - LOG_N_LANES)) {
        let is_prod = pre[0].data[vec_row];
        let is_cons = pre[1].data[vec_row];
        let num = PackedQM31::from(is_prod - is_cons);
        // tuple = (col_idx, c[0..4]) — main cols 0, 1, 2, 3, 4.
        let tuple: [PackedM31; TUPLE_LEN] = std::array::from_fn(|c| main[c].data[vec_row]);
        let denom = rel.combine(&tuple);
        col.write_frac(vec_row, num, denom);
    }
    col.finalize_col();
    let (simd, claimed_sum) = logup.finalize_last();
    (to_cpu(&simd), claimed_sum)
}

struct Proven {
    component: FrameworkComponent<DeepCoupleEval>,
    proof: StarkProof<P2MerkleHasher>,
    claimed_sum: SecureField,
}

fn prove_couple(config: PcsConfig, tamper: Tamper) -> Result<Proven, String> {
    let (pre_simd, main_simd) = gen_traces(tamper);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(LOG_SIZE + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);

    // Tree 0: preprocessed.
    let mut tb = cs.tree_builder();
    tb.extend_evals(to_cpu(&pre_simd));
    tb.commit(channel);
    // Tree 1: main.
    let mut tb = cs.tree_builder();
    tb.extend_evals(to_cpu(&main_simd));
    tb.commit(channel);

    // Draw the relation AFTER the main commitment (Fiat-Shamir).
    let rel = DeepCoupleRelation::draw(channel);
    let (inter, claimed_sum) = gen_interaction(&pre_simd, &main_simd, &rel);
    channel.mix_felts(&[claimed_sum]);
    // Tree 2: interaction.
    let mut tb = cs.tree_builder();
    tb.extend_evals(inter);
    tb.commit(channel);

    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&preproc_ids());
    let component = FrameworkComponent::<DeepCoupleEval>::new(
        &mut alloc,
        DeepCoupleEval {
            log_n_rows: LOG_SIZE,
            host_s: host_s(),
            rel: rel.clone(),
        },
        claimed_sum,
    );
    // A leaf tamper makes the host trace itself invalid (S ≠ host total) ⇒ the
    // prover rejects it here (ConstraintsNotSatisfied), as a closed honest prover
    // should; a c tamper still proves but unbalances the logup (caught in verify).
    let proof = prove::<CpuBackend, P2MerkleChannel>(
        &[&component as &dyn ComponentProver<CpuBackend>],
        channel,
        cs,
    )
    .map_err(|e| format!("prove: {e:?}"))?;
    Ok(Proven {
        component,
        proof,
        claimed_sum,
    })
}

fn verify_couple(p: Proven, config: PcsConfig) -> Result<(), String> {
    // The self-balancing logup must net to zero (consumed (col,c) == produced).
    if p.claimed_sum != SecureField::zero() {
        return Err(format!("claimed-sum balance != 0: {:?}", p.claimed_sum));
    }
    let channel = &mut Poseidon2M31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = p.component.trace_log_degree_bounds();
    vs.commit(p.proof.commitments[0], &sizes[0], channel); // preprocessed
    vs.commit(p.proof.commitments[1], &sizes[1], channel); // main
    let _rel = DeepCoupleRelation::draw(channel); // replay the draw
    channel.mix_felts(&[p.claimed_sum]); // replay the claimed-sum mix
    vs.commit(p.proof.commitments[2], &sizes[2], channel); // interaction
    verify(&[&p.component as &dyn Component], channel, &mut vs, p.proof)
        .map_err(|e| format!("verify: {e:?}"))
}

/// DIAGNOSTIC: localize a violated constraint (assert checks zero-ness, pinpoints
/// the failing constraint — unlike the prover's generic ConstraintsNotSatisfied).
#[test]
fn deep_couple_assert() {
    use stwo::core::fields::m31::M31;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    let (pre_simd, main_simd) = gen_traces(Tamper::None);
    let channel = &mut Poseidon2M31Channel::default();
    let rel = DeepCoupleRelation::draw(channel);
    let (inter, claimed_sum) = gen_interaction(&pre_simd, &main_simd, &rel);

    let pre: Vec<Vec<M31>> = to_cpu(&pre_simd)
        .iter()
        .map(|e| e.values.to_cpu())
        .collect();
    let main: Vec<Vec<M31>> = to_cpu(&main_simd)
        .iter()
        .map(|e| e.values.to_cpu())
        .collect();
    let intr: Vec<Vec<M31>> = inter.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![
        pre.iter().collect(),
        main.iter().collect(),
        intr.iter().collect(),
    ]);
    let eval = DeepCoupleEval {
        log_n_rows: LOG_SIZE,
        host_s: host_s(),
        rel,
    };
    assert_constraints_on_trace(
        &tv,
        LOG_SIZE,
        |e| {
            eval.evaluate(e);
        },
        claimed_sum,
    );
    eprintln!("deep_couple_assert: all constraints satisfied (claimed_sum {claimed_sum:?})");
}

#[test]
fn deep_couple_gate() {
    let config = mobile_config();

    // Prove AND verify; a tamper rejected at EITHER stage counts as rejection.
    let run = |t: Tamper| -> Result<(), String> {
        let p = prove_couple(config, t)?;
        verify_couple(p, config)
    };

    let honest = prove_couple(config, Tamper::None).expect("honest prove");
    assert_eq!(
        honest.claimed_sum,
        SecureField::zero(),
        "honest leaf↔c couple must balance to 0"
    );
    verify_couple(honest, config).expect("honest leaf↔c logup couple must prove+verify");

    // A producer c the consumer never matches ⇒ logup imbalance (caught in verify).
    assert!(
        run(Tamper::ProducerC).is_err(),
        "an unmatched (col_index, c) must be rejected"
    );
    // A consumer leaf tamper ⇒ S ≠ host total (caught at prove, the honest-prover
    // invariant: the binding makes the tampered trace itself unprovable).
    assert!(
        run(Tamper::ConsumerLeaf).is_err(),
        "a tampered consumer leaf (S ≠ host total) must be rejected"
    );

    eprintln!(
        "deep_couple_gate GREEN: the flat↔sorted leaf↔c coupling — a PRODUCER presenting \
         (col_index, c) in flat order (+1) and a CONSUMER draining it in sorted (permuted) order \
         (−1) while accumulating leaf·c into a carry-latched S — proves+verifies in ONE uniform \
         component through the lifted Poseidon2-M31 protocol at degree ≤ 2; the claimed-sum \
         balance forces the consumer's c to match the producer's per col_index. An unmatched c \
         (logup imbalance) AND a tampered consumer leaf (S ≠ host total) are each rejected. This \
         is the step-4c layout crux: the DEEP numerator can read the trace-decommit leaves \
         (sorted order) and multiply by the flat-order derived c via this permutation."
    );
}
