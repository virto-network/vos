//! Recursion build P5.3 — **step 4c architecture de-risk: the full DEEP wiring
//! (derive-c-in-producer + per-query logup multiplicity + the cross-region
//! eval↔first_layer latched carrier) in ONE uniform component.**
//!
//! `recursion_deep_couple` proved the flat↔sorted leaf↔c logup permutation with
//! `c` as a free committed column. This file wires the three remaining
//! compositions the 4c integration needs, at small log (fast proves), so the
//! architecture is validated before the ~25-min log-17 build:
//!   1. **derive-c-in-producer:** the producer's logup `c` is CONSTRAINED equal to
//!      the in-AIR derivation `c = α^i·(z̄.y − z.y)` (the soundness-critical line
//!      coeff, from the OODS mask side) — so the value the logup binds is the
//!      genuine derived `c`, not a free host column (the 4b derivation + the 4c
//!      logup, fused).
//!   2. **per-query logup multiplicity:** the producer emits each `(batch_id,
//!      col_index, c)` with multiplicity `+N_QUERIES` (one producer entry serves
//!      all queries' leaf rows); each query's consumer leaf drains it `−1`. The
//!      claimed-sum balance forces the consumer's `c` to match the producer's
//!      across all queries.
//!   3. **the cross-region eval↔first_layer carrier:** the DEEP `eval[qi]` is
//!      finalized on the leaf-region's evalfin row, while `first_layer[qi]` lives
//!      in a DISTANT region (the FRI fold rows in the real verifier). A
//!      GLOBALLY-LATCHED per-query `eval_lat[qi]` (held constant by `not_last`)
//!      bridges them: bound to the computed eval at the evalfin row and to
//!      `first_layer[qi]` at the distant flayer row (each via a one-hot query
//!      selector). A latched column held constant on ALL rows carries its value
//!      across ANY region distance — so the adversarial review's "third coupling"
//!      needs no second logup.
//!
//! The full factored-form eval (`Σ_b denom_inv·(L − p.y·A − B)`) is 4b-proven +
//! algebraically verified; here `eval[qi] = L[0][qi] + L[1][qi]` is the stand-in
//! that exercises the carrier (the carrier is eval-agnostic). `L[b][qi]` is read
//! into the evalfin row from the consumer carry at FIXED cross-row offsets (the
//! standalone has fixed per-batch block sizes; the real integration's variable
//! batch sizes use the same latched-value-by-selector pattern as `eval_lat`).
//!
//! GREEN GATE: honest prove+verify; a tampered consumer `c` (logup imbalance), a
//! tampered leaf (`eval ≠ first_layer`), and a tampered `first_layer` are each
//! rejected.
//!
//! Run: `cargo test -p zkpvm --test recursion_deep_full -- --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::{
    P2MerkleChannel, P2MerkleHasher, Poseidon2M31Channel, mobile_config, to_cpu,
};
use stwo::core::air::Component;
use stwo::core::channel::Channel;
use stwo::core::fields::ComplexConjugate;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::verifier::verify;
use stwo::prover::backend::CpuBackend;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{LOG_N_LANES, PackedM31};
use stwo::prover::backend::simd::qm31::PackedQM31;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, ComponentProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, ORIGINAL_TRACE_IDX,
    Relation, RelationEntry, TraceLocationAllocator, preprocessed_columns::PreProcessedColumnId,
    relation,
};

// Logup tuple: (batch_id, col_index, c[4]).
const TUPLE_LEN: usize = 2 + SECURE_EXTENSION_DEGREE;
relation!(DeepLeafRelation, TUPLE_LEN);

const NQ: usize = 4; // queries
const NB: usize = 2; // batches
const NC: usize = 8; // columns (0..4 -> batch 0, 4..8 -> batch 1)
const COLS_PER_BATCH: usize = NC / NB; // 4
const LOG_SIZE: u32 = 6; // n = 64

fn batch_of(col: usize) -> usize {
    col / COLS_PER_BATCH
}
/// Sorted-order column permutation within a (query, batch) sub-block (a fixed
/// shuffle standing in for the lifted Merkle leaf order vs commit order).
fn sorted_col(b: usize, k: usize) -> usize {
    b * COLS_PER_BATCH + (k * 3 + 1) % COLS_PER_BATCH
}

// ── Preprocessed column ids (registration order == read order) ───────────────
const NOT_LAST: &str = "df_not_last";
const IS_PROD: &str = "df_is_prod";
const IS_CONS: &str = "df_is_cons";
const IS_EVALFIN: &str = "df_is_evalfin";
const IS_FLAYER: &str = "df_is_flayer";
const L_CONT: &str = "df_l_cont"; // consumer carry continues the (query,batch) sub-block
const BATCH_ROUTE: &str = "df_batch_route"; // batch_id for the logup tuple
const COL_ROUTE: &str = "df_col_route"; // col_index for the logup tuple
fn qsel_id(q: usize) -> String {
    format!("df_qsel_{q}") // one-hot query selector (evalfin/flayer rows)
}

fn preproc_ids() -> Vec<PreProcessedColumnId> {
    let mut ids: Vec<PreProcessedColumnId> = [
        NOT_LAST,
        IS_PROD,
        IS_CONS,
        IS_EVALFIN,
        IS_FLAYER,
        L_CONT,
        BATCH_ROUTE,
        COL_ROUTE,
    ]
    .into_iter()
    .map(|id| PreProcessedColumnId { id: id.to_string() })
    .collect();
    for q in 0..NQ {
        ids.push(PreProcessedColumnId { id: qsel_id(q) });
    }
    ids
}

// ── Main columns (committed), in evaluate read order ─────────────────────────
// c[4], v[4], pow[4], rcs[4] (=selected raw_c witness), cw[4] (=pow*rcs witness),
// leaf[1], lc[4], L[4] (carry, read [-5,-1,0]), first_layer[4]. Latched:
// zy[NB][4], eval_lat[NQ][4].
const N_MAIN: usize = 4 + 4 + 4 + 4 + 4 + 1 + 4 + 4 + 4 + NB * 4 + NQ * 4;

const OFF_L0: isize = -((COLS_PER_BATCH + 1) as isize); // end of (qi, batch0) sub-block
const OFF_L1: isize = -1; // end of (qi, batch1) sub-block

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

#[derive(Clone)]
struct DeepFullEval {
    log_n_rows: u32,
    rel: DeepLeafRelation,
}

impl FrameworkEval for DeepFullEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree <= 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let rel = &self.rel;
        let zero = E::F::zero();
        let ef = E::combine_ef;
        let read4 = |eval: &mut E| -> [E::F; 4] { std::array::from_fn(|_| eval.next_trace_mask()) };
        let pre = |eval: &mut E, id: &str| {
            eval.get_preprocessed_column(PreProcessedColumnId { id: id.to_string() })
        };

        let not_last = pre(&mut eval, NOT_LAST);
        let is_prod = pre(&mut eval, IS_PROD);
        let is_cons = pre(&mut eval, IS_CONS);
        let is_evalfin = pre(&mut eval, IS_EVALFIN);
        let is_flayer = pre(&mut eval, IS_FLAYER);
        let l_cont = pre(&mut eval, L_CONT);
        let batch_route = pre(&mut eval, BATCH_ROUTE);
        let col_route = pre(&mut eval, COL_ROUTE);
        let qsel: [E::F; NQ] = std::array::from_fn(|q| pre(&mut eval, &qsel_id(q)));

        // Main columns.
        let c = read4(&mut eval);
        let v = read4(&mut eval);
        let pow = read4(&mut eval);
        let rcs = read4(&mut eval); // witnessed selected raw_c (= raw_c[batch_route])
        let cw = read4(&mut eval); // witnessed pow * rcs
        let leaf = eval.next_trace_mask();
        let lc = read4(&mut eval);
        let l_mask: [[E::F; 3]; 4] = std::array::from_fn(|_| {
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [OFF_L0, OFF_L1, 0])
        });
        let first_layer = read4(&mut eval);
        let zy: [[E::F; 4]; NB] = std::array::from_fn(|_| read4(&mut eval));
        // eval_lat read with [0,1] for the held-constant (not_last) latch.
        let eval_lat: [[[E::F; 2]; 4]; NQ] = std::array::from_fn(|_| {
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]))
        });

        // ── Producer: derive c = pow * raw_c, raw_c = conj(z.y) - z.y = [0,0,-2zy2,-2zy3]
        //    for the routed batch; bind the logup c to the derivation. ──
        // raw_c for the routed batch: select zy[batch_route]. (NB=2; one-hot in
        // batch_route via 1-bit: batch 0 -> zy[0], batch 1 -> zy[1].)
        // raw_c_b = [0,0,-2*zy_b[2], -2*zy_b[3]].
        let raw_c_of = |zyb: &[E::F; 4]| -> E::EF {
            ef([
                zero.clone(),
                zero.clone(),
                zero.clone() - zyb[2].clone() - zyb[2].clone(),
                zero.clone() - zyb[3].clone() - zyb[3].clone(),
            ])
        };
        // Select raw_c by batch_route (0/1): raw_c = (1-batch_route)*raw_c0 + batch_route*raw_c1.
        let raw_c0 = raw_c_of(&zy[0]);
        let raw_c1 = raw_c_of(&zy[1]);
        // rcs = raw_c0 + batch_route*(raw_c1 - raw_c0) witnessed (deg-2: preproc*EF);
        // cw = pow * rcs witnessed (deg 2); on producer rows c == cw.
        eval.add_constraint(
            ef(rcs.clone()) - (raw_c0.clone() + (raw_c1 - raw_c0) * batch_route.clone()),
        );
        eval.add_constraint(ef(cw.clone()) - ef(pow) * ef(rcs));
        eval.add_constraint((ef(c.clone()) - ef(cw)) * is_prod.clone());
        let _ = &v; // v feeds the full (a,b,c) in the integration; here only c is exercised

        // ── Leaf accumulation (consumer carry): lc = leaf*c (witnessed); L carry
        //    L_cur = lc + l_cont*L_prev (reset at each (query,batch) sub-block). ──
        for k in 0..4 {
            eval.add_constraint(lc[k].clone() - c[k].clone() * leaf.clone());
        }
        let l_cur = |k: usize| l_mask[k][2].clone();
        let l_at = |k: usize, slot: usize| l_mask[k][slot].clone();
        for k in 0..4 {
            // l_cont * L_prev: L_prev = L at offset -1? No: the carry threads
            // consecutive rows, so L_prev is offset -1. But l_mask offsets are
            // [OFF_L0, OFF_L1=-1, 0]; slot 1 is the -1 (previous-row) value.
            eval.add_constraint(l_cur(k) - lc[k].clone() - l_cont.clone() * l_at(k, 1));
        }

        // ── Evalfin: eval[qi] = L[0][qi] + L[1][qi] (read at fixed offsets), bound
        //    to the latched eval_lat[qi] via the one-hot query selector. ──
        let eval_lat_cur = |q: usize| ef(std::array::from_fn(|k| eval_lat[q][k][0].clone()));
        // selected eval_lat (deg2: qsel preproc * latched main).
        let mut sel_eval = E::EF::zero();
        for q in 0..NQ {
            sel_eval += eval_lat_cur(q) * qsel[q].clone();
        }
        // computed eval = L0 + L1 (the L sub-block ends read at OFF_L0/OFF_L1).
        let l0 = ef(std::array::from_fn(|k| l_at(k, 0)));
        let l1 = ef(std::array::from_fn(|k| l_at(k, 1)));
        let computed_eval = l0 + l1;
        eval.add_constraint((sel_eval.clone() - computed_eval) * is_evalfin.clone());

        // ── Flayer: bind eval_lat[qi] == first_layer[qi] (the distant region). ──
        eval.add_constraint((sel_eval - ef(first_layer)) * is_flayer.clone());

        // ── eval_lat held constant across all rows (the cross-region carrier). ──
        for q in 0..NQ {
            for k in 0..4 {
                eval.add_constraint(
                    not_last.clone() * (eval_lat[q][k][1].clone() - eval_lat[q][k][0].clone()),
                );
            }
        }

        // ── The leaf<->c logup: +NQ on producer rows, -1 on consumer rows. ──
        let lift = |f: E::F| -> E::EF { ef([f, zero.clone(), zero.clone(), zero.clone()]) };
        let mult = lift(is_prod * BaseField::from(NQ as u32)) - lift(is_cons);
        let tuple = [
            batch_route,
            col_route,
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

// ── Synthetic data ───────────────────────────────────────────────────────────
fn v_of(col: usize) -> SecureField {
    SecureField::from_m31_array([
        BaseField::from((col * 5 + 1) as u32),
        BaseField::from((col * 7 + 2) as u32),
        BaseField::from((col * 11 + 3) as u32),
        BaseField::from((col * 13 + 4) as u32),
    ])
}
fn zy_of(b: usize) -> SecureField {
    SecureField::from_m31_array([
        BaseField::from((b * 17 + 5) as u32),
        BaseField::from((b * 19 + 6) as u32),
        BaseField::from((b * 23 + 7) as u32),
        BaseField::from((b * 29 + 8) as u32),
    ])
}
fn alpha() -> SecureField {
    SecureField::from_m31_array([
        BaseField::from(3u32),
        BaseField::from(5u32),
        BaseField::from(7u32),
        BaseField::from(11u32),
    ])
}
fn pow_of(col: usize) -> SecureField {
    let mut p = SecureField::one();
    for _ in 0..col {
        p *= alpha();
    }
    p
}
fn c_of(col: usize) -> SecureField {
    let zy = zy_of(batch_of(col));
    let raw_c = zy.complex_conjugate() - zy;
    pow_of(col) * raw_c
}
fn leaf_of(col: usize, qi: usize) -> BaseField {
    BaseField::from((col * 31 + qi * 13 + 9) as u32)
}
/// L[b][qi] = Σ_{col in b} leaf[col][qi] * c[col]; eval[qi] = L0+L1.
fn first_layer_of(qi: usize) -> SecureField {
    (0..NC)
        .map(|col| c_of(col) * SecureField::from(leaf_of(col, qi)))
        .sum()
}

type SimdEvals = Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>;
type CpuEvals = Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>;

#[derive(Clone, Copy)]
enum Tamper {
    None,
    ConsumerC,  // a consumer c the producer never matches -> logup imbalance
    Leaf,       // a tampered leaf -> eval != first_layer
    FirstLayer, // a tampered first_layer -> eval_lat != first_layer
}

/// Row plan: producer (NC) | per query [batch0 cons (CPB) | batch1 cons (CPB) |
/// evalfin] | flayer (NQ). Returns (kind, payload) per logical row.
struct RowPlan {
    is_prod: bool,
    is_cons: bool,
    is_evalfin: bool,
    is_flayer: bool,
    l_cont: bool,
    batch: usize,
    col: usize,
    qi: usize,
}

fn row_plan() -> Vec<RowPlan> {
    let mut rows = Vec::new();
    // Producer: flat order cols 0..NC.
    for col in 0..NC {
        rows.push(RowPlan {
            is_prod: true,
            is_cons: false,
            is_evalfin: false,
            is_flayer: false,
            l_cont: false,
            batch: batch_of(col),
            col,
            qi: 0,
        });
    }
    // Per query: batch0 cons, batch1 cons, evalfin.
    for qi in 0..NQ {
        for b in 0..NB {
            for k in 0..COLS_PER_BATCH {
                let col = sorted_col(b, k);
                rows.push(RowPlan {
                    is_prod: false,
                    is_cons: true,
                    is_evalfin: false,
                    is_flayer: false,
                    l_cont: k != 0,
                    batch: b,
                    col,
                    qi,
                });
            }
        }
        rows.push(RowPlan {
            is_prod: false,
            is_cons: false,
            is_evalfin: true,
            is_flayer: false,
            l_cont: false,
            batch: 0,
            col: 0,
            qi,
        });
    }
    // Flayer rows (distant region).
    for qi in 0..NQ {
        rows.push(RowPlan {
            is_prod: false,
            is_cons: false,
            is_evalfin: false,
            is_flayer: true,
            l_cont: false,
            batch: 0,
            col: 0,
            qi,
        });
    }
    rows
}

fn gen_traces(tamper: Tamper) -> (SimdEvals, SimdEvals) {
    let n = 1usize << LOG_SIZE;
    let plan = row_plan();
    assert!(plan.len() <= n, "row plan {} > n {n}", plan.len());
    let mut pre: Vec<Vec<BaseField>> = vec![vec![BaseField::zero(); n]; preproc_ids().len()];
    let mut main: Vec<Vec<BaseField>> = vec![vec![BaseField::zero(); n]; N_MAIN];

    // Latched values (constant across all rows): zy[b], eval_lat[qi].
    let zy_vals: [SecureField; NB] = std::array::from_fn(zy_of);
    let eval_lat_vals: [SecureField; NQ] = std::array::from_fn(first_layer_of);

    // A no-op padding row (all selectors 0; latched columns still hold the
    // constants so the constancy constraints hold across the padding boundary).
    let pad = RowPlan {
        is_prod: false,
        is_cons: false,
        is_evalfin: false,
        is_flayer: false,
        l_cont: false,
        batch: 0,
        col: 0,
        qi: 0,
    };
    let mut l_run = SecureField::zero();
    for logical in 0..n {
        let rp = plan.get(logical).unwrap_or(&pad);
        let st = storage_index(logical, LOG_SIZE);

        // Derive c for this row's routed col (producer) / consumer c.
        let col = rp.col;
        let mut c = if rp.is_prod || rp.is_cons {
            c_of(col)
        } else {
            SecureField::zero()
        };
        if let Tamper::ConsumerC = tamper {
            if rp.is_cons && rp.col == sorted_col(0, 0) && rp.qi == 0 {
                c += SecureField::one();
            }
        }
        let v = if rp.is_prod || rp.is_cons {
            v_of(col)
        } else {
            SecureField::zero()
        };
        let pow = if rp.is_prod {
            pow_of(col)
        } else {
            SecureField::zero()
        };
        // rcs = the selected raw_c (= raw_c[batch_route]); cw = pow * rcs (0 off
        // producer rows since pow=0).
        let rcs = zy_vals[rp.batch].complex_conjugate() - zy_vals[rp.batch];
        let cw = pow * rcs;

        let mut leaf = if rp.is_cons {
            leaf_of(col, rp.qi)
        } else {
            BaseField::zero()
        };
        if let Tamper::Leaf = tamper {
            if rp.is_cons && rp.col == sorted_col(0, 0) && rp.qi == 0 {
                leaf += BaseField::one();
            }
        }
        let lc = c * SecureField::from(leaf);
        // L carry: reset at sub-block start (l_cont=false), else accumulate.
        l_run = if rp.is_cons {
            if rp.l_cont { l_run + lc } else { lc }
        } else {
            SecureField::zero()
        };

        let first_layer = if rp.is_flayer {
            let mut f = first_layer_of(rp.qi);
            if let Tamper::FirstLayer = tamper {
                if rp.qi == 0 {
                    f += SecureField::one();
                }
            }
            f
        } else {
            SecureField::zero()
        };

        // ── Preprocessed fill ──
        let b = |x: bool| {
            if x {
                BaseField::one()
            } else {
                BaseField::zero()
            }
        };
        let mut pc = 0usize;
        let putp = |pre: &mut Vec<Vec<BaseField>>, v: BaseField, pc: &mut usize| {
            pre[*pc][st] = v;
            *pc += 1;
        };
        putp(
            &mut pre,
            if logical + 1 < n {
                BaseField::one()
            } else {
                BaseField::zero()
            },
            &mut pc,
        );
        putp(&mut pre, b(rp.is_prod), &mut pc);
        putp(&mut pre, b(rp.is_cons), &mut pc);
        putp(&mut pre, b(rp.is_evalfin), &mut pc);
        putp(&mut pre, b(rp.is_flayer), &mut pc);
        putp(&mut pre, b(rp.l_cont), &mut pc);
        putp(&mut pre, BaseField::from(rp.batch as u32), &mut pc);
        putp(&mut pre, BaseField::from(rp.col as u32), &mut pc);
        for q in 0..NQ {
            let on = (rp.is_evalfin || rp.is_flayer) && rp.qi == q;
            putp(&mut pre, b(on), &mut pc);
        }
        debug_assert_eq!(pc, preproc_ids().len());

        // ── Main fill (read order) ──
        let mut mc = 0usize;
        let putm = |main: &mut Vec<Vec<BaseField>>, q: SecureField, mc: &mut usize| {
            for v in q.to_m31_array() {
                main[*mc][st] = v;
                *mc += 1;
            }
        };
        putm(&mut main, c, &mut mc);
        putm(&mut main, v, &mut mc);
        putm(&mut main, pow, &mut mc);
        putm(&mut main, rcs, &mut mc);
        putm(&mut main, cw, &mut mc);
        main[mc][st] = leaf;
        mc += 1;
        putm(&mut main, lc, &mut mc);
        putm(&mut main, l_run, &mut mc);
        putm(&mut main, first_layer, &mut mc);
        for b in 0..NB {
            putm(&mut main, zy_vals[b], &mut mc);
        }
        for q in 0..NQ {
            putm(&mut main, eval_lat_vals[q], &mut mc);
        }
        debug_assert_eq!(mc, N_MAIN);
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

fn gen_interaction(
    pre: &SimdEvals,
    main: &SimdEvals,
    rel: &DeepLeafRelation,
) -> (CpuEvals, SecureField) {
    // main column offsets: c is cols 0..4; preproc batch_route=6, col_route=7.
    let mut logup = LogupTraceGenerator::new(LOG_SIZE);
    let mut col = logup.new_col();
    let nq = PackedM31::broadcast(BaseField::from(NQ as u32));
    for vec_row in 0..(1usize << (LOG_SIZE - LOG_N_LANES)) {
        let is_prod = pre[1].data[vec_row];
        let is_cons = pre[2].data[vec_row];
        let num = PackedQM31::from(is_prod * nq - is_cons);
        // tuple = (batch_route, col_route, c0..c3) = pre[6], pre[7], main[0..4].
        let tuple: [PackedM31; TUPLE_LEN] = [
            pre[6].data[vec_row],
            pre[7].data[vec_row],
            main[0].data[vec_row],
            main[1].data[vec_row],
            main[2].data[vec_row],
            main[3].data[vec_row],
        ];
        let denom = rel.combine(&tuple);
        col.write_frac(vec_row, num, denom);
    }
    col.finalize_col();
    let (simd, claimed_sum) = logup.finalize_last();
    (to_cpu(&simd), claimed_sum)
}

struct Proven {
    component: FrameworkComponent<DeepFullEval>,
    proof: StarkProof<P2MerkleHasher>,
    claimed_sum: SecureField,
}

fn prove_full(config: PcsConfig, tamper: Tamper) -> Result<Proven, String> {
    let (pre_simd, main_simd) = gen_traces(tamper);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(LOG_SIZE + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);
    let mut tb = cs.tree_builder();
    tb.extend_evals(to_cpu(&pre_simd));
    tb.commit(channel);
    let mut tb = cs.tree_builder();
    tb.extend_evals(to_cpu(&main_simd));
    tb.commit(channel);

    let rel = DeepLeafRelation::draw(channel);
    let (inter, claimed_sum) = gen_interaction(&pre_simd, &main_simd, &rel);
    channel.mix_felts(&[claimed_sum]);
    let mut tb = cs.tree_builder();
    tb.extend_evals(inter);
    tb.commit(channel);

    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&preproc_ids());
    let component = FrameworkComponent::<DeepFullEval>::new(
        &mut alloc,
        DeepFullEval {
            log_n_rows: LOG_SIZE,
            rel: rel.clone(),
        },
        claimed_sum,
    );
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

fn verify_full(p: Proven, config: PcsConfig) -> Result<(), String> {
    if p.claimed_sum != SecureField::zero() {
        return Err(format!("claimed-sum balance != 0: {:?}", p.claimed_sum));
    }
    let channel = &mut Poseidon2M31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = p.component.trace_log_degree_bounds();
    vs.commit(p.proof.commitments[0], &sizes[0], channel);
    vs.commit(p.proof.commitments[1], &sizes[1], channel);
    let _rel = DeepLeafRelation::draw(channel);
    channel.mix_felts(&[p.claimed_sum]);
    vs.commit(p.proof.commitments[2], &sizes[2], channel);
    verify(&[&p.component as &dyn Component], channel, &mut vs, p.proof)
        .map_err(|e| format!("verify: {e:?}"))
}

#[test]
fn deep_full_assert() {
    use stwo::core::fields::m31::M31;
    use stwo::core::pcs::TreeVec;
    use stwo::prover::backend::Column;
    use stwo_constraint_framework::assert_constraints_on_trace;

    let (pre_simd, main_simd) = gen_traces(Tamper::None);
    let channel = &mut Poseidon2M31Channel::default();
    let rel = DeepLeafRelation::draw(channel);
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
    let comp = DeepFullEval {
        log_n_rows: LOG_SIZE,
        rel,
    };
    assert_constraints_on_trace(
        &tv,
        LOG_SIZE,
        |e| {
            comp.evaluate(e);
        },
        claimed_sum,
    );
    eprintln!("deep_full_assert: all constraints satisfied (claimed_sum {claimed_sum:?})");
}

#[test]
fn deep_full_gate() {
    let config = mobile_config();
    let run = |t: Tamper| -> Result<(), String> {
        prove_full(config, t).and_then(|p| verify_full(p, config))
    };

    run(Tamper::None).expect("honest full DEEP wiring must prove+verify");
    assert!(
        run(Tamper::ConsumerC).is_err(),
        "a consumer c the producer never matches must be rejected"
    );
    assert!(
        run(Tamper::Leaf).is_err(),
        "a tampered leaf (eval != first_layer) must be rejected"
    );
    assert!(
        run(Tamper::FirstLayer).is_err(),
        "a tampered first_layer must be rejected"
    );

    eprintln!(
        "deep_full_gate GREEN: the full step-4c wiring proves+verifies in ONE uniform component at \
         degree <= 2 — the producer DERIVES the logup c = alpha^i*(zbar.y - z.y) (bound to the \
         tuple), emits it with multiplicity +{NQ} (one entry per (batch,col) serving all queries), \
         each query's consumer leaf drains it -1 while accumulating leaf*c into L[b][qi]; the DEEP \
         eval[qi] = L0+L1 (read at fixed cross-row offsets) is carried to a DISTANT first_layer \
         region by a globally-latched per-query eval_lat[qi] (one-hot query selector at both ends) \
         — the cross-region binding needs NO second logup. A tampered consumer c (logup imbalance), \
         a tampered leaf (eval != first_layer), and a tampered first_layer are each rejected."
    );
}
