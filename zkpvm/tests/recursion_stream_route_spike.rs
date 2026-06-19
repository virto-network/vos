//! Recursion build P5.3 task #1 — variable-offset PREPROCESSED-ROUTING spike: can
//! a uniform AIR reconstruct each operand from a fixed window of recent stream
//! samples via preprocessed coefficients, witness the product, and chain it —
//! all at degree ≤ 2?
//!
//! The co-locate layout (recursion_stream_layout) lays the OODS embed's products
//! down the rows; each product reads its product-operands cross-row at offsets
//! bounded by W_p ≈ 65 in product-rank space (≈ a handful of rows at a few
//! ops/row). The unsolved mechanism — neither `offset_spike` (offsets read the
//! right row) nor `stream_scale` (a UNIFORM per-row op) covered it — is that
//! different products read DIFFERENT past offsets with DIFFERENT coefficients,
//! while a uniform AIR applies one fixed constraint to every row.
//!
//! The resolution: the schedule (which sample, what coefficient) is FIXED across
//! all canonical segments (same 31 chips, same constraint structure, same mask
//! shape — only the OODS VALUES differ per proof), so it is PREPROCESSED. Each
//! row reads the stream column at a fixed offset window `[0,-1,…,-D]` and
//! reconstructs an operand as `a = Σ_{k=1}^{D} ca[k] · sample(-k)` with `ca[k]`
//! preprocessed (mostly zero — only this row's actual operand offsets are
//! nonzero). `ca[k]·sample` is preproc(deg 1)·main(deg 1) = deg 2; the whole sum
//! is ONE degree-2 constraint (term count is free — only multiplicative degree is
//! bounded). The product `P = a·b` and the chain `s = P` close it, all ≤ deg 2.
//!
//! The reconstruction + product constraints are UNGATED (they hold on every row,
//! including the seed/wrap rows where the columns are zero); only the linear chain
//! `active·(s − P)` is gated (degree-1 selector × degree-1 diff = degree 2 —
//! gating a degree-2 expr would be degree 3, over the bound). `assert_constraints`
//! checks only zero-ness, NOT the degree bound (a degree-3 slip surfaces only as a
//! FRI failure), so this MUST prove+verify, not just assert.
//!
//! Run: `cargo test -p zkpvm --test recursion_stream_route_spike -- --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::{P2MerkleChannel, Poseidon2M31Channel, mobile_config};
use stwo::core::air::Component;
use stwo::core::fields::m31::{BaseField, M31};
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
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

/// Offset-window depth (rows back). The layout measurement bounds the
/// product→product reach to ≤ 64 in product-rank space → ≤ ~8 rows at ~8 ops/row.
const D: usize = 8;
/// Offsets read on the stream column each row: `[0, -1, …, -D]` (D+1 samples).
/// Index 0 is the current row (for the chain); index k = offset −k (operands).
const N_OFF: usize = D + 1;
const OFFSETS: [isize; N_OFF] = [0, -1, -2, -3, -4, -5, -6, -7, -8];

const ACTIVE: &str = "route_active";
fn ca_id(k: usize, c: usize) -> String {
    format!("route_ca_{k}_{c}")
}
fn cb_id(k: usize, c: usize) -> String {
    format!("route_cb_{k}_{c}")
}

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

// ───────────────────────────────────────────────────────────────────────────
// The routing AIR: each row reconstructs a, b from preprocessed coefficients
// over the recent stream window, then s = a·b (chained), all degree ≤ 2.
// ───────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct RouteEval {
    log_n_rows: u32,
}

impl FrameworkEval for RouteEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let active = eval.get_preprocessed_column(PreProcessedColumnId {
            id: ACTIVE.to_string(),
        });
        // Preprocessed QM31 coefficients ca[k], cb[k] for k = 1..=D (4 base cols each).
        let read_coeff = |eval: &mut E, idf: &dyn Fn(usize, usize) -> String, k: usize| -> E::EF {
            let coords: [E::F; SECURE_EXTENSION_DEGREE] = std::array::from_fn(|c| {
                eval.get_preprocessed_column(PreProcessedColumnId { id: idf(k, c) })
            });
            E::combine_ef(coords)
        };
        let ca: [E::EF; D] = std::array::from_fn(|j| read_coeff(&mut eval, &ca_id, j + 1));
        let cb: [E::EF; D] = std::array::from_fn(|j| read_coeff(&mut eval, &cb_id, j + 1));

        // The stream column (QM31 = 4 base cols), each read at the fixed window.
        let s_coords: [[E::F; N_OFF]; SECURE_EXTENSION_DEGREE] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, OFFSETS));
        let sample =
            |j: usize| -> E::EF { E::combine_ef(std::array::from_fn(|c| s_coords[c][j].clone())) };

        // Witnessed operands + product (main reads at offset 0).
        let read4 = |eval: &mut E| -> E::EF {
            E::combine_ef(std::array::from_fn(|_| eval.next_trace_mask()))
        };
        let a_col = read4(&mut eval);
        let b_col = read4(&mut eval);
        let p = read4(&mut eval);

        // Reconstruction: a = Σ ca[k]·sample(-k), b = Σ cb[k]·sample(-k). Each
        // term is preproc(deg1)·main(deg1) = deg2; the sum is ONE deg-2 constraint.
        // UNGATED: on seed/wrap rows ca=cb=a_col=b_col=0 ⇒ 0 − 0 = 0.
        let mut a_sum = E::EF::zero();
        let mut b_sum = E::EF::zero();
        for k in 1..=D {
            a_sum += ca[k - 1].clone() * sample(k);
            b_sum += cb[k - 1].clone() * sample(k);
        }
        eval.add_constraint(a_col.clone() - a_sum);
        eval.add_constraint(b_col.clone() - b_sum);

        // Product P = a·b (deg 2), UNGATED (seed rows: 0 − 0·0 = 0).
        eval.add_constraint(p.clone() - a_col * b_col);

        // Chain: on active rows the stream value IS the product. Gated by the
        // degree-1 selector × degree-1 diff = degree 2.
        let lift =
            |f: E::F| -> E::EF { E::combine_ef([f, E::F::zero(), E::F::zero(), E::F::zero()]) };
        let s0 = sample(0);
        eval.add_constraint(lift(active) * (s0 - p));
        eval
    }
}

const fn main_cols() -> usize {
    SECURE_EXTENSION_DEGREE * 4 // s, a_col, b_col, p
}

struct RouteTrace {
    preprocessed: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    main: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    log_size: u32,
}

/// A deterministic QM31 stream (no `Math.random` in this env): a small LCG.
struct Lcg(u64);
impl Lcg {
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }
    fn next_qm31(&mut self) -> SecureField {
        SecureField::from_u32_unchecked(
            self.next_u32(),
            self.next_u32(),
            self.next_u32(),
            self.next_u32(),
        )
    }
    /// A small offset in `1..=D`.
    fn next_off(&mut self) -> usize {
        1 + (self.next_u32() as usize) % D
    }
}

/// Host-fill the routing trace: seed rows `[0,D)` carry arbitrary nonzero stream
/// values (the initial window); active rows `[D,n)` each pick two variable
/// offsets/coefficients per operand, reconstruct a, b, and set `s = a·b`.
fn gen_trace(log_size: u32, tamper: Option<usize>) -> RouteTrace {
    let n = 1usize << log_size;
    let mut rng = Lcg(0x1234_5678_9abc_def0);

    let mut s = vec![SecureField::zero(); n];
    let mut a_col = vec![SecureField::zero(); n];
    let mut b_col = vec![SecureField::zero(); n];
    let mut p_col = vec![SecureField::zero(); n];
    let mut active = vec![BaseField::zero(); n];
    // ca[k-1][r], cb[k-1][r] as QM31 (filled into 4 base cols at storage time).
    let mut ca = vec![vec![SecureField::zero(); n]; D];
    let mut cb = vec![vec![SecureField::zero(); n]; D];

    for r in 0..D.min(n) {
        s[r] = rng.next_qm31(); // seed window (unconstrained as a product)
    }
    for r in D..n {
        // Operand a: two variable offsets with random coefficients.
        let recon =
            |rng: &mut Lcg, coeffs: &mut [Vec<SecureField>], s: &[SecureField]| -> SecureField {
                let mut acc = SecureField::zero();
                for _ in 0..2 {
                    let k = rng.next_off();
                    let c = rng.next_qm31();
                    coeffs[k - 1][r] = c; // last write wins if k repeats — fine
                    acc += c * s[r - k];
                }
                // Recompute from the stored coeffs so a repeated offset is consistent
                // with what the AIR reads (Σ over ALL k of coeff·s[r-k]).
                let mut exact = SecureField::zero();
                for k in 1..=D {
                    exact += coeffs[k - 1][r] * s[r - k];
                }
                let _ = acc;
                exact
            };
        let a = recon(&mut rng, &mut ca, &s);
        let b = recon(&mut rng, &mut cb, &s);
        a_col[r] = a;
        b_col[r] = b;
        let prod = a * b;
        p_col[r] = prod;
        s[r] = prod;
        active[r] = BaseField::one();
    }

    // Lay logical columns into bit-reversed storage, QM31 → 4 base cols.
    let domain = CanonicCoset::new(log_size).circle_domain();
    let wrap = |col: Vec<BaseField>| {
        let mut c = Col::<CpuBackend, BaseField>::zeros(n);
        for (i, v) in col.into_iter().enumerate() {
            c.set(i, v);
        }
        CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, c)
    };
    let split = |q: &[SecureField]| -> Vec<Vec<BaseField>> {
        (0..SECURE_EXTENSION_DEGREE)
            .map(|c| {
                let mut col = vec![BaseField::zero(); n];
                for (i, v) in q.iter().enumerate() {
                    col[storage_index(i, log_size)] = v.to_m31_array()[c];
                }
                col
            })
            .collect()
    };

    // Main columns, in the eval's read order: s (4), a_col (4), b_col (4), p (4).
    let mut main_logical: Vec<Vec<BaseField>> = Vec::new();
    main_logical.extend(split(&s));
    main_logical.extend(split(&a_col));
    main_logical.extend(split(&b_col));
    main_logical.extend(split(&p_col));
    debug_assert_eq!(main_logical.len(), main_cols());

    if let Some(c) = tamper {
        // Tamper an ACTIVE row's stream value (row D, the first product): it is
        // constrained by `active·(s − p)` and consumed downstream, so the tamper
        // is detected. (Seed-row values are unconstrained and can be dead-weighted.)
        let r = storage_index(D, log_size);
        main_logical[c][r] += BaseField::one();
    }

    // Preprocessed columns, in the registration order: active, then ca_{k}_{c},
    // then cb_{k}_{c} (k = 1..=D, c = 0..4).
    let mut pre_logical: Vec<Vec<BaseField>> = Vec::new();
    {
        let mut act = vec![BaseField::zero(); n];
        for (i, &v) in active.iter().enumerate() {
            act[storage_index(i, log_size)] = v;
        }
        pre_logical.push(act);
    }
    for k in 1..=D {
        for c in 0..SECURE_EXTENSION_DEGREE {
            let mut col = vec![BaseField::zero(); n];
            for (i, v) in ca[k - 1].iter().enumerate() {
                col[storage_index(i, log_size)] = v.to_m31_array()[c];
            }
            pre_logical.push(col);
        }
    }
    for k in 1..=D {
        for c in 0..SECURE_EXTENSION_DEGREE {
            let mut col = vec![BaseField::zero(); n];
            for (i, v) in cb[k - 1].iter().enumerate() {
                col[storage_index(i, log_size)] = v.to_m31_array()[c];
            }
            pre_logical.push(col);
        }
    }

    RouteTrace {
        preprocessed: pre_logical.into_iter().map(wrap).collect(),
        main: main_logical.into_iter().map(wrap).collect(),
        log_size,
    }
}

fn preproc_ids() -> Vec<PreProcessedColumnId> {
    let mut ids = vec![PreProcessedColumnId {
        id: ACTIVE.to_string(),
    }];
    for k in 1..=D {
        for c in 0..SECURE_EXTENSION_DEGREE {
            ids.push(PreProcessedColumnId { id: ca_id(k, c) });
        }
    }
    for k in 1..=D {
        for c in 0..SECURE_EXTENSION_DEGREE {
            ids.push(PreProcessedColumnId { id: cb_id(k, c) });
        }
    }
    ids
}

fn prove_and_verify(trace: RouteTrace) -> Result<(), String> {
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

    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&preproc_ids());
    let component = FrameworkComponent::<RouteEval>::new(
        &mut alloc,
        RouteEval {
            log_n_rows: log_size,
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

/// FAST gate: the routing trace satisfies the AIR (AssertEvaluator), log 6.
#[test]
fn route_air_satisfied() {
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
    assert_constraints_on_trace(
        &tv,
        log_size,
        |e| {
            RouteEval {
                log_n_rows: log_size,
            }
            .evaluate(e);
        },
        SecureField::zero(),
    );
    eprintln!(
        "route_air_satisfied: variable-offset preprocessed-routing AIR satisfied (window D={D}, \
         {} main M31 cols, {} preproc M31 cols).",
        main_cols(),
        preproc_ids().len(),
    );
}

/// THE GATE: the routing mechanism proves+verifies at degree ≤ 2 (the degree
/// bound is only enforced here, not by assert_constraints); a tampered stream
/// sample is rejected.
#[test]
fn route_gate() {
    prove_and_verify(gen_trace(8, None))
        .expect("honest variable-offset routing must prove+verify at degree ≤ 2");
    assert!(
        prove_and_verify(gen_trace(8, Some(0))).is_err(),
        "a tampered stream sample must be rejected"
    );
    eprintln!(
        "route_gate GREEN: each row reconstructs operands from a fixed window [0,-{D}] via \
         PREPROCESSED coefficients (variable per row — the schedule is fixed across segments), \
         witnesses the product, and chains it — proving+verifying at degree ≤ 2 through the \
         lifted Poseidon2-M31 protocol. A tampered stream sample is rejected. This de-risks the \
         streamed OodsEval's core emission mechanism (the co-locate layout's variable-offset \
         product reads)."
    );
}
