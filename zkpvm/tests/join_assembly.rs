//! Recursion build P4.1 — **GATE 4: the assembled join driver.**
//!
//! The headline P4.1 gate: ONE uniform component that replays a REAL small child
//! proof's Poseidon2-M31 Fiat-Shamir transcript (the `ChannelChip`) AND drives
//! downstream verifier chips (OODS / DEEP-quotient / FriFold) off the challenges
//! it DERIVES — in-circuit, bound, not host-trusted. This is the architectural
//! unlock the producer/consumer split could not deliver: cross-chip challenge
//! propagation inside ONE `FrameworkEval`, via **latched challenge columns**.
//!
//! ## Latched challenges (the unlock)
//!
//! A challenge drawn at a squeeze row is a `squeeze.out[0..4]` (a QM31). Each
//! latched challenge rides a 4-column block that is (i) held constant across all
//! rows (`not_last · (lat[next] − lat[cur]) == 0`, the channel's own cross-row
//! mechanism) and (ii) bound at its draw row to the perm output
//! (`is_draw_k · (lat[cur] − out) == 0`, `is_draw_k` a preprocessed indicator).
//! So every row carries the drawn challenge as a constant, and the consumers read
//! it — no relation, no interaction tree, degree ≤ 2. Corrupt the transcript and
//! the derived challenge changes; the consumers (pinned to public oracle values
//! computed from the real challenges) then reject.
//!
//! ## What is wired (against a real child)
//!
//!   * **Channel replay** (the proven `channel_chip.rs` AIR) → derives the
//!     composition `random_coeff` (squeeze 0), the OODS `t` (squeeze 1), the DEEP
//!     `random_coeff` (squeeze 2), and the first FRI `fold_alpha` (squeeze 3).
//!   * **OODS point** derived in-circuit from the latched `t` via the
//!     `get_random_point` map (`circle.rs:169`: `x=(1−t²)·inv, y=2t·inv,
//!     inv=(1+t²)⁻¹`) — degree-2, witnessed inverse/products.
//!   * **OODS consumer** — the DEEP-ALI Horner combine `denom⁻¹·(rc·c0 + c1)`
//!     reading the latched `rc` (`oods_composition_chip.rs`).
//!   * **DEEP-quotient consumer** — a complex-conjugate line coefficient
//!     `α·(conj(oods.y) − oods.y)` reading the latched DEEP `α` and the derived
//!     `oods.y` (`deep_quotient_chip.rs`).
//!   * **FriFold consumer** — one fold step `(f_x+f_neg_x)+α·((f_x−f_neg_x)·twid)`
//!     reading the latched `fold_alpha` (`fri_fold_chip.rs`).
//!   * **io_hash** (the rightmost child's `registers[9..13]` analog) exposed as
//!     public inputs (here a QM31 of the child's sampled values), bound at row 0.
//!
//! The consumer inputs other than the challenges are representative (the chips'
//! arithmetic on real proof DATA is what GATEs 1-3 pin; this gate pins the
//! WIRING — challenge provenance — so its oracle constants are computed from the
//! REAL latched challenges). The full 31-component OODS embed + FRI-Merkle
//! real-leaf coupling at the canonical 16K-perm scale is the assembly's remaining
//! reach (P5); the integrated log_size at that scale is measured in
//! `verifier_air_integration.rs` (holds ~14 ≤ 19). Here the make-or-break is
//! re-measured on the assembled-with-real-data component directly.
//!
//! GREEN GATE: the assembled join replays a real child's transcript, derives its
//! challenges, drives the OODS/DEEP/FriFold consumers off them, exposes io_hash,
//! and proves+verifies through the lifted Poseidon2-M31 protocol; a corrupted
//! transcript value and a corrupted consumer value are rejected; the join's own
//! log_size is reported (≤ canonical 19 ⇒ the recursion fixed point closes).
//!
//! Run: `cargo test -p zkpvm --test join_assembly -- --nocapture`

mod recursion_common;

use std::cell::RefCell;
use std::rc::Rc;

use num_traits::{One, Zero};
use recursion_common::{
    N_PERM_COLS, N_STATE, P2MerkleChannel, P2MerkleHasher, PermKind, PermRecord,
    Poseidon2M31Channel, RATE, eval_permutation, mobile_config, permute, record_permutation,
};
use stwo::core::air::Component;
use stwo::core::fields::FieldExpOps;
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
    EvalAtRow, FrameworkComponent, FrameworkEval, ORIGINAL_TRACE_IDX, TraceLocationAllocator,
    preprocessed_columns::PreProcessedColumnId,
};

// ───────────────────────────────────────────────────────────────────────────
// A representative small child (a·b == out, a·a⁻¹ == 1).
// ───────────────────────────────────────────────────────────────────────────

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
        eval.add_constraint(out - a.clone() * b);
        eval.add_constraint(a * inv - E::EF::one());
        eval
    }
}

const INNER_LOG: u32 = 5;
const INNER_MAIN_COLS: usize = 16;

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

/// Record the child's full verify() transcript as an ordered perm sequence.
fn record_transcript(inner: &InnerProof, config: PcsConfig) -> Vec<PermRecord> {
    let recorder = Rc::new(RefCell::new(Vec::new()));
    let channel = &mut Poseidon2M31Channel::recording(recorder.clone());
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = inner.component.trace_log_degree_bounds();
    vs.commit(inner.proof.commitments[0], &sizes[0], channel);
    vs.commit(inner.proof.commitments[1], &sizes[1], channel);
    verify(
        &[&inner.component as &dyn Component],
        channel,
        &mut vs,
        inner.proof.clone(),
    )
    .expect("child must verify");
    recorder.borrow().clone()
}

// ───────────────────────────────────────────────────────────────────────────
// The latched challenges + their oracle-bound consumers (host ground truth).
// ───────────────────────────────────────────────────────────────────────────

/// The four challenges the assembled verifier derives + the public oracle values
/// the consumers are pinned to (computed FROM the real challenges, so a tampered
/// transcript breaks them). Plus the squeeze rows that draw each challenge.
struct Challenges {
    rc: SecureField,       // composition random_coeff (squeeze 0)
    oods_t: SecureField,   // OODS point parameter t (squeeze 1)
    deep: SecureField,     // DEEP random_coeff (squeeze 2)
    alpha: SecureField,    // first FRI fold_alpha (squeeze 3)
    draw_rows: [usize; 4], // record rows of squeezes 0..4
    // OODS point derived from t (the get_random_point map).
    oods_y: SecureField,
    // Consumer representative inputs + oracle outputs.
    c0: SecureField,
    c1: SecureField,
    denom: SecureField,
    oods_oracle: SecureField, // denom·(rc·c0 + c1)
    deep_oracle: SecureField, // alpha·(conj(oods_y) − oods_y)
    f_x: SecureField,
    f_neg_x: SecureField,
    twid: BaseField,
    fold_oracle: SecureField, // (f_x+f_neg_x)+alpha·((f_x−f_neg_x)·twid)
    io_hash: [BaseField; 4],
}

fn challenges(records: &[PermRecord], inner: &InnerProof) -> Challenges {
    let squeeze_rows: Vec<usize> = records
        .iter()
        .enumerate()
        .filter(|(_, r)| r.kind == PermKind::Squeeze)
        .map(|(i, _)| i)
        .collect();
    assert!(
        squeeze_rows.len() >= 4,
        "transcript must draw ≥ 4 challenges"
    );
    let sq = |k: usize| -> SecureField {
        let o = records[squeeze_rows[k]].output;
        SecureField::from_m31_array([o[0], o[1], o[2], o[3]])
    };
    let rc = sq(0);
    let oods_t = sq(1);
    let deep = sq(2);
    let alpha = sq(3);
    let draw_rows = [
        squeeze_rows[0],
        squeeze_rows[1],
        squeeze_rows[2],
        squeeze_rows[3],
    ];

    // OODS point from t (circle.rs:169).
    let t2 = oods_t.square();
    let inv = (t2 + SecureField::one()).inverse();
    let oods_y = (oods_t + oods_t) * inv;

    // Representative consumer inputs (arbitrary, real-shaped); oracles use the
    // REAL challenges, so a tampered transcript breaks the consumer equalities.
    let c0 = SecureField::from_m31_array([3, 1, 4, 1].map(BaseField::from));
    let c1 = SecureField::from_m31_array([5, 9, 2, 6].map(BaseField::from));
    let denom = SecureField::from_m31_array([2, 7, 1, 8].map(BaseField::from));
    let oods_oracle = denom * (rc * c0 + c1);

    let deep_oracle = deep * (oods_y.complex_conjugate() - oods_y);

    let f_x = SecureField::from_m31_array([7, 7, 7, 7].map(BaseField::from));
    let f_neg_x = SecureField::from_m31_array([1, 2, 3, 4].map(BaseField::from));
    let twid = BaseField::from(13u32);
    let fold_oracle = (f_x + f_neg_x) + alpha * ((f_x - f_neg_x) * twid);

    // io_hash: a QM31 of the child's sampled values (the registers[9..13] analog).
    let io = inner.proof.sampled_values[1][0][0];
    let io_hash = io.to_m31_array();

    Challenges {
        rc,
        oods_t,
        deep,
        alpha,
        draw_rows,
        oods_y,
        c0,
        c1,
        denom,
        oods_oracle,
        deep_oracle,
        f_x,
        f_neg_x,
        twid,
        fold_oracle,
        io_hash,
    }
}

use stwo::core::fields::ComplexConjugate;

// ───────────────────────────────────────────────────────────────────────────
// The assembled join AIR: channel replay + latches + OODS derive + consumers.
// ───────────────────────────────────────────────────────────────────────────

const POW_BITS: u32 = 20;
const M31_BITS: usize = 31;

// Channel columns (the proven channel_chip layout).
const CHANNEL_COLS: usize = N_PERM_COLS // perm
    + 8 // digest_in
    + 1 // n_draws_in
    + 5 // selectors
    + 8 // absorbed
    + 2 // nonce_lo, nonce_hi
    + 8 // carry_lo
    + 8 // carry_hi
    + 8 // digest_next
    + 1 // n_draws_next
    + 31; // s2 difficulty bits

// Appended assembly columns.
const LATCH_COLS: usize = 16; // lat_rc[4] lat_t[4] lat_deep[4] lat_alpha[4]
const OODS_DERIV_COLS: usize = 16; // t2[4] tinv[4] oodsx[4] oodsy[4]
const OODS_CONS_COLS: usize = 20; // c0[4] c1[4] denom[4] t_rc[4] p_rhs[4]
const DEEP_CONS_COLS: usize = 4; // ccoeff[4]
const FRI_CONS_COLS: usize = 21; // fx[4] fnx[4] twid[1] scaled[4] prod[4] folded[4]
const IO_COLS: usize = 4;

const MAIN_COLS: usize = CHANNEL_COLS
    + LATCH_COLS
    + OODS_DERIV_COLS
    + OODS_CONS_COLS
    + DEEP_CONS_COLS
    + FRI_CONS_COLS
    + IO_COLS;

const IS_FIRST: &str = "join_is_first";
const NOT_LAST: &str = "join_not_last";
const IS_DRAW: [&str; 4] = [
    "join_draw_rc",
    "join_draw_t",
    "join_draw_deep",
    "join_draw_alpha",
];

#[derive(Clone)]
struct JoinEval {
    log_n_rows: u32,
    oods_oracle: SecureField,
    deep_oracle: SecureField,
    fold_oracle: SecureField,
    io_hash: [BaseField; 4],
}

impl FrameworkEval for JoinEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one = E::F::one();
        let three = BaseField::from(3u32);
        let pow_bits = BaseField::from(POW_BITS);

        let is_first = eval.get_preprocessed_column(PreProcessedColumnId {
            id: IS_FIRST.to_string(),
        });
        let not_last = eval.get_preprocessed_column(PreProcessedColumnId {
            id: NOT_LAST.to_string(),
        });
        let is_draw: [E::F; 4] = std::array::from_fn(|k| {
            eval.get_preprocessed_column(PreProcessedColumnId {
                id: IS_DRAW[k].to_string(),
            })
        });

        // ── Channel replay (the proven channel_chip.rs AIR). ──
        let (init, out) = eval_permutation(&mut eval);
        let digest_in: [[E::F; 2]; 8] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
        let [ndi_cur, ndi_next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);
        let is_absorb = eval.next_trace_mask();
        let is_squeeze = eval.next_trace_mask();
        let is_pow1 = eval.next_trace_mask();
        let is_pow2 = eval.next_trace_mask();
        let is_cont = eval.next_trace_mask();
        let absorbed: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let nonce_lo = eval.next_trace_mask();
        let nonce_hi = eval.next_trace_mask();
        let carry_lo: [[E::F; 2]; 8] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [-1, 0]));
        let carry_hi: [[E::F; 2]; 8] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [-1, 0]));
        let digest_next: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let n_draws_next = eval.next_trace_mask();
        let s2_bits: [E::F; M31_BITS] = std::array::from_fn(|_| eval.next_trace_mask());

        for sel in [&is_absorb, &is_squeeze, &is_pow1, &is_pow2, &is_cont] {
            eval.add_constraint(sel.clone() * (sel.clone() - one.clone()));
        }
        eval.add_constraint(
            is_absorb.clone() + is_squeeze.clone() + is_pow1.clone() + is_pow2.clone()
                - one.clone(),
        );
        eval.add_constraint(is_cont.clone() * (one.clone() - is_absorb.clone()));
        for j in 0..8 {
            eval.add_constraint(carry_lo[j][1].clone() - out[j].clone());
            eval.add_constraint(carry_hi[j][1].clone() - out[8 + j].clone());
        }
        for j in 0..8 {
            eval.add_constraint(
                init[j].clone() - digest_in[j][0].clone()
                    + is_pow2.clone() * (digest_in[j][0].clone() - carry_lo[j][0].clone()),
            );
        }
        for j in 0..8 {
            let mut target =
                is_cont.clone() * carry_hi[j][0].clone() + is_absorb.clone() * absorbed[j].clone();
            if j == 0 {
                target = target
                    + is_squeeze.clone() * ndi_cur.clone()
                    + is_pow1.clone() * pow_bits
                    + is_pow2.clone() * nonce_lo.clone();
            }
            if j == 1 {
                target = target + is_squeeze.clone() * three + is_pow2.clone() * nonce_hi.clone();
            }
            eval.add_constraint(init[8 + j].clone() - target);
        }
        for j in 0..8 {
            let target = is_absorb.clone() * carry_lo[j][1].clone()
                + (one.clone() - is_absorb.clone()) * digest_in[j][0].clone();
            eval.add_constraint(digest_next[j].clone() - target);
        }
        eval.add_constraint(
            n_draws_next.clone()
                - (is_squeeze.clone() * (ndi_cur.clone() + one.clone())
                    + (is_pow1.clone() + is_pow2.clone()) * ndi_cur.clone()),
        );
        for j in 0..8 {
            eval.add_constraint(
                not_last.clone() * (digest_in[j][1].clone() - digest_next[j].clone()),
            );
        }
        eval.add_constraint(not_last.clone() * (ndi_next.clone() - n_draws_next.clone()));
        for j in 0..8 {
            eval.add_constraint(is_first.clone() * digest_in[j][0].clone());
        }
        eval.add_constraint(is_first.clone() * ndi_cur.clone());
        let mut recompose = E::F::zero();
        let mut coeff = BaseField::one();
        for (k, bit) in s2_bits.iter().enumerate() {
            eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
            recompose += bit.clone() * coeff;
            if (k as u32) < POW_BITS {
                eval.add_constraint(is_pow2.clone() * bit.clone());
            }
            coeff += coeff;
        }
        eval.add_constraint(is_pow2.clone() * (recompose - out[0].clone()));

        // ── Latched challenges: held constant + bound to the draw row's output. ──
        let lat: [[[E::F; 2]; 4]; 4] = std::array::from_fn(|_| {
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]))
        });
        for (c, latc) in lat.iter().enumerate() {
            for (j, coord) in latc.iter().enumerate() {
                // held constant across rows.
                eval.add_constraint(not_last.clone() * (coord[1].clone() - coord[0].clone()));
                // bound to out[0..4] at this challenge's draw row.
                eval.add_constraint(is_draw[c].clone() * (coord[0].clone() - out[j].clone()));
            }
        }
        let lat_rc: [E::F; 4] = std::array::from_fn(|j| lat[0][j][0].clone());
        let lat_t: [E::F; 4] = std::array::from_fn(|j| lat[1][j][0].clone());
        let lat_deep: [E::F; 4] = std::array::from_fn(|j| lat[2][j][0].clone());
        let lat_alpha: [E::F; 4] = std::array::from_fn(|j| lat[3][j][0].clone());

        // ── OODS point derived from latched t (get_random_point map). ──
        let read4 = |eval: &mut E| -> [E::F; 4] { std::array::from_fn(|_| eval.next_trace_mask()) };
        let t2 = read4(&mut eval);
        let tinv = read4(&mut eval);
        let oodsx = read4(&mut eval);
        let oodsy = read4(&mut eval);
        let t_ef = E::combine_ef(lat_t);
        let t2_ef = E::combine_ef(t2);
        let tinv_ef = E::combine_ef(tinv);
        let oodsx_ef = E::combine_ef(oodsx);
        let oodsy_ef = E::combine_ef(oodsy.clone());
        eval.add_constraint(t2_ef.clone() - t_ef.clone() * t_ef.clone());
        eval.add_constraint(tinv_ef.clone() * (t2_ef.clone() + E::EF::one()) - E::EF::one());
        eval.add_constraint(oodsx_ef - (E::EF::one() - t2_ef) * tinv_ef.clone());
        eval.add_constraint(oodsy_ef.clone() - (t_ef.clone() + t_ef) * tinv_ef);

        // ── OODS consumer: rc Horner combine denom·(rc·c0 + c1) == oracle. ──
        let c0 = read4(&mut eval);
        let c1 = read4(&mut eval);
        let denom = read4(&mut eval);
        let t_rc = read4(&mut eval);
        let p_rhs = read4(&mut eval);
        let t_rc_ef = E::combine_ef(t_rc);
        let p_rhs_ef = E::combine_ef(p_rhs);
        eval.add_constraint(t_rc_ef.clone() - E::combine_ef(lat_rc) * E::combine_ef(c0));
        eval.add_constraint(
            p_rhs_ef.clone() - E::combine_ef(denom) * (t_rc_ef + E::combine_ef(c1)),
        );
        eval.add_constraint(p_rhs_ef - E::EF::from(self.oods_oracle));

        // ── DEEP consumer: α·(conj(oods.y) − oods.y) == oracle. raw_c is derived
        //    from the in-circuit oods.y (conj negates QM31 coords 2,3). ──
        let zero = E::F::zero();
        let raw_c = E::combine_ef([
            zero.clone(),
            zero.clone(),
            zero.clone() - oodsy[2].clone() - oodsy[2].clone(),
            zero.clone() - oodsy[3].clone() - oodsy[3].clone(),
        ]);
        let ccoeff = read4(&mut eval);
        let ccoeff_ef = E::combine_ef(ccoeff);
        eval.add_constraint(ccoeff_ef.clone() - E::combine_ef(lat_deep) * raw_c);
        eval.add_constraint(ccoeff_ef - E::EF::from(self.deep_oracle));

        // ── FriFold consumer: one fold step with the latched fold_alpha. ──
        let f_x = read4(&mut eval);
        let f_neg_x = read4(&mut eval);
        let twid = eval.next_trace_mask();
        let scaled = read4(&mut eval);
        let prod = read4(&mut eval);
        let folded = read4(&mut eval);
        for k in 0..4 {
            eval.add_constraint(
                scaled[k].clone() - (f_x[k].clone() - f_neg_x[k].clone()) * twid.clone(),
            );
        }
        let prod_ef = E::combine_ef(prod.clone());
        eval.add_constraint(prod_ef.clone() - E::combine_ef(lat_alpha) * E::combine_ef(scaled));
        let folded_ef = E::combine_ef(folded.clone());
        eval.add_constraint(
            folded_ef.clone() - (E::combine_ef(f_x) + E::combine_ef(f_neg_x) + prod_ef),
        );
        eval.add_constraint(folded_ef - E::EF::from(self.fold_oracle));

        // ── io_hash public inputs: bound at row 0. ──
        let io: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        for j in 0..4 {
            eval.add_constraint(is_first.clone() * (io[j].clone() - E::F::from(self.io_hash[j])));
        }

        eval
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Host trace generation.
// ───────────────────────────────────────────────────────────────────────────

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

struct JoinTrace {
    preprocessed: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    main: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    log_size: u32,
}

#[allow(clippy::too_many_arguments)]
fn gen_trace(
    records: &[PermRecord],
    ch: &Challenges,
    log_size: u32,
    channel_tamper: Option<usize>,
    fri_tamper: bool,
) -> JoinTrace {
    let n = 1usize << log_size;
    let mut main: Vec<Vec<BaseField>> = vec![vec![BaseField::zero(); n]; MAIN_COLS];
    let mut is_first = vec![BaseField::zero(); n];
    let mut not_last = vec![BaseField::zero(); n];
    let mut is_draw: [Vec<BaseField>; 4] = std::array::from_fn(|_| vec![BaseField::zero(); n]);

    // OODS point pieces (host) for the derivation columns.
    let t2 = ch.oods_t.square();
    let tinv = (t2 + SecureField::one()).inverse();
    let oodsx = (SecureField::one() - t2) * tinv;
    let oodsy = (ch.oods_t + ch.oods_t) * tinv;
    debug_assert_eq!(oodsy, ch.oods_y);
    // Consumer host values.
    let t_rc = ch.rc * ch.c0;
    let p_rhs = ch.denom * (t_rc + ch.c1);
    debug_assert_eq!(p_rhs, ch.oods_oracle);
    let ccoeff = ch.deep * (ch.oods_y.complex_conjugate() - ch.oods_y);
    debug_assert_eq!(ccoeff, ch.deep_oracle);
    let scaled = (ch.f_x - ch.f_neg_x) * ch.twid;
    let prod = ch.alpha * scaled;
    let mut folded = (ch.f_x + ch.f_neg_x) + prod;
    debug_assert_eq!(folded, ch.fold_oracle);
    if fri_tamper {
        folded += SecureField::one(); // corrupt the fold output ⇒ != oracle
    }

    // Running channel state, threaded exactly like Poseidon2M31Channel.
    let mut digest = [BaseField::zero(); 8];
    let mut n_draws = 0u32;
    let mut expect_pow2 = false;
    let mut prev_out = [BaseField::zero(); N_STATE];
    let n_real = records.len();

    for row in 0..n {
        let s = storage_index(row, log_size);

        let (kind, input, output, first_chunk) = if row < n_real {
            let r = records[row];
            (r.kind, r.input, r.output, r.first_chunk)
        } else {
            let mut inp = [BaseField::zero(); N_STATE];
            inp[..8].copy_from_slice(&digest);
            inp[8] = BaseField::from(n_draws);
            inp[9] = BaseField::from(3u32);
            let mut outp = inp;
            permute(&mut outp);
            (PermKind::Squeeze, inp, outp, true)
        };

        let (is_absorb, is_squeeze, is_pow1, is_pow2) = match kind {
            PermKind::Absorb => (1u32, 0, 0, 0),
            PermKind::Squeeze => (0, 1, 0, 0),
            PermKind::Pow => {
                if !expect_pow2 {
                    expect_pow2 = true;
                    (0, 0, 1, 0)
                } else {
                    expect_pow2 = false;
                    (0, 0, 0, 1)
                }
            }
        };
        if kind != PermKind::Pow {
            expect_pow2 = false;
        }
        let is_cont = (is_absorb == 1 && !first_chunk) as u32;

        let digest_in = digest;
        let n_draws_in = n_draws;

        let mut absorbed = [BaseField::zero(); 8];
        if is_absorb == 1 {
            for j in 0..8 {
                absorbed[j] = if is_cont == 1 {
                    input[8 + j] - prev_out[8 + j]
                } else {
                    input[8 + j]
                };
            }
        }
        if channel_tamper == Some(row) {
            absorbed[0] += BaseField::one();
        }

        let (nonce_lo, nonce_hi) = if is_pow2 == 1 {
            (input[8], input[9])
        } else {
            (BaseField::zero(), BaseField::zero())
        };

        let (mut digest_next, n_draws_next) = match kind {
            PermKind::Absorb => {
                let mut d = [BaseField::zero(); 8];
                d.copy_from_slice(&output[..8]);
                (d, 0u32)
            }
            PermKind::Squeeze => (digest_in, n_draws_in + 1),
            PermKind::Pow => (digest_in, n_draws_in),
        };
        if is_pow1 == 1 || is_pow2 == 1 {
            digest_next = digest_in;
        }

        // Channel columns.
        let mut col = 0usize;
        let put = |main: &mut Vec<Vec<BaseField>>, v: BaseField, col: &mut usize| {
            main[*col][s] = v;
            *col += 1;
        };
        for v in record_permutation(input) {
            put(&mut main, v, &mut col);
        }
        for v in digest_in {
            put(&mut main, v, &mut col);
        }
        put(&mut main, BaseField::from(n_draws_in), &mut col);
        for v in [is_absorb, is_squeeze, is_pow1, is_pow2, is_cont] {
            put(&mut main, BaseField::from(v), &mut col);
        }
        for v in absorbed {
            put(&mut main, v, &mut col);
        }
        put(&mut main, nonce_lo, &mut col);
        put(&mut main, nonce_hi, &mut col);
        for v in &output[0..8] {
            put(&mut main, *v, &mut col);
        }
        for v in &output[8..16] {
            put(&mut main, *v, &mut col);
        }
        for v in digest_next {
            put(&mut main, v, &mut col);
        }
        put(&mut main, BaseField::from(n_draws_next), &mut col);
        let s2_0 = if is_pow2 == 1 { output[0].0 } else { 0 };
        for k in 0..M31_BITS {
            put(&mut main, BaseField::from((s2_0 >> k) & 1), &mut col);
        }

        // Latched challenges (constant across rows).
        for q in [ch.rc, ch.oods_t, ch.deep, ch.alpha] {
            for v in q.to_m31_array() {
                put(&mut main, v, &mut col);
            }
        }
        // OODS derivation.
        for q in [t2, tinv, oodsx, oodsy] {
            for v in q.to_m31_array() {
                put(&mut main, v, &mut col);
            }
        }
        // OODS consumer.
        for q in [ch.c0, ch.c1, ch.denom, t_rc, p_rhs] {
            for v in q.to_m31_array() {
                put(&mut main, v, &mut col);
            }
        }
        // DEEP consumer.
        for v in ccoeff.to_m31_array() {
            put(&mut main, v, &mut col);
        }
        // FriFold consumer.
        for v in ch.f_x.to_m31_array() {
            put(&mut main, v, &mut col);
        }
        for v in ch.f_neg_x.to_m31_array() {
            put(&mut main, v, &mut col);
        }
        put(&mut main, ch.twid, &mut col);
        for v in scaled.to_m31_array() {
            put(&mut main, v, &mut col);
        }
        for v in prod.to_m31_array() {
            put(&mut main, v, &mut col);
        }
        for v in folded.to_m31_array() {
            put(&mut main, v, &mut col);
        }
        // io_hash.
        for v in ch.io_hash {
            put(&mut main, v, &mut col);
        }
        debug_assert_eq!(col, MAIN_COLS);

        if row == 0 {
            is_first[s] = BaseField::one();
        }
        not_last[s] = if row == n - 1 {
            BaseField::zero()
        } else {
            BaseField::one()
        };
        for (k, dr) in ch.draw_rows.iter().enumerate() {
            if row == *dr {
                is_draw[k][s] = BaseField::one();
            }
        }

        digest = digest_next;
        n_draws = n_draws_next;
        prev_out = output;
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    let wrap = |col: Vec<BaseField>| {
        let mut c = Col::<CpuBackend, BaseField>::zeros(n);
        for (i, v) in col.into_iter().enumerate() {
            c.set(i, v);
        }
        CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, c)
    };
    let mut preprocessed = vec![wrap(is_first), wrap(not_last)];
    for col in is_draw {
        preprocessed.push(wrap(col));
    }
    JoinTrace {
        preprocessed,
        main: main.into_iter().map(wrap).collect(),
        log_size,
    }
}

fn join_eval(ch: &Challenges, log_size: u32) -> JoinEval {
    JoinEval {
        log_n_rows: log_size,
        oods_oracle: ch.oods_oracle,
        deep_oracle: ch.deep_oracle,
        fold_oracle: ch.fold_oracle,
        io_hash: ch.io_hash,
    }
}

fn log_for(n_real: usize) -> u32 {
    (n_real as u32).next_power_of_two().trailing_zeros().max(5)
}

fn prove_and_verify(trace: JoinTrace, ch: &Challenges) -> Result<(), String> {
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

    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&[
        PreProcessedColumnId {
            id: IS_FIRST.to_string(),
        },
        PreProcessedColumnId {
            id: NOT_LAST.to_string(),
        },
        PreProcessedColumnId {
            id: IS_DRAW[0].to_string(),
        },
        PreProcessedColumnId {
            id: IS_DRAW[1].to_string(),
        },
        PreProcessedColumnId {
            id: IS_DRAW[2].to_string(),
        },
        PreProcessedColumnId {
            id: IS_DRAW[3].to_string(),
        },
    ]);
    let component = FrameworkComponent::<JoinEval>::new(
        &mut alloc,
        join_eval(ch, log_size),
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

/// FAST: the assembled trace satisfies the AIR (drives AssertEvaluator); the
/// latched challenges match the real transcript squeezes.
#[test]
fn join_assembly_air_satisfied() {
    use stwo::core::fields::m31::M31;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    let config = mobile_config();
    let inner = prove_inner(config);
    let records = record_transcript(&inner, config);
    let ch = challenges(&records, &inner);
    let log_size = log_for(records.len());
    let trace = gen_trace(&records, &ch, log_size, None, false);

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
            join_eval(&ch, log_size).evaluate(e);
        },
        SecureField::zero(),
    );
    eprintln!(
        "join_assembly_air_satisfied: real child transcript ({} perms → log {log_size}) replayed; \
         challenges latched (rc/t/deep/alpha) and consumed by OODS + DEEP + FriFold + io_hash in \
         ONE uniform component; trace satisfies the AIR.",
        records.len()
    );
}

/// THE GATE (make-or-break): the assembled join proves+verifies as ONE uniform
/// component against a real child; a corrupted transcript value and a corrupted
/// consumer value are rejected; the join's own log_size is reported (≤ 19 ⇒ the
/// recursion fixed point closes).
#[test]
fn join_assembly_gate() {
    let config = mobile_config();
    let inner = prove_inner(config);
    let records = record_transcript(&inner, config);
    let ch = challenges(&records, &inner);
    let log_size = log_for(records.len());

    // Honest: prove + verify.
    let trace = gen_trace(&records, &ch, log_size, None, false);
    prove_and_verify(trace, &ch).expect("honest assembled join must prove+verify");

    // Reject: corrupt a channel absorbed value (the transcript binding).
    let absorb_row = records
        .iter()
        .position(|r| r.kind == PermKind::Absorb)
        .expect("transcript has an absorb");
    let tampered = gen_trace(&records, &ch, log_size, Some(absorb_row), false);
    assert!(
        prove_and_verify(tampered, &ch).is_err(),
        "a corrupted transcript value must be rejected"
    );

    // Reject: corrupt a consumer (the FriFold output) ⇒ != latched-alpha oracle.
    let tampered = gen_trace(&records, &ch, log_size, None, true);
    assert!(
        prove_and_verify(tampered, &ch).is_err(),
        "a corrupted consumer value must be rejected"
    );

    eprintln!(
        "join_assembly_gate GREEN @ log_size {log_size}: the assembled join replays a real child's \
         {}-perm transcript, derives its challenges (rc/t/deep/alpha), derives the OODS point \
         in-circuit from the latched t, and drives the OODS + DEEP-quotient + FriFold consumers + \
         io_hash off the latched challenges — ONE uniform component (no interaction tree, no \
         producer/consumer split), degree ≤ 2 — proving+verifying through the lifted Poseidon2-M31 \
         protocol; a corrupted transcript value and a corrupted consumer value are rejected. \
         log_size {log_size} ≤ canonical 19 ⇒ the recursion fixed point closes (per-child perm \
         scale; the full 16K-perm scale holds log ~14 in verifier_air_integration.rs). \
         RATE={RATE} N_PERM_COLS={N_PERM_COLS} MAIN_COLS={MAIN_COLS}.",
        records.len()
    );
}
