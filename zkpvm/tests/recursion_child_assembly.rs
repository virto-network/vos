#![cfg(feature = "poseidon2-channel")]

//! Recursion build P5.3 — **the per-child assembly (step 1: channel + streamed
//! OODS embed + rc latch).**
//!
//! P5.2 proved the streamed OODS embed standalone (`recursion_stream_embed`); P4.1
//! proved the channel transcript replay + latched cross-chip propagation
//! (`join_assembly`). This file MERGES them into ONE uniform `FrameworkEval` over a
//! single row grid, driven off ONE REAL `prove_canonical` segment:
//!
//!   * **Channel replay** — the proven `channel_chip`/`join_assembly` AIR replays
//!     the real segment's full Poseidon2-M31 Fiat-Shamir transcript (8584 perms →
//!     log 14), one perm/row, the digest chain held across rows by `not_last`.
//!   * **Streamed OODS embed** — the proven `recursion_stream_embed` co-locate AIR
//!     rides on the SAME rows (its 6251 stream rows fit within the channel's 16384),
//!     re-evaluating the full 31-component OODS composition at degree ≤ 2.
//!   * **rc latch (the cross-chip binding)** — the embed's `rc` latched column
//!     (`latched[0]`, the composition Horner base) is BOUND to the channel's
//!     composition-`random_coeff` squeeze: a preprocessed `is_rc_draw` indicator
//!     fires on the first `Squeeze` at-or-after `prefix_len` (stwo's verifier head
//!     draws `random_coeff` first), and the constraint
//!     `is_rc_draw · (lat_rc[j] − squeeze_out[j]) == 0` pins the embed's rc to the
//!     transcript-derived one. So the embed no longer TRUSTS a host rc; it consumes
//!     the channel's. (dinv/ox/comp/lookup latches are bound in step 1b+.)
//!
//! The two AIRs share `not_last` (channel digest chain + embed latched constancy)
//! and the storage indexing; otherwise the column blocks + constraints are
//! independent. Both are individually proven at degree ≤ 2; the latch binding is
//! `deg1·deg1 = deg2` (the join_assembly pattern), so the merge stays degree ≤ 2.
//!
//! `assert_constraints_on_trace` checks only ZERO-ness, NOT the degree bound (a
//! degree-3 slip surfaces only as a FRI failure at prove), so the milestone is the
//! PROVE, not the assert; the assert is the fast value-bug gate run first.
//!
//! Run (heavy gates, release):
//! `cargo test -p zkpvm --release --features poseidon2-channel \
//!     --test recursion_child_assembly -- --ignored --nocapture`

mod recursion_common;

use std::cell::RefCell;
use std::rc::Rc;

use num_traits::{One, Zero};
use recursion_common::oods_auto::{
    ColocateLayout, ComponentMask, N_LATCHED, StreamBackend, WinPos, drive_multi,
};
use recursion_common::{
    N_PERM_COLS, N_STATE, P2MerkleChannel, Poseidon2M31Channel, eval_permutation, mobile_config,
    permute, record_permutation,
};
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
use zkpvm::poseidon2::{PermKind, PermRecord};
use zkpvm::{Proof, SideNote};

// ── Locked embed layout parameters (recursion_stream_embed sweet spot) ───────
const T_PER_MAC: usize = 16;
const OPS_S: usize = 4;
const DR: usize = 24;
const N_OFF: usize = DR + 1;
const NLEAF: usize = 80;
/// Window positions a recon reads, in canonical order: leaves, per-lane stream
/// offsets, then latched.
const WIN: usize = NLEAF + OPS_S * N_OFF + N_LATCHED;

const fn offsets() -> [isize; N_OFF] {
    let mut o = [0isize; N_OFF];
    let mut k = 0;
    while k < N_OFF {
        o[k] = -(k as isize);
        k += 1;
    }
    o
}
const OFFSETS: [isize; N_OFF] = offsets();

// ── Channel layout (the proven channel_chip / join_assembly block) ───────────
const POW_BITS: u32 = 20;
const M31_BITS: usize = 31;
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

/// Embed main QM31 logical columns per row: NLEAF leaves + per-lane (oa,ob,r) +
/// latched.
const fn embed_qm31_cols() -> usize {
    NLEAF + OPS_S * 3 + N_LATCHED
}

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

// ── Preprocessed column ids (the fixed routing "program") ────────────────────
// Registration / read / fill order: not_last, ch_is_first, is_rc_draw,
// emb_final[OPS_S], then the recon program (per lane, side: const then coeffs).
const NOT_LAST: &str = "ca_not_last";
const CH_IS_FIRST: &str = "ca_is_first";
const IS_RC_DRAW: &str = "ca_is_rc_draw";
fn final_id(l: usize) -> String {
    format!("ca_final_{l}")
}
fn const_id(l: usize, r: usize, c: usize) -> String {
    format!("ca_c_{l}_{r}_{c}")
}
fn coeff_id(l: usize, r: usize, p: usize, c: usize) -> String {
    format!("ca_k_{l}_{r}_{p}_{c}")
}

fn preproc_ids() -> Vec<PreProcessedColumnId> {
    let mut ids = vec![
        PreProcessedColumnId {
            id: NOT_LAST.to_string(),
        },
        PreProcessedColumnId {
            id: CH_IS_FIRST.to_string(),
        },
        PreProcessedColumnId {
            id: IS_RC_DRAW.to_string(),
        },
    ];
    for l in 0..OPS_S {
        ids.push(PreProcessedColumnId { id: final_id(l) });
    }
    for l in 0..OPS_S {
        for r in 0..2 {
            for c in 0..SECURE_EXTENSION_DEGREE {
                ids.push(PreProcessedColumnId {
                    id: const_id(l, r, c),
                });
            }
            for p in 0..WIN {
                for c in 0..SECURE_EXTENSION_DEGREE {
                    ids.push(PreProcessedColumnId {
                        id: coeff_id(l, r, p, c),
                    });
                }
            }
        }
    }
    ids
}

/// Map a resolved [`WinPos`] to its canonical window-position index.
fn win_index(pos: &WinPos) -> usize {
    match *pos {
        WinPos::Leaf { lane, .. } => lane,
        WinPos::Slot { lane, off } => NLEAF + lane * N_OFF + off,
        WinPos::Latched(s) => NLEAF + OPS_S * N_OFF + s,
        _ => unreachable!("co-locate layout uses Leaf/Slot/Latched"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The merged per-child AIR: channel replay + streamed embed + rc latch.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ChildEval {
    log_n_rows: u32,
}

impl FrameworkEval for ChildEval {
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
        let lift =
            |f: E::F| -> E::EF { E::combine_ef([f, E::F::zero(), E::F::zero(), E::F::zero()]) };

        // ── Preprocessed reads (cursor-based: EXACT registration order) ──
        let not_last = eval.get_preprocessed_column(PreProcessedColumnId {
            id: NOT_LAST.to_string(),
        });
        let ch_is_first = eval.get_preprocessed_column(PreProcessedColumnId {
            id: CH_IS_FIRST.to_string(),
        });
        let is_rc_draw = eval.get_preprocessed_column(PreProcessedColumnId {
            id: IS_RC_DRAW.to_string(),
        });
        let is_final: [E::F; OPS_S] = std::array::from_fn(|l| {
            eval.get_preprocessed_column(PreProcessedColumnId { id: final_id(l) })
        });
        let mut prog: Vec<(E::EF, Vec<E::EF>)> = Vec::with_capacity(2 * OPS_S);
        for l in 0..OPS_S {
            for r in 0..2 {
                let cst = E::combine_ef(std::array::from_fn(|c| {
                    eval.get_preprocessed_column(PreProcessedColumnId {
                        id: const_id(l, r, c),
                    })
                }));
                let cf: Vec<E::EF> = (0..WIN)
                    .map(|p| {
                        E::combine_ef(std::array::from_fn(|c| {
                            eval.get_preprocessed_column(PreProcessedColumnId {
                                id: coeff_id(l, r, p, c),
                            })
                        }))
                    })
                    .collect();
                prog.push((cst, cf));
            }
        }

        // ── Channel block (verbatim from the proven join_assembly AIR) ──
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
            eval.add_constraint(ch_is_first.clone() * digest_in[j][0].clone());
        }
        eval.add_constraint(ch_is_first.clone() * ndi_cur.clone());
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

        // ── Embed block (verbatim from the proven recursion_stream_embed AIR) ──
        let read4_0 = |eval: &mut E| -> E::EF {
            E::combine_ef(std::array::from_fn(|_| eval.next_trace_mask()))
        };
        let leaves: [E::EF; NLEAF] = std::array::from_fn(|_| read4_0(&mut eval));

        let mut oa: Vec<E::EF> = Vec::with_capacity(OPS_S);
        let mut ob: Vec<E::EF> = Vec::with_capacity(OPS_S);
        let mut r_coords: Vec<[[E::F; N_OFF]; SECURE_EXTENSION_DEGREE]> = Vec::with_capacity(OPS_S);
        for _ in 0..OPS_S {
            oa.push(read4_0(&mut eval));
            ob.push(read4_0(&mut eval));
            let rc: [[E::F; N_OFF]; SECURE_EXTENSION_DEGREE] =
                std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, OFFSETS));
            r_coords.push(rc);
        }
        let r_at = |l: usize,
                    off: usize,
                    r_coords: &[[[E::F; N_OFF]; SECURE_EXTENSION_DEGREE]]|
         -> E::EF {
            E::combine_ef(std::array::from_fn(|c| r_coords[l][c][off].clone()))
        };

        // Latched OODS scalars (held by not_last). Capture rc's coords (slot 0) for
        // the channel binding.
        let mut lat_cur: [E::EF; N_LATCHED] = std::array::from_fn(|_| E::EF::zero());
        let mut lat_next: [E::EF; N_LATCHED] = std::array::from_fn(|_| E::EF::zero());
        let mut rc_coords: [E::F; SECURE_EXTENSION_DEGREE] = std::array::from_fn(|_| E::F::zero());
        for s in 0..N_LATCHED {
            let c: [[E::F; 2]; SECURE_EXTENSION_DEGREE] =
                std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
            if s == 0 {
                rc_coords = std::array::from_fn(|i| c[i][0].clone());
            }
            lat_cur[s] = E::combine_ef(std::array::from_fn(|i| c[i][0].clone()));
            lat_next[s] = E::combine_ef(std::array::from_fn(|i| c[i][1].clone()));
        }

        let window: Vec<E::EF> = (0..WIN)
            .map(|p| {
                if p < NLEAF {
                    leaves[p].clone()
                } else if p < NLEAF + OPS_S * N_OFF {
                    let q = p - NLEAF;
                    r_at(q / N_OFF, q % N_OFF, &r_coords)
                } else {
                    lat_cur[p - (NLEAF + OPS_S * N_OFF)].clone()
                }
            })
            .collect();

        for l in 0..OPS_S {
            for (r, side) in [&oa[l], &ob[l]].into_iter().enumerate() {
                let (cst, cf) = &prog[l * 2 + r];
                let mut recon = cst.clone();
                for p in 0..WIN {
                    recon += cf[p].clone() * window[p].clone();
                }
                eval.add_constraint(side.clone() - recon); // deg 2, UNGATED
            }
            let r_l = r_at(l, 0, &r_coords);
            eval.add_constraint(r_l.clone() - oa[l].clone() * ob[l].clone()); // deg 2
            eval.add_constraint(lift(is_final[l].clone()) * r_l); // final: lhs−rhs == 0
        }

        // Latched held constant across rows (ONE consistent OODS scalar set).
        for s in 0..N_LATCHED {
            eval.add_constraint(
                lift(not_last.clone()) * (lat_next[s].clone() - lat_cur[s].clone()),
            );
        }

        // ── rc latch: bind the embed's rc (latched[0]) to the channel's
        //    composition-random_coeff squeeze output at the is_rc_draw row. ──
        for j in 0..SECURE_EXTENSION_DEGREE {
            eval.add_constraint(is_rc_draw.clone() * (rc_coords[j].clone() - out[j].clone()));
        }

        eval
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Host trace generation (merged channel + embed fill).
// ─────────────────────────────────────────────────────────────────────────────

struct ChildTrace {
    preprocessed: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    main: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    log_size: u32,
}

/// `channel_tamper`: bump one absorbed value on that record row (breaks the
/// transcript binding → derived rc diverges). `final_tamper`: bump the embed's
/// final-slot oa column (breaks the composition).
#[allow(clippy::too_many_arguments)]
fn gen_trace(
    records: &[PermRecord],
    rc_row: usize,
    lay: &ColocateLayout,
    log_size: u32,
    channel_tamper: Option<usize>,
    final_tamper: bool,
) -> ChildTrace {
    assert!(lay.ops_s == OPS_S && lay.nleaf == NLEAF);
    assert!(lay.dr <= DR, "layout dr={} exceeds DR={DR}", lay.dr);
    assert!(lay.max_leaf_in_row <= NLEAF);
    let n = 1usize << log_size;
    assert!(
        records.len() <= n,
        "transcript {} > rows {n}",
        records.len()
    );
    assert!(lay.n_rows <= n, "embed rows {} > rows {n}", lay.n_rows);
    let z = SecureField::zero();
    let zb = BaseField::zero();

    // ── Channel logical columns ──
    let mut ch: Vec<Vec<BaseField>> = vec![vec![zb; n]; CHANNEL_COLS];
    let mut ch_is_first = vec![zb; n];
    let mut is_rc_draw = vec![zb; n];

    let mut digest = [zb; 8];
    let mut n_draws = 0u32;
    let mut expect_pow2 = false;
    let mut prev_out = [zb; N_STATE];
    let n_real = records.len();

    for row in 0..n {
        let (kind, input, output, first_chunk) = if row < n_real {
            let r = records[row];
            (r.kind, r.input, r.output, r.first_chunk)
        } else {
            // Padding: synthetic squeeze threading the running digest.
            let mut inp = [zb; N_STATE];
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

        let mut absorbed = [zb; 8];
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
            (zb, zb)
        };

        let (mut digest_next, n_draws_next) = match kind {
            PermKind::Absorb => {
                let mut d = [zb; 8];
                d.copy_from_slice(&output[..8]);
                (d, 0u32)
            }
            PermKind::Squeeze => (digest_in, n_draws_in + 1),
            PermKind::Pow => (digest_in, n_draws_in),
        };
        if is_pow1 == 1 || is_pow2 == 1 {
            digest_next = digest_in;
        }

        let mut col = 0usize;
        let put = |ch: &mut Vec<Vec<BaseField>>, v: BaseField, col: &mut usize| {
            ch[*col][row] = v;
            *col += 1;
        };
        for v in record_permutation(input) {
            put(&mut ch, v, &mut col);
        }
        for v in digest_in {
            put(&mut ch, v, &mut col);
        }
        put(&mut ch, BaseField::from(n_draws_in), &mut col);
        for v in [is_absorb, is_squeeze, is_pow1, is_pow2, is_cont] {
            put(&mut ch, BaseField::from(v), &mut col);
        }
        for v in absorbed {
            put(&mut ch, v, &mut col);
        }
        put(&mut ch, nonce_lo, &mut col);
        put(&mut ch, nonce_hi, &mut col);
        for v in &output[0..8] {
            put(&mut ch, *v, &mut col);
        }
        for v in &output[8..16] {
            put(&mut ch, *v, &mut col);
        }
        for v in digest_next {
            put(&mut ch, v, &mut col);
        }
        put(&mut ch, BaseField::from(n_draws_next), &mut col);
        let s2_0 = if is_pow2 == 1 { output[0].0 } else { 0 };
        for k in 0..M31_BITS {
            put(&mut ch, BaseField::from((s2_0 >> k) & 1), &mut col);
        }
        debug_assert_eq!(col, CHANNEL_COLS);

        if row == 0 {
            ch_is_first[row] = BaseField::one();
        }
        if row == rc_row {
            is_rc_draw[row] = BaseField::one();
        }

        digest = digest_next;
        n_draws = n_draws_next;
        prev_out = output;
    }

    // ── Embed QM31 logical columns ──
    let mut emb_q: Vec<Vec<SecureField>> = Vec::with_capacity(embed_qm31_cols());
    for j in 0..NLEAF {
        emb_q.push(
            (0..n)
                .map(|i| {
                    if i < lay.n_rows {
                        lay.leaf_val[i][j]
                    } else {
                        z
                    }
                })
                .collect(),
        );
    }
    for l in 0..OPS_S {
        emb_q.push(
            (0..n)
                .map(|i| {
                    if i < lay.n_rows {
                        lay.slot_oa_val[i][l]
                    } else {
                        z
                    }
                })
                .collect(),
        );
        emb_q.push(
            (0..n)
                .map(|i| {
                    if i < lay.n_rows {
                        lay.slot_ob_val[i][l]
                    } else {
                        z
                    }
                })
                .collect(),
        );
        emb_q.push(
            (0..n)
                .map(|i| if i < lay.n_rows { lay.slot_r[i][l] } else { z })
                .collect(),
        );
    }
    for s in 0..N_LATCHED {
        emb_q.push(vec![lay.latched_value[s]; n]);
    }
    debug_assert_eq!(emb_q.len(), embed_qm31_cols());

    // ── Preprocessed logical columns, in registration order ──
    let mut pre_b: Vec<Vec<BaseField>> = Vec::new();
    pre_b.push(
        (0..n)
            .map(|i| if i + 1 < n { BaseField::one() } else { zb })
            .collect(),
    ); // not_last
    pre_b.push(ch_is_first);
    pre_b.push(is_rc_draw);
    for l in 0..OPS_S {
        pre_b.push(
            (0..n)
                .map(|i| {
                    if i == lay.final_row && l == lay.final_lane {
                        BaseField::one()
                    } else {
                        zb
                    }
                })
                .collect(),
        );
    }
    for l in 0..OPS_S {
        for r in 0..2 {
            let mut cst = vec![z; n];
            for i in 0..lay.n_rows {
                let rec = if r == 0 {
                    &lay.slot_oa[i][l]
                } else {
                    &lay.slot_ob[i][l]
                };
                cst[i] = rec.constant;
            }
            for c in 0..SECURE_EXTENSION_DEGREE {
                pre_b.push(cst.iter().map(|q| q.to_m31_array()[c]).collect());
            }
            let mut coeff = vec![vec![z; n]; WIN];
            for i in 0..lay.n_rows {
                let rec = if r == 0 {
                    &lay.slot_oa[i][l]
                } else {
                    &lay.slot_ob[i][l]
                };
                for (pos, c) in &rec.terms {
                    coeff[win_index(pos)][i] += *c;
                }
            }
            for p in 0..WIN {
                for c in 0..SECURE_EXTENSION_DEGREE {
                    pre_b.push(coeff[p].iter().map(|q| q.to_m31_array()[c]).collect());
                }
            }
        }
    }

    // ── Flatten + storage-index both trees ──
    let domain = CanonicCoset::new(log_size).circle_domain();
    let wrap = |logical: Vec<BaseField>| {
        let mut c = Col::<CpuBackend, BaseField>::zeros(n);
        for (i, v) in logical.into_iter().enumerate() {
            c.set(storage_index(i, log_size), v);
        }
        CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, c)
    };

    let preprocessed: Vec<_> = pre_b.into_iter().map(wrap).collect();

    let mut main_logical: Vec<Vec<BaseField>> = ch;
    for q in &emb_q {
        for c in 0..SECURE_EXTENSION_DEGREE {
            main_logical.push(q.iter().map(|v| v.to_m31_array()[c]).collect());
        }
    }
    if final_tamper {
        // Bump the embed's final-slot oa base column on the final row.
        let oa_col = CHANNEL_COLS + (NLEAF + lay.final_lane * 3) * SECURE_EXTENSION_DEGREE;
        main_logical[oa_col][lay.final_row] += BaseField::one();
    }
    let main: Vec<_> = main_logical.into_iter().map(wrap).collect();

    ChildTrace {
        preprocessed,
        main,
        log_size,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Real-segment driver.
// ─────────────────────────────────────────────────────────────────────────────

/// Prove a small but genuine program as ONE full 31-component canonical segment.
fn canonical_segment() -> (Proof, SideNote) {
    use javm::PVM_REGISTER_COUNT;
    use javm::instruction::Opcode;
    use javm::interpreter::Interpreter;
    use zkpvm::core::tracing::TracingPvm;
    use zkpvm::prove_canonical;

    let code = vec![
        Opcode::Add64 as u8,
        0x10,
        2,
        Opcode::Add64 as u8,
        0x12,
        3,
        Opcode::Add64 as u8,
        0x13,
        4,
        Opcode::Add64 as u8,
        0x14,
        5,
        Opcode::Add64 as u8,
        0x15,
        6,
        Opcode::Add64 as u8,
        0x16,
        7,
        Opcode::Trap as u8,
    ];
    let bitmask: Vec<u8> = vec![1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1];
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 1;
    let initial_memory = vec![0u8; 4 * 1024 * 1024];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        initial_memory.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), javm::ExitReason::Trap);
    let steps = tracing.into_trace();
    let mut sn = SideNote::new(steps, code, bitmask).with_memory(initial_memory);
    let proof = prove_canonical(&mut sn, &[]).expect("prove_canonical under Poseidon2-M31");
    (proof, sn)
}

/// Everything the assembly AIR is driven from: the real transcript records, the
/// rc-draw row, the co-locate embed layout, and the channel log_size.
struct ChildInputs {
    records: Vec<PermRecord>,
    rc_row: usize,
    lay: ColocateLayout,
    log_size: u32,
}

fn build_inputs() -> ChildInputs {
    use zkpvm::framework_access::drive_chip_oods;
    use zkpvm::{chip_idx, reconstruct_oods_for_recursion, record_canonical_transcript};

    let (proof, sn) = canonical_segment();
    assert_eq!(
        proof.num_components,
        chip_idx::COUNT,
        "canonical proof must carry all 31 components"
    );

    // Channel transcript + the composition-rc draw row.
    let transcript = record_canonical_transcript(&proof, &sn);
    let records = transcript.records;
    let prefix_len = transcript.prefix_len;
    let rc_row = records
        .iter()
        .enumerate()
        .position(|(i, r)| i >= prefix_len && r.kind == PermKind::Squeeze)
        .expect("a squeeze at/after prefix_len (the composition random_coeff)");

    // Streamed OODS embed layout from the SAME segment's reconstructed OODS data.
    let r = reconstruct_oods_for_recursion(&proof, &sn);
    let component_masks: Vec<ComponentMask> = r
        .component_masks
        .into_iter()
        .map(|m| ComponentMask {
            mask: m.mask,
            preproc_indices: m.preproc_indices,
        })
        .collect();
    let backend = StreamBackend::new(
        component_masks,
        r.random_coeff,
        r.denom_inverse,
        r.oods_x_doubled,
        r.comp_mask,
    );
    let ctx = Rc::new(RefCell::new(backend));
    let lookup = &r.lookup_elements;
    drive_multi(&ctx, &r.comps, |idx, ls, e| {
        drive_chip_oods(idx, ls, lookup, e)
    });
    let capture = Rc::try_unwrap(ctx)
        .unwrap_or_else(|_| panic!("a Handle outlived the real capture walk"))
        .into_inner()
        .finish();
    let lay = capture
        .schedule_two_stream(T_PER_MAC)
        .layout_colocate(OPS_S, NLEAF);

    // The component spans max(transcript rows, embed rows); the transcript
    // dominates (8584 perms vs 6251 stream rows).
    let log_size = records
        .len()
        .max(lay.n_rows)
        .next_power_of_two()
        .trailing_zeros()
        .max(1);

    ChildInputs {
        records,
        rc_row,
        lay,
        log_size,
    }
}

fn prove_and_verify(trace: ChildTrace) -> Result<(), String> {
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
    let component = FrameworkComponent::<ChildEval>::new(
        &mut alloc,
        ChildEval {
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

/// FAST gate: the merged trace satisfies the AIR (AssertEvaluator) on the REAL
/// channel + embed data — catches value bugs before the heavy prove.
#[test]
#[ignore = "heavy: prove_canonical builds a real 31-component segment (~30s release)"]
fn child_assembly_air_satisfied() {
    let inp = build_inputs();
    let trace = gen_trace(
        &inp.records,
        inp.rc_row,
        &inp.lay,
        inp.log_size,
        None,
        false,
    );
    let log_size = trace.log_size;
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
            ChildEval {
                log_n_rows: log_size,
            }
            .evaluate(e);
        },
        SecureField::zero(),
    );
    eprintln!(
        "child_assembly_air_satisfied: REAL segment — channel ({} perms) + streamed OODS embed \
         ({} stream rows) merged in ONE component at log {log_size}; rc latched to the channel's \
         composition-rc squeeze (row {}). main {} M31 cols, preproc {} M31 cols. Trace satisfies \
         the AIR.",
        inp.records.len(),
        inp.lay.n_rows,
        inp.rc_row,
        CHANNEL_COLS + embed_qm31_cols() * SECURE_EXTENSION_DEGREE,
        preproc_ids().len(),
    );
}

/// THE GATE (heavy): the merged per-child component proves+verifies a REAL
/// canonical segment at degree ≤ 2; a tampered transcript value (→ derived rc
/// diverges) and a tampered embed value are each rejected.
#[test]
#[ignore = "heavy: real-segment channel+embed assembly prove+verify (release, minutes)"]
fn child_assembly_gate() {
    let inp = build_inputs();

    prove_and_verify(gen_trace(
        &inp.records,
        inp.rc_row,
        &inp.lay,
        inp.log_size,
        None,
        false,
    ))
    .expect("honest per-child assembly must prove+verify at degree ≤ 2");

    // Reject: corrupt a channel absorbed value (the transcript binding).
    let absorb_row = inp
        .records
        .iter()
        .position(|r| r.kind == PermKind::Absorb)
        .expect("transcript has an absorb");
    assert!(
        prove_and_verify(gen_trace(
            &inp.records,
            inp.rc_row,
            &inp.lay,
            inp.log_size,
            Some(absorb_row),
            false,
        ))
        .is_err(),
        "a corrupted transcript value must be rejected"
    );

    // Reject: corrupt the embed composition (the final-slot oa value).
    assert!(
        prove_and_verify(gen_trace(
            &inp.records,
            inp.rc_row,
            &inp.lay,
            inp.log_size,
            None,
            true,
        ))
        .is_err(),
        "a corrupted embed value must be rejected"
    );

    eprintln!(
        "child_assembly_gate GREEN @ log {}: ONE uniform component replays a REAL canonical \
         segment's {}-perm transcript AND re-evaluates its full 31-component OODS composition \
         (streamed embed, {} stream rows), with the embed's rc latched to the channel's \
         composition-rc squeeze — proving+verifying through the lifted Poseidon2-M31 protocol at \
         degree ≤ 2; a tampered transcript value and a tampered embed value are rejected.",
        inp.log_size,
        inp.records.len(),
        inp.lay.n_rows,
    );
}
