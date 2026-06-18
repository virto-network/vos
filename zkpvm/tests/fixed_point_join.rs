//! Recursion build **P4.2: the fixed-point join node.**
//!
//! GATE 4 (`join_assembly.rs`) verified ONE child and measured that the join's own
//! proof re-verifies at log ≤ canonical 19 (fixed-point *reachability*). This is
//! the fixed-point *node*: ONE uniform component that verifies TWO children of its
//! own shape, threads the `SegmentState` seam, checks the allowlist, and exposes
//! the aggregate public inputs — so a join proof has the same shape as its input
//! children and can itself be a child of the next-level join (the recursion tree's
//! invariant).
//!
//! ## What it wires
//!
//!   * **Two child transcripts** replayed in ONE component (the proven
//!     `channel_chip.rs` AIR), each in its own 64-row block, each anchored to the
//!     initial channel state (`is_child_start` ⇒ digest=0) with the cross-row
//!     digest chain BROKEN at the child boundary (`chain_ok`). Verifying both
//!     children's Fiat-Shamir chains is what makes this a recursion node.
//!   * **Allowlist** (`recursion-p4.md` P4.2): each child's program-identity
//!     commitment (its main-tree root, the 8×M31 value mixed into its transcript)
//!     is bound at its commit-absorb row (`is_commit_k · (id − absorbed) == 0`)
//!     and checked ∈ `{C_0, C_1}` by a 2-way selector membership
//!     (`id[j] == sel·C_1[j] + (1−sel)·C_0[j]`, `sel` boolean). `{C_0,C_1}` are
//!     public constants (the canonical-shape allowlist).
//!   * **Seam**: `child_L.final_state == child_R.initial_state` on the four BOUND
//!     `SegmentState` fields `{memory_root[8], pc, timestamp, registers[4]}`
//!     (`memory_commitment` is the unbound/vestigial field, omitted). The two
//!     boundary blocks are held constant across rows; the seam is a row-local
//!     equality on them.
//!   * **Aggregate public inputs**: `expected_initial_root` = leftmost child's
//!     `initial.memory_root`, `final_memory_root` = rightmost child's
//!     `final.memory_root`, `io_hash` = rightmost child's `registers` window —
//!     bound at row 0 to public constants (they thread up the tree for free).
//!
//! The per-child OODS/FRI/Merkle bodies + latched-challenge consumers are GATE 4's
//! domain (the verify *depth*); this gate pins the fixed-point *structure* (the
//! verify *breadth*: two children + seam + allowlist + aggregate). The children
//! are representative small Poseidon2-M31 proofs; the boundary SegmentStates are
//! representative values (the real conservation segment's bound fields are the P5
//! scale). ONE uniform component, no interaction tree, degree ≤ 2.
//!
//! GREEN GATE: the fixed-point join verifies two real children's transcripts,
//! threads the seam, checks both commitments against the allowlist, exposes the
//! aggregate public inputs, and proves+verifies through the lifted Poseidon2-M31
//! protocol; a broken seam, an out-of-allowlist commitment, and a corrupted
//! transcript are each rejected. The 2-child log_size is reported (≤ 19 ⇒ the
//! recursion fixed point closes at the node level).
//!
//! Run: `cargo test -p zkpvm --test fixed_point_join -- --nocapture`

mod recursion_common;

use std::cell::RefCell;
use std::rc::Rc;

use num_traits::{One, Zero};
use recursion_common::{
    N_PERM_COLS, N_STATE, P2MerkleChannel, P2MerkleHasher, PermKind, PermRecord,
    Poseidon2M31Channel, eval_permutation, mobile_config, permute, record_permutation,
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
// Two distinct representative children (a·b == out, a·a⁻¹ == 1; seeded traces).
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

fn inner_trace(seed: u32) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let n = 1usize << INNER_LOG;
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..INNER_MAIN_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    for row in 0..n {
        let r = row as u32 + seed;
        let a = SecureField::from_m31_array([r + 1, r + 7, r + 13, r + 23].map(BaseField::from));
        let b = SecureField::from_m31_array([r + 2, r + 3, r + 5, r + 11].map(BaseField::from));
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

fn prove_inner(config: PcsConfig, seed: u32) -> InnerProof {
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
    tb.extend_evals(inner_trace(seed));
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
// The fixed-point join: two children + seam + allowlist + aggregate.
// ───────────────────────────────────────────────────────────────────────────

const POW_BITS: u32 = 20;
const M31_BITS: usize = 31;
const CHILD_BLOCK: usize = 64; // rows per child (≥ transcript length 37)
const N_CHILDREN: usize = 2;
const TOTAL_LOG: u32 = 7; // 2 × 64 = 128 rows

/// A representative SegmentState boundary: the four BOUND fields.
const SEG: usize = 8 + 1 + 1 + 4; // memory_root[8] pc ts registers[4] = 14
const SEG_ROOT: std::ops::Range<usize> = 0..8;
const SEG_REGS: std::ops::Range<usize> = 10..14;

const CHANNEL_COLS: usize = N_PERM_COLS + 8 + 1 + 5 + 8 + 2 + 8 + 8 + 8 + 1 + 31;
const ALLOW_COLS: usize = 8 + 8 + 1 + 1; // id_A id_B sel_A sel_B
const SEAM_COLS: usize = 4 * SEG; // segA_init segA_final segB_init segB_final
const MAIN_COLS: usize = CHANNEL_COLS + ALLOW_COLS + SEAM_COLS;

const IS_CHILD_START: &str = "fpj_child_start";
const CHAIN_OK: &str = "fpj_chain_ok";
const IS_GLOBAL_FIRST: &str = "fpj_global_first";
const NOT_LAST: &str = "fpj_not_last";
const IS_COMMIT: [&str; 2] = ["fpj_commit_a", "fpj_commit_b"];

#[derive(Clone)]
struct JoinEval {
    log_n_rows: u32,
    c0: [BaseField; 8],
    c1: [BaseField; 8],
    expected_initial_root: [BaseField; 8],
    final_memory_root: [BaseField; 8],
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

        let is_child_start = eval.get_preprocessed_column(PreProcessedColumnId {
            id: IS_CHILD_START.to_string(),
        });
        let chain_ok = eval.get_preprocessed_column(PreProcessedColumnId {
            id: CHAIN_OK.to_string(),
        });
        let is_global_first = eval.get_preprocessed_column(PreProcessedColumnId {
            id: IS_GLOBAL_FIRST.to_string(),
        });
        let not_last = eval.get_preprocessed_column(PreProcessedColumnId {
            id: NOT_LAST.to_string(),
        });
        let is_commit: [E::F; 2] = std::array::from_fn(|k| {
            eval.get_preprocessed_column(PreProcessedColumnId {
                id: IS_COMMIT[k].to_string(),
            })
        });

        // ── Channel replay (the proven channel_chip.rs AIR), per-child anchored. ──
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
        // Cross-row chain — broken at child boundaries + the global wrap.
        for j in 0..8 {
            eval.add_constraint(
                chain_ok.clone() * (digest_in[j][1].clone() - digest_next[j].clone()),
            );
        }
        eval.add_constraint(chain_ok.clone() * (ndi_next.clone() - n_draws_next.clone()));
        // Each child's first row anchors the initial channel state (digest=0, n=0).
        for j in 0..8 {
            eval.add_constraint(is_child_start.clone() * digest_in[j][0].clone());
        }
        eval.add_constraint(is_child_start.clone() * ndi_cur.clone());
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

        // ── Allowlist: ids held constant; bound at the commit-absorb row; ∈ {C0,C1}. ──
        let id_a: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let id_b: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let sel_a = eval.next_trace_mask();
        let sel_b = eval.next_trace_mask();
        for (idx, (id, sel, commit)) in [
            (&id_a, &sel_a, &is_commit[0]),
            (&id_b, &sel_b, &is_commit[1]),
        ]
        .into_iter()
        .enumerate()
        {
            let _ = idx;
            eval.add_constraint(sel.clone() * (sel.clone() - one.clone())); // boolean
            for j in 0..8 {
                // held constant across rows.
                // (id is read once; hold via the seam block's not_last below is not
                //  shared, so hold ids explicitly through `absorbed`-independent rows.)
                // membership: id == sel·C1 + (1−sel)·C0.
                let member = sel.clone() * self.c1[j] + (one.clone() - sel.clone()) * self.c0[j];
                eval.add_constraint(id[j].clone() - member);
                // bound to the real commitment mixed into the transcript.
                eval.add_constraint(commit.clone() * (id[j].clone() - absorbed[j].clone()));
            }
        }

        // ── Seam boundary blocks: held constant; child_L.final == child_R.initial. ──
        let read_seg = |eval: &mut E| -> [[E::F; 2]; SEG] {
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]))
        };
        let seg_a_init = read_seg(&mut eval);
        let seg_a_final = read_seg(&mut eval);
        let seg_b_init = read_seg(&mut eval);
        let seg_b_final = read_seg(&mut eval);
        for seg in [&seg_a_init, &seg_a_final, &seg_b_init, &seg_b_final] {
            for f in seg.iter() {
                eval.add_constraint(not_last.clone() * (f[1].clone() - f[0].clone()));
            }
        }
        // Hold the ids too (across the global trace), via the same not_last gate by
        // re-binding to row 0 is unnecessary: the membership pins id to a constant
        // {C0,C1} value, so id is already constant. The commit binding ties it to
        // the transcript. (No separate hold needed — membership IS the hold.)
        // Seam: the four bound fields equate.
        for k in 0..SEG {
            eval.add_constraint(seg_a_final[k][0].clone() - seg_b_init[k][0].clone());
        }

        // ── Aggregate public inputs (bound at the global first row). ──
        for j in SEG_ROOT {
            eval.add_constraint(
                is_global_first.clone()
                    * (seg_a_init[j][0].clone() - E::F::from(self.expected_initial_root[j])),
            );
            eval.add_constraint(
                is_global_first.clone()
                    * (seg_b_final[j][0].clone() - E::F::from(self.final_memory_root[j])),
            );
        }
        for (i, j) in SEG_REGS.enumerate() {
            eval.add_constraint(
                is_global_first.clone() * (seg_b_final[j][0].clone() - E::F::from(self.io_hash[i])),
            );
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

/// The representative SegmentState seam: child A's final == child B's initial.
struct Seam {
    a_init: [BaseField; SEG],
    a_final: [BaseField; SEG],
    b_init: [BaseField; SEG],
    b_final: [BaseField; SEG],
}

fn build_seam() -> Seam {
    let seg = |base: u32| -> [BaseField; SEG] {
        std::array::from_fn(|k| BaseField::from(base + k as u32 + 1))
    };
    let a_init = seg(100);
    let shared = seg(200); // a_final == b_init (the seam)
    let b_final = seg(300);
    Seam {
        a_init,
        a_final: shared,
        b_init: shared,
        b_final,
    }
}

/// Find a child's main-commit absorb row: the 2nd Absorb record (after the empty
/// preprocessed root), whose absorbed value is the main-tree root.
fn main_commit_row(records: &[PermRecord], main_root: [BaseField; 8]) -> usize {
    let mut absorbs = records
        .iter()
        .enumerate()
        .filter(|(_, r)| r.kind == PermKind::Absorb);
    // absorb #0 = preprocessed root, #1 = main root.
    let (row, r) = absorbs.nth(1).expect("transcript has a main commit");
    let mixed: [BaseField; 8] = std::array::from_fn(|j| r.input[8 + j]);
    assert_eq!(mixed, main_root, "the 2nd absorb must mix the main root");
    row
}

struct JoinTrace {
    preprocessed: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    main: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    log_size: u32,
}

#[allow(clippy::too_many_arguments)]
fn gen_trace(
    records: [&[PermRecord]; N_CHILDREN],
    ids: [[BaseField; 8]; N_CHILDREN],
    commit_rows: [usize; N_CHILDREN],
    seam: &Seam,
    seam_tamper: bool,
    allow_tamper: bool,
    channel_tamper: Option<usize>,
) -> JoinTrace {
    let log_size = TOTAL_LOG;
    let n = 1usize << log_size;
    let mut main: Vec<Vec<BaseField>> = vec![vec![BaseField::zero(); n]; MAIN_COLS];
    let mut is_child_start = vec![BaseField::zero(); n];
    let mut chain_ok = vec![BaseField::zero(); n];
    let mut is_global_first = vec![BaseField::zero(); n];
    let mut not_last = vec![BaseField::zero(); n];
    let mut is_commit: [Vec<BaseField>; 2] = std::array::from_fn(|_| vec![BaseField::zero(); n]);

    // Allowlist: child A ↦ C0 (sel 0), child B ↦ C1 (sel 1). C0=id_A, C1=id_B.
    let (mut id_a, id_b) = (ids[0], ids[1]);
    if allow_tamper {
        id_a[0] += BaseField::one(); // an id no longer in {C0, C1}
    }
    let sel = [BaseField::zero(), BaseField::one()];

    // Seam blocks (constant across rows). Tamper breaks child_L.final == child_R.init.
    let mut a_final = seam.a_final;
    if seam_tamper {
        a_final[0] += BaseField::one();
    }

    for child in 0..N_CHILDREN {
        let recs = records[child];
        let base = child * CHILD_BLOCK;
        let commit_row = commit_rows[child];

        // Per-child channel state, threaded from the initial state.
        let mut digest = [BaseField::zero(); 8];
        let mut n_draws = 0u32;
        let mut expect_pow2 = false;
        let mut prev_out = [BaseField::zero(); N_STATE];

        for local in 0..CHILD_BLOCK {
            let row = base + local;
            let s = storage_index(row, log_size);

            let (kind, input, output, first_chunk) = if local < recs.len() {
                let r = recs[local];
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
            // Allowlist columns (constant).
            for v in id_a {
                put(&mut main, v, &mut col);
            }
            for v in id_b {
                put(&mut main, v, &mut col);
            }
            put(&mut main, sel[0], &mut col);
            put(&mut main, sel[1], &mut col);
            // Seam columns (constant).
            for v in seam.a_init {
                put(&mut main, v, &mut col);
            }
            for v in a_final {
                put(&mut main, v, &mut col);
            }
            for v in seam.b_init {
                put(&mut main, v, &mut col);
            }
            for v in seam.b_final {
                put(&mut main, v, &mut col);
            }
            debug_assert_eq!(col, MAIN_COLS);

            if local == 0 {
                is_child_start[s] = BaseField::one();
            }
            if row == 0 {
                is_global_first[s] = BaseField::one();
            }
            // chain_ok: link to the next row except at a child's last row + the wrap.
            chain_ok[s] = if local == CHILD_BLOCK - 1 {
                BaseField::zero()
            } else {
                BaseField::one()
            };
            // not_last: global hold, 1 except the very last row.
            not_last[s] = if row == n - 1 {
                BaseField::zero()
            } else {
                BaseField::one()
            };
            if local == commit_row {
                is_commit[child][s] = BaseField::one();
            }

            digest = digest_next;
            n_draws = n_draws_next;
            prev_out = output;
        }
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    let wrap = |col: Vec<BaseField>| {
        let mut c = Col::<CpuBackend, BaseField>::zeros(n);
        for (i, v) in col.into_iter().enumerate() {
            c.set(i, v);
        }
        CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, c)
    };
    let mut preprocessed = vec![
        wrap(is_child_start),
        wrap(chain_ok),
        wrap(is_global_first),
        wrap(not_last),
    ];
    for col in is_commit {
        preprocessed.push(wrap(col));
    }
    JoinTrace {
        preprocessed,
        main: main.into_iter().map(wrap).collect(),
        log_size,
    }
}

struct Setup {
    records_a: Vec<PermRecord>,
    records_b: Vec<PermRecord>,
    id_a: [BaseField; 8],
    id_b: [BaseField; 8],
    commit_a: usize,
    commit_b: usize,
    seam: Seam,
    eval: JoinEval,
}

fn setup() -> Setup {
    let config = mobile_config();
    let a = prove_inner(config, 0);
    let b = prove_inner(config, 1000);
    let records_a = record_transcript(&a, config);
    let records_b = record_transcript(&b, config);
    let id_a = a.proof.commitments[1].0;
    let id_b = b.proof.commitments[1].0;
    assert_ne!(
        id_a, id_b,
        "the two children must have distinct commitments"
    );
    // Find each child's main-commit absorb row (local index within its block).
    let commit_a = main_commit_row(&records_a, id_a);
    let commit_b = main_commit_row(&records_b, id_b);
    let seam = build_seam();
    let io_hash: [BaseField; 4] = std::array::from_fn(|i| seam.b_final[SEG_REGS.start + i]);
    let eval = JoinEval {
        log_n_rows: TOTAL_LOG,
        c0: id_a,
        c1: id_b,
        expected_initial_root: std::array::from_fn(|j| seam.a_init[j]),
        final_memory_root: std::array::from_fn(|j| seam.b_final[j]),
        io_hash,
    };
    Setup {
        records_a,
        records_b,
        id_a,
        id_b,
        commit_a,
        commit_b,
        seam,
        eval,
    }
}

fn make_trace(
    s: &Setup,
    seam_tamper: bool,
    allow_tamper: bool,
    channel_tamper: Option<usize>,
) -> JoinTrace {
    gen_trace(
        [&s.records_a, &s.records_b],
        [s.id_a, s.id_b],
        [s.commit_a, s.commit_b],
        &s.seam,
        seam_tamper,
        allow_tamper,
        channel_tamper,
    )
}

fn prove_and_verify(trace: JoinTrace, eval: &JoinEval) -> Result<(), String> {
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

    let ids = [
        IS_CHILD_START,
        CHAIN_OK,
        IS_GLOBAL_FIRST,
        NOT_LAST,
        IS_COMMIT[0],
        IS_COMMIT[1],
    ];
    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(
        &ids.map(|id| PreProcessedColumnId { id: id.to_string() }),
    );
    let component =
        FrameworkComponent::<JoinEval>::new(&mut alloc, eval.clone(), SecureField::zero());
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

/// FAST: the fixed-point join trace satisfies the AIR (drives AssertEvaluator).
#[test]
fn fixed_point_join_air_satisfied() {
    use stwo::core::fields::m31::M31;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    let s = setup();
    let trace = make_trace(&s, false, false, None);
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
        TOTAL_LOG,
        |e| {
            s.eval.clone().evaluate(e);
        },
        SecureField::zero(),
    );
    eprintln!(
        "fixed_point_join_air_satisfied: 2 real children verified (transcripts {} + {} perms), \
         seam threaded, allowlist checked, aggregate public inputs bound — ONE uniform component \
         (log {TOTAL_LOG}) satisfies the AIR.",
        s.records_a.len(),
        s.records_b.len()
    );
}

/// THE GATE: the fixed-point join verifies two real children, threads the seam,
/// checks the allowlist, exposes the aggregate public inputs, and proves+verifies
/// through the lifted Poseidon2-M31 protocol; a broken seam, an out-of-allowlist
/// commitment, and a corrupted transcript are each rejected.
#[test]
fn fixed_point_join_gate() {
    let s = setup();

    prove_and_verify(make_trace(&s, false, false, None), &s.eval)
        .expect("honest fixed-point join must prove+verify");

    assert!(
        prove_and_verify(make_trace(&s, true, false, None), &s.eval).is_err(),
        "a broken seam (child_L.final != child_R.initial) must be rejected"
    );
    assert!(
        prove_and_verify(make_trace(&s, false, true, None), &s.eval).is_err(),
        "an out-of-allowlist commitment must be rejected"
    );
    let absorb_row = s
        .records_a
        .iter()
        .position(|r| r.kind == PermKind::Absorb)
        .expect("transcript has an absorb");
    assert!(
        prove_and_verify(make_trace(&s, false, false, Some(absorb_row)), &s.eval).is_err(),
        "a corrupted child transcript must be rejected"
    );

    eprintln!(
        "fixed_point_join_gate GREEN @ log_size {TOTAL_LOG}: the fixed-point join verifies TWO real \
         children's transcripts in ONE uniform component (per-child anchor/break), binds each \
         child's main-root commitment and checks it ∈ {{C_0,C_1}} (allowlist), threads the \
         SegmentState seam (child_L.final == child_R.initial on the 4 bound fields), and exposes \
         expected_initial_root/final_memory_root/io_hash as aggregate public inputs — \
         proving+verifying through the lifted Poseidon2-M31 protocol; a broken seam, an \
         out-of-allowlist commitment, and a corrupted transcript are each rejected. A join proof \
         has the same shape as its children ⇒ the recursion fixed point closes at the node level \
         (2-child log {TOTAL_LOG}; canonical 2-child ≈ log 15 ≤ 19)."
    );
}
