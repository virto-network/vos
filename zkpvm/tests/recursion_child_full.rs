#![cfg(feature = "poseidon2-channel")]

//! Recursion build P5.3 — **the FULL per-child verifier (step 5 integration).**
//!
//! This file FUSES the proven recursion mechanisms into ONE uniform `FrameworkEval`
//! at the real per-child scale: the channel transcript replay + streamed
//! 31-component OODS embed + latched challenges + claimed-sum balance + boundary
//! recompute (all proven in `recursion_child_assembly`), PLUS the streamed
//! multi-tree Merkle decommit (`recursion_decommit_scale`) sharing ONE
//! `eval_permutation` per row via a preprocessed row-type selector
//! (`recursion_shared_perm`). The FRI fold chain + FRI-layer decommit + DEEP
//! reconstruction land in later steps.
//!
//! `recursion_child_assembly` stays the proven log-14 regression gate. The first
//! step here is **`is_transcript` gating**: the channel block's structural
//! constraints fold behind a preprocessed `is_transcript` selector (the digest
//! chain uses a preprocessed `not_last_tr = is_transcript[i]·is_transcript[i+1]`,
//! degree 2; latched constancy keeps the FULL `not_last`), so the channel only
//! constrains transcript rows and the merkle rows drive the shared perm slot. With
//! an empty merkle region this proves identically to the assembly — the safe
//! checkpoint — then a real streamed decommit region rides the freed slot.
//!
//! Original assembly mechanism notes follow:
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
//!     the channel's.
//!   * **OODS-point derivation (step 1b)** — the embed's `dinv` (`latched[1]`) and
//!     `ox` (`latched[2]`) are DERIVED in-circuit from a latched `oods_t` (bound to
//!     its squeeze, the 2nd `Squeeze` at/after `prefix_len`, via `is_oods_draw`):
//!     the `get_random_point` map gives the OODS point, then `ox =
//!     double_x^{mlbd-1}(oods.x)` and `dinv = 1/coset_vanishing(coset, oods)` (a
//!     shift by the fixed coset point `C`, then a `double_x` chain). All degree ≤ 2.
//!     This removes two more trusted host inputs. (comp/lookup latches + the embed
//!     leaves are bound via the FRI/DEEP + Merkle path in steps 2–3.)
//!   * **claimed-sum balance (step 4a)** — the 31 per-component `claimed_sums` are
//!     bound to the channel's `mix_felts(claimed_sums)` absorb (16 RATE-8 chunks,
//!     the last prefix perms before the interaction commit; chunk `c` carries
//!     `claimed_sum[2c]`/`[2c+1]` in `absorbed[0..4]`/`[4..8]`), then `Σ
//!     claimed_sums == 0` is enforced in-AIR — the global logup-balance check
//!     (`verify.rs:299`).
//!   * **boundary public-input recompute (step 4b)** — the 4 boundary chips'
//!     claimed sums are RECOMPUTED in-AIR from the PUBLIC boundary states (initial/
//!     final registers, pc, ts, memory roots) and each compared to its (step-4a-
//!     bound) `claimed_sum`, binding the io-hash (`final.registers[9..13]`) + the
//!     memory roots (`verify.rs:318` → `check_boundary_claimed_sums`). Each chip's
//!     sum is `Σ 1/⟨z, tuple⟩` where `⟨z, tuple⟩ = Σ alpha^i·tuple_i − z`; the three
//!     relations' `(z, alpha)` are latched to their draw squeezes (each from ONE
//!     `draw_secure_felts(2)`), `alpha`-powers derived in-AIR (witnessed chain), and
//!     each `1/⟨z, tuple⟩` a witnessed inverse — all degree ≤ 2. This is the
//!     federation cash-in (the public io-hash + roots are now bound in the
//!     verifier-AIR). (Connecting the embed's BAKED claimed_sums + lookup elements
//!     to these bound columns is a follow-on; the embed LEAVES bind via Merkle.)
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
//!     --test recursion_child_full -- --ignored --nocapture`

mod recursion_common;

use std::cell::RefCell;
use std::rc::Rc;

use num_traits::{One, Zero};
use recursion_common::oods_auto::{
    ColocateLayout, ComponentMask, N_LATCHED, StreamBackend, WinPos, drive_multi,
};
use recursion_common::{
    N_PERM_COLS, N_STATE, P2MerkleChannel, P2MerkleHasher, Poseidon2M31Channel, eval_permutation,
    hash_children_m31, mobile_config, permute, record_permutation,
};
use std::collections::HashMap;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::air::Component;
use stwo::core::fields::FieldExpOps;
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

// ── Merkle decommit layout (the streamed gadget, shared eval_permutation slot) ─
// Main columns the merkle region adds (after the channel block, before the embed):
// st[16] (the 16-wide sponge/hash state, read at [0,1]) + chunk[8] + sib[8] + bit
// + mux[8]. The perm (init/out) is SHARED with the channel via eval_permutation.
const MK_COLS: usize = N_STATE + 8 + 8 + 1 + 8; // 41
// Preprocessed row-type selectors (the segment-invariant decommit schedule).
const M_SPONGE: &str = "ca_m_sponge";
const M_NODE: &str = "ca_m_node";
const M_ROOT: &str = "ca_m_root";
const ZERO_ST: &str = "ca_zero_st";
const HASH_LINK: &str = "ca_hash_link";
const CAP_FWD: &str = "ca_cap_fwd";
/// Per-row pinned tree root (the recomputed root of each path's tree). Step 1b
/// pins this to the real commitment; step 2 binds it to the channel commit-absorb.
fn dc_root_id(j: usize) -> String {
    format!("ca_dc_root_{j}")
}

// ── Preprocessed column ids (the fixed routing "program") ────────────────────
// Registration / read / fill order: not_last, ch_is_first, is_rc_draw,
// is_oods_draw, is_cs_chunk[N_CS_CHUNKS], emb_final[OPS_S], then the recon program
// (per lane, side: const then coeffs).
const NOT_LAST: &str = "ca_not_last";
const CH_IS_FIRST: &str = "ca_is_first";
/// Row-type selector: 1 on the channel-transcript rows, 0 on the merkle/FRI
/// decommit rows. Gates the channel block's structural constraints.
const IS_TRANSCRIPT: &str = "ca_is_transcript";
/// `is_transcript[i] · is_transcript[i+1]` — the digest chain only threads WITHIN
/// the transcript region (keeps the chain constraint degree 2).
const NOT_LAST_TR: &str = "ca_not_last_tr";
const IS_RC_DRAW: &str = "ca_is_rc_draw";
const IS_OODS_DRAW: &str = "ca_is_oods_draw";

// Claimed-sum balance: the canonical proof has 31 per-component claimed sums
// (one QM31 each), absorbed via mix_felts(claimed_sums) = 124 M31 = 16 RATE-8
// chunks; chunk c carries claimed_sum[2c] (absorbed[0..4]) + claimed_sum[2c+1]
// (absorbed[4..8]).
const N_CS: usize = 31;
const N_CS_CHUNKS: usize = (N_CS * SECURE_EXTENSION_DEGREE).div_ceil(8); // 16
fn cs_chunk_id(c: usize) -> String {
    format!("ca_cs_chunk_{c}")
}

// Boundary relation-draw indicators (one per relation: register-memory,
// program-execution, merkle-node), firing on each relation's z/alpha draw squeeze.
const REL_DRAW_ID: [&str; N_BND_REL] = ["ca_rel_reg", "ca_rel_prog", "ca_rel_merkle"];

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
            id: IS_TRANSCRIPT.to_string(),
        },
        PreProcessedColumnId {
            id: NOT_LAST_TR.to_string(),
        },
    ];
    for id in [M_SPONGE, M_NODE, M_ROOT, ZERO_ST, HASH_LINK, CAP_FWD] {
        ids.push(PreProcessedColumnId { id: id.to_string() });
    }
    for j in 0..8 {
        ids.push(PreProcessedColumnId { id: dc_root_id(j) });
    }
    ids.extend([
        PreProcessedColumnId {
            id: IS_RC_DRAW.to_string(),
        },
        PreProcessedColumnId {
            id: IS_OODS_DRAW.to_string(),
        },
    ]);
    for c in 0..N_CS_CHUNKS {
        ids.push(PreProcessedColumnId { id: cs_chunk_id(c) });
    }
    for id in REL_DRAW_ID {
        ids.push(PreProcessedColumnId { id: id.to_string() });
    }
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
// Merkle decommit host machinery (adapted from recursion_decommit_scale): replay
// the lifted Merkle verify into per-path (leaf_row, bits, siblings), then stream
// each path as one perm/row (leaf sponge + each hash_children level).
// ─────────────────────────────────────────────────────────────────────────────

type Hash8 = [BaseField; 8];

fn sponge_leaf(row: &[BaseField]) -> Hash8 {
    let mut h = P2MerkleHasher::default();
    h.update_leaf(row);
    h.finalize().0
}

struct DecommitPath {
    leaf_row: Vec<BaseField>, // the sorted-by-log-size leaf row
    bits: Vec<u32>,
    sibs: Vec<Hash8>,
}

fn decommit_node_map(
    height: u32,
    root: Hash8,
    query_positions: &[usize],
    sorted_queried: &[Vec<BaseField>], // [w][n_queries] in SORTED column order
    hash_witness: &[Hash8],
) -> Vec<HashMap<usize, Hash8>> {
    let n_cols = sorted_queried.len();
    let mut node_map: Vec<HashMap<usize, Hash8>> = vec![HashMap::new(); (height + 1) as usize];
    let mut layer: Vec<(usize, Hash8)> = Vec::new();
    for (i, &pos) in query_positions.iter().enumerate() {
        let row: Vec<BaseField> = (0..n_cols).map(|c| sorted_queried[c][i]).collect();
        let leaf = sponge_leaf(&row);
        layer.push((pos, leaf));
        node_map[0].insert(pos, leaf);
    }
    let mut witness = hash_witness.iter();
    for level in 0..height as usize {
        let mut next: Vec<(usize, Hash8)> = Vec::new();
        let mut idx = 0;
        while idx < layer.len() {
            let (i0, h0) = layer[idx];
            let (children, consumed) = if idx + 1 < layer.len() && (i0 ^ 1) == layer[idx + 1].0 {
                ((h0, layer[idx + 1].1), 2)
            } else {
                let w = *witness.next().expect("witness too short");
                node_map[level].insert(i0 ^ 1, w);
                (if i0 & 1 == 0 { (h0, w) } else { (w, h0) }, 1)
            };
            let parent = hash_children_m31(&children.0, &children.1);
            next.push((i0 >> 1, parent));
            node_map[level + 1].insert(i0 >> 1, parent);
            idx += consumed;
        }
        layer = next;
    }
    assert!(witness.next().is_none(), "witness not fully consumed");
    assert_eq!(layer.len(), 1, "fold must reach a single root");
    assert_eq!(layer[0].1, root, "recomputed root must equal the commitment");
    node_map
}

/// All decommit paths for one tree: sort columns by log size (the lifted leaf
/// order), build per-position sorted leaf rows, replay the node map, extract paths.
fn tree_paths(
    queried: &[Vec<BaseField>], // [w][n_queries], commit order
    column_log_sizes: &[u32],
    height: u32,
    root: Hash8,
    hash_witness: &[Hash8],
    query_positions: &[usize],
) -> Vec<DecommitPath> {
    let w = queried.len();
    assert_eq!(column_log_sizes.len(), w);
    let mut order: Vec<usize> = (0..w).collect();
    order.sort_by_key(|&c| column_log_sizes[c]);
    let sorted_queried: Vec<Vec<BaseField>> = order.iter().map(|&c| queried[c].clone()).collect();

    let node_map = decommit_node_map(height, root, query_positions, &sorted_queried, hash_witness);
    query_positions
        .iter()
        .enumerate()
        .map(|(i, &pos)| {
            let leaf_row: Vec<BaseField> = (0..w).map(|c| sorted_queried[c][i]).collect();
            let mut bits = Vec::with_capacity(height as usize);
            let mut sibs = Vec::with_capacity(height as usize);
            for level in 0..height as usize {
                let node_idx = pos >> level;
                bits.push((node_idx & 1) as u32);
                sibs.push(node_map[level][&(node_idx ^ 1)]);
            }
            DecommitPath {
                leaf_row,
                bits,
                sibs,
            }
        })
        .collect()
}

/// One tree's streamed-decommit inputs.
struct TreeData {
    width: usize,
    height: u32,
    root: Hash8,
    paths: Vec<DecommitPath>,
}

fn build_tree(proof: &Proof, data: &zkpvm::RecursionData, t: usize) -> TreeData {
    let sp = &proof.stark_proof;
    let queried = &sp.queried_values[t];
    let width = queried.len();
    let height = data.tree_heights[t];
    let root: Hash8 = sp.commitments[t].0;
    let hash_witness: Vec<Hash8> = sp.decommitments[t]
        .hash_witness
        .iter()
        .map(|h| h.0)
        .collect();
    let qpos = if t == 0 {
        &data.preprocessed_query_positions
    } else {
        &data.query_positions
    };
    let paths = tree_paths(
        queried,
        &data.tree_column_log_sizes[t],
        height,
        root,
        &hash_witness,
        qpos,
    );
    TreeData {
        width,
        height,
        root,
        paths,
    }
}

/// Streamed leaf-sponge perms for a leaf of `w` columns: `floor(w/8)` full absorbs
/// + 1 partial-rate finalize.
fn leaf_perms(w: usize) -> usize {
    w / 8 + 1
}

/// The 8-value sponge chunks for a leaf row: `floor(w/8)` full chunks + the
/// partial-rate finalize chunk `[leftover…, 1, 0…]`.
fn leaf_chunks(leaf_row: &[BaseField]) -> Vec<[BaseField; 8]> {
    let w = leaf_row.len();
    let n_full = w / 8;
    let mut chunks = Vec::with_capacity(n_full + 1);
    for c in 0..n_full {
        let mut ch = [BaseField::zero(); 8];
        ch.copy_from_slice(&leaf_row[c * 8..c * 8 + 8]);
        chunks.push(ch);
    }
    let rem = w % 8;
    let mut fin = [BaseField::zero(); 8];
    fin[..rem].copy_from_slice(&leaf_row[n_full * 8..]);
    fin[rem] = BaseField::one(); // the [1,0,…] pad
    chunks.push(fin);
    chunks
}

/// One streamed merkle row (one perm). `init` is the perm input (shared slot).
#[derive(Clone)]
struct MkRow {
    init: [BaseField; N_STATE],
    st_cur: [BaseField; N_STATE],
    chunk: [BaseField; 8],
    sib: [BaseField; 8],
    bit: u32,
    root: [BaseField; 8],
    m_sponge: bool,
    m_node: bool,
    m_root: bool,
    zero_st: bool,
    hash_link: bool,
    cap_fwd: bool,
}

fn mk_zfill() -> MkRow {
    let zb = BaseField::zero();
    MkRow {
        init: [zb; N_STATE],
        st_cur: [zb; N_STATE],
        chunk: [zb; 8],
        sib: [zb; 8],
        bit: 0,
        root: [zb; 8],
        m_sponge: false,
        m_node: false,
        m_root: false,
        zero_st: false,
        hash_link: false,
        cap_fwd: false,
    }
}

/// Lay the given trees' decommit paths out as streamed rows (one perm/row).
fn mk_resolve(trees: &[&TreeData]) -> Vec<MkRow> {
    let zb = BaseField::zero();
    let mut rows: Vec<MkRow> = Vec::new();
    for tree in trees {
        for path in &tree.paths {
            let chunks = leaf_chunks(&path.leaf_row);
            debug_assert_eq!(chunks.len(), leaf_perms(tree.width));
            // ── Leaf sponge ──
            let mut state = [zb; N_STATE];
            for (ci, ch) in chunks.iter().enumerate() {
                let first = ci == 0;
                let last_sponge = ci + 1 == chunks.len();
                let mut f = mk_zfill();
                f.m_sponge = true;
                f.zero_st = first;
                f.chunk = *ch;
                let st_cur = if first { [zb; N_STATE] } else { state };
                f.st_cur = st_cur;
                let mut init = st_cur;
                for j in 0..8 {
                    init[j] += ch[j];
                }
                f.init = init;
                let mut o = init;
                permute(&mut o);
                state = o;
                f.hash_link = true; // rate threads into next sponge/node
                f.cap_fwd = !last_sponge; // capacity threads only sponge→sponge
                rows.push(f);
            }
            debug_assert_eq!(
                &state[..8],
                &sponge_leaf(&path.leaf_row)[..],
                "streamed sponge must reproduce the lifted leaf hash"
            );
            // ── hash_children up to the root ──
            for level in 0..tree.height as usize {
                let mut f = mk_zfill();
                f.m_node = true;
                let bit = path.bits[level];
                let sib = path.sibs[level];
                f.bit = bit;
                f.sib = sib;
                let mut st_cur = [zb; N_STATE];
                st_cur[..8].copy_from_slice(&state[..8]);
                f.st_cur = st_cur;
                let cur: [BaseField; 8] = std::array::from_fn(|j| st_cur[j]);
                let (left, right) = if bit == 0 { (cur, sib) } else { (sib, cur) };
                let mut init = [zb; N_STATE];
                init[..8].copy_from_slice(&left);
                init[8..].copy_from_slice(&right);
                f.init = init;
                let mut o = init;
                permute(&mut o);
                state = o;
                let is_root = level + 1 == tree.height as usize;
                f.m_root = is_root;
                f.root = tree.root;
                f.hash_link = !is_root; // threads to next node; path ends at root
                rows.push(f);
            }
        }
    }
    rows
}

// ── Boundary public-input recompute (step 4b) ────────────────────────────────
// Each boundary chip's claimed sum is a closed form over the public boundary
// states + a relation's Fiat-Shamir (z, alpha): combine(tuple) = Σ alpha^i·tuple_i
// − z, and the sum is Σ 1/combine over the chip's tuples. The three relations
// (register-memory, program-execution, merkle-node) have these tuple lengths:
const N_REGS: usize = 13;
const N_REG_TUPLE: usize = 1 + 8 + 8 + 1; // reg, value[8], ts[8], is_write
const N_PROG_TUPLE: usize = 8 + 4; // ts[8], pc[4]
const N_MEM_TUPLE: usize = 1 + 1 + 32 + 32; // level, index, init_root[32], final_root[32]
const N_BND_REL: usize = 3; // register-memory, program-execution, merkle-node

fn le8(v: u64) -> [BaseField; 8] {
    std::array::from_fn(|i| BaseField::from(((v >> (8 * i)) & 0xff) as u32))
}
fn le4(v: u32) -> [BaseField; 4] {
    std::array::from_fn(|i| BaseField::from((v >> (8 * i)) & 0xff))
}

/// `combine(tuple) = Σ_i tuple_i·alpha^i − z` (host), then `1/combine`. The exact
/// closed form `boundary_binding` checks the proof's claimed sums against.
fn combine_inv_host(tuple: &[BaseField], alpha: SecureField, z: SecureField) -> SecureField {
    let mut c = -z;
    let mut p = SecureField::one();
    for &t in tuple {
        c += p * SecureField::from(t);
        p *= alpha;
    }
    c.inverse()
}

/// In-AIR alpha powers `[1, alpha, alpha², …, alpha^{n-1}]`: `pow[0]=1`,
/// `pow[1]=alpha` (the latched challenge), `pow[i]=pow[i-1]·alpha` each witnessed.
fn air_powers<E: EvalAtRow>(eval: &mut E, alpha: E::EF, n: usize) -> Vec<E::EF> {
    let mut pow = Vec::with_capacity(n);
    pow.push(E::EF::one());
    if n > 1 {
        pow.push(alpha.clone());
    }
    for i in 2..n {
        let p = E::combine_ef(std::array::from_fn(|_| eval.next_trace_mask()));
        eval.add_constraint(p.clone() - pow[i - 1].clone() * alpha.clone()); // deg 2
        pow.push(p);
    }
    pow
}

/// In-AIR `1/combine(tuple)`: `combine = Σ tuple_i·pow[i] − z` (deg 1, constant
/// `tuple_i`), `inv` witnessed, `inv·combine == 1` (deg 2). Returns `inv`.
fn air_inv<E: EvalAtRow>(eval: &mut E, tuple: &[BaseField], pow: &[E::EF], z: &E::EF) -> E::EF {
    let lift = |f: BaseField| -> E::EF {
        E::combine_ef([E::F::from(f), E::F::zero(), E::F::zero(), E::F::zero()])
    };
    let mut combine = E::EF::zero() - z.clone();
    for (i, &t) in tuple.iter().enumerate() {
        combine += pow[i].clone() * lift(t);
    }
    let inv = E::combine_ef(std::array::from_fn(|_| eval.next_trace_mask()));
    eval.add_constraint(inv.clone() * combine - E::EF::one()); // deg 2
    inv
}

/// The public boundary states + the boundary chips' positions in the active-
/// component (claimed-sums) order — the constants the recompute folds.
#[derive(Clone)]
struct BoundaryAir {
    init_regs: [u64; N_REGS],
    final_regs: [u64; N_REGS],
    init_pc: u32,
    final_pc: u32,
    init_ts: u64,
    final_ts: u64,
    init_root: [u8; 32],
    final_root: [u8; 32],
    /// Positions of [register_boundary, register_closing, program, memory] in the
    /// active-component order (the index into the latched claimed_sums).
    pos: [usize; 4],
}

impl BoundaryAir {
    fn reg_tuple(
        &self,
        regs: &[u64; N_REGS],
        r: usize,
        ts: u64,
        is_write: u32,
    ) -> [BaseField; N_REG_TUPLE] {
        let mut t = [BaseField::zero(); N_REG_TUPLE];
        t[0] = BaseField::from(r as u32);
        t[1..9].copy_from_slice(&le8(regs[r]));
        t[9..17].copy_from_slice(&le8(ts));
        t[17] = BaseField::from(is_write);
        t
    }
    fn prog_tuple(&self, pc: u32, ts: u64) -> [BaseField; N_PROG_TUPLE] {
        let mut t = [BaseField::zero(); N_PROG_TUPLE];
        t[0..8].copy_from_slice(&le8(ts));
        t[8..12].copy_from_slice(&le4(pc));
        t
    }
    fn mem_tuple(&self) -> [BaseField; N_MEM_TUPLE] {
        let mut t = [BaseField::zero(); N_MEM_TUPLE];
        // level, index = 0, 0.
        for i in 0..32 {
            t[2 + i] = BaseField::from(self.init_root[i] as u32);
            t[34 + i] = BaseField::from(self.final_root[i] as u32);
        }
        t
    }
}

/// Host-side boundary data: the AIR constants + the three relations' drawn
/// `(z, alpha)` + their draw-squeeze rows (matched against the transcript).
#[derive(Clone)]
struct Bnd {
    air: BoundaryAir,
    z: [SecureField; N_BND_REL],
    alpha: [SecureField; N_BND_REL],
    draw_row: [usize; N_BND_REL],
}

// ─────────────────────────────────────────────────────────────────────────────
// The merged per-child AIR: channel replay + streamed embed + rc latch.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ChildFullEval {
    log_n_rows: u32,
    /// `mlbd - 1` `double_x` steps for the OODS-point `ox`/`dinv` derivation
    /// (`mlbd` = the segment's composition vanishing-domain log size).
    dbl_steps: usize,
    /// The fixed coset-shift point `C = step_size.half().to_point() - coset.initial`
    /// of `CanonicCoset::new(mlbd).coset`, used to derive `coset_vanishing` in-AIR.
    cx: BaseField,
    cy: BaseField,
    /// Public boundary states + the boundary chips' claimed-sum positions (step 4b).
    bound: BoundaryAir,
}

impl FrameworkEval for ChildFullEval {
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
        let is_transcript = eval.get_preprocessed_column(PreProcessedColumnId {
            id: IS_TRANSCRIPT.to_string(),
        });
        let not_last_tr = eval.get_preprocessed_column(PreProcessedColumnId {
            id: NOT_LAST_TR.to_string(),
        });
        let m_sponge = eval.get_preprocessed_column(PreProcessedColumnId {
            id: M_SPONGE.to_string(),
        });
        let m_node = eval.get_preprocessed_column(PreProcessedColumnId {
            id: M_NODE.to_string(),
        });
        let m_root = eval.get_preprocessed_column(PreProcessedColumnId {
            id: M_ROOT.to_string(),
        });
        let zero_st = eval.get_preprocessed_column(PreProcessedColumnId {
            id: ZERO_ST.to_string(),
        });
        let hash_link = eval.get_preprocessed_column(PreProcessedColumnId {
            id: HASH_LINK.to_string(),
        });
        let cap_fwd = eval.get_preprocessed_column(PreProcessedColumnId {
            id: CAP_FWD.to_string(),
        });
        let dc_root: [E::F; 8] = std::array::from_fn(|j| {
            eval.get_preprocessed_column(PreProcessedColumnId { id: dc_root_id(j) })
        });
        let is_rc_draw = eval.get_preprocessed_column(PreProcessedColumnId {
            id: IS_RC_DRAW.to_string(),
        });
        let is_oods_draw = eval.get_preprocessed_column(PreProcessedColumnId {
            id: IS_OODS_DRAW.to_string(),
        });
        let is_cs_chunk: [E::F; N_CS_CHUNKS] = std::array::from_fn(|c| {
            eval.get_preprocessed_column(PreProcessedColumnId { id: cs_chunk_id(c) })
        });
        let is_rel_draw: [E::F; N_BND_REL] = std::array::from_fn(|k| {
            eval.get_preprocessed_column(PreProcessedColumnId {
                id: REL_DRAW_ID[k].to_string(),
            })
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

        // ── Channel constraints, all GATED by `is_transcript` so the channel only
        //    binds transcript rows (merkle/FRI rows drive the shared perm freely).
        //    The selectors (is_absorb/is_squeeze/is_pow1/is_pow2/is_cont) are 0 on
        //    non-transcript rows, so any term carrying one is automatically 0 there
        //    and needs NO extra gate; only the bare (selector-free) terms get the
        //    `is_transcript` factor — keeping every constraint degree ≤ 2 (a deg-2
        //    selector·value term × is_transcript would be deg 3). ──
        for sel in [&is_absorb, &is_squeeze, &is_pow1, &is_pow2, &is_cont] {
            eval.add_constraint(sel.clone() * (sel.clone() - one.clone()));
        }
        // exactly-one selector (only on transcript rows; sum is 0 on merkle rows).
        eval.add_constraint(
            is_transcript.clone()
                * (is_absorb.clone() + is_squeeze.clone() + is_pow1.clone() + is_pow2.clone()
                    - one.clone()),
        );
        eval.add_constraint(is_cont.clone() * (one.clone() - is_absorb.clone()));
        // carry == perm output (only the channel binds carry; gate by is_transcript).
        for j in 0..8 {
            eval.add_constraint(is_transcript.clone() * (carry_lo[j][1].clone() - out[j].clone()));
            eval.add_constraint(
                is_transcript.clone() * (carry_hi[j][1].clone() - out[8 + j].clone()),
            );
        }
        // perm INPUT (rate): on transcript rows init[j] = digest_in (the is_pow2 term
        // already carries a selector ⇒ no extra gate, stays deg 2).
        for j in 0..8 {
            eval.add_constraint(
                is_transcript.clone() * (init[j].clone() - digest_in[j][0].clone())
                    + is_pow2.clone() * (digest_in[j][0].clone() - carry_lo[j][0].clone()),
            );
        }
        // perm INPUT (capacity): every `target` term carries a selector ⇒ gate only
        // the bare init[8+j] by is_transcript.
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
            eval.add_constraint(is_transcript.clone() * init[8 + j].clone() - target);
        }
        // digest_next: rewritten as gated-bare + selector-carrying terms (deg 2).
        for j in 0..8 {
            eval.add_constraint(
                is_transcript.clone() * (digest_next[j].clone() - digest_in[j][0].clone())
                    + is_absorb.clone() * (digest_in[j][0].clone() - carry_lo[j][1].clone()),
            );
        }
        eval.add_constraint(
            is_transcript.clone() * n_draws_next.clone()
                - (is_squeeze.clone() * (ndi_cur.clone() + one.clone())
                    + (is_pow1.clone() + is_pow2.clone()) * ndi_cur.clone()),
        );
        // Digest chain: threads ONLY within the transcript region (not_last_tr).
        for j in 0..8 {
            eval.add_constraint(
                not_last_tr.clone() * (digest_in[j][1].clone() - digest_next[j].clone()),
            );
        }
        eval.add_constraint(not_last_tr.clone() * (ndi_next.clone() - n_draws_next.clone()));
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

        // ── Merkle decommit block (streamed, shares the eval_permutation slot). ──
        //    On merkle rows is_transcript=0 (channel off) and one of m_sponge/m_node
        //    is 1; the perm INIT is bound by the merkle row type, the perm OUT threads
        //    the 16-wide state via the [0,1] latch (the recursion_shared_perm gadget).
        let st: [[E::F; 2]; N_STATE] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
        let st_cur = |j: usize| st[j][0].clone();
        let st_next = |j: usize| st[j][1].clone();
        let mk_chunk: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let mk_sib: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let mk_bit = eval.next_trace_mask();
        let mk_mux: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());

        // Fresh sponge / zeroed state on each path's first row.
        for j in 0..N_STATE {
            eval.add_constraint(zero_st.clone() * st_cur(j));
        }
        // bit booleanity + the degree-lowering mux = bit·(sib − cur).
        eval.add_constraint(mk_bit.clone() * (mk_bit.clone() - one.clone()));
        for j in 0..8 {
            eval.add_constraint(mk_mux[j].clone() - mk_bit.clone() * (mk_sib[j].clone() - st_cur(j)));
        }
        // Leaf sponge: rate += chunk, capacity carried (chunk encodes both a full
        // absorb and the partial-rate finalize [leftover…, 1, 0…]).
        for j in 0..8 {
            eval.add_constraint(
                m_sponge.clone() * (init[j].clone() - st_cur(j) - mk_chunk[j].clone()),
            );
            eval.add_constraint(m_sponge.clone() * (init[8 + j].clone() - st_cur(8 + j)));
        }
        // hash_children: bit-ordered (cur, sib) via the witnessed mux.
        for j in 0..8 {
            let left = st_cur(j) + mk_mux[j].clone(); // bit=0 → cur, bit=1 → sib
            let right = mk_sib[j].clone() - mk_mux[j].clone(); // bit=0 → sib, bit=1 → cur
            eval.add_constraint(m_node.clone() * (init[j].clone() - left));
            eval.add_constraint(m_node.clone() * (init[8 + j].clone() - right));
        }
        // State threading: rate within a path, capacity only across sponge rows.
        for j in 0..8 {
            eval.add_constraint(hash_link.clone() * (st_next(j) - out[j].clone()));
            eval.add_constraint(cap_fwd.clone() * (st_next(8 + j) - out[8 + j].clone()));
        }
        // Pin the recomputed root at each path's last (root) node row. Step 1b pins
        // dc_root to the real commitment (preprocessed); step 2 binds it to the
        // channel commit-absorb.
        for j in 0..8 {
            eval.add_constraint(m_root.clone() * (out[j].clone() - dc_root[j].clone()));
        }

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
        //
        // `is_rc_draw`/`is_oods_draw` are PREPROCESSED columns — part of the fixed
        // verifier-program identity (like `ch_is_first`/`not_last`/the recon-routing
        // program), pinned in the full recursion by the W0 commitment allowlist
        // ({C_0,C_1}); a verifier rejects any preprocessed root ∉ the allowlist, so
        // a prover cannot move the indicator to a wrong row. WHICH squeeze it selects
        // (the 1st/2nd `Squeeze` at/after `prefix_len` = composition rc / oods_t) is
        // thus program-pinned, exactly as the rc/oods_t draw order is fixed by the
        // verify head. The AIR additionally enforces below that the indicator fires
        // only on a genuine `Squeeze` row (`is_X_draw·(1−is_squeeze)==0`), so even a
        // mis-generated indicator cannot bind rc/oods_t to a non-challenge perm
        // output (an Absorb/Pow row's permutation output).
        for j in 0..SECURE_EXTENSION_DEGREE {
            eval.add_constraint(is_rc_draw.clone() * (rc_coords[j].clone() - out[j].clone()));
        }
        eval.add_constraint(is_rc_draw.clone() * (one.clone() - is_squeeze.clone()));

        // ── OODS-point derivation: bind dinv (latched[1]) + ox (latched[2]) to the
        //    transcript by deriving the OODS point in-circuit from a latched oods_t
        //    (bound to its squeeze), then `ox = double_x^{mlbd-1}(oods.x)` and
        //    `dinv = 1/coset_vanishing(coset, oods)` — removing two trusted host
        //    inputs. (rc done above; comp is bound later via the FRI/DEEP path.) ──
        let oods_t_c: [[E::F; 2]; SECURE_EXTENSION_DEGREE] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
        let oods_t = E::combine_ef(std::array::from_fn(|i| oods_t_c[i][0].clone()));
        let oods_t_next = E::combine_ef(std::array::from_fn(|i| oods_t_c[i][1].clone()));
        let t2 = read4_0(&mut eval);
        let tinv = read4_0(&mut eval);
        let oodsx = read4_0(&mut eval);
        let oodsy = read4_0(&mut eval);
        // get_random_point map (circle.rs): x=(1−t²)·inv, y=2t·inv, inv=(1+t²)⁻¹.
        eval.add_constraint(t2.clone() - oods_t.clone() * oods_t.clone());
        eval.add_constraint(tinv.clone() * (t2.clone() + E::EF::one()) - E::EF::one());
        eval.add_constraint(oodsx.clone() - (E::EF::one() - t2.clone()) * tinv.clone());
        eval.add_constraint(oodsy.clone() - (oods_t.clone() + oods_t.clone()) * tinv);
        // oods_t held constant + bound to its squeeze (the get_random_point draw).
        eval.add_constraint(lift(not_last.clone()) * (oods_t_next - oods_t));
        for j in 0..SECURE_EXTENSION_DEGREE {
            eval.add_constraint(is_oods_draw.clone() * (oods_t_c[j][0].clone() - out[j].clone()));
        }
        eval.add_constraint(is_oods_draw.clone() * (one.clone() - is_squeeze.clone()));
        // ox = double_x^{mlbd-1}(oods.x): x_{k+1} = 2·x_k² − 1, each square witnessed.
        let mut x = oodsx.clone();
        for _ in 0..self.dbl_steps {
            let sq = read4_0(&mut eval);
            eval.add_constraint(sq.clone() - x.clone() * x.clone()); // deg 2
            x = sq.clone() + sq - E::EF::one(); // 2·x² − 1, deg 1
        }
        eval.add_constraint(lat_cur[2].clone() - x); // bind ox, deg 1
        // dinv = 1/double_x^{mlbd-1}(p'.x), p' = oods + C (coset_vanishing shift).
        let cx = lift(E::F::from(self.cx));
        let cy = lift(E::F::from(self.cy));
        let mut y = oodsx * cx - oodsy * cy; // p'.x = oods.x·C.x − oods.y·C.y, deg 1
        for _ in 0..self.dbl_steps {
            let sq = read4_0(&mut eval);
            eval.add_constraint(sq.clone() - y.clone() * y.clone()); // deg 2
            y = sq.clone() + sq - E::EF::one();
        }
        eval.add_constraint(lat_cur[1].clone() * y - E::EF::one()); // bind dinv, deg 2

        // ── Claimed-sum balance: bind the 31 per-component claimed_sums to the
        //    transcript's mix_felts(claimed_sums) absorb (chunk c carries
        //    claimed_sum[2c] in absorbed[0..4], claimed_sum[2c+1] in absorbed[4..8]),
        //    then enforce Σ claimed_sums == 0 (the global logup-balance check,
        //    verify.rs:299). The is_cs_chunk indicators are preprocessed (same trust
        //    model as the draw indicators); the AIR enforces each fires only on a
        //    genuine Absorb row. ──
        let cs: [[[E::F; 2]; SECURE_EXTENSION_DEGREE]; N_CS] = std::array::from_fn(|_| {
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]))
        });
        // Held constant across rows (one consistent claimed-sum set).
        for csk in &cs {
            for coord in csk {
                eval.add_constraint(not_last.clone() * (coord[1].clone() - coord[0].clone()));
            }
        }
        // Bind absorbed → claimed_sums at each chunk's absorb row.
        for (c, ind) in is_cs_chunk.iter().enumerate() {
            eval.add_constraint(ind.clone() * (one.clone() - is_absorb.clone()));
            for j in 0..SECURE_EXTENSION_DEGREE {
                eval.add_constraint(ind.clone() * (absorbed[j].clone() - cs[2 * c][j][0].clone()));
                if 2 * c + 1 < N_CS {
                    eval.add_constraint(
                        ind.clone() * (absorbed[4 + j].clone() - cs[2 * c + 1][j][0].clone()),
                    );
                }
            }
        }
        // Per-component claimed sum (cur), reused by the balance + the boundary recompute.
        let cs_ef: [E::EF; N_CS] =
            std::array::from_fn(|k| E::combine_ef(std::array::from_fn(|i| cs[k][i][0].clone())));
        // Global balance: Σ claimed_sums == 0 (degree 1, ungated).
        let mut cs_sum = E::EF::zero();
        for e in &cs_ef {
            cs_sum += e.clone();
        }
        eval.add_constraint(cs_sum);

        // ── Boundary public-input recompute (step 4b): bind the io-hash + memory
        //    roots by recomputing the 4 boundary chips' claimed sums from the PUBLIC
        //    boundary states + each relation's transcript-bound (z, alpha). Each
        //    chip's recomputed sum must equal its claimed_sum (now bound, step 4a). ──
        let mut z_lat: [E::EF; N_BND_REL] = std::array::from_fn(|_| E::EF::zero());
        let mut alpha_lat: [E::EF; N_BND_REL] = std::array::from_fn(|_| E::EF::zero());
        for k in 0..N_BND_REL {
            let z: [[E::F; 2]; SECURE_EXTENSION_DEGREE] =
                std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
            let a: [[E::F; 2]; SECURE_EXTENSION_DEGREE] =
                std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
            // Held constant + bound to the relation's draw squeeze (z = out[0..4],
            // alpha = out[4..8] of the same `draw_secure_felts(2)` squeeze).
            for coord in z.iter().chain(a.iter()) {
                eval.add_constraint(not_last.clone() * (coord[1].clone() - coord[0].clone()));
            }
            for j in 0..SECURE_EXTENSION_DEGREE {
                eval.add_constraint(is_rel_draw[k].clone() * (z[j][0].clone() - out[j].clone()));
                eval.add_constraint(
                    is_rel_draw[k].clone() * (a[j][0].clone() - out[4 + j].clone()),
                );
            }
            eval.add_constraint(is_rel_draw[k].clone() * (one.clone() - is_squeeze.clone()));
            z_lat[k] = E::combine_ef(std::array::from_fn(|i| z[i][0].clone()));
            alpha_lat[k] = E::combine_ef(std::array::from_fn(|i| a[i][0].clone()));
        }
        let reg_pow = air_powers(&mut eval, alpha_lat[0].clone(), N_REG_TUPLE);
        let prog_pow = air_powers(&mut eval, alpha_lat[1].clone(), N_PROG_TUPLE);
        let mem_pow = air_powers(&mut eval, alpha_lat[2].clone(), N_MEM_TUPLE);

        // register_boundary: Σ_r 1/⟨z, (reg, init_regs[r], 0, is_write=1)⟩.
        let mut reg_b = E::EF::zero();
        for r in 0..N_REGS {
            let t = self.bound.reg_tuple(&self.bound.init_regs, r, 0, 1);
            reg_b += air_inv(&mut eval, &t, &reg_pow, &z_lat[0]);
        }
        eval.add_constraint(reg_b - cs_ef[self.bound.pos[0]].clone());

        // register_closing: Σ_r 1/⟨z, (reg, final_regs[r], final_ts, is_write=0)⟩.
        let mut reg_c = E::EF::zero();
        for r in 0..N_REGS {
            let t = self
                .bound
                .reg_tuple(&self.bound.final_regs, r, self.bound.final_ts, 0);
            reg_c += air_inv(&mut eval, &t, &reg_pow, &z_lat[0]);
        }
        eval.add_constraint(reg_c - cs_ef[self.bound.pos[1]].clone());

        // program_boundary: 1/⟨z, (init_ts, init_pc)⟩ − 1/⟨z, (final_ts, final_pc)⟩.
        let t_in = self
            .bound
            .prog_tuple(self.bound.init_pc, self.bound.init_ts);
        let prod = air_inv(&mut eval, &t_in, &prog_pow, &z_lat[1]);
        let t_fin = self
            .bound
            .prog_tuple(self.bound.final_pc, self.bound.final_ts);
        let cons = air_inv(&mut eval, &t_fin, &prog_pow, &z_lat[1]);
        eval.add_constraint(prod - cons - cs_ef[self.bound.pos[2]].clone());

        // memory_root_boundary: −1/⟨z, (0, 0, init_root[32], final_root[32])⟩.
        let t_mem = self.bound.mem_tuple();
        let mem_inv = air_inv(&mut eval, &t_mem, &mem_pow, &z_lat[2]);
        eval.add_constraint(E::EF::zero() - mem_inv - cs_ef[self.bound.pos[3]].clone());

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
    dbl_steps: usize,
    cx: BaseField,
    cy: BaseField,
    bound: BoundaryAir,
}

/// Tampers (each must be rejected by the gate): `channel_tamper` bumps an absorbed
/// value (breaks the transcript binding → derived rc/oods_t diverge); `final_tamper`
/// bumps the embed's final-slot oa (breaks the composition); `oods_t_tamper` corrupts
/// the latched oods_t (isolates the OODS-point derivation); `indicator_tamper`
/// mis-places `is_rc_draw` onto a non-squeeze row; `cs_tamper` corrupts a claimed_sum;
/// `mk_chunk_tamper` bumps a streamed leaf chunk (breaks a leaf hash → root);
/// `mk_sib_tamper` bumps a streamed sibling on a node row.
#[allow(clippy::too_many_arguments)]
fn gen_trace(
    records: &[PermRecord],
    rc_row: usize,
    oods_row: usize,
    oods_t: SecureField,
    dbl_steps: usize,
    cx: BaseField,
    cy: BaseField,
    claimed_sums: &[SecureField],
    prefix_len: usize,
    bnd: &Bnd,
    lay: &ColocateLayout,
    mk_fills: &[MkRow],
    log_size: u32,
    channel_tamper: Option<usize>,
    final_tamper: bool,
    oods_t_tamper: bool,
    indicator_tamper: bool,
    cs_tamper: bool,
    state_tamper: bool,
    mk_chunk_tamper: bool,
    mk_sib_tamper: bool,
) -> ChildTrace {
    assert_eq!(
        claimed_sums.len(),
        N_CS,
        "canonical proof has 31 claimed sums"
    );
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
    let mut is_oods_draw = vec![zb; n];

    let mut digest = [zb; 8];
    let mut n_draws = 0u32;
    let mut expect_pow2 = false;
    let mut prev_out = [zb; N_STATE];
    let n_real = records.len();

    // The transcript region (rows 0..n_real) runs the channel; the merkle/padding
    // rows (n_real..n) only fill the SHARED perm columns (channel non-perm stays 0,
    // is_transcript=0 gates the channel off there).
    for row in 0..n_real {
        let r = records[row];
        let (kind, input, output, first_chunk) = (r.kind, r.input, r.output, r.first_chunk);

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
        // Honest: is_rc_draw fires at the rc-draw squeeze. `indicator_tamper`
        // mis-places it onto the first Absorb row (a non-squeeze) — the
        // is_rc_draw·(1−is_squeeze) hardening must reject this.
        let rc_indicator_row = if indicator_tamper {
            records
                .iter()
                .position(|r| r.kind == PermKind::Absorb)
                .expect("transcript has an absorb")
        } else {
            rc_row
        };
        if row == rc_indicator_row {
            is_rc_draw[row] = BaseField::one();
        }
        if row == oods_row {
            is_oods_draw[row] = BaseField::one();
        }

        digest = digest_next;
        n_draws = n_draws_next;
        prev_out = output;
    }

    // ── Merkle/padding rows: fill ONLY the SHARED perm columns from each row's
    //    perm input (channel non-perm columns stay 0; is_transcript=0 gates the
    //    channel off; padding rows permute 0). ──
    for row in n_real..n {
        let perm_init = if row - n_real < mk_fills.len() {
            mk_fills[row - n_real].init
        } else {
            [zb; N_STATE]
        };
        for (c, v) in record_permutation(perm_init).into_iter().enumerate() {
            ch[c][row] = v;
        }
    }

    // ── Merkle main columns (st[16], chunk[8], sib[8], bit, mux[8]) + the merkle
    //    preprocessed selectors + the per-path pinned root. ──
    let mut mk_rows: Vec<MkRow> = mk_fills.to_vec();
    if mk_chunk_tamper {
        let r = mk_rows
            .iter()
            .position(|f| f.m_sponge)
            .expect("a merkle sponge row");
        mk_rows[r].chunk[0] += BaseField::one();
    }
    if mk_sib_tamper {
        let r = mk_rows
            .iter()
            .position(|f| f.m_node)
            .expect("a merkle node row");
        mk_rows[r].sib[0] += BaseField::one();
    }
    let mut mk: Vec<Vec<BaseField>> = vec![vec![zb; n]; MK_COLS];
    let mut m_sponge = vec![zb; n];
    let mut m_node = vec![zb; n];
    let mut m_root = vec![zb; n];
    let mut zero_st = vec![zb; n];
    let mut hash_link = vec![zb; n];
    let mut cap_fwd = vec![zb; n];
    let mut dc_root: Vec<Vec<BaseField>> = vec![vec![zb; n]; 8];
    for (i, f) in mk_rows.iter().enumerate() {
        let row = n_real + i;
        assert!(row < n, "merkle rows overflow the trace");
        let mux: [BaseField; 8] =
            std::array::from_fn(|j| BaseField::from(f.bit) * (f.sib[j] - f.st_cur[j]));
        let mut col = 0usize;
        for v in f.st_cur {
            mk[col][row] = v;
            col += 1;
        }
        for v in f.chunk {
            mk[col][row] = v;
            col += 1;
        }
        for v in f.sib {
            mk[col][row] = v;
            col += 1;
        }
        mk[col][row] = BaseField::from(f.bit);
        col += 1;
        for v in mux {
            mk[col][row] = v;
            col += 1;
        }
        debug_assert_eq!(col, MK_COLS);
        let b = |x: bool| if x { BaseField::one() } else { zb };
        m_sponge[row] = b(f.m_sponge);
        m_node[row] = b(f.m_node);
        m_root[row] = b(f.m_root);
        zero_st[row] = b(f.zero_st);
        hash_link[row] = b(f.hash_link);
        cap_fwd[row] = b(f.cap_fwd);
        for j in 0..8 {
            dc_root[j][row] = f.root[j];
        }
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

    // ── OODS-derivation QM31 columns (constant across rows; in read order:
    //    oods_t, t2, tinv, oodsx, oodsy, ox squares×dbl, dinv squares×dbl) ──
    let one = SecureField::one();
    let t2 = oods_t.square();
    let tinv = (t2 + one).inverse();
    let oodsx = (one - t2) * tinv;
    let oodsy = (oods_t + oods_t) * tinv;
    // Corrupt the latched oods_t (only the in-circuit OODS derivation reads it,
    // so this isolates the new binding from the embed's own constraints).
    let oods_t_col = if oods_t_tamper {
        oods_t + SecureField::one()
    } else {
        oods_t
    };
    let mut oods_q: Vec<SecureField> = vec![oods_t_col, t2, tinv, oodsx, oodsy];
    let mut x = oodsx;
    for _ in 0..dbl_steps {
        let sq = x.square();
        oods_q.push(sq);
        x = sq + sq - one;
    }
    debug_assert_eq!(x, lay.latched_value[2], "derived ox must match reconstruct");
    let mut y = oodsx * SecureField::from(cx) - oodsy * SecureField::from(cy);
    for _ in 0..dbl_steps {
        let sq = y.square();
        oods_q.push(sq);
        y = sq + sq - one;
    }
    debug_assert_eq!(
        lay.latched_value[1] * y,
        one,
        "derived dinv·vanishing must equal 1"
    );
    let oods_cols: Vec<Vec<SecureField>> = oods_q.into_iter().map(|v| vec![v; n]).collect();

    // ── Claimed-sum columns (31 QM31, held constant) + chunk indicators ──
    debug_assert_eq!(
        claimed_sums.iter().copied().sum::<SecureField>(),
        SecureField::zero(),
        "a valid proof's claimed_sums must balance to 0"
    );
    let cs_cols: Vec<Vec<SecureField>> = (0..N_CS)
        .map(|k| {
            let mut v = claimed_sums[k];
            if cs_tamper && k == 0 {
                v += SecureField::one();
            }
            vec![v; n]
        })
        .collect();
    // The mix_felts(claimed_sums) absorb is the last 16 prefix perms before the
    // interaction-tree commit (= records[prefix_len-1]); chunk c is at prefix_len-17+c.
    let cs_chunk_row = |c: usize| prefix_len - (N_CS_CHUNKS + 1) + c;
    for c in 0..N_CS_CHUNKS {
        debug_assert_eq!(
            records[cs_chunk_row(c)].kind,
            PermKind::Absorb,
            "claimed_sums chunk {c} must land on an Absorb record"
        );
    }
    let mut is_cs_chunk: Vec<Vec<BaseField>> = vec![vec![zb; n]; N_CS_CHUNKS];
    for c in 0..N_CS_CHUNKS {
        is_cs_chunk[c][cs_chunk_row(c)] = BaseField::one();
    }

    // ── Boundary recompute (step 4b): z/alpha latched + alpha powers + inverses ──
    // `state_tamper` claims a wrong final memory root (the io-hash/root attack): the
    // recompute (consistent with the claimed state) then ≠ the transcript-bound
    // claimed_sum, so the boundary comparison rejects.
    let mut air_eff = bnd.air.clone();
    if state_tamper {
        air_eff.final_root[0] ^= 1;
    }
    let air = &air_eff;
    let mut bnd_q: Vec<SecureField> = Vec::new();
    for k in 0..N_BND_REL {
        bnd_q.push(bnd.z[k]);
        bnd_q.push(bnd.alpha[k]);
    }
    let powers = |alpha: SecureField, lo: usize, hi: usize| -> Vec<SecureField> {
        let mut p = SecureField::one();
        (0..hi)
            .map(|_| {
                let v = p;
                p *= alpha;
                v
            })
            .skip(lo)
            .collect()
    };
    bnd_q.extend(powers(bnd.alpha[0], 2, N_REG_TUPLE)); // reg pow[2..18]
    bnd_q.extend(powers(bnd.alpha[1], 2, N_PROG_TUPLE)); // prog pow[2..12]
    bnd_q.extend(powers(bnd.alpha[2], 2, N_MEM_TUPLE)); // mem pow[2..66]
    // Inverses, in evaluate order: reg_boundary(13), reg_closing(13), prog(2), mem(1).
    let mut reg_b = SecureField::zero();
    for r in 0..N_REGS {
        let inv = combine_inv_host(
            &air.reg_tuple(&air.init_regs, r, 0, 1),
            bnd.alpha[0],
            bnd.z[0],
        );
        bnd_q.push(inv);
        reg_b += inv;
    }
    let mut reg_c = SecureField::zero();
    for r in 0..N_REGS {
        let inv = combine_inv_host(
            &air.reg_tuple(&air.final_regs, r, air.final_ts, 0),
            bnd.alpha[0],
            bnd.z[0],
        );
        bnd_q.push(inv);
        reg_c += inv;
    }
    let prod = combine_inv_host(
        &air.prog_tuple(air.init_pc, air.init_ts),
        bnd.alpha[1],
        bnd.z[1],
    );
    let cons = combine_inv_host(
        &air.prog_tuple(air.final_pc, air.final_ts),
        bnd.alpha[1],
        bnd.z[1],
    );
    bnd_q.push(prod);
    bnd_q.push(cons);
    let mem_inv = combine_inv_host(&air.mem_tuple(), bnd.alpha[2], bnd.z[2]);
    bnd_q.push(mem_inv);
    // Cross-check the recompute against the proof's claimed_sums (validates the
    // tuple encodings + the matched (z, alpha) + the combine formula). Skipped under
    // `state_tamper`, which deliberately recomputes from a wrong (claimed) state.
    if !state_tamper {
        debug_assert_eq!(
            reg_b, claimed_sums[air.pos[0]],
            "register_boundary recompute"
        );
        debug_assert_eq!(
            reg_c, claimed_sums[air.pos[1]],
            "register_closing recompute"
        );
        debug_assert_eq!(
            prod - cons,
            claimed_sums[air.pos[2]],
            "program_boundary recompute"
        );
        debug_assert_eq!(
            -mem_inv, claimed_sums[air.pos[3]],
            "memory_root_boundary recompute"
        );
    }
    let bnd_cols: Vec<Vec<SecureField>> = bnd_q.into_iter().map(|v| vec![v; n]).collect();

    let mut is_rel_draw: Vec<Vec<BaseField>> = vec![vec![zb; n]; N_BND_REL];
    for k in 0..N_BND_REL {
        debug_assert_eq!(
            records[bnd.draw_row[k]].kind,
            PermKind::Squeeze,
            "relation {k} draw must land on a Squeeze record"
        );
        is_rel_draw[k][bnd.draw_row[k]] = BaseField::one();
    }

    // ── Preprocessed logical columns, in registration order ──
    // The transcript region is rows 0..n_real (the real records); the trailing
    // rows are the streamed merkle decommit + padding (is_transcript=0 there).
    let n_transcript = n_real;
    let mut pre_b: Vec<Vec<BaseField>> = Vec::new();
    pre_b.push(
        (0..n)
            .map(|i| if i + 1 < n { BaseField::one() } else { zb })
            .collect(),
    ); // not_last
    pre_b.push(ch_is_first);
    pre_b.push(
        (0..n)
            .map(|i| if i < n_transcript { BaseField::one() } else { zb })
            .collect(),
    ); // is_transcript
    pre_b.push(
        (0..n)
            .map(|i| {
                if i + 1 < n_transcript {
                    BaseField::one()
                } else {
                    zb
                }
            })
            .collect(),
    ); // not_last_tr
    pre_b.push(m_sponge);
    pre_b.push(m_node);
    pre_b.push(m_root);
    pre_b.push(zero_st);
    pre_b.push(hash_link);
    pre_b.push(cap_fwd);
    for col in dc_root {
        pre_b.push(col);
    }
    pre_b.push(is_rc_draw);
    pre_b.push(is_oods_draw);
    for col in is_cs_chunk {
        pre_b.push(col);
    }
    for col in is_rel_draw {
        pre_b.push(col);
    }
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

    // Main column order = channel (CHANNEL_COLS) + merkle (MK_COLS) + the QM31
    // blocks (embed, oods, cs, bnd), matching the evaluate read order exactly.
    let mut main_logical: Vec<Vec<BaseField>> = ch;
    for col in mk {
        main_logical.push(col);
    }
    for q in emb_q
        .iter()
        .chain(oods_cols.iter())
        .chain(cs_cols.iter())
        .chain(bnd_cols.iter())
    {
        for c in 0..SECURE_EXTENSION_DEGREE {
            main_logical.push(q.iter().map(|v| v.to_m31_array()[c]).collect());
        }
    }
    if final_tamper {
        // Bump the embed's final-slot oa base column on the final row (the embed
        // QM31 block starts after the channel + merkle columns).
        let oa_col = CHANNEL_COLS + MK_COLS + (NLEAF + lay.final_lane * 3) * SECURE_EXTENSION_DEGREE;
        main_logical[oa_col][lay.final_row] += BaseField::one();
    }
    let main: Vec<_> = main_logical.into_iter().map(wrap).collect();

    ChildTrace {
        preprocessed,
        main,
        log_size,
        dbl_steps,
        cx,
        cy,
        bound: air_eff,
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
    oods_row: usize,
    oods_t: SecureField,
    dbl_steps: usize,
    cx: BaseField,
    cy: BaseField,
    claimed_sums: Vec<SecureField>,
    prefix_len: usize,
    bnd: Bnd,
    lay: ColocateLayout,
    mk_fills: Vec<MkRow>,
    log_size: u32,
}

fn build_inputs() -> ChildInputs {
    use stwo::core::poly::circle::CanonicCoset;
    use zkpvm::boundary_binding::boundary_positions_in_mask;
    use zkpvm::framework_access::{boundary_relation_challenges, drive_chip_oods};
    use zkpvm::{chip_idx, extract_recursion_data, reconstruct_oods_for_recursion};

    let (proof, sn) = canonical_segment();
    assert_eq!(
        proof.num_components,
        chip_idx::COUNT,
        "canonical proof must carry all 31 components"
    );

    // Channel transcript + FRI/OODS data (mlbd, oods_point). The transcript's
    // squeezes at/after prefix_len are, in order: rc, oods_t, deep, fold_alphas…
    let data = extract_recursion_data(&proof, &sn);
    let claimed_sums = proof.claimed_sums.clone();
    let records = data.transcript.records.clone();
    let prefix_len = data.transcript.prefix_len;
    let squeezes: Vec<usize> = records
        .iter()
        .enumerate()
        .filter(|(i, r)| *i >= prefix_len && r.kind == PermKind::Squeeze)
        .map(|(i, _)| i)
        .collect();
    let rc_row = squeezes[0];
    let oods_row = squeezes[1];
    let oods_t = {
        let o = records[oods_row].output;
        SecureField::from_m31_array([o[0], o[1], o[2], o[3]])
    };

    // The OODS-point derivation chain length + coset-shift constant C, from mlbd.
    let mlbd = data.max_log_degree_bound;
    let dbl_steps = (mlbd - 1) as usize;
    let coset = CanonicCoset::new(mlbd).coset;
    let c_point = coset.step_size.half().to_point() - coset.initial;
    let (cx, cy) = (c_point.x, c_point.y);
    // Cross-check C against the real OODS point: p'.x = oods.x·C.x − oods.y·C.y.
    debug_assert_eq!(
        data.oods_point.x * SecureField::from(cx) - data.oods_point.y * SecureField::from(cy),
        (data.oods_point - coset.initial.into_ef() + coset.step_size.half().to_point().into_ef()).x,
        "coset-shift constant C mismatch"
    );

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

    // Boundary recompute inputs (step 4b): the 3 relations' (z, alpha) + their draw
    // squeezes (matched by output value) + the boundary chips' claimed-sum positions.
    let ch = boundary_relation_challenges(&r.lookup_elements);
    let z: [SecureField; N_BND_REL] = std::array::from_fn(|k| ch[k].0);
    let alpha: [SecureField; N_BND_REL] = std::array::from_fn(|k| ch[k].1);
    let draw_row: [usize; N_BND_REL] = std::array::from_fn(|k| {
        let zc = z[k].to_m31_array();
        let ac = alpha[k].to_m31_array();
        records[..prefix_len]
            .iter()
            .position(|rec| {
                rec.kind == PermKind::Squeeze
                    && (0..4).all(|j| rec.output[j] == zc[j])
                    && (0..4).all(|j| rec.output[4 + j] == ac[j])
            })
            .expect("relation (z, alpha) draw squeeze in the prefix")
    });
    let positions =
        boundary_positions_in_mask(proof.component_mask).expect("boundary chips present");
    let bnd = Bnd {
        air: BoundaryAir {
            init_regs: proof.initial_state.registers,
            final_regs: proof.final_state.registers,
            init_pc: proof.initial_state.pc,
            final_pc: proof.final_state.pc,
            init_ts: proof.initial_state.timestamp,
            final_ts: proof.final_state.timestamp,
            init_root: proof.initial_state.memory_root,
            final_root: proof.final_state.memory_root,
            pos: [
                positions.register_boundary,
                positions.register_closing,
                positions.program_boundary,
                positions.memory_root_boundary,
            ],
        },
        z,
        alpha,
        draw_row,
    };

    // Step 1b: a small REAL streamed decommit region (the composition trace tree,
    // 8 cols) rides the freed perm slot after the transcript. The full 4-tree
    // decommit is step 2; here it validates the channel⊕merkle perm-sharing.
    let comp_tree = build_tree(&proof, &data, data.tree_heights.len() - 1);
    let mk_fills = mk_resolve(&[&comp_tree]);

    // The component spans max(transcript + merkle rows, embed rows).
    let log_size = (records.len() + mk_fills.len())
        .max(lay.n_rows)
        .next_power_of_two()
        .trailing_zeros()
        .max(1);

    ChildInputs {
        records,
        rc_row,
        oods_row,
        oods_t,
        dbl_steps,
        cx,
        cy,
        claimed_sums,
        prefix_len,
        bnd,
        lay,
        mk_fills,
        log_size,
    }
}

impl ChildInputs {
    #[allow(clippy::too_many_arguments)]
    fn trace(
        &self,
        channel_tamper: Option<usize>,
        final_tamper: bool,
        oods_t_tamper: bool,
        indicator_tamper: bool,
        cs_tamper: bool,
        state_tamper: bool,
        mk_chunk_tamper: bool,
        mk_sib_tamper: bool,
    ) -> ChildTrace {
        gen_trace(
            &self.records,
            self.rc_row,
            self.oods_row,
            self.oods_t,
            self.dbl_steps,
            self.cx,
            self.cy,
            &self.claimed_sums,
            self.prefix_len,
            &self.bnd,
            &self.lay,
            &self.mk_fills,
            self.log_size,
            channel_tamper,
            final_tamper,
            oods_t_tamper,
            indicator_tamper,
            cs_tamper,
            state_tamper,
            mk_chunk_tamper,
            mk_sib_tamper,
        )
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
    let component = FrameworkComponent::<ChildFullEval>::new(
        &mut alloc,
        ChildFullEval {
            log_n_rows: log_size,
            dbl_steps: trace.dbl_steps,
            cx: trace.cx,
            cy: trace.cy,
            bound: trace.bound.clone(),
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
fn child_full_air_satisfied() {
    let inp = build_inputs();
    let trace = inp.trace(None, false, false, false, false, false, false, false);
    let log_size = trace.log_size;
    let (dbl_steps, cx, cy) = (trace.dbl_steps, trace.cx, trace.cy);
    let bound = trace.bound.clone();
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
            ChildFullEval {
                log_n_rows: log_size,
                dbl_steps,
                cx,
                cy,
                bound: bound.clone(),
            }
            .evaluate(e);
        },
        SecureField::zero(),
    );
    eprintln!(
        "child_full_air_satisfied: REAL segment — channel ({} perms) + streamed OODS embed \
         ({} stream rows) + streamed merkle decommit ({} rows, sharing the perm slot) merged in \
         ONE component at log {log_size}; rc latched to the channel's composition-rc squeeze \
         (row {}). main {} M31 cols, preproc {} M31 cols. Trace satisfies the AIR.",
        inp.records.len(),
        inp.lay.n_rows,
        inp.mk_fills.len(),
        inp.rc_row,
        CHANNEL_COLS + MK_COLS + embed_qm31_cols() * SECURE_EXTENSION_DEGREE,
        preproc_ids().len(),
    );
}

/// THE GATE (heavy): the merged per-child component proves+verifies a REAL
/// canonical segment at degree ≤ 2; a tampered transcript value (→ derived rc
/// diverges) and a tampered embed value are each rejected.
#[test]
#[ignore = "heavy: real-segment channel+embed assembly prove+verify (release, minutes)"]
fn child_full_gate() {
    let inp = build_inputs();

    prove_and_verify(inp.trace(None, false, false, false, false, false, false, false))
        .expect("honest per-child assembly must prove+verify at degree ≤ 2");

    // Reject: corrupt a channel absorbed value (the transcript binding) — also
    // diverges the rc + oods_t squeezes the latches bind to.
    let absorb_row = inp
        .records
        .iter()
        .position(|r| r.kind == PermKind::Absorb)
        .expect("transcript has an absorb");
    assert!(
        prove_and_verify(inp.trace(Some(absorb_row), false, false, false, false, false, false, false))
            .is_err(),
        "a corrupted transcript value must be rejected"
    );

    // Reject: corrupt the embed composition (the final-slot oa value).
    assert!(
        prove_and_verify(inp.trace(None, true, false, false, false, false, false, false)).is_err(),
        "a corrupted embed value must be rejected"
    );

    // Reject: corrupt the latched oods_t (isolates the in-circuit OODS-point
    // derivation: only it reads oods_t, so this confirms the dinv/ox binding is
    // non-vacuous independent of the embed).
    assert!(
        prove_and_verify(inp.trace(None, false, true, false, false, false, false, false)).is_err(),
        "a corrupted oods_t must be rejected by the OODS-point derivation"
    );

    // Reject: mis-place the is_rc_draw preprocessed indicator onto a non-squeeze
    // (Absorb) row — the is_rc_draw·(1−is_squeeze) hardening must reject binding rc
    // to a non-challenge perm output.
    assert!(
        prove_and_verify(inp.trace(None, false, false, true, false, false, false, false)).is_err(),
        "an is_rc_draw indicator on a non-squeeze row must be rejected"
    );

    // Reject: corrupt a claimed_sum — breaks both its transcript-absorb binding
    // and the Σ claimed_sums == 0 balance.
    assert!(
        prove_and_verify(inp.trace(None, false, false, false, true, false, false, false)).is_err(),
        "a corrupted claimed_sum must be rejected"
    );

    // Reject: claim a wrong final memory root (the io-hash/root attack) — the
    // boundary recompute then ≠ the transcript-bound claimed_sum.
    assert!(
        prove_and_verify(inp.trace(None, false, false, false, false, true, false, false)).is_err(),
        "a wrong claimed boundary state (memory root) must be rejected"
    );

    // Reject: corrupt a streamed leaf chunk (the merkle decommit) — the leaf hash
    // diverges from the pinned root.
    assert!(
        prove_and_verify(inp.trace(None, false, false, false, false, false, true, false)).is_err(),
        "a corrupted merkle leaf chunk must be rejected"
    );

    // Reject: corrupt a streamed sibling on a node row — the re-hashed path diverges
    // from the pinned root.
    assert!(
        prove_and_verify(inp.trace(None, false, false, false, false, false, false, true)).is_err(),
        "a corrupted merkle sibling must be rejected"
    );

    eprintln!(
        "child_full_gate GREEN @ log {}: ONE uniform component replays a REAL canonical \
         segment's {}-perm transcript, re-evaluates its full 31-component OODS composition \
         (streamed embed, {} stream rows), AND streams a real trace-tree Merkle decommit ({} \
         rows) sharing the SAME eval_permutation slot via is_transcript/m_* row-type selectors — \
         with the embed's rc latched to the channel's composition-rc squeeze, dinv/ox derived \
         in-circuit from a transcript-bound oods_t (mlbd-1={} double_x steps), the 31 claimed_sums \
         bound to the mix_felts(claimed_sums) absorb + Σ == 0, AND the 4 boundary chips' claimed \
         sums recomputed in-AIR from the PUBLIC boundary states (io-hash + memory roots) via each \
         relation's transcript-bound (z, alpha) — proving+verifying through the lifted \
         Poseidon2-M31 protocol at degree ≤ 2; every tamper (transcript / embed / oods_t / \
         claimed_sum / boundary state / merkle leaf / merkle sibling) AND a mis-placed is_rc_draw \
         indicator are each rejected.",
        inp.log_size,
        inp.records.len(),
        inp.lay.n_rows,
        inp.mk_fills.len(),
        inp.dbl_steps,
    );
}
