//! Recursion build P5.3 — **the make-or-break MEASUREMENT + the streamed
//! multi-tree trace-tree decommit on REAL data (step 2).**
//!
//! Two deliverables:
//!
//!   1. **MEASUREMENT (`decommit_scale_measure`).** Extract a real canonical
//!      segment's decommit shapes (per-tree leaf widths + heights + distinct query
//!      counts; FRI layer count + witness shapes) and compute the streamed perm
//!      totals → the per-child LOG. This is the cost-model ground-truth the design
//!      front-loaded.
//!   2. **STREAMED MULTI-TREE DECOMMIT (`decommit_streamed_assert` /
//!      `decommit_streamed_prove`).** Generalise the shared-perm-block spike
//!      (`recursion_shared_perm`) to the REAL trace trees: per-tree leaf widths +
//!      heights, MIXED-DEGREE leaves (the lifted Merkle hashes each leaf row with
//!      columns sorted ascending by log size), real `queried_values`, roots pinned
//!      to the proof's real commitments. One perm/row, the 16-wide sponge/hash
//!      state threaded by the `[0,1]` latch. Validates the streamed decommit
//!      reproduces every real trace-tree root in-AIR.
//!
//! The leaf sponge is a generic per-row chunk absorb (`rate += chunk`), so a width
//! that is NOT a multiple of 8 finalises with the partial-rate chunk
//! `[leftover…, 1, 0…]` (the lifted hasher's `update_leaf` + `finalize`); the
//! capacity threads across sponge rows and resets (unused) on `hash_children` rows.
//!
//! Run:
//! `cargo test -p zkpvm --release --features poseidon2-channel --test \
//!     recursion_decommit_scale -- --ignored --nocapture`

#![cfg(feature = "poseidon2-channel")]

mod recursion_common;

use std::collections::HashMap;

use num_traits::{One, Zero};
use recursion_common::{
    N_PERM_COLS, N_STATE, P2MerkleChannel, P2MerkleHasher, Poseidon2M31Channel, eval_permutation,
    hash_children_m31, mobile_config, permute, record_permutation,
};
use stwo::core::air::Component;
use stwo::core::fields::m31::{BaseField, M31};
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::verify;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, ORIGINAL_TRACE_IDX, TraceLocationAllocator,
    assert_constraints_on_trace, preprocessed_columns::PreProcessedColumnId,
};
use zkpvm::{Proof, SideNote, extract_recursion_data};

/// Prove a small but genuine program as ONE full 31-component canonical segment
/// (identical to `recursion_child_assembly::canonical_segment`).
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

/// Streamed leaf-sponge perms for a leaf of `w` columns: `floor(w/8)` full RATE
/// absorbs + 1 (partial-rate) finalize.
fn leaf_perms(w: usize) -> usize {
    w / 8 + 1
}

#[test]
#[ignore = "heavy: prove_canonical builds a real 31-component segment (~30s release)"]
fn decommit_scale_measure() {
    let (proof, sn) = canonical_segment();
    let data = extract_recursion_data(&proof, &sn);
    let sp = &proof.stark_proof;

    let n_trees = sp.commitments.len();
    let dedup = |v: &[usize]| -> usize {
        let mut s: Vec<usize> = v.to_vec();
        s.sort_unstable();
        s.dedup();
        s.len()
    };
    let n_pos_trace = dedup(&data.query_positions);
    let n_pos_pre = dedup(&data.preprocessed_query_positions);

    eprintln!("── Real canonical segment decommit shapes ──");
    eprintln!(
        "transcript: {} perms (prefix_len {}), lifting_log_size {}, max_log_degree_bound {}",
        data.transcript.records.len(),
        data.transcript.prefix_len,
        data.lifting_log_size,
        data.max_log_degree_bound,
    );
    eprintln!(
        "query positions: {} distinct (of {}); preprocessed: {} distinct (of {})",
        n_pos_trace,
        data.query_positions.len(),
        n_pos_pre,
        data.preprocessed_query_positions.len(),
    );
    eprintln!("tree_heights: {:?}", data.tree_heights);

    let mut trace_perms = 0usize;
    for t in 0..n_trees {
        let w = sp.queried_values[t].len();
        let h = data.tree_heights[t] as usize;
        let n_pos = if t == 0 { n_pos_pre } else { n_pos_trace };
        let lp = leaf_perms(w);
        let per_path = lp + h;
        let tree_total = n_pos * per_path;
        trace_perms += tree_total;
        eprintln!(
            "  tree {t}: width {w} cols, height {h}, {n_pos} paths → leaf {lp} + nodes {h} = \
             {per_path}/path × {n_pos} = {tree_total} perms",
        );
    }
    eprintln!("trace-tree decommit total: {trace_perms} perms");

    let fp = &sp.fri_proof;
    let n_inner = fp.inner_layers.len();
    let mut fri_hash_witness_total = fp.first_layer.decommitment.hash_witness.len();
    for layer in fp.inner_layers.iter() {
        fri_hash_witness_total += layer.decommitment.hash_witness.len();
    }
    eprintln!(
        "FRI: {} layers; last_layer_poly len {}; hash_witness total {fri_hash_witness_total}",
        1 + n_inner,
        fp.last_layer_poly.len(),
    );

    let transcript_perms = data.transcript.records.len();
    let grand_total = transcript_perms + trace_perms + fri_hash_witness_total;
    let log = (grand_total as u32).next_power_of_two().trailing_zeros();
    eprintln!("── PROJECTED per-child total ──");
    eprintln!(
        "transcript {transcript_perms} + trace-tree {trace_perms} + FRI-layer(lb) \
         {fri_hash_witness_total} = {grand_total} perms → log {log}",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Host decommit replay (sorted mixed-degree leaves) → per-path data.
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
    assert_eq!(
        layer[0].1, root,
        "recomputed root must equal the commitment"
    );
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
    // Stable sort of column indices by ascending log size (the lifted leaf order).
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

// ─────────────────────────────────────────────────────────────────────────────
// The streamed multi-tree decommit AIR (one perm/row).
// ─────────────────────────────────────────────────────────────────────────────

const M_SPONGE: &str = "dc_m_sponge";
const M_NODE: &str = "dc_m_node";
const M_ROOT: &str = "dc_m_root";
const ZERO_ST: &str = "dc_zero_st";
const HASH_LINK: &str = "dc_hash_link";
const CAP_FWD: &str = "dc_cap_fwd";
fn root_id(j: usize) -> String {
    format!("dc_root_{j}")
}

fn preproc_ids() -> Vec<PreProcessedColumnId> {
    let mut ids: Vec<PreProcessedColumnId> =
        [M_SPONGE, M_NODE, M_ROOT, ZERO_ST, HASH_LINK, CAP_FWD]
            .into_iter()
            .map(|id| PreProcessedColumnId { id: id.to_string() })
            .collect();
    for j in 0..8 {
        ids.push(PreProcessedColumnId { id: root_id(j) });
    }
    ids
}

// Main columns: perm then st[16], chunk[8], sib[8], bit, mux[8].
const N_MAIN_COLS: usize = N_PERM_COLS + 16 + 8 + 8 + 1 + 8;

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

#[derive(Clone)]
struct StreamedDecommitEval {
    log_n_rows: u32,
}

impl FrameworkEval for StreamedDecommitEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one = E::F::one();
        let pre = |eval: &mut E, id: &str| {
            eval.get_preprocessed_column(PreProcessedColumnId { id: id.to_string() })
        };
        let m_sponge = pre(&mut eval, M_SPONGE);
        let m_node = pre(&mut eval, M_NODE);
        let m_root = pre(&mut eval, M_ROOT);
        let zero_st = pre(&mut eval, ZERO_ST);
        let hash_link = pre(&mut eval, HASH_LINK);
        let cap_fwd = pre(&mut eval, CAP_FWD);
        let root: [E::F; 8] = std::array::from_fn(|j| {
            eval.get_preprocessed_column(PreProcessedColumnId { id: root_id(j) })
        });

        let (init, out) = eval_permutation(&mut eval);
        let st: [[E::F; 2]; N_STATE] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
        let st_cur = |j: usize| st[j][0].clone();
        let st_next = |j: usize| st[j][1].clone();
        let chunk: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let sib: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let bit = eval.next_trace_mask();
        let mux: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());

        // Fresh sponge on the first row of each path.
        for j in 0..N_STATE {
            eval.add_constraint(zero_st.clone() * st_cur(j));
        }
        // bit booleanity + degree-lowering mux = bit·(sib − cur).
        eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
        for j in 0..8 {
            eval.add_constraint(mux[j].clone() - bit.clone() * (sib[j].clone() - st_cur(j)));
        }
        // Leaf sponge: rate += chunk, capacity carried (the chunk encodes both a
        // full absorb and the partial-rate finalize [leftover…, 1, 0…]).
        for j in 0..8 {
            eval.add_constraint(
                m_sponge.clone() * (init[j].clone() - st_cur(j) - chunk[j].clone()),
            );
            eval.add_constraint(m_sponge.clone() * (init[8 + j].clone() - st_cur(8 + j)));
        }
        // hash_children: bit-ordered (cur, sib) via the witnessed mux.
        for j in 0..8 {
            let left = st_cur(j) + mux[j].clone();
            let right = sib[j].clone() - mux[j].clone();
            eval.add_constraint(m_node.clone() * (init[j].clone() - left));
            eval.add_constraint(m_node.clone() * (init[8 + j].clone() - right));
        }
        // State threading.
        for j in 0..8 {
            eval.add_constraint(hash_link.clone() * (st_next(j) - out[j].clone()));
            eval.add_constraint(cap_fwd.clone() * (st_next(8 + j) - out[8 + j].clone()));
        }
        // Pin the recomputed root at each path's root node row.
        for j in 0..8 {
            eval.add_constraint(m_root.clone() * (out[j].clone() - root[j].clone()));
        }
        eval
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Host schedule + trace fill.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct RowFill {
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

fn zfill() -> RowFill {
    let zb = BaseField::zero();
    RowFill {
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

/// Lay the given trees' decommit paths out as streamed rows (one perm/row).
fn resolve(trees: &[&TreeData]) -> Vec<RowFill> {
    let zb = BaseField::zero();
    let mut rows: Vec<RowFill> = Vec::new();
    for tree in trees {
        for path in &tree.paths {
            let chunks = leaf_chunks(&path.leaf_row);
            debug_assert_eq!(chunks.len(), leaf_perms(tree.width));
            // ── Leaf sponge ──
            let mut state = [zb; N_STATE];
            for (ci, ch) in chunks.iter().enumerate() {
                let first = ci == 0;
                let last_sponge = ci + 1 == chunks.len();
                let mut f = zfill();
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
                let mut f = zfill();
                f.m_node = true;
                let bit = path.bits[level];
                let sib = path.sibs[level];
                f.bit = bit;
                f.sib = sib;
                // cur = previous out[0..8] (carried by hash_link), capacity unused.
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

struct Trace {
    preprocessed: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    main: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    log_size: u32,
}

#[derive(Clone, Copy)]
enum Tamper {
    None,
    Chunk,   // bump a leaf chunk value (breaks a leaf hash → root)
    Sibling, // bump a sibling on a node row
}

fn gen_trace(trees: &[&TreeData], tamper: Tamper) -> Trace {
    let mut rows = resolve(trees);
    let n_used = rows.len();
    let log_size = (n_used as u32).next_power_of_two().trailing_zeros().max(1);
    let n = 1usize << log_size;
    rows.resize(n, zfill());

    match tamper {
        Tamper::None => {}
        Tamper::Chunk => {
            let r = rows.iter().position(|f| f.m_sponge).unwrap();
            rows[r].chunk[0] += BaseField::one();
        }
        Tamper::Sibling => {
            let r = rows.iter().position(|f| f.m_node).unwrap();
            rows[r].sib[0] += BaseField::one();
        }
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    let wrap = |logical: Vec<BaseField>| {
        let mut c = Col::<CpuBackend, BaseField>::zeros(n);
        for (i, v) in logical.into_iter().enumerate() {
            c.set(storage_index(i, log_size), v);
        }
        CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, c)
    };

    let bcol = |sel: &dyn Fn(&RowFill) -> bool| -> Vec<BaseField> {
        rows.iter()
            .map(|f| {
                if sel(f) {
                    BaseField::one()
                } else {
                    BaseField::zero()
                }
            })
            .collect()
    };
    let mut pre_b: Vec<Vec<BaseField>> = vec![
        bcol(&|f| f.m_sponge),
        bcol(&|f| f.m_node),
        bcol(&|f| f.m_root),
        bcol(&|f| f.zero_st),
        bcol(&|f| f.hash_link),
        bcol(&|f| f.cap_fwd),
    ];
    for j in 0..8 {
        pre_b.push(rows.iter().map(|f| f.root[j]).collect());
    }
    let preprocessed: Vec<_> = pre_b.into_iter().map(wrap).collect();

    let mut main_cols: Vec<Vec<BaseField>> =
        (0..N_MAIN_COLS).map(|_| Vec::with_capacity(n)).collect();
    for f in &rows {
        let mut row: Vec<BaseField> = record_permutation(f.init);
        row.extend_from_slice(&f.st_cur);
        row.extend_from_slice(&f.chunk);
        row.extend_from_slice(&f.sib);
        row.push(BaseField::from(f.bit));
        let mux: [BaseField; 8] =
            std::array::from_fn(|j| BaseField::from(f.bit) * (f.sib[j] - f.st_cur[j]));
        row.extend_from_slice(&mux);
        debug_assert_eq!(row.len(), N_MAIN_COLS);
        for (c, v) in row.into_iter().enumerate() {
            main_cols[c].push(v);
        }
    }
    let main: Vec<_> = main_cols.into_iter().map(wrap).collect();

    Trace {
        preprocessed,
        main,
        log_size,
    }
}

fn assert_air(trees: &[&TreeData]) -> u32 {
    let trace = gen_trace(trees, Tamper::None);
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
            StreamedDecommitEval {
                log_n_rows: log_size,
            }
            .evaluate(e);
        },
        SecureField::zero(),
    );
    log_size
}

fn prove_and_verify(trees: &[&TreeData], tamper: Tamper) -> Result<(), String> {
    let config = mobile_config();
    let trace = gen_trace(trees, tamper);
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
    let component = FrameworkComponent::<StreamedDecommitEval>::new(
        &mut alloc,
        StreamedDecommitEval {
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

/// CORRECTNESS: each of the 4 REAL trace trees' decommit re-hashes to its real
/// root in the streamed (one-perm/row) form — the mixed-degree leaf (columns
/// sorted by log size, partial-rate finalize), real queried_values + witnesses.
#[test]
#[ignore = "heavy: prove_canonical builds a real 31-component segment (~30s release)"]
fn decommit_streamed_assert() {
    let (proof, sn) = canonical_segment();
    let data = extract_recursion_data(&proof, &sn);
    let n_trees = proof.stark_proof.commitments.len();
    for t in 0..n_trees {
        let tree = build_tree(&proof, &data, t);
        let log = assert_air(&[&tree]);
        eprintln!(
            "  tree {t}: width {} height {} → {} streamed rows (log {log}) re-hash to the real \
             root; AIR satisfied.",
            tree.width,
            tree.height,
            tree.paths.len() * (leaf_perms(tree.width) + tree.height as usize),
        );
    }
    eprintln!(
        "decommit_streamed_assert GREEN: all {n_trees} real trace-tree decommits re-hash to their \
         real roots in the streamed mixed-degree form.",
    );
}

/// MEMORY ANCHOR: prove+verify the WIDE main-tree decommit alone (log 16, ~48K
/// perms) — confirms a decommit-only component is tractable even when TALL (its
/// preproc is only ~14 narrow columns), isolating the real cost driver as the
/// EMBED's wide preproc replicated across the decommit's tall rows in a COMBINED
/// uniform component. Run with `/usr/bin/time -v` to capture peak RSS.
#[test]
#[ignore = "heavy: wide main-tree decommit prove (log 16, release) — memory anchor"]
fn decommit_streamed_prove_main() {
    let (proof, sn) = canonical_segment();
    let data = extract_recursion_data(&proof, &sn);
    let main = build_tree(&proof, &data, 1);
    let rows = main.paths.len() * (leaf_perms(main.width) + main.height as usize);
    prove_and_verify(&[&main], Tamper::None).expect("honest main-tree streamed decommit");
    let log = (rows as u32).next_power_of_two().trailing_zeros();
    eprintln!(
        "decommit_streamed_prove_main GREEN: the WIDE main-tree decommit ({} cols, {rows} perms → \
         log {log}) proves+verifies at degree ≤ 2 with only ~14 narrow preproc columns.",
        main.width,
    );
}

/// DEGREE + MECHANISM: prove+verify the streamed decommit of the NARROW trees
/// (preprocessed + composition) — confirms degree ≤ 2 on real mixed-degree data
/// at a memory-tractable scale; tampered chunk / sibling rejected. (The wide
/// main/interaction trees push the combined component to log 17 — see the
/// measurement; not provable on a 62 GiB box with the scalar hasher.)
#[test]
#[ignore = "heavy: real-segment streamed decommit prove+verify (release)"]
fn decommit_streamed_prove() {
    let (proof, sn) = canonical_segment();
    let data = extract_recursion_data(&proof, &sn);
    let preproc = build_tree(&proof, &data, 0);
    let comp = build_tree(&proof, &data, data.tree_heights.len() - 1);
    let trees: Vec<&TreeData> = vec![&preproc, &comp];

    prove_and_verify(&trees, Tamper::None).expect("honest narrow-tree streamed decommit");
    assert!(
        prove_and_verify(&trees, Tamper::Chunk).is_err(),
        "a tampered leaf chunk must be rejected"
    );
    assert!(
        prove_and_verify(&trees, Tamper::Sibling).is_err(),
        "a tampered sibling must be rejected"
    );

    let rows: usize = trees
        .iter()
        .map(|t| t.paths.len() * (leaf_perms(t.width) + t.height as usize))
        .sum();
    eprintln!(
        "decommit_streamed_prove GREEN: streamed decommit of the preprocessed ({} cols) + \
         composition ({} cols) trees ({rows} perms) proves+verifies through the lifted \
         Poseidon2-M31 protocol at degree ≤ 2; tampered chunk / sibling rejected.",
        preproc.width, comp.width,
    );
}
