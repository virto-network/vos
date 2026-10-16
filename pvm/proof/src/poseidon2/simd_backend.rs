//! The Poseidon2-M31 commitment and grind on `SimdBackend`, sixteen
//! permutations at once.
//!
//! The impls are orphan-legal: each names a local type (`P2Hash`,
//! `P2MerkleHasher`, `Poseidon2M31Channel`, `P2MerkleChannel`).
//!
//! **Leaves** follow `CpuBackend`'s lifted algorithm: one sponge a leaf of the
//! current layer, columns grouped by size in increasing order, each group's
//! layer lifted from the previous one (leaf `idx` continues the sponge of
//! leaf `((idx >> (r + 1)) << 1) + (idx & 1)` of a layer `2^r` times smaller),
//! then the group absorbed. A layer of at least sixteen leaves holds its
//! sponges sixteen to a block and absorbs a whole block at a time. The
//! sponges are finalized before the last lift, which copies hashes instead of
//! sponges.
//!
//! **The grind** returns the smallest valid nonce, as `CpuBackend`'s does.

use alloc::vec;
use alloc::vec::Vec;

use rayon::prelude::*;
use stwo::core::fields::m31::BaseField;
use stwo::core::proof_of_work::GrindOps;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{BackendForChannel, Col, Column, ColumnOps, CpuBackend};
use stwo::prover::vcs_lifted::ops::MerkleOpsLifted;

use super::packed::{LANES, States, permute_x16};
use super::{N_STATE, P2Hash, P2MerkleChannel, P2MerkleHasher, Poseidon2M31Channel, RATE};

const LOG_LANES: u32 = LANES.ilog2();
const P: u32 = (1 << 31) - 1;

// Hash columns are a plain `Vec`, as `SimdBackend` stores its Blake2s hash
// columns. They are never bit-reversed: hashes live only in the tree.
impl ColumnOps<P2Hash> for SimdBackend {
    type Column = Vec<P2Hash>;
    fn bit_reverse_column(_column: &mut Self::Column) {
        unimplemented!("P2Hash columns are never bit-reversed")
    }
}

impl MerkleOpsLifted<P2MerkleHasher> for SimdBackend {
    fn build_leaves(columns: &[&Col<Self, BaseField>], lifting_log_size: u32) -> Vec<P2Hash> {
        if columns.is_empty() {
            return vec![P2MerkleHasher::default().finalize()];
        }
        assert!(columns[0].len() >= 2, "A column must be of length >= 2.");
        let mut layer = Layer::Scalar(vec![P2MerkleHasher::default(); 2]);
        let mut layer_log_size = 1;
        let mut start = 0;
        while start < columns.len() {
            let log_size = columns[start].len().ilog2();
            let end = start
                + columns[start..]
                    .iter()
                    .take_while(|column| column.len().ilog2() == log_size)
                    .count();
            let group = &columns[start..end];
            let log_ratio = log_size - layer_log_size;
            layer = if log_size < LOG_LANES {
                Layer::Scalar(absorb_rows(&layer, log_size, log_ratio, group))
            } else {
                let buffered = layer.buffered();
                let blocks = (0..1usize << (log_size - LOG_LANES))
                    .into_par_iter()
                    .map(|block| {
                        let mut leaves = layer.lifted_block(block, log_ratio);
                        leaves.absorb_columns(buffered, block, group);
                        leaves
                    })
                    .collect();
                Layer::Packed {
                    blocks,
                    buffered: (buffered + group.len()) % RATE,
                }
            };
            layer_log_size = log_size;
            start = end;
        }
        let hashes = layer.finalize();
        let log_ratio = lifting_log_size - layer_log_size;
        if log_ratio == 0 {
            return hashes;
        }
        (0..1usize << lifting_log_size)
            .into_par_iter()
            .map(|idx| hashes[lifted_index(idx, log_ratio)])
            .collect()
    }

    fn build_next_layer(prev_layer: &Vec<P2Hash>) -> Vec<P2Hash> {
        let n_parents = prev_layer.len() / 2;
        if n_parents < LANES {
            return <CpuBackend as MerkleOpsLifted<P2MerkleHasher>>::build_next_layer(prev_layer);
        }
        let mut parents = vec![P2Hash::default(); n_parents];
        parents
            .par_chunks_exact_mut(LANES)
            .zip(prev_layer.par_chunks_exact(2 * LANES))
            .for_each(|(parents, children)| {
                let mut state: States = [[0; LANES]; N_STATE];
                for (lane, pair) in children.chunks_exact(2).enumerate() {
                    for i in 0..8 {
                        state[i][lane] = pair[0].0[i].0;
                        state[8 + i][lane] = pair[1].0[i].0;
                    }
                }
                permute_x16(&mut state);
                for (lane, parent) in parents.iter_mut().enumerate() {
                    *parent = P2Hash(core::array::from_fn(|i| {
                        BaseField::from_u32_unchecked(state[i][lane])
                    }));
                }
            });
        parents
    }
}

/// The sponges of one layer of leaves.
enum Layer {
    /// Fewer than sixteen leaves: one scalar hasher each.
    Scalar(Vec<P2MerkleHasher>),
    /// Sixteen leaves a block. Every sponge has the same `buffered` words
    /// waiting for a whole block.
    Packed { blocks: Vec<Block>, buffered: usize },
}

/// The sponges of sixteen leaves, one a lane.
#[derive(Clone)]
struct Block {
    state: States,
    buffer: [[u32; LANES]; RATE],
}

impl Layer {
    fn buffered(&self) -> usize {
        match self {
            Layer::Scalar(hashers) => hashers[0].buffer.len(),
            Layer::Packed { buffered, .. } => *buffered,
        }
    }

    /// The sponge of leaf `idx` of this layer.
    fn sponge(&self, idx: usize) -> ([u32; N_STATE], [u32; RATE]) {
        match self {
            Layer::Scalar(hashers) => {
                let hasher = &hashers[idx];
                let mut buffer = [0; RATE];
                for (word, value) in buffer.iter_mut().zip(&hasher.buffer) {
                    *word = value.0;
                }
                (hasher.state.map(|word| word.0), buffer)
            }
            Layer::Packed { blocks, .. } => {
                let block = &blocks[idx >> LOG_LANES];
                let lane = idx % LANES;
                (
                    block.state.map(|word| word[lane]),
                    block.buffer.map(|word| word[lane]),
                )
            }
        }
    }

    /// Block `block` of the layer `2^log_ratio` times larger than this one.
    fn lifted_block(&self, block: usize, log_ratio: u32) -> Block {
        let mut lifted = Block {
            state: [[0; LANES]; N_STATE],
            buffer: [[0; LANES]; RATE],
        };
        for lane in 0..LANES {
            let (state, buffer) = self.sponge(lifted_index(block * LANES + lane, log_ratio));
            for (word, value) in lifted.state.iter_mut().zip(state) {
                word[lane] = value;
            }
            for (word, value) in lifted.buffer.iter_mut().zip(buffer) {
                word[lane] = value;
            }
        }
        lifted
    }

    fn finalize(self) -> Vec<P2Hash> {
        match self {
            Layer::Scalar(hashers) => hashers.into_iter().map(P2MerkleHasher::finalize).collect(),
            Layer::Packed { blocks, buffered } => {
                let mut hashes = vec![P2Hash::default(); blocks.len() * LANES];
                hashes
                    .par_chunks_exact_mut(LANES)
                    .zip(blocks)
                    .for_each(|(hashes, mut block)| {
                        // The padding: a one, then zeros to a whole block.
                        block.buffer[buffered] = [1; LANES];
                        for word in &mut block.buffer[buffered + 1..] {
                            *word = [0; LANES];
                        }
                        block.absorb();
                        for (lane, hash) in hashes.iter_mut().enumerate() {
                            *hash = P2Hash(core::array::from_fn(|i| {
                                BaseField::from_u32_unchecked(block.state[i][lane])
                            }));
                        }
                    });
                hashes
            }
        }
    }
}

impl Block {
    /// Append block `block` of each column to the sponges, `buffered` words
    /// already waiting.
    fn absorb_columns(
        &mut self,
        mut buffered: usize,
        block: usize,
        columns: &[&Col<SimdBackend, BaseField>],
    ) {
        for column in columns {
            let rows = &column.as_slice()[block * LANES..(block + 1) * LANES];
            for (word, row) in self.buffer[buffered].iter_mut().zip(rows) {
                *word = row.0;
            }
            buffered += 1;
            if buffered == RATE {
                self.absorb();
                buffered = 0;
            }
        }
    }

    /// Add the buffered block into the rate words and permute.
    fn absorb(&mut self) {
        for (state, buffer) in self.state.iter_mut().zip(&self.buffer) {
            for (word, value) in state.iter_mut().zip(buffer) {
                // Both in [0, P] and the state canonical, so the sum is below 2P.
                let sum = *word + value;
                *word = if sum >= P { sum - P } else { sum };
            }
        }
        permute_x16(&mut self.state);
    }
}

/// The leaves of a layer of fewer than sixteen leaves, lifted from `layer` and
/// absorbing `columns` row by row.
fn absorb_rows(
    layer: &Layer,
    log_size: u32,
    log_ratio: u32,
    columns: &[&Col<SimdBackend, BaseField>],
) -> Vec<P2MerkleHasher> {
    let Layer::Scalar(hashers) = layer else {
        unreachable!("a layer of sixteen leaves or more precedes only larger ones")
    };
    (0..1usize << log_size)
        .map(|idx| {
            let mut hasher = hashers[lifted_index(idx, log_ratio)].clone();
            let row: Vec<BaseField> = columns.iter().map(|column| column.at(idx)).collect();
            hasher.update_leaf(&row);
            hasher
        })
        .collect()
}

/// The leaf of a layer `2^log_ratio` times smaller whose sponge leaf `idx`
/// continues.
fn lifted_index(idx: usize, log_ratio: u32) -> usize {
    ((idx >> (log_ratio + 1)) << 1) + (idx & 1)
}

// ── The grind ──────────────────────────────────────────────────────────────

/// Nonces one task tries before the smallest hit in a round is taken.
const GRIND_CHUNK: u64 = 1 << 12;

impl GrindOps<Poseidon2M31Channel> for SimdBackend {
    /// The smallest nonce `verify_pow_nonce` accepts: a round of chunks at a
    /// time across the thread pool, each scanned in order.
    fn grind(channel: &Poseidon2M31Channel, pow_bits: u32) -> u64 {
        let prefix = channel.pow_prefix(pow_bits);
        let chunks_per_round = 4 * rayon::current_num_threads() as u64;
        (0..)
            .find_map(|round: u64| {
                let first = round * chunks_per_round;
                (first..first + chunks_per_round)
                    .into_par_iter()
                    .filter_map(|chunk| grind_chunk(&prefix, pow_bits, chunk * GRIND_CHUNK))
                    .min()
            })
            .expect("a nonce below 2^64")
    }
}

/// The first nonce in `[start, start + GRIND_CHUNK)` whose permutation has
/// `pow_bits` trailing zeros in word 0.
fn grind_chunk(prefix: &[BaseField; 8], pow_bits: u32, start: u64) -> Option<u64> {
    (start..start + GRIND_CHUNK)
        .step_by(LANES)
        .find_map(|first| {
            let mut state: States = [[0; LANES]; N_STATE];
            for (word, value) in state.iter_mut().zip(prefix) {
                *word = [value.0; LANES];
            }
            for lane in 0..LANES {
                for (word, limb) in state[8..12]
                    .iter_mut()
                    .zip(super::u64_limbs(first + lane as u64))
                {
                    word[lane] = limb.0;
                }
            }
            permute_x16(&mut state);
            (0..LANES)
                .find(|&lane| state[0][lane].trailing_zeros() >= pow_bits)
                .map(|lane| first + lane as u64)
        })
}

impl BackendForChannel<P2MerkleChannel> for SimdBackend {}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::channel::Channel;
    use stwo::core::vcs_lifted::verifier::MerkleVerifierLifted;
    use stwo::prover::backend::simd::column::BaseColumn;
    use stwo::prover::vcs_lifted::prover::MerkleProverLifted;

    fn column(log_size: u32, seed: u32) -> BaseColumn {
        (0..1u32 << log_size)
            .map(|row| {
                let x = row.wrapping_mul(0x9e37_79b9) ^ seed.wrapping_mul(0x85eb_ca6b);
                // Include P, the redundant zero a packed column may hold.
                BaseField::from_u32_unchecked(if x.is_multiple_of(97) { P } else { x % P })
            })
            .collect()
    }

    fn cpu_leaves(columns: &[BaseColumn], lifting_log_size: u32) -> Vec<P2Hash> {
        let cpu: Vec<Vec<BaseField>> = columns.iter().map(|c| c.to_cpu()).collect();
        let refs: Vec<&Vec<BaseField>> = cpu.iter().collect();
        <CpuBackend as MerkleOpsLifted<P2MerkleHasher>>::build_leaves(&refs, lifting_log_size)
    }

    fn simd_leaves(columns: &[BaseColumn], lifting_log_size: u32) -> Vec<P2Hash> {
        let refs: Vec<&BaseColumn> = columns.iter().collect();
        <SimdBackend as MerkleOpsLifted<P2MerkleHasher>>::build_leaves(&refs, lifting_log_size)
    }

    #[test]
    fn leaves_equal_the_cpu_backend_over_lifted_groups() {
        // Sizes in increasing order, groups that straddle a sponge block and
        // the sixteen-leaf boundary, and a final lift.
        let shapes: [&[(u32, usize)]; 5] = [
            &[(1, 1)],
            &[(2, 3), (3, 2)],
            &[(3, 5), (4, 3), (6, 9), (7, 1)],
            &[(4, 8), (5, 16), (8, 7)],
            &[(2, 1), (5, 13), (5, 0), (9, 21)],
        ];
        for (shape_index, shape) in shapes.iter().enumerate() {
            let columns: Vec<BaseColumn> = shape
                .iter()
                .flat_map(|&(log_size, count)| (0..count).map(move |c| (log_size, c)))
                .enumerate()
                .map(|(i, (log_size, _))| column(log_size, i as u32))
                .collect();
            let max = columns.last().unwrap().len().ilog2();
            for lifting_log_size in [max, max + 2] {
                assert_eq!(
                    simd_leaves(&columns, lifting_log_size),
                    cpu_leaves(&columns, lifting_log_size),
                    "shape {shape_index}, lifting to {lifting_log_size}"
                );
            }
        }
    }

    #[test]
    fn nodes_equal_the_cpu_backend() {
        for log_size in [1, 4, 5, 6, 9] {
            let leaves = simd_leaves(&[column(log_size, 3), column(log_size, 4)], log_size);
            assert_eq!(
                <SimdBackend as MerkleOpsLifted<P2MerkleHasher>>::build_next_layer(&leaves),
                <CpuBackend as MerkleOpsLifted<P2MerkleHasher>>::build_next_layer(&leaves),
                "log size {log_size}"
            );
        }
    }

    #[test]
    fn the_grind_finds_the_cpu_backends_nonce() {
        for (seed, pow_bits) in [(1u32, 4), (2, 9), (3, 13)] {
            let mut channel = Poseidon2M31Channel::default();
            channel.mix_u32s(&[seed, seed * 7]);
            let simd = <SimdBackend as GrindOps<Poseidon2M31Channel>>::grind(&channel, pow_bits);
            let cpu = <CpuBackend as GrindOps<Poseidon2M31Channel>>::grind(&channel, pow_bits);
            assert_eq!(simd, cpu, "seed {seed}, {pow_bits} bits");
            assert!(channel.verify_pow_nonce(pow_bits, simd));
        }
    }

    #[test]
    fn a_committed_tree_decommits_and_verifies() {
        let log_sizes = [3, 3, 6, 6, 6, 6, 6, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8];
        let columns: Vec<BaseColumn> = log_sizes
            .iter()
            .enumerate()
            .map(|(i, &log_size)| column(log_size, 100 + i as u32))
            .collect();
        let refs: Vec<&BaseColumn> = columns.iter().collect();
        let lifting_log_size = 9;
        let prover = MerkleProverLifted::<SimdBackend, P2MerkleHasher>::commit(
            refs.clone(),
            lifting_log_size,
            0,
        );
        let cpu_columns: Vec<Vec<BaseField>> = columns.iter().map(|c| c.to_cpu()).collect();
        let cpu = MerkleProverLifted::<CpuBackend, P2MerkleHasher>::commit(
            cpu_columns.iter().collect(),
            lifting_log_size,
            0,
        );
        assert_eq!(prover.root(), cpu.root());

        let queries = [0, 5, 77, 300, 511, 77];
        let (values, decommitment) = prover.decommit(&queries, refs);
        let verifier = MerkleVerifierLifted::<P2MerkleHasher>::new(
            prover.root(),
            log_sizes.to_vec(),
            Some(lifting_log_size),
        );
        verifier
            .verify(&queries, values.clone(), decommitment.decommitment.clone())
            .expect("the honest decommitment verifies");

        let mut tampered = values;
        tampered[7][3] += BaseField::from_u32_unchecked(1);
        assert!(
            verifier
                .verify(&queries, tampered, decommitment.decommitment)
                .is_err(),
            "a changed value is refused"
        );
    }

    #[test]
    fn an_empty_tree_hashes_as_the_cpu_backend() {
        assert_eq!(
            simd_leaves(&[], 0),
            vec![P2MerkleHasher::default().finalize()]
        );
    }
}
