//! A segment proof's values as a verifier circuit reads them: the witness
//! builder. It runs the native verifier's own walk over a valid proof
//! (`vos_pvm_proof::extract_recursion_data`), then lays each value where
//! the circuit guesses it: per query, in the order the queries were drawn
//! (repeats kept), each tree's sorted leaf row and its whole path, and each
//! FRI layer's sibling and path ([`expand_decommitment`]).
//!
//! [`SegmentValues::blank`] is the same layout without values, for the
//! circuit's wiring alone.
//!
//! The FRI walk is adapted from Stwo, as the workspace pins it,
//! crates/stwo/src/core/fri.rs (`compute_decommitment_positions_and_rebuild_evals`
//! and `SparseEvaluation`'s folds, Apache-2.0), modified to keep every
//! layer's values by position and expand its decommitment.

use std::collections::BTreeMap;

use num_traits::Zero;
use stwo::core::circle::Coset;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::{fold_circle_into_line, fold_coset};
use stwo::core::pcs::utils::prepare_preprocessed_query_positions;
use stwo::core::poly::circle::{CanonicCoset, CircleDomain};
use stwo::core::poly::line::LineDomain;
use stwo::core::proof::StarkProof;
use stwo::core::utils::bit_reverse_index;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use vos_pvm_proof::Proof;
use vos_pvm_proof::boundary_binding::{BOUNDARY_STATE_BYTES, boundary_state_bytes};
use vos_pvm_proof::pcs::StarkProofAny;
use vos_pvm_proof::poseidon2::{P2Hash, P2MerkleHasher, PermKind};

use crate::value::Value;

use super::channel::u64_wire;
use super::fri::FriOpening;
use super::merkle::{ExpandError, Expanded, expand_decommitment};
use super::shape::{SegmentShape, ShapeMismatch};

/// A query's opening of a trace tree: its leaf's row, sorted and packed
/// four values a wire, and its path, the leaf's sibling first.
#[derive(Clone, Debug)]
pub struct TreeOpening<V> {
    pub leaf: Vec<V>,
    pub path: Vec<[V; 2]>,
}

/// A query's openings: the four trees, then FRI's layers.
#[derive(Clone, Debug)]
pub struct QueryValues<V> {
    pub trees: Vec<TreeOpening<V>>,
    pub fri: Vec<FriOpening<V>>,
}

/// Every value a segment verifier circuit guesses.
#[derive(Clone, Debug)]
pub struct SegmentValues<V> {
    /// The statement header's words, each as four 16-bit limbs.
    pub header: Vec<V>,
    /// The main, interaction and composition roots.
    pub roots: [[V; 2]; 3],
    /// The boundary states' 296 bytes, four a wire.
    pub boundary: Vec<V>,
    pub interaction_nonce: V,
    pub claimed_sums: Vec<V>,
    /// The sampled values, by tree, column and sample.
    pub sampled: Vec<V>,
    /// FRI's roots, the first layer's first.
    pub fri_roots: Vec<[V; 2]>,
    pub last_layer: V,
    pub nonce: V,
    /// Per query, in draw order.
    pub queries: Vec<QueryValues<V>>,
}

/// Why a proof's values cannot be laid out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessError {
    Shape(ShapeMismatch),
    Expand(ExpandError),
    /// A recomputed root is not the proof's.
    Root(&'static str),
}

impl From<ShapeMismatch> for WitnessError {
    fn from(error: ShapeMismatch) -> Self {
        Self::Shape(error)
    }
}

impl From<ExpandError> for WitnessError {
    fn from(error: ExpandError) -> Self {
        Self::Expand(error)
    }
}

/// `values` packed four a wire, zeros past the end.
pub fn pack(values: &[BaseField]) -> Vec<SecureField> {
    values
        .chunks(4)
        .map(|chunk| {
            SecureField::from_m31_array(core::array::from_fn(|i| {
                chunk.get(i).copied().unwrap_or_else(BaseField::zero)
            }))
        })
        .collect()
}

/// A digest's two wires.
pub fn digest_wires(hash: &P2Hash) -> [SecureField; 2] {
    let packed = pack(&hash.0);
    [packed[0], packed[1]]
}

fn leaf_of(row: &[BaseField]) -> P2Hash {
    let mut hasher = P2MerkleHasher::default();
    hasher.update_leaf(row);
    hasher.finalize()
}

impl<V: Value> SegmentValues<V> {
    /// The layout of `shape`'s values, every value zero (or no value).
    pub fn blank(shape: &SegmentShape) -> Self {
        let zero = V::from_qm31(SecureField::zero());
        let lifting = shape.layout.lifting_log_size as usize;
        let query = QueryValues {
            trees: (0..4)
                .map(|tree| TreeOpening {
                    leaf: vec![zero; shape.leaf_order[tree].len().div_ceil(4)],
                    path: vec![[zero; 2]; shape.heights[tree] as usize],
                })
                .collect(),
            fri: (0..shape.n_fri_layers)
                .map(|layer| FriOpening {
                    sibling: zero,
                    path: vec![[zero; 2]; lifting - layer - 1],
                })
                .collect(),
        };
        Self {
            header: vec![zero; shape.header.len()],
            roots: [[zero; 2]; 3],
            boundary: vec![zero; BOUNDARY_STATE_BYTES.div_ceil(4)],
            interaction_nonce: zero,
            claimed_sums: vec![zero; shape.log_sizes.len()],
            sampled: vec![zero; shape.n_samples],
            fri_roots: vec![[zero; 2]; shape.n_fri_layers],
            last_layer: zero,
            nonce: zero,
            queries: vec![query; shape.config().fri_config.n_queries],
        }
    }
}

impl SegmentValues<SecureField> {
    /// The values of `proof`, a valid proof of `shape`.
    ///
    /// # Panics
    /// When the proof does not verify natively: the builder lays out a valid
    /// proof's values, which a test may then tamper.
    pub fn from_proof(shape: &SegmentShape, proof: &Proof) -> Result<Self, WitnessError> {
        shape.check(proof)?;
        let StarkProofAny::Poseidon2M31(stark) = &proof.stark_proof else {
            return Err(ShapeMismatch::Structure("not a Poseidon2-M31 proof").into());
        };
        let data = vos_pvm_proof::extract_recursion_data(proof);
        let config = shape.config();
        let n_queries = config.fri_config.n_queries;
        let lifting = shape.layout.lifting_log_size;
        if data.lifting_log_size != lifting || stark.sampled_values.len() != 4 {
            return Err(ShapeMismatch::Structure("the trees").into());
        }

        // The positions in draw order: the transcript's last squeezes.
        let n_draws = n_queries.div_ceil(8);
        let records = &data.transcript.records;
        let draws = &records[records.len() - n_draws..];
        assert!(draws.iter().all(|record| record.kind == PermKind::Squeeze));
        let mask = (1usize << lifting) - 1;
        let drawn: Vec<usize> = draws
            .iter()
            .flat_map(|record| record.output[..8].iter().map(|word| word.0 as usize & mask))
            .take(n_queries)
            .collect();
        let mut sorted = drawn.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, data.query_positions, "the drawn positions");

        let trees = trace_openings(shape, stark, &data.query_positions)?;
        let fri = fri_openings(
            shape,
            stark,
            &data.query_positions,
            &data.first_layer_evals,
            &data.fold_alphas,
        )?;

        let queries = drawn
            .iter()
            .map(|&position| {
                let index = data.query_positions.binary_search(&position).unwrap();
                QueryValues {
                    trees: trees.iter().map(|tree| tree[index].clone()).collect(),
                    fri: fri
                        .iter()
                        .enumerate()
                        .map(|(layer, (values, expanded))| {
                            let position = position >> layer;
                            FriOpening {
                                sibling: values[&(position ^ 1)],
                                path: expanded.path(position)[1..]
                                    .iter()
                                    .map(digest_wires)
                                    .collect(),
                            }
                        })
                        .collect(),
                }
            })
            .collect();

        let bytes = boundary_state_bytes(&proof.initial_state, &proof.final_state);
        let bytes: Vec<BaseField> = bytes.iter().map(|&b| BaseField::from(b as u32)).collect();
        let fri_proof = &stark.fri_proof;
        let fri_roots = core::iter::once(&fri_proof.first_layer)
            .chain(&fri_proof.inner_layers)
            .map(|layer| digest_wires(&layer.commitment))
            .collect();
        let [last_layer] = fri_proof.last_layer_poly[..] else {
            return Err(ShapeMismatch::Structure("a last layer of one coefficient").into());
        };
        Ok(Self {
            header: shape.header.iter().map(|&word| u64_wire(word)).collect(),
            roots: [1, 2, 3].map(|tree| digest_wires(&stark.commitments[tree])),
            boundary: pack(&bytes),
            interaction_nonce: u64_wire(proof.interaction_pow),
            claimed_sums: proof.claimed_sums.clone(),
            sampled: stark
                .sampled_values
                .iter()
                .flatten()
                .flatten()
                .copied()
                .collect(),
            fri_roots,
            last_layer,
            nonce: u64_wire(stark.proof_of_work),
            queries,
        })
    }
}

/// Each trace tree's opening at each sorted query position.
fn trace_openings(
    shape: &SegmentShape,
    stark: &StarkProof<P2MerkleHasher>,
    positions: &[usize],
) -> Result<Vec<Vec<TreeOpening<SecureField>>>, WitnessError> {
    let lifting = shape.layout.lifting_log_size;
    (0..4)
        .map(|tree| {
            let tree_positions = if tree == 0 {
                prepare_preprocessed_query_positions(positions, lifting, shape.heights[0])
            } else {
                positions.to_vec()
            };
            let columns = &stark.queried_values[tree];
            if columns.len() != shape.leaf_order[tree].len()
                || columns.iter().any(|column| column.len() != positions.len())
            {
                return Err(ShapeMismatch::Structure("the queried values").into());
            }
            let rows: Vec<Vec<BaseField>> = (0..positions.len())
                .map(|index| {
                    shape.leaf_order[tree]
                        .iter()
                        .map(|&column| columns[column][index])
                        .collect()
                })
                .collect();
            let leaves: BTreeMap<usize, P2Hash> = tree_positions
                .iter()
                .zip(&rows)
                .map(|(&position, row)| (position, leaf_of(row)))
                .collect();
            let leaves: Vec<(usize, P2Hash)> = leaves.into_iter().collect();
            let expanded = expand_decommitment::<P2MerkleHasher>(
                shape.heights[tree],
                &leaves,
                &stark.decommitments[tree].hash_witness,
            )?;
            if expanded.root != stark.commitments[tree] {
                return Err(WitnessError::Root("a trace tree"));
            }
            Ok(tree_positions
                .iter()
                .zip(&rows)
                .map(|(&position, row)| TreeOpening {
                    leaf: pack(row),
                    path: expanded.path(position).iter().map(digest_wires).collect(),
                })
                .collect())
        })
        .collect()
}

/// Each FRI layer's values at its decommitted positions, and its expanded
/// decommitment: Stwo's `decommit` walk, the folds by Stwo's own
/// functions.
#[allow(clippy::type_complexity)]
fn fri_openings(
    shape: &SegmentShape,
    stark: &StarkProof<P2MerkleHasher>,
    positions: &[usize],
    first_layer_evals: &[SecureField],
    alphas: &[SecureField],
) -> Result<Vec<(BTreeMap<usize, SecureField>, Expanded<P2Hash>)>, WitnessError> {
    let lifting = shape.layout.lifting_log_size;
    let fri = &stark.fri_proof;
    let layers: Vec<_> = core::iter::once(&fri.first_layer)
        .chain(&fri.inner_layers)
        .collect();
    if layers.len() != shape.n_fri_layers {
        return Err(ShapeMismatch::Structure("FRI's layers").into());
    }
    let circle = CanonicCoset::new(lifting).circle_domain();
    let mut line = LineDomain::new(Coset::half_odds(lifting - 1));
    let mut positions = positions.to_vec();
    let mut evals = first_layer_evals.to_vec();
    let mut out = Vec::with_capacity(layers.len());
    for (layer, proof_layer) in layers.iter().enumerate() {
        let log_size = lifting - layer as u32;
        let mut witness = proof_layer.fri_witness.iter().copied();
        let mut values = BTreeMap::new();
        for subset in positions.chunk_by(|a, b| a >> 1 == b >> 1) {
            let start = subset[0] & !1;
            for position in start..start + 2 {
                let value = match subset.iter().position(|&p| p == position) {
                    Some(_) => evals[positions.binary_search(&position).unwrap()],
                    None => witness
                        .next()
                        .ok_or(WitnessError::Root("a FRI witness too short"))?,
                };
                values.insert(position, value);
            }
        }
        if witness.next().is_some() {
            return Err(WitnessError::Root("a FRI witness too long"));
        }
        let leaves: Vec<(usize, P2Hash)> = values
            .iter()
            .map(|(&position, value)| (position, leaf_of(&value.to_m31_array())))
            .collect();
        let expanded = expand_decommitment::<P2MerkleHasher>(
            log_size,
            &leaves,
            &proof_layer.decommitment.hash_witness,
        )?;
        if expanded.root != proof_layer.commitment {
            return Err(WitnessError::Root("a FRI layer"));
        }
        let alpha = alphas[layer];
        let mut next: Vec<usize> = positions.iter().map(|p| p >> 1).collect();
        next.dedup();
        evals = next
            .iter()
            .map(|&k| {
                let pair = [values[&(2 * k)], values[&(2 * k + 1)]];
                let start = bit_reverse_index(2 * k, log_size);
                if layer == 0 {
                    let domain = CircleDomain::new(Coset::new(circle.index_at(start), 0));
                    fold_circle_into_line(&pair, domain, alpha)[0]
                } else {
                    let domain = LineDomain::new(Coset::new(line.coset().index_at(start), 1));
                    fold_coset(pair.to_vec(), domain, alpha)
                }
            })
            .collect();
        if layer > 0 {
            line = line.double();
        }
        positions = next;
        out.push((values, expanded));
    }
    let [last] = stark.fri_proof.last_layer_poly[..] else {
        return Err(ShapeMismatch::Structure("a last layer of one coefficient").into());
    };
    if evals.iter().any(|&eval| eval != last) {
        return Err(WitnessError::Root("the last layer"));
    }
    Ok(out)
}
