//! What every verifier circuit shares, for a proof of any AIR on a lossless
//! Poseidon2-M31 format at FRI fold step 1: its geometry ([`StarkShape`]:
//! the trees' orders and heights, the samples, DEEP's plan, FRI's layers and
//! the compiled constraints), the values past the AIR's own prefix
//! ([`StarkValues`]), and the transcript from the interaction PoW on
//! ([`interaction`], [`verify_rest`]).
//!
//! An AIR's verifier runs its own prefix (a segment: its header, its
//! preprocessed root against the shape's, its boundary states; a recursion
//! AIR proof: its header, its preprocessed root, its outputs), then
//! [`interaction`], its own logup check, then [`verify_rest`], each check
//! where the native verifier makes it.

use stwo::core::pcs::PcsConfig;
use vos_pvm_proof::SampleLayout;
use vos_pvm_proof::format::{ChannelKind, Encoding, Format};

use crate::compile::{Compiled, Input};
use crate::context::{Bit, Context, Var};
use crate::value::Value;

use super::channel::Channel;
use super::circle::{Point, domain_point, random_point};
use super::deep::{self, DeepPlan};
use super::fri::{FriCommitment, verify_query};
use super::merkle::verify_opening;
use super::oods;
use super::witness::QueryValues;

/// What the channel drew, as wires.
#[derive(Clone, Debug)]
pub struct Draws {
    /// Each relation's `z` and `α`, in draw order.
    pub relations: Vec<[Var; 2]>,
    pub composition_coeff: Var,
    pub oods: Point,
    pub deep_coeff: Var,
    pub fri_alphas: Vec<Var>,
    /// Each query's position bits, least significant first, in draw order.
    pub queries: Vec<Vec<Bit>>,
}

/// The preprocessed tree's position bits from a query's, the tree `height`
/// levels at most the lifting height's `bits.len()`: Stwo's
/// `prepare_preprocessed_query_positions`, `(p >> (H − h + 1) << 1) + (p & 1)`,
/// keeps the first bit and the top `h − 1`.
pub fn preprocessed_bits(bits: &[Bit], height: u32) -> Vec<Bit> {
    let lifting = bits.len();
    let height = height as usize;
    assert!(
        (1..=lifting).contains(&height),
        "a tree no taller than the lifting"
    );
    let mut out = vec![bits[0]];
    out.extend_from_slice(&bits[lifting - height + 1..]);
    out
}

/// A verifier circuit's geometry: what it is built for past its AIR's own
/// prefix, fixed before any proof is read.
pub struct StarkShape {
    pub format: &'static Format,
    pub layout: SampleLayout,
    /// The relations, by name, in the order the channel draws them.
    pub relations: Vec<String>,
    pub compiled: Compiled,
    /// Each tree's height: preprocessed, main, interaction, composition.
    pub heights: [u32; 4],
    /// Each tree's columns in the order its leaves hash them: by log size,
    /// stable.
    pub leaf_order: Vec<Vec<usize>>,
    /// Each tree's columns' first sample's index in the sampled values.
    pub sample_index: Vec<Vec<usize>>,
    pub n_samples: usize,
    pub deep: DeepPlan,
    /// FRI's layers: the first, then the inner ones.
    pub n_fri_layers: usize,
}

/// A compiled input's wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompiledInput {
    /// A sampled value, by its index in the flattened sampled values.
    Sample(usize),
    ClaimedSum(usize),
    /// A relation's draw, `0` its `z` and `1` its `α`.
    Challenge(usize, usize),
}

impl StarkShape {
    /// The geometry of a proof under `format` whose verifier samples as
    /// `layout` says, its channel drawing `relations` (by name, in order)
    /// and its constraints `compiled`, one component a component of
    /// `layout`.
    ///
    /// # Panics
    /// When the format is not a lossless Poseidon2-M31 format at fold step
    /// 1, last layer degree bound 0 and no fixed lifting height, with both
    /// PoWs; when a compiled component's columns are not the layout's; when
    /// a trace tree is not at the lifting height, or the preprocessed tree
    /// above it.
    pub fn new(
        format: &'static Format,
        layout: SampleLayout,
        relations: Vec<String>,
        compiled: Compiled,
    ) -> Self {
        let config = format.pcs_config();
        assert_eq!(
            format.channel,
            ChannelKind::Poseidon2M31,
            "the Poseidon2-M31 channel"
        );
        assert_eq!(
            format.encoding,
            Encoding::Lossless,
            "the lossless encodings"
        );
        assert_eq!(config.fri_config.fold_step, 1, "FRI at fold step 1");
        assert_eq!(
            config.fri_config.log_last_layer_degree_bound, 0,
            "a constant last layer"
        );
        assert_eq!(
            config.lifting_log_size, None,
            "the lifting height the composition's"
        );
        assert!(
            config.pow_bits > 0 && format.interaction_pow_bits() > 0,
            "both PoWs"
        );
        assert_eq!(
            compiled.components.len(),
            layout.components.len(),
            "a compiled component a component"
        );
        for (component, place) in compiled.components.iter().zip(&layout.components) {
            for (tree, columns) in [(1, &place.main_columns), (2, &place.interaction_columns)] {
                let offsets = &component.offsets[tree - 1];
                assert_eq!(offsets.len(), columns.len(), "a component's columns");
                for (k, column) in columns.clone().enumerate() {
                    assert_eq!(
                        offsets[k].len(),
                        layout.sample_offsets[tree][column].len(),
                        "a column's samples"
                    );
                }
            }
        }

        let heights: [u32; 4] = core::array::from_fn(|tree| {
            *layout.column_log_sizes[tree]
                .iter()
                .max()
                .expect("a column")
        });
        for &height in &heights[1..] {
            assert_eq!(
                height, layout.lifting_log_size,
                "a trace tree at the lifting height"
            );
        }
        assert!(
            (2..=layout.lifting_log_size).contains(&heights[0]),
            "the preprocessed tree at most at the lifting height"
        );
        let leaf_order: Vec<Vec<usize>> = layout
            .column_log_sizes
            .iter()
            .map(|sizes| {
                let mut order: Vec<usize> = (0..sizes.len()).collect();
                order.sort_by_key(|&column| sizes[column]);
                order
            })
            .collect();
        let mut n_samples = 0;
        let sample_index = layout
            .sample_offsets
            .iter()
            .map(|tree| {
                tree.iter()
                    .map(|column| {
                        let index = n_samples;
                        n_samples += column.len();
                        index
                    })
                    .collect()
            })
            .collect();
        let deep = DeepPlan::new(&layout, &leaf_order);
        let n_fri_layers = 1 + (layout.max_log_degree_bound - 1) as usize;
        Self {
            format,
            layout,
            relations,
            compiled,
            heights,
            leaf_order,
            sample_index,
            n_samples,
            deep,
            n_fri_layers,
        }
    }

    /// The PCS configuration the circuit verifies under.
    pub fn config(&self) -> PcsConfig {
        self.format.pcs_config()
    }

    /// The wire inputs of the compiled constraints, each a sampled value's
    /// index, a claimed sum's, or a relation's challenge.
    pub fn compiled_inputs(&self) -> Vec<CompiledInput> {
        self.compiled
            .inputs
            .iter()
            .map(|input| match *input {
                Input::Sample {
                    chip,
                    tree,
                    column,
                    offset,
                } => {
                    let layout = &self.layout.components[chip];
                    let global = if tree == 0 {
                        layout.main_columns.start + column
                    } else {
                        layout.interaction_columns.start + column
                    };
                    let k = self.compiled.components[chip].offsets[tree][column]
                        .iter()
                        .position(|&o| o == offset)
                        .expect("an offset of the column's mask");
                    CompiledInput::Sample(self.sample_index[tree + 1][global] + k)
                }
                Input::Preprocessed(index) => {
                    let (chip, k) = self
                        .compiled
                        .components
                        .iter()
                        .enumerate()
                        .find_map(|(chip, component)| {
                            component
                                .preprocessed
                                .iter()
                                .position(|&read| read == index)
                                .map(|k| (chip, k))
                        })
                        .expect("a component reads it");
                    let column = self.layout.components[chip].preprocessed_indices[k];
                    CompiledInput::Sample(self.sample_index[0][column])
                }
                Input::ClaimedSum(chip) => CompiledInput::ClaimedSum(chip),
                Input::Z(r) => CompiledInput::Challenge(self.relation(r), 0),
                Input::Alpha(r) => CompiledInput::Challenge(self.relation(r), 1),
            })
            .collect()
    }

    /// The draw position of the compiled shape's relation `r`.
    fn relation(&self, r: usize) -> usize {
        let name = &self.compiled.relations[r].0;
        self.relations
            .iter()
            .position(|known| known == name)
            .expect("a drawn relation")
    }
}

/// The values a verifier circuit guesses past its AIR's own prefix.
#[derive(Clone, Debug)]
pub struct StarkValues<V> {
    /// The main, interaction and composition roots.
    pub roots: [[V; 2]; 3],
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

impl<V: Value> StarkValues<V> {
    /// The layout of `shape`'s values, every value zero (or no value).
    pub fn blank(shape: &StarkShape) -> Self {
        let zero = V::from_qm31(num_traits::Zero::zero());
        let lifting = shape.layout.lifting_log_size as usize;
        let query = QueryValues {
            trees: (0..4)
                .map(|tree| super::witness::TreeOpening {
                    leaf: vec![zero; shape.leaf_order[tree].len().div_ceil(4)],
                    path: vec![[zero; 2]; shape.heights[tree] as usize],
                })
                .collect(),
            fri: (0..shape.n_fri_layers)
                .map(|layer| super::fri::FriOpening {
                    sibling: zero,
                    path: vec![[zero; 2]; lifting - layer - 1],
                })
                .collect(),
        };
        Self {
            roots: [[zero; 2]; 3],
            interaction_nonce: zero,
            claimed_sums: vec![zero; shape.layout.components.len()],
            sampled: vec![zero; shape.n_samples],
            fri_roots: vec![[zero; 2]; shape.n_fri_layers],
            last_layer: zero,
            nonce: zero,
            queries: vec![query; shape.config().fri_config.n_queries],
        }
    }

    /// Asserts every length is `shape`'s: the circuit's structure is the
    /// shape's alone, never the values'.
    pub fn assert_lengths(&self, shape: &StarkShape) {
        let lifting = shape.layout.lifting_log_size as usize;
        assert_eq!(
            self.claimed_sums.len(),
            shape.layout.components.len(),
            "claimed sums"
        );
        assert_eq!(self.sampled.len(), shape.n_samples, "sampled values");
        assert_eq!(self.fri_roots.len(), shape.n_fri_layers, "FRI roots");
        assert_eq!(
            self.queries.len(),
            shape.config().fri_config.n_queries,
            "queries"
        );
        for query in &self.queries {
            assert_eq!(query.trees.len(), 4, "trees");
            for (tree, opening) in query.trees.iter().enumerate() {
                assert_eq!(
                    opening.leaf.len(),
                    shape.leaf_order[tree].len().div_ceil(4),
                    "leaf wires"
                );
                assert_eq!(
                    opening.path.len(),
                    shape.heights[tree] as usize,
                    "tree path nodes"
                );
            }
            assert_eq!(query.fri.len(), shape.n_fri_layers, "FRI layers");
            for (layer, opening) in query.fri.iter().enumerate() {
                assert_eq!(opening.path.len(), lifting - layer - 1, "FRI path nodes");
            }
        }
    }
}

/// The interaction PoW, then the relations drawn and the claimed sums
/// guessed and mixed: each relation's `z` and `α`, and the sums' wires.
pub fn interaction<V: Value>(
    context: &mut Context<V>,
    shape: &StarkShape,
    channel: &mut Channel<V>,
    values: &StarkValues<V>,
) -> (Vec<[Var; 2]>, Vec<Var>) {
    context.piece("pow");
    let interaction_nonce = context.guess(values.interaction_nonce);
    channel.check_pow(
        context,
        shape.format.interaction_pow_bits(),
        interaction_nonce,
    );
    context.piece("channel");
    let relations: Vec<[Var; 2]> = shape
        .relations
        .iter()
        .map(|_| channel.draw_felts(context))
        .collect();
    let claimed_sums: Vec<Var> = values
        .claimed_sums
        .iter()
        .map(|&v| context.guess(v))
        .collect();
    channel.mix_felts(context, &claimed_sums);
    (relations, claimed_sums)
}

/// The rest of the proof from the interaction root: the composition and
/// OODS, the sampled values, FRI's commitment, the PoW, the queries, and
/// each query's openings, DEEP quotient and FRI folds. `roots` are the
/// preprocessed and main roots' wires; `relations` and `claimed_sums` what
/// [`interaction`] returned. The draws and each query's first-layer value.
pub fn verify_rest<V: Value>(
    context: &mut Context<V>,
    shape: &StarkShape,
    channel: &mut Channel<V>,
    roots: [[Var; 2]; 2],
    relations: Vec<[Var; 2]>,
    claimed_sums: &[Var],
    values: &StarkValues<V>,
) -> (Draws, Vec<Var>) {
    let config = shape.config();
    let lifting = shape.layout.lifting_log_size;
    context.piece("channel");
    let interaction_root = context.guess_pair(values.roots[1]);
    channel.mix_root(context, interaction_root);
    let composition_coeff = channel.draw_felt(context);
    let composition_root = context.guess_pair(values.roots[2]);
    channel.mix_root(context, composition_root);
    let t = channel.draw_felt(context);

    context.piece("oods");
    let oods_point = random_point(context, t);
    let sampled: Vec<Var> = values.sampled.iter().map(|&v| context.guess(v)).collect();
    let inputs: Vec<Var> = shape
        .compiled_inputs()
        .into_iter()
        .map(|input| match input {
            CompiledInput::Sample(index) => sampled[index],
            CompiledInput::ClaimedSum(chip) => claimed_sums[chip],
            CompiledInput::Challenge(r, k) => relations[r][k],
        })
        .collect();
    let composition: [Var; 8] = core::array::from_fn(|c| sampled[shape.sample_index[3][c]]);
    oods::check(
        context,
        &shape.compiled,
        &inputs,
        composition_coeff,
        oods_point,
        shape.layout.max_log_degree_bound,
        composition,
    );

    context.piece("channel");
    channel.mix_felts(context, &sampled);
    let deep_coeff = channel.draw_felt(context);
    let mut fri_roots = Vec::with_capacity(shape.n_fri_layers);
    let mut fri_alphas = Vec::with_capacity(shape.n_fri_layers);
    for &root in &values.fri_roots {
        let root = context.guess_pair(root);
        channel.mix_root(context, root);
        fri_roots.push(root);
        fri_alphas.push(channel.draw_felt(context));
    }
    let last_layer = context.guess(values.last_layer);
    channel.mix_felts(context, &[last_layer]);
    context.piece("pow");
    let nonce = context.guess(values.nonce);
    channel.check_pow(context, config.pow_bits, nonce);
    context.piece("queries");
    let queries = channel.draw_queries(context, config.fri_config.n_queries, lifting);

    context.piece("deep once");
    let constants = deep::prepare(context, &shape.deep, oods_point, deep_coeff, &sampled);
    let commitment = FriCommitment {
        roots: fri_roots,
        alphas: fri_alphas.clone(),
        last_layer,
    };
    let [preprocessed_root, main_root] = roots;
    let roots = [
        preprocessed_root,
        main_root,
        interaction_root,
        composition_root,
    ];
    let mut answers = Vec::with_capacity(queries.len());
    for (bits, query) in queries.iter().zip(&values.queries) {
        context.piece("circle");
        let point = domain_point(context, lifting, bits);
        context.piece("merkle");
        let leaves: Vec<Vec<Var>> = query
            .trees
            .iter()
            .map(|tree| tree.leaf.iter().map(|&v| context.guess(v)).collect())
            .collect();
        for (tree, opening) in query.trees.iter().enumerate() {
            let tree_bits = if tree == 0 {
                preprocessed_bits(bits, shape.heights[0])
            } else {
                bits.clone()
            };
            verify_opening(
                context,
                &leaves[tree],
                shape.leaf_order[tree].len(),
                &tree_bits,
                &opening.path,
                roots[tree],
            );
        }
        context.piece("deep");
        let answer = deep::answer(
            context,
            &shape.deep,
            &constants,
            point,
            [&leaves[0], &leaves[1], &leaves[2], &leaves[3]],
        );
        context.piece("fri");
        verify_query(
            context,
            lifting,
            &commitment,
            bits,
            point,
            answer,
            &query.fri,
        );
        answers.push(answer);
    }
    context.piece("end");
    let draws = Draws {
        relations,
        composition_coeff,
        oods: oods_point,
        deep_coeff,
        fri_alphas,
        queries,
    };
    (draws, answers)
}
