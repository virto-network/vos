//! A verifier circuit's shape: everything it is built for, fixed before any
//! proof is read (`recursion-air.md` §2: a circuit is its wiring).
//!
//! The circuit is built for one segment format and one kernel class: a
//! component mask and its log sizes, and the program's preprocessed root.
//! From them come the statement header the channel mixes, the trees' column
//! orders, the sample points, the relations' draw order, the compiled
//! constraints and FRI's layers. [`SegmentShape::new`] refuses, as the
//! native verifier does, a format not admitted, a log size out of range and
//! a shape below the format's security floor: no circuit is built for a
//! shape the native verifier refuses. [`SegmentShape::check`] refuses a
//! proof of another shape, field by field, before its values reach a
//! circuit; in the circuit, the header the channel mixes is checked against
//! the shape's constants word by word, and every structural use of the log
//! sizes is the shape's, every length of the values checked against it.

use core::cell::RefCell;
use std::rc::Rc;

use stwo::core::channel::Channel as _;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::PcsConfig;
use vos_pvm_proof::boundary_binding::{BoundaryChipPositions, boundary_positions_in_mask};
use vos_pvm_proof::format::{ChannelKind, Encoding, Format, Status};
use vos_pvm_proof::framework_access::boundary_relation_challenges;
use vos_pvm_proof::framework_access::{AllLookupElements, draw_all_lookup_elements};
use vos_pvm_proof::pcs::Commitment;
use vos_pvm_proof::poseidon2::{P2Hash, PermKind, Poseidon2M31Channel};
use vos_pvm_proof::proof::{MIN_PROOF_LOG_SIZE, check_format_security};
use vos_pvm_proof::{DEFAULT_MAX_LOG_SIZE, Proof, SampleLayout, chip_idx, sample_layout};

use crate::compile::{self, Compiled, Input, Recording};

use super::deep::DeepPlan;

/// Why a proof is refused for a circuit's shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShapeMismatch {
    Format {
        circuit: u32,
        proof: u32,
    },
    Config,
    ComponentMask {
        circuit: u32,
        proof: u32,
    },
    LogSizes,
    PreprocessedRoot,
    /// A proof whose parts do not have the shape's dimensions.
    Structure(&'static str),
}

/// The words `mix_statement_header` mixes, as `mix_u64` takes them.
#[derive(Clone, Debug, Default)]
struct HeaderWords(Vec<u64>);

impl stwo::core::channel::Channel for HeaderWords {
    const BYTES_PER_HASH: usize = 32;

    fn verify_pow_nonce(&self, _: u32, _: u64) -> bool {
        unreachable!("the header mixes words only")
    }
    fn mix_u32s(&mut self, _: &[u32]) {
        unreachable!("the header mixes words only")
    }
    fn mix_felts(&mut self, _: &[SecureField]) {
        unreachable!("the header mixes words only")
    }
    fn mix_u64(&mut self, value: u64) {
        self.0.push(value);
    }
    fn draw_secure_felt(&mut self) -> SecureField {
        unreachable!("the header draws nothing")
    }
    fn draw_secure_felts(&mut self, _: usize) -> Vec<SecureField> {
        unreachable!("the header draws nothing")
    }
    fn draw_u32s(&mut self) -> Vec<u32> {
        unreachable!("the header draws nothing")
    }
}

/// A segment verifier circuit's shape.
pub struct SegmentShape {
    pub format: &'static Format,
    pub component_mask: u32,
    pub log_sizes: Vec<u32>,
    pub preprocessed_root: P2Hash,
    /// The statement header's words: the domain, the format, the PCS
    /// configuration, then each log size.
    pub header: Vec<u64>,
    pub layout: SampleLayout,
    /// The relations, by name, in the order the channel draws them.
    pub relations: Vec<String>,
    /// The register-memory, program-execution and Merkle-node relations'
    /// indices in [`SegmentShape::relations`].
    pub boundary_relations: [usize; 3],
    pub positions: BoundaryChipPositions,
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

impl SegmentShape {
    /// The shape of a proof under `format` with `component_mask`, its
    /// `log_sizes` in the mask's order, of the program whose preprocessed
    /// root is `preprocessed_root`.
    ///
    /// # Panics
    /// On a shape the native verifier refuses: a format not admitted, a mask
    /// outside the AIR or without its log sizes, a log size outside
    /// `MIN_PROOF_LOG_SIZE..=DEFAULT_MAX_LOG_SIZE`, or counts below the
    /// format's security floor at this shape. And when the format is not a
    /// lossless Poseidon2-M31 format at fold step 1, last layer degree bound
    /// 0 and no fixed lifting height, with both PoWs; or when the mask lacks
    /// a boundary chip.
    pub fn new(
        format: &'static Format,
        component_mask: u32,
        log_sizes: &[u32],
        preprocessed_root: P2Hash,
    ) -> Self {
        let config = format.pcs_config();
        assert_eq!(format.status, Status::Admitted, "an admitted format");
        assert!(
            component_mask != 0 && component_mask & !chip_idx::ALL == 0,
            "a mask of this AIR's chips"
        );
        assert_eq!(
            component_mask.count_ones() as usize,
            log_sizes.len(),
            "a log size a component"
        );
        assert!(
            log_sizes
                .iter()
                .all(|log_size| (MIN_PROOF_LOG_SIZE..=DEFAULT_MAX_LOG_SIZE).contains(log_size)),
            "log sizes the native verifier admits"
        );
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

        let mut header = HeaderWords::default();
        vos_pvm_proof::proof::mix_statement_header(&mut header, format.number, &config, log_sizes);

        let layout = sample_layout(component_mask, log_sizes, &config);
        if let Err(refusal) = check_format_security(format, &config, &layout.security_shape) {
            panic!("a shape the format's floors admit: {refusal}");
        }
        let (relations, lookup) = draw_order(component_mask);
        let challenges = lookup.relation_challenges();
        let boundary_relations = boundary_relation_challenges(&lookup).map(|(z, _)| {
            let name = &challenges
                .iter()
                .find(|relation| relation.z == z)
                .expect("a drawn relation")
                .name;
            relations
                .iter()
                .position(|known| known == name)
                .expect("a drawn relation")
        });
        let positions =
            boundary_positions_in_mask(component_mask).expect("the boundary chips are active");

        let recordings: Vec<Recording> = layout
            .components
            .iter()
            .map(|component| Recording::chip(component.chip, component.log_size, &lookup))
            .collect();
        let compiled = compile::compile(&recordings, &compile::relations_of(&challenges));
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
            component_mask,
            log_sizes: log_sizes.to_vec(),
            preprocessed_root,
            header: header.0,
            layout,
            relations,
            boundary_relations,
            positions,
            compiled,
            heights,
            leaf_order,
            sample_index,
            n_samples,
            deep,
            n_fri_layers,
        }
    }

    /// The shape a proof claims: its format, mask, log sizes and
    /// preprocessed root.
    pub fn of(proof: &Proof) -> Self {
        let format = vos_pvm_proof::proof::proof_format(proof).expect("an admitted format");
        Self::new(
            format,
            proof.component_mask,
            &proof.log_sizes,
            preprocessed_root(proof).expect("a Poseidon2-M31 preprocessed root"),
        )
    }

    /// The PCS configuration the circuit verifies under.
    pub fn config(&self) -> PcsConfig {
        self.format.pcs_config()
    }

    /// Refuses a proof of another shape.
    pub fn check(&self, proof: &Proof) -> Result<(), ShapeMismatch> {
        if proof.format_version != self.format.number {
            return Err(ShapeMismatch::Format {
                circuit: self.format.number,
                proof: proof.format_version,
            });
        }
        if proof.pcs_config != self.config() {
            return Err(ShapeMismatch::Config);
        }
        if proof.component_mask != self.component_mask {
            return Err(ShapeMismatch::ComponentMask {
                circuit: self.component_mask,
                proof: proof.component_mask,
            });
        }
        if proof.log_sizes != self.log_sizes {
            return Err(ShapeMismatch::LogSizes);
        }
        let root = preprocessed_root(proof).ok_or(ShapeMismatch::Structure(
            "no Poseidon2-M31 preprocessed root",
        ))?;
        if root != self.preprocessed_root {
            return Err(ShapeMismatch::PreprocessedRoot);
        }
        Ok(())
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

/// A compiled input's wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompiledInput {
    /// A sampled value, by its index in the flattened sampled values.
    Sample(usize),
    ClaimedSum(usize),
    /// A relation's draw, `0` its `z` and `1` its `α`.
    Challenge(usize, usize),
}

/// A proof's preprocessed root, when it is a Poseidon2-M31 one.
fn preprocessed_root(proof: &Proof) -> Option<P2Hash> {
    match proof.preprocessed_commitment()? {
        Commitment::Poseidon2M31(root) => Some(root),
        Commitment::Blake2s(_) => None,
    }
}

/// The relations a mask draws, in the channel's order, and the drawn
/// elements: a recording channel's squeezes, each a relation's `z` and `α`.
fn draw_order(component_mask: u32) -> (Vec<String>, AllLookupElements) {
    let records = Rc::new(RefCell::new(Vec::new()));
    let mut channel = Poseidon2M31Channel::recording(records.clone());
    channel.mix_u64(1);
    let mut lookup = AllLookupElements::default();
    draw_all_lookup_elements(&mut lookup, &mut channel, component_mask);
    let challenges = lookup.relation_challenges();
    let names = records
        .borrow()
        .iter()
        .filter(|record| record.kind == PermKind::Squeeze)
        .map(|record| {
            let z = SecureField::from_m31_array(core::array::from_fn(|i| record.output[i]));
            challenges
                .iter()
                .find(|relation| relation.z == z)
                .expect("each squeeze a relation's")
                .name
                .clone()
        })
        .collect();
    (names, lookup)
}
