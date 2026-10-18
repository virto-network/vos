//! A segment verifier circuit's shape: everything it is built for, fixed
//! before any proof is read (`recursion-air.md` §2: a circuit is its
//! wiring).
//!
//! The circuit is built for one segment format and one kernel class: a
//! component mask and its log sizes, and the program's preprocessed root.
//! From them come the statement header the channel mixes and the circuit's
//! geometry ([`StarkShape`]: the trees' column orders, the sample points,
//! the relations' draw order, the compiled constraints and FRI's layers).
//! [`SegmentShape::new`] refuses, as the
//! native verifier does, a format not admitted, a log size out of range and
//! a shape below the format's security floor: no circuit is built for a
//! shape the native verifier refuses. [`SegmentShape::check`] refuses a
//! proof of another shape, field by field, before its values reach a
//! circuit; in the circuit, the header the channel mixes is checked against
//! the shape's constants word by word, and every structural use of the log
//! sizes is the shape's, every length of the values checked against it.
//! [`SegmentShape::chip_isolated`] is a chip's shape without the boundary
//! chips, whose logup check is the claimed sums' total alone: a chip's leaf
//! measured, never a segment's.

use core::cell::RefCell;
use std::rc::Rc;

use stwo::core::channel::Channel as _;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::PcsConfig;
use vos_pvm_proof::boundary_binding::{BoundaryChipPositions, boundary_positions_in_mask};
use vos_pvm_proof::format::{Format, Status};
use vos_pvm_proof::framework_access::boundary_relation_challenges;
use vos_pvm_proof::framework_access::{AllLookupElements, draw_all_lookup_elements};
use vos_pvm_proof::pcs::Commitment;
use vos_pvm_proof::poseidon2::{P2Hash, PermKind, Poseidon2M31Channel};
use vos_pvm_proof::proof::{MIN_PROOF_LOG_SIZE, check_format_security};
use vos_pvm_proof::{DEFAULT_MAX_LOG_SIZE, Proof, chip_idx, sample_layout};

use crate::compile::{self, Recording};

use super::stark::StarkShape;

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

/// The words `mix_statement_header` mixes for a proof under the format
/// `number` at `config` and `log_sizes`, as `mix_u64` takes them.
pub(crate) fn header_words(number: u32, config: &PcsConfig, log_sizes: &[u32]) -> Vec<u64> {
    let mut header = HeaderWords::default();
    vos_pvm_proof::proof::mix_statement_header(&mut header, number, config, log_sizes);
    header.0
}

/// The chips whose claimed sums the boundary states bind.
const BOUNDARY_CHIPS: u32 = 1 << chip_idx::REGISTER_MEMORY_BOUNDARY
    | 1 << chip_idx::REGISTER_MEMORY_CLOSING
    | 1 << chip_idx::PROGRAM_BOUNDARY
    | 1 << chip_idx::MEMORY_ROOT_BOUNDARY;

/// Where the boundary chips' claimed sums are checked against the public
/// terms over the boundary states.
#[derive(Clone, Copy, Debug)]
pub struct BoundaryTerms {
    /// The register-memory, program-execution and Merkle-node relations'
    /// indices in [`StarkShape::relations`].
    pub relations: [usize; 3],
    pub positions: BoundaryChipPositions,
}

/// A segment verifier circuit's shape.
pub struct SegmentShape {
    /// Its geometry: the trees, the samples, DEEP's plan, FRI's layers and
    /// the compiled constraints.
    pub stark: StarkShape,
    pub component_mask: u32,
    pub log_sizes: Vec<u32>,
    pub preprocessed_root: P2Hash,
    /// The statement header's words: the domain, the format, the PCS
    /// configuration, then each log size.
    pub header: Vec<u64>,
    /// The boundary chips' public terms; none in a chip-isolated shape.
    pub boundary: Option<BoundaryTerms>,
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
        let positions =
            boundary_positions_in_mask(component_mask).expect("the boundary chips are active");
        Self::build(
            format,
            component_mask,
            log_sizes,
            preprocessed_root,
            Some(positions),
        )
    }

    /// The shape of a chip-isolated proof
    /// (`vos_pvm_proof::prove_chip_isolated_format`): its logup check is the
    /// claimed sums' total alone, as `verify_with_explicit_components`
    /// checks it, without the boundary binding. Such a proof binds no
    /// boundary state and is no segment; it measures a chip's leaf.
    ///
    /// # Panics
    /// As [`SegmentShape::new`], and when the mask holds any boundary chip:
    /// a segment's shape is built by [`SegmentShape::new`] alone.
    pub fn chip_isolated(
        format: &'static Format,
        component_mask: u32,
        log_sizes: &[u32],
        preprocessed_root: P2Hash,
    ) -> Self {
        assert!(
            component_mask & BOUNDARY_CHIPS == 0,
            "a mask without the boundary chips"
        );
        Self::build(format, component_mask, log_sizes, preprocessed_root, None)
    }

    fn build(
        format: &'static Format,
        component_mask: u32,
        log_sizes: &[u32],
        preprocessed_root: P2Hash,
        positions: Option<BoundaryChipPositions>,
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

        let header = header_words(format.number, &config, log_sizes);

        let layout = sample_layout(component_mask, log_sizes, &config);
        if let Err(refusal) = check_format_security(format, &config, &layout.security_shape) {
            panic!("a shape the format's floors admit: {refusal}");
        }
        let (relations, lookup) = draw_order(component_mask);
        let challenges = lookup.relation_challenges();
        let boundary = positions.map(|positions| BoundaryTerms {
            relations: boundary_relation_challenges(&lookup).map(|(z, _)| {
                let name = &challenges
                    .iter()
                    .find(|relation| relation.z == z)
                    .expect("a drawn relation")
                    .name;
                relations
                    .iter()
                    .position(|known| known == name)
                    .expect("a drawn relation")
            }),
            positions,
        });

        let recordings: Vec<Recording> = layout
            .components
            .iter()
            .map(|component| Recording::chip(component.chip, component.log_size, &lookup))
            .collect();
        let compiled = compile::compile(&recordings, &compile::relations_of(&challenges));
        Self {
            stark: StarkShape::new(format, layout, relations, compiled),
            component_mask,
            log_sizes: log_sizes.to_vec(),
            preprocessed_root,
            header,
            boundary,
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
        self.stark.config()
    }

    /// Refuses a proof of another shape.
    pub fn check(&self, proof: &Proof) -> Result<(), ShapeMismatch> {
        if proof.format_version != self.stark.format.number {
            return Err(ShapeMismatch::Format {
                circuit: self.stark.format.number,
                proof: proof.format_version,
            });
        }
        if self.stark.format.verifier_config(&proof.pcs_config) != self.config() {
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
