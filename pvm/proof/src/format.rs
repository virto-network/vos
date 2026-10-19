//! The proof format registry.
//!
//! A proof's `format_version` names an entry here, and the entry decides, at
//! run time, the proof's channel, its parameters and its encodings: one
//! verifier build reads every admitted format, and a prover is told which
//! format to produce.
//!
//! | number | proofs | channel | log blowup, queries, PoW, fold step, last layer, interaction PoW | floors | at its reference shape |
//! |---|---|---|---|---|---|
//! | 28 | the final wrap | Blake2b-256 | 6, 20, 26, 3, 6, 8, affine DEEP batching | 100 / 80 | 146 / 82 |
//! | 30 | credential proofs, masked | Blake2s-M31 | 1, 86, 20, 1, 0, 8 | 100 / 60 | 106 / 62 |
//! | 32 | leaves and folds | Poseidon2-M31 | 2, 44, 20, 1, 0, 8 | 100 / 60 | 108 / 63 |
//! | 35 | segments | Poseidon2-M31 | 2, 40, 24, 1, 0, 8 | 100 / 60 | 104 / 62 |
//! | 37 | device proofs, masked | Blake2s-M31 | 1, 86, 20, 1, 0, 8 | 100 / 60 | 106 / 62 |
//! | 39 | the final wrap, masked | Blake2b-256 | 5, 24, 26, 3, 6, 8, affine DEEP batching | 100 / 80 | 146 / 82 |
//!
//! - **The segment AIR** is the one every segment, leaf and device format
//!   names: 35 and 37 name its current form, without the columns and
//!   next-row masks no constraint reads, and 32's leaves verify it. The
//!   numbers that named its earlier forms are [`RETIRED`]: refused, and never
//!   registered again. 24 to 27 and 29 named it before its hardening (the
//!   witness input, the removal of the curve chips, the AIR audit's fixes); 31,
//!   33 and 34 named the hardened form with those columns, 31 at 44 queries;
//!   36 named its legacy Blake2s form, below the proven floor.
//!   28, 30, 32 and 39 prove the recursion AIR (`vos-pvm-recair-air`) and
//!   keep their numbers.
//! - **Every format** takes exactly its parameters, mixes the boundary
//!   states as the boundary chips' bytes and grinds its interaction PoW
//!   before the relation challenges. 30 and 37 are
//!   registered and refused until their AIRs and channels exist, and 39 until
//!   its masked AIR, prover and verifier do. 32 is registered and refused
//!   although its AIR and channel exist: `vos-pvm-recair` proves and verifies
//!   its proofs natively, pinning each circuit by its hash, and no verifier
//!   outside the recursion reads a leaf or a fold. 28 is admitted:
//!   `vos-pvm-recair` proves the wrap on the fork's Blake2b-256 channel and
//!   `vos-pvm-final-verifier` verifies it, fold step 3 reviewed in the fork. A
//!   segment verifier takes only a segment format ([`admitted_segment`]).
//! - **The inner formats** grind 8 bits of interaction PoW. Segments (35)
//!   take 40 queries and 24 bits of PoW: 62.86 proven bits, the query term
//!   binding, and 104 conjectured. A kernel leaf's rows grow with the
//!   segment's width times its queries, and 4 fewer queries keep the leaf's
//!   `p2` under 2^16 with room. Leaves and folds (32) take 44 queries and 20
//!   bits: a fold verifies under half the recursion AIR's shape.
//! - **The device and credential formats** (37, 30) take the least query
//!   count, 86, whose proven count clears the floor of 60 by 2 bits.
//! - **The wrap** (28) needs DEEP batching with an independent coefficient a
//!   sampled value ([`DeepBatching::Affine`]) for its proven 80. Stwo batches
//!   by powers of one coefficient, whose error is the batched values' count
//!   times a proximity-gap error that grows with the blowup: at blowup 64 that
//!   term caps the count at 74.7 however many queries are taken, 18 or 20.
//!   The ways to 80 are affine batching at blowup 64 and 19–20 queries (about
//!   1.06× the verifier's cost, a change to the fork for this format only), a
//!   6-bit PoW in the batching phase at blowup 64 and 20 queries (about
//!   1.11×), or blowup 8 with 41 queries (about 1.97×). The fork batches
//!   affinely when a configuration asks ([`FormatParams::batching`]), and
//!   [`crate::security`] counts 82.6 at 20 queries (80 needs 19). Batching is
//!   not in a proof's bytes: a verifier sets it from the format
//!   ([`Format::verifier_config`]). 39 needs it too: batched by powers, it
//!   caps at 76.98 at blowup 32 and 74.48 at blowup 64.
//! - **The masked wrap** (39) is 28's AIR under masking variant (c)
//!   (`research/slice-5/spike2-masking.md` §3b; [`crate::security`] counts
//!   it): every main and interaction column masked to twice its rows'
//!   degree, the preprocessed ones left as they are, the composition
//!   committed whole at four times the tallest component's rows and sampled
//!   at `π(z)`, R2's blinding, a FRI mask of eight columns and salted trees.
//!   It takes a number of its own, as a bump of 28 would make one number
//!   name two sets of parameters. Its FRI runs at blowup 32, where each
//!   column's own extension is the size 28's is at 64, with 24 queries:
//!   146 / 82 (82.70), the query term binding; 23 queries is the least that
//!   clears 80 (80.84). Blowup 64 at 20 queries counts 81.74, its DEEP
//!   batching term binding, at twice the prover's memory. Its proofs are a
//!   fixed layout ([`ProofBytes::FixedLayout`]); 28's are postcard.
//! - **`masked`** says what a format's proofs are: masking a format's proofs
//!   is a format change.
//! - **The bit counts** are [`crate::security`]'s, at each entry's reference
//!   shape; the verifier counts again at the proof's own shape and refuses a
//!   proof below either floor.

use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;

use crate::security::{SecurityBits, SecurityShape};

/// What a format proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    Segment,
    LeafFold,
    Wrap,
    Device,
    Credential,
}

/// The Merkle hash and Fiat–Shamir channel of a format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelKind {
    Blake2s,
    Poseidon2M31,
    Blake2sM31,
    Blake2b256,
}

/// How a format's DEEP quotient batches its sampled values: by powers of one
/// coefficient (Stwo's), or with an independent coefficient a sampled value
/// (the fork's, `DIVERGENCE-012`), whose error loses the factor of the
/// values' count. A proof does not carry it: a verifier sets it from the
/// format ([`Format::verifier_config`]).
pub use stwo::core::pcs::DeepBatching;

/// How a format's proofs are laid out in bytes when they leave the prover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofBytes {
    /// The proof's serde form, the final wrap's as its postcard encoding:
    /// varint lengths, whose canonical form a decoder checks by re-encoding.
    Postcard,
    /// The fields in a fixed order, little-endian, with explicit u32 counts
    /// and no varints, every count checked against the format before any
    /// allocation, nothing after the last field: one encoding a proof.
    FixedLayout,
}

/// Whether a verifier accepts a format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Admitted,
    /// Registered, with its parameters and counts, and refused until its AIR
    /// and channel exist.
    Reserved,
}

/// A format's PCS parameters, and its interaction PoW.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormatParams {
    pub log_blowup: u32,
    pub n_queries: usize,
    pub pow_bits: u32,
    pub fold_step: u32,
    pub log_last_layer: u32,
    pub interaction_pow_bits: u32,
    pub batching: DeepBatching,
}

impl FormatParams {
    pub const fn pcs_config(&self) -> PcsConfig {
        PcsConfig {
            pow_bits: self.pow_bits,
            fri_config: FriConfig {
                log_last_layer_degree_bound: self.log_last_layer,
                log_blowup_factor: self.log_blowup,
                n_queries: self.n_queries,
                fold_step: self.fold_step,
            },
            lifting_log_size: None,
            deep_batching: self.batching,
        }
    }

    /// The parameters of a proof's own config, with its format's
    /// `interaction_pow_bits` and `batching`: a proof's config does not
    /// carry its batching.
    pub fn of(config: &PcsConfig, interaction_pow_bits: u32, batching: DeepBatching) -> Self {
        Self {
            log_blowup: config.fri_config.log_blowup_factor,
            n_queries: config.fri_config.n_queries,
            pow_bits: config.pow_bits,
            fold_step: config.fri_config.fold_step,
            log_last_layer: config.fri_config.log_last_layer_degree_bound,
            interaction_pow_bits,
            batching,
        }
    }
}

/// The least counts a verifier accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityFloor {
    pub conjectured: u32,
    pub proven: u32,
}

/// One registry entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    pub number: u32,
    pub kind: ProofKind,
    pub channel: ChannelKind,
    /// The parameters a proof must carry exactly.
    pub params: FormatParams,
    pub bytes: ProofBytes,
    pub masked: bool,
    pub floor: SecurityFloor,
    pub status: Status,
    /// The shape [`Format::bits`] is counted at.
    pub reference: SecurityShape,
    /// [`crate::security::security_bits`] at `reference`, pinned by the
    /// format tests.
    pub bits: SecurityBits,
}

impl Format {
    /// The format's configuration, its DEEP batching among it.
    pub const fn pcs_config(&self) -> PcsConfig {
        self.params.pcs_config()
    }

    /// The configuration a verifier checks a proof under: the proof's own,
    /// with the format's DEEP batching, which a proof does not carry (its
    /// deserialized config reads [`DeepBatching::Powers`]).
    pub const fn verifier_config(&self, proof: &PcsConfig) -> PcsConfig {
        PcsConfig {
            deep_batching: self.params.batching,
            ..*proof
        }
    }

    /// The interaction PoW a proof under this format grinds, 0 for none.
    pub const fn interaction_pow_bits(&self) -> u32 {
        self.params.interaction_pow_bits
    }

    /// Whether [`Format::bits`] clears both floors.
    pub const fn meets_floors(&self) -> bool {
        self.bits.conjectured >= self.floor.conjectured && self.bits.proven >= self.floor.proven
    }
}

/// Every segment AIR's widest relation (`Blake2bCompression`, 265 limbs),
/// rounded up.
const SEGMENT_RELATION_WIDTH: u64 = 265;
/// The recursion AIR's one relation, `Gate`: an address and four limbs.
const RECURSION_RELATION_WIDTH: u64 = 5;

/// Every chip of the segment AIR at 2^20 rows (`framework_access`'s
/// `security_shape` of the full component set; a test recomputes it).
pub const SEGMENT_REFERENCE: SecurityShape = SecurityShape {
    log_degree_bound: 20,
    log_trace_length: 20,
    log_composition_degree_bound: 21,
    sampled_values: 10_016,
    max_samples_per_column: 3,
    constraints: 5_177,
    logup_fractions: 1_553_989_632,
    relation_width: SEGMENT_RELATION_WIDTH,
    composition_point_doublings: 0,
};

/// Every chip of the segment AIR at 2^16 rows, a phone's segment.
pub const DEVICE_REFERENCE: SecurityShape = SecurityShape {
    log_degree_bound: 16,
    log_trace_length: 16,
    log_composition_degree_bound: 17,
    logup_fractions: 97_124_352,
    ..SEGMENT_REFERENCE
};

/// The recursion AIR's padded shape (`recursion-air.md` §0, §1.2): `p2`,
/// `qm31` and `h8` at 2^16, 2^17 and 2^16 rows; 458 columns, each counted at
/// two DEEP values (an upper bound: the batch holds 486), a column at most
/// three; 313 constraints of degree 3; 5, 4 and 6 fractions a row.
pub const LEAF_FOLD_REFERENCE: SecurityShape = SecurityShape {
    log_degree_bound: 18,
    log_trace_length: 17,
    log_composition_degree_bound: 19,
    sampled_values: 2 * 458,
    max_samples_per_column: 3,
    constraints: 313,
    logup_fractions: (5 << 16) + (4 << 17) + (6 << 16),
    relation_width: RECURSION_RELATION_WIDTH,
    composition_point_doublings: 0,
};

/// The wrap (`recursion-air.md` §7): the same AIR at 2^14, 2^15 and 2^11
/// rows.
pub const WRAP_REFERENCE: SecurityShape = SecurityShape {
    log_degree_bound: 16,
    log_trace_length: 15,
    log_composition_degree_bound: 17,
    logup_fractions: (5 << 14) + (4 << 15) + (6 << 11),
    ..LEAF_FOLD_REFERENCE
};

/// The values the masked wrap's DEEP quotient batches, exactly: one for
/// each sampled column (57 preprocessed, 373 main and 40 interaction
/// columns, the composition's 4 whole and the FRI mask's 8; the salts are
/// never sampled), and two more for each of the 28 columns read at the
/// previous row, `p2`'s 16 and each component's running sum, sampled twice
/// and given a periodicity value.
const MASKED_WRAP_DEEP_VALUES: u64 = (57 + 373 + 40 + 4 + 8) + 2 * (16 + 3 * 4);

/// The wrap masked under variant (c), format 39's reference: the AIR of
/// [`WRAP_REFERENCE`] at its tallest component's 2^15 rows, its columns at
/// degree bound 2^16, its composition whole at 2^17 and sampled at `π(z)`
/// ([`SecurityShape::variant_c`]), plus what the masking commits beside it:
/// the shape of the built masked components, which a test derives. The batch
/// is counted exactly (`MASKED_WRAP_DEEP_VALUES`); it enters only the count
/// by powers. R2's blinding adds a fraction a row a component on a relation
/// nothing else uses: `p2`'s pairs with its lone fraction, and `qm31`'s and
/// `h8`'s take a new pair column and its constraint each.
pub const MASKED_WRAP_REFERENCE: SecurityShape = SecurityShape {
    sampled_values: MASKED_WRAP_DEEP_VALUES,
    constraints: WRAP_REFERENCE.constraints + 2,
    logup_fractions: (6 << 14) + (5 << 15) + (7 << 11),
    ..WRAP_REFERENCE.variant_c()
};

/// The credential AIR (`proving.md` §8): the recursion AIR's `p2`, 354
/// columns and 303 constraints, at 2^14 rows.
pub const CREDENTIAL_REFERENCE: SecurityShape = SecurityShape {
    log_degree_bound: 15,
    log_trace_length: 14,
    log_composition_degree_bound: 16,
    sampled_values: 2 * 354,
    max_samples_per_column: 3,
    constraints: 303,
    logup_fractions: 5 << 14,
    relation_width: RECURSION_RELATION_WIDTH,
    composition_point_doublings: 0,
};

/// Segments': fewer queries and more PoW than [`LEAF_FOLD_PARAMS`], for the
/// kernel leaf's rows, which grow with the queries times the segment's width.
const SEGMENT_PARAMS: FormatParams = FormatParams {
    log_blowup: 2,
    n_queries: 40,
    pow_bits: 24,
    fold_step: 1,
    log_last_layer: 0,
    interaction_pow_bits: 8,
    batching: DeepBatching::Powers,
};

/// Leaves' and folds': a fold verifies under half the recursion AIR's
/// shape, so its rows leave room for 44 queries.
const LEAF_FOLD_PARAMS: FormatParams = FormatParams {
    log_blowup: 2,
    n_queries: 44,
    pow_bits: 20,
    fold_step: 1,
    log_last_layer: 0,
    interaction_pow_bits: 8,
    batching: DeepBatching::Powers,
};

const DEVICE: FormatParams = FormatParams {
    log_blowup: 1,
    n_queries: 86,
    pow_bits: 20,
    fold_step: 1,
    log_last_layer: 0,
    interaction_pow_bits: 8,
    batching: DeepBatching::Powers,
};

const INNER_FLOOR: SecurityFloor = SecurityFloor {
    conjectured: 100,
    proven: 60,
};

pub const SEGMENT: Format = Format {
    number: 35,
    kind: ProofKind::Segment,
    channel: ChannelKind::Poseidon2M31,
    params: SEGMENT_PARAMS,
    bytes: ProofBytes::Postcard,
    masked: false,
    floor: INNER_FLOOR,
    status: Status::Admitted,
    reference: SEGMENT_REFERENCE,
    bits: SecurityBits {
        conjectured: 104,
        proven: 62,
    },
};

/// The padded shape every leaf and fold proves at, [`LEAF_FOLD`]'s
/// (`proving.md` §3.4): `p2`, `qm31` and `h8` at 2^16, 2^17 and 2^16 rows.
/// One shape for both, so a fold verifies either child with one circuit,
/// and a fold's own rows fit it (`recursion-air.md` §6, the fixed point).
pub const LEAF_FOLD_LOG_SIZES: [u32; 3] = [16, 17, 16];

pub const LEAF_FOLD: Format = Format {
    number: 32,
    kind: ProofKind::LeafFold,
    channel: ChannelKind::Poseidon2M31,
    params: LEAF_FOLD_PARAMS,
    bytes: ProofBytes::Postcard,
    masked: false,
    floor: INNER_FLOOR,
    status: Status::Reserved,
    reference: LEAF_FOLD_REFERENCE,
    bits: SecurityBits {
        conjectured: 108,
        proven: 63,
    },
};

pub const WRAP: Format = Format {
    number: 28,
    kind: ProofKind::Wrap,
    channel: ChannelKind::Blake2b256,
    params: FormatParams {
        log_blowup: 6,
        n_queries: 20,
        pow_bits: 26,
        fold_step: 3,
        log_last_layer: 6,
        interaction_pow_bits: 8,
        batching: DeepBatching::Affine,
    },
    bytes: ProofBytes::Postcard,
    masked: false,
    floor: SecurityFloor {
        conjectured: 100,
        proven: 80,
    },
    status: Status::Admitted,
    reference: WRAP_REFERENCE,
    bits: SecurityBits {
        conjectured: 146,
        proven: 82,
    },
};

/// The final wrap, masked: see the module's notes.
pub const MASKED_WRAP: Format = Format {
    number: 39,
    kind: ProofKind::Wrap,
    channel: ChannelKind::Blake2b256,
    params: FormatParams {
        log_blowup: 5,
        n_queries: 24,
        ..WRAP.params
    },
    bytes: ProofBytes::FixedLayout,
    masked: true,
    floor: WRAP.floor,
    status: Status::Reserved,
    reference: MASKED_WRAP_REFERENCE,
    bits: SecurityBits {
        conjectured: 146,
        proven: 82,
    },
};

pub const DEVICE_PROOF: Format = Format {
    number: 37,
    kind: ProofKind::Device,
    channel: ChannelKind::Blake2sM31,
    params: DEVICE,
    bytes: ProofBytes::Postcard,
    masked: true,
    floor: INNER_FLOOR,
    status: Status::Reserved,
    reference: DEVICE_REFERENCE,
    bits: SecurityBits {
        conjectured: 106,
        proven: 62,
    },
};

pub const CREDENTIAL_PROOF: Format = Format {
    number: 30,
    kind: ProofKind::Credential,
    channel: ChannelKind::Blake2sM31,
    params: DEVICE,
    bytes: ProofBytes::Postcard,
    masked: true,
    floor: INNER_FLOOR,
    status: Status::Reserved,
    reference: CREDENTIAL_REFERENCE,
    bits: SecurityBits {
        conjectured: 106,
        proven: 62,
    },
};

/// Every registered format, by number.
pub const REGISTRY: [Format; 6] = [
    WRAP,
    CREDENTIAL_PROOF,
    LEAF_FOLD,
    SEGMENT,
    DEVICE_PROOF,
    MASKED_WRAP,
];

/// The numbers no format takes again, each refused:
/// - **superseded AIRs:** 24 and its Poseidon2-M31 variant 25, and 26, 27
///   and 29, the registry's first segment, leaf and device formats, all of
///   the segment AIR before its hardening; 31, 33 and 34, the segment,
///   legacy and device formats of the hardened AIR with the columns no
///   constraint reads;
/// - **36, below the floor:** the legacy Blake2s segment format of the
///   current AIR, its parameters the proof's own under a 96-bit conjectured
///   floor, 57 proven bits at its MOBILE shape, below the inner formats'
///   60; its boundary states mixed a word at a time and no interaction PoW;
/// - **40, never registered:** the masked wrap at blowup 64 and 20 queries,
///   proved and measured as a candidate for 39. A proof was made under it,
///   so no later format takes it.
///
/// So a number names one AIR and one set of parameters.
pub const RETIRED: [u32; 10] = [24, 25, 26, 27, 29, 31, 33, 34, 36, 40];

/// The entry for `number`, admitted or not.
pub fn lookup(number: u32) -> Option<&'static Format> {
    REGISTRY.iter().find(|format| format.number == number)
}

/// The entry for `number`, if a verifier accepts proofs under it.
pub fn admitted(number: u32) -> Result<&'static Format, alloc::string::String> {
    match lookup(number) {
        Some(format) if format.status == Status::Admitted => Ok(format),
        Some(format) => Err(alloc::format!(
            "proof format {number} ({:?}) is registered but not admitted",
            format.kind
        )),
        None if RETIRED.contains(&number) => Err(alloc::format!(
            "proof format {number} is retired: no format takes it again"
        )),
        None => Err(alloc::format!("proof format {number} is not registered")),
    }
}

/// The entry for `number`, if it is admitted and names segment proofs: what
/// a segment verifier accepts.
pub fn admitted_segment(number: u32) -> Result<&'static Format, alloc::string::String> {
    let format = admitted(number)?;
    if format.kind != ProofKind::Segment {
        return Err(alloc::format!(
            "proof format {number} ({:?}) does not name segment proofs",
            format.kind
        ));
    }
    Ok(format)
}

#[cfg(test)]
#[path = "format_masked_tests.rs"]
mod masked_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework_access::{
        AllLookupElements, air_layout, create_verifier_components, draw_all_lookup_elements,
    };
    use alloc::vec::Vec;
    use num_traits::Zero;
    use stwo::core::air::Component;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::TraceLocationAllocator;

    /// The segment AIR's shape with every chip at `2^log_size` rows.
    fn segment_air_shape(log_size: u32, format: &Format) -> SecurityShape {
        let count = crate::chip_idx::COUNT;
        let mask = ((1u64 << count) - 1) as u32;
        let log_sizes = alloc::vec![log_size; count];
        let (trace_sizes, preprocessed) =
            create_verifier_components::trace_and_preprocessed_sizes(&log_sizes, mask);
        let mut trees = TreeVec::concat_cols(trace_sizes.into_iter());
        trees[0] = preprocessed;
        let mut lookups = AllLookupElements::default();
        draw_all_lookup_elements(
            &mut lookups,
            &mut stwo::core::channel::Blake2sChannel::default(),
            mask,
        );
        let components = create_verifier_components::components(
            &mut TraceLocationAllocator::default(),
            &lookups,
            &log_sizes,
            &alloc::vec![SecureField::zero(); count],
            mask,
        );
        let refs: Vec<&dyn Component> = components.iter().map(|c| &**c).collect();
        air_layout(&format.pcs_config(), &refs, &trees)
            .unwrap()
            .security_shape(&refs)
    }

    /// The registry's segment and device reference shapes are the segment
    /// AIR's, every chip at 2^20 and 2^16 rows.
    #[test]
    fn the_reference_shapes_are_the_segment_airs() {
        assert_eq!(segment_air_shape(20, &SEGMENT), SEGMENT_REFERENCE);
        assert_eq!(segment_air_shape(16, &DEVICE_PROOF), DEVICE_REFERENCE);
        assert_eq!(
            crate::lookups::MAX_RELATION_WIDTH as u64,
            SEGMENT_RELATION_WIDTH
        );
    }

    /// The tool's two counts, pinned per format at its reference shape:
    /// every format clears its floors, the wrap with affine batching.
    #[test]
    fn the_bit_counts_are_pinned_per_format() {
        let pinned: Vec<(u32, u32, u32)> = REGISTRY
            .iter()
            .map(|format| {
                let bits =
                    crate::security::security_bits(&format.params, &format.reference).unwrap();
                assert_eq!(bits, format.bits, "format {}", format.number);
                (format.number, bits.conjectured, bits.proven)
            })
            .collect();
        assert_eq!(
            pinned,
            [
                (28, 146, 82),
                (30, 106, 62),
                (32, 108, 63),
                (35, 104, 62),
                (37, 106, 62),
                (39, 146, 82),
            ]
        );
        assert!(REGISTRY.iter().all(Format::meets_floors));
        // Every format grinds an interaction PoW: the prover always grinds
        // and the verifier always checks one.
        assert!(
            REGISTRY
                .iter()
                .all(|format| format.interaction_pow_bits() > 0)
        );
    }

    /// The unrounded counts the parameters were chosen by: the segments'
    /// 62.86 at 40 queries and PoW 24, no less than 44 queries at PoW 20
    /// give the same shape, and the device formats' least query count whose
    /// count clears 62.
    #[test]
    fn the_parameters_are_the_least_that_clear_their_margins() {
        let count = |params: &FormatParams, shape: &SecurityShape| {
            crate::security::proven_count(params, shape).unwrap()
        };
        let segment = count(&SEGMENT.params, &SEGMENT_REFERENCE);
        assert!((62.85..62.86).contains(&segment), "{segment}");
        let at_44 = count(&LEAF_FOLD.params, &SEGMENT_REFERENCE);
        assert!((62.74..62.75).contains(&at_44), "{at_44}");
        for format in [DEVICE_PROOF, CREDENTIAL_PROOF] {
            let fewer = FormatParams {
                n_queries: format.params.n_queries - 1,
                ..format.params
            };
            assert!(count(&format.params, &format.reference) >= 62.0);
            if format.number == DEVICE_PROOF.number {
                assert!(count(&fewer, &format.reference) < 62.0);
            }
        }
    }

    /// The wrap counts 82.6 proven bits under affine batching, and needs 19
    /// queries for its floor of 80. Batched by powers of one coefficient it
    /// counts 74.7 at blowup 64 with 18 queries or 20, and as many queries
    /// as the analysis takes: that batching term binds, and it grows with
    /// the blowup; at blowup 8 it reaches 80 with 41 queries. The verifier's
    /// check says so.
    #[test]
    fn the_wrap_needs_affine_batching() {
        let count = |batching, log_blowup, n_queries| {
            let params = FormatParams {
                log_blowup,
                n_queries,
                batching,
                ..WRAP.params
            };
            crate::security::proven_count(&params, &WRAP_REFERENCE).unwrap()
        };
        assert_eq!(WRAP.params.batching, DeepBatching::Affine);
        let affine = count(DeepBatching::Affine, 6, 20);
        assert!((82.60..82.61).contains(&affine), "{affine}");
        let least =
            |batching, log_blowup| (1..=256).find(|&q| count(batching, log_blowup, q) >= 80.0);
        assert_eq!(least(DeepBatching::Affine, 6), Some(19));

        for queries in [18, 20, 256] {
            let bits = count(DeepBatching::Powers, 6, queries);
            assert!((74.71..74.72).contains(&bits), "{queries} queries: {bits}");
        }
        assert_eq!(
            [6, 4, 3].map(|log_blowup| least(DeepBatching::Powers, log_blowup)),
            [None, None, Some(41)]
        );
        let powers = Format {
            params: FormatParams {
                batching: DeepBatching::Powers,
                ..WRAP.params
            },
            ..WRAP
        };
        let error =
            crate::proof::check_format_security(&powers, &powers.pcs_config(), &WRAP_REFERENCE)
                .unwrap_err();
        assert!(
            error.contains("74 proven bits, below format 28's floor of 80"),
            "{error}"
        );
        assert_eq!(
            crate::proof::check_format_security(&WRAP, &WRAP.pcs_config(), &WRAP_REFERENCE),
            Ok(WRAP.bits)
        );
    }

    /// A proof's config does not carry its batching: deserialized, it reads
    /// powers, and the verifier takes the format's.
    #[test]
    fn the_verifier_takes_the_batching_from_the_format() {
        let carried = PcsConfig {
            deep_batching: DeepBatching::Powers,
            ..WRAP.pcs_config()
        };
        assert_eq!(WRAP.verifier_config(&carried), WRAP.pcs_config());
        assert_eq!(WRAP.pcs_config().deep_batching, DeepBatching::Affine);
        assert!(crate::proof::check_format_security(&WRAP, &carried, &WRAP_REFERENCE).is_ok());
        for format in [SEGMENT, LEAF_FOLD] {
            assert_eq!(format.pcs_config().deep_batching, DeepBatching::Powers);
        }
    }

    /// Every number names one entry; only 28 and 35 are admitted, and a
    /// segment verifier takes 35 alone; the retired numbers are
    /// refused as retired and name no entry; every other number is refused.
    #[test]
    fn the_registry_numbers_round_trip() {
        for format in REGISTRY {
            assert_eq!(lookup(format.number), Some(&format));
            assert_eq!(
                admitted(format.number).is_ok(),
                [WRAP.number, SEGMENT.number].contains(&format.number)
            );
            assert_eq!(
                admitted_segment(format.number).is_ok(),
                format.number == SEGMENT.number
            );
            assert!(!RETIRED.contains(&format.number), "{}", format.number);
        }
        assert!(REGISTRY.windows(2).all(|w| w[0].number < w[1].number));
        for number in RETIRED {
            assert!(lookup(number).is_none());
            let error = admitted(number).unwrap_err();
            assert!(error.contains("retired"), "{error}");
        }
        for number in (0..24).chain([38, u32::MAX]) {
            assert!(lookup(number).is_none());
            assert!(admitted(number).is_err());
        }
        assert_eq!(SEGMENT.number, crate::proof::PROOF_FORMAT_VERSION);
    }

    /// A proof below either floor is refused: fewer queries than the
    /// conjectured floor allows, less PoW than the proven floor allows, a
    /// shape whose proven count falls short, and parameters other than the
    /// format's.
    #[test]
    fn a_proof_below_a_floor_is_refused() {
        let check = crate::proof::check_format_security;
        let config = SEGMENT.pcs_config();
        assert_eq!(
            check(&SEGMENT, &config, &SEGMENT_REFERENCE).unwrap(),
            SEGMENT.bits
        );

        let mut fewer = config;
        fewer.fri_config.n_queries = 37;
        let error = check(&SEGMENT, &fewer, &SEGMENT_REFERENCE).unwrap_err();
        assert!(error.contains("98 conjectured bits"), "{error}");

        // 20 + 40 · 2 = 100 conjectured, but the query term tends to
        // 20 + 40 = 60 proven bits, and falls short of it.
        let mut less_pow = config;
        less_pow.pow_bits = 20;
        let error = check(&SEGMENT, &less_pow, &SEGMENT_REFERENCE).unwrap_err();
        assert!(
            error.contains("59 proven bits, below format 35's floor of 60"),
            "{error}"
        );

        // 2^30 sampled values over a 2^28-row trace: the batching term binds.
        let wide = SecurityShape {
            log_degree_bound: 28,
            log_trace_length: 28,
            log_composition_degree_bound: 29,
            sampled_values: 1 << 30,
            ..SEGMENT_REFERENCE
        };
        let error = check(&SEGMENT, &config, &wide).unwrap_err();
        assert!(error.contains("proven bits"), "{error}");

        let mut stronger = config;
        stronger.fri_config.n_queries = 41;
        let error = check(&SEGMENT, &stronger, &SEGMENT_REFERENCE).unwrap_err();
        assert!(error.contains("differ from format 35"), "{error}");
    }
}
