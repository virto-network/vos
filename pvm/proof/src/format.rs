//! The proof format registry.
//!
//! A proof's `format_version` names an entry here, and the entry decides, at
//! run time, the proof's channel, its parameters and its encodings: one
//! verifier build reads every admitted format, and a prover is told which
//! format to produce.
//!
//! | number | proofs | channel | log blowup, queries, PoW, fold step, last layer, interaction PoW | floors | at its reference shape |
//! |---|---|---|---|---|---|
//! | 28 | the final wrap, masked | Blake2b-256 | 6, 20, 26, 3, 6, 8 | 100 / 80 | 146 / 74, short without affine batching |
//! | 30 | credential proofs, masked | Blake2s-M31 | 1, 86, 20, 1, 0, 8 | 100 / 60 | 106 / 62 |
//! | 31 | segments | Poseidon2-M31 | 2, 44, 20, 1, 0, 8 | 100 / 60 | 108 / 62 |
//! | 32 | leaves and folds | Poseidon2-M31 | 2, 44, 20, 1, 0, 8 | 100 / 60 | 108 / 63 |
//! | 33 | segments, legacy encodings | Blake2s | the proof's own, 96 conjectured bits or more | 96 / — | MOBILE: 96 / 57 |
//! | 34 | device proofs, masked | Blake2s-M31 | 1, 86, 20, 1, 0, 8 | 100 / 60 | 106 / 62 |
//!
//! - **The segment AIR** is the one every segment, leaf and device format
//!   names: 31, 32, 33 and 34 name its hardened form (the witness input, the
//!   Ristretto chips removed, the AIR audit's fixes), and the numbers that
//!   named its earlier form, 24 to 27 and 29, are [`RETIRED`]: refused, and
//!   never registered again. 28 and 30 prove the recursion AIR and keep
//!   their numbers.
//! - **33** is the Blake2s segment format the default entry points produce,
//!   kept while the refine bundles, the chain proofs and their tests use it.
//!   Its transcript has no interaction PoW and mixes the boundary states a
//!   word at a time, and its parameters are the proof's own under the 96-bit
//!   conjectured floor.
//! - **28 and 30 to 32, and 34** use the lossless encodings
//!   ([`Encoding::Lossless`]) and exactly their parameters. 28, 30, 32 and 34
//!   are registered and refused until their AIRs and channels exist; the
//!   wrap's fold step 3 is refused until it is reviewed.
//! - **The inner formats** (31, 32) grind 20 bits of PoW and 8 of interaction
//!   PoW and take 44 queries: 62.8 proven bits for segments, the query
//!   term binding.
//! - **The device and credential formats** (34, 30) take the least query
//!   count, 86, whose proven count clears the floor of 60 by 2 bits.
//! - **The wrap** (28) needs DEEP batching with an independent coefficient a
//!   sampled value ([`DeepBatching::Affine`]) for its proven 80. Stwo batches
//!   by powers of one coefficient, whose error is the batched values' count
//!   times a proximity-gap error that grows with the blowup: at blowup 64 that
//!   term caps the count at 74.7 however many queries are taken, 18 or 20.
//!   The ways to 80 are affine batching at blowup 64 and 19–20 queries (about
//!   1.06× the verifier's cost, a change to the fork for this format only), a
//!   6-bit PoW in the batching phase at blowup 64 and 20 queries (about
//!   1.11×), or blowup 8 with 41 queries (about 1.97×). The entry carries the
//!   affine plan's parameters; [`crate::security`] counts what is built and
//!   finds 74.
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

/// How values enter a format's hashes and transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// Format 33's: the boundary states mixed a word at a time, and no
    /// interaction PoW.
    Legacy,
    /// The boundary states as the boundary chips' bytes, one M31 a byte, in
    /// one run; every other u64 as four 16-bit limbs (a u32 two); and the
    /// interaction PoW before the relation challenges.
    Lossless,
}

/// How a format's DEEP quotient batches its sampled values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeepBatching {
    /// By powers of one coefficient: Stwo's, what [`crate::security`]
    /// counts.
    Powers,
    /// An independent coefficient a sampled value, whose error loses the
    /// factor of the values' count. Not built: a format that names it needs
    /// it for its proven floor.
    Affine,
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
        }
    }

    /// The parameters of a proof's own config, with `interaction_pow_bits`.
    pub fn of(config: &PcsConfig, interaction_pow_bits: u32) -> Self {
        Self {
            log_blowup: config.fri_config.log_blowup_factor,
            n_queries: config.fri_config.n_queries,
            pow_bits: config.pow_bits,
            fold_step: config.fri_config.fold_step,
            log_last_layer: config.fri_config.log_last_layer_degree_bound,
            interaction_pow_bits,
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
    pub encoding: Encoding,
    /// The parameters a proof must carry exactly, but for format 33, which
    /// takes the proof's own and records MOBILE's here.
    pub params: FormatParams,
    pub masked: bool,
    /// The DEEP batching the format's proven floor assumes.
    pub batching: DeepBatching,
    pub floor: SecurityFloor,
    pub status: Status,
    /// The shape [`Format::bits`] is counted at.
    pub reference: SecurityShape,
    /// [`crate::security::security_bits`] at `reference`, pinned by the
    /// format tests.
    pub bits: SecurityBits,
}

impl Format {
    /// Whether a proof's parameters must equal [`Format::params`].
    pub const fn exact_params(&self) -> bool {
        matches!(self.encoding, Encoding::Lossless)
    }

    pub const fn pcs_config(&self) -> PcsConfig {
        self.params.pcs_config()
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

/// The number the default prover produces: the legacy Blake2s segment
/// format.
pub const LEGACY_SEGMENT_NUMBER: u32 = 33;

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
    sampled_values: 9_047,
    max_samples_per_column: 2,
    constraints: 5_177,
    logup_fractions: 1_553_989_632,
    relation_width: SEGMENT_RELATION_WIDTH,
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
/// two samples; 313 constraints of degree 3; 5, 4 and 6 fractions a row.
pub const LEAF_FOLD_REFERENCE: SecurityShape = SecurityShape {
    log_degree_bound: 18,
    log_trace_length: 17,
    log_composition_degree_bound: 19,
    sampled_values: 2 * 458,
    max_samples_per_column: 2,
    constraints: 313,
    logup_fractions: (5 << 16) + (4 << 17) + (6 << 16),
    relation_width: RECURSION_RELATION_WIDTH,
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

/// The credential AIR (`proving.md` §8): the recursion AIR's `p2`, 354
/// columns and 303 constraints, at 2^14 rows.
pub const CREDENTIAL_REFERENCE: SecurityShape = SecurityShape {
    log_degree_bound: 15,
    log_trace_length: 14,
    log_composition_degree_bound: 16,
    sampled_values: 2 * 354,
    max_samples_per_column: 2,
    constraints: 303,
    logup_fractions: 5 << 14,
    relation_width: RECURSION_RELATION_WIDTH,
};

const INNER: FormatParams = FormatParams {
    log_blowup: 2,
    n_queries: 44,
    pow_bits: 20,
    fold_step: 1,
    log_last_layer: 0,
    interaction_pow_bits: 8,
};

const DEVICE: FormatParams = FormatParams {
    log_blowup: 1,
    n_queries: 86,
    pow_bits: 20,
    fold_step: 1,
    log_last_layer: 0,
    interaction_pow_bits: 8,
};

const INNER_FLOOR: SecurityFloor = SecurityFloor {
    conjectured: 100,
    proven: 60,
};

pub const LEGACY_SEGMENT: Format = Format {
    number: LEGACY_SEGMENT_NUMBER,
    kind: ProofKind::Segment,
    channel: ChannelKind::Blake2s,
    encoding: Encoding::Legacy,
    params: FormatParams {
        log_blowup: 2,
        n_queries: 38,
        pow_bits: 20,
        fold_step: 1,
        log_last_layer: 0,
        interaction_pow_bits: 0,
    },
    masked: false,
    batching: DeepBatching::Powers,
    floor: SecurityFloor {
        conjectured: crate::proof::MIN_CONJECTURED_SECURITY_BITS,
        proven: 0,
    },
    status: Status::Admitted,
    reference: SEGMENT_REFERENCE,
    bits: SecurityBits {
        conjectured: 96,
        proven: 57,
    },
};

pub const SEGMENT: Format = Format {
    number: 31,
    kind: ProofKind::Segment,
    channel: ChannelKind::Poseidon2M31,
    encoding: Encoding::Lossless,
    params: INNER,
    masked: false,
    batching: DeepBatching::Powers,
    floor: INNER_FLOOR,
    status: Status::Admitted,
    reference: SEGMENT_REFERENCE,
    bits: SecurityBits {
        conjectured: 108,
        proven: 62,
    },
};

pub const LEAF_FOLD: Format = Format {
    number: 32,
    kind: ProofKind::LeafFold,
    channel: ChannelKind::Poseidon2M31,
    encoding: Encoding::Lossless,
    params: INNER,
    masked: false,
    batching: DeepBatching::Powers,
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
    encoding: Encoding::Lossless,
    params: FormatParams {
        log_blowup: 6,
        n_queries: 20,
        pow_bits: 26,
        fold_step: 3,
        log_last_layer: 6,
        interaction_pow_bits: 8,
    },
    masked: true,
    batching: DeepBatching::Affine,
    floor: SecurityFloor {
        conjectured: 100,
        proven: 80,
    },
    status: Status::Reserved,
    reference: WRAP_REFERENCE,
    bits: SecurityBits {
        conjectured: 146,
        proven: 74,
    },
};

pub const DEVICE_PROOF: Format = Format {
    number: 34,
    kind: ProofKind::Device,
    channel: ChannelKind::Blake2sM31,
    encoding: Encoding::Lossless,
    params: DEVICE,
    masked: true,
    batching: DeepBatching::Powers,
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
    encoding: Encoding::Lossless,
    params: DEVICE,
    masked: true,
    batching: DeepBatching::Powers,
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
    SEGMENT,
    LEAF_FOLD,
    LEGACY_SEGMENT,
    DEVICE_PROOF,
];

/// The numbers whose AIR a later format superseded: 24 and its Poseidon2-M31
/// variant 25, and 26, 27 and 29, the registry's first segment, leaf and
/// device formats, all of the segment AIR before its hardening. Each is
/// refused and never registered again, so a number names one AIR.
pub const RETIRED: [u32; 5] = [24, 25, 26, 27, 29];

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
            "proof format {number} is retired: its AIR is superseded"
        )),
        None => Err(alloc::format!("proof format {number} is not registered")),
    }
}

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
    /// every format clears its floors but the wrap, which needs affine
    /// batching for its proven count.
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
                (28, 146, 74),
                (30, 106, 62),
                (31, 108, 62),
                (32, 108, 63),
                (33, 96, 57),
                (34, 106, 62),
            ]
        );
        for format in REGISTRY {
            assert_eq!(
                format.meets_floors(),
                format.batching == DeepBatching::Powers,
                "format {}",
                format.number
            );
        }
    }

    /// The unrounded counts the parameters were chosen by: the inner formats'
    /// 62.8, and the device formats' least query count whose count clears 62.
    #[test]
    fn the_parameters_are_the_least_that_clear_their_margins() {
        let count = |params: &FormatParams, shape: &SecurityShape| {
            crate::security::proven_count(params, shape).unwrap()
        };
        let segment = count(&SEGMENT.params, &SEGMENT_REFERENCE);
        assert!((62.79..62.80).contains(&segment), "{segment}");
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

    /// The wrap counts 74.7 proven bits at blowup 64 with 18 queries or 20,
    /// and as many queries as the analysis takes: the batching term of
    /// powers-of-one-coefficient DEEP binds, and it grows with the blowup. At
    /// blowup 8 it reaches 80 with 41 queries. The verifier's check says so.
    #[test]
    fn the_wrap_falls_short_without_affine_batching() {
        let proven = |log_blowup, n_queries| {
            let params = FormatParams {
                log_blowup,
                n_queries,
                ..WRAP.params
            };
            crate::security::proven_count(&params, &WRAP_REFERENCE).unwrap()
        };
        assert_eq!(WRAP.batching, DeepBatching::Affine);
        for queries in [18, 20, 256] {
            let bits = proven(6, queries);
            assert!((74.71..74.72).contains(&bits), "{queries} queries: {bits}");
        }
        let least = |log_blowup| (1..=256).find(|&q| proven(log_blowup, q) >= 80.0);
        assert_eq!([least(6), least(4), least(3)], [None, None, Some(41)]);
        let error = crate::proof::check_format_security(&WRAP, &WRAP.pcs_config(), &WRAP_REFERENCE)
            .unwrap_err();
        assert!(
            error.contains("74 proven bits, below format 28's floor of 80"),
            "{error}"
        );
    }

    /// Every number names one entry; only 31 and 33 are admitted; the
    /// retired numbers are refused as retired and name no entry; every other
    /// number is refused.
    #[test]
    fn the_registry_numbers_round_trip() {
        for format in REGISTRY {
            assert_eq!(lookup(format.number), Some(&format));
            assert_eq!(
                admitted(format.number).is_ok(),
                [31, 33].contains(&format.number)
            );
            assert!(!RETIRED.contains(&format.number), "{}", format.number);
        }
        assert!(REGISTRY.windows(2).all(|w| w[0].number < w[1].number));
        for number in RETIRED {
            assert!(lookup(number).is_none());
            let error = admitted(number).unwrap_err();
            assert!(error.contains("retired"), "{error}");
        }
        for number in (0..24).chain([35, u32::MAX]) {
            assert!(lookup(number).is_none());
            assert!(admitted(number).is_err());
        }
        assert_eq!(LEGACY_SEGMENT.number, crate::proof::PROOF_FORMAT_VERSION);
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
        fewer.fri_config.n_queries = 39;
        let error = check(&SEGMENT, &fewer, &SEGMENT_REFERENCE).unwrap_err();
        assert!(error.contains("98 conjectured bits"), "{error}");

        // 15 + 44 · 2 = 103 conjectured, but the query term tends to
        // 15 + 44 = 59 proven bits.
        let mut less_pow = config;
        less_pow.pow_bits = 15;
        let error = check(&SEGMENT, &less_pow, &SEGMENT_REFERENCE).unwrap_err();
        assert!(
            error.contains("proven bits, below format 31's floor of 60"),
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
        stronger.fri_config.n_queries = 45;
        let error = check(&SEGMENT, &stronger, &SEGMENT_REFERENCE).unwrap_err();
        assert!(error.contains("differ from format 31"), "{error}");

        // Format 33 takes its own parameters at its conjectured floor.
        let standard = PcsConfig {
            pow_bits: 20,
            fri_config: FriConfig::new(0, 4, 19, 1),
            lifting_log_size: None,
        };
        assert!(check(&LEGACY_SEGMENT, &standard, &SEGMENT_REFERENCE).is_ok());
    }
}
