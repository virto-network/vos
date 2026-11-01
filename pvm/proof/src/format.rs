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
//! | 32 | leaves and folds | Poseidon2-M31 | 2, 44, 20, 1, 0, 8 | 100 / 60 | 108 / 63 |
//! | 39 | the final wrap, masked | Blake2b-256 | 5, 24, 26, 3, 6, 8, affine DEEP batching | 100 / 80 | 146 / 82 |
//! | 41 | segments | Poseidon2-M31 | 2, 40, 24, 1, 0, 8 | 100 / 60 | 104 / 62 |
//! | 44 | credential proofs, masked | Blake2s-M31 | 2, 47, 16, 1, 0, 8, affine DEEP batching | 100 / 60 | 110 / 62 |
//! | 46 | device proofs, masked | Blake2s-M31 | 2, 47, 16, 1, 0, 8, affine DEEP batching | 100 / 60 | 110 / 62 |
//!
//! - **The segment AIR** is the one every segment, leaf and device format
//!   names: 41 and 46 name its current form, one chip set the node's
//!   segments and the device shape share (the CPU acknowledging the
//!   Poseidon2 call, the Poseidon2 chip, the logical right shifts through
//!   the multiplication, no column a constraint pins to zero), and 32's
//!   leaves verify it. The numbers that named its earlier forms are
//!   [`RETIRED`]: refused, and never registered again. 28, 32 and 39 prove the recursion AIR (`vos-pvm-recair-air`) and keep
//!   their numbers; 44 proves its `p2` and `qm31` alone, the credential AIR.
//! - **Every format** takes exactly its parameters, mixes the boundary
//!   states as the boundary chips' bytes and grinds its interaction PoW
//!   before the relation challenges. 46 is admitted: a space's ingress
//!   verifies device proofs of auth's statement against the program it
//!   computes from the installed kernel (`vos-pvm-recair`'s `device`). 32
//!   is registered and refused
//!   although its AIR and channel exist: `vos-pvm-recair` proves and verifies
//!   its proofs natively, pinning each circuit by its hash, and no verifier
//!   outside the recursion reads a leaf or a fold. 28 is admitted:
//!   `vos-pvm-recair` proves the wrap on the fork's Blake2b-256 channel and
//!   `vos-pvm-final-verifier` verifies it (under its `test-formats`
//!   feature), fold step 3 reviewed in the fork. 39 is admitted: the masked
//!   wrap, `vos-pvm-recair`'s masked prover and `vos-pvm-final-verifier`'s
//!   masked verifier, its bytes a fixed layout ([`ProofBytes::FixedLayout`]);
//!   production venues accept it alone. 44 is admitted: `vos-pvm-recair`'s
//!   credential prover and `vos-pvm-final-verifier`'s credential verifier,
//!   on the fork's Blake2s-M31 channel; a space's ingress takes it. A
//!   segment verifier takes only a segment format ([`admitted_segment`]).
//! - **The inner formats** grind 8 bits of interaction PoW. Segments (41)
//!   take 40 queries and 24 bits of PoW: 62.81 proven bits on 41's own
//!   reference (every chip, the Poseidon2 chip among them, at 2^20 rows),
//!   the query term binding, and 104 conjectured. A kernel leaf's rows grow
//!   with the segment's width times its queries, and 4 fewer queries keep
//!   the leaf's `p2` under 2^16 with room. Leaves and folds (32) take 44
//!   queries and 20 bits: a fold verifies under half the recursion AIR's
//!   shape.
//! - **The device format** (46) is counted on the device shape's masked
//!   reference ([`DEVICE_REFERENCE`]: every chip a device program may hold
//!   at `2^17` rows, the most install, the prover and the verifier admit).
//!   It takes the credential format's parameters: blowup 4, 47 queries,
//!   PoW 16, affine batching (62.82 proven bits), with `h = 256`
//!   (`proving.md` §5, how large `h` must be): every device chip reveals at
//!   most 149 rows at 47 queries, so `h = 256` holds the masking's
//!   condition without its factor two, every chip's floor at 2^10 rows.
//!   The candidates measured are in `proving.md` §4.
//! - **The credential format** (44) is counted on its masked shape
//!   ([`CREDENTIAL_REFERENCE`]): two components at the masking's floor of
//!   2^11 rows, where every blowup costs the same cells, so blowup 4, and
//!   PoW 16 with the least queries that clear 62 bits beside it, 47: PoW 16's
//!   grind keeps a short tail on a phone.
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
//!   (`proving.md` §5; [`crate::security`] counts it): every main and
//!   interaction column masked to twice its rows' degree, the preprocessed
//!   ones left as they are, the composition committed whole at four times the
//!   tallest component's rows and sampled at `π(z)`, R2's blinding, a FRI mask
//!   of eight columns and salted trees. It takes a number of its own, as a
//!   bump of 28 would make one number name two sets of parameters. Its FRI
//!   runs at blowup 32, where each column's own extension is the size 28's is
//!   at 64, with 24 queries: 146 / 82 (82.70), the query term binding; 23
//!   queries is the least that clears 80 (80.84). Blowup 64 at 20 queries
//!   counts 81.74, its DEEP batching term binding, at twice the prover's
//!   memory. Its proofs are a fixed layout ([`ProofBytes::FixedLayout`]); 28's
//!   are postcard.
//! - **`masked`** says what a format's proofs are: masking a format's proofs
//!   is a format change. A masked format whose masking is built pins it
//!   ([`Format::masking`], [`Masking`]): its salt and FRI-mask columns and
//!   its randomizer's size, which a prover and a verifier take from the
//!   format, never from a proof.
//! - **The bit counts** are [`crate::security`]'s, at each entry's reference
//!   shape; the verifier counts again at the proof's own shape and refuses a
//!   proof below either floor.

use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;

use crate::security::{SecurityBits, SecurityShape};

mod reference;

pub use reference::{
    CREDENTIAL_REFERENCE, DEVICE_REFERENCE, LEAF_FOLD_REFERENCE, MASKED_WRAP_REFERENCE,
    SEGMENT_REFERENCE, WRAP_REFERENCE,
};

/// What a format proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    Segment,
    LeafFold,
    Wrap,
    Device,
    Credential,
}

/// The Merkle hash and Fiat–Shamir channel of a format. Its tag (`as u8`)
/// is pinned: the masked prover's witness digest binds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelKind {
    Blake2s = 0,
    Poseidon2M31 = 1,
    Blake2sM31 = 2,
    Blake2b256 = 3,
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

/// A masked format's masking (`proving.md` §5, R6): what its trees commit
/// beside the AIR's columns, and the randomizer's size. A prover masks with
/// it and a verifier lays the trees out by it; neither reads it from a
/// proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Masking {
    /// The uniform salt columns at the end of each salted tree (main,
    /// interaction, composition), never sampled.
    pub salt_columns: usize,
    /// The FRI mask `R`'s uniform base columns, in the composition tree
    /// after the composition's own, sampled at the out-of-domain point.
    pub fri_mask_columns: usize,
    /// `log2 h`: each masked column is `f + v_H·r`, `r` of `h` random
    /// coefficients.
    pub log_mask_rows: u32,
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
    /// The masking's pins for a masked format, `None` for an unmasked one.
    pub masking: Option<Masking>,
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

/// Segments': fewer queries and more PoW than [`LEAF_FOLD_PARAMS`], for the
/// kernel leaf's rows, which grow with the queries times the segment's width.
/// Counted on format 41's reference: 62.81 proven bits.
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

/// Device proofs': credential proofs' parameters (format 44), picked by
/// measurement (see the module's notes).
const DEVICE: FormatParams = FormatParams {
    log_blowup: 2,
    n_queries: 47,
    pow_bits: 16,
    fold_step: 1,
    log_last_layer: 0,
    interaction_pow_bits: 8,
    batching: DeepBatching::Affine,
};

const INNER_FLOOR: SecurityFloor = SecurityFloor {
    conjectured: 100,
    proven: 60,
};

pub const SEGMENT: Format = Format {
    number: 41,
    kind: ProofKind::Segment,
    channel: ChannelKind::Poseidon2M31,
    params: SEGMENT_PARAMS,
    bytes: ProofBytes::Postcard,
    masked: false,
    masking: None,
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
    masking: None,
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
    masking: None,
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

/// Format 39's masking: 8 salt columns a tree (248 bits); an `R` of 8
/// columns, whose 8 independent DEEP coefficients span QM31 over M31 but
/// with probability about `p^-5`, so R3 holds without a check; and `h = 256`,
/// at least `2(4|O| + q(|O| + 1)) = 160` for `q = 24` queries and `|O| = 2`
/// offsets, and at most a quarter of the smallest component's `2^11` rows.
pub const MASKED_WRAP_MASKING: Masking = Masking {
    salt_columns: 8,
    fri_mask_columns: 8,
    log_mask_rows: 8,
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
    masking: Some(MASKED_WRAP_MASKING),
    floor: WRAP.floor,
    status: Status::Admitted,
    reference: MASKED_WRAP_REFERENCE,
    bits: SecurityBits {
        conjectured: 146,
        proven: 82,
    },
};

/// Format 46's masking: 8 salt columns a tree; an `R` of 8 columns (R3
/// under affine batching); and `h = 256`, at least the
/// `4|O| + q(|O| + 1) = 149` rows a column reveals for `q = 47` queries and
/// `|O| = 2` offsets, every device chip's widest (`proving.md` §5), so each
/// component pads to `4h = 2^10` rows.
pub const DEVICE_MASKING: Masking = Masking {
    salt_columns: 8,
    fri_mask_columns: 8,
    log_mask_rows: 8,
};

/// Device proofs, masked: see the module's notes.
pub const DEVICE_PROOF: Format = Format {
    number: 46,
    kind: ProofKind::Device,
    channel: ChannelKind::Blake2sM31,
    params: DEVICE,
    bytes: ProofBytes::Postcard,
    masked: true,
    masking: Some(DEVICE_MASKING),
    floor: INNER_FLOOR,
    status: Status::Admitted,
    reference: DEVICE_REFERENCE,
    bits: SecurityBits {
        conjectured: 110,
        proven: 62,
    },
};

/// Format 44's masking: 8 salt columns a tree; an `R` of 8 columns (R3
/// under affine batching); and `h = 512`, at least
/// `2(4|O| + q(|O| + 1)) = 298` for `q = 47` queries and `|O| = 2` offsets,
/// so each component pads to `4h = 2^11` rows.
pub const CREDENTIAL_MASKING: Masking = Masking {
    salt_columns: 8,
    fri_mask_columns: 8,
    log_mask_rows: 9,
};

const CREDENTIAL: FormatParams = FormatParams {
    log_blowup: 2,
    n_queries: 47,
    pow_bits: 16,
    fold_step: 1,
    log_last_layer: 0,
    interaction_pow_bits: 8,
    batching: DeepBatching::Affine,
};

/// Credential proofs, masked: see the module's notes.
pub const CREDENTIAL_PROOF: Format = Format {
    number: 44,
    kind: ProofKind::Credential,
    channel: ChannelKind::Blake2sM31,
    params: CREDENTIAL,
    bytes: ProofBytes::Postcard,
    masked: true,
    masking: Some(CREDENTIAL_MASKING),
    floor: INNER_FLOOR,
    status: Status::Admitted,
    reference: CREDENTIAL_REFERENCE,
    bits: SecurityBits {
        conjectured: 110,
        proven: 62,
    },
};

/// Every registered format, by number.
pub const REGISTRY: [Format; 6] = [
    WRAP,
    LEAF_FOLD,
    MASKED_WRAP,
    SEGMENT,
    CREDENTIAL_PROOF,
    DEVICE_PROOF,
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
///   so no later format takes it;
/// - **30, reserved, never admitted:** credential proofs at blowup 2 and 86
///   queries, counted on an unmasked shape; 44 is the credential format,
///   counted on its masked one;
/// - **42, admitted, then retired:** credential proofs at 43 queries and
///   PoW 20 (106 / 62), whose grind's 95th percentile on the gate phone
///   passed 50 ms; 44 takes PoW 16 at 47 queries. Proofs were made under
///   it, so no later format takes it;
/// - **37, reserved, never admitted:** device proofs at blowup 2 and 86
///   queries, counted on an unmasked shape; the device format is counted
///   on its masked one;
/// - **43, admitted, then retired:** device proofs at 46's parameters
///   with `h = 512`, twice the rows a column reveals; 45 took `h = 256`,
///   its floors 2^10 rows. Proofs were made under it, so no later format
///   takes it;
/// - **35 and 45, admitted, then retired:** the segment and device formats
///   of the chip set before the node shared it: 35's CPU ended a run at the
///   Poseidon2 call, and both divided for a logical right shift and held
///   seven columns a constraint pins to zero. 41 and 46 take their
///   parameters over the current form. Proofs were made under them, so no
///   later format takes them.
///
/// So a number names one AIR and one set of parameters.
pub const RETIRED: [u32; 16] = [
    24, 25, 26, 27, 29, 30, 31, 33, 34, 35, 36, 37, 40, 42, 43, 45,
];

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
mod masked_tests;

#[cfg(test)]
mod tests;
