//! The proof formats' plain data: each registered format's number, kind,
//! channel, parameters, encoding, masking, floors and status, and the
//! header every format's transcript starts with. Both sides read this one
//! copy: the prover and the segment verifier through `vos_pvm_proof::format`,
//! which adds each format's security count at its reference shape, and the
//! final verifier, which derives its masked format from [`MASKED_WRAP`].
//!
//! A proof's `format_version` names an entry of [`REGISTRY`], and the entry
//! decides its channel, its parameters and its encodings; nothing of these
//! is read from a proof. `vos_pvm_proof::format`'s notes give each entry's
//! reasons and counts.

use alloc::vec::Vec;

use stwo::core::channel::Channel;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;

/// How a format's DEEP quotient batches its sampled values: by powers of one
/// coefficient (Stwo's), or with an independent coefficient a sampled value
/// (the fork's, `DIVERGENCE-012`), whose error loses the factor of the
/// values' count. A proof does not carry it: a verifier sets it from the
/// format ([`Format::verifier_config`]).
pub use stwo::core::pcs::DeepBatching;

/// What a format proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    Segment,
    LeafFold,
    Wrap,
    Device,
}

/// The Merkle hash and Fiat–Shamir channel of a format. Its tag (`as u8`)
/// is pinned: the masked prover's witness digest binds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelKind {
    Poseidon2M31 = 1,
    Blake2sM31 = 2,
    Blake2b256 = 3,
}

/// How a format's proofs are laid out in bytes when they leave the prover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofBytes {
    /// The proof's serde form as its postcard encoding (segment, leaf and
    /// fold, and device proofs): varint lengths, whose canonical form a
    /// decoder checks by re-encoding.
    Postcard,
    /// The fields in a fixed order, little-endian, with explicit u32 counts
    /// and no varints, every count checked against the format before any
    /// allocation, nothing after the last field: one encoding a proof.
    FixedLayout,
}

/// Whether a verifier outside the prover accepts a format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Admitted,
    /// Registered, with its parameters and counts, and proved and verified
    /// inside the prover alone: no verifier a proof is submitted to reads
    /// it ([`admitted`] refuses it).
    Internal,
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
    /// coefficients. The prover's: a verifier reads no mask.
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
    /// The masking's pins for a masked format, `None` for an unmasked one.
    pub masking: Option<Masking>,
    pub floor: SecurityFloor,
    pub status: Status,
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
}

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

/// Device proofs', picked by measurement (`vos_pvm_proof::format`'s notes).
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

/// Segments: a node's runs, which a kernel leaf verifies.
pub const SEGMENT: Format = Format {
    number: 41,
    kind: ProofKind::Segment,
    channel: ChannelKind::Poseidon2M31,
    params: SEGMENT_PARAMS,
    bytes: ProofBytes::Postcard,
    masking: None,
    floor: INNER_FLOOR,
    status: Status::Admitted,
};

/// The padded shape every leaf and fold proves at, [`LEAF_FOLD`]'s
/// (`proving.md` §3.4): `p2`, `qm31` and `h8` at 2^16, 2^17 and 2^16 rows.
/// One shape for both, so a fold verifies either child with one circuit,
/// and a fold's own rows fit it (`recursion-air.md` §6, the fixed point).
pub const LEAF_FOLD_LOG_SIZES: [u32; 3] = [16, 17, 16];

/// Leaves and folds: the recursion AIR, inside the prover.
pub const LEAF_FOLD: Format = Format {
    number: 32,
    kind: ProofKind::LeafFold,
    channel: ChannelKind::Poseidon2M31,
    params: LEAF_FOLD_PARAMS,
    bytes: ProofBytes::Postcard,
    masking: None,
    floor: INNER_FLOOR,
    status: Status::Internal,
};

/// Format 39's masking: 8 salt columns a tree (248 bits); an `R` of 8
/// columns, whose 8 independent DEEP coefficients span QM31 over M31 but
/// with probability about `p^-5`, so R3 holds without a check; and `h` at
/// most 256, at most a quarter of the smallest component's `2^11` rows.
/// Each component takes twice the rows a column of it reveals, rounded up
/// to a power of two (the final verifier's `mask_rows`): `h = 128` for the
/// wrap's, as `2(4|O| + q(|O| + 1)) = 112` for `q = 16` queries and
/// `|O| = 2` offsets.
pub const MASKED_WRAP_MASKING: Masking = Masking {
    salt_columns: 8,
    fri_mask_columns: 8,
    log_mask_rows: 8,
};

/// Format 39's floor: no weaker than the weakest inner format on either
/// count (segments, 41: 104 conjectured, 62.81 proven), since forging a
/// fold's input forges the final proof: a statement is no stronger than
/// its weakest inner format, whatever the wrap's count.
const WRAP_FLOOR: SecurityFloor = SecurityFloor {
    conjectured: 104,
    proven: 63,
};

/// The final wrap, masked: the recursion AIR under masking variant (c), on
/// the Blake2b-256 channel, its bytes a fixed layout. The one final format.
pub const MASKED_WRAP: Format = Format {
    number: 39,
    kind: ProofKind::Wrap,
    channel: ChannelKind::Blake2b256,
    params: FormatParams {
        log_blowup: 5,
        n_queries: 16,
        pow_bits: 26,
        fold_step: 3,
        log_last_layer: 6,
        interaction_pow_bits: 8,
        batching: DeepBatching::Affine,
    },
    bytes: ProofBytes::FixedLayout,
    masking: Some(MASKED_WRAP_MASKING),
    floor: WRAP_FLOOR,
    status: Status::Admitted,
};

/// The device format's masking: 8 salt columns a tree; an `R` of 8 columns (R3
/// under affine batching); and `h = 256`, at least the
/// `4|O| + q(|O| + 1) = 149` rows a column reveals for `q = 47` queries and
/// `|O| = 2` offsets, every device chip's widest (`proving.md` §5), so each
/// component pads to `4h = 2^10` rows.
pub const DEVICE_MASKING: Masking = Masking {
    salt_columns: 8,
    fri_mask_columns: 8,
    log_mask_rows: 8,
};

/// Device proofs under the per-program CPU and the word ledger, masked:
/// the device format.
pub const DEVICE_PROOF: Format = Format {
    number: 47,
    kind: ProofKind::Device,
    channel: ChannelKind::Blake2sM31,
    params: DEVICE,
    bytes: ProofBytes::Postcard,
    masking: Some(DEVICE_MASKING),
    floor: INNER_FLOOR,
    status: Status::Admitted,
};

/// Every registered format, by number.
pub const REGISTRY: [Format; 4] = [LEAF_FOLD, MASKED_WRAP, SEGMENT, DEVICE_PROOF];

/// The numbers earlier formats took, retired: never registered again, and
/// refused as [`Refused::Retired`].
pub const RETIRED: [u32; 3] = [28, 44, 46];

/// Why a format number is refused where a proof names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// No entry has the number.
    Unregistered,
    /// An earlier format's number ([`RETIRED`]).
    Retired,
    /// The entry is proved and verified inside the prover alone
    /// ([`Status::Internal`]).
    Internal,
    /// The entry names another kind of proof than the verifier reads.
    NotSegment,
}

/// Shown as what is said of the format: `proof format 18 {refused}` reads
/// "proof format 18 is not registered".
impl core::fmt::Display for Refused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unregistered => "is not registered",
            Self::Retired => "is retired and not registered",
            Self::Internal => "is registered but not admitted",
            Self::NotSegment => "does not name segment proofs",
        })
    }
}

impl core::error::Error for Refused {}

/// The entry for `number`, admitted or not.
pub fn lookup(number: u32) -> Option<&'static Format> {
    REGISTRY.iter().find(|format| format.number == number)
}

/// The entry for `number`, if a verifier accepts proofs under it.
pub fn admitted(number: u32) -> Result<&'static Format, Refused> {
    match lookup(number) {
        Some(format) if format.status == Status::Admitted => Ok(format),
        Some(_) => Err(Refused::Internal),
        None if RETIRED.contains(&number) => Err(Refused::Retired),
        None => Err(Refused::Unregistered),
    }
}

/// The entry for `number`, if it is admitted and names segment proofs: what
/// a segment verifier accepts.
pub fn admitted_segment(number: u32) -> Result<&'static Format, Refused> {
    let format = admitted(number)?;
    if format.kind != ProofKind::Segment {
        return Err(Refused::NotSegment);
    }
    Ok(format)
}

// Two fixed little-endian words spelling "VOS/PVM/" and "STARK/FS". The
// format version follows as its own word. This is deliberately mixed before
// log sizes or roots on every proving and verifying path: changing a wire
// version can never merely relabel an old proof under the same transcript.
const PROOF_FS_DOMAIN_WORD_0: u64 = u64::from_le_bytes(*b"VOS/PVM/");
const PROOF_FS_DOMAIN_WORD_1: u64 = u64::from_le_bytes(*b"STARK/FS");

/// The statement header's words, as `mix_u64` takes them.
fn header_words<'a>(
    format_version: u32,
    config: &PcsConfig,
    log_sizes: &'a [u32],
) -> impl Iterator<Item = u64> + 'a {
    let (lifted, lifting) = match config.lifting_log_size {
        None => (0, None),
        Some(lifting) => (1, Some(u64::from(lifting))),
    };
    [
        PROOF_FS_DOMAIN_WORD_0,
        PROOF_FS_DOMAIN_WORD_1,
        u64::from(format_version),
        u64::from(config.pow_bits),
        config.fri_config.n_queries as u64,
        u64::from(config.fri_config.log_blowup_factor),
        u64::from(config.fri_config.log_last_layer_degree_bound),
        u64::from(config.fri_config.fold_step),
        lifted,
    ]
    .into_iter()
    .chain(lifting)
    .chain(log_sizes.iter().map(|&log_size| u64::from(log_size)))
}

/// A.1's first item, as the words `mix_u64` takes: the protocol domain,
/// the exact format generation and the PCS configuration, then each
/// component's log size. This prefix authenticates every format's
/// transcript, the segment's, the recursion's and the masked ones'. It
/// does not mix the DEEP batching, the interaction PoW's bits or the
/// masking: the format's number names them, one registry entry a number
/// never reused, and every verifier takes them from its entry, never from
/// a proof.
pub fn statement_header_words(
    format_version: u32,
    config: &PcsConfig,
    log_sizes: &[u32],
) -> Vec<u64> {
    header_words(format_version, config, log_sizes).collect()
}

/// Mixes the statement's header ([`statement_header_words`]) into `channel`.
pub fn mix_statement_header(
    channel: &mut impl Channel,
    format_version: u32,
    config: &PcsConfig,
    log_sizes: &[u32],
) {
    for word in header_words(format_version, config, log_sizes) {
        channel.mix_u64(word);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header's words for format 39 at the wrap's log sizes, as every
    /// transcript of it starts: a change here moves every proof's
    /// challenges.
    #[test]
    fn the_header_is_pinned() {
        let words =
            statement_header_words(MASKED_WRAP.number, &MASKED_WRAP.pcs_config(), &[14, 15, 11]);
        assert_eq!(
            words,
            [
                u64::from_le_bytes(*b"VOS/PVM/"),
                u64::from_le_bytes(*b"STARK/FS"),
                39,
                26,
                16,
                5,
                6,
                3,
                0,
                14,
                15,
                11
            ]
        );
        let lifted = PcsConfig {
            lifting_log_size: Some(20),
            ..MASKED_WRAP.pcs_config()
        };
        assert_eq!(statement_header_words(39, &lifted, &[])[8..], [1, 20]);
    }

    /// Every number names one entry; only 39, 41 and 47 are admitted, a
    /// segment verifier takes 41 alone; a retired number is refused as
    /// retired, every other as unregistered.
    #[test]
    fn the_registry_refuses_by_cause() {
        assert!(REGISTRY.windows(2).all(|w| w[0].number < w[1].number));
        assert_eq!(admitted(32), Err(Refused::Internal));
        assert_eq!(admitted_segment(39), Err(Refused::NotSegment));
        assert_eq!(admitted_segment(47), Err(Refused::NotSegment));
        assert_eq!(admitted_segment(41), Ok(&SEGMENT));
        for number in RETIRED {
            assert!(lookup(number).is_none());
            assert_eq!(admitted(number), Err(Refused::Retired));
        }
        for number in [0, 23, 35, 38, 48, u32::MAX] {
            assert_eq!(admitted(number), Err(Refused::Unregistered));
        }
    }
}
