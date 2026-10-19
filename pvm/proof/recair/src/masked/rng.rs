//! The masking's randomness (pin C's R4): hedged, so neither a replayed
//! operating-system state nor a known witness alone fixes the masks.
//!
//! Each attempt's stream is ChaCha20 seeded with
//! `BLAKE2b-256("vos/mask/seed/v1" ‖ 32 OS bytes ‖ witness digest ‖ attempt as u32 LE)`,
//! the witness digest binding the statement (the format, its configuration
//! and masking, its channel, the log sizes, the public values) and the
//! main columns. Two proofs from one replayed OS state differ when their
//! witnesses or their statements do, so one witness proved under two formats
//! or channels never reuses a mask; two proofs of one witness differ when the
//! OS bytes do. Every mask, salt, `R` column and blinding value of the attempt
//! is drawn from that stream.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rayon::prelude::*;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::DeepBatching;
use vos_pvm_proof::format::{Format, Masking};

use crate::prove::ProveError;
use crate::trace::Evaluations;

type Blake2b256 = Blake2b<U32>;

const SEED_DOMAIN: &[u8] = b"vos/mask/seed/v1";
const WITNESS_DOMAIN: &[u8] = b"vos/mask/witness/v1";

/// Where an attempt's 32 entropy bytes come from: the operating system's
/// ([`MaskRng::default`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MaskRng {
    /// The operating system's randomness: every build's.
    #[default]
    Os,
    /// A test's seed in place of the OS bytes, the witness digest and the
    /// attempt still hashed in, so a proof is reproducible byte for byte.
    /// Only the prover's tests have it, on a dev edge (`seeded-masks`); no
    /// production build does.
    #[cfg(feature = "seeded-masks")]
    Seeded(u64),
}

impl MaskRng {
    /// The stream of attempt `attempt` over the witness digest `witness`.
    pub(crate) fn attempt(
        self,
        witness: &[u8; 32],
        attempt: u32,
    ) -> Result<ChaCha20Rng, ProveError> {
        let mut entropy = [0u8; 32];
        match self {
            Self::Os => getrandom::getrandom(&mut entropy).map_err(|_| ProveError::Entropy)?,
            #[cfg(feature = "seeded-masks")]
            Self::Seeded(seed) => entropy[..8].copy_from_slice(&seed.to_le_bytes()),
        }
        let seed = Blake2b256::new()
            .chain_update(SEED_DOMAIN)
            .chain_update(entropy)
            .chain_update(witness)
            .chain_update(attempt.to_le_bytes())
            .finalize();
        Ok(ChaCha20Rng::from_seed(seed.into()))
    }
}

/// What a masked proof states beside its columns: the hedge binds it.
pub(crate) struct Statement<'a> {
    pub format: &'a Format,
    pub masking: &'a Masking,
    pub log_sizes: &'a [u32],
    pub public: &'a [SecureField],
}

/// The witness digest R4 hedges with: `BLAKE2b-256` of the domain, the
/// statement's words (the format's number, its configuration, its masking
/// and interaction PoW, its channel's tag, each log size, as u64
/// little-endian; each public value's 4 limbs, as u32
/// little-endian), then each main column's digest in commitment order, a
/// column's the `BLAKE2b-256` of its values, 4 bytes little-endian each in
/// Stwo's storage order. Every private value of the witness is in the main
/// columns.
pub(crate) fn witness_digest(statement: &Statement<'_>, main: &[Evaluations]) -> [u8; 32] {
    let columns: Vec<[u8; 32]> = main
        .iter()
        .flatten()
        .collect::<Vec<_>>()
        .par_iter()
        .map(|column| {
            let bytes: &[u8] = bytemuck::cast_slice(column.values.as_slice());
            Blake2b256::digest(bytes).into()
        })
        .collect();
    let config = statement.format.pcs_config();
    let fri = config.fri_config;
    let lifting = config
        .lifting_log_size
        .map_or(0, |log_size| 1 + u64::from(log_size));
    let batching = match config.deep_batching {
        DeepBatching::Powers => 0,
        DeepBatching::Affine => 1,
    };
    let masking = statement.masking;
    let mut hasher = Blake2b256::new().chain_update(WITNESS_DOMAIN);
    for word in [
        u64::from(statement.format.number),
        u64::from(config.pow_bits),
        fri.n_queries as u64,
        u64::from(fri.log_blowup_factor),
        u64::from(fri.log_last_layer_degree_bound),
        u64::from(fri.fold_step),
        lifting,
        batching,
        u64::from(statement.format.interaction_pow_bits()),
        statement.format.channel as u64,
        masking.salt_columns as u64,
        masking.fri_mask_columns as u64,
        u64::from(masking.log_mask_rows),
        statement.log_sizes.len() as u64,
    ]
    .into_iter()
    .chain(
        statement
            .log_sizes
            .iter()
            .map(|&log_size| u64::from(log_size)),
    ) {
        hasher.update(word.to_le_bytes());
    }
    hasher.update((statement.public.len() as u64).to_le_bytes());
    for value in statement.public {
        for limb in value.to_m31_array() {
            hasher.update(limb.0.to_le_bytes());
        }
    }
    for column in columns {
        hasher.update(column);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use stwo::core::fields::m31::BaseField;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::prover::backend::simd::column::BaseColumn;
    use stwo::prover::poly::circle::CircleEvaluation;
    use vos_pvm_proof::format::{ChannelKind, Format, MASKED_WRAP};

    use super::*;

    fn column(values: &[u32]) -> Evaluations {
        let domain = CanonicCoset::new(4).circle_domain();
        vec![CircleEvaluation::new(
            domain,
            values
                .iter()
                .map(|&value| BaseField::from(value))
                .collect::<BaseColumn>(),
        )]
    }

    /// R4 against a replayed state: one OS state hedged with two witnesses
    /// differing in one value, or with one witness under two channels or
    /// public values, seeds two other streams; the same witness and state
    /// seed one.
    #[test]
    fn a_replayed_state_draws_other_masks_for_another_witness() {
        use rand::RngCore;
        let masking = MASKED_WRAP.masking.unwrap();
        let public = [SecureField::from(BaseField::from(7))];
        let poseidon = Format {
            channel: ChannelKind::Poseidon2M31,
            ..MASKED_WRAP
        };
        let statement = |format, public| Statement {
            format,
            masking: &masking,
            log_sizes: &[4],
            public,
        };
        let values: Vec<u32> = (0..16).collect();
        let mut amount = values.clone();
        amount[3] += 1;
        let digests = [
            witness_digest(&statement(&MASKED_WRAP, &public), &[column(&values)]),
            witness_digest(&statement(&MASKED_WRAP, &public), &[column(&amount)]),
            witness_digest(&statement(&poseidon, &public), &[column(&values)]),
            witness_digest(&statement(&MASKED_WRAP, &[]), &[column(&values)]),
        ];
        let first_word = |digest: &[u8; 32], attempt| {
            MaskRng::Seeded(5)
                .attempt(digest, attempt)
                .unwrap()
                .next_u64()
        };
        let words: Vec<u64> = digests.iter().map(|digest| first_word(digest, 0)).collect();
        for (i, a) in words.iter().enumerate() {
            for b in &words[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_eq!(first_word(&digests[0], 0), words[0]);
        assert_ne!(first_word(&digests[0], 1), words[0]);
    }
}
