//! The masking's randomness (pin C's R4): hedged, so neither a replayed
//! operating-system state nor a known witness alone fixes the masks.
//!
//! Each attempt's stream is ChaCha20 seeded with
//! `BLAKE2b-256("vos/mask/seed/v1" ‖ 32 OS bytes ‖ witness digest ‖ attempt as u32 LE)`.
//! Two proofs from one replayed OS state differ when their witnesses do, and
//! two proofs of one witness differ when the OS bytes do. Every mask, salt,
//! `R` column and blinding value of the attempt is drawn from that stream.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rayon::prelude::*;

use crate::prove::ProveError;
use crate::trace::Evaluations;

type Blake2b256 = Blake2b<U32>;

const SEED_DOMAIN: &[u8] = b"vos/mask/seed/v1";
const WITNESS_DOMAIN: &[u8] = b"vos/mask/witness/v1";

/// Where an attempt's 32 entropy bytes come from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MaskRng {
    /// The operating system's randomness: every build's.
    #[default]
    Os,
    /// A test's seed in place of the OS bytes, the witness digest and the
    /// attempt still hashed in, so a fixture's proof is reproducible byte
    /// for byte. Only tests and the fixtures' generator (`seeded-masks`)
    /// have it; no production build does.
    #[cfg(any(test, feature = "seeded-masks"))]
    Seeded(u64),
}

impl MaskRng {
    /// The production randomness, the OS's.
    pub const fn new() -> Self {
        Self::Os
    }

    /// The stream of attempt `attempt` over the witness digest `witness`.
    pub(crate) fn attempt(
        &self,
        witness: &[u8; 32],
        attempt: u32,
    ) -> Result<ChaCha20Rng, ProveError> {
        let mut entropy = [0u8; 32];
        match self {
            Self::Os => getrandom::getrandom(&mut entropy).map_err(|_| ProveError::Entropy)?,
            #[cfg(any(test, feature = "seeded-masks"))]
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

/// The witness digest R4 hedges with: `BLAKE2b-256` of the domain and each
/// main column's digest in commitment order, a column's the `BLAKE2b-256` of
/// its values, 4 bytes little-endian each in Stwo's storage order. Every
/// private value of the witness is in the main columns.
pub(crate) fn witness_digest(main: &[Evaluations]) -> [u8; 32] {
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
    let mut hasher = Blake2b256::new().chain_update(WITNESS_DOMAIN);
    for column in columns {
        hasher.update(column);
    }
    hasher.finalize().into()
}
