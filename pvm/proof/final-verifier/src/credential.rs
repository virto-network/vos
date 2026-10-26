//! Credential proofs (`docs/design/proving.md` §8): format 42, the
//! credential AIR's `p2` and `qm31` masked under variant (c) on the fork's
//! Blake2s-M31 channel, verified against the program of the statement's
//! kind ([`verify`]).
//!
//! **What is pinned, never read from a proof:** the format (its number,
//! configuration, interaction PoW, salts, `R`, `h`), the two components'
//! log sizes ([`LOG_SIZES`], the masking's floor), the trees' widths and
//! the values the DEEP quotient batches, and each kind's preprocessed root
//! ([`preprocessed_root`]), which the proof's first commitment must equal.
//! The kind picks the circuit; the proof never does.
//!
//! **The public words** are the statement's, in its order
//! (`vos_pvm_recair_air::credential`): `kind`, then auth's `map_root`,
//! `scope`, `nullifier` and `binding`, or owner's `owner` and `binding`,
//! each word below `p`. They are the masked transcript's public values and
//! the public uses the claimed sums cancel, so a proof verifies under its
//! own words alone. `binding` is read by no gate: the transcript and the
//! public sum bind it.
//!
//! **Two blinded components:** the claimed sums are uniform but for their
//! total, which the public words fix; a one-component set is refused by
//! the masked verifier.
//!
//! **The bytes** are the proof's postcard encoding, at most
//! [`MAX_PROOF_BYTES`] and canonical (re-encoding gives the same bytes):
//! `decode`, under the `credential-bytes` feature.

#[cfg(feature = "credential-bytes")]
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{DeepBatching, PcsConfig};
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use vos_pvm_recair_air::GateRelation;
use vos_pvm_recair_air::credential::{self, CredentialKind};
use vos_pvm_recair_air::masked::{CredentialComponents, MaskPins};

use crate::Error;
use crate::masked::{Claim, MaskedFormat, TREES, verify_masked};

/// The credential format's number (`vos_pvm_proof::format::CREDENTIAL_PROOF`).
pub const FORMAT: u32 = 42;

/// Format 42's PCS configuration: blowup 4, 43 queries, PoW 20, FRI fold
/// step 1, a last layer of one coefficient, affine DEEP batching.
pub const CONFIG: PcsConfig = PcsConfig {
    pow_bits: 20,
    fri_config: FriConfig {
        log_last_layer_degree_bound: 0,
        log_blowup_factor: 2,
        n_queries: 43,
        fold_step: 1,
    },
    lifting_log_size: None,
    deep_batching: DeepBatching::Affine,
};

/// Format 42's parameters as the program id hashes them: log blowup,
/// queries, PoW, fold step, log last layer, interaction PoW.
pub const PARAMS: [u32; 6] = [2, 43, 20, 1, 0, 8];

/// Format 42's interaction PoW.
pub const INTERACTION_POW_BITS: u32 = 8;

/// Format 42's trees beside the AIR's columns: 8 salt columns a salted
/// tree, an `R` of 8 columns.
pub const PINS: MaskPins = MaskPins {
    salt_columns: 8,
    fri_mask_columns: 8,
};

/// Format 42's `log2 h`: the prover's randomizer, 512 coefficients a
/// column. The verifier reads no mask; pinned with the format.
pub const LOG_MASK_ROWS: u32 = 9;

/// The components' log sizes, `p2` and `qm31`: each at the masking's floor,
/// `4h` rows, whatever its statement uses of them.
pub const LOG_SIZES: [u32; 2] = [11, 11];

/// Format 42's trees' widths: preprocessed 50 (`p2`'s 33, `qm31`'s 17);
/// main 341 (`p2`'s 309 and `qm31`'s 16, 4 blinding columns each, 8
/// salts); interaction 32 (12 and 12, 8 salts); composition 20 (its 4
/// coordinates, `R`'s 8, 8 salts).
pub const TREE_WIDTHS: [usize; TREES] = [50, 341, 32, 20];

/// The values format 42's DEEP quotient batches: one a sampled column
/// (`50 + 333 + 24 + 4 + 8`), and two more for each of the 24 columns read
/// at the previous row (`p2`'s 16, each running sum's 4), a second sample
/// and its periodicity value.
pub const DEEP_VALUES: usize = 467;

/// The longest credential proof a decode reads, in bytes: ingress's cap.
pub const MAX_PROOF_BYTES: usize = 512 << 10;

/// Format 42 as its verifier pins it.
pub const CREDENTIAL: MaskedFormat<'static> = MaskedFormat {
    number: FORMAT,
    config: CONFIG,
    interaction_pow_bits: INTERACTION_POW_BITS,
    pins: PINS,
    log_mask_rows: LOG_MASK_ROWS,
    log_sizes: &LOG_SIZES,
    tree_widths: TREE_WIDTHS,
    deep_values: DEEP_VALUES,
    program: &[],
};

/// The auth circuit's preprocessed root on the Blake2s-M31 trees under
/// format 42: `vos-pvm-recair`'s credential tests compute it from the
/// circuit, and refuse a change here that is not theirs.
pub const AUTH_ROOT: [u8; 32] = [
    218, 77, 85, 120, 51, 250, 250, 87, 36, 62, 83, 81, 242, 254, 49, 93, 240, 230, 50, 68, 159,
    44, 227, 35, 215, 80, 138, 24, 219, 58, 39, 74,
];

/// The owner circuit's preprocessed root, as [`AUTH_ROOT`].
pub const OWNER_ROOT: [u8; 32] = [
    42, 249, 50, 99, 47, 32, 137, 52, 176, 74, 24, 17, 14, 62, 121, 33, 212, 9, 75, 71, 211, 124,
    119, 108, 146, 19, 120, 54, 146, 134, 80, 37,
];

/// The auth circuit's program id under format 42
/// ([`vos_pvm_recair_air::credential::program_id`] of [`AUTH_ROOT`]): what a
/// binding names.
pub const AUTH_PROGRAM: [u8; 32] = [
    187, 33, 248, 87, 177, 255, 104, 73, 219, 202, 147, 68, 29, 200, 89, 34, 109, 100, 197, 30,
    134, 196, 201, 16, 98, 58, 130, 107, 74, 110, 68, 118,
];

/// The owner circuit's program id under format 42, as [`AUTH_PROGRAM`].
pub const OWNER_PROGRAM: [u8; 32] = [
    55, 63, 103, 84, 89, 130, 93, 7, 116, 111, 171, 81, 214, 216, 165, 24, 91, 17, 198, 25, 46, 61,
    243, 62, 108, 118, 92, 47, 59, 232, 104, 125,
];

/// The preprocessed root of `kind`'s circuit.
pub const fn preprocessed_root(kind: CredentialKind) -> &'static [u8; 32] {
    match kind {
        CredentialKind::Auth => &AUTH_ROOT,
        CredentialKind::Owner => &OWNER_ROOT,
    }
}

/// The program id of `kind`'s circuit under format 42.
pub const fn program(kind: CredentialKind) -> &'static [u8; 32] {
    match kind {
        CredentialKind::Auth => &AUTH_PROGRAM,
        CredentialKind::Owner => &OWNER_PROGRAM,
    }
}

/// A credential proof: its format, the interaction PoW nonce, the two
/// blinded claimed sums and the STARK proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialProof {
    pub format_version: u32,
    pub interaction_pow: u64,
    /// `p2`'s and `qm31`'s, blinded.
    pub claimed_sums: [SecureField; 2],
    pub stark_proof: StarkProof<Blake2sM31MerkleHasher>,
}

/// The proof in `bytes`: at most [`MAX_PROOF_BYTES`], its postcard encoding
/// read whole and canonical (re-encoded, the same bytes), its format 42.
#[cfg(feature = "credential-bytes")]
pub fn decode(bytes: &[u8]) -> Result<CredentialProof, Error> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(Error::Length);
    }
    let (proof, rest): (CredentialProof, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| Error::Decode)?;
    if !rest.is_empty() || encode(&proof).as_deref() != Some(bytes) {
        return Err(Error::Decode);
    }
    if proof.format_version != FORMAT {
        return Err(Error::Format);
    }
    Ok(proof)
}

/// `proof`'s bytes, the one encoding [`decode`] reads; `None` when it
/// cannot be encoded.
#[cfg(feature = "credential-bytes")]
pub fn encode(proof: &CredentialProof) -> Option<Vec<u8>> {
    postcard::to_allocvec(proof).ok()
}

/// Verifies `proof` of a `kind` statement whose public words are `words`
/// (the kind's first): the circuit `kind`'s, under format 42.
pub fn verify(kind: CredentialKind, words: &[u32], proof: CredentialProof) -> Result<(), Error> {
    check_words(kind, words)?;
    verify_with(&CREDENTIAL, preprocessed_root(kind), words, proof)
}

/// `words` are a `kind` statement's: its count, its kind first, each below
/// `p`.
pub fn check_words(kind: CredentialKind, words: &[u32]) -> Result<(), Error> {
    let below_p = credential::public_values(words).is_some();
    if words.len() != kind.public_words()
        || words.first() != Some(&u32::from(kind as u8))
        || !below_p
    {
        return Err(Error::PublicWords);
    }
    Ok(())
}

/// Verifies the proof in `bytes` ([`decode`]) of a `kind` statement whose
/// public words are `words` ([`verify`]).
#[cfg(feature = "credential-bytes")]
pub fn verify_bytes(kind: CredentialKind, words: &[u32], bytes: &[u8]) -> Result<(), Error> {
    verify(kind, words, decode(bytes)?)
}

/// Verifies `proof` of the circuit whose preprocessed root is
/// `preprocessed_root`, under `format`, against its public `words`: the
/// masked transcript over the credential set, the claimed sums and the
/// words' public uses adding to zero. It takes no kind and checks no kind
/// word: ingress calls [`verify`], which picks the root by kind; this is
/// the circuit-generic step it runs, which the tests and the joint
/// circuit's measurement call with roots of their own.
pub fn verify_with(
    format: &MaskedFormat<'_>,
    preprocessed_root: &[u8; 32],
    words: &[u32],
    proof: CredentialProof,
) -> Result<(), Error> {
    if proof.format_version != format.number {
        return Err(Error::Format);
    }
    let log_sizes: &[u32; 2] = format.log_sizes.try_into().map_err(|_| Error::Format)?;
    let public = credential::public_values(words).ok_or(Error::PublicWords)?;
    let public_sum = |relation: &GateRelation| credential::public_sum(relation, &public);
    let layout = CredentialComponents::layout(log_sizes);
    verify_masked::<Blake2sM31MerkleChannel, CredentialComponents>(
        format,
        &Claim {
            log_sizes: format.log_sizes,
            circuit: Some(Blake2sHash(*preprocessed_root)),
            public: &public,
            public_sum: Some(&public_sum),
            bound_sums: None,
            interaction_pow: proof.interaction_pow,
            claimed_sums: &proof.claimed_sums,
        },
        &layout,
        proof.stark_proof,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use vos_pvm_recair_air::masked::{committed_log_sizes, sample_points};

    use crate::masked::{fri_rounds, shape_of};

    /// The credential set at format 42's pins: the trees' widths and DEEP
    /// values as pinned, the composition tree the last and the tallest, at
    /// FRI's degree bound 2^13.
    #[test]
    fn the_pinned_shape_is_the_credential_components() {
        let layout = CredentialComponents::layout(&LOG_SIZES);
        assert_eq!(shape_of(&layout, &PINS), Some((TREE_WIDTHS, DEEP_VALUES)));
        let trees = committed_log_sizes(&layout, &PINS).unwrap();
        assert_eq!(trees.iter().flatten().max(), Some(&13));
        assert!(trees[3].iter().all(|&level| level == 13));
        assert!(sample_points(&layout, stwo::core::circle::CirclePoint::zero(), &PINS).is_some());
        assert_eq!(fri_rounds(13, &CONFIG.fri_config).unwrap(), [1; 13]);
    }

    /// The constants are format 42's registry entry; its program ids are
    /// its roots' under the circuit hash; the header is the segment
    /// transcript's.
    #[test]
    fn the_constants_are_format_42s() {
        let entry = &vos_pvm_proof::format::CREDENTIAL_PROOF;
        let masking = entry.masking.unwrap();
        assert_eq!(entry.number, FORMAT);
        assert_eq!(entry.pcs_config(), CONFIG);
        assert_eq!(entry.interaction_pow_bits(), INTERACTION_POW_BITS);
        let params = entry.params;
        assert_eq!(
            [
                params.log_blowup,
                params.n_queries as u32,
                params.pow_bits,
                params.fold_step,
                params.log_last_layer,
                params.interaction_pow_bits,
            ],
            PARAMS
        );
        assert_eq!(
            (
                masking.salt_columns,
                masking.fri_mask_columns,
                masking.log_mask_rows
            ),
            (PINS.salt_columns, PINS.fri_mask_columns, LOG_MASK_ROWS)
        );
        assert_eq!(entry.reference.sampled_values, DEEP_VALUES as u64);
        for kind in CredentialKind::ALL {
            assert_eq!(
                credential::program_id(FORMAT, PARAMS, &LOG_SIZES, preprocessed_root(kind))
                    .as_ref(),
                Some(program(kind)),
                "{kind:?}"
            );
        }
        assert_ne!(AUTH_ROOT, OWNER_ROOT);
    }

    /// Words not a kind's are refused before any work: another count,
    /// another kind word, a word at or above `p`.
    #[test]
    fn words_not_the_kinds_are_refused() {
        let words = |kind: CredentialKind| {
            let mut words = alloc::vec![0u32; kind.public_words()];
            words[0] = u32::from(kind as u8);
            words
        };
        for kind in CredentialKind::ALL {
            assert!(check_words(kind, &words(kind)).is_ok());
        }
        let auth = words(CredentialKind::Auth);
        assert!(matches!(
            check_words(CredentialKind::Owner, &auth),
            Err(Error::PublicWords)
        ));
        let mut owner = words(CredentialKind::Owner);
        owner[0] = 0;
        assert!(matches!(
            check_words(CredentialKind::Owner, &owner),
            Err(Error::PublicWords)
        ));
        let mut high = auth.clone();
        high[5] = stwo::core::fields::m31::P;
        assert!(matches!(
            check_words(CredentialKind::Auth, &high),
            Err(Error::PublicWords)
        ));
    }
}
