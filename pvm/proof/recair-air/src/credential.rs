//! The credential statements' public words (`docs/design/proving.md` §8):
//! what a credential circuit outputs, in order, and the program id a
//! circuit's preprocessed root makes.
//!
//! - **Auth** ([`CredentialKind::Auth`]): `kind`, `map_root`, `scope`,
//!   `nullifier`, `binding`, 33 words.
//! - **Owner** ([`CredentialKind::Owner`]): `kind`, `owner`, `binding`, 17
//!   words.
//!
//! `kind` is one word and each digest its eight, every word below `p`. Each
//! word is one output of the circuit, the QM31 `(word, 0, 0, 0)` at a node's
//! output addresses ([`Layout::node`]): a public value of the masked
//! transcript, and a public use the claimed sums must cancel.

use alloc::vec::Vec;

use stwo::core::fields::m31::{BaseField, P};
use stwo::core::fields::qm31::SecureField;
use vos_pvm_poseidon2::{Digest, M31};

use crate::gate::{GateRelation, Layout, public_logup_sum};

/// A digest's words.
pub const DIGEST_WORDS: usize = 8;

/// A credential statement's kind, its first public word
/// (`identity-and-authority.md` §5's `CredentialPublic` index).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CredentialKind {
    /// A member's leaf under a root, and a nullifier in a scope.
    Auth = 0,
    /// The owner digest of a secret.
    Owner = 1,
}

impl CredentialKind {
    pub const ALL: [CredentialKind; 2] = [CredentialKind::Auth, CredentialKind::Owner];

    /// The statement's public words: `kind` and its digests'.
    pub const fn public_words(self) -> usize {
        1 + DIGEST_WORDS * self.digests()
    }

    /// The digests after `kind`: `map_root`, `scope`, `nullifier` and
    /// `binding`; or `owner` and `binding`.
    pub const fn digests(self) -> usize {
        match self {
            CredentialKind::Auth => 4,
            CredentialKind::Owner => 2,
        }
    }
}

/// The layout of a circuit stating `n_words` public words: a node's, its
/// outputs from address 3.
pub const fn layout(n_words: usize) -> Layout {
    Layout::node(n_words as u32)
}

/// The public values of `words`, each the QM31 `(word, 0, 0, 0)`; `None`
/// when a word is at or above `p`.
pub fn public_values(words: &[u32]) -> Option<Vec<SecureField>> {
    words
        .iter()
        .map(|&word| {
            (word < P).then(|| {
                SecureField::from_m31_array([
                    BaseField::from_u32_unchecked(word),
                    BaseField::from_u32_unchecked(0),
                    BaseField::from_u32_unchecked(0),
                    BaseField::from_u32_unchecked(0),
                ])
            })
        })
        .collect()
}

/// The public terms' logup sum of a circuit stating `values`, under
/// `relation`: `u`'s use and each word's.
pub fn public_sum(relation: &GateRelation, values: &[SecureField]) -> SecureField {
    public_logup_sum(
        relation,
        layout(values.len()).public_terms(values.iter().copied()),
    )
}

/// A credential circuit's program id: the circuit hash
/// ([`crate::circuit_hash`]) of `format` and its parameters, the log sizes
/// of `p2` and `qm31` (`h8`'s 0: the set has none) and the preprocessed
/// root, its 32 bytes as eight little-endian words. `None` for a root whose
/// words are not below `p` (a Blake2s-M31 root's always are).
pub fn program_id(
    format: u32,
    params: [u32; 6],
    log_sizes: &[u32; 2],
    preprocessed_root: &[u8; 32],
) -> Option<[u8; 32]> {
    let mut root = [M31::ZERO; DIGEST_WORDS];
    for (word, bytes) in root.iter_mut().zip(preprocessed_root.chunks_exact(4)) {
        let value = u32::from_le_bytes(bytes.try_into().ok()?);
        *word = (value < P).then(|| M31::new(value))?;
    }
    let [p2, qm31] = *log_sizes;
    let hash: Digest = crate::circuit_hash(format, params, &[p2, qm31, 0], &root);
    let mut id = [0; 32];
    for (bytes, word) in id.chunks_exact_mut(4).zip(hash) {
        bytes.copy_from_slice(&word.value().to_le_bytes());
    }
    Some(id)
}
