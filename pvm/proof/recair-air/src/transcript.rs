//! The recursion AIR's transcript, as its prover runs it and every verifier
//! of its proofs replays it:
//! 1. the proof's domain, the format and the PCS configuration, then the
//!    components' log sizes (`vos_pvm_proof::proof::mix_statement_header`);
//! 2. the preprocessed root, then the main trace's root;
//! 3. the public values, in their addresses' order: a leaf's or a fold's
//!    outputs, the wrap's words, each word the QM31 `(w, 0, 0, 0)`; the
//!    public logup terms read them, so they are mixed before any challenge
//!    is drawn;
//! 4. the interaction PoW nonce;
//! 5. the `Gate` relation's challenges;
//! 6. the three claimed sums, then the interaction root; then Stwo's
//!    protocol.
//!
//! [`replay_prefix`] replays steps 2 to 6 for a verifier, after the header.

use alloc::vec::Vec;

use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;

use crate::GateRelation;

/// What a proof commits to between its header and Stwo's protocol.
pub struct Prefix<'a, H> {
    /// The preprocessed, main and interaction roots.
    pub roots: [H; 3],
    /// Each committed tree's column log sizes
    /// ([`committed_log_sizes`](crate::committed_log_sizes)).
    pub log_sizes: &'a [Vec<u32>; 3],
    /// The public values.
    pub public: &'a [SecureField],
    /// The components' claimed sums.
    pub claimed_sums: &'a [SecureField],
}

/// Steps 2 to 6 of the transcript on `channel` and `scheme`, the header
/// mixed: `interaction_pow` checks the proof's interaction PoW nonce on the
/// channel and mixes it. Returns the `Gate` relation's challenges, or
/// `interaction_pow`'s refusal.
pub fn replay_prefix<MC: MerkleChannel, E>(
    channel: &mut MC::C,
    scheme: &mut CommitmentSchemeVerifier<MC>,
    prefix: Prefix<'_, <MC::H as MerkleHasherLifted>::Hash>,
    interaction_pow: impl FnOnce(&mut MC::C) -> Result<(), E>,
) -> Result<GateRelation, E> {
    let [preprocessed, main, interaction] = prefix.roots;
    scheme.commit(preprocessed, &prefix.log_sizes[0], channel);
    scheme.commit(main, &prefix.log_sizes[1], channel);
    channel.mix_felts(prefix.public);
    interaction_pow(channel)?;
    let relation = GateRelation::draw(channel);
    channel.mix_felts(prefix.claimed_sums);
    scheme.commit(interaction, &prefix.log_sizes[2], channel);
    Ok(relation)
}
