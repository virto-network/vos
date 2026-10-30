//! The PCS stacks a proof's format selects at run time.
//!
//! A format names its channel ([`crate::format::ChannelKind`]); the code that
//! proves, verifies or replays a transcript is generic over [`PcsStack`],
//! and [`with_stack!`](crate::with_stack) picks the stack for a segment
//! format's channel. A proof holds its Stwo proof as a [`StarkProofAny`],
//! whose variant is its channel's, and its commitments as [`Commitment`]s.
//!
//! **Three stacks:** Blake2s, Poseidon2-M31 and Blake2s-M31 (the fork's
//! `Blake2sM31MerkleChannel`: Blake2s with each digest word reduced below
//! `p`, the credential formats' and the device format's). A Blake2s-M31 root
//! is a [`Blake2sHash`] whose words are each below `p`; its commitment is
//! [`Commitment::Blake2sM31`], tagged by its stack, not by its hash type,
//! which it shares with Blake2s ([`PcsStack::commitment`]).
//!
//! The lookup elements are drawn through object-safe component methods, so
//! they take a [`ChannelRef`], which names the concrete channel.

use core::fmt;

use serde::{Deserialize, Serialize};
use stwo::core::channel::{Blake2sChannel, Blake2sM31Channel, Channel, MerkleChannel};
use stwo::core::fields::m31::{BaseField, P};
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs::hash::Hash;
use stwo::core::vcs_lifted::blake2_merkle::{
    Blake2sM31MerkleChannel, Blake2sM31MerkleHasher, Blake2sMerkleChannel, Blake2sMerkleHasher,
};
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;

use crate::format::ChannelKind;
use crate::poseidon2::{P2Hash, P2MerkleChannel, P2MerkleHasher, Poseidon2M31Channel};

/// A channel, named, for the lookup draws of the object-safe component
/// methods.
pub enum ChannelRef<'a> {
    Blake2s(&'a mut Blake2sChannel),
    Poseidon2M31(&'a mut Poseidon2M31Channel),
    Blake2sM31(&'a mut Blake2sM31Channel),
}

impl<'a> From<&'a mut Blake2sChannel> for ChannelRef<'a> {
    fn from(channel: &'a mut Blake2sChannel) -> Self {
        Self::Blake2s(channel)
    }
}

impl<'a> From<&'a mut Poseidon2M31Channel> for ChannelRef<'a> {
    fn from(channel: &'a mut Poseidon2M31Channel) -> Self {
        Self::Poseidon2M31(channel)
    }
}

impl<'a> From<&'a mut Blake2sM31Channel> for ChannelRef<'a> {
    fn from(channel: &'a mut Blake2sM31Channel) -> Self {
        Self::Blake2sM31(channel)
    }
}

/// A Fiat–Shamir channel a format runs on.
pub trait FsChannel: Channel {
    fn as_ref_channel(&mut self) -> ChannelRef<'_>;

    /// Absorb `bytes` as one run: the lossless encoding of a run whose
    /// length the transcript fixes (the boundary states', 296 bytes).
    /// Blake2s and Poseidon2-M31 take one word a byte; Blake2s-M31, whose
    /// words a hash absorbs as bytes, four bytes a little-endian word, and
    /// refuses a run that is not whole words.
    fn mix_bytes(&mut self, bytes: &[u8]);
}

impl FsChannel for Blake2sChannel {
    fn as_ref_channel(&mut self) -> ChannelRef<'_> {
        ChannelRef::Blake2s(self)
    }

    fn mix_bytes(&mut self, bytes: &[u8]) {
        let words: alloc::vec::Vec<u32> = bytes.iter().map(|&byte| u32::from(byte)).collect();
        self.mix_u32s(&words);
    }
}

impl FsChannel for Blake2sM31Channel {
    fn as_ref_channel(&mut self) -> ChannelRef<'_> {
        ChannelRef::Blake2sM31(self)
    }

    fn mix_bytes(&mut self, bytes: &[u8]) {
        assert!(
            bytes.len().is_multiple_of(4),
            "a Blake2s-M31 run is whole words"
        );
        let words: alloc::vec::Vec<u32> = bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        self.mix_u32s(&words);
    }
}

impl FsChannel for Poseidon2M31Channel {
    fn as_ref_channel(&mut self) -> ChannelRef<'_> {
        ChannelRef::Poseidon2M31(self)
    }

    fn mix_bytes(&mut self, bytes: &[u8]) {
        let values: alloc::vec::Vec<BaseField> = bytes
            .iter()
            .map(|&byte| BaseField::from_u32_unchecked(u32::from(byte)))
            .collect();
        self.mix_m31s(&values);
    }
}

/// A Merkle root of a format's hash.
pub trait ProofHash: Hash {
    /// The 32-byte form: a Blake2s digest's bytes, or a Poseidon2-M31
    /// digest's eight limbs as little-endian u32s.
    fn to_bytes(&self) -> [u8; 32];

    /// The inverse of [`ProofHash::to_bytes`] on canonical bytes.
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self>;

    /// Whether every limb is a canonical M31.
    fn is_canonical(&self) -> bool;

    fn into_commitment(self) -> Commitment;
}

impl ProofHash for Blake2sHash {
    fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Some(Blake2sHash(*bytes))
    }

    fn is_canonical(&self) -> bool {
        true
    }

    fn into_commitment(self) -> Commitment {
        Commitment::Blake2s(self)
    }
}

impl ProofHash for P2Hash {
    fn to_bytes(&self) -> [u8; 32] {
        P2Hash::to_bytes(self)
    }

    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut limbs = [BaseField::from_u32_unchecked(0); 8];
        for (limb, word) in limbs.iter_mut().zip(bytes.chunks_exact(4)) {
            let value = u32::from_le_bytes(word.try_into().ok()?);
            if value >= P {
                return None;
            }
            *limb = BaseField::from_u32_unchecked(value);
        }
        Some(P2Hash(limbs))
    }

    fn is_canonical(&self) -> bool {
        self.0.iter().all(|limb| limb.0 < P)
    }

    fn into_commitment(self) -> Commitment {
        Commitment::Poseidon2M31(self)
    }
}

/// A Merkle commitment of a proof, in its format's hash. A program's
/// commitment is its preprocessed root.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Commitment {
    Blake2s(Blake2sHash),
    Poseidon2M31(P2Hash),
    /// A Blake2s-M31 root: each word below `p`.
    Blake2sM31(Blake2sHash),
}

impl Commitment {
    pub fn channel(&self) -> ChannelKind {
        match self {
            Self::Blake2s(_) => ChannelKind::Blake2s,
            Self::Poseidon2M31(_) => ChannelKind::Poseidon2M31,
            Self::Blake2sM31(_) => ChannelKind::Blake2sM31,
        }
    }

    /// The 32-byte form ([`ProofHash::to_bytes`]).
    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            Self::Blake2s(hash) | Self::Blake2sM31(hash) => hash.to_bytes(),
            Self::Poseidon2M31(hash) => ProofHash::to_bytes(hash),
        }
    }

    /// A commitment of `channel`'s hash from its 32-byte form: a
    /// Blake2s-M31 root's words each below `p`.
    pub fn from_bytes(channel: ChannelKind, bytes: &[u8; 32]) -> Option<Self> {
        match channel {
            ChannelKind::Blake2s => Blake2sHash::from_bytes(bytes).map(Self::Blake2s),
            ChannelKind::Poseidon2M31 => P2Hash::from_bytes(bytes).map(Self::Poseidon2M31),
            ChannelKind::Blake2sM31 => Some(Blake2sHash(*bytes))
                .filter(words_below_p)
                .map(Self::Blake2sM31),
            ChannelKind::Blake2b256 => None,
        }
    }
}

/// Whether each of a Blake2s-M31 root's eight little-endian words is below
/// `p`, as the hasher reduces them.
pub fn words_below_p(root: &Blake2sHash) -> bool {
    root.0
        .chunks_exact(4)
        .all(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]) < P)
}

impl fmt::Display for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.to_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A Stwo proof, in its format's channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StarkProofAny {
    Blake2s(StarkProof<Blake2sMerkleHasher>),
    Poseidon2M31(StarkProof<P2MerkleHasher>),
    Blake2sM31(StarkProof<Blake2sM31MerkleHasher>),
}

impl StarkProofAny {
    pub fn channel(&self) -> ChannelKind {
        match self {
            Self::Blake2s(_) => ChannelKind::Blake2s,
            Self::Poseidon2M31(_) => ChannelKind::Poseidon2M31,
            Self::Blake2sM31(_) => ChannelKind::Blake2sM31,
        }
    }

    /// Every tree's root, in tree order.
    pub fn commitments(&self) -> alloc::vec::Vec<Commitment> {
        match self {
            Self::Blake2s(proof) => roots::<Blake2sMerkleChannel>(proof).collect(),
            Self::Poseidon2M31(proof) => roots::<P2MerkleChannel>(proof).collect(),
            Self::Blake2sM31(proof) => roots::<Blake2sM31MerkleChannel>(proof).collect(),
        }
    }

    /// The number of trees.
    pub fn commitment_count(&self) -> usize {
        match self {
            Self::Blake2s(proof) => proof.commitments.len(),
            Self::Poseidon2M31(proof) => proof.commitments.len(),
            Self::Blake2sM31(proof) => proof.commitments.len(),
        }
    }

    /// The root of tree `index`.
    pub fn commitment(&self, index: usize) -> Option<Commitment> {
        match self {
            Self::Blake2s(proof) => roots::<Blake2sMerkleChannel>(proof).nth(index),
            Self::Poseidon2M31(proof) => roots::<P2MerkleChannel>(proof).nth(index),
            Self::Blake2sM31(proof) => roots::<Blake2sM31MerkleChannel>(proof).nth(index),
        }
    }

    /// The FRI proof-of-work nonce.
    pub fn proof_of_work(&self) -> u64 {
        match self {
            Self::Blake2s(proof) => proof.proof_of_work,
            Self::Poseidon2M31(proof) => proof.proof_of_work,
            Self::Blake2sM31(proof) => proof.proof_of_work,
        }
    }

    pub fn config(&self) -> stwo::core::pcs::PcsConfig {
        match self {
            Self::Blake2s(proof) => proof.config,
            Self::Poseidon2M31(proof) => proof.config,
            Self::Blake2sM31(proof) => proof.config,
        }
    }
}

/// A proof's roots as commitments of `MC`'s stack.
fn roots<MC: PcsStack>(proof: &StarkProof<MC::H>) -> impl Iterator<Item = Commitment> + '_ {
    proof.commitments.iter().map(|&root| MC::commitment(root))
}

/// The Merkle channel, channel and hash of one format channel.
pub trait PcsStack:
    MerkleChannel<C: FsChannel, H: MerkleHasherLifted<Hash: ProofHash>> + Default + 'static
{
    const CHANNEL: ChannelKind;

    /// A root of the stack's trees as a commitment, tagged by the stack.
    fn commitment(root: <Self::H as MerkleHasherLifted>::Hash) -> Commitment {
        root.into_commitment()
    }

    fn stark(proof: &StarkProofAny) -> Option<&StarkProof<Self::H>>;

    fn stark_mut(proof: &mut StarkProofAny) -> Option<&mut StarkProof<Self::H>>;

    fn into_any(proof: StarkProof<Self::H>) -> StarkProofAny;

    fn from_any(proof: StarkProofAny) -> Option<StarkProof<Self::H>>;
}

impl PcsStack for Blake2sMerkleChannel {
    const CHANNEL: ChannelKind = ChannelKind::Blake2s;

    fn stark(proof: &StarkProofAny) -> Option<&StarkProof<Self::H>> {
        match proof {
            StarkProofAny::Blake2s(proof) => Some(proof),
            StarkProofAny::Poseidon2M31(_) | StarkProofAny::Blake2sM31(_) => None,
        }
    }

    fn stark_mut(proof: &mut StarkProofAny) -> Option<&mut StarkProof<Self::H>> {
        match proof {
            StarkProofAny::Blake2s(proof) => Some(proof),
            StarkProofAny::Poseidon2M31(_) | StarkProofAny::Blake2sM31(_) => None,
        }
    }

    fn into_any(proof: StarkProof<Self::H>) -> StarkProofAny {
        StarkProofAny::Blake2s(proof)
    }

    fn from_any(proof: StarkProofAny) -> Option<StarkProof<Self::H>> {
        match proof {
            StarkProofAny::Blake2s(proof) => Some(proof),
            StarkProofAny::Poseidon2M31(_) | StarkProofAny::Blake2sM31(_) => None,
        }
    }
}

impl PcsStack for P2MerkleChannel {
    const CHANNEL: ChannelKind = ChannelKind::Poseidon2M31;

    fn stark(proof: &StarkProofAny) -> Option<&StarkProof<Self::H>> {
        match proof {
            StarkProofAny::Poseidon2M31(proof) => Some(proof),
            StarkProofAny::Blake2s(_) | StarkProofAny::Blake2sM31(_) => None,
        }
    }

    fn stark_mut(proof: &mut StarkProofAny) -> Option<&mut StarkProof<Self::H>> {
        match proof {
            StarkProofAny::Poseidon2M31(proof) => Some(proof),
            StarkProofAny::Blake2s(_) | StarkProofAny::Blake2sM31(_) => None,
        }
    }

    fn into_any(proof: StarkProof<Self::H>) -> StarkProofAny {
        StarkProofAny::Poseidon2M31(proof)
    }

    fn from_any(proof: StarkProofAny) -> Option<StarkProof<Self::H>> {
        match proof {
            StarkProofAny::Poseidon2M31(proof) => Some(proof),
            StarkProofAny::Blake2s(_) | StarkProofAny::Blake2sM31(_) => None,
        }
    }
}

impl PcsStack for Blake2sM31MerkleChannel {
    const CHANNEL: ChannelKind = ChannelKind::Blake2sM31;

    fn commitment(root: Blake2sHash) -> Commitment {
        Commitment::Blake2sM31(root)
    }

    fn stark(proof: &StarkProofAny) -> Option<&StarkProof<Self::H>> {
        match proof {
            StarkProofAny::Blake2sM31(proof) => Some(proof),
            StarkProofAny::Blake2s(_) | StarkProofAny::Poseidon2M31(_) => None,
        }
    }

    fn stark_mut(proof: &mut StarkProofAny) -> Option<&mut StarkProof<Self::H>> {
        match proof {
            StarkProofAny::Blake2sM31(proof) => Some(proof),
            StarkProofAny::Blake2s(_) | StarkProofAny::Poseidon2M31(_) => None,
        }
    }

    fn into_any(proof: StarkProof<Self::H>) -> StarkProofAny {
        StarkProofAny::Blake2sM31(proof)
    }

    fn from_any(proof: StarkProofAny) -> Option<StarkProof<Self::H>> {
        match proof {
            StarkProofAny::Blake2sM31(proof) => Some(proof),
            StarkProofAny::Blake2s(_) | StarkProofAny::Poseidon2M31(_) => None,
        }
    }
}

/// Run `$body` with `$stack` the [`PcsStack`] of channel `$channel`, or
/// evaluate `$unbuilt` for a channel no segment format names.
#[macro_export]
#[doc(hidden)]
macro_rules! with_stack {
    ($channel:expr, $stack:ident => $body:expr, unbuilt => $unbuilt:expr $(,)?) => {
        match $channel {
            $crate::format::ChannelKind::Poseidon2M31 => {
                type $stack = $crate::poseidon2::P2MerkleChannel;
                $body
            }
            $crate::format::ChannelKind::Blake2s
            | $crate::format::ChannelKind::Blake2sM31
            | $crate::format::ChannelKind::Blake2b256 => $unbuilt,
        }
    };
}

#[cfg(all(test, feature = "prover"))]
mod tests {
    use alloc::vec::Vec;

    use stwo::core::fields::m31::M31;
    use stwo::core::vcs_lifted::verifier::MerkleVerifierLifted;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo::prover::backend::simd::column::BaseColumn;
    use stwo::prover::vcs_lifted::ops::MerkleOpsLifted;
    use stwo::prover::vcs_lifted::prover::MerkleProverLifted;

    use super::*;

    /// A leaf of 4 M31s whose Blake2s digest's word 4 is `2^32 - 1`, which
    /// reduces to 1.
    const EDGE_LEAF: [u32; 4] = [0x5208_0a2a, 0x5368_d2ec, 0x1b80_dd5a, 0x2826_d36f];

    /// Two children whose Blake2s digest's word 0 is `2^32 - 2`, which
    /// reduces to 0.
    const EDGE_CHILDREN: [u32; 16] = [
        0x3332_5aa3,
        0x0,
        0x3c6e_f372,
        0x5aa6_6d2c,
        0x78dd_e6e4,
        0x1715_609d,
        0x354c_da57,
        0x5384_540f,
        0x71bb_cdc9,
        0x0ff3_4782,
        0x2e2a_c13a,
        0x4c62_3af4,
        0x6a99_b4ac,
        0x08d1_2e65,
        0x2708_a81f,
        0x4540_21d7,
    ];

    fn hash(words: &[u32]) -> Blake2sHash {
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes.chunks_exact_mut(4).zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        Blake2sHash(bytes)
    }

    /// [`EDGE_LEAF`]'s hash under `H`.
    fn leaf<H: MerkleHasherLifted<Hash = Blake2sHash>>() -> Blake2sHash {
        let mut hasher = H::default();
        hasher.update_leaf(&EDGE_LEAF.map(M31::from_u32_unchecked));
        hasher.finalize()
    }

    /// The SIMD prover's Blake2s-M31 tree is the one the verifier
    /// recomputes when a leaf's digest has a word at the top of the `u32`
    /// range: the word reduced to 1, the leaf's decommitment verified
    /// against the root.
    #[test]
    fn a_leaf_digest_word_at_the_top_reduces_as_the_verifier_does() {
        const LOG_SIZE: u32 = 5;
        const EDGE_ROW: usize = 19;
        let columns: Vec<BaseColumn> = (0..EDGE_LEAF.len())
            .map(|i| {
                let values: Vec<M31> = (0..1u32 << LOG_SIZE)
                    .map(|row| match row as usize {
                        EDGE_ROW => M31::from_u32_unchecked(EDGE_LEAF[i]),
                        _ => M31::from(row * 4 + i as u32),
                    })
                    .collect();
                BaseColumn::from_cpu(&values)
            })
            .collect();
        let tree = MerkleProverLifted::<SimdBackend, Blake2sM31MerkleHasher>::commit(
            columns.iter().collect(),
            LOG_SIZE,
            0,
        );
        assert_eq!(
            leaf::<Blake2sMerkleHasher>().0[16..20],
            u32::MAX.to_le_bytes()
        );
        assert_eq!(
            leaf::<Blake2sM31MerkleHasher>().0[16..20],
            1u32.to_le_bytes()
        );

        let (values, decommitment) = tree.decommit(&[EDGE_ROW], columns.iter().collect());
        assert!(words_below_p(&tree.root()));
        MerkleVerifierLifted::<Blake2sM31MerkleHasher>::new(
            tree.root(),
            alloc::vec![LOG_SIZE; EDGE_LEAF.len()],
            None,
        )
        .verify(&[EDGE_ROW], values, decommitment.decommitment)
        .expect("the verifier recomputes the prover's root");
    }

    /// The SIMD prover hashes two children whose digest has a word at
    /// `2^32 - 2` to the verifier's node, the word reduced to 0.
    #[test]
    fn a_node_digest_word_at_the_top_reduces_as_the_verifier_does() {
        const EDGE_NODE: usize = 11;
        let layer: Vec<Blake2sHash> = (0..64u32)
            .map(|i| match i as usize {
                i if i == 2 * EDGE_NODE => hash(&EDGE_CHILDREN[..8]),
                i if i == 2 * EDGE_NODE + 1 => hash(&EDGE_CHILDREN[8..]),
                _ => hash(&[i; 8]),
            })
            .collect();
        let built =
            <SimdBackend as MerkleOpsLifted<Blake2sM31MerkleHasher>>::build_next_layer(&layer);
        let children = (hash(&EDGE_CHILDREN[..8]), hash(&EDGE_CHILDREN[8..]));
        let raw = Blake2sMerkleHasher::hash_children(children);
        assert_eq!(raw.0[..4], (u32::MAX - 1).to_le_bytes());
        let node = Blake2sM31MerkleHasher::hash_children(children);
        assert_eq!(node.0[..4], [0; 4]);
        assert_eq!(built[EDGE_NODE], node);
    }
}

#[cfg(all(test, feature = "prover"))]
mod mix_tests {
    use super::*;

    /// Blake2s-M31 mixes a run's bytes four a word: the digest of the
    /// channel's state and the bytes themselves, so a boundary-state run of
    /// 296 bytes hashes 296 bytes, not 1,184; each byte of a run moves it,
    /// and a run of part of a word is refused.
    #[test]
    fn blake2s_m31_mixes_four_bytes_a_word() {
        let bytes: alloc::vec::Vec<u8> = (0..296u32).map(|i| (i * 37 + 11) as u8).collect();
        let mixed = |bytes: &[u8]| {
            let mut channel = Blake2sM31Channel::default();
            channel.mix_bytes(bytes);
            channel.digest()
        };
        let mut packed = Blake2sM31Channel::default();
        let words: alloc::vec::Vec<u32> = bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        packed.mix_u32s(&words);
        assert_eq!(mixed(&bytes), packed.digest());
        let mut one_a_byte = Blake2sM31Channel::default();
        let wide: alloc::vec::Vec<u32> = bytes.iter().map(|&byte| u32::from(byte)).collect();
        one_a_byte.mix_u32s(&wide);
        assert_ne!(mixed(&bytes), one_a_byte.digest());
        assert!(std::panic::catch_unwind(|| mixed(&[1, 2, 3])).is_err());
        for at in [0, 1, 2, 3, 147, 295] {
            let mut changed = bytes.clone();
            changed[at] ^= 1;
            assert_ne!(mixed(&changed), mixed(&bytes), "byte {at}");
        }
    }
}
