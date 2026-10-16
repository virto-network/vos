//! The PCS stacks a proof's format selects at run time.
//!
//! A format names its channel ([`crate::format::ChannelKind`]); the code that
//! proves, verifies or replays a transcript is generic over [`PcsStack`],
//! and [`with_stack!`](crate::with_stack) picks the stack for a channel. A proof holds its Stwo
//! proof as a [`StarkProofAny`], whose variant is its channel's, and its
//! commitments as [`Commitment`]s.
//!
//! The lookup elements are drawn through object-safe component methods, so
//! they take a [`ChannelRef`], which names the concrete channel.

use core::fmt;

use serde::{Deserialize, Serialize};
use stwo::core::channel::{Blake2sChannel, Channel, MerkleChannel};
use stwo::core::fields::m31::{BaseField, P};
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs::hash::Hash;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;

use crate::format::ChannelKind;
use crate::poseidon2::{P2Hash, P2MerkleChannel, P2MerkleHasher, Poseidon2M31Channel};

/// A channel, named, for the lookup draws of the object-safe component
/// methods.
pub enum ChannelRef<'a> {
    Blake2s(&'a mut Blake2sChannel),
    Poseidon2M31(&'a mut Poseidon2M31Channel),
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

/// A Fiat–Shamir channel a format runs on.
pub trait FsChannel: Channel {
    fn as_ref_channel(&mut self) -> ChannelRef<'_>;

    /// Absorb `bytes`, one M31 a byte, as one run: the lossless encoding of
    /// the boundary states.
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

    fn from_commitment(commitment: &Commitment) -> Option<Self>;
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

    fn from_commitment(commitment: &Commitment) -> Option<Self> {
        match commitment {
            Commitment::Blake2s(hash) => Some(*hash),
            Commitment::Poseidon2M31(_) => None,
        }
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

    fn from_commitment(commitment: &Commitment) -> Option<Self> {
        match commitment {
            Commitment::Poseidon2M31(hash) => Some(*hash),
            Commitment::Blake2s(_) => None,
        }
    }
}

/// A Merkle commitment of a proof, in its format's hash. A program's
/// commitment is its preprocessed root.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Commitment {
    Blake2s(Blake2sHash),
    Poseidon2M31(P2Hash),
}

impl Commitment {
    pub fn channel(&self) -> ChannelKind {
        match self {
            Self::Blake2s(_) => ChannelKind::Blake2s,
            Self::Poseidon2M31(_) => ChannelKind::Poseidon2M31,
        }
    }

    /// The 32-byte form ([`ProofHash::to_bytes`]).
    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            Self::Blake2s(hash) => hash.to_bytes(),
            Self::Poseidon2M31(hash) => ProofHash::to_bytes(hash),
        }
    }

    /// A commitment of `channel`'s hash from its 32-byte form.
    pub fn from_bytes(channel: ChannelKind, bytes: &[u8; 32]) -> Option<Self> {
        match channel {
            ChannelKind::Blake2s => Blake2sHash::from_bytes(bytes).map(Self::Blake2s),
            ChannelKind::Poseidon2M31 => P2Hash::from_bytes(bytes).map(Self::Poseidon2M31),
            ChannelKind::Blake2sM31 | ChannelKind::Blake2b256 => None,
        }
    }
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
}

impl StarkProofAny {
    pub fn channel(&self) -> ChannelKind {
        match self {
            Self::Blake2s(_) => ChannelKind::Blake2s,
            Self::Poseidon2M31(_) => ChannelKind::Poseidon2M31,
        }
    }

    /// Every tree's root, in tree order.
    pub fn commitments(&self) -> alloc::vec::Vec<Commitment> {
        match self {
            Self::Blake2s(proof) => proof
                .commitments
                .iter()
                .map(|root| root.into_commitment())
                .collect(),
            Self::Poseidon2M31(proof) => proof
                .commitments
                .iter()
                .map(|root| root.into_commitment())
                .collect(),
        }
    }

    /// The root of tree `index`.
    pub fn commitment(&self, index: usize) -> Option<Commitment> {
        match self {
            Self::Blake2s(proof) => proof
                .commitments
                .get(index)
                .map(|root| root.into_commitment()),
            Self::Poseidon2M31(proof) => proof
                .commitments
                .get(index)
                .map(|root| root.into_commitment()),
        }
    }

    pub fn config(&self) -> stwo::core::pcs::PcsConfig {
        match self {
            Self::Blake2s(proof) => proof.config,
            Self::Poseidon2M31(proof) => proof.config,
        }
    }
}

/// The Merkle channel, channel and hash of one format channel.
pub trait PcsStack:
    MerkleChannel<C: FsChannel, H: MerkleHasherLifted<Hash: ProofHash>> + Default + 'static
{
    const CHANNEL: ChannelKind;

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
            StarkProofAny::Poseidon2M31(_) => None,
        }
    }

    fn stark_mut(proof: &mut StarkProofAny) -> Option<&mut StarkProof<Self::H>> {
        match proof {
            StarkProofAny::Blake2s(proof) => Some(proof),
            StarkProofAny::Poseidon2M31(_) => None,
        }
    }

    fn into_any(proof: StarkProof<Self::H>) -> StarkProofAny {
        StarkProofAny::Blake2s(proof)
    }

    fn from_any(proof: StarkProofAny) -> Option<StarkProof<Self::H>> {
        match proof {
            StarkProofAny::Blake2s(proof) => Some(proof),
            StarkProofAny::Poseidon2M31(_) => None,
        }
    }
}

impl PcsStack for P2MerkleChannel {
    const CHANNEL: ChannelKind = ChannelKind::Poseidon2M31;

    fn stark(proof: &StarkProofAny) -> Option<&StarkProof<Self::H>> {
        match proof {
            StarkProofAny::Poseidon2M31(proof) => Some(proof),
            StarkProofAny::Blake2s(_) => None,
        }
    }

    fn stark_mut(proof: &mut StarkProofAny) -> Option<&mut StarkProof<Self::H>> {
        match proof {
            StarkProofAny::Poseidon2M31(proof) => Some(proof),
            StarkProofAny::Blake2s(_) => None,
        }
    }

    fn into_any(proof: StarkProof<Self::H>) -> StarkProofAny {
        StarkProofAny::Poseidon2M31(proof)
    }

    fn from_any(proof: StarkProofAny) -> Option<StarkProof<Self::H>> {
        match proof {
            StarkProofAny::Poseidon2M31(proof) => Some(proof),
            StarkProofAny::Blake2s(_) => None,
        }
    }
}

/// Run `$body` with `$stack` the [`PcsStack`] of channel `$channel`, or
/// evaluate `$unbuilt` for a channel no stack implements yet.
#[macro_export]
#[doc(hidden)]
macro_rules! with_stack {
    ($channel:expr, $stack:ident => $body:expr, unbuilt => $unbuilt:expr $(,)?) => {
        match $channel {
            $crate::format::ChannelKind::Blake2s => {
                type $stack = ::stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
                $body
            }
            $crate::format::ChannelKind::Poseidon2M31 => {
                type $stack = $crate::poseidon2::P2MerkleChannel;
                $body
            }
            $crate::format::ChannelKind::Blake2sM31 | $crate::format::ChannelKind::Blake2b256 => {
                $unbuilt
            }
        }
    };
}
