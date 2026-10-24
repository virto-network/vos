//! Poseidon2 over M31, width 16, on Stwo: the Merkle hasher and the
//! Fiat-Shamir channel.
//!
//! The recursion verifier-AIR commits inner proofs under an **M31-algebraic**
//! hash so the Merkle-decommit paths are cheap to re-express as constraints,
//! and replays an M31-algebraic Fiat-Shamir transcript so no Blake2s appears on
//! the commit/transcript path. This module adapts `vos_pvm_poseidon2`'s
//! permutation and modes to Stwo — the [`MerkleHasherLifted`] commitment hash
//! and the [`Channel`] transcript — which the formats on the Poseidon2-M31
//! channel ([`crate::format`]) select at run time.
//!
//! **The prover's hashing** runs sixteen permutations at once on the widest
//! SIMD the build targets ([`packed`]); the scalar [`permute`] is the
//! reference the verifier uses, and the packed code equals it lane for lane.

use alloc::rc::Rc;
use alloc::vec::Vec;

use num_traits::Zero;
use serde::{Deserialize, Serialize};
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::vcs::hash::Hash;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use vos_pvm_poseidon2::{LeafSponge, M31, Observer, Transcript};

use core::cell::RefCell;

#[cfg(feature = "prover")]
pub use vos_pvm_poseidon2::packed;
pub use vos_pvm_poseidon2::{
    FULL_ROUNDS, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS, N_STATE, PermKind, RATE,
};

/// A Stwo word as the permutation's.
fn word(value: BaseField) -> M31 {
    M31::from(value.0)
}

/// The permutation's word as Stwo's.
fn base(value: M31) -> BaseField {
    BaseField::from_u32_unchecked(value.value())
}

/// The Poseidon2-over-M31 permutation under the reference round constants.
pub fn permute(state: &mut [BaseField; N_STATE]) {
    let mut words = state.map(word);
    vos_pvm_poseidon2::permute(&mut words);
    *state = words.map(base);
}

/// A u32's two 16-bit limbs, little-endian.
pub fn u32_limbs(value: u32) -> [BaseField; 2] {
    vos_pvm_poseidon2::u32_limbs(value).map(base)
}

/// A u64's four 16-bit limbs, little-endian.
pub fn u64_limbs(value: u64) -> [BaseField; 4] {
    vos_pvm_poseidon2::u64_limbs(value).map(base)
}

// ── M31-algebraic Merkle hasher (the de-risked PCS commitment) ────────────

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Serialize, Deserialize)]
pub struct P2Hash(pub [BaseField; 8]);

impl core::fmt::Display for P2Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "P2Hash({:?})", self.0.map(|m| m.0))
    }
}
impl Hash for P2Hash {}

impl From<vos_pvm_poseidon2::Digest> for P2Hash {
    fn from(digest: vos_pvm_poseidon2::Digest) -> Self {
        Self(digest.map(base))
    }
}

impl From<P2Hash> for vos_pvm_poseidon2::Digest {
    fn from(hash: P2Hash) -> Self {
        hash.0.map(word)
    }
}

impl P2Hash {
    /// The canonical 32-byte serialization: the 8 M31 limbs as little-endian
    /// `u32`s. Inverse of [`P2Hash::from`] for canonical limbs (`< p`), which is
    /// always the case for a real commitment. This is the 32-byte wire form the
    /// program-commitment allowlist bakes (mirrors `Blake2sHash`'s `[u8; 32]`).
    pub fn to_bytes(&self) -> [u8; 8 * 4] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&limb.0.to_le_bytes());
        }
        out
    }
}

/// Parse a 32-byte commitment (8 little-endian `u32` limbs, each reduced mod
/// `p`) back into a `P2Hash`. Mirrors `Blake2sHash: From<&[u8]>` so the
/// channel-agnostic `CommitmentHash::from(&[u8])` in the prover extension works
/// under the Poseidon2-M31 stack. Panics on a non-32-byte slice (callers guard).
impl From<&[u8]> for P2Hash {
    fn from(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 32, "P2Hash requires exactly 32 bytes");
        let mut limbs = [BaseField::zero(); 8];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let w = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
            *limb = BaseField::reduce(w as u64);
        }
        P2Hash(limbs)
    }
}

/// The leaf sponge and the node compression, as Stwo's Merkle hasher.
#[derive(Clone, Debug, Default)]
pub struct P2MerkleHasher {
    sponge: LeafSponge,
}

impl P2MerkleHasher {
    /// The sponge's state after the whole blocks absorbed so far.
    #[cfg(feature = "prover")]
    fn state(&self) -> [u32; N_STATE] {
        self.sponge.state().map(M31::value)
    }

    /// The words waiting for a whole block.
    #[cfg(feature = "prover")]
    fn buffered(&self) -> &[M31] {
        self.sponge.buffered()
    }
}

impl MerkleHasherLifted for P2MerkleHasher {
    type Hash = P2Hash;
    fn hash_children((left, right): (P2Hash, P2Hash)) -> P2Hash {
        vos_pvm_poseidon2::compress(&left.into(), &right.into()).into()
    }
    fn update_leaf(&mut self, column_values: &[BaseField]) {
        self.sponge
            .absorb(column_values.iter().map(|&value| word(value)));
    }
    fn finalize(self) -> P2Hash {
        self.sponge.finalize().into()
    }
}

// Dummy serde for the hasher: `StarkProof<H>`'s derive bounds `H: Serialize +
// Deserialize`, but the hasher *value* is never serialized — only `H::Hash`
// (the committed roots) is. Mirrors stwo's own `Blake2sMerkleHasher` dummy
// impls so a `StarkProof<P2MerkleHasher>` (and thus `Proof`) is (de)serializable.
impl Serialize for P2MerkleHasher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let ser = serializer.serialize_struct("P2MerkleHasher", 0)?;
        serde::ser::SerializeStruct::end(ser)
    }
}
impl<'de> Deserialize<'de> for P2MerkleHasher {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self::default())
    }
}

// ── Poseidon2-M31 Fiat-Shamir channel (no Blake2s on commit OR transcript) ─

/// One width-16 permutation as the transcript drove it: its full input + output
/// state and which op invoked it. The ground truth the channel-replay AIR must
/// reproduce row-for-row.
///
/// `first_chunk` is `false` only for the continuation chunks of a multi-chunk
/// absorption (where the rate half carries the previous chunk's permuted
/// state); it is `true` for a fresh absorption's first chunk, every squeeze, and
/// both pow permutations.
#[derive(Clone, Copy, Debug)]
pub struct PermRecord {
    pub kind: PermKind,
    pub input: [BaseField; N_STATE],
    pub output: [BaseField; N_STATE],
    pub first_chunk: bool,
}

/// Records each permutation into a shared buffer, when there is one.
struct Recorder<'a>(Option<&'a RefCell<Vec<PermRecord>>>);

impl Observer for Recorder<'_> {
    fn permuted(
        &mut self,
        kind: PermKind,
        first_chunk: bool,
        input: &[M31; N_STATE],
        output: &[M31; N_STATE],
    ) {
        if let Some(records) = self.0 {
            records.borrow_mut().push(PermRecord {
                kind,
                input: input.map(base),
                output: output.map(base),
                first_chunk,
            });
        }
    }
}

/// `vos_pvm_poseidon2`'s transcript as Stwo's channel: absorptions for the
/// mixes, draws for the felts and words, and its PoW check.
///
/// When a `recorder` is attached (via [`Poseidon2M31Channel::recording`]) every
/// permutation the transcript performs is appended to it, in caller order — this
/// is how the native-recursion verifier-AIR pins the exact op sequence the stwo
/// verifier drives over a real segment proof. Default (no recorder) is
/// zero-overhead, so the production transcript is unaffected.
#[derive(Clone, Debug, Default)]
pub struct Poseidon2M31Channel {
    transcript: Transcript,
    recorder: Option<Rc<RefCell<Vec<PermRecord>>>>,
}

impl Poseidon2M31Channel {
    /// A fresh channel that records every permutation it performs into the
    /// shared buffer. Clones share the buffer, so a channel handed to a stwo
    /// `verify()` records the whole verifier transcript (the recursion seam
    /// `crate::record_canonical_transcript` uses this).
    pub fn recording(recorder: Rc<RefCell<Vec<PermRecord>>>) -> Self {
        Self {
            transcript: Transcript::default(),
            recorder: Some(recorder),
        }
    }

    fn absorb(&mut self, values: &[M31]) {
        self.transcript
            .absorb(values, &mut Recorder(self.recorder.as_deref()));
    }

    fn squeeze8(&mut self) -> [BaseField; 8] {
        self.transcript
            .squeeze(&mut Recorder(self.recorder.as_deref()))
            .map(base)
    }

    /// Absorb M31 values as one run.
    pub fn mix_m31s(&mut self, values: &[BaseField]) {
        let words: Vec<M31> = values.iter().map(|&value| word(value)).collect();
        self.absorb(&words);
    }

    /// The rate words of `verify_pow_nonce`'s first permutation, which a
    /// nonce does not enter.
    #[cfg(feature = "prover")]
    fn pow_prefix(&self, n_bits: u32) -> [BaseField; 8] {
        self.transcript.pow_prefix(n_bits).map(base)
    }
}

impl Channel for Poseidon2M31Channel {
    const BYTES_PER_HASH: usize = 32;

    fn verify_pow_nonce(&self, n_bits: u32, nonce: u64) -> bool {
        self.transcript
            .verify_pow_nonce(n_bits, nonce, &mut Recorder(self.recorder.as_deref()))
    }

    fn mix_u32s(&mut self, data: &[u32]) {
        let words: Vec<M31> = data
            .iter()
            .flat_map(|&value| vos_pvm_poseidon2::u32_limbs(value))
            .collect();
        self.absorb(&words);
    }

    fn mix_felts(&mut self, felts: &[SecureField]) {
        let words: Vec<M31> = felts
            .iter()
            .flat_map(|felt| felt.to_m31_array().map(word))
            .collect();
        self.absorb(&words);
    }

    fn mix_u64(&mut self, value: u64) {
        self.absorb(&vos_pvm_poseidon2::u64_limbs(value));
    }

    fn draw_secure_felt(&mut self) -> SecureField {
        let f = self.squeeze8();
        SecureField::from_m31_array([f[0], f[1], f[2], f[3]])
    }

    fn draw_secure_felts(&mut self, n_felts: usize) -> Vec<SecureField> {
        let mut out = Vec::with_capacity(n_felts);
        while out.len() < n_felts {
            let f = self.squeeze8();
            out.push(SecureField::from_m31_array([f[0], f[1], f[2], f[3]]));
            if out.len() < n_felts {
                out.push(SecureField::from_m31_array([f[4], f[5], f[6], f[7]]));
            }
        }
        out
    }

    fn draw_u32s(&mut self) -> Vec<u32> {
        self.squeeze8().iter().map(|m| m.0).collect()
    }
}

/// The Merkle channel pairing the Poseidon2-M31 hasher with the Poseidon2-M31
/// transcript: no Blake2s on the commitments or the Fiat–Shamir path.
#[derive(Default)]
pub struct P2MerkleChannel;
impl MerkleChannel for P2MerkleChannel {
    type C = Poseidon2M31Channel;
    type H = P2MerkleHasher;
    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasherLifted>::Hash) {
        channel.absorb(&vos_pvm_poseidon2::Digest::from(root));
    }
}

/// The one orphan-legal marker the custom channel needs: every super-bound of
/// `BackendForChannel<P2MerkleChannel>` is blanket-satisfied on `CpuBackend`;
/// legal because the trait's type parameter (`P2MerkleChannel`) is local.
#[cfg(feature = "prover")]
impl stwo::prover::backend::BackendForChannel<P2MerkleChannel>
    for stwo::prover::backend::CpuBackend
{
}

// ── SimdBackend `BackendForChannel<P2MerkleChannel>` ──────────────────────
//
// Production proves on `SimdBackend` (vectorized FRI / quotients / twiddles),
// and so does the Poseidon2-M31 stack: `simd_backend` hashes leaves and nodes
// and grinds sixteen permutations at once ([`packed`]). Its roots and nonces
// equal `CpuBackend`'s.
#[cfg(feature = "prover")]
mod simd_backend;
