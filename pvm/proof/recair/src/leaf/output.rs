//! A node's output, natively (`proving.md` A.3): the state digests and the
//! preimage a leaf or a fold hashes to its 8-word output digest.
//!
//! **A state digest** is the leaf sponge over 148 words, one a byte: the 13
//! registers (8 little-endian bytes each), pc (4), ts (8) and the memory
//! root (32), the boundary chips' own byte limbs.
//!
//! **The preimage** is 52 words, each field on whole wires of four, so a
//! circuit hashes the wires it holds as they are:
//!
//! | words | field |
//! |---|---|
//! | 0..8 | the program id |
//! | 8..12 | `first`, `last`, the entry flag, the halt flag |
//! | 12..20 | the entry state's digest |
//! | 20..28 | the exit state's digest |
//! | 28..44 | the io-hash, φ9..12's 32 bytes as 16 limbs `b0 + 256·b1` |
//! | 44..52 | the fold-circuit word W |
//!
//! The digest is the leaf sponge over them, as the program id's.

use stwo::core::fields::m31::BaseField;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use vos_pvm_proof::SegmentState;
use vos_pvm_proof::poseidon2::{P2Hash, P2MerkleHasher};

/// The words a state digest hashes.
pub const STATE_WORDS: usize = 13 * 8 + 4 + 8 + 32;

/// The words a node's output preimage holds.
pub const PREIMAGE_WORDS: usize = 52;

/// A state as a state digest takes it: its registers, pc, ts and memory
/// root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub registers: [u64; 13],
    pub pc: u32,
    pub timestamp: u64,
    pub memory_root: [u8; 32],
}

impl From<&SegmentState> for State {
    fn from(state: &SegmentState) -> Self {
        Self {
            registers: state.registers,
            pc: state.pc,
            timestamp: state.timestamp,
            memory_root: state.memory_root,
        }
    }
}

impl State {
    /// Its 148 bytes, in the digest's order.
    pub fn bytes(&self) -> [u8; STATE_WORDS] {
        let mut bytes = [0u8; STATE_WORDS];
        let mut at = 0;
        let mut put = |part: &[u8]| {
            bytes[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        };
        for register in &self.registers {
            put(&register.to_le_bytes());
        }
        put(&self.pc.to_le_bytes());
        put(&self.timestamp.to_le_bytes());
        put(&self.memory_root);
        bytes
    }

    /// Its digest.
    pub fn digest(&self) -> P2Hash {
        let words: Vec<BaseField> = self
            .bytes()
            .iter()
            .map(|&byte| BaseField::from(u32::from(byte)))
            .collect();
        leaf_sponge(&words)
    }
}

/// The leaf sponge over `words`.
fn leaf_sponge(words: &[BaseField]) -> P2Hash {
    let mut hasher = P2MerkleHasher::default();
    hasher.update_leaf(words);
    hasher.finalize()
}

/// The io-hash's 16 limbs: its bytes in pairs, `b0 + 256·b1`.
pub fn io_hash_limbs(io_hash: &[u8; 32]) -> [BaseField; 16] {
    core::array::from_fn(|i| {
        BaseField::from(u32::from(io_hash[2 * i]) | u32::from(io_hash[2 * i + 1]) << 8)
    })
}

/// The io-hash a run's final registers hold: φ9..12's bytes.
pub fn io_hash_of(registers: &[u64; 13]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (chunk, register) in bytes.chunks_exact_mut(8).zip(&registers[9..13]) {
        chunk.copy_from_slice(&register.to_le_bytes());
    }
    bytes
}

/// A node's output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeOutput {
    pub program: P2Hash,
    pub first: u32,
    pub last: u32,
    pub entry: bool,
    pub halt: bool,
    pub entry_digest: P2Hash,
    pub exit_digest: P2Hash,
    pub io_hash: [u8; 32],
    pub fold_word: P2Hash,
}

impl NodeOutput {
    /// Its preimage's words.
    pub fn preimage(&self) -> [BaseField; PREIMAGE_WORDS] {
        let mut words = Vec::with_capacity(PREIMAGE_WORDS);
        words.extend(self.program.0);
        words.extend(
            [self.first, self.last, self.entry.into(), self.halt.into()].map(BaseField::from),
        );
        words.extend(self.entry_digest.0);
        words.extend(self.exit_digest.0);
        words.extend(io_hash_limbs(&self.io_hash));
        words.extend(self.fold_word.0);
        words.try_into().expect("the preimage's words")
    }

    /// Its digest.
    pub fn digest(&self) -> P2Hash {
        leaf_sponge(&self.preimage())
    }
}
