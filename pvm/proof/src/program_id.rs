//! A kernel's program id (`proving.md` §3.6): the Poseidon2-M31 hash of
//! what pins its proofs, so a fold can recompute it in-circuit.
//!
//! **Two levels,** so that one fold circuit recomputes the id of every
//! kernel: the kernel's fields hash to its digest, a run of words whose
//! length is the kernel's, and the id hashes a preimage of fixed length,
//! [`ID_WORDS`], every field on whole wires of four words:
//!
//! | words | field |
//! |---|---|
//! | 0..8 | the kernel's digest |
//! | 8..12 | the leaf-circuit slot's version and its hashes' count (a u32 each) |
//! | 12..44 | [`MAX_LEAF_CIRCUITS`] hashes, eight words each, zeros past the count |
//!
//! The fold takes the id's preimage as a witness: the leaf circuits a fold
//! admits are its hashes. A zero hash past the count admits none, as no
//! circuit hashes to zero.
//!
//! **The kernel's digest** is over a run of M31 words, every value in A.3's
//! lossless limbs: a u32 two 16-bit limbs, little-endian, a 32-byte hash 16,
//! a byte or a log size one; a Poseidon2-M31 root its own eight words. In
//! order:
//!
//! 1. the domain, `vos/program-id`'s 14 bytes as 7 limbs, and the
//!    preimage's version, 3 (a u32);
//! 2. `TRANSPILER_VERSION`, the derivation's version (a u32);
//! 3. the kernel's `ProgramHash` (32 bytes);
//! 4. its shape: its chips' mask (a u32), its classes' count (a u32), and
//!    each class's `log_steps`, `pages` and the log size of each of its
//!    chips in chip order (a limb each);
//! 5. the segment format its proofs are in (a u32), which names their
//!    channel;
//! 6. each class's preprocessed root, in the classes' order, in the format's
//!    channel: eight words for Poseidon2-M31, 16 limbs for Blake2s;
//! 7. the image root, the page tree's over the kernel's initial memory (32
//!    bytes).
//!
//! **The leaf-circuit slot:** version 1 holds each class's leaf circuit's
//! hash, in the classes' order (`vos_pvm_recair::leaf`, the prover role's);
//! version 0 holds none, a program whose leaves are not built.
//!
//! **Both hashes** are the recursion AIR's `p2` leaf mode: eight words a
//! permutation, absorbed into the rate, then a 1 and zeros to the next
//! eight (`P2MerkleHasher`'s leaf).

use alloc::string::String;
use alloc::vec::Vec;

use stwo::core::fields::m31::BaseField;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;

use crate::format::ChannelKind;
use crate::pcs::Commitment;
use crate::poseidon2::{P2Hash, P2MerkleHasher, u32_limbs};
use crate::shape::{KernelShape, MAX_CLASSES};

/// The kernel digest's domain.
pub const DOMAIN: &[u8; 14] = b"vos/program-id";

/// The preimage's version.
pub const VERSION: u32 = 3;

/// The leaf-circuit hashes an id's preimage holds: one a class.
pub const MAX_LEAF_CIRCUITS: usize = MAX_CLASSES;

/// The words of an id's preimage.
pub const ID_WORDS: usize = 8 + 4 + 8 * MAX_LEAF_CIRCUITS;

/// A kernel's program id: eight M31 words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramId(pub [BaseField; 8]);

impl ProgramId {
    /// Its words as integers: the form a statement names it in.
    pub fn words(&self) -> [u32; 8] {
        self.0.map(|word| word.0)
    }

    /// The 32-byte form: each word as four little-endian bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes.chunks_exact_mut(4).zip(&self.0) {
            chunk.copy_from_slice(&word.0.to_le_bytes());
        }
        bytes
    }
}

/// The leaf circuits' slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeafCircuits {
    /// Version 0: no leaf circuit, a program no fold binds.
    None,
    /// Version 1: each class's leaf circuit's hash, in the classes' order.
    Hashes(Vec<P2Hash>),
}

impl LeafCircuits {
    /// The slot's version.
    pub fn version(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Hashes(_) => 1,
        }
    }

    /// Its hashes: none in version 0.
    pub fn hashes(&self) -> &[P2Hash] {
        match self {
            Self::None => &[],
            Self::Hashes(hashes) => hashes,
        }
    }
}

/// An id's preimage: a kernel's digest and its leaf circuits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdPreimage {
    pub kernel: P2Hash,
    pub leaf_circuits: LeafCircuits,
}

impl IdPreimage {
    /// Its [`ID_WORDS`] words.
    ///
    /// # Panics
    /// When the slot holds more than [`MAX_LEAF_CIRCUITS`] hashes, which
    /// [`KernelProgram::check`] refuses.
    pub fn words(&self) -> [BaseField; ID_WORDS] {
        let hashes = self.leaf_circuits.hashes();
        assert!(
            hashes.len() <= MAX_LEAF_CIRCUITS,
            "at most {MAX_LEAF_CIRCUITS} leaf circuits"
        );
        let mut words = [BaseField::from(0); ID_WORDS];
        words[..8].copy_from_slice(&self.kernel.0);
        let slot: Vec<BaseField> = u32_limbs(self.leaf_circuits.version())
            .into_iter()
            .chain(u32_limbs(hashes.len() as u32))
            .collect();
        words[8..12].copy_from_slice(&slot);
        for (k, hash) in hashes.iter().enumerate() {
            words[12 + 8 * k..20 + 8 * k].copy_from_slice(&hash.0);
        }
        words
    }

    /// The id it hashes to.
    pub fn id(&self) -> ProgramId {
        ProgramId(leaf_sponge(&self.words()).0)
    }
}

/// The `p2` leaf mode's sponge over `words`.
fn leaf_sponge(words: &[BaseField]) -> P2Hash {
    let mut hasher = P2MerkleHasher::default();
    hasher.update_leaf(words);
    hasher.finalize()
}

/// What a kernel's program id pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelProgram {
    pub transpiler: u32,
    pub program: [u8; 32],
    pub shape: KernelShape,
    /// The segment format its proofs are in.
    pub format: u32,
    /// Each class's preprocessed root, in the classes' order.
    pub preprocessed_roots: Vec<Commitment>,
    pub image_root: [u8; 32],
    pub leaf_circuits: LeafCircuits,
}

/// Where a run of a kernel starts, as the loader lays the kernel out with no
/// arguments: its first step's pc and timestamp, and its registers. A chain
/// of the kernel's segments starts there, and ends at [`HALT_PC`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelEntry {
    /// A standard program starts at its code's first byte.
    pub pc: u32,
    /// φ0 the halt address, φ1 the stack's top, φ7 the argument window,
    /// the rest 0.
    pub registers: [u64; vos_pvm_program::REGISTER_COUNT],
}

/// A run's first step's timestamp.
pub const ENTRY_TIMESTAMP: u64 = 1;

/// The pc a run ends at when it halts: the halt address.
pub const HALT_PC: u32 = vos_pvm_program::HALT_ADDRESS as u32;

impl KernelEntry {
    /// The entry of `blob`, the kernel `program` pins: refused when `blob`
    /// is not the program it names, by its hash and its image root, or not
    /// a standard program.
    pub fn of(program: &KernelProgram, blob: &[u8]) -> Result<Self, String> {
        if vos_pvm_precompiles::blake2b_256(blob) != program.program {
            return Err("the blob is not the kernel's program".into());
        }
        let standard = vos_pvm_program::parse_standard_program(blob)
            .ok_or_else(|| String::from("the kernel is not a standard program"))?;
        if standard.image_root() != Some(program.image_root) {
            return Err("the blob's image root is not the kernel's".into());
        }
        let layout = standard
            .layout(&[])
            .ok_or_else(|| String::from("the kernel's layout does not fit"))?;
        Ok(Self {
            pc: 0,
            registers: layout.registers,
        })
    }
}

/// A byte string's 16-bit limbs, little-endian, the last zero-extended.
fn byte_limbs(bytes: &[u8]) -> impl Iterator<Item = BaseField> + '_ {
    bytes.chunks(2).map(|pair| {
        BaseField::from_u32_unchecked(
            u32::from(pair[0]) | u32::from(*pair.get(1).unwrap_or(&0)) << 8,
        )
    })
}

impl KernelProgram {
    /// Whether it is one a venue may pin: a well-formed shape, a segment
    /// format the registry knows, and a root per class in its channel.
    pub fn check(&self) -> Result<(), String> {
        self.shape.check()?;
        let format = crate::format::lookup(self.format)
            .filter(|format| format.kind == crate::format::ProofKind::Segment)
            .ok_or_else(|| alloc::format!("format {} is no segment format", self.format))?;
        if self.preprocessed_roots.len() != self.shape.classes.len() {
            return Err(alloc::format!(
                "{} preprocessed roots for {} classes",
                self.preprocessed_roots.len(),
                self.shape.classes.len()
            ));
        }
        if self
            .preprocessed_roots
            .iter()
            .any(|root| root.channel() != format.channel)
        {
            return Err(alloc::format!(
                "a preprocessed root is not in format {}'s channel",
                self.format
            ));
        }
        if let LeafCircuits::Hashes(hashes) = &self.leaf_circuits
            && hashes.len() != self.shape.classes.len()
        {
            return Err(alloc::format!(
                "{} leaf circuits for {} classes",
                hashes.len(),
                self.shape.classes.len()
            ));
        }
        Ok(())
    }

    /// The words its digest hashes: every field but the leaf circuits.
    pub fn kernel_words(&self) -> Vec<BaseField> {
        let mut words: Vec<BaseField> = byte_limbs(DOMAIN).collect();
        words.extend(u32_limbs(VERSION));
        words.extend(u32_limbs(self.transpiler));
        words.extend(byte_limbs(&self.program));
        words.extend(u32_limbs(self.shape.components));
        words.extend(u32_limbs(self.shape.classes.len() as u32));
        for class in &self.shape.classes {
            words.push(BaseField::from(u32::from(class.log_steps)));
            words.push(BaseField::from(u32::from(class.pages)));
            words.extend(
                class
                    .log_sizes
                    .iter()
                    .map(|&size| BaseField::from(u32::from(size))),
            );
        }
        words.extend(u32_limbs(self.format));
        for root in &self.preprocessed_roots {
            match root {
                Commitment::Poseidon2M31(hash) => words.extend(hash.0),
                Commitment::Blake2s(_) => words.extend(byte_limbs(&root.to_bytes())),
            }
        }
        words.extend(byte_limbs(&self.image_root));
        words
    }

    /// The kernel's digest.
    pub fn kernel_digest(&self) -> P2Hash {
        leaf_sponge(&self.kernel_words())
    }

    /// Its id's preimage.
    pub fn id_preimage(&self) -> IdPreimage {
        IdPreimage {
            kernel: self.kernel_digest(),
            leaf_circuits: self.leaf_circuits.clone(),
        }
    }

    /// Its program id.
    pub fn id(&self) -> ProgramId {
        self.id_preimage().id()
    }

    /// The channel its proofs commit in.
    pub fn channel(&self) -> Option<ChannelKind> {
        crate::format::lookup(self.format).map(|format| format.channel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chip_idx;
    use crate::shape::SegmentClass;
    use alloc::vec;

    /// A program whose every field differs from its neighbours'.
    fn program() -> KernelProgram {
        let components = chip_idx::ALWAYS | 1 << chip_idx::MUL | 1 << chip_idx::COMPARE;
        let chips = components.count_ones() as usize;
        let class = |log_steps: u8| SegmentClass {
            log_steps,
            pages: 8,
            log_sizes: (0..chips as u8).map(|chip| 4 + chip % 13).collect(),
        };
        KernelProgram {
            transpiler: 3,
            program: core::array::from_fn(|i| i as u8),
            shape: KernelShape {
                components,
                classes: vec![class(12), class(15)],
            },
            format: crate::format::SEGMENT.number,
            preprocessed_roots: vec![
                Commitment::Poseidon2M31(P2Hash(core::array::from_fn(|i| {
                    BaseField::from(1_000 + i as u32)
                }))),
                Commitment::Poseidon2M31(P2Hash(core::array::from_fn(|i| {
                    BaseField::from(2_000 + i as u32)
                }))),
            ],
            image_root: core::array::from_fn(|i| 0xa0 + i as u8),
            leaf_circuits: LeafCircuits::None,
        }
    }

    /// The kernel digest's words, word by word, and the id's golden
    /// vector.
    #[test]
    fn the_program_id_is_pinned() {
        let program = program();
        program.check().unwrap();
        let words: Vec<u32> = program.kernel_words().iter().map(|word| word.0).collect();
        let chips = program.shape.components.count_ones() as usize;
        assert_eq!(chips, 18);
        assert_eq!(
            words.len(),
            7 + 2 + 2 + 16 + 2 + 2 + 2 * (2 + chips) + 2 + 2 * 8 + 16
        );
        assert_eq!(
            &words[..7],
            &[0x6f76, 0x2f73, 0x7270, 0x676f, 0x6172, 0x2d6d, 0x6469]
        );
        assert_eq!(&words[7..11], &[3, 0, 3, 0]);
        assert_eq!(&words[11..13], &[0x0100, 0x0302]);
        let shape = 27;
        assert_eq!(
            &words[shape..shape + 6],
            &[
                program.shape.components & 0xffff,
                program.shape.components >> 16,
                2,
                0,
                12,
                8
            ]
        );
        let format = shape + 4 + 2 * (2 + chips);
        assert_eq!(&words[format..format + 3], &[35, 0, 1_000]);
        assert_eq!(&words[words.len() - 2..], &[0xbdbc, 0xbfbe]);
        let id = program.id_preimage().words();
        assert_eq!(id[..8], program.kernel_digest().0);
        assert!(id[8..].iter().all(|&word| word == BaseField::from(0)));
        assert_eq!(
            program.id().words(),
            [
                2135066872, 100226137, 1685726148, 2064667428, 305260091, 2132776637, 2063760913,
                1333887263
            ],
            "the golden vector"
        );
    }

    /// The `p2` leaf mode's sponge over `words`: eight words added into the
    /// rate a permutation, then a 1 and zeros to the next eight, the first
    /// eight words of the state out.
    fn sponge(words: &[BaseField]) -> [BaseField; 8] {
        let mut words = words.to_vec();
        words.push(BaseField::from(1));
        words.resize(words.len().next_multiple_of(8), BaseField::from(0));
        let mut state = [BaseField::from(0); 16];
        for block in words.chunks_exact(8) {
            for (lane, word) in state.iter_mut().zip(block) {
                *lane += *word;
            }
            crate::poseidon2::permute(&mut state);
        }
        state[..8].try_into().unwrap()
    }

    /// The kernel's digest and the id are the `p2` leaf mode's sponges over
    /// their words.
    #[test]
    fn the_id_is_the_leaf_modes_sponge() {
        let mut program = program();
        program.leaf_circuits = LeafCircuits::Hashes(vec![
            P2Hash(core::array::from_fn(|i| {
                BaseField::from(9 + i as u32)
            }));
            2
        ]);
        assert_eq!(program.kernel_digest().0, sponge(&program.kernel_words()));
        assert_eq!(program.id().0, sponge(&program.id_preimage().words()));
    }

    /// Every field reaches the id.
    #[test]
    fn every_field_moves_the_id() {
        let id = program().id();
        let changed: [fn(&mut KernelProgram); 10] = [
            |p| p.transpiler += 1,
            |p| p.program[31] ^= 1,
            |p| p.shape.components |= 1 << chip_idx::DIVREM,
            |p| p.shape.classes[1].log_steps += 1,
            |p| p.shape.classes[1].pages += 1,
            |p| p.shape.classes[0].log_sizes[3] += 1,
            |p| p.format = crate::format::DEVICE_PROOF.number,
            |p| {
                if let Commitment::Poseidon2M31(hash) = &mut p.preprocessed_roots[1] {
                    hash.0[7] = BaseField::from(7);
                }
            },
            |p| p.image_root[0] ^= 1,
            |p| {
                p.leaf_circuits = LeafCircuits::Hashes(vec![P2Hash::default(); 2]);
            },
        ];
        for (index, change) in changed.iter().enumerate() {
            let mut program = program();
            change(&mut program);
            assert_ne!(program.id(), id, "field {index}");
        }
    }

    /// A root in another channel than the format's, a root count other than
    /// the classes', or a format that proves no segments is refused.
    #[test]
    fn a_malformed_program_is_refused() {
        let mut blake = program();
        blake.preprocessed_roots[0] = Commitment::Blake2s(Default::default());
        assert!(blake.check().unwrap_err().contains("channel"));
        let mut short = program();
        short.preprocessed_roots.pop();
        assert!(short.check().is_err());
        let mut leaf = program();
        leaf.format = crate::format::LEAF_FOLD.number;
        assert!(leaf.check().is_err());
        let mut leaves = program();
        leaves.leaf_circuits = LeafCircuits::Hashes(vec![P2Hash::default()]);
        assert!(leaves.check().unwrap_err().contains("leaf circuits"));
    }

    /// Version 1's slot: its version, the hashes' count and each hash's
    /// words, after the kernel's digest, zeros past the count; a hash's word
    /// moves the id, and the kernel's digest does not depend on the slot.
    #[test]
    fn the_leaf_circuits_slot_is_pinned() {
        let mut program = program();
        let hashes: Vec<P2Hash> = (0..2u32)
            .map(|class| {
                P2Hash(core::array::from_fn(|i| {
                    BaseField::from(3_000 + 100 * class + i as u32)
                }))
            })
            .collect();
        let kernel = program.kernel_digest();
        program.leaf_circuits = LeafCircuits::Hashes(hashes.clone());
        program.check().unwrap();
        assert_eq!(program.kernel_digest(), kernel);
        let words: Vec<u32> = program
            .id_preimage()
            .words()
            .iter()
            .map(|word| word.0)
            .collect();
        assert_eq!(words.len(), ID_WORDS);
        assert_eq!(&words[..8], &kernel.0.map(|word| word.0)[..]);
        let slot = &words[8..];
        assert_eq!(&slot[..4], &[1, 0, 2, 0]);
        for (k, hash) in hashes.iter().enumerate() {
            assert_eq!(&slot[4 + 8 * k..12 + 8 * k], &hash.0.map(|word| word.0)[..]);
        }
        assert!(slot[4 + 16..].iter().all(|&word| word == 0));
        let id = program.id();
        let LeafCircuits::Hashes(hashes) = &mut program.leaf_circuits else {
            unreachable!()
        };
        hashes[1].0[7] = BaseField::from(1);
        assert_ne!(program.id(), id);
    }
}
