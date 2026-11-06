//! Poseidon2-M31 as a kernel writes it (`light-node.md` §4.2): [`Digest`],
//! the tags' [`TagHash::hash`], [`Digest::hash`] and [`Path::root`], each
//! one `0x402` call reading its block where it lies; and arguments read in
//! place ([`InPlace`], [`in_place`]), which a device kernel's arguments by
//! reference are.
//!
//! A digest is eight M31 words, its bytes the words as little-endian
//! `u32`s ([`vos_wire::credentials`]'s), held 8-aligned so the guest moves
//! it as four `u64`s. The compression `C(l, r)` is the first eight words
//! of the width-16 permutation of `l ‖ r`; a word at or above p traps.
//!
//! The words are moved whole: aligned loads and stores of `u64`s, and where
//! the alignment is not known ([`encode_in_place`]) one load and one store
//! a word through [`load_u64`] and [`store_u64`], which the PVM serves at
//! any address (the guest target's own unaligned accesses go byte by
//! byte). Nothing here reaches BLAKE2b, so a device kernel may use all of
//! it.

use alloc::vec::Vec;
use core::mem::MaybeUninit;

use vos_wire::scale::DecodeError;

pub use vos_sdk_macros::InPlace;
pub use vos_wire::credentials::{DEPTH, Tag};

/// A digest: eight M31 words, 8-aligned. Its encoding is its 32 bytes, the
/// words as little-endian `u32`s.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, align(8))]
pub struct Digest(pub [u32; 8]);

/// A member's secret: a digest.
pub type Secret = Digest;

/// A path in the credential tree: the 32 siblings from the leaf's level up
/// and the leaf's slot, whose low 32 bits the walk reads (bit `l` set when
/// the level-`l` node is a right child). Its encoding is its 1,032 bytes,
/// the siblings then the slot as a little-endian `u64`.
#[derive(Clone, Copy, Debug, InPlace)]
#[repr(C)]
pub struct Path {
    pub siblings: [Digest; DEPTH],
    pub slot: u64,
}

/// A type whose value is its bytes, read in place: any `size_of::<Self>()`
/// bytes are one, at an address of its alignment, which is at most eight;
/// its encoding is those bytes. `#[derive(InPlace)]` makes a `#[repr(C)]`
/// struct of such fields one, and refuses one with padding.
///
/// # Safety
///
/// Every bit pattern of its size is a valid value, it holds no padding, no
/// pointer and no interior mutability, and its alignment is at most eight.
/// Its `Encode` and `Decode`, where it has them, are its bytes
/// ([`encode_in_place`], [`decode_in_place`]): a client encodes a device
/// kernel's message by value and the kernel reads the same bytes in place.
pub unsafe trait InPlace: Copy + 'static {}

// SAFETY: plain integers and arrays of in-place values, with no padding.
unsafe impl InPlace for u8 {}
// SAFETY: as above.
unsafe impl InPlace for u16 {}
// SAFETY: as above.
unsafe impl InPlace for u32 {}
// SAFETY: as above.
unsafe impl InPlace for u64 {}
// SAFETY: eight `u32`s, 32 bytes at an 8-alignment: no padding.
unsafe impl InPlace for Digest {}
// SAFETY: an array of in-place values holds no padding between them.
unsafe impl<T: InPlace, const N: usize> InPlace for [T; N] {}

/// The `T` at `*at` in `input`, in place, its end then `*at`: a device
/// kernel's argument by reference, which [`InPlace`]'s size, a multiple of
/// eight bytes, keeps the next one aligned after. Bytes too few, or not at
/// `T`'s alignment, trap: on the PVM a kernel's witness input starts
/// page-aligned, and a caller elsewhere must hand it 8-aligned bytes.
#[inline(always)]
pub fn in_place<'a, T: InPlace>(input: &'a [u8], at: &mut usize) -> &'a T {
    const {
        assert!(
            size_of::<T>().is_multiple_of(8),
            "an in-place argument's size is whole words"
        )
    };
    let start = *at;
    let end = start.wrapping_add(size_of::<T>());
    if end > input.len() || end < start {
        trap();
    }
    // SAFETY: `start ≤ end ≤ len`.
    let pointer = unsafe { input.as_ptr().add(start) };
    if !(pointer as usize).is_multiple_of(align_of::<T>()) {
        trap();
    }
    *at = end;
    // SAFETY: `size_of::<T>()` bytes of `input`, live for `'a`, at `T`'s
    // alignment; every bit pattern is a `T` (`InPlace`'s contract).
    unsafe { &*pointer.cast::<T>() }
}

/// `value`'s bytes appended to `buf`, a word at a time when its size is
/// whole words, one load and one store each at any alignment.
#[inline(always)]
pub fn encode_in_place<T: InPlace>(value: &T, buf: &mut Vec<u8>) {
    let from = (value as *const T).cast::<u8>();
    if size_of::<T>().is_multiple_of(8) {
        buf.reserve(size_of::<T>());
        let len = buf.len();
        // SAFETY: `size_of::<T>()` bytes reserved past `len`, each written
        // before the length takes them in; `value`'s bytes are readable and
        // hold no padding (`InPlace`).
        unsafe {
            let to = buf.as_mut_ptr().add(len);
            for i in 0..size_of::<T>() / 8 {
                store_u64(to.add(8 * i), load_u64(from.add(8 * i)));
            }
            buf.set_len(len + size_of::<T>());
        }
    } else {
        // SAFETY: as above.
        buf.extend_from_slice(unsafe { core::slice::from_raw_parts(from, size_of::<T>()) });
    }
}

/// The `T` whose bytes start `data`, copied: an in-place type's decode by
/// value.
#[inline]
pub fn decode_in_place<T: InPlace>(data: &[u8]) -> Result<(T, usize), DecodeError> {
    if data.len() < size_of::<T>() {
        return Err(DecodeError::UnexpectedEof);
    }
    // SAFETY: `size_of::<T>()` readable bytes; every bit pattern is a `T`.
    Ok((
        unsafe { core::ptr::read_unaligned(data.as_ptr().cast::<T>()) },
        size_of::<T>(),
    ))
}

impl vos_wire::Encode for Digest {
    #[inline(always)]
    fn encode_to(&self, buf: &mut Vec<u8>) {
        encode_in_place(self, buf)
    }
}

impl vos_wire::Decode for Digest {
    #[inline]
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        decode_in_place(data)
    }
}

impl Digest {
    /// The digest of `bytes`, the words as little-endian `u32`s; a word at
    /// or above p is refused only when hashed.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(core::array::from_fn(|i| {
            u32::from_le_bytes([
                bytes[4 * i],
                bytes[4 * i + 1],
                bytes[4 * i + 2],
                bytes[4 * i + 3],
            ])
        }))
    }

    /// Its 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        for (to, word) in bytes.chunks_exact_mut(4).zip(self.0) {
            to.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// `C(self, right)`: one `0x402` call.
    #[inline(always)]
    pub fn hash(&self, right: &Digest) -> Digest {
        let mut block = MaybeUninit::<[u64; 8]>::uninit();
        let block = block.as_mut_ptr().cast::<u64>();
        // SAFETY: the block's eight words, each written before the call
        // reads it; the call writes the result's four.
        unsafe {
            put(block, self.words());
            put(block.add(4), right.words());
            compress(block)
        }
    }

    /// Its four `u64`s.
    #[inline(always)]
    fn words(&self) -> &[u64; 4] {
        // SAFETY: 32 bytes at an 8-alignment, every bit pattern a `u64`.
        unsafe { &*(self as *const Self).cast::<[u64; 4]>() }
    }
}

/// The reference statement of the credential kernels (`light-node.md`
/// §4.4): a fixed secret, known to all, its member at slot 0 of the empty
/// tree, its nullifier in a fixed scope, a fixed binding. A public, valid
/// statement of no member of any space, on which a credential kernel's
/// reference run (`#[attestable(device, reference = path)]`) sizes its
/// device program.
pub mod reference {
    use super::{DEPTH, Digest, Path, Secret};

    /// The secret: word `i` is `0x7e1e_0000 + i`.
    pub const SECRET: Secret = Digest(words(0x7e1e_0000));
    /// The scope: word `i` is `0x5c0e_0000 + i`.
    pub const SCOPE: Digest = Digest(words(0x5c0e_0000));
    /// The binding: word `i` is `0x0b1d_0000 + i`.
    pub const BINDING: Digest = Digest(words(0x0b1d_0000));
    /// Slot 0 of the empty tree: each sibling the empty subtree's root at
    /// its level.
    pub const PATH: Path = {
        let mut siblings = [Digest([0; 8]); DEPTH];
        let mut level = 0;
        while level < DEPTH {
            siblings[level] = Digest(vos_wire::credentials::EMPTY[level]);
            level += 1;
        }
        Path { siblings, slot: 0 }
    };

    const fn words(base: u32) -> [u32; 8] {
        let mut words = [0; 8];
        let mut i = 0;
        while i < 8 {
            words[i] = base + i as u32;
            i += 1;
        }
        words
    }
}

/// Equal by every word, never stopping early.
impl PartialEq for Digest {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        let (ours, theirs) = (self.words(), other.words());
        (0..4).fold(0, |differ, i| differ | (ours[i] ^ theirs[i])) == 0
    }
}

impl Eq for Digest {}

/// A tag's compression, `C(T(tag), value)`.
pub trait TagHash {
    /// `C(T(self), value)`: one `0x402` call.
    fn hash(self, value: &Digest) -> Digest;
}

impl TagHash for Tag {
    #[inline(always)]
    fn hash(self, value: &Digest) -> Digest {
        let mut block = MaybeUninit::<[u64; 8]>::uninit();
        let block = block.as_mut_ptr().cast::<u64>();
        // SAFETY: as `Digest::hash`'s.
        unsafe {
            put(block, &[self.word() as u64, 0, 0, 0]);
            put(block.add(4), value.words());
            compress(block)
        }
    }
}

impl Path {
    /// The root this path gives `leaf`: one call a level in the lane
    /// `[sibling, node, sibling]`, the sibling written on the side the
    /// slot's bit picks and the call reading `node ‖ sibling` from the
    /// lane's middle or `sibling ‖ node` from its start, never a branch,
    /// the parent written over the node.
    #[inline]
    pub fn root(&self, leaf: &Digest) -> Digest {
        let mut lane = MaybeUninit::<[u64; 12]>::uninit();
        let lane = lane.as_mut_ptr().cast::<u64>();
        // SAFETY: the lane's twelve words; the node's four written first,
        // a sibling's before each call reads it, and the call writing the
        // node's four.
        unsafe {
            put(lane.add(4), leaf.words());
            for (level, sibling) in self.siblings.iter().enumerate() {
                let left = 4 - 4 * ((self.slot as usize >> level) & 1);
                put(lane.add(2 * left), sibling.words());
                call(lane.add(left), lane.add(4));
            }
            let mut root = MaybeUninit::<Digest>::uninit();
            put(
                root.as_mut_ptr().cast::<u64>(),
                &*lane.add(4).cast::<[u64; 4]>(),
            );
            root.assume_init()
        }
    }
}

/// Four words written at `to`.
///
/// # Safety
///
/// `to` must point at four writable `u64`s.
#[inline(always)]
unsafe fn put(to: *mut u64, words: &[u64; 4]) {
    for (i, &word) in words.iter().enumerate() {
        // SAFETY: the caller's contract.
        unsafe { to.add(i).write(word) };
    }
}

/// The compression of the block at `block`, its result returned.
///
/// # Safety
///
/// `block` must point at eight readable `u64`s, 8-aligned.
#[inline(always)]
unsafe fn compress(block: *const u64) -> Digest {
    let mut out = MaybeUninit::<Digest>::uninit();
    // SAFETY: the caller's contract; the call writes the result's four
    // words.
    unsafe {
        call(block, out.as_mut_ptr().cast::<u64>());
        out.assume_init()
    }
}

/// The `0x402` call on the sixteen words at `input`, its eight out at
/// `output`; a host that does not serve it traps the kernel (no software
/// permutation is linked on the guest). `input` may overlap `output`: the
/// call reads all of its input before it writes.
///
/// # Safety
///
/// `input` must point at 64 readable bytes and `output` at 32 writable
/// ones, each 4-aligned.
#[inline(always)]
pub unsafe fn call(input: *const u64, output: *mut u64) {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: the caller's contract; the call touches nothing else.
    unsafe {
        let answer: u64;
        core::arch::asm!(
            "li t0, {id}",
            "csrw 0x801, zero",
            "ecall",
            id = const vos_pvm_precompiles::ECALL_POSEIDON2,
            out("t0") _,
            inlateout("a0") input as u64 => answer,
            in("a1") output as u64,
            in("a2") 0u64,
            in("a3") 0u64,
            options(nostack),
        );
        if answer == u64::MAX - 1 {
            core::arch::asm!("unimp", options(noreturn));
        }
    }
    #[cfg(not(target_arch = "riscv64"))]
    // SAFETY: the caller's contract.
    unsafe {
        let words: [u32; 16] = core::ptr::read_unaligned(input.cast());
        let out = vos_pvm_precompiles::poseidon2_compress_block(&words);
        core::ptr::write_unaligned(output.cast::<[u32; 8]>(), out);
    }
}

/// The eight bytes at `at`, any alignment, little-endian: on the guest in
/// one load, which the PVM serves at any address.
///
/// # Safety
///
/// `at` must point at eight readable bytes.
#[inline(always)]
pub unsafe fn load_u64(at: *const u8) -> u64 {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: the caller's contract; the load touches nothing else.
    unsafe {
        let word: u64;
        core::arch::asm!(
            "ld {word}, 0({at})",
            word = out(reg) word,
            at = in(reg) at,
            options(nostack, readonly, preserves_flags),
        );
        word
    }
    #[cfg(not(target_arch = "riscv64"))]
    // SAFETY: the caller's contract.
    unsafe {
        u64::from_le(core::ptr::read_unaligned(at.cast()))
    }
}

/// Stores `word` at `at`, any alignment, little-endian: on the guest in one
/// store.
///
/// # Safety
///
/// `at` must point at eight writable bytes.
#[inline(always)]
pub unsafe fn store_u64(at: *mut u8, word: u64) {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: the caller's contract; the store touches nothing else.
    unsafe {
        core::arch::asm!(
            "sd {word}, 0({at})",
            word = in(reg) word,
            at = in(reg) at,
            options(nostack, preserves_flags),
        );
    }
    #[cfg(not(target_arch = "riscv64"))]
    // SAFETY: the caller's contract.
    unsafe {
        core::ptr::write_unaligned(at.cast::<[u8; 8]>(), word.to_le_bytes())
    };
}

/// A trap, on the guest; a panic elsewhere.
#[cold]
#[inline]
fn trap() -> ! {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: `unimp` lowers to a PVM trap, which fails the run.
    unsafe {
        core::arch::asm!("unimp", options(noreturn))
    }
    #[cfg(not(target_arch = "riscv64"))]
    panic!("an in-place argument past its bytes or its alignment")
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use vos_wire::credentials::{self, EMPTY, Words};
    use vos_wire::{Decode, Encode};

    fn digest(words: &Words) -> Digest {
        Digest(*words)
    }

    /// The tags' and the digests' compressions, and a path's root, are
    /// `vos_wire::credentials`' for every slot's shape.
    #[test]
    fn hashes_and_roots_are_the_trees() {
        let secret: Words = core::array::from_fn(|i| 0x0123_4567 + 7_919 * i as u32);
        let member = credentials::compress(&Tag::Member.block(), &secret);
        assert_eq!(Tag::Member.hash(&digest(&secret)), digest(&member));
        let scope: Words = core::array::from_fn(|i| 0x5c5c_0000 + i as u32);
        assert_eq!(
            digest(&secret).hash(&digest(&scope)),
            digest(&credentials::compress(&secret, &scope))
        );
        let mut siblings: [Words; DEPTH] = core::array::from_fn(|level| EMPTY[level]);
        siblings[5] = [9; 8];
        let leaf = credentials::leaf(&member);
        for slot in [0, 1, 0x1234_5678, u32::MAX] {
            let path = Path {
                siblings: core::array::from_fn(|level| digest(&siblings[level])),
                slot: u64::from(slot) | 0xdead << 32,
            };
            assert_eq!(
                path.root(&digest(&leaf)),
                digest(&credentials::root_of(&leaf, slot, &siblings))
            );
        }
    }

    /// An in-place type's encoding is its bytes; read in place where they
    /// are aligned, refused where they are not or too few.
    #[test]
    fn in_place_values_are_their_bytes() {
        let path = Path {
            siblings: core::array::from_fn(|level| Digest([level as u32; 8])),
            slot: 7,
        };
        let bytes = path.encode();
        assert_eq!(bytes.len(), 1032);
        assert_eq!(&bytes[1024..], &7u64.to_le_bytes());
        assert_eq!(Path::decode(&bytes).unwrap().0.siblings[3], Digest([3; 8]));
        let words: Vec<u64> = bytes
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        // SAFETY: the words' bytes, 8-aligned.
        let aligned =
            unsafe { core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), bytes.len()) };
        let mut at = 0;
        assert_eq!(in_place::<Path>(aligned, &mut at).slot, 7);
        assert_eq!(at, 1032);
        let mut at = 32;
        assert_eq!(*in_place::<Digest>(aligned, &mut at), Digest([1; 8]));
        let short = std::panic::catch_unwind(|| in_place::<Digest>(&aligned[..31], &mut 0));
        assert!(short.is_err());
        let skewed = std::panic::catch_unwind(|| in_place::<Digest>(&aligned[4..], &mut 0));
        assert!(skewed.is_err());
    }
}
