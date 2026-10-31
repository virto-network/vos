//! A device kernel's io-hash `H_io` (`proving.md` §8): what a device proof
//! binds of its statement, over the Poseidon2-M31 compression `C` alone, so
//! a device kernel's shape holds no BLAKE2b.
//!
//! - **The bytes** `E` are exactly what [`crate::compute_io_hash`] hashes
//!   after its domain: `compact(|a|) ‖ a ‖ compact(|o|) ‖ o ‖ compact(|R|)`
//!   and each root read's kind byte, space, window and root. A device
//!   kernel returns `E` itself ([`device_return_parts`] reads it back): it
//!   reads no root, so its `E` ends with the count 0.
//! - **The words:** `E` zero-padded to blocks of 24 bytes, each block eight
//!   words of three little-endian bytes, every word below 2^24.
//! - **The chain:** from `T(io)` = `[DEVICE_IO_TAG, 0, …, 0]`, one `C` a
//!   block, `h_i = C(h_{i−1}, block_i)`; then the length block, `H_io =
//!   C(h_n, [ℓ, 0, …, 0])` with `ℓ = |E|`. Its eight words as 32
//!   little-endian bytes are the io-hash.
//! - **The bound:** `ℓ < 2^24` ([`MAX_DEVICE_IO`]); a longer `E` has no
//!   io-hash, never a wrapped or truncated one.
//!
//! [`DeviceIoHasher`] streams `E` in parts, so a kernel absorbs its return
//! where it lies and ingress feeds a request's words, with one
//! implementation; the compression is a [`Lane`], the precompile's call in a
//! kernel ([`Poseidon2Call`]) or the permutation in software
//! ([`Poseidon2Software`]).
//!
//! The construction extends from `H_io` alone (a chain state is an output
//! of `C`); that is harmless here, where every verifier recomputes `H_io`
//! from parts it holds whole and nothing secret is prefixed. `H_io` is no
//! keyed commitment and must never be used as one.

/// `t_io`, the tag word of the name `io`: `u32_le(BLAKE2b-256("vos/p2/io")
/// [0..4]) & 0x7fff_ffff`, reduced mod p, pinned (`vos_wire::credentials::
/// Tag::Io` is the same word).
pub const DEVICE_IO_TAG: u32 = 0x7038_de5c;

/// The bytes `E` may hold: below 2^24. A kernel's return lies in its heap,
/// 512 KiB at most, and a work result holds 4 MiB, so no return a
/// kernel makes reaches it; it keeps the length block's word below 2^24
/// as every data word is.
pub const MAX_DEVICE_IO: u64 = 1 << 24;

/// A block's bytes: eight words of three.
const BLOCK: usize = 24;

/// The compression `C` over a lane of sixteen words: `C(lane[..8],
/// lane[8..])` written over `lane[..8]`.
pub trait Lane {
    fn compress(lane: &mut [u32; 16]);
}

/// The compression as the permutation in software: a venue's, a test's.
pub struct Poseidon2Software;

impl Lane for Poseidon2Software {
    fn compress(lane: &mut [u32; 16]) {
        let output = crate::poseidon2_compress_block(lane);
        lane[..8].copy_from_slice(&output);
    }
}

/// The compression as a kernel makes it: on the guest, the `0x402` call
/// issued directly, reading the lane and writing its first half in place,
/// and a host that does not serve it traps the kernel (no software
/// permutation is linked); elsewhere, [`Poseidon2Software`].
pub struct Poseidon2Call;

impl Lane for Poseidon2Call {
    #[inline(always)]
    fn compress(lane: &mut [u32; 16]) {
        #[cfg(target_arch = "riscv64")]
        {
            let lane = lane.as_mut_ptr() as u64;
            let answer: u64;
            // SAFETY: the call reads the lane's 64 bytes, 4-aligned, before
            // it writes its first 32, and touches nothing else.
            unsafe {
                core::arch::asm!(
                    "li t0, {id}",
                    "csrw 0x801, zero",
                    "ecall",
                    id = const crate::ECALL_POSEIDON2,
                    out("t0") _,
                    inlateout("a0") lane => answer,
                    in("a1") lane,
                    in("a2") 0u64,
                    in("a3") 0u64,
                    options(nostack),
                );
                if answer == u64::MAX - 1 {
                    core::arch::asm!("unimp", options(noreturn));
                }
            }
        }
        #[cfg(not(target_arch = "riscv64"))]
        Poseidon2Software::compress(lane);
    }
}

/// `H_io` over `E` given in parts, in order.
pub struct DeviceIoHasher<L: Lane> {
    /// The chain's state, then the block being absorbed.
    lane: [u32; 16],
    /// A block's bytes not absorbed yet.
    buf: [u8; BLOCK],
    buffered: usize,
    /// `E`'s bytes so far.
    len: u64,
    lane_kind: core::marker::PhantomData<L>,
}

impl<L: Lane> Default for DeviceIoHasher<L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<L: Lane> DeviceIoHasher<L> {
    /// The chain at `T(io)`.
    pub const fn new() -> Self {
        let mut lane = [0u32; 16];
        lane[0] = DEVICE_IO_TAG;
        Self {
            lane,
            buf: [0; BLOCK],
            buffered: 0,
            len: 0,
            lane_kind: core::marker::PhantomData,
        }
    }

    /// `E`'s next bytes.
    pub fn update(&mut self, mut bytes: &[u8]) {
        self.len = self.len.saturating_add(bytes.len() as u64);
        if self.buffered > 0 {
            let take = (BLOCK - self.buffered).min(bytes.len());
            self.buf[self.buffered..self.buffered + take].copy_from_slice(&bytes[..take]);
            self.buffered += take;
            bytes = &bytes[take..];
            if self.buffered < BLOCK {
                return;
            }
            let block = self.buf;
            self.absorb(&block);
            self.buffered = 0;
        }
        let mut blocks = bytes.chunks_exact(BLOCK);
        for block in &mut blocks {
            self.absorb(block);
        }
        let rest = blocks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// `H_io`, or `None` for an `E` of [`MAX_DEVICE_IO`] bytes or more.
    pub fn finalize(mut self) -> Option<[u8; 32]> {
        if self.len >= MAX_DEVICE_IO {
            return None;
        }
        if self.buffered > 0 {
            self.buf[self.buffered..].fill(0);
            let block = self.buf;
            self.absorb(&block);
        }
        self.lane[8] = self.len as u32;
        self.lane[9..].fill(0);
        L::compress(&mut self.lane);
        let mut hash = [0u8; 32];
        for (bytes, word) in hash.chunks_exact_mut(4).zip(&self.lane[..8]) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        Some(hash)
    }

    /// One block of 24 bytes into the chain.
    #[inline(always)]
    fn absorb(&mut self, block: &[u8]) {
        pack(&mut self.lane, block);
        L::compress(&mut self.lane);
    }
}

/// `H_io` of `E`, the first `len` bytes of `padded`, as its eight words:
/// `padded` holds `E` and then zeros up to the next multiple of 24 bytes,
/// so every block is read where it lies, with no copy. `None` for an `E`
/// of [`MAX_DEVICE_IO`] bytes or more, or a `padded` of another length.
/// A device kernel's end hashes its return so; [`DeviceIoHasher`] gives
/// the same words for the same `E`.
#[inline(always)]
pub fn padded_device_io_words<L: Lane>(padded: &[u8], len: usize) -> Option<[u32; 8]> {
    if len as u64 >= MAX_DEVICE_IO || padded.len() != len.div_ceil(BLOCK) * BLOCK {
        return None;
    }
    let mut lane = [0u32; 16];
    lane[0] = DEVICE_IO_TAG;
    for block in padded.chunks_exact(BLOCK) {
        pack(&mut lane, block);
        L::compress(&mut lane);
    }
    lane[8] = len as u32;
    lane[9..].fill(0);
    L::compress(&mut lane);
    let mut words = [0u32; 8];
    words.copy_from_slice(&lane[..8]);
    Some(words)
}

/// A block of 24 bytes as the lane's second half: eight words of three
/// little-endian bytes. On the guest, one four-byte load a word, which the
/// PVM serves at any address (the target's own unaligned reads go byte by
/// byte).
#[inline(always)]
fn pack(lane: &mut [u32; 16], block: &[u8]) {
    #[cfg(target_arch = "riscv64")]
    {
        assert!(block.len() == BLOCK);
        let at = block.as_ptr();
        // SAFETY: each load reads four of the block's 24 bytes.
        unsafe {
            for (j, word) in lane[8..15].iter_mut().enumerate() {
                *word = load_u32(at.add(3 * j)) & 0x00ff_ffff;
            }
            lane[15] = load_u32(at.add(20)) >> 8;
        }
    }
    #[cfg(not(target_arch = "riscv64"))]
    for (word, bytes) in lane[8..].iter_mut().zip(block.chunks_exact(3)) {
        *word = u32::from(bytes[0]) | u32::from(bytes[1]) << 8 | u32::from(bytes[2]) << 16;
    }
}

/// The four bytes at `at`, any alignment, little-endian, in one load.
///
/// # Safety
///
/// `at` must point at four readable bytes.
#[cfg(target_arch = "riscv64")]
#[inline(always)]
unsafe fn load_u32(at: *const u8) -> u32 {
    let word: u64;
    // SAFETY: the caller's contract; the load touches nothing else.
    unsafe {
        core::arch::asm!(
            "lwu {word}, 0({at})",
            word = out(reg) word,
            at = in(reg) at,
            options(nostack, readonly, preserves_flags),
        );
    }
    word as u32
}

/// A device kernel's io-hash over its statement's parts, as
/// [`crate::compute_io_hash`] encodes them; `None` when their encoding
/// holds [`MAX_DEVICE_IO`] bytes or more.
pub fn compute_device_io_hash(
    public_args: &[u8],
    output: &[u8],
    roots: &[crate::RootRead],
) -> Option<[u8; 32]> {
    let mut hasher = DeviceIoHasher::<Poseidon2Software>::new();
    for bytes in [public_args, output] {
        hasher.update(crate::io::compact(bytes.len() as u64).as_slice());
        hasher.update(bytes);
    }
    hasher.update(crate::io::compact(roots.len() as u64).as_slice());
    for root in roots {
        hasher.update(&[root.kind as u8]);
        hasher.update(&root.space);
        hasher.update(&root.window.to_le_bytes());
        hasher.update(&root.root);
    }
    hasher.finalize()
}

/// A device kernel's return `E` read back as its public arguments and its
/// output: each a canonical compact length then its bytes, then a root
/// count of 0, and nothing after; `None` for any other bytes.
pub fn device_return_parts(returned: &[u8]) -> Option<(&[u8], &[u8])> {
    let (public_args, rest) = framed(returned)?;
    let (output, rest) = framed(rest)?;
    (rest == [0]).then_some((public_args, output))
}

/// A compact length's bytes then as many bytes, and what follows.
fn framed(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = *bytes.first()?;
    let (len, used) = match first & 3 {
        0 => (u64::from(first >> 2), 1),
        1 => (
            u64::from(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?) >> 2),
            2,
        ),
        2 => (
            u64::from(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) >> 2),
            4,
        ),
        _ => return None,
    };
    if crate::io::compact(len).as_slice() != &bytes[..used] {
        return None;
    }
    let end = used.checked_add(usize::try_from(len).ok()?)?;
    Some((bytes.get(used..end)?, &bytes[end..]))
}

/// A length's SCALE compact encoding below 2^30, the most a device return's
/// part holds, as its bytes and their count: one, two or four.
pub fn compact_below_2_30(len: u32) -> Option<([u8; 4], usize)> {
    let encoded = crate::io::compact(u64::from(len));
    let bytes = encoded.as_slice();
    (bytes.len() <= 4).then(|| {
        let mut out = [0u8; 4];
        out[..bytes.len()].copy_from_slice(bytes);
        (out, bytes.len())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// `E` packed and chained by hand, from the definition.
    fn by_hand(encoded: &[u8]) -> [u8; 32] {
        let mut state = [0u32; 8];
        state[0] = DEVICE_IO_TAG;
        let mut padded = encoded.to_vec();
        padded.resize(encoded.len().div_ceil(24) * 24, 0);
        for block in padded.chunks_exact(24) {
            let words: [u32; 8] = core::array::from_fn(|j| {
                u32::from(block[3 * j])
                    | u32::from(block[3 * j + 1]) << 8
                    | u32::from(block[3 * j + 2]) << 16
            });
            state = crate::poseidon2_compress(&state, &words);
        }
        let mut length = [0u32; 8];
        length[0] = encoded.len() as u32;
        let digest = crate::poseidon2_compress(&state, &length);
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes.chunks_exact_mut(4).zip(digest) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// The tag is the name's, as the credential tags are: `vos/p2/io`'s
    /// BLAKE2b-256, its first four bytes, the top bit cleared.
    #[test]
    fn the_tag_is_pinned() {
        use blake2::digest::{Digest, consts::U32};
        let hash: [u8; 32] = blake2::Blake2b::<U32>::digest(b"vos/p2/io").into();
        let word = u32::from_le_bytes(hash[..4].try_into().unwrap()) & crate::poseidon2::P;
        assert_eq!(
            DEVICE_IO_TAG,
            if word == crate::poseidon2::P { 0 } else { word }
        );
        assert_ne!(DEVICE_IO_TAG, 0);
    }

    /// The hash is the definition's over `compute_io_hash`'s bytes, however
    /// they are split into parts.
    #[test]
    fn the_hash_is_the_chain_over_the_encoding() {
        let root = crate::RootRead {
            kind: crate::RootKind::Space,
            space: [0xa1; 32],
            window: 0x0102_0304_0506_0708,
            root: [0xb2; 32],
        };
        let public: Vec<u8> = (0..129u8).collect();
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&[0x05, 0x02]);
        encoded.extend_from_slice(&public);
        encoded.extend_from_slice(&[3 << 2, 7, 8, 9]);
        encoded.extend_from_slice(&[1 << 2, 0]);
        encoded.extend_from_slice(&root.space);
        encoded.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        encoded.extend_from_slice(&root.root);
        let expected = by_hand(&encoded);
        assert_eq!(
            compute_device_io_hash(&public, &[7, 8, 9], &[root]),
            Some(expected)
        );
        for split in [1, 23, 24, 25, 47, 48, 100] {
            let mut hasher = DeviceIoHasher::<Poseidon2Call>::new();
            for part in encoded.chunks(split) {
                hasher.update(part);
            }
            assert_eq!(hasher.finalize(), Some(expected), "{split}");
        }
        // Auth's statement: 129 public bytes, no output, no root: 133 bytes,
        // six blocks and the length's.
        let auth = compute_device_io_hash(&public, &[], &[]).unwrap();
        let mut bytes = alloc::vec![0x05, 0x02];
        bytes.extend_from_slice(&public);
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(bytes.len(), 133);
        assert_eq!(auth, by_hand(&bytes));
    }

    /// Every word is below p, so the hash's bytes are canonical; the hash
    /// tells its parts, where one ends, and trailing zeros apart, and is not
    /// the BLAKE2b io-hash.
    #[test]
    fn the_hash_tells_its_inputs_apart() {
        let hashes = [
            compute_device_io_hash(&[], &[], &[]),
            compute_device_io_hash(&[1], &[], &[]),
            compute_device_io_hash(&[], &[1], &[]),
            compute_device_io_hash(&[1, 2], &[], &[]),
            compute_device_io_hash(&[1], &[2], &[]),
            compute_device_io_hash(&[0; 21], &[], &[]),
            compute_device_io_hash(&[0; 22], &[], &[]),
        ];
        for (index, hash) in hashes.iter().enumerate() {
            let hash = hash.unwrap();
            assert!(!hashes[..index].contains(&Some(hash)), "{index}");
            for word in hash.chunks_exact(4) {
                assert!(u32::from_le_bytes(word.try_into().unwrap()) < crate::poseidon2::P);
            }
        }
        assert_ne!(hashes[0], Some(crate::compute_io_hash(&[], &[], &[])));
        // Equal lengths, one block apart: the chain differs.
        let mut hasher = DeviceIoHasher::<Poseidon2Software>::new();
        hasher.update(&[0; 24]);
        let zeros = hasher.finalize();
        let mut hasher = DeviceIoHasher::<Poseidon2Software>::new();
        hasher.update(&[0; 23]);
        hasher.update(&[1]);
        assert_ne!(zeros, hasher.finalize());
    }

    /// The padded hash is the chain's for every length across three blocks,
    /// its words the hash's bytes; a padding of another length, or an
    /// oversize encoding, has none.
    #[test]
    fn the_padded_hash_is_the_chains() {
        for len in 0..=73usize {
            let encoded: Vec<u8> = (0..len as u8).map(|byte| byte.wrapping_mul(37)).collect();
            let mut padded = encoded.clone();
            padded.resize(len.div_ceil(24) * 24, 0);
            let words = padded_device_io_words::<Poseidon2Call>(&padded, len).unwrap();
            let mut bytes = [0u8; 32];
            for (chunk, word) in bytes.chunks_exact_mut(4).zip(words) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
            assert_eq!(bytes, by_hand(&encoded), "{len}");
            padded.push(0);
            assert_eq!(padded_device_io_words::<Poseidon2Call>(&padded, len), None);
        }
        let oversize = MAX_DEVICE_IO as usize;
        assert_eq!(
            padded_device_io_words::<Poseidon2Software>(&alloc::vec![0; oversize + 8], oversize),
            None
        );
    }

    /// An encoding of 2^24 bytes or more has no hash; one byte less has.
    #[test]
    fn an_oversize_encoding_is_refused() {
        let mut hasher = DeviceIoHasher::<Poseidon2Software>::new();
        hasher.update(&alloc::vec![0; MAX_DEVICE_IO as usize - 1]);
        assert!(hasher.finalize().is_some());
        let mut hasher = DeviceIoHasher::<Poseidon2Software>::new();
        hasher.update(&alloc::vec![0; MAX_DEVICE_IO as usize - 1]);
        hasher.update(&[0]);
        assert_eq!(hasher.finalize(), None);
        let mut hasher = DeviceIoHasher::<Poseidon2Software>::new();
        hasher.len = u64::MAX - 1;
        hasher.update(&[0; 4]);
        assert_eq!(hasher.finalize(), None);
    }

    /// A device return reads back as the parts it frames, and only bytes
    /// framed so, canonically, with no root, read at all.
    #[test]
    fn a_device_return_reads_back_as_its_parts() {
        let public: Vec<u8> = (0..129u8).collect();
        let mut returned = alloc::vec![0x05, 0x02];
        returned.extend_from_slice(&public);
        returned.extend_from_slice(&[2 << 2, 7, 8, 0]);
        assert_eq!(
            device_return_parts(&returned),
            Some((&public[..], &[7u8, 8][..]))
        );
        assert_eq!(device_return_parts(&[0, 0, 0]), Some((&[][..], &[][..])));
        for refused in [
            &[0, 0][..],
            &[0, 0, 0, 0],
            &[0, 0, 4],
            &[0x01, 0x00, 0, 0],
            &[4, 0],
            &[3, 0, 0, 0, 0, 0, 0],
        ] {
            assert_eq!(device_return_parts(refused), None, "{refused:?}");
        }
    }

    #[test]
    fn short_lengths_encode_as_scale_compacts() {
        assert_eq!(compact_below_2_30(0), Some(([0, 0, 0, 0], 1)));
        assert_eq!(compact_below_2_30(129), Some(([0x05, 0x02, 0, 0], 2)));
        assert_eq!(compact_below_2_30(16_384), Some(([2, 0, 1, 0], 4)));
        assert_eq!(compact_below_2_30(1 << 30), None);
    }
}
