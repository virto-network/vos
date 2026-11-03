//! A device kernel's end (`#[attestable(device)]`, `proving.md` §8): its
//! statement's parts written once, in place, and their io-hash through the
//! Poseidon2 call alone.

use alloc::vec::Vec;

use crate::runtime::Output;

/// A device kernel's end (`#[attestable(device)]`): its statement's parts
/// written once, in place, as the io-hash's encoding `E` (each part a
/// compact length then its bytes, then a root count of 0: a device kernel
/// reads none), which is both what the host reads at the halt
/// ([`vos_wire::result::KernelReturn::from_device_return`]) and what the io-hash absorbs
/// where it lies, through the Poseidon2 call alone
/// ([`vos_pvm_precompiles::device_io::padded_device_io_words`]): no BLAKE2b, no
/// re-encoding, no copy.
///
/// The bytes start with room for each part's compact length, four bytes
/// before the public arguments and four before the output; [`Self::end`]
/// writes each length into its room and closes the gap the output's leaves.
///
/// Its methods are `#[inline(always)]`, so its code is each device
/// kernel's own, never one function the crate's kernels and references
/// call (a call per part and an outlined end cost a kernel hundreds of
/// steps), and the SDK's own code, which node kernels reach, is laid out
/// as without it.
pub struct DeviceReturn {
    bytes: Vec<u8>,
    /// Where the output's room starts, once [`Self::output`] began it.
    output_at: Option<usize>,
}

/// The room a part's compact length takes at most: four bytes, a length
/// below 2^30.
const ROOM: usize = 4;

impl Default for DeviceReturn {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceReturn {
    /// An end with room for parts of `DEVICE_RETURN` bytes before it grows.
    #[inline(always)]
    pub fn new() -> Self {
        const DEVICE_RETURN: usize = 256;
        let mut bytes = Vec::with_capacity(DEVICE_RETURN);
        bytes.extend_from_slice(&[0; ROOM]);
        Self {
            bytes,
            output_at: None,
        }
    }

    /// Where the public arguments' encodings go, in order.
    #[inline(always)]
    pub fn public_args(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    /// Where the output's encoding goes, after the public arguments: once;
    /// a second call traps.
    #[inline(always)]
    pub fn output(&mut self) -> &mut Vec<u8> {
        if self.output_at.is_some() {
            trap();
        }
        self.output_at = Some(self.bytes.len());
        self.bytes.extend_from_slice(&[0; ROOM]);
        &mut self.bytes
    }

    /// The parts' encoding `E`, leaked for the host, and its io-hash `H_io`
    /// written at `io_hash`. A part of 2^30 bytes or more, or an `E` of
    /// 2^24 or more, traps, after the method ran, as does an end whose
    /// output [`Self::output`] never began.
    ///
    /// # Safety
    ///
    /// `io_hash` must point at 32 writable bytes.
    #[inline(always)]
    pub unsafe fn end(self, io_hash: *mut [u8; 32]) -> Output {
        let Self {
            mut bytes,
            output_at,
        } = self;
        let output_at = output_at.unwrap_or_else(|| trap());
        let length = |len: usize| {
            u32::try_from(len)
                .ok()
                .and_then(vos_pvm_precompiles::device_io::compact_below_2_30)
                .unwrap_or_else(|| trap())
        };
        let (public, public_len) = length(output_at - ROOM);
        let start = ROOM - public_len;
        bytes[start..ROOM].copy_from_slice(&public[..public_len]);
        let (output, output_len) = length(bytes.len() - output_at - ROOM);
        bytes[output_at..output_at + output_len].copy_from_slice(&output[..output_len]);
        if output_len < ROOM {
            bytes.copy_within(output_at + ROOM.., output_at + output_len);
            bytes.truncate(bytes.len() - (ROOM - output_len));
        }
        // No root: a device kernel reads none.
        bytes.push(0);
        // Zeros to a whole block past `E`, so the io-hash reads every block
        // where it lies; the host reads `E` alone.
        let len = bytes.len() - start;
        bytes.resize(start + len.div_ceil(BLOCK) * BLOCK, 0);
        // The resize may move the bytes: every address below is taken after it.
        let words = vos_pvm_precompiles::device_io::padded_device_io_words::<
            vos_pvm_precompiles::Poseidon2Call,
        >(&bytes[start..], len)
        .unwrap_or_else(|| trap());
        let at = io_hash.cast::<u8>();
        for (i, &word) in words.iter().enumerate() {
            // SAFETY: the caller's contract: 32 writable bytes at `io_hash`.
            unsafe { store_u32(at.add(4 * i), word) };
        }
        let output = Output {
            address: bytes[start..].as_ptr() as u64,
            len: len as u64,
        };
        core::mem::forget(bytes);
        output
    }
}

/// The io-hash's block: 24 bytes.
const BLOCK: usize = 24;

/// Stores `word` at `at`, any alignment, little-endian: on the guest in one
/// store, which the PVM serves at any address (the target's own unaligned
/// writes go byte by byte).
///
/// # Safety
///
/// `at` must point at four writable bytes.
#[inline(always)]
unsafe fn store_u32(at: *mut u8, word: u32) {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: the caller's contract; the store touches nothing else.
    unsafe {
        core::arch::asm!(
            "sw {word}, 0({at})",
            word = in(reg) word,
            at = in(reg) at,
            options(nostack, preserves_flags),
        );
    }
    #[cfg(not(target_arch = "riscv64"))]
    // SAFETY: the caller's contract.
    unsafe {
        core::ptr::write_unaligned(at.cast::<[u8; 4]>(), word.to_le_bytes())
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
    panic!("a device return past its bounds")
}
