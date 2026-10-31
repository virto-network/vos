//! A device kernel's end (`#[attestable(device)]`, `proving.md` §8): its
//! statement's parts written once, in place, and their io-hash through the
//! Poseidon2 call alone.

use alloc::vec::Vec;

use crate::runtime::Output;

/// A device kernel's end (`#[attestable(device)]`): its statement's parts
/// written once, in place, as the io-hash's encoding `E` (each part a
/// compact length then its bytes, then a root count of 0: a device kernel
/// reads none), which is both what the host reads at the halt
/// ([`vos_wire::result::KernelReturn::from_device_return`]) and what the io-hash absorbs,
/// through the Poseidon2 call alone
/// ([`vos_pvm_precompiles::DeviceIoHasher`]): no BLAKE2b, no re-encoding.
///
/// The bytes start with room for each part's compact length, four bytes
/// before the public arguments and four before the output; [`Self::end`]
/// writes each length into its room and closes the gap the output's leaves.
pub struct DeviceReturn {
    bytes: Vec<u8>,
    /// Where the output's room starts, once [`Self::output`] began it.
    output_at: usize,
}

/// The room a part's compact length takes at most: four bytes, a length
/// below 2^30.
const ROOM: usize = 4;

impl Default for DeviceReturn {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceReturn {
    /// An end with room for parts of `DEVICE_RETURN` bytes before it grows.
    pub fn new() -> Self {
        const DEVICE_RETURN: usize = 256;
        let mut bytes = Vec::with_capacity(DEVICE_RETURN);
        bytes.extend_from_slice(&[0; ROOM]);
        Self {
            bytes,
            output_at: 0,
        }
    }

    /// Where the public arguments' encodings go, in order.
    pub fn public_args(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    /// Where the output's encoding goes, after the public arguments.
    pub fn output(&mut self) -> &mut Vec<u8> {
        self.output_at = self.bytes.len();
        self.bytes.extend_from_slice(&[0; ROOM]);
        &mut self.bytes
    }

    /// The parts' encoding `E`, leaked for the host, and its io-hash `H_io`
    /// written at `io_hash`. A part of 2^30 bytes or more, or an `E` of
    /// 2^24 or more, traps, after the method ran.
    ///
    /// # Safety
    ///
    /// `io_hash` must point at 32 writable bytes.
    pub unsafe fn end(self, io_hash: *mut [u8; 32]) -> Output {
        let Self {
            mut bytes,
            output_at,
        } = self;
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
        let encoded = &bytes[start..];
        let mut hasher =
            vos_pvm_precompiles::DeviceIoHasher::<vos_pvm_precompiles::Poseidon2Call>::new();
        hasher.update(encoded);
        let hash = hasher.finalize().unwrap_or_else(|| trap());
        // SAFETY: the caller's contract.
        unsafe { io_hash.write(hash) };
        let output = Output {
            address: encoded.as_ptr() as u64,
            len: encoded.len() as u64,
        };
        core::mem::forget(bytes);
        output
    }
}

/// A trap, on the guest; a panic elsewhere.
#[cold]
fn trap() -> ! {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: `unimp` lowers to a PVM trap, which fails the run.
    unsafe {
        core::arch::asm!("unimp", options(noreturn))
    }
    #[cfg(not(target_arch = "riscv64"))]
    panic!("a device return past its bounds")
}
