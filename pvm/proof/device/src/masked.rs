//! The device profile's masked segment (`docs/design/proving.md` §8): a
//! kernel's whole run proved masked over the device's chip set
//! (`vos_pvm_proof::device`), verified against its program.
//!
//! - **The program** ([`DeviceProgram`], [`install`]) is computed from the
//!   kernel alone, never taken from a proof: its chips (what its code can
//!   reach), a log size each, its layout, and the preprocessed root those
//!   commit (its code, its data table, its regions and permissions, its
//!   entry registers). The transcript mixes its chips right after the
//!   header ([`DeviceProgram::header`]), beside the format, the log sizes
//!   and, as the first commitment, the root.
//! - **The proof** ([`DeviceProof`]) states the io-hash, φ9..12 at the
//!   halt, and nothing else: the public values after the main tree's root
//!   are its 32 bytes, DeviceIoChip's claimed sum the one the verifier
//!   recomputes from them, every other blinded.
//! - **The trace is the program's shape** (a witness-independent
//!   trace): every chip at its program's log size, the prover refusing a run
//!   that needs more ([`crate::Error::Fit`]), so a proof's shape never
//!   depends on its witness. A kernel whose step count does not depend on
//!   its witness (branch-free) proves every witness under one program.
//! - **Its verifier** ([`verify_device`]) returns the masked verifier's own
//!   refusals (`vos_pvm_final_verifier::Error`), which the forgery gates
//!   tell apart; a program's verifier ([`crate::Verifier`]) refuses with a
//!   [`crate::Refusal`].

use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use vos_pvm_final_verifier::masking::MaskedProof;
use vos_pvm_proof::chips::CpuColumns;
use vos_pvm_proof::device::{DeviceLayout, DeviceShape};

mod prove;
mod verify;

#[cfg(feature = "seeded-masks")]
pub use prove::prove_device_forced;
pub use prove::{DeviceProver, device_shape, device_trace, install, prove_device};
pub use verify::{device_floors, device_format, device_reveals, verify_device, verify_device_in};

/// The word the transcript mixes before a device program's chips.
pub const DEVICE_PROGRAM_TAG: u64 = u64::from_le_bytes(*b"VOS/DEV1");

/// The word the transcript mixes after a device program's chips and CPU:
/// its memory ledger, a row a word.
pub const DEVICE_WORD_MEMORY_TAG: u64 = u64::from_le_bytes(*b"VOS/WMEM");

/// A device program, as its verifier pins it: its chips, their log sizes,
/// its CPU's columns, its layout and the preprocessed root they commit
/// under its format.
#[derive(Clone, Debug)]
pub struct DeviceProgram<H: MerkleHasherLifted> {
    /// The chips, a device mask (`vos_pvm_proof::device::device_chip`).
    pub active: u32,
    /// The CPU's columns, the code's (`CpuColumns::of_code`).
    pub cpu: CpuColumns,
    /// Each chip's log size, in `DEVICE_ORDER`.
    pub log_sizes: Vec<u32>,
    pub layout: DeviceLayout,
    /// The preprocessed root.
    pub circuit: H::Hash,
}

impl<H: MerkleHasherLifted> DeviceProgram<H> {
    /// The words the transcript mixes right after the header: the tag, the
    /// chips, for a CPU that cuts any its columns' words, and
    /// [`DEVICE_WORD_MEMORY_TAG`]. The header holds
    /// the format and the log sizes; the first commitment, the preprocessed
    /// root.
    pub fn header(&self) -> Vec<u64> {
        let mut words = vec![DEVICE_PROGRAM_TAG, u64::from(self.active)];
        if self.cpu != CpuColumns::ALL {
            words.extend(self.cpu.words());
        }
        words.push(DEVICE_WORD_MEMORY_TAG);
        words
    }

    /// Its components: the chips and the CPU's columns.
    pub fn shape(&self) -> DeviceShape {
        DeviceShape {
            chips: self.active,
            cpu: self.cpu,
        }
    }
}

/// A device proof: the io-hash it states and the masked proof.
#[derive(Clone, Debug)]
pub struct DeviceProof<H: MerkleHasherLifted> {
    /// φ9..12 at the halt, 32 LE bytes.
    pub io: [u8; 32],
    pub proof: MaskedProof<H>,
}
