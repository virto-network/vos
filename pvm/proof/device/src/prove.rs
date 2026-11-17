//! A device program's prover: its install from the kernel, its runs traced
//! and proved at its shape.

use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use vos_pvm_final_verifier::Error;
use vos_pvm_proof::format::Format;

use super::Hasher;
use super::verify::{Masked, Verifier, encode, masked, program_id, verify};
use vos_pvm_recair::ProveError;
use vos_pvm_recair::masked::{MaskRng, MaskStats, MaskedProof};

use crate::masked::{DeviceProgram, DeviceProof, DeviceProver, device_shape};

/// The most gas a device kernel's run is traced with, 2^18: a step a unit,
/// a Poseidon2 call 3,000, so the most steps the device format's CPU holds,
/// `2^DEVICE_MAX_LOG_SIZE`, and as much again for its Poseidon2 calls
/// (auth's 43 take 129,000 beside its 19,000 or so steps): about 87
/// Poseidon2 calls a run, fewer as its steps grow, which a device kernel's
/// install meets as a run out of gas. A longer run stops out of gas rather
/// than being traced past twice any program's steps, on an executor that
/// bounds no memory.
pub const GAS: u64 = 2 << vos_pvm_proof::device::DEVICE_MAX_LOG_SIZE;

/// The most gas a reference program's run takes, 2^22: it is never
/// proved, and returns a kernel's whole arguments, so it hashes them into
/// its io-hash beside what it computes.
pub const REFERENCE_GAS: u64 = 1 << 22;

/// A device kernel's program under a device format, as its prover and its
/// verifier pin it, and the kernel it proves.
pub struct Program {
    format: Format,
    prover: DeviceProver<Blake2sM31MerkleChannel>,
    kernel: Vec<u8>,
    id: [u8; 32],
    masked: Masked,
}

impl Program {
    /// Kernel `kernel`'s program under the device format `format`, its log
    /// sizes the ones its run on `reference` needs (each at least its
    /// floor), each raised by `headroom`. Refused when the kernel does not
    /// run to its halt on `reference`, or a raised size is past
    /// `DEVICE_MAX_LOG_SIZE`.
    pub fn install(
        format: &Format,
        kernel: &[u8],
        reference: &[u8],
        headroom: u8,
    ) -> Result<Self, ProveError> {
        let mut run = trace(kernel, reference)?;
        let (active, log_sizes) = device_shape(format, kernel, &mut run)?;
        drop(run);
        let log_sizes: Vec<u32> = log_sizes
            .iter()
            .map(|size| size + u32::from(headroom))
            .collect();
        Self::released(format, kernel, active, &log_sizes)
    }

    /// The program of a device kernel's release under the device format
    /// `format`: `kernel` sized on what its reference program `reference`
    /// returns ([`reference_arguments`]), raised by `headroom`.
    pub fn of(
        format: &Format,
        kernel: &[u8],
        reference: &[u8],
        headroom: u8,
    ) -> Result<Self, ProveError> {
        Self::install(format, kernel, &reference_arguments(reference)?, headroom)
    }

    /// The program of `kernel` under the device format `format` at the chips
    /// `active` and the log sizes `log_sizes`, as a release embeds it: its
    /// preprocessed tree committed from the kernel, no run of anything.
    /// Refused when `active` is not the chips the kernel's code reaches, or
    /// a size is under its floor or past `DEVICE_MAX_LOG_SIZE`.
    pub fn released(
        format: &Format,
        kernel: &[u8],
        active: u32,
        log_sizes: &[u32],
    ) -> Result<Self, ProveError> {
        let prover =
            DeviceProver::<Blake2sM31MerkleChannel>::install(format, kernel, active, log_sizes)?;
        let id = program_id(format, prover.program());
        let masked = masked(format, prover.program()).ok_or(ProveError::TraceShape(
            "a program outside the format's shape",
        ))?;
        Ok(Self {
            format: *format,
            prover,
            kernel: kernel.to_vec(),
            id,
            masked,
        })
    }

    /// Whether the kernel's run on `arguments` fits the program's shape: it
    /// runs to its halt, and needs no chip past its log size. A witness
    /// that does not fit fails to prove (`device_fits`, `light-node.md`
    /// §4.4).
    pub fn fits(&self, arguments: &[u8]) -> Result<(), ProveError> {
        let mut run = trace(&self.kernel, arguments)?;
        let (active, needed) = device_shape(&self.format, &self.kernel, &mut run)?;
        let program = self.program();
        if active != program.active
            || needed
                .iter()
                .zip(&program.log_sizes)
                .any(|(needed, size)| needed > size)
        {
            return Err(ProveError::TraceShape("a run past the program's shape"));
        }
        Ok(())
    }

    /// The chips, a device mask.
    pub fn chips(&self) -> u32 {
        self.program().active
    }

    /// The device format it proves and verifies under.
    pub fn format(&self) -> &Format {
        &self.format
    }

    /// `proof`'s bytes under its format, the one encoding
    /// [`Program::verify`] reads; `None` when it cannot be encoded.
    pub fn encode(&self, proof: &MaskedProof<Hasher>) -> Option<Vec<u8>> {
        encode(&self.format, proof)
    }

    /// Its id, which a binding names.
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// The program as the verifier pins it: its chips, log sizes, layout
    /// and root.
    pub fn program(&self) -> &DeviceProgram<Hasher> {
        self.prover.program()
    }

    /// Each chip's log size, in `DEVICE_ORDER`.
    pub fn log_sizes(&self) -> &[u32] {
        &self.program().log_sizes
    }

    /// The kernel it proves.
    pub fn kernel(&self) -> &[u8] {
        &self.kernel
    }

    /// The kernel's run on `arguments`, through its witness input, proved
    /// under the program, its masks from `rng`. A run that does not halt,
    /// or needs more rows than the program's shape, is refused.
    pub fn prove(
        &self,
        arguments: &[u8],
        rng: MaskRng,
    ) -> Result<(DeviceProof<Hasher>, MaskStats), ProveError> {
        let mut run = trace(&self.kernel, arguments)?;
        let proved = self.prover.prove(&mut run, rng);
        drop(run);
        proved
    }

    /// Verifies the proof in `bytes` ([`decode`](super::decode)) of this program's kernel
    /// stating the io-hash `io`.
    pub fn verify(&self, io: &[u8; 32], bytes: &[u8]) -> Result<(), Error> {
        verify(&self.format, self.program(), &self.masked, io, bytes)
    }

    /// What a verifier keeps of it: the program, its masked format and its
    /// id, without the prover's committed tree.
    pub fn verifier(&self) -> Verifier {
        Verifier {
            format: self.format,
            program: self.program().clone(),
            id: self.id,
            masked: self.masked,
        }
    }
}

/// The reference arguments a device kernel's reference program
/// `reference` returns: its output, run to its halt on no input within
/// [`REFERENCE_GAS`], stating no public arguments.
pub fn reference_arguments(reference: &[u8]) -> Result<Vec<u8>, ProveError> {
    let run = vos_pvm_proof::kernel::trace_kernel(reference, &[], REFERENCE_GAS)
        .map_err(|error| ProveError::Segment(format!("the reference: {error:?}")))?;
    match vos_pvm_precompiles::device_return_parts(&run.output) {
        Some(([], output)) => Ok(output.to_vec()),
        _ => Err(ProveError::Segment(
            "the reference returns no arguments alone".into(),
        )),
    }
}

/// `kernel`'s run on `arguments`, traced to its halt.
fn trace(
    kernel: &[u8],
    arguments: &[u8],
) -> Result<vos_pvm_proof::side_note::SideNote, ProveError> {
    vos_pvm_proof::kernel::trace_kernel(kernel, arguments, GAS)
        .map(|trace| trace.side_note)
        .map_err(|error| ProveError::Segment(format!("{error:?}")))
}
