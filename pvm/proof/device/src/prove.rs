//! A device program's prover: its program from the kernel or from a release
//! artifact, its runs traced and proved at its shape.

use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use vos_pvm_proof::format::Format;
use vos_pvm_proof::kernel::KernelTraceError;
use vos_pvm_proof::side_note::SideNote;

use super::verify::{Masked, Verifier, encode, masked, verify};
use super::{
    DeviceProgramId, Error, Hasher, ReferenceArguments, ReferenceProgram, Refusal, Release,
};
use crate::masked::{DeviceProgram, DeviceProof, DeviceProver, device_shape};
use crate::{MaskRng, MaskStats, MaskedProof};

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
    id: DeviceProgramId,
    masked: Masked,
}

impl Program {
    /// Kernel `kernel`'s program under device format `format`, as a node's
    /// install computes it and a release build embeds it: its log sizes
    /// those its run on what `reference` returns needs (each at least its
    /// floor), each raised by `headroom`. Refused when this build proves no
    /// such format, the reference does not return the arguments alone, the
    /// kernel does not run to its halt on them, or a raised size is past
    /// `DEVICE_MAX_LOG_SIZE`.
    pub fn from_kernel(
        format: u32,
        kernel: &[u8],
        reference: ReferenceProgram<'_>,
        headroom: u8,
    ) -> Result<Self, Error> {
        let arguments = reference.arguments()?;
        Self::sized_for(format, kernel, ReferenceArguments(&arguments), headroom)
    }

    /// Kernel `kernel`'s program under device format `format`, its log sizes
    /// those its run on `reference` needs, each raised by `headroom`: a
    /// test's or a bench's, which holds the arguments without a reference
    /// program ([`Program::from_kernel`]).
    pub fn sized_for(
        format: u32,
        kernel: &[u8],
        reference: ReferenceArguments<'_>,
        headroom: u8,
    ) -> Result<Self, Error> {
        let format = crate::format(format).ok_or(Error::Format(format))?;
        let mut run = trace(kernel, reference.0, GAS)?;
        let (active, log_sizes) = device_shape(format, kernel, &mut run)?;
        drop(run);
        let log_sizes: Vec<u32> = log_sizes
            .iter()
            .map(|size| size + u32::from(headroom))
            .collect();
        Self::at(format, kernel, active, &log_sizes)
    }

    /// The program `release` names: its preprocessed tree committed from
    /// the kernel at the artifact's chips and log sizes in its format, no
    /// reference run and no transpiler. Refused when this build proves no
    /// such format, the chips are not the kernel's code's, a size is under
    /// its floor or past `DEVICE_MAX_LOG_SIZE`, or the program's id is not
    /// the artifact's.
    pub fn from_release(release: &Release) -> Result<Self, Error> {
        let format = crate::format(release.format).ok_or(Error::Format(release.format))?;
        let program = Self::at(format, &release.kernel, release.chips, &release.log_sizes)?;
        if program.id.0 != release.id {
            return Err(Error::IdMismatch);
        }
        Ok(program)
    }

    /// The program of `kernel` under `format` at the chips `active` and the
    /// log sizes `log_sizes`.
    fn at(format: &Format, kernel: &[u8], active: u32, log_sizes: &[u32]) -> Result<Self, Error> {
        let prover =
            DeviceProver::<Blake2sM31MerkleChannel>::install(format, kernel, active, log_sizes)?;
        let id = DeviceProgramId::of(format, prover.program());
        let masked = masked(format, prover.program()).ok_or(Error::Masking)?;
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
    /// that does not fit fails to prove ([`Error::Fit`], `light-node.md`
    /// §4.4).
    pub fn fits(&self, arguments: &[u8]) -> Result<(), Error> {
        let mut run = trace(&self.kernel, arguments, GAS)?;
        let (active, needed) =
            device_shape(&self.format, &self.kernel, &mut run).map_err(|_| Error::Fit)?;
        let program = self.program();
        if active != program.active
            || needed
                .iter()
                .zip(&program.log_sizes)
                .any(|(needed, size)| needed > size)
        {
            return Err(Error::Fit);
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
    pub fn id(&self) -> &DeviceProgramId {
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
    /// under the program, its masks from `rng`. A run that does not halt
    /// ([`Error::Halt`]), or needs more rows than the program's shape
    /// ([`Error::Fit`]), is refused.
    pub fn prove(
        &self,
        arguments: &[u8],
        rng: MaskRng,
    ) -> Result<(DeviceProof<Hasher>, MaskStats), Error> {
        let mut run = trace(&self.kernel, arguments, GAS)?;
        let proved = self.prover.prove(&mut run, rng);
        drop(run);
        proved
    }

    /// Verifies the proof in `bytes` ([`decode`](super::decode)) of this
    /// program's kernel stating the io-hash `io`.
    pub fn verify(&self, io: &[u8; 32], bytes: &[u8]) -> Result<(), Refusal> {
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

impl ReferenceProgram<'_> {
    /// The reference arguments it returns: its output, run to its halt on
    /// no input within [`REFERENCE_GAS`], stating no public arguments.
    pub fn arguments(&self) -> Result<Vec<u8>, Error> {
        let run = trace_run(self.0, &[], REFERENCE_GAS)?;
        match vos_pvm_precompiles::device_return_parts(&run.output) {
            Some(([], output)) => Ok(output.to_vec()),
            _ => Err(Error::Reference),
        }
    }
}

/// `kernel`'s run on `arguments`, traced to its halt within `gas`.
fn trace(kernel: &[u8], arguments: &[u8], gas: u64) -> Result<SideNote, Error> {
    trace_run(kernel, arguments, gas).map(|trace| trace.side_note)
}

/// [`trace`], the whole run: [`Error::Layout`] for a blob that is not a
/// standard program, [`Error::Arguments`] for arguments the run does not
/// read whole, [`Error::Halt`] for a run that does not halt.
fn trace_run(
    blob: &[u8],
    arguments: &[u8],
    gas: u64,
) -> Result<vos_pvm_proof::kernel::KernelTrace, Error> {
    vos_pvm_proof::kernel::trace_kernel(blob, arguments, gas).map_err(|error| match error {
        KernelTraceError::Program => Error::Layout,
        KernelTraceError::Input | KernelTraceError::Unread { .. } => Error::Arguments,
        KernelTraceError::Exit(_) | KernelTraceError::Output => Error::Halt,
    })
}
