//! Device kernels proved under the device profile (`proving.md` §8): a
//! kernel's program, computed from the
//! kernel as a space's ingress computes it, a run of it proved against
//! that program, and auth's statement proved by a device kernel, which
//! ingress takes as it takes auth's credential proof.

use vos_pvm_recair::device::{self as profile, Program};
use vos_wire::credentials::Words;
use vos_wire::ids::MethodId;
use vos_wire::ingress::DeviceWindow;
use zeroize::Zeroize;

use crate::prover::auth_digests;
use crate::release::Device;
use crate::secret::DeviceSecret;
use crate::{AuthWitness, Call, CredentialProof, CredentialPublic, DeviceError, Prover, scope};

/// The device format's number, the registry's: format 46.
pub const DEVICE_FORMAT: u32 = profile::FORMAT.number;

/// The most memory a device kernel's proof takes, in bytes: the device budget,
/// above the auth kernel's peak resident size measured on the gate phone
/// (0.70 GiB). A prover allowing less refuses to prove one.
pub const DEVICE_PEAK_BYTES: u64 = 1 << 30;

/// A device kernel's program under the device format: the chips its code
/// reaches, a log size each and the preprocessed root they commit, all
/// computed from the kernel, never taken from a proof. A branch-free kernel
/// proves every witness under its one program.
pub struct DeviceProgram(Program);

impl DeviceProgram {
    /// Kernel `kernel`'s program, its log sizes those its run on
    /// `reference` needs, each raised by `headroom`: [`DeviceError::Prove`]
    /// when the kernel does not run to its halt on it, or needs more than
    /// the format's shape. A test's, or a bench's: the light node takes its
    /// programs as release artifacts ([`DeviceProgram::released`]).
    pub fn install(kernel: &[u8], reference: &[u8], headroom: u8) -> Result<Self, DeviceError> {
        Program::install(kernel, reference, headroom)
            .map(Self)
            .map_err(|_| DeviceError::Prove)
    }

    /// The program a release artifact names: its preprocessed tree
    /// committed from the kernel at the artifact's chips and log sizes, no
    /// reference run and no transpiler; [`DeviceError::Prove`] when that is
    /// no program of the device format, or its id is not the artifact's.
    pub fn released(device: &Device) -> Result<Self, DeviceError> {
        if device.format != DEVICE_FORMAT {
            return Err(DeviceError::Prove);
        }
        let program = Program::released(&device.kernel, device.chips, &device.log_sizes)
            .map_err(|_| DeviceError::Prove)?;
        if *program.id() != device.id {
            return Err(DeviceError::Prove);
        }
        Ok(Self(program))
    }

    /// Its id, which a binding names.
    pub fn id(&self) -> &[u8; 32] {
        self.0.id()
    }

    /// Each chip's log size, in the device order.
    pub fn log_sizes(&self) -> &[u32] {
        self.0.log_sizes()
    }

    /// The chips, a device mask.
    pub fn chips(&self) -> u32 {
        self.0.program().active
    }

    /// Verifies `proof`'s bytes under this program against its io-hash,
    /// which a caller holding the statement's words computes itself.
    pub fn verify(&self, proof: &DeviceProof) -> Result<(), DeviceError> {
        if proof.format != DEVICE_FORMAT {
            return Err(DeviceError::Verify);
        }
        self.0
            .verify(&proof.io, &proof.proof)
            .map_err(|_| DeviceError::Verify)
    }
}

/// The newest of `shipped`, the release artifacts a light node ships for
/// device kernel `method`, that a space's `window` admits: its program id
/// among the kernel's admitted programs, its format among the admitted
/// formats. [`DeviceError::Window`] when it admits none: the app or the
/// space must update, and nothing is proved. `shipped` is newest first.
pub fn choose<'a>(
    shipped: &'a [Device],
    window: &DeviceWindow,
    method: MethodId,
) -> Result<&'a Device, DeviceError> {
    let admitted = window
        .kernels
        .iter()
        .find(|kernel| kernel.method == method)
        .ok_or(DeviceError::Window)?;
    shipped
        .iter()
        .filter(|device| device.method == method)
        .find(|device| {
            window
                .formats
                .iter()
                .any(|format| format.format == device.format)
                && admitted
                    .programs
                    .iter()
                    .any(|program| program.id == device.id && program.format == device.format)
        })
        .ok_or(DeviceError::Window)
}

/// The io-hash a device kernel of auth's statement states for its public
/// arguments `public` (the SCALE encoding of auth's `CredentialPublic`):
/// `H_io` of them, no output, no root; `None` past `H_io`'s bound.
pub fn auth_io(public: &[u8]) -> Option<[u8; 32]> {
    profile::auth_io(public)
}

/// A device kernel's proof: the io-hash its run states and the proof's
/// bytes, which hold no io-hash (a verifier takes it from the words it
/// holds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceProof {
    pub format: u32,
    pub io: [u8; 32],
    pub proof: Vec<u8>,
}

impl Prover {
    /// `program`'s kernel run on `arguments`, through its witness input,
    /// proved under the device format in this prover's pool. A run that
    /// does not halt, or needs more rows than the program's shape, is
    /// [`DeviceError::Prove`]; an allowance below [`DEVICE_PEAK_BYTES`] is
    /// [`DeviceError::Memory`].
    pub fn prove_kernel(
        &self,
        program: &DeviceProgram,
        arguments: &[u8],
    ) -> Result<DeviceProof, DeviceError> {
        if self.max_memory < DEVICE_PEAK_BYTES {
            return Err(DeviceError::Memory);
        }
        self.pool.install(|| {
            let (proof, _) = program
                .0
                .prove(arguments, self.masks)
                .map_err(|_| DeviceError::Prove)?;
            Ok(DeviceProof {
                format: DEVICE_FORMAT,
                io: proof.io,
                proof: profile::encode(&proof.proof).ok_or(DeviceError::Prove)?,
            })
        })
    }

    /// Proves auth's statement with device kernel `program`: `secret`'s
    /// member holds the leaf `witness` places under its root, and its
    /// nullifier in the scope of the guard named `name`, for `call`, the
    /// binding naming the program. The witness is checked first, as
    /// [`Prover::prove_auth`] checks it. The proof is what a `Credentialed`
    /// request carries under the device format.
    pub fn prove_device_auth(
        &self,
        secret: &DeviceSecret,
        witness: &AuthWitness,
        name: &[u8],
        call: &Call,
        program: &DeviceProgram,
    ) -> Result<CredentialProof, DeviceError> {
        let public = auth_digests(secret, witness, name, call, program.id(), 0)?;
        let bytes = profile::auth_public(
            &public.map_root.to_bytes(),
            &public.scope.to_bytes(),
            &public.nullifier.to_bytes(),
            &public.binding.to_bytes(),
        );
        let siblings: [Words; vos_wire::credentials::DEPTH] =
            witness.siblings.map(|sibling| sibling.0);
        let mut arguments = profile::auth_arguments(&siblings, &secret.0, witness.slot, &bytes);
        let proved = self.prove_kernel(program, &arguments);
        arguments.zeroize();
        let proof = proved?;
        if Some(proof.io) != profile::auth_io(&bytes) {
            return Err(DeviceError::Prove);
        }
        Ok(CredentialProof {
            format: DEVICE_FORMAT,
            public: CredentialPublic::Auth {
                map_root: public.map_root,
                scope: public.scope,
                nullifier: public.nullifier,
                binding: public.binding,
            },
            proof: proof.proof,
        })
    }
}

/// Verifies a device proof of auth's statement against `call` as ingress
/// does: its format the device format, its binding `call`'s under
/// `program`'s id, its scope the one the guard named `name` gives, then the
/// proof under `program` against the io-hash of its words.
pub fn verify_device(
    proof: &CredentialProof,
    call: &Call,
    name: &[u8],
    program: &DeviceProgram,
) -> Result<(), DeviceError> {
    let CredentialPublic::Auth {
        map_root,
        scope: proved,
        nullifier,
        binding,
    } = proof.public
    else {
        return Err(DeviceError::Verify);
    };
    if proof.format != DEVICE_FORMAT
        || call.check().is_err()
        || binding != call.binding(program.id(), 0)
        || scope(&call.space, call.agent, call.instance, name) != Some(proved)
    {
        return Err(DeviceError::Verify);
    }
    let bytes = profile::auth_public(
        &map_root.to_bytes(),
        &proved.to_bytes(),
        &nullifier.to_bytes(),
        &binding.to_bytes(),
    );
    let io = profile::auth_io(&bytes).ok_or(DeviceError::Verify)?;
    program
        .0
        .verify(&io, &proof.proof)
        .map_err(|_| DeviceError::Verify)
}

#[cfg(test)]
mod tests {
    use vos_wire::ingress::{FormatWindow, KernelWindow, ProgramWindow};

    use super::*;

    const AUTH: MethodId = MethodId(7);

    /// A release artifact of `AUTH` whose program id is `id`, in `format`.
    fn shipped(id: u8, format: u32) -> Device {
        Device {
            elf: [id; 32],
            method: AUTH,
            kernel: Vec::new(),
            format,
            chips: 0,
            log_sizes: Vec::new(),
            id: [id; 32],
        }
    }

    /// A window admitting `programs` of `AUTH`, each in its format, and the
    /// formats `formats`.
    fn window(programs: &[(u8, u32)], formats: &[u32]) -> DeviceWindow {
        DeviceWindow {
            formats: formats
                .iter()
                .map(|&format| FormatWindow {
                    format,
                    retires_ms: None,
                })
                .collect(),
            kernels: vec![KernelWindow {
                method: AUTH,
                programs: programs
                    .iter()
                    .map(|&(id, format)| ProgramWindow {
                        id: [id; 32],
                        format,
                        retires_ms: None,
                    })
                    .collect(),
            }],
        }
    }

    /// The newest program the app ships that the window admits, in a format
    /// it admits; none admitted, or no window for the kernel, is
    /// `DeviceError::Window`, before anything is proved.
    #[test]
    fn the_newest_admitted_program_is_chosen() {
        let app = [shipped(2, DEVICE_FORMAT), shipped(1, DEVICE_FORMAT)];
        let id = |window: &DeviceWindow| choose(&app, window, AUTH).map(|device| device.id[0]);
        let format = DEVICE_FORMAT;
        assert_eq!(id(&window(&[(2, format), (1, format)], &[format])), Ok(2));
        assert_eq!(id(&window(&[(1, format)], &[format])), Ok(1));
        assert_eq!(id(&window(&[(3, format), (2, format)], &[format])), Ok(2));
        assert_eq!(
            id(&window(&[(3, format)], &[format])),
            Err(DeviceError::Window),
            "the app is behind"
        );
        assert_eq!(
            id(&window(&[(2, format)], &[])),
            Err(DeviceError::Window),
            "its format retired"
        );
        assert_eq!(
            id(&window(&[(2, format + 1)], &[format, format + 1])),
            Err(DeviceError::Window),
            "the program in another format"
        );
        assert_eq!(
            choose(&app, &window(&[(2, format)], &[format]), MethodId(8)).map(|_| ()),
            Err(DeviceError::Window),
            "no window for the kernel"
        );
    }
}
