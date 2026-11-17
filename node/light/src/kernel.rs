//! Device kernels proved under the device profile (`proving.md` §8): a
//! kernel's program, from its release artifact as the app embeds it (or
//! computed from the kernel as a space's ingress computes it), and a run
//! of it proved against that program.

use vos_pvm_device::{self as profile, Program};
use vos_wire::ids::MethodId;
use vos_wire::ingress::DeviceWindow;

use crate::release::Device;
use crate::{DeviceError, Prover};

/// The device format's number, the registry's: format 47, the one this
/// light node's release artifacts are computed in.
pub const DEVICE_FORMAT: u32 = profile::FORMAT.number;

/// A device kernel's program under a device format (the device format, or
/// another this build proves, [`profile::FORMATS`]): the chips its code
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
        Program::install(&profile::FORMAT, kernel, reference, headroom)
            .map(Self)
            .map_err(|_| DeviceError::Prove)
    }

    /// The program a release artifact names: its preprocessed tree
    /// committed from the kernel at the artifact's chips and log sizes in
    /// its format, no reference run and no transpiler;
    /// [`DeviceError::Prove`] when this build proves no such format, that is
    /// no program of it, or its id is not the artifact's.
    pub fn released(device: &Device) -> Result<Self, DeviceError> {
        let format = profile::format(device.format).ok_or(DeviceError::Prove)?;
        let program = Program::released(format, &device.kernel, device.chips, &device.log_sizes)
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

    /// The device format it proves under.
    pub fn format(&self) -> u32 {
        self.0.format().number
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
    /// which a caller holding the claim computes itself ([`claim_io`]).
    pub fn verify(&self, proof: &DeviceProof) -> Result<(), DeviceError> {
        if proof.format != self.format() {
            return Err(DeviceError::Verify);
        }
        self.verify_io(&proof.io, &proof.proof)
    }

    /// Verifies a proof's bytes `proof` under this program against `io`.
    pub(crate) fn verify_io(&self, io: &[u8; 32], proof: &[u8]) -> Result<(), DeviceError> {
        self.0.verify(io, proof).map_err(|_| DeviceError::Verify)
    }
}

/// The newest of `shipped`, the release artifacts a light node ships for
/// device kernel `method`, that a space's `window` admits: its program id
/// among the kernel's admitted programs, its format among the admitted
/// formats. [`DeviceError::Window`] when it admits none: the app or the
/// space must update, and nothing is proved; [`DeviceError::Unavailable`]
/// when it admits none of them yet but the node could not compute one of
/// the window's programs: ask again, or another replica. `shipped` is
/// newest first, a release's artifact in the device format before its
/// artifact in the previous one.
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
        .ok_or(match admitted.unavailable {
            true => DeviceError::Unavailable,
            false => DeviceError::Window,
        })
}

/// The io-hash a device kernel states for its claim `claim`, its public
/// arguments' encoding: `H_io` of it, no output, no root; `None` past
/// `H_io`'s bound.
pub fn claim_io(claim: &[u8]) -> Option<[u8; 32]> {
    profile::claim_io(claim)
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
    /// proved under the program's format in this prover's pool. A run that
    /// does not halt, or needs more rows than the program's shape, is
    /// [`DeviceError::Prove`].
    pub fn prove_kernel(
        &self,
        program: &DeviceProgram,
        arguments: &[u8],
    ) -> Result<DeviceProof, DeviceError> {
        self.pool.install(|| {
            let (proof, _) = program
                .0
                .prove(arguments, self.masks)
                .map_err(|_| DeviceError::Prove)?;
            Ok(DeviceProof {
                format: program.format(),
                io: proof.io,
                proof: program.0.encode(&proof.proof).ok_or(DeviceError::Prove)?,
            })
        })
    }
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
                unavailable: false,
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
        let mut pending = window(&[(3, format)], &[format]);
        pending.kernels[0].unavailable = true;
        assert_eq!(
            id(&pending),
            Err(DeviceError::Unavailable),
            "a program the node holds not yet"
        );
        assert_eq!(
            choose(&app, &window(&[(2, format)], &[format]), MethodId(8)).map(|_| ()),
            Err(DeviceError::Window),
            "no window for the kernel"
        );
    }

    /// An app shipping a kernel's program in the device format and in a
    /// previous one proves with the device format's where the space admits
    /// both, and with the previous one's where it admits that format alone.
    #[test]
    fn the_newest_admitted_format_is_chosen() {
        // Any number but 47's: the window and the app name it alone.
        let previous = 48;
        let app = [shipped(2, DEVICE_FORMAT), shipped(1, previous)];
        let chosen = |window: &DeviceWindow| {
            choose(&app, window, AUTH).map(|device| (device.id[0], device.format))
        };
        let both = window(
            &[(2, DEVICE_FORMAT), (1, previous)],
            &[DEVICE_FORMAT, previous],
        );
        assert_eq!(chosen(&both), Ok((2, DEVICE_FORMAT)));
        assert_eq!(
            chosen(&window(&[(1, previous)], &[previous])),
            Ok((1, previous))
        );
        assert_eq!(
            chosen(&window(&[(2, DEVICE_FORMAT)], &[DEVICE_FORMAT])),
            Ok((2, DEVICE_FORMAT))
        );
    }
}

#[cfg(test)]
mod wire_tests {
    use scale::Encode;
    use vos_wire::ingress::{FormatWindow, KernelWindow, ProgramWindow};

    use super::*;

    /// A `Devices` request is its kind's bytes then the agent and the
    /// instance; its answer decodes as the node encodes it.
    #[test]
    fn a_devices_request_and_its_answer() {
        let request = crate::wire::devices_request(5, 9);
        assert_eq!(&request[..2], &0x0005u16.to_le_bytes());
        assert_eq!(&request[2..], &[5, 0, 0, 0, 9, 0, 0, 0]);
        let window = DeviceWindow {
            formats: vec![FormatWindow {
                format: DEVICE_FORMAT,
                retires_ms: Some(7),
            }],
            kernels: vec![KernelWindow {
                method: MethodId(3),
                programs: vec![ProgramWindow {
                    id: [1; 32],
                    format: DEVICE_FORMAT,
                    retires_ms: None,
                }],
                unavailable: false,
            }],
        };
        assert_eq!(
            crate::wire::devices_answer(&Some(window.clone()).encode()),
            Ok(Some(window))
        );
        assert_eq!(crate::wire::devices_answer(&[0]), Ok(None));
        assert_eq!(crate::wire::devices_answer(&[2]), Err(DeviceError::Decode));
    }
}
