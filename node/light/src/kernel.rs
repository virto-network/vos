//! Device kernels proved under the device profile (`proving.md` §8): a
//! kernel's program, from its release artifact as the app embeds it (or
//! computed from the kernel as a space's ingress computes it), and a run
//! of it proved against that program.

use vos_wire::ids::MethodId;
use vos_wire::ingress::DeviceWindow;

use crate::release::Release;
use crate::{DeviceError, Prover};

/// A device kernel's program under a device format (the device format, or
/// another this build proves, `vos_pvm_device::FORMATS`): the chips its
/// code reaches, a log size each and the preprocessed root they commit, all
/// computed from the kernel, never taken from a proof. A branch-free kernel
/// proves every witness under its one program. The light node takes its
/// programs as release artifacts (`DeviceProgram::from_release`).
pub use vos_pvm_device::Program as DeviceProgram;

/// The device format's number, the registry's: format 47, the one this
/// light node's release artifacts are computed in.
pub const DEVICE_FORMAT: u32 = vos_pvm_device::FORMAT.number;

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
    shipped: &'a [Release],
    window: &DeviceWindow,
    method: MethodId,
) -> Result<&'a Release, DeviceError> {
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
    vos_pvm_device::claim_io(claim)
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

impl DeviceProof {
    /// Verifies it under `program` against its io-hash, which a caller
    /// holding the claim computes itself ([`claim_io`]): its format the
    /// program's, then its bytes.
    pub fn verify(&self, program: &DeviceProgram) -> Result<(), DeviceError> {
        if self.format != program.format().number {
            return Err(DeviceError::Verify);
        }
        program
            .verify(&self.io, &self.proof)
            .map_err(|_| DeviceError::Verify)
    }
}

impl Prover {
    /// `program`'s kernel run on `arguments`, through its witness input,
    /// proved under the program's format in this prover's pool. A run that
    /// does not halt, or needs more rows than the program's shape, is
    /// [`DeviceError::Program`], its cause the device profile's.
    pub fn prove_kernel(
        &self,
        program: &DeviceProgram,
        arguments: &[u8],
    ) -> Result<DeviceProof, DeviceError> {
        self.pool.install(|| {
            let (proof, _) = program
                .prove(arguments, self.masks)
                .map_err(DeviceError::Program)?;
            Ok(DeviceProof {
                format: program.format().number,
                io: proof.io,
                proof: program.encode(&proof.proof).ok_or(DeviceError::Prove)?,
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
    fn shipped(id: u8, format: u32) -> Release {
        Release {
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
