//! Release artifacts (`light-node.md` §4.4): what the light node installs,
//! runs and proves, computed when the app is built and embedded in it, so
//! the phone runs no transpiler and no reference run.
//!
//! - A [`Package`] is a local actor as an install names it: its derivation
//!   and its programs, transpiled from its ELF. The agent program is the
//!   default agent, linked. A package of another [`TRANSPILER`] is refused
//!   at its install.
//! - A [`Release`] is a device kernel's program as a space computes it
//!   from the same ELF: the kernel, its chips and log sizes, and the
//!   program's id (`vos_pvm_device::Release`). The app ships the stock
//!   kernels' (and any kernel it puts a secret into), in the device format,
//!   and proves with the newest a space's window admits
//!   ([`crate::choose`]): the app and the space take one release artifact,
//!   the ELF, by its hash.
//!
//! The `release` feature builds them from ELFs (`package`, `agent`,
//! `devices`): the release build's edge to the transpiler, which the app's
//! build never enables.

#[cfg(feature = "release")]
use vos_abi::ids::MethodId;
use vos_abi::records::Derivation;
use vos_abi::{Decode, Encode};
use vos_pvm::pool::CodeHash;

/// The transpiler's version whose packages this light node installs: the
/// derivation's (`vos_pvm_compiler::TRANSPILER_VERSION`), which the
/// release build checks.
pub const TRANSPILER: u32 = 1;

/// A device kernel's release artifact, its ELF hash that of
/// `vos_pvm_compiler::Derived::elf`: the light node commits the program's
/// preprocessed tree from it at its first proof
/// ([`crate::DeviceProgram::from_release`]) and checks the id it gets.
pub use vos_pvm_device::Release;

/// A local actor's release artifact: its derivation, its programs (the
/// actor's, then each kernel's, then each reference's, in the
/// derivation's order), and its release, numbered from 1 up across the
/// actor's releases. Every operation a device issues carries the release
/// it ran on, and a device holds one of a later release than it installed
/// until it installs that one (`light-node.md` §3.2); a later release runs
/// every earlier one's operations as they ran, and one that cannot starts
/// a new scope (§8, D7).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Package {
    pub derivation: Derivation,
    pub programs: Vec<Vec<u8>>,
    pub release: u32,
}

impl Package {
    /// Its programs with their hashes, if they are the derivation's, in its
    /// order: the actor's, then each kernel's, then each reference's.
    pub fn checked(&self) -> Option<Vec<([u8; 32], &[u8])>> {
        let named: Vec<[u8; 32]> = self.derivation.programs().map(|hash| hash.0).collect();
        if named.len() != self.programs.len() {
            return None;
        }
        named
            .into_iter()
            .zip(&self.programs)
            .map(|(hash, program)| {
                (CodeHash::of(program).0 == hash).then_some((hash, &program[..]))
            })
            .collect()
    }
}

/// The release artifact of release `release` of the local actor whose
/// ELF is `elf`: its programs derived from it as a node's install derives
/// them.
#[cfg(feature = "release")]
pub fn package(elf: &[u8], release: u32) -> Result<Package, String> {
    let derived = vos_pvm_compiler::derive(elf).map_err(|error| error.to_string())?;
    Ok(Package {
        derivation: derived.derivation(),
        programs: derived.programs(),
        release,
    })
}

/// The agent program from the default agent's ELF, `elf`, linked.
#[cfg(feature = "release")]
pub fn agent(elf: &[u8]) -> Result<Vec<u8>, String> {
    vos_pvm_compiler::link_elf_spi(elf).map_err(|error| error.to_string())
}

/// The device kernels' release artifacts of the package whose ELF is
/// `elf`, by method in ascending order: each kernel's program computed as
/// a node's install computes it, from its reference run, in the device
/// format.
#[cfg(feature = "release")]
pub fn devices(elf: &[u8]) -> Result<Vec<Release>, String> {
    devices_in(vos_pvm_device::FORMAT.number, elf)
}

/// [`devices`] in the device format numbered `format`, one this build
/// proves (`vos_pvm_device::FORMATS`): an app's artifacts for a
/// space that admits only that format.
#[cfg(feature = "release")]
pub fn devices_in(format: u32, elf: &[u8]) -> Result<Vec<Release>, String> {
    vos_pvm_device::format(format)
        .ok_or_else(|| format!("no device format {format} in this build"))?;
    let derived = vos_pvm_compiler::derive(elf).map_err(|error| error.to_string())?;
    let derivation = derived.derivation();
    derived
        .references
        .iter()
        .map(|(method, reference, headroom)| {
            let kernel = derived
                .kernels
                .iter()
                .find(|(bound, _)| bound == method)
                .map(|(_, kernel)| kernel.clone())
                .ok_or_else(|| format!("device kernel {method:#010x} has no kernel"))?;
            let program = vos_pvm_device::Program::from_kernel(
                format,
                &kernel,
                vos_pvm_device::ReferenceProgram(reference),
                *headroom,
            )
            .map_err(|error| format!("device kernel {method:#010x}: {error}"))?;
            Ok(Release {
                elf: derivation.elf,
                method: MethodId(*method),
                format,
                chips: program.chips(),
                log_sizes: program.log_sizes().to_vec(),
                id: program.id().0,
                kernel,
            })
        })
        .collect()
}

/// The release artifact of device kernel `method`, by name, of the package
/// whose ELF is `elf` ([`devices`]).
#[cfg(feature = "release")]
pub fn device(elf: &[u8], method: &str) -> Result<Release, String> {
    let id = MethodId(crate::method_id(method));
    devices(elf)?
        .into_iter()
        .find(|device| device.method == id)
        .ok_or_else(|| format!("no device kernel {method}"))
}

#[cfg(all(test, feature = "release"))]
mod tests {
    /// The light node's transpiler is the derivation's.
    #[test]
    fn the_transpiler_is_the_derivations() {
        assert_eq!(super::TRANSPILER, vos_pvm_compiler::TRANSPILER_VERSION);
    }
}
