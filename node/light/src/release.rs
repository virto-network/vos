//! Release artifacts (`light-node.md` §4.4): what the light node installs,
//! runs and proves, computed when the app is built and embedded in it, so
//! the phone runs no transpiler and no reference run.
//!
//! - A [`Package`] is a local actor as an install names it: its derivation
//!   and its programs, transpiled from its ELF. The agent program is the
//!   default agent, linked. A package of another [`TRANSPILER`] is refused
//!   at its install.
//! - A [`Device`] is a device kernel's program as a space computes it from
//!   the same ELF: the kernel, its chips and log sizes, and the program's
//!   id. The app ships the stock kernels' (and any kernel it puts a secret
//!   into), the current release's and the previous one's, and proves with
//!   the newest a space's window admits ([`crate::choose`]): the app and
//!   the space take one release artifact, the ELF, by its hash.
//!
//! The `release` feature builds them from ELFs (`package`, `agent`,
//! `devices`): the release build's edge to the transpiler, which the app's
//! build never enables.

use vos_pvm::pool::CodeHash;
use vos_wire::ids::MethodId;
use vos_wire::records::Derivation;
use vos_wire::{Decode, Encode};

/// The transpiler's version whose packages this light node installs: the
/// derivation's (`vos_pvm_compiler::TRANSPILER_VERSION`), which the
/// release build checks.
pub const TRANSPILER: u32 = 1;

/// A device kernel's release artifact: method `method`'s kernel of the
/// package whose ELF hashes to `elf`, and its device program as every node
/// computes it from that package (`vos_pvm_recair::device::Program::of`):
/// its chips, its log sizes, its format and its id. The light node
/// commits the program's preprocessed tree from these at its first proof
/// ([`crate::DeviceProgram::released`]) and checks the id it gets.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Device {
    pub elf: [u8; 32],
    pub method: MethodId,
    pub kernel: Vec<u8>,
    pub format: u32,
    pub chips: u32,
    pub log_sizes: Vec<u32>,
    pub id: [u8; 32],
}

/// A local actor's release artifact: its derivation, and its programs,
/// the actor's, then each kernel's, then each reference's, in the
/// derivation's order.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Package {
    pub derivation: Derivation,
    pub programs: Vec<Vec<u8>>,
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

/// The release artifact of the local actor whose ELF is `elf`: its
/// programs derived from it as a node's install derives them.
#[cfg(feature = "release")]
pub fn package(elf: &[u8]) -> Result<Package, String> {
    let derived = vos_pvm_compiler::derive(elf).map_err(|error| error.to_string())?;
    Ok(Package {
        derivation: derived.derivation(elf),
        programs: derived.programs(),
    })
}

/// The agent program from the default agent's ELF, `elf`, linked.
#[cfg(feature = "release")]
pub fn agent(elf: &[u8]) -> Result<Vec<u8>, String> {
    vos_pvm_compiler::link_elf_spi(elf).map_err(|error| error.to_string())
}

/// The device kernels' release artifacts of the package whose ELF is
/// `elf`, by method in ascending order: each kernel's program computed as
/// a node's install computes it, from its reference run.
#[cfg(feature = "release")]
pub fn devices(elf: &[u8]) -> Result<Vec<Device>, String> {
    let derived = vos_pvm_compiler::derive(elf).map_err(|error| error.to_string())?;
    let derivation = derived.derivation(elf);
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
            let program = vos_pvm_recair::device::Program::of(&kernel, reference, *headroom)
                .map_err(|error| format!("device kernel {method:#010x}: {error}"))?;
            Ok(Device {
                elf: derivation.elf,
                method: MethodId(*method),
                format: vos_pvm_recair::device::FORMAT.number,
                chips: program.chips(),
                log_sizes: program.log_sizes().to_vec(),
                id: *program.id(),
                kernel,
            })
        })
        .collect()
}

/// The release artifact of device kernel `method`, by name, of the package
/// whose ELF is `elf` ([`devices`]).
#[cfg(feature = "release")]
pub fn device(elf: &[u8], method: &str) -> Result<Device, String> {
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
