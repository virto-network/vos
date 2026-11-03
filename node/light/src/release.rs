//! Release artifacts (`light-node.md` §4.4): what the light node installs
//! and runs, computed when the app is built and embedded in it, so the
//! phone runs no transpiler. A [`Package`] is a local actor as an install
//! names it: its derivation and its programs, transpiled from its ELF.
//! The agent program is the default agent, linked.
//!
//! The `release` feature builds them from ELFs (`package`, `agent`):
//! the release build's edge to the transpiler, which the app's build never
//! enables.

use vos_pvm::pool::CodeHash;
use vos_wire::records::Derivation;
use vos_wire::{Decode, Encode};

/// A local actor's release artifact: its derivation, and its programs,
/// the actor's and then each kernel's, in the derivation's order.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Package {
    pub derivation: Derivation,
    pub programs: Vec<Vec<u8>>,
}

impl Package {
    /// Its programs with their hashes, if they are the derivation's, in its
    /// order: the actor's, then each kernel's.
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
