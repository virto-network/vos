//! The programs an agent on JAM runs, as preimages of its service.
//!
//! - **Derived** from each package's ELF by the derivation a VOS node runs
//!   at install ([`vos_pvm_compiler::derive`]): the actor's program and a
//!   kernel per attestable method, the same bytes and hashes from the same
//!   ELF and transpiler version, named by the same constructor
//!   ([`Derivation::new`]), so the two agree whenever a space's proof is
//!   verified on chain. The builder provides them as preimages and the
//!   install names them.
//! - **Never forgotten:** the agent's accumulate solicits a program when a
//!   package names it and never forgets one, so a program stays solicited
//!   while any live workflow names it, whatever an upgrade installed since,
//!   and after. Forgetting the programs nothing names any more is left for
//!   a later slice.

use vos_wire::ids::MethodId;
use vos_wire::records::Derivation;

use crate::Error;

/// What an install takes of a package: its programs, to provide as
/// preimages, and the derivation that names them.
#[derive(Clone, Debug)]
pub struct Installable {
    pub derivation: Derivation,
    /// The actor's program, then each kernel, by method.
    pub programs: Vec<Vec<u8>>,
}

/// Derive package `elf`'s programs, as a VOS node derives them.
pub fn derive(elf: &[u8]) -> Result<Installable, Error> {
    let derived =
        vos_pvm_compiler::derive(elf).map_err(|error| Error::Package(error.to_string()))?;
    let derivation = Derivation::new(
        elf,
        &derived.actor,
        derived
            .kernels
            .iter()
            .map(|(method, kernel)| (MethodId(*method), kernel.as_slice())),
        derived.transpiler_version,
    );
    let programs = core::iter::once(derived.actor)
        .chain(derived.kernels.into_iter().map(|(_, kernel)| kernel))
        .collect();
    Ok(Installable {
        derivation,
        programs,
    })
}
