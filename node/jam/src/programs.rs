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
//!   and after, when nothing names it any more.

use vos_wire::abi::cap;
use vos_wire::records::Derivation;
use vos_wire::schema::Schema;

use crate::Error;

/// What an install takes of a package: its programs, to provide as
/// preimages, the derivation that names them, and the actor's schema.
#[derive(Clone, Debug)]
pub struct Installable {
    pub derivation: Derivation,
    /// The actor's program, then each kernel, by method.
    pub programs: Vec<Vec<u8>>,
    pub schema: Schema,
}

/// Derive package `elf`'s programs, as a VOS node derives them. One with an
/// attestable method declaring more gas than a kernel runs with on JAM
/// (`cap::JAM.kernel_gas()`) is refused, naming it, as its install would
/// be.
pub fn derive(elf: &[u8]) -> Result<Installable, Error> {
    let derived =
        vos_pvm_compiler::derive(elf).map_err(|error| Error::Package(error.to_string()))?;
    let schema = Schema::read(&derived.schema)
        .map_err(|error| Error::Package(format!("its schema: {error:?}")))?;
    let most = cap::JAM.kernel_gas().expect("JAM bounds a kernel");
    if let Some(method) = schema
        .methods
        .iter()
        .find(|method| method.kind.is_attestable() && method.gas.is_some_and(|gas| gas > most))
    {
        return Err(Error::Package(format!(
            "attestable method `{}` declares gas {}, past the {most} a kernel runs with on JAM",
            String::from_utf8_lossy(&method.name),
            method.gas.unwrap_or_default(),
        )));
    }
    let derivation = Derivation::new(
        elf,
        &derived.actor,
        &derived.kernels,
        &derived.shapes,
        derived.transpiler_version,
        derived.heap,
    );
    let programs = core::iter::once(derived.actor)
        .chain(derived.kernels.into_iter().map(|(_, kernel)| kernel))
        .collect();
    Ok(Installable {
        derivation,
        programs,
        schema,
    })
}
