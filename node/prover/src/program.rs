//! A kernel's program id from its actor's ELF, as an install derives the
//! kernel: what `vos program-id <elf> <method>` prints, and the
//! reproducibility gate recomputes on another architecture.

use vos_abi::schema::Schema;
use vos_pvm_proof::format::SEGMENT;

/// The circuits' constants every statement's proof rests on, as the
/// repository pins them (`vos_pvm_proof::constants`), computed here: by
/// name, `H_FOLD` as its eight M31 words and `PREPROCESSED_ROOT_39` (the
/// final verifier's) as its 32 bytes.
pub fn circuits() -> Vec<(&'static str, Vec<u32>)> {
    let wrap = vos_pvm_recair::wrap::WrapCircuit::get();
    let bytes = |root: [u8; 32]| root.iter().map(|&byte| u32::from(byte)).collect();
    vec![
        (
            "H_FOLD",
            vos_pvm_recair::fold::FoldCircuit::word()
                .0
                .iter()
                .map(|word| word.0)
                .collect(),
        ),
        (
            "PREPROCESSED_ROOT_39",
            bytes(wrap.masked_preprocessed_root().0),
        ),
    ]
}

/// The program id of the kernel of `method`, an attestable method of the
/// actor whose package is `elf`: derived as an install derives it, its
/// program recomputed from the kernel's blob.
pub fn program_id(elf: &[u8], method: &str) -> Result<[u32; 8], ProgramIdError> {
    let derived = vos_pvm_compiler::derive(elf).map_err(ProgramIdError::Derive)?;
    let actor = vos_pvm_program::parse_standard_program(&derived.actor)
        .ok_or(ProgramIdError::NotStandard)?;
    let schema = Schema::read(&actor.ro_data).map_err(ProgramIdError::Schema)?;
    let id = schema.method_id(method).ok_or(ProgramIdError::NoMethod)?;
    let install = derived.derivation();
    let record = install
        .kernels
        .iter()
        .find(|kernel| kernel.method == id)
        .ok_or(ProgramIdError::NotAttestable)?;
    let (_, blob) = derived
        .kernels
        .iter()
        .find(|(bound, _)| *bound == id.0)
        .ok_or(ProgramIdError::NoKernel)?;
    let (program, _) =
        vos_pvm_recair::leaf::kernel_program(blob, record, derived.transpiler_version, &SEGMENT)
            .map_err(ProgramIdError::Kernel)?;
    Ok(program.id().words())
}

/// Why an actor's package gives no program id for a method: each the
/// package's own fault, a public artifact's.
#[derive(Debug)]
pub enum ProgramIdError {
    /// The package does not derive.
    Derive(vos_pvm_compiler::DeriveError),
    /// The actor is not a standard program.
    NotStandard,
    /// The actor's schema does not read.
    Schema(vos_abi::schema::SchemaError),
    /// The schema names no such method.
    NoMethod,
    /// The method is not attestable.
    NotAttestable,
    /// The derivation holds no kernel for the method.
    NoKernel,
    /// The kernel's program does not build.
    Kernel(vos_pvm_proof::program_id::KernelError),
}

impl core::fmt::Display for ProgramIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Derive(error) => write!(f, "the package does not derive: {error}"),
            Self::NotStandard => f.write_str("the actor is not a standard program"),
            Self::Schema(error) => write!(f, "its schema: {error:?}"),
            Self::NoMethod => f.write_str("no such method"),
            Self::NotAttestable => f.write_str("the method is not attestable"),
            Self::NoKernel => f.write_str("the method has no kernel"),
            Self::Kernel(error) => write!(f, "its kernel's program: {error}"),
        }
    }
}

impl std::error::Error for ProgramIdError {}
