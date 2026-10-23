//! A kernel's program id from its actor's ELF, as an install derives the
//! kernel: what `vos program-id <elf> <method>` prints, and the
//! reproducibility gate recomputes on another architecture.

use vos_pvm_proof::format::SEGMENT;
use vos_wire::records::Derivation;
use vos_wire::schema::Schema;

/// The circuits' constants every statement's proof rests on, as the
/// repository pins them (`vos_pvm_proof::constants`), computed here: by
/// name, `H_FOLD` as its eight M31 words, `WRAP_ROOT_28` and
/// `WRAP_ROOT_39` as their 32 bytes.
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
        ("WRAP_ROOT_28", bytes(wrap.preprocessed_root().0)),
        ("WRAP_ROOT_39", bytes(wrap.masked_preprocessed_root().0)),
    ]
}

/// The program id of the kernel of `method`, an attestable method of the
/// actor whose package is `elf`: derived as an install derives it, its
/// program recomputed from the kernel's blob.
pub fn program_id(elf: &[u8], method: &str) -> Result<[u32; 8], String> {
    let derived = vos_pvm_compiler::derive(elf).map_err(|error| format!("{error:?}"))?;
    let actor = vos_pvm_program::parse_standard_program(&derived.actor)
        .ok_or_else(|| String::from("the actor is not a standard program"))?;
    let schema = Schema::read(&actor.ro_data).map_err(|error| format!("its schema: {error:?}"))?;
    let id = schema
        .method_id(method)
        .ok_or_else(|| format!("no method {method}"))?;
    let install = Derivation::new(
        elf,
        &derived.actor,
        &derived.kernels,
        &derived.shapes,
        derived.transpiler_version,
        derived.heap,
    );
    let record = install
        .kernels
        .iter()
        .find(|kernel| kernel.method == id)
        .ok_or_else(|| format!("{method} is not attestable"))?;
    let (_, blob) = derived
        .kernels
        .iter()
        .find(|(bound, _)| *bound == id.0)
        .ok_or_else(|| format!("{method} has no kernel"))?;
    let (program, _) =
        vos_pvm_recair::leaf::kernel_program(blob, record, derived.transpiler_version, &SEGMENT)?;
    Ok(program.id().0.map(|word| word.0))
}
