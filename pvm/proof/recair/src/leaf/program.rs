//! A kernel's program id finalized (`proving.md` §3.6): its leaf-circuit
//! slot holds each class's leaf circuit's hash.
//!
//! **Computed in the prover role, not at install.** A leaf circuit takes its
//! class's preprocessed root as a constant, so its hash needs the root, a
//! commitment to the kernel's preprocessed trace at the class's sizes, and
//! the leaf's own preprocessed commitment at the padded shape: seconds a
//! class, and the prover's dependencies, where an install derives programs
//! and shapes only. An install's record ([`vos_wire::records::Kernel`])
//! carries what the prover role needs: the kernel's hash, its image root and
//! its shape, the shape's policy version among it; the transpiler's version
//! is the derivation's. The program id covers the shape itself, so a record
//! of any policy computes to its own id.

use vos_pvm_proof::format::Format;
use vos_pvm_proof::poseidon2::P2Hash;
use vos_pvm_proof::program_id::{KernelEntry, KernelProgram, LeafCircuits};
use vos_pvm_proof::shape::KernelShape;

use super::LeafCircuit;

/// The leaf-circuit slot's version a program's leaves are built at.
pub const LEAF_CIRCUITS_VERSION: u32 = 1;

/// Each class's leaf circuit's hash, in the classes' order: `program`'s
/// kernel, whose run starts at `entry`.
pub(crate) fn leaf_circuit_hashes(program: &KernelProgram, entry: &KernelEntry) -> Vec<P2Hash> {
    (0..program.shape.classes.len())
        .map(|class| LeafCircuit::of_class(program, entry, class).hash())
        .collect()
}

/// The program of the kernel `blob`, as an install records it (`record`),
/// its proofs in `format`: each class's preprocessed root computed from its
/// code, and the leaf circuits' hashes in its slot; and its entry.
pub fn kernel_program(
    blob: &[u8],
    record: &vos_wire::records::Kernel,
    transpiler: u32,
    format: &'static Format,
) -> Result<(KernelProgram, KernelEntry), String> {
    let shape = KernelShape::try_from(&record.shape)?;
    let side_note =
        vos_pvm_proof::kernel::kernel_side_note(blob).map_err(|error| format!("{error:?}"))?;
    let preprocessed_roots = (0..shape.classes.len())
        .map(|class| {
            let segment = shape.segment(class).expect("a class");
            vos_pvm_proof::program_commitment_for_shape(&side_note, &segment, format)
                .ok_or_else(|| format!("class {class}'s preprocessed root"))
        })
        .collect::<Result<_, _>>()?;
    let mut program = KernelProgram {
        transpiler,
        program: record.program.0,
        shape,
        format: format.number,
        preprocessed_roots,
        image_root: record.image_root,
        leaf_circuits: LeafCircuits::None,
    };
    program.check()?;
    let entry = KernelEntry::of(&program, blob)?;
    program.leaf_circuits = LeafCircuits::Hashes(leaf_circuit_hashes(&program, &entry));
    debug_assert_eq!(program.leaf_circuits.version(), LEAF_CIRCUITS_VERSION);
    Ok((program, entry))
}
