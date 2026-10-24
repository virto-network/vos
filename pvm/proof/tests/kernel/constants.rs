//! The reproducibility gate's constants (`vos_pvm_proof::constants`),
//! recomputed from their sources: each known kernel's program id from its
//! test actor's ELF, derived as an install derives it, `H_fold` from the
//! fold circuit and the wrap's preprocessed roots from the wrap circuit.
//! `test-proof` runs it under both of the prover's feature sets.

use vos_pvm_proof::constants;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_recair::fold::FoldCircuit;
use vos_pvm_recair::wrap::WrapCircuit;
use vos_testkit::programs::{derivation, derived, method, package};

/// The program id of test actor `actor`'s attestable `name`, from its ELF.
pub fn program_id(actor: &str, name: &str) -> [u32; 8] {
    let derived = derived(actor);
    let id = method(&derived.actor, name);
    let install = derivation(&package(actor), &derived);
    let record = install
        .kernels
        .iter()
        .find(|kernel| kernel.method == id)
        .expect("the method's kernel");
    let (_, blob) = derived
        .kernels
        .iter()
        .find(|(method, _)| *method == id.0)
        .expect("its blob");
    let (program, _) = vos_pvm_recair::leaf::kernel_program(
        blob,
        record,
        vos_pvm_compiler::TRANSPILER_VERSION,
        &SEGMENT,
    )
    .expect("the kernel's program");
    program.id().words()
}

/// Each constant is what its source computes, the wrap's roots the final
/// verifier's too.
#[test]
fn the_constants_are_the_repositorys() {
    let computed = [
        (
            "WINDOW_PROGRAM",
            program_id("window", "settle"),
            constants::WINDOW_PROGRAM,
        ),
        (
            "BALANCE_PROGRAM",
            program_id("balance", "at_least"),
            constants::BALANCE_PROGRAM,
        ),
        (
            "PREDICATE_PROGRAM",
            program_id("kernels", "areas"),
            constants::PREDICATE_PROGRAM,
        ),
        (
            "H_FOLD",
            FoldCircuit::word().0.map(|word| word.0),
            constants::H_FOLD,
        ),
    ];
    let wrap = WrapCircuit::get();
    let roots = [
        (
            "WRAP_ROOT_28",
            wrap.preprocessed_root().0,
            constants::WRAP_ROOT_28,
        ),
        (
            "WRAP_ROOT_39",
            wrap.masked_preprocessed_root().0,
            constants::WRAP_ROOT_39,
        ),
    ];
    for (name, words, _) in &computed {
        eprintln!("{name}: {words:?}");
    }
    for (name, bytes, _) in &roots {
        eprintln!("{name}: {bytes:?}");
    }
    for (name, words, pinned) in computed {
        assert_eq!(words, pinned, "{name}");
    }
    for (name, bytes, pinned) in roots {
        assert_eq!(bytes, pinned, "{name}");
    }
    assert_eq!(
        constants::WRAP_ROOT_28,
        vos_pvm_final_verifier::PREPROCESSED_ROOT
    );
    assert_eq!(
        constants::WRAP_ROOT_39,
        vos_pvm_final_verifier::PREPROCESSED_ROOT_39
    );
}
