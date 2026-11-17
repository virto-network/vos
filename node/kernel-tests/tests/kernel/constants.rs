//! The reproducibility gate's program ids (`vos_pvm_proof::constants`),
//! recomputed from their sources: each known kernel's program id from its
//! test actor's ELF, derived as an install derives it. The circuits'
//! constants are `vos-pvm-proof`'s own `constants::`. `test-proof` runs it
//! under both of the prover's feature sets; under `VOS_PINS=write` (`just
//! repin`) it writes the ids that moved.

use vos_pvm_proof::constants;
use vos_pvm_proof::format::SEGMENT;
use vos_testkit::programs::{derived, method};

/// The program id of test actor `actor`'s attestable `name`, from its ELF.
pub fn program_id(actor: &str, name: &str) -> [u32; 8] {
    let derived = derived(actor);
    let id = method(&derived.actor, name);
    let install = derived.derivation();
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
    program.id().0
}

/// Each known program's id is what its test actor's ELF derives.
#[test]
fn the_programs_ids_are_the_repositorys() {
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
    ];
    let moved = computed.iter().any(|(_, words, pinned)| words != pinned);
    if moved && std::env::var("VOS_PINS").as_deref() == Ok("write") {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../pvm/proof/src/constants.rs");
        assert!(
            path.is_file(),
            "{}: the proof crate's constants",
            path.display()
        );
        crate::common::write_constants(
            &path,
            computed
                .iter()
                .map(|(name, words, _)| (*name, words.map(u64::from).to_vec())),
        );
    } else {
        for (name, words, pinned) in computed {
            assert_eq!(words, pinned, "{name} moved: `just repin`");
        }
    }
}
