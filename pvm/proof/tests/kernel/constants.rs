//! The reproducibility gate's constants (`vos_pvm_proof::constants`),
//! recomputed from their sources: each known kernel's program id from its
//! test actor's ELF, derived as an install derives it, `H_fold` from the
//! fold circuit and the wrap's preprocessed root from the wrap circuit.
//! `test-proof` runs it under both of the prover's feature sets; under
//! `VOS_PINS=write` (`just repin`) it writes the constants that moved.

use vos_pvm_proof::constants;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_recair::fold::FoldCircuit;
use vos_pvm_recair::wrap::WrapCircuit;
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
    program.id().words()
}

/// Each constant is what its source computes, the wrap's root the final
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
    let roots = [(
        "WRAP_ROOT_39",
        wrap.masked_preprocessed_root().0,
        constants::WRAP_ROOT_39,
    )];
    let moved = computed.iter().any(|(_, words, pinned)| words != pinned)
        || roots.iter().any(|(_, bytes, pinned)| bytes != pinned);
    if moved && std::env::var("VOS_PINS").as_deref() == Ok("write") {
        let values = computed
            .iter()
            .map(|(name, words, _)| (*name, words.map(u64::from).to_vec()))
            .chain(
                roots
                    .iter()
                    .map(|(name, bytes, _)| (*name, bytes.map(u64::from).to_vec())),
            );
        write(values);
        return;
    }
    for (name, words, pinned) in computed {
        assert_eq!(words, pinned, "{name} moved: `just repin`");
    }
    for (name, bytes, pinned) in roots {
        assert_eq!(bytes, pinned, "{name} moved: `just repin`");
    }
    assert_eq!(
        constants::WRAP_ROOT_39,
        vos_pvm_final_verifier::PREPROCESSED_ROOT_39
    );
}

/// Write `constants` into `src/constants.rs`, each its array's values, as
/// rustfmt lays an array out: `just repin`'s write (`VOS_PINS=write`).
fn write(constants: impl Iterator<Item = (&'static str, Vec<u64>)>) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/constants.rs");
    let mut source = std::fs::read_to_string(&path).unwrap();
    for (name, values) in constants {
        let start = source
            .find(&format!("pub const {name}: "))
            .unwrap_or_else(|| panic!("no {name} in {}", path.display()));
        let open = start + source[start..].find("= [").expect("its array") + 3;
        let close = open + source[open..].find("];").expect("its end");
        let mut body = String::from("\n   ");
        let mut width = 3;
        for value in values {
            let item = format!(" {value},");
            if width + item.len() > 100 {
                body.push_str("\n   ");
                width = 3;
            }
            body.push_str(&item);
            width += item.len();
        }
        body.push('\n');
        source.replace_range(open..close, &body);
    }
    std::fs::write(&path, source).unwrap();
    eprintln!("{}: written", path.display());
}
