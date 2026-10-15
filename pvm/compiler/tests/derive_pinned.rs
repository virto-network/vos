//! A committed package, the `kernels` test actor's ELF, whose derived
//! programs are pinned: a change to the bytes the derivation gives fails
//! here until [`TRANSPILER_VERSION`] moves and the pins with it, since an
//! installed kernel's hash is pinned on chain per version.
//!
//! The fixture is rebuilt with `just build-test-actors`, from
//! `agent/test-actors/target/riscv64em-vos/release/kernels.elf`. A rebuild
//! derives the same programs while the actor's source stands, but not the
//! same file: its symbols' names carry crate hashes that follow where it
//! was built and the SDK's dependencies.

use vos_pvm_compiler::{TRANSPILER_VERSION, derive};

/// The version, the actor's program's hash, and each kernel's by method:
/// `areas`, `digest` and `named`.
const PINNED: (u32, &str, [(u32, &str); 3]) = (
    1,
    "39c1cbcc3db749f631540ba3bcd37339ea4902d21f2138aeefbdb3ad87147228",
    [
        (
            0x94bb_3e83,
            "24bbc43e65f8eb14f878d7d14f5fcff66d3be90e2ca16f93091b53624c42a2cc",
        ),
        (
            0xcf46_1499,
            "de9625ea5ae2ea387e7cc85e0e9497608238e1f78e4a756522bbcb5f47588983",
        ),
        (
            0xe389_a21d,
            "2bd64ca06bd9fbee8265609e368fa6f97e04523f4bcd21e95c4c8b0ce55fd864",
        ),
    ],
);

fn hash(bytes: &[u8]) -> String {
    vos_pvm::precompile::blake2b_256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn a_fixed_package_derives_its_pinned_programs() {
    let derived = derive(include_bytes!("fixtures/kernels.elf")).expect("derives");
    let kernels: Vec<(u32, String)> = derived
        .kernels
        .iter()
        .map(|(method, kernel)| (*method, hash(kernel)))
        .collect();
    let pinned: Vec<(u32, String)> = PINNED
        .2
        .iter()
        .map(|(method, kernel)| (*method, kernel.to_string()))
        .collect();
    assert_eq!(
        (TRANSPILER_VERSION, hash(&derived.actor), kernels),
        (PINNED.0, PINNED.1.to_string(), pinned),
        "the derivation's bytes changed: move TRANSPILER_VERSION, and pin what it derives"
    );
}
