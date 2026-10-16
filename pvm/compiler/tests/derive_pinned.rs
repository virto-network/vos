//! A committed package, the `kernels` test actor's ELF built with a heap
//! past what a kernel holds (`roomy`), whose derived programs are pinned:
//! a change to the bytes the derivation gives fails here until
//! [`TRANSPILER_VERSION`] moves and the pins with it, since an installed
//! kernel's hash is pinned on chain per version.
//!
//! The fixture is rebuilt with `just build-test-actors`, from
//! `agent/test-actors/target/riscv64em-vos/release/roomy.elf`. A rebuild
//! derives the same programs while the actor's source stands, but not the
//! same file: its symbols' names carry crate hashes that follow where it
//! was built and the SDK's dependencies.

use vos_pvm_compiler::{TRANSPILER_VERSION, derive};

/// The version, the actor's program's hash, the pages of its heap it
/// leaves out, and each kernel's hash by method: `areas`, `digest` and
/// `named`.
const PINNED: (u32, &str, u32, [(u32, &str); 3]) = (
    3,
    "58b2f60263b31316b68f143cf0533dddb87bbf97322dbad282b327d0eab5fb96",
    896,
    [
        (
            0x94bb_3e83,
            "1965796dd7f4a906f08fe61ead896acee9cfffe4820c26fa2693651f429ead88",
        ),
        (
            0xcf46_1499,
            "5b38a5b674631ff8941e6e2c2817612ee69913384bf2f74c65d50292f0114e40",
        ),
        (
            0xe389_a21d,
            "d413a5ab4eed05679fbbbdc77106cfab6b33c59570792edf74380641686f996a",
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
    let derived = derive(include_bytes!("fixtures/roomy.elf")).expect("derives");
    let kernels: Vec<(u32, String)> = derived
        .kernels
        .iter()
        .map(|(method, kernel)| (*method, hash(kernel)))
        .collect();
    let pinned: Vec<(u32, String)> = PINNED
        .3
        .iter()
        .map(|(method, kernel)| (*method, kernel.to_string()))
        .collect();
    assert_eq!(
        (
            TRANSPILER_VERSION,
            hash(&derived.actor),
            derived.heap,
            kernels
        ),
        (PINNED.0, PINNED.1.to_string(), PINNED.2, pinned),
        "the derivation's bytes changed: move TRANSPILER_VERSION, and pin what it derives"
    );
}
