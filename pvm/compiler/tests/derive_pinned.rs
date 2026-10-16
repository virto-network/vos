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
    2,
    "77e6fd9e4f59f94340f6bcd470c11299c8f4eda4ef5d973a0b3c68cac32c17f3",
    896,
    [
        (
            0x94bb_3e83,
            "78959c01cb94450a9877040618de7084bca5e752bd31770309515fbd0316ac58",
        ),
        (
            0xcf46_1499,
            "3a44754e6a473da601432680cb1673f8110bffa20ebc9042e09f155d0fa0618b",
        ),
        (
            0xe389_a21d,
            "f980ee92cdabfd38dd6621e689ea4734ae8772e62b9c2435ab27227fd70bc50c",
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
