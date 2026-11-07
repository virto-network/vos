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
//! was built and the SDK's dependencies. Its ELF hash leaves the temporary
//! symbols' names out, which follow the dependencies' source, so an edit to
//! a dependency's source that leaves the code as it is moves neither the
//! programs nor the hash.

use vos_pvm_compiler::{TRANSPILER_VERSION, derive};

/// The version, the actor's program's hash, the pages of its heap it
/// leaves out, and each kernel's hash by method: `areas`, `digest` and
/// `named`.
const PINNED: (u32, &str, u32, [(u32, &str); 3]) = (
    1,
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

/// The fixture's ELF hash, the names of its temporary symbols left out:
/// what every derivation and release artifact of it names.
const ELF: &str = "55ccaddc6f02637ff36bf7f621ad060d752a628cb11abdc126b9965facfea51f";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash(bytes: &[u8]) -> String {
    hex(&vos_pvm::precompile::blake2b_256(bytes))
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

/// `elf` with the byte `at` bytes into each occurrence of `name` set to
/// `to`, and how many it changed.
fn renamed(elf: &[u8], name: &[u8], at: usize, to: u8) -> (Vec<u8>, usize) {
    let mut renamed = elf.to_vec();
    let mut changed = 0;
    for start in 0..=elf.len().saturating_sub(name.len()) {
        if elf[start..].starts_with(name) {
            renamed[start + at] = to;
            changed += 1;
        }
    }
    (renamed, changed)
}

/// A rebuild after an edit to a dependency, its code the same, differs in
/// its anonymous data's names (`.Lanon.<hash>.<n>`), whose hash is the
/// dependency's: its ELF hash, its programs and its derivation stay. Any
/// other name moves the hash.
#[test]
fn an_elf_hash_leaves_out_temporary_symbols_names() {
    let elf = include_bytes!("fixtures/roomy.elf");
    let derived = derive(elf).expect("derives");
    assert_eq!(
        hex(&derived.elf),
        ELF,
        "what an ELF hash covers changed, which every derivation names: move TRANSPILER_VERSION, \
         and pin the hash"
    );

    let (rebuilt, names) = renamed(elf, b".Lanon.", 7, b'0');
    assert!(names > 0, "the fixture names its anonymous data");
    assert_ne!(&rebuilt[..], &elf[..]);
    let again = derive(&rebuilt).expect("derives");
    assert_eq!(again.derivation(), derived.derivation());
    assert_eq!(again.programs(), derived.programs());

    let (renamed, names) = renamed(elf, b"_RNv", 4, b'Z');
    assert!(names > 0, "the fixture names its functions");
    assert_ne!(derive(&renamed).expect("derives").elf, derived.elf);
}
