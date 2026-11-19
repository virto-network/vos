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
    "e66e2b68f72b6bcfeb12a56a90eeffb82de42af7f1f7b83d3b8cbf25a9ee1d0a",
    896,
    [
        (
            0x94bb_3e83,
            "5a7dee77e5daa62cde225d0f418af35a514bbaf33069f1cf1e78f7f163ebc97d",
        ),
        (
            0xcf46_1499,
            "8e5b2b117d85bf1bbe782491c2ff3b20ef3d4dced05c7d4c71e3f7a74c9d1eb1",
        ),
        (
            0xe389_a21d,
            "76dacc916ba4c83973563cd5d2e952933c1cdf791a7eefbc0866b04cfc1e4c79",
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
