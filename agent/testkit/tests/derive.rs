//! One ELF in, programs out: the derivation an install runs over every test
//! actor's package. It gives the bytes `link_elf_spi` gives for the actor's
//! program, the same bytes in any process, kernels that run their methods
//! as the actor's code does, and it refuses a kernel that makes a host call
//! other than a precompile. Fed mutated packages, it never panics.

use std::collections::BTreeMap;
use std::process::{Command, Stdio};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use proptest::prelude::*;
use vos_pvm_compiler::{DeriveError, derive, link_elf_spi};
use vos_testkit::programs::{actor_elf, derived, method, package};
use vos_testkit::{Testkit, decode};
use vos_wire::Encode;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;

/// Every test actor's package, by name: those an install takes.
const PACKAGES: [&str; 9] = [
    "counter", "ledger", "caller", "shop", "big", "huge", "lean", "rounds", "kernels",
];

/// Where a child process writes what it derived.
const CHILD: &str = "VOS_DERIVE_CHILD";

fn digest(bytes: &[u8]) -> String {
    Blake2b::<U32>::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Each package's derivation, a line each: its actor's program, schema
/// and kernels, by their hashes.
fn derivations() -> String {
    let mut lines = String::new();
    for name in PACKAGES {
        let derived = derive(&package(name)).expect("derives");
        lines += &format!(
            "{name} {} {} {}",
            digest(&derived.actor),
            digest(&derived.schema),
            derived.transpiler_version
        );
        for (method, kernel) in &derived.kernels {
            lines += &format!(" {method:#010x}={}", digest(kernel));
        }
        lines += "\n";
    }
    lines
}

/// The same ELF and transpiler give the same bytes in any process: a
/// child derives every package with its own hash maps' seeds, twice over,
/// and both children write what this process derives.
#[test]
fn a_derivation_is_the_same_in_every_process() {
    if let Ok(out) = std::env::var(CHILD) {
        std::fs::write(out, derivations()).unwrap();
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let derived = derivations();
    for child in 0..2 {
        let out = dir.path().join(format!("child-{child}"));
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "a_derivation_is_the_same_in_every_process"])
            .env(CHILD, &out)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            derived,
            "child {child}"
        );
    }
    println!("{derived}");
}

/// The actor's program is what `link_elf_spi` links from the ELF, byte for
/// byte, and the schema is the program's.
#[test]
fn the_actors_program_is_the_elf_linked() {
    for name in PACKAGES {
        let elf = package(name);
        let derived = derive(&elf).unwrap();
        assert_eq!(derived.actor, link_elf_spi(&elf).unwrap(), "{name}");
        let parsed = vos_pvm::spi::parse_standard_program(&derived.actor).unwrap();
        assert_eq!(
            Schema::read(&parsed.ro_data).unwrap(),
            Schema::read(&derived.schema).unwrap(),
            "{name}"
        );
        let attestables: Vec<u32> = Schema::read(&derived.schema)
            .unwrap()
            .methods
            .iter()
            .filter(|method| method.kind == vos_wire::abi::Kind::Attestable)
            .map(|method| method.id.0)
            .collect();
        let mut kernels: Vec<u32> = derived.kernels.iter().map(|(id, _)| *id).collect();
        kernels.sort_unstable();
        let mut attestables = attestables;
        attestables.sort_unstable();
        assert_eq!(kernels, attestables, "{name}: a kernel per attestable");
    }
}

/// Kernels run their methods as the actor's code does: a precompile and
/// its fallback's constants, a jump table of relative entries and calls
/// through a vtable, each reached from its entry alone, and each kernel's
/// hash pinned by its own code.
#[test]
fn kernels_run_their_methods() {
    let kinds = relocation_kinds(&package("kernels"));
    assert!(
        kinds.contains(&35) && kinds.contains(&39),
        "a jump table's ADD32 and SUB32: {kinds:?}"
    );
    let derived = derived("kernels");
    let program = &derived.actor;
    let mut kit = Testkit::new(AgentId(7));
    let kernels: Vec<(MethodId, &[u8])> = derived
        .kernels
        .iter()
        .map(|(method, kernel)| (MethodId(*method), kernel.as_slice()))
        .collect();
    kit.install(InstanceId(1), program, &kernels, &[]).unwrap();
    let check = method(program, "check");
    for values in [vec![], vec![1u64, 2, 3], (0..40).collect::<Vec<u64>>()] {
        let step = kit.command(
            Principal::Client([1; 32]),
            InstanceId(1),
            check,
            &values.encode(),
        );
        let Outcome::Done(reply) = step.outcome else {
            panic!("{:?}", step.outcome);
        };
        let (digest, named, areas): (Vec<u8>, u64, u64) = decode(&reply).unwrap();
        let bytes: Vec<u8> = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        let expected: [u8; 32] = Blake2b::<U32>::new()
            .chain_update(b"kernels")
            .chain_update(&bytes)
            .finalize()
            .into();
        assert_eq!(digest, expected);
        let arms: [(u64, u64); 12] = [
            (0x1111, 3),
            (0x2345, 5),
            (0x3579, 7),
            (0x4bcd, 9),
            (0x5e0f, 11),
            (0x6a1b, 13),
            (0x7c2d, 15),
            (0x8e3f, 17),
            (0x9041, 19),
            (0xa253, 21),
            (0xb465, 23),
            (0xc677, 25),
        ];
        let (constant, factor) = arms[values.len() % 12];
        let x = values.len() as u64;
        assert_eq!(named, (x ^ constant).wrapping_mul(factor));
        let area = |side: u64| -> u64 {
            let scale = side + 1;
            match side % 3 {
                0 => side.wrapping_mul(side).wrapping_mul(scale),
                1 => side.wrapping_mul(scale).wrapping_add(1),
                _ => side.wrapping_sub(side / 2).wrapping_mul(scale) ^ 0x5a,
            }
        };
        assert_eq!(
            areas,
            values
                .iter()
                .map(|&side| area(side))
                .fold(0, u64::wrapping_add)
        );
        assert_eq!(step.attests.len(), 3);
    }
    // Each kernel holds its own method's code: none is another's.
    let hashes: BTreeMap<String, u32> = derived
        .kernels
        .iter()
        .map(|(method, kernel)| (digest(kernel), *method))
        .collect();
    assert_eq!(hashes.len(), 3);
    for (_, kernel) in &derived.kernels {
        assert!(kernel.len() < program.len(), "a kernel is pruned");
    }
}

/// A package whose attestable method reaches a host call other than a
/// precompile derives no kernel: the error names the chain of functions
/// from the entry to the call.
#[test]
fn a_kernel_making_a_host_call_is_refused() {
    let error = derive(&package("tainted")).unwrap_err();
    let DeriveError::HostCall { id, chain, .. } = &error else {
        panic!("{error}");
    };
    assert_eq!(*id, vos_wire::abi::Op::Now.id());
    assert!(chain[0].ends_with("__vos_attest_stamp"), "{chain:?}");
    assert!(
        chain.iter().any(|name| name.contains("stamped")),
        "{chain:?}"
    );
    println!("{error}");
}

/// An ELF that is no package: the default agent has no schema; a package
/// stripped of its relocations cannot be pruned soundly.
#[test]
fn what_is_no_package_is_refused() {
    let agent = std::fs::read(vos_testkit::programs::agent_elf()).unwrap();
    assert!(matches!(derive(&agent), Err(DeriveError::NoSchema)));
    let mut stripped = package("ledger");
    strip_relocations(&mut stripped);
    assert!(matches!(derive(&stripped), Err(DeriveError::NoRelocations)));
    assert!(matches!(
        derive(&vec![0; vos_pvm_compiler::MAX_ELF + 1]),
        Err(DeriveError::TooLarge(_))
    ));
}

/// A little-endian field of `len` bytes at `at`.
fn field(elf: &[u8], at: usize, len: usize) -> usize {
    let mut bytes = [0u8; 8];
    bytes[..len].copy_from_slice(&elf[at..at + len]);
    u64::from_le_bytes(bytes) as usize
}

/// Each section's header offset, type, file offset and size, of the
/// section headers the file holds.
fn sections(elf: &[u8]) -> Vec<(usize, usize, usize, usize)> {
    if elf.len() < 64 {
        return Vec::new();
    }
    let (shoff, shentsize, shnum) = (field(elf, 40, 8), field(elf, 58, 2), field(elf, 60, 2));
    (0..shnum)
        .map(|index| shoff.saturating_add(index.saturating_mul(shentsize)))
        .take_while(|header| header.saturating_add(64) <= elf.len())
        .map(|header| {
            let kind = field(elf, header + 4, 4);
            (
                header,
                kind,
                field(elf, header + 24, 8),
                field(elf, header + 32, 8),
            )
        })
        .collect()
}

/// The relocation types an ELF holds.
fn relocation_kinds(elf: &[u8]) -> std::collections::BTreeSet<u32> {
    sections(elf)
        .into_iter()
        .filter(|&(_, kind, _, _)| kind == 4)
        .flat_map(|(_, _, offset, size)| {
            elf[offset..offset + size]
                .chunks_exact(24)
                .map(|entry| u32::from_le_bytes(entry[8..12].try_into().unwrap()))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Mark every relocation section of an ELF as no section at all.
fn strip_relocations(elf: &mut [u8]) {
    for (header, kind, _, _) in sections(elf) {
        if kind == 4 {
            elf[header + 4..header + 8].copy_from_slice(&0u32.to_le_bytes());
        }
    }
}

/// A package's bytes mutated where a parser reads them: an entry of its
/// symbol or relocation tables, a field of its section table, its code
/// and data anywhere, and rarely its header or a cut.
#[derive(Clone, Debug)]
enum Mutation {
    /// A field of an entry of a symbol table (2) or a relocation table (4).
    Entry {
        kind: usize,
        index: usize,
        field: usize,
        value: u64,
    },
    Section {
        index: usize,
        field: usize,
        value: u64,
    },
    Flip {
        at: usize,
        bit: u8,
    },
    Word {
        at: usize,
        value: u64,
    },
    Header {
        at: usize,
        value: u64,
    },
    Cut {
        len: usize,
    },
}

/// A value a field might hold: small, near the addresses a program uses,
/// or anything.
fn value() -> impl Strategy<Value = u64> {
    prop_oneof![
        0..64u64,
        0x1_0000..0x10_0000u64,
        0xd_0000..0xf_0000u64,
        any::<u64>(),
    ]
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        4 => (prop::sample::select(vec![2usize, 4]), any::<usize>(), 0..3usize, value()).prop_map(
            |(kind, index, field, value)| Mutation::Entry {
                kind,
                index,
                field,
                value
            }
        ),
        3 => (0..64usize, 0..8usize, value())
            .prop_map(|(index, field, value)| Mutation::Section { index, field, value }),
        3 => (any::<usize>(), 0..8u8).prop_map(|(at, bit)| Mutation::Flip { at, bit }),
        2 => (any::<usize>(), value()).prop_map(|(at, value)| Mutation::Word { at, value }),
        1 => (0..64usize, value()).prop_map(|(at, value)| Mutation::Header { at, value }),
        1 => any::<usize>().prop_map(|len| Mutation::Cut { len }),
    ]
}

fn mutate(elf: &mut Vec<u8>, mutation: &Mutation) {
    let len = elf.len();
    let write = |elf: &mut Vec<u8>, at: usize, value: u64| {
        if at.saturating_add(8) <= elf.len() {
            elf[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
    };
    match *mutation {
        Mutation::Entry {
            kind,
            index,
            field,
            value,
        } => {
            let tables: Vec<_> = sections(elf)
                .into_iter()
                .filter(|&(_, of, offset, size)| {
                    of == kind && size >= 24 && offset.saturating_add(size) <= len
                })
                .collect();
            if let Some(&(_, _, offset, size)) = tables.get(index % tables.len().max(1)) {
                let entry = offset + (index / 7 % (size / 24)) * 24;
                write(elf, entry + field * 8, value);
            }
        }
        Mutation::Section {
            index,
            field,
            value,
        } => {
            let (shoff, shnum) = (field_or(elf, 40, 8), field_or(elf, 60, 2));
            let header = shoff.saturating_add((index % shnum.max(1)) * 64 + field * 8);
            write(elf, header, value);
        }
        Mutation::Flip { at, bit } => elf[at % len] ^= 1 << bit,
        Mutation::Word { at, value } => write(elf, at % len, value),
        Mutation::Header { at, value } => write(elf, at, value),
        Mutation::Cut { len: cut } => elf.truncate(cut % len),
    }
}

/// A field of a header the mutations may have broken, or 0.
fn field_or(elf: &[u8], at: usize, len: usize) -> usize {
    if at + len <= elf.len() {
        field(elf, at, len)
    } else {
        0
    }
}

/// The cases the fuzz runs: 256 in the suite. A longer run, as before a
/// release: `VOS_DERIVE_FUZZ_CASES=20000 cargo test -p vos-testkit --test
/// derive a_mutated_package`.
fn cases() -> u32 {
    std::env::var("VOS_DERIVE_FUZZ_CASES")
        .ok()
        .and_then(|cases| cases.parse().ok())
        .unwrap_or(256)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// Mutated packages derive or are refused, and never panic: every field
    /// a parser reads is checked against the file and the derivation's
    /// limits.
    #[test]
    fn a_mutated_package_never_panics(
        name in prop::sample::select(vec!["ledger", "kernels", "caller", "tainted"]),
        mutations in prop::collection::vec(mutation(), 1..6),
    ) {
        let mut elf = package(name);
        for mutation in &mutations {
            if elf.len() < 64 {
                break;
            }
            mutate(&mut elf, mutation);
        }
        let _ = derive(&elf);
    }
}

/// The test actors' ELFs are where the derivation reads them.
#[test]
fn every_package_is_built() {
    for name in PACKAGES.into_iter().chain(["tainted"]) {
        assert!(actor_elf(name).exists(), "{name}");
    }
}
