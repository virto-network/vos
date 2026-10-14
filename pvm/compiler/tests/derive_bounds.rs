//! A derivation's work stays bounded however an ELF is shaped within its
//! limits: a crafted package of megabytes of code-like data and of a jump
//! table of hundreds of thousands of relative entries derives in seconds,
//! where a search per entry would take minutes.

use std::time::{Duration, Instant};

use vos_pvm_compiler::derive;

const SCHEMA: u64 = 0x1_0000;
const TEXT: u64 = 0x100_0000;
/// Eight-byte words in data, each a code address no relocation names: what
/// the heuristic scan rewrites.
const WORDS: usize = 1 << 20;
/// A jump table's relative entries, each an ADD32 and SUB32 pair.
const ENTRIES: usize = 200_000;

const RA: u32 = 1;
const T0: u32 = 5;
const A0: u32 = 10;

fn i_type(opcode: u32, funct3: u32, rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

/// A section: its name, type, flags, address, contents, link and info.
struct Section {
    name: &'static str,
    kind: u32,
    flags: u64,
    address: u64,
    bytes: Vec<u8>,
    link: u32,
    info: u32,
}

/// An ELF64 of `sections`, a NULL section before them and the names'
/// table after.
fn elf(entry: u64, sections: Vec<Section>) -> Vec<u8> {
    let mut names = vec![0u8];
    let mut offsets = Vec::new();
    let mut file = vec![0u8; 64];
    for section in &sections {
        offsets.push((names.len() as u32, file.len() as u64));
        names.extend_from_slice(section.name.as_bytes());
        names.push(0);
        file.extend_from_slice(&section.bytes);
        while !file.len().is_multiple_of(8) {
            file.push(0);
        }
    }
    let names_name = names.len() as u32;
    names.extend_from_slice(b".shstrtab\0");
    let names_at = file.len() as u64;
    file.extend_from_slice(&names);
    while !file.len().is_multiple_of(8) {
        file.push(0);
    }
    let table_at = file.len() as u64;
    let header = |file: &mut Vec<u8>,
                  name: u32,
                  kind: u32,
                  flags: u64,
                  address: u64,
                  at: u64,
                  size: u64,
                  link: u32,
                  info: u32| {
        let mut h = [0u8; 64];
        h[0..4].copy_from_slice(&name.to_le_bytes());
        h[4..8].copy_from_slice(&kind.to_le_bytes());
        h[8..16].copy_from_slice(&flags.to_le_bytes());
        h[16..24].copy_from_slice(&address.to_le_bytes());
        h[24..32].copy_from_slice(&at.to_le_bytes());
        h[32..40].copy_from_slice(&size.to_le_bytes());
        h[40..44].copy_from_slice(&link.to_le_bytes());
        h[44..48].copy_from_slice(&info.to_le_bytes());
        file.extend_from_slice(&h);
    };
    header(&mut file, 0, 0, 0, 0, 0, 0, 0, 0);
    for (section, (name, at)) in sections.iter().zip(&offsets) {
        header(
            &mut file,
            *name,
            section.kind,
            section.flags,
            section.address,
            *at,
            section.bytes.len() as u64,
            section.link,
            section.info,
        );
    }
    header(
        &mut file,
        names_name,
        3,
        0,
        0,
        names_at,
        names.len() as u64,
        0,
        0,
    );
    let count = sections.len() as u16 + 2;
    file[0..4].copy_from_slice(b"\x7fELF");
    file[4] = 2;
    file[5] = 1;
    file[24..32].copy_from_slice(&entry.to_le_bytes());
    file[40..48].copy_from_slice(&table_at.to_le_bytes());
    file[58..60].copy_from_slice(&64u16.to_le_bytes());
    file[60..62].copy_from_slice(&count.to_le_bytes());
    file[62..64].copy_from_slice(&(count - 1).to_le_bytes());
    file
}

fn symbol(name: u32, kind: u8, value: u64, size: u64) -> Vec<u8> {
    let mut entry = vec![0u8; 24];
    entry[0..4].copy_from_slice(&name.to_le_bytes());
    entry[4] = kind;
    entry[8..16].copy_from_slice(&value.to_le_bytes());
    entry[16..24].copy_from_slice(&size.to_le_bytes());
    entry
}

fn relocation(at: u64, symbol: u64, kind: u64, addend: i64) -> Vec<u8> {
    [
        at.to_le_bytes(),
        ((symbol << 32) | kind).to_le_bytes(),
        addend.to_le_bytes(),
    ]
    .concat()
}

/// A package whose one attestable's entry reads a table of `WORDS`
/// code-like words, beside a jump table of `ENTRIES` relative entries.
fn crafted() -> Vec<u8> {
    // Code: `_start` returns; the entry loads the table's address by a
    // PC-relative pair and returns.
    let start = TEXT;
    let entry = TEXT + 4;
    let code: Vec<u8> = [
        i_type(0x67, 0, 0, RA, 0), // _start: ret
        T0 << 7 | 0x17,            // auipc t0, table
        i_type(0x13, 0, T0, T0, 0),
        i_type(0x03, 3, A0, T0, 0), // ld a0, 0(t0)
        i_type(0x67, 0, 0, RA, 0),
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect();

    // Read-only data: the schema, then the attestables' table, the words
    // and the jump table.
    let schema = [b"VOSS".as_slice(), &0u32.to_le_bytes()].concat();
    let rodata_at = SCHEMA + 8;
    let attest = rodata_at;
    let words_at = attest + 16;
    let jumps_at = words_at + 8 * WORDS as u64;
    let mut rodata = Vec::new();
    rodata.extend_from_slice(&1u64.to_le_bytes());
    rodata.extend_from_slice(&entry.to_le_bytes());
    for _ in 0..WORDS {
        rodata.extend_from_slice(&entry.to_le_bytes());
    }
    for _ in 0..ENTRIES {
        rodata.extend_from_slice(&((entry - jumps_at) as u32).to_le_bytes());
    }

    // Symbols: the entry, `_start`, the table `VOS_ATTEST`, the words, the
    // jump table and the PC-relative pair's label.
    let strtab = b"\0entry\0_start\0VOS_ATTEST\0words\0jumps\0.Lpcrel\0".to_vec();
    let symtab = [
        symbol(0, 0, 0, 0),
        symbol(1, 2, entry, 16),
        symbol(7, 2, start, 4),
        symbol(14, 1, attest, 16),
        symbol(25, 1, words_at, 8 * WORDS as u64),
        symbol(31, 1, jumps_at, 4 * ENTRIES as u64),
        symbol(37, 0, entry, 0),
    ]
    .concat();
    let text_relocations = [
        relocation(entry, 4, 23, 0),     // PCREL_HI20 to the words
        relocation(entry + 4, 6, 24, 0), // PCREL_LO12_I by its label
    ]
    .concat();
    let mut data_relocations = relocation(attest + 8, 1, 2, 0); // R_RISCV_64
    for index in 0..ENTRIES as u64 {
        let at = jumps_at + 4 * index;
        data_relocations.extend(relocation(at, 1, 35, 0)); // ADD32 the entry
        data_relocations.extend(relocation(at, 5, 39, 0)); // SUB32 the table
    }
    elf(
        start,
        vec![
            Section {
                name: ".vos_schema",
                kind: 1,
                flags: 2,
                address: SCHEMA,
                bytes: schema,
                link: 0,
                info: 0,
            },
            Section {
                name: ".rodata",
                kind: 1,
                flags: 2,
                address: rodata_at,
                bytes: rodata,
                link: 0,
                info: 0,
            },
            Section {
                name: ".text",
                kind: 1,
                flags: 6,
                address: TEXT,
                bytes: code,
                link: 0,
                info: 0,
            },
            Section {
                name: ".symtab",
                kind: 2,
                flags: 0,
                address: 0,
                bytes: symtab,
                link: 5,
                info: 0,
            },
            Section {
                name: ".strtab",
                kind: 3,
                flags: 0,
                address: 0,
                bytes: strtab,
                link: 0,
                info: 0,
            },
            Section {
                name: ".rela.text",
                kind: 4,
                flags: 0,
                address: 0,
                bytes: text_relocations,
                link: 4,
                info: 3,
            },
            Section {
                name: ".rela.rodata",
                kind: 4,
                flags: 0,
                address: 0,
                bytes: data_relocations,
                link: 4,
                info: 2,
            },
        ],
    )
}

#[test]
fn a_crafted_package_derives_in_bounded_time() {
    let elf = crafted();
    let started = Instant::now();
    let derived = derive(&elf).expect("derives");
    let took = started.elapsed();
    println!(
        "{} MiB package, {WORDS} code-like words, {ENTRIES} jump table entries: derived in {took:?}",
        elf.len() >> 20
    );
    assert_eq!(derived.kernels.len(), 1);
    assert!(
        derived.kernels[0].1.len() > 8 * WORDS,
        "the kernel holds the words its entry reads"
    );
    assert!(took < Duration::from_secs(30), "{took:?}");
}
