//! A derivation's work stays bounded however an ELF is shaped within its
//! limits: a crafted package of megabytes of code-like data and of a jump
//! table of hundreds of thousands of relative entries derives in seconds,
//! where a search per entry would take minutes. And a crafted kernel that
//! jumps into the prologue its derivation adds is refused.

use std::time::{Duration, Instant};

use vos_pvm_compiler::derive;

const SCHEMA: u64 = 0x1_0000;
const TEXT: u64 = 0x100_0000;
/// Eight-byte words in data, each equal to a code address no relocation
/// names: plain data, kept as it is.
const WORDS: usize = 1 << 20;
/// A jump table's relative entries, each an ADD32 and SUB32 pair.
const ENTRIES: usize = 200_000;

const RA: u32 = 1;
const T0: u32 = 5;
const A0: u32 = 10;

fn i_type(opcode: u32, funct3: u32, rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

/// `jal rd, offset`.
fn jal(rd: u32, offset: i32) -> u32 {
    let o = offset as u32;
    (((o >> 20) & 1) << 31)
        | (((o >> 1) & 0x3ff) << 21)
        | (((o >> 11) & 1) << 20)
        | (((o >> 12) & 0xff) << 12)
        | (rd << 7)
        | 0x6f
}

/// Section types: program bits, a symbol table, a string table, and
/// relocations with addends.
const PROGBITS: u32 = 1;
const SYMTAB: u32 = 2;
const STRTAB: u32 = 3;
const RELA: u32 = 4;
/// Section flags: loaded, and executed.
const ALLOC: u64 = 2;
const EXECUTE: u64 = 4;

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

impl Section {
    /// Loaded bytes at `address`, with `flags` beside `ALLOC`.
    fn loaded(name: &'static str, flags: u64, address: u64, bytes: Vec<u8>) -> Self {
        Self {
            name,
            kind: PROGBITS,
            flags: ALLOC | flags,
            address,
            bytes,
            link: 0,
            info: 0,
        }
    }

    /// A table the program does not load: of `kind`, linked to section
    /// `link`, and applying to section `info`.
    fn table(name: &'static str, kind: u32, bytes: Vec<u8>, link: u32, info: u32) -> Self {
        Self {
            name,
            kind,
            flags: 0,
            address: 0,
            bytes,
            link,
            info,
        }
    }
}

/// A section header for `section`, its name at `name` of the names' table
/// and its bytes at `at` of the file.
fn header(file: &mut Vec<u8>, section: &Section, name: u32, at: u64) {
    let mut h = [0u8; 64];
    h[0..4].copy_from_slice(&name.to_le_bytes());
    h[4..8].copy_from_slice(&section.kind.to_le_bytes());
    h[8..16].copy_from_slice(&section.flags.to_le_bytes());
    h[16..24].copy_from_slice(&section.address.to_le_bytes());
    h[24..32].copy_from_slice(&at.to_le_bytes());
    h[32..40].copy_from_slice(&(section.bytes.len() as u64).to_le_bytes());
    h[40..44].copy_from_slice(&section.link.to_le_bytes());
    h[44..48].copy_from_slice(&section.info.to_le_bytes());
    file.extend_from_slice(&h);
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
    header(&mut file, &Section::table("", 0, Vec::new(), 0, 0), 0, 0);
    for (section, (name, at)) in sections.iter().zip(&offsets) {
        header(&mut file, section, *name, *at);
    }
    let shstrtab = Section::table(".shstrtab", STRTAB, names, 0, 0);
    header(&mut file, &shstrtab, names_name, names_at);
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
    let schema = no_methods();
    let rodata_at = SCHEMA + schema.len() as u64;
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
            Section::loaded(".vos_schema", 0, SCHEMA, schema),
            Section::loaded(".rodata", 0, rodata_at, rodata),
            Section::loaded(".text", EXECUTE, TEXT, code),
            Section::table(".symtab", SYMTAB, symtab, 5, 0),
            Section::table(".strtab", STRTAB, strtab, 0, 0),
            Section::table(".rela.text", RELA, text_relocations, 4, 3),
            Section::table(".rela.rodata", RELA, data_relocations, 4, 2),
        ],
    )
}

#[test]
fn a_crafted_package_derives_in_bounded_time() {
    let elf = crafted();
    let started = Instant::now();
    let derived = derive(&elf).expect("derives");
    let took = started.elapsed();
    assert_eq!(derived.kernels.len(), 1);
    assert!(
        derived.kernels[0].1.len() > 8 * WORDS,
        "the kernel holds the words its entry reads"
    );
    assert!(
        took < Duration::from_secs(30),
        "{} MiB package, {WORDS} code-like words, {ENTRIES} jump table entries: derived in {took:?}",
        elf.len() >> 20
    );
}

/// A kernel's prologue, which its derivation places at the first 16-byte
/// boundary past the code, calls the entry by an AUIPC and JALR pair. Code
/// that jumps there jumps past every code section of the whole program, so
/// the derivation refuses it at the program's own link, before its kernels'
/// (whose link refuses a target that splits a call pair).
#[test]
fn a_kernel_jumping_into_its_prologue_is_refused() {
    // `_start` returns; the entry jumps to the prologue's JALR, at the
    // prologue (TEXT + 16) plus 80.
    let start = TEXT;
    let entry = TEXT + 4;
    let code: Vec<u8> = [
        i_type(0x67, 0, 0, RA, 0), // _start: ret
        jal(0, 92),                // entry: j TEXT + 96
        i_type(0x67, 0, 0, RA, 0),
        i_type(0x67, 0, 0, RA, 0),
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect();
    let schema = no_methods();
    let attest = SCHEMA + schema.len() as u64;
    let rodata = [1u64.to_le_bytes(), entry.to_le_bytes()].concat();
    let strtab = b"\0entry\0_start\0VOS_ATTEST\0".to_vec();
    let symtab = [
        symbol(0, 0, 0, 0),
        symbol(1, 2, entry, 4),
        symbol(7, 2, start, 4),
        symbol(14, 1, attest, 16),
    ]
    .concat();
    let elf = elf(
        start,
        vec![
            Section::loaded(".vos_schema", 0, SCHEMA, schema),
            Section::loaded(".rodata", 0, attest, rodata),
            Section::loaded(".text", EXECUTE, TEXT, code),
            Section::table(".symtab", SYMTAB, symtab, 5, 0),
            Section::table(".strtab", STRTAB, strtab, 0, 0),
            // R_RISCV_64 of the entry, in the attestables' table.
            Section::table(".rela.rodata", RELA, relocation(attest + 8, 1, 2, 0), 4, 2),
        ],
    );
    let refused = derive(&elf).expect_err("a jump past the code is refused");
    assert!(
        refused
            .to_string()
            .contains(&format!("unresolved branch target {:#x}", TEXT + 96)),
        "{refused}"
    );
}

/// A schema section of no method, padded to eight bytes: it reads, and
/// declares no method `Reading`.
fn no_methods() -> Vec<u8> {
    [
        b"VOSS".as_slice(),
        &4u32.to_le_bytes(),
        &0u32.to_le_bytes(),
        &[0; 4],
    ]
    .concat()
}

/// `elf` with every code section's header naming the first one's bytes.
fn aliased(mut elf: Vec<u8>) -> Vec<u8> {
    let field = |elf: &[u8], at: usize| u64::from_le_bytes(elf[at..at + 8].try_into().unwrap());
    let table = field(&elf, 40) as usize;
    let count = u16::from_le_bytes(elf[60..62].try_into().unwrap()) as usize;
    let mut first: Option<Vec<u8>> = None;
    for index in 0..count {
        let header = table + 64 * index;
        if field(&elf, header + 8) & EXECUTE == 0 {
            continue;
        }
        match &first {
            None => first = Some(elf[header + 24..header + 40].to_vec()),
            Some(span) => elf[header + 24..header + 40].copy_from_slice(span),
        }
    }
    elf
}

/// Code sections that all name one span of the file are refused as they
/// are parsed: 4,093 of them over 64 KiB would copy 256 MiB.
#[test]
fn sections_sharing_the_files_bytes_are_refused() {
    let mut sections = vec![Section::loaded(".text", EXECUTE, TEXT, vec![0; 1 << 16])];
    for _ in 0..4093 {
        sections.push(Section::loaded(".text", EXECUTE, TEXT, Vec::new()));
    }
    let elf = aliased(elf(TEXT, sections));
    let started = Instant::now();
    let refused = derive(&elf).expect_err("shared bytes are refused");
    assert!(
        refused.to_string().contains("share the file's bytes"),
        "{refused}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

/// Read-only data linked just under the address space's top is refused
/// before the blob's padding to it is allocated.
#[test]
fn read_only_data_linked_far_up_is_refused() {
    let code: Vec<u8> = i_type(0x67, 0, 0, RA, 0).to_le_bytes().to_vec();
    let elf = elf(
        TEXT,
        vec![
            Section::loaded(".rodata", 0, 0xFFFF_F000, vec![1]),
            Section::loaded(".text", EXECUTE, TEXT, code),
        ],
    );
    let refused = vos_pvm_compiler::link_elf_spi(&elf).expect_err("refused");
    assert!(refused.to_string().contains("far past"), "{refused}");
}

/// A package of `methods` attestable methods, each naming the one entry,
/// over read-only data with one byte linked at `high`.
fn many_kernels(methods: u64, high: u64) -> Vec<u8> {
    let start = TEXT;
    let entry = TEXT + 4;
    let code: Vec<u8> = [i_type(0x67, 0, 0, RA, 0), i_type(0x67, 0, 0, RA, 0)]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let schema = no_methods();
    let attest = SCHEMA + schema.len() as u64;
    let table: Vec<u8> = (1..=methods)
        .flat_map(|method| [method.to_le_bytes(), entry.to_le_bytes()])
        .flatten()
        .collect();
    let strtab = b"\0entry\0_start\0VOS_ATTEST\0".to_vec();
    let symtab = [
        symbol(0, 0, 0, 0),
        symbol(1, 2, entry, 4),
        symbol(7, 2, start, 4),
        symbol(14, 1, attest, 16 * methods),
    ]
    .concat();
    elf(
        start,
        vec![
            Section::loaded(".vos_schema", 0, SCHEMA, schema),
            Section::loaded(".rodata", 0, attest, table),
            Section::loaded(".rodata.high", 0, high, vec![1]),
            Section::loaded(".text", EXECUTE, TEXT, code),
            Section::table(".symtab", SYMTAB, symtab, 6, 0),
            Section::table(".strtab", STRTAB, strtab, 0, 0),
            // R_RISCV_64 of the entry, in the attestables' table.
            Section::table(".rela.rodata", RELA, relocation(attest + 8, 1, 2, 0), 5, 2),
        ],
    )
}

/// 1,024 kernels of one entry, each holding read-only data that spans
/// 15 MiB, pass what a derivation holds: refused as they are made.
#[test]
fn kernels_past_what_a_derivation_holds_are_refused() {
    let elf = many_kernels(1024, 0xF0_0000);
    let started = Instant::now();
    match derive(&elf) {
        Err(vos_pvm_compiler::DeriveError::Derived(held)) => {
            assert!(held > vos_pvm_compiler::MAX_DERIVED)
        }
        other => panic!("{:?}", other.map(|derived| derived.kernels.len())),
    }
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "{:?}",
        started.elapsed()
    );
}

/// `2^16` function symbols, one at each instruction of a chain of jumps
/// and each sized to the code's end, so their ranges all overlap: the
/// entry's walk reads each instruction once, not once for each range
/// holding it.
#[test]
fn overlapping_functions_are_walked_once() {
    const FUNCTIONS: u64 = 1 << 16;
    let start = TEXT;
    let entry = TEXT + 4;
    let end = entry + 4 * FUNCTIONS;
    let code: Vec<u8> = std::iter::once(i_type(0x67, 0, 0, RA, 0))
        .chain((1..FUNCTIONS).map(|_| jal(0, 4)))
        .chain(std::iter::once(i_type(0x67, 0, 0, RA, 0)))
        .flat_map(u32::to_le_bytes)
        .collect();
    let schema = no_methods();
    let attest = SCHEMA + schema.len() as u64;
    let table = [1u64.to_le_bytes(), entry.to_le_bytes()].concat();
    let strtab = b"\0entry\0_start\0VOS_ATTEST\0".to_vec();
    let mut symtab = [
        symbol(0, 0, 0, 0),
        symbol(7, 2, start, 4),
        symbol(14, 1, attest, 16),
    ]
    .concat();
    for at in (entry..end).step_by(4) {
        symtab.extend(symbol(1, 2, at, end - at));
    }
    let elf = elf(
        start,
        vec![
            Section::loaded(".vos_schema", 0, SCHEMA, schema),
            Section::loaded(".rodata", 0, attest, table),
            Section::loaded(".text", EXECUTE, TEXT, code),
            Section::table(".symtab", SYMTAB, symtab, 5, 0),
            Section::table(".strtab", STRTAB, strtab, 0, 0),
            // R_RISCV_64 of the entry, in the attestables' table.
            Section::table(".rela.rodata", RELA, relocation(attest + 8, 3, 2, 0), 4, 2),
        ],
    );
    let started = Instant::now();
    let derived = derive(&elf).expect("derives");
    let took = started.elapsed();
    assert_eq!(derived.kernels.len(), 1);
    assert!(
        took < Duration::from_secs(30),
        "{FUNCTIONS} overlapping functions: {took:?}"
    );
}

/// A package whose read-only data holds, past its attestables' table, a
/// plain word equal to its entry's address, and `debug`, sections the
/// program does not load.
fn package_with(debug: Vec<Section>) -> Vec<u8> {
    let start = TEXT;
    let entry = TEXT + 4;
    let code: Vec<u8> = [i_type(0x67, 0, 0, RA, 0), i_type(0x67, 0, 0, RA, 0)]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let schema = no_methods();
    let attest = SCHEMA + schema.len() as u64;
    let rodata = [1u64, entry, entry].map(u64::to_le_bytes).concat();
    let strtab = b"\0entry\0_start\0VOS_ATTEST\0".to_vec();
    let symtab = [
        symbol(0, 0, 0, 0),
        symbol(1, 2, entry, 4),
        symbol(7, 2, start, 4),
        symbol(14, 1, attest, 16),
    ]
    .concat();
    let mut sections = vec![
        Section::loaded(".vos_schema", 0, SCHEMA, schema),
        Section::loaded(".rodata", 0, attest, rodata),
        Section::loaded(".text", EXECUTE, TEXT, code),
        Section::table(".symtab", SYMTAB, symtab, 5, 0),
        Section::table(".strtab", STRTAB, strtab, 0, 0),
        // R_RISCV_64 of the entry, in the attestables' table.
        Section::table(".rela.rodata", RELA, relocation(attest + 8, 1, 2, 0), 4, 2),
    ];
    sections.extend(debug);
    elf(start, sections)
}

/// Relocations in a section the program does not load, as debug
/// information, change nothing derived: their offsets are no program
/// addresses, though one here equals the plain word's and one a code
/// address, and both name the entry.
#[test]
fn relocations_of_an_unloaded_section_change_nothing() {
    let attest = SCHEMA + no_methods().len() as u64;
    let plain = package_with(Vec::new());
    let debug = package_with(vec![
        Section::table(".debug_info", PROGBITS, vec![0; 64], 0, 0),
        Section::table(
            ".rela.debug_info",
            RELA,
            [
                relocation(attest + 16, 1, 2, 0), // R_RISCV_64 at the plain word
                relocation(TEXT + 4, 1, 23, 0),   // PCREL_HI20 at the entry
                relocation(TEXT, 1, 19, 0),       // CALL_PLT at `_start`
            ]
            .concat(),
            4,
            7,
        ),
    ]);
    let (plain, debug) = (
        derive(&plain).expect("derives"),
        derive(&debug).expect("derives"),
    );
    assert_eq!(
        (&plain.actor, &plain.kernels),
        (&debug.actor, &debug.kernels)
    );
}
