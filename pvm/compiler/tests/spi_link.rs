//! `link_elf_spi` end-to-end: transpile hand-assembled rv64em ELFs into GP
//! standard-program (SPI) blobs and validate them against vos_pvm — the parser
//! (`spi::parse_standard_program`), the GP layout (`StandardProgram::layout`),
//! and the kernel-free Refine harness (`vos_pvm::refine`). The retired
//! JAR/capability-kernel profile is deliberately not an oracle or fallback.
//!
//! The guests follow the zero-hostcall refine convention, which is
//! backend-portable: arguments arrive as `φ7 = ptr` / `φ8 = len`, output is
//! designated by leaving `φ7`/`φ8` pointing at readable bytes, and the guest
//! exits by returning through `φ0` (the host-installed halt address).

use vos_pvm::refine::{self, MemoryModel};
use vos_pvm::spi::parse_standard_program;
use vos_pvm::{ExitReason, PVM_HALT_ADDR, PVM_INIT_INPUT_SIZE, PVM_ZONE_SIZE};
use vos_pvm_compiler::{TranspileError, link_elf_spi};

const GAS: u64 = 10_000_000;

// ---------------------------------------------------------------------------
// Minimal rv64em ELF synthesis (just enough for the linker's parser).
// ---------------------------------------------------------------------------

/// One ELF section: (name, sh_type, sh_flags, vaddr, contents).
type Section<'a> = (&'a str, u32, u64, u64, &'a [u8]);

/// Build a minimal ELF64 (little-endian, RISC-V) image from `sections`,
/// with `entry` as `e_entry`. A NULL section and the `.shstrtab` are added
/// automatically.
fn build_elf(entry: u64, sections: &[Section<'_>]) -> Vec<u8> {
    // Section-name string table: NUL, then each name NUL-terminated.
    let mut shstrtab = vec![0u8];
    let mut name_offsets = Vec::new();
    for (name, ..) in sections {
        name_offsets.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(name.as_bytes());
        shstrtab.push(0);
    }
    let shstrtab_name_off = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");

    // File layout: ELF header, section contents, shstrtab, section headers.
    let mut file = vec![0u8; 64];
    let mut offsets = Vec::new();
    for (_, _, _, _, data) in sections {
        offsets.push(file.len() as u64);
        file.extend_from_slice(data);
    }
    let shstrtab_off = file.len() as u64;
    file.extend_from_slice(&shstrtab);
    let e_shoff = file.len() as u64;

    // Section headers: NULL, the given sections, .shstrtab.
    let shnum = sections.len() as u16 + 2;
    let mut shdr = |name_off: u32, sh_type: u32, flags: u64, addr: u64, off: u64, size: u64| {
        let mut h = [0u8; 64];
        h[0..4].copy_from_slice(&name_off.to_le_bytes());
        h[4..8].copy_from_slice(&sh_type.to_le_bytes());
        h[8..16].copy_from_slice(&flags.to_le_bytes());
        h[16..24].copy_from_slice(&addr.to_le_bytes());
        h[24..32].copy_from_slice(&off.to_le_bytes());
        h[32..40].copy_from_slice(&size.to_le_bytes());
        file.extend_from_slice(&h);
    };
    shdr(0, 0, 0, 0, 0, 0); // NULL
    for (i, (_, sh_type, flags, addr, data)) in sections.iter().enumerate() {
        shdr(
            name_offsets[i],
            *sh_type,
            *flags,
            *addr,
            offsets[i],
            data.len() as u64,
        );
    }
    shdr(
        shstrtab_name_off,
        3, // STRTAB
        0,
        0,
        shstrtab_off,
        shstrtab.len() as u64,
    );

    // ELF header (only the fields parse_linked_elf reads).
    file[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    file[4] = 2; // ELFCLASS64
    file[5] = 1; // little-endian
    file[24..32].copy_from_slice(&entry.to_le_bytes());
    file[40..48].copy_from_slice(&e_shoff.to_le_bytes());
    file[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    file[60..62].copy_from_slice(&shnum.to_le_bytes());
    file[62..64].copy_from_slice(&(shnum - 1).to_le_bytes()); // e_shstrndx
    file
}

// ---------------------------------------------------------------------------
// Hand assembler for the handful of rv64em instructions the guests use.
// ---------------------------------------------------------------------------

const RA: u32 = 1;
const SP: u32 = 2;
const T0: u32 = 5; // → φ2
const T1: u32 = 6; // → φ3
const T2: u32 = 7; // → φ4
const A0: u32 = 10; // → φ7
const A1: u32 = 11; // → φ8
const A2: u32 = 12; // → φ9

fn lui(rd: u32, imm20: u32) -> u32 {
    (imm20 << 12) | (rd << 7) | 0x37
}
fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0xFFF) << 20) | (rs1 << 15) | (rd << 7) | 0x13
}
fn ld(rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0xFFF) << 20) | (rs1 << 15) | (3 << 12) | (rd << 7) | 0x03
}
fn lbu(rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0xFFF) << 20) | (rs1 << 15) | (4 << 12) | (rd << 7) | 0x03
}
fn add(rd: u32, rs1: u32, rs2: u32) -> u32 {
    (rs2 << 20) | (rs1 << 15) | (rd << 7) | 0x33
}
fn beq(rs1: u32, rs2: u32, imm: i32) -> u32 {
    let i = imm as u32;
    (((i >> 12) & 1) << 31)
        | (((i >> 5) & 0x3f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (((i >> 1) & 0xf) << 8)
        | (((i >> 11) & 1) << 7)
        | 0x63
}
fn jal(rd: u32, imm: i32) -> u32 {
    let i = imm as u32;
    (((i >> 20) & 1) << 31)
        | (((i >> 1) & 0x3ff) << 21)
        | (((i >> 11) & 1) << 20)
        | (((i >> 12) & 0xff) << 12)
        | (rd << 7)
        | 0x6f
}
fn jalr(rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0x67
}
fn sb(rs2: u32, rs1: u32, imm: i32) -> u32 {
    let i = imm as u32 & 0xfff;
    ((i >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | ((i & 0x1f) << 7) | 0x23
}
fn sd(rs2: u32, rs1: u32, imm: i32) -> u32 {
    let i = imm as u32 & 0xFFF;
    ((i >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (3 << 12) | ((i & 0x1F) << 7) | 0x23
}
/// `ret` = `jalr x0, 0(ra)` — a djump through φ0, the halt address.
fn ret() -> u32 {
    (RA << 15) | 0x67
}

fn assemble(insts: &[u32]) -> Vec<u8> {
    insts.iter().flat_map(|i| i.to_le_bytes()).collect()
}

#[test]
fn relocated_relative_table_value_is_not_a_raw_call_interior_pointer() {
    const TEXT: u64 = 0x40_0000;
    const TABLE: u64 = 0x1_0000;
    const CALLEE: u64 = TEXT + TABLE + 4;
    // target - table_base numerically equals the second instruction of a call.
    // It is a relocated four-byte offset, not an eight-byte absolute pointer.
    let mut instructions = vec![addi(0, 0, 0); ((CALLEE - TEXT) / 4 + 1) as usize];
    instructions[0] = (RA << 7) | 0x17;
    instructions[1] = jalr(RA, RA, 0);
    instructions[2] = jalr(0, RA, 0);
    *instructions.last_mut().unwrap() = jalr(0, RA, 0);
    let text = assemble(&instructions);
    let table = (CALLEE - TABLE).to_le_bytes();
    let mut symbols = vec![0; 3 * 24];
    symbols[24 + 8..24 + 16].copy_from_slice(&CALLEE.to_le_bytes());
    symbols[48 + 8..48 + 16].copy_from_slice(&TABLE.to_le_bytes());
    let relocation = |address: u64, symbol: u64, kind: u64| {
        [
            address.to_le_bytes(),
            ((symbol << 32) | kind).to_le_bytes(),
            0u64.to_le_bytes(),
        ]
        .concat()
    };
    let mut relocations = relocation(TEXT, 1, 19); // CALL_PLT
    let build = |relocations: &[u8]| {
        build_elf(
            TEXT,
            &[
                (".text", 1, 6, TEXT, &text),
                (".rodata", 1, 2, TABLE, &table),
                (".symtab", 2, 0, 0, &symbols),
                (".rela.text", 4, 0, 0, relocations),
            ],
        )
    };
    // Without data relocations this really is a claimed raw interior pointer;
    // do not weaken the existing fusion-safety rejection to fix the false hit.
    assert!(matches!(
        link_elf_spi(&build(&relocations)),
        Err(TranspileError::InvalidSection(_))
    ));
    relocations.extend(relocation(TABLE, 1, 35)); // ADD32 target
    relocations.extend(relocation(TABLE, 2, 39)); // SUB32 table base
    let blob = link_elf_spi(&build(&relocations)).expect("relative table must not split call pair");
    let parsed = parse_standard_program(&blob).expect("valid standard program");
    assert_eq!(
        &parsed.ro_data[4..8],
        &[0; 4],
        "four-byte relocation must not overwrite its neighbor"
    );
    assert_ne!(
        &parsed.ro_data[..4],
        &table[..4],
        "relative target must still be rewritten"
    );

    // A relocation covering only the high half also excludes the whole raw
    // eight-byte candidate, even when its symbolic target is not executable.
    // Both target discovery and pointer rewriting must honor that ownership.
    let mut high_half = relocation(TEXT, 1, 19);
    high_half.extend(relocation(TABLE + 4, 0, 1)); // ABS32 to null
    let blob = link_elf_spi(&build(&high_half)).expect("overlapping relocation excludes heuristic");
    let parsed = parse_standard_program(&blob).unwrap();
    assert_eq!(
        parsed.ro_data, table,
        "heuristic must not rewrite relocated scalar bytes"
    );
}

// ---------------------------------------------------------------------------
// The guests.
// ---------------------------------------------------------------------------

/// Code is linked away from data (its addresses are translated, never
/// materialized, so the value is arbitrary — chosen high to keep small
/// ro constants out of the code-pointer heuristic's range).
const TEXT_VADDR: u64 = 0x40_0000;
/// The GP read-only base `Z_Z`: where SPI guests must link `.rodata`.
const RO_VADDR: u64 = PVM_ZONE_SIZE as u64; // 0x1_0000
const RO_CONST: u64 = 0x0123_4567_89AB_CDEF;
const ARGS: [u8; 3] = [5, 0xAA, 0xBB];
const SUM: u64 = RO_CONST + ARGS[0] as u64;

/// A refine-convention guest: read `args[0]` via φ7, add a constant from
/// `.rodata` (linked at the GP ro base, so the absolute address resolves
/// under BOTH containers), store the sum on the (SP-relative) stack,
/// designate it as output via φ7/φ8, and return-to-halt.
fn checksum_guest_elf() -> Vec<u8> {
    let text = assemble(&[
        lui(T1, (RO_VADDR >> 12) as u32), // t1 = 0x1_0000 (ro base)
        ld(T2, T1, 0),                    // t2 = RO_CONST
        lbu(T0, A0, 0),                   // t0 = args[0]
        add(A2, T2, T0),                  // a2 = RO_CONST + args[0]
        sd(A2, SP, -8),                   // stack[-8] = a2
        addi(A0, SP, -8),                 // φ7 = output ptr
        addi(A1, 0, 8),                   // φ8 = output len
        ret(),
    ]);
    build_elf(
        TEXT_VADDR,
        &[
            (".text", 1, 0x6, TEXT_VADDR, &text), // PROGBITS, ALLOC|EXEC
            (".rodata", 1, 0x2, RO_VADDR, &RO_CONST.to_le_bytes()), // PROGBITS, ALLOC
        ],
    )
}

/// Two predecessors carry different stack offsets into one shared ADD. The
/// linear predecessor's load-immediate must never fuse into the targeted ADD:
/// doing so overwrites the other predecessor's live register value.
fn shared_consumer_diamond_elf() -> Vec<u8> {
    let text = assemble(&[
        lbu(T0, A0, 0),       //  0: select a predecessor
        beq(T0, 0, 16),       //  4: zero -> alternate at 20
        lui(A2, 0),           //  8: fallthrough offset producer
        addi(A2, A2, -0x1e0), // 12
        jal(0, 12),           // 16: join at 28 with a2 = -0x1e0
        lui(A2, 0),           // 20: alternate offset producer
        addi(A2, A2, -0x2d0), // 24
        add(A0, SP, A2),      // 28: shared, directly targeted consumer
        addi(T1, 0, 0x5a),    // 32
        sb(T1, A0, 0),        // 36: make the selected byte readable
        addi(A1, 0, 1),       // 40: one-byte output
        ret(),                // 44
    ]);
    build_elf(TEXT_VADDR, &[(".text", 1, 0x6, TEXT_VADDR, &text)])
}

/// A stripped direct call represented only by a raw AUIPC+JALR pair. Its
/// callee entry is also the consumer after an unrelated linear predecessor.
fn raw_direct_call_elf() -> Vec<u8> {
    let text = assemble(&[
        addi(T2, RA, 0),      //  0: preserve the host return address
        addi(A2, 0, -0x1e0),  //  4: caller's live stack offset
        0x0000_0297,          //  8: auipc t0, 0
        jalr(RA, T0, 24),     // 12: call target 32, return to 16
        addi(RA, T2, 0),      // 16: restore host return address
        ret(),                // 20
        lui(A2, 0),           // 24: unrelated linear predecessor
        addi(A2, A2, -0x2d0), // 28
        add(A0, SP, A2),      // 32: raw-pair-only callee entry
        addi(T1, 0, 0x5a),    // 36
        sb(T1, A0, 0),        // 40
        addi(A1, 0, 1),       // 44
        ret(),                // 48
    ]);
    build_elf(TEXT_VADDR, &[(".text", 1, 0x6, TEXT_VADDR, &text)])
}

/// A stripped code pointer materialized by raw AUIPC+ADDI before an indirect
/// call. The linker accepts this form without relocation metadata as well.
fn raw_materialized_pointer_call_elf() -> Vec<u8> {
    let text = assemble(&[
        addi(T2, RA, 0),      //  0: preserve the host return address
        addi(A2, 0, -0x1e0),  //  4: caller's live stack offset
        0x0000_0297,          //  8: auipc t0, 0
        addi(T0, T0, 28),     // 12: materialize callee entry 36
        jalr(RA, T0, 0),      // 16: indirect call, return to 20
        addi(RA, T2, 0),      // 20: restore host return address
        ret(),                // 24
        lui(A2, 0),           // 28: unrelated linear predecessor
        addi(A2, A2, -0x2d0), // 32
        add(A0, SP, A2),      // 36: materialized-pointer-only callee entry
        addi(T1, 0, 0x5a),    // 40
        sb(T1, A0, 0),        // 44
        addi(A1, 0, 1),       // 48
        ret(),                // 52
    ]);
    build_elf(TEXT_VADDR, &[(".text", 1, 0x6, TEXT_VADDR, &text)])
}

/// A stripped indirect call whose callee is discoverable only through a raw
/// initialized-data code pointer accepted by the linker's pointer rewriter.
fn raw_data_pointer_call_elf() -> Vec<u8> {
    let callee = TEXT_VADDR + 36;
    let pointer = callee.to_le_bytes();
    let text = assemble(&[
        addi(T2, RA, 0),      //  0: preserve the host return address
        lui(T0, 0x10),        //  4: raw pointer at 0x1_0000
        ld(T0, T0, 0),        //  8
        addi(A2, 0, -0x1e0),  // 12: caller's live stack offset
        jalr(RA, T0, 0),      // 16: indirect call, return to 20
        addi(RA, T2, 0),      // 20: restore host return address
        ret(),                // 24
        lui(A2, 0),           // 28: unrelated linear predecessor
        addi(A2, A2, -0x2d0), // 32
        add(A0, SP, A2),      // 36: raw-pointer-only callee entry
        addi(T1, 0, 0x5a),    // 40
        sb(T1, A0, 0),        // 44
        addi(A1, 0, 1),       // 48
        ret(),                // 52
    ]);
    build_elf(
        TEXT_VADDR,
        &[
            (".rodata", 1, 0x2, RO_VADDR, &pointer),
            (".text", 1, 0x6, TEXT_VADDR, &text),
        ],
    )
}

// ---------------------------------------------------------------------------
// (a) Round-trip: the emitted blob parses and lays out the intended zones.
// ---------------------------------------------------------------------------

#[test]
fn spi_blob_round_trips_and_lays_out_per_gp() {
    let z_z = PVM_ZONE_SIZE as u64;
    let z_i = PVM_INIT_INPUT_SIZE as u64;

    let blob = link_elf_spi(&checksum_guest_elf()).expect("links");
    let prog = parse_standard_program(&blob).expect("emitted blob parses");

    // Sections and header fields carry the linker's values (§ the mapping
    // documented on `link_elf_spi`): ro linked exactly at Z_Z needs no
    // padding; the stack byte capacity equals the standard program's declared
    // stack size; the heap page count is the linker's default 16.
    assert_eq!(prog.ro_data, RO_CONST.to_le_bytes());
    assert!(prog.rw_data.is_empty());
    assert_eq!(prog.stack_size as u64, z_z);
    assert_eq!(prog.heap_pages, 16);

    // The GP layout lands every region where the ELF was linked.
    let l = prog.layout(&ARGS).expect("lays out");
    assert_eq!(l.ro.base, z_z, "ro data at its linked vaddr");
    assert_eq!(l.ro.size, 0x1000);
    assert!(!l.ro.writable);
    assert_eq!(
        l.rw.base,
        2 * z_z + z_z,
        "rw base = 2*Z_Z + zone_round(|o|)"
    );
    assert_eq!(l.rw.size, 16 * 0x1000, "16 zeroed heap pages");
    assert!(l.rw.writable);
    let stack_top = (1u64 << 32) - 2 * z_z - z_i;
    assert_eq!(l.stack.base, stack_top - z_z);
    assert_eq!(l.stack.size, z_z);
    assert_eq!(l.args.base, (1u64 << 32) - z_z - z_i);
    assert_eq!(l.args.size, 0x1000);
    assert!(!l.args.writable);
    // Registers per GP eq A.43.
    assert_eq!(l.registers[0], PVM_HALT_ADDR);
    assert_eq!(l.registers[1], stack_top);
    assert_eq!(l.registers[7], l.args.base);
    assert_eq!(l.registers[8], ARGS.len() as u64);
}

#[test]
fn branch_target_preserves_each_predecessors_live_immediate() {
    let blob = link_elf_spi(&shared_consumer_diamond_elf()).expect("diamond links");

    for (argument, offset) in [(1u8, 0x1e0u64), (0, 0x2d0)] {
        let invocation = refine::execute(&blob, &[argument], GAS).expect("diamond executes");
        assert_eq!(invocation.exit, ExitReason::Halt);
        assert_eq!(invocation.output_bounded(1).as_deref(), Some(&[0x5a][..]));
        assert_eq!(
            invocation.registers[7],
            invocation.registers[1] - offset,
            "the shared ADD must consume the offset from its actual predecessor"
        );
    }
}

#[test]
fn stripped_direct_and_data_pointer_entries_preserve_live_inputs() {
    for elf in [
        raw_direct_call_elf(),
        raw_materialized_pointer_call_elf(),
        raw_data_pointer_call_elf(),
    ] {
        let blob = link_elf_spi(&elf).expect("stripped call links");
        let invocation = refine::execute(&blob, &[], GAS).expect("stripped call executes");
        assert_eq!(invocation.exit, ExitReason::Halt);
        assert_eq!(invocation.output_bounded(1).as_deref(), Some(&[0x5a][..]));
        assert_eq!(
            invocation.registers[7],
            invocation.registers[1] - 0x1e0,
            "callee must consume the caller's live offset"
        );
    }
}

/// `.rodata` linked above the GP base gets leading zero padding so it still
/// lands at its vaddr — and the program still executes correctly.
#[test]
fn ro_linked_above_base_gets_leading_padding() {
    let ro_vaddr = 0x1_2000u64;
    let text = assemble(&[
        lui(T1, (ro_vaddr >> 12) as u32),
        ld(T2, T1, 0),
        sd(T2, SP, -8),
        addi(A0, SP, -8),
        addi(A1, 0, 8),
        ret(),
    ]);
    let elf = build_elf(
        TEXT_VADDR,
        &[
            (".text", 1, 0x6, TEXT_VADDR, &text),
            (".rodata", 1, 0x2, ro_vaddr, &RO_CONST.to_le_bytes()),
        ],
    );

    let blob = link_elf_spi(&elf).expect("links");
    let prog = parse_standard_program(&blob).expect("parses");
    let pad = (ro_vaddr - PVM_ZONE_SIZE as u64) as usize;
    assert_eq!(prog.ro_data.len(), pad + 8);
    assert!(prog.ro_data[..pad].iter().all(|&b| b == 0));
    assert_eq!(prog.ro_data[pad..], RO_CONST.to_le_bytes());

    let inv = refine::execute(&blob, &[], GAS).expect("executes");
    assert_eq!(inv.exit, ExitReason::Halt);
    assert_eq!(
        inv.output_bounded(core::mem::size_of::<u64>()).as_deref(),
        Some(&RO_CONST.to_le_bytes()[..])
    );
}

/// `.data` is re-based to the GP rw base `2·Z_Z + zone_round(|o|)`: the
/// linker's inter-section padding is stripped, the section keeps its vaddr,
/// and the region is writable. This test pins the standard-program zone
/// placement independently of the retired capability-manifest layout.
#[test]
fn rw_data_lands_at_linked_vaddr_under_spi() {
    let rw_vaddr = 3 * PVM_ZONE_SIZE as u64; // 0x3_0000 (|o| = 8 → one ro zone)
    let rw_const = 0xFEED_FACE_CAFE_BEEFu64;
    let text = assemble(&[
        lui(T1, (rw_vaddr >> 12) as u32), // t1 = 0x3_0000
        ld(T2, T1, 0),                    // t2 = rw constant
        sd(T2, T1, 8),                    // prove the region is writable
        sd(T2, SP, -8),
        addi(A0, SP, -8),
        addi(A1, 0, 8),
        ret(),
    ]);
    let elf = build_elf(
        TEXT_VADDR,
        &[
            (".text", 1, 0x6, TEXT_VADDR, &text),
            (".rodata", 1, 0x2, RO_VADDR, &RO_CONST.to_le_bytes()),
            (".data", 1, 0x3, rw_vaddr, &rw_const.to_le_bytes()), // ALLOC|WRITE
        ],
    );

    let blob = link_elf_spi(&elf).expect("links");
    let prog = parse_standard_program(&blob).expect("parses");
    assert_eq!(prog.rw_data, rw_const.to_le_bytes(), "padding stripped");
    assert_eq!(prog.layout(&[]).expect("lays out").rw.base, rw_vaddr);

    let inv = refine::execute(&blob, &[], GAS).expect("executes");
    assert_eq!(inv.exit, ExitReason::Halt);
    assert_eq!(
        inv.output_bounded(core::mem::size_of::<u64>()).as_deref(),
        Some(&rw_const.to_le_bytes()[..])
    );
}

#[test]
fn trailing_bss_is_encoded_as_zero_pages_not_artifact_bytes() {
    let rw_vaddr = 3 * PVM_ZONE_SIZE as u64;
    let data = 0xCAFE_BABEu64.to_le_bytes();
    let bss = [0u8; 2 * 4096];
    let text = assemble(&[ret()]);
    let elf = build_elf(
        TEXT_VADDR,
        &[
            (".text", 1, 0x6, TEXT_VADDR, &text),
            (".rodata", 1, 0x2, RO_VADDR, &RO_CONST.to_le_bytes()),
            (".data", 1, 0x3, rw_vaddr, &data),
            (".bss", 8, 0x3, rw_vaddr + 4096, &bss),
        ],
    );

    let blob = link_elf_spi(&elf).expect("links");
    let program = parse_standard_program(&blob).expect("parses");
    assert_eq!(program.rw_data, &data[..4]);
    assert_eq!(program.heap_pages, 18, "two BSS pages plus base heap");
    let layout = program.layout(&[]).expect("lays out");
    assert_eq!(layout.rw.base, rw_vaddr);
    assert_eq!(layout.rw.size, 19 * 4096);
}

/// Guests linked below the GP bases cannot resolve their absolute data
/// addresses under the SPI layout — rejected loudly, not mis-emitted.
#[test]
fn data_linked_below_gp_bases_is_rejected() {
    let text = assemble(&[ret()]);

    let ro_low = build_elf(
        TEXT_VADDR,
        &[
            (".text", 1, 0x6, TEXT_VADDR, &text),
            (".rodata", 1, 0x2, 0x8000, &RO_CONST.to_le_bytes()),
        ],
    );
    let err = link_elf_spi(&ro_low).expect_err("ro below Z_Z must fail");
    assert!(
        matches!(&err, TranspileError::InvalidSection(m) if m.contains("read-only")),
        "unexpected error: {err:?}"
    );
    let rw_low = build_elf(
        TEXT_VADDR,
        &[
            (".text", 1, 0x6, TEXT_VADDR, &text),
            (".rodata", 1, 0x2, RO_VADDR, &RO_CONST.to_le_bytes()),
            // 0x2_0000 < 2·Z_Z + zone_round(|o|) = 0x3_0000.
            (".data", 1, 0x3, 2 * PVM_ZONE_SIZE as u64, &[1, 2, 3, 4]),
        ],
    );
    let err = link_elf_spi(&rw_low).expect_err("rw below its GP base must fail");
    assert!(
        matches!(&err, TranspileError::InvalidSection(m) if m.contains("read-write")),
        "unexpected error: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Refine-convention smoke under the standard harness, both memory models.
// ---------------------------------------------------------------------------

/// The refine-convention contract end-to-end on the SPI backend: args in via
/// φ7/φ8, output designated via φ7/φ8, return-to-halt — under both interpreter
/// memory representations (Sparse is what a wasm32 embedder gets from
/// `MemoryModel::Auto`).
#[test]
fn refine_convention_guest_round_trips_args() {
    let blob = link_elf_spi(&checksum_guest_elf()).expect("links");

    for model in [MemoryModel::Flat, MemoryModel::Sparse] {
        let inv = refine::execute_with(&blob, &ARGS, GAS, model).expect("executes");
        assert_eq!(inv.exit, ExitReason::Halt, "{model:?}");
        assert_eq!(
            inv.output_bounded(core::mem::size_of::<u64>()).as_deref(),
            Some(&SUM.to_le_bytes()[..]),
            "{model:?}: output is RO_CONST + args[0]"
        );
        assert_eq!(inv.registers[2], ARGS[0] as u64, "φ2 = args[0]");
        assert_eq!(inv.registers[4], RO_CONST, "φ4 = the ro constant");
        assert_eq!(inv.registers[8], 8, "φ8 = output length");
        assert!(inv.gas_used > 0 && inv.gas_used < GAS);
    }

    // Empty args are valid: φ8 = 0 — the guest must not be entered with
    // garbage registers. (This guest reads args[0], so give it one byte.)
    let inv = refine::execute(&blob, &[0], GAS).expect("executes");
    assert_eq!(inv.exit, ExitReason::Halt);
    assert_eq!(
        inv.output_bounded(core::mem::size_of::<u64>()).as_deref(),
        Some(&RO_CONST.to_le_bytes()[..])
    );
}
