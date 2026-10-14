//! Linker-based RISC-V ELF to PVM transpilation.
//!
//! Unlike the basic `transpile_elf`, this module processes ELF relocations
//! to correctly handle data references in code. This is required for
//! real-world programs (like k256 crypto) that reference .rodata constants.
//!
//! Approach:
//! 1. Parse ELF sections and relocations
//! 2. Compute PVM memory layout (stack, ro_data, rw_data addresses)
//! 3. Build a relocation map: code_offset → resolved_address
//! 4. Translate RISC-V instructions, using relocation info to replace
//!    AUIPC+LO12 pairs with direct load_imm of the final PVM address

use crate::TranspileError;
use crate::riscv::{TranslationContext, decode_b_imm, decode_j_imm};
use std::collections::{HashMap, HashSet};

/// RISC-V relocation types we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelocType {
    /// R_RISCV_32 (1): Absolute 32-bit address
    Abs32,
    /// R_RISCV_64 (2): Absolute 64-bit address
    Abs64,
    /// R_RISCV_CALL_PLT (19): AUIPC+JALR pair for function calls
    CallPlt,
    /// R_RISCV_PCREL_HI20 (23): Upper 20 bits of PC-relative address (AUIPC)
    PcrelHi20,
    /// R_RISCV_PCREL_LO12_I (24): Lower 12 bits, I-type (load/addi)
    PcrelLo12I,
    /// R_RISCV_PCREL_LO12_S (25): Lower 12 bits, S-type (store)
    PcrelLo12S,
    /// R_RISCV_ADD32 (35): Add 32-bit (paired with SUB32 for relative jump tables)
    Add32,
    /// R_RISCV_SUB32 (39): Subtract 32-bit (paired with ADD32 for relative jump tables)
    Sub32,
}

impl RelocType {
    fn from_raw(r: u32) -> Option<Self> {
        match r {
            1 => Some(Self::Abs32),
            2 => Some(Self::Abs64),
            19 => Some(Self::CallPlt),
            23 => Some(Self::PcrelHi20),
            24 => Some(Self::PcrelLo12I),
            25 => Some(Self::PcrelLo12S),
            35 => Some(Self::Add32),
            39 => Some(Self::Sub32),
            _ => None,
        }
    }
}

/// A symbol's type: a function.
pub(crate) const STT_FUNC: u8 = 2;

/// A defined symbol: its value, size, type (`STT_*`), and where its name
/// starts in [`LinkedElf::names`].
#[derive(Clone, Copy)]
pub(crate) struct Symbol {
    pub(crate) value: u64,
    pub(crate) size: u64,
    pub(crate) kind: u8,
    pub(crate) name: usize,
}

/// Parsed ELF with relocation info for linking.
pub(crate) struct LinkedElf {
    pub(crate) is_64bit: bool,
    /// All code sections: (file_offset, vaddr, data)
    pub(crate) code_sections: Vec<(u64, u64, Vec<u8>)>,
    /// RO data blob and the vaddr its first byte is linked at
    /// (`stack_size`, the page-floored lowest ro section address).
    pub(crate) ro_data: Vec<u8>,
    pub(crate) ro_base: u64,
    /// RW data blob, its initialized part, and the vaddr its first byte is
    /// linked at (`min(rw_pvm_base, lowest rw section address)`).
    pub(crate) rw_data: Vec<u8>,
    pub(crate) rw_base: u64,
    /// Lowest rw section vaddr (== `rw_base` when there are no rw sections).
    pub(crate) rw_min: u64,
    /// The rw span from `rw_base`, NOBITS included: zeros past `rw_data`.
    pub(crate) rw_len: u64,
    /// Stack size in bytes (= ro_base, so RO data is at the right PVM address)
    pub(crate) stack_size: u32,
    /// Heap pages
    pub(crate) heap_pages: u32,
    /// Every defined symbol, in the table's order.
    pub(crate) symbols: Vec<Symbol>,
    /// The symbols' string table, its names read only where needed.
    pub(crate) names: Vec<u8>,
    /// Relocations in loaded sections that place an address in data:
    /// `R_RISCV_32`, `_64` and `_ADD32`, each where and what it names.
    pub(crate) data_relocs: Vec<(u64, u64)>,
    /// Relocations in loaded sections naming an address by a symbol, a
    /// PC-relative pair's or data's: where, and the symbol's own value.
    pub(crate) symbol_refs: Vec<(u64, u64)>,
    /// How many relocation entries the ELF holds, of any type.
    pub(crate) relocations: usize,
    /// The first relocation type the linker does not follow, in a section
    /// the program loads, branches and jumps aside.
    pub(crate) unknown_relocation: Option<u32>,
    /// The `.vos_schema` section's bytes, an actor program's schema.
    pub(crate) schema: Option<Vec<u8>>,
    /// PCREL_HI20: AUIPC instruction vaddr → resolved data address.
    /// The AUIPC itself should emit load_imm with this address.
    pub(crate) hi20_targets: HashMap<u64, u64>,
    /// PCREL_LO12: instruction vaddr → resolved data address (looked up from paired HI20).
    /// These instructions should use the already-loaded address (from AUIPC/load_imm).
    pub(crate) lo12_targets: HashMap<u64, u64>,
    /// CALL_PLT: AUIPC instruction vaddr → target function RISC-V vaddr.
    pub(crate) call_targets: HashMap<u64, u64>,
    /// Absolute code pointers in data sections: (data_vaddr, target_code_vaddr, entry_size).
    /// entry_size is 4 for 32-bit or 8 for 64-bit entries.
    pub(crate) abs_code_ptrs: Vec<(u64, u64, u8)>,
    /// SUB32 relocations: (data_vaddr, subtracted_addr).
    /// For LLVM relative jump tables: entry = target - subtracted_addr.
    /// Combined with the resolved entry value, we can recover the target.
    pub(crate) sub32_relocs: Vec<(u64, u64)>,
    /// Bytes whose data-pointer interpretation is already defined by a
    /// relocation, including non-code targets. Never rescan as raw pointers.
    pub(crate) data_relocation_ranges: Vec<(u64, u64)>,
    /// Code section address ranges for detecting code pointers, sorted
    /// and merged.
    pub(crate) code_ranges: Vec<(u64, u64)>,
    /// Every statically reachable RISC-V instruction address. Translation-time
    /// predecessor fusion must stop at these boundaries.
    pub(crate) control_flow_targets: HashSet<u64>,
    /// ELF entry point (e_entry) — the RISC-V vaddr of _start (refine entry).
    pub(crate) entry_vaddr: u64,
    /// RISC-V vaddr of the exported `accumulate` symbol, if the service
    /// defines one (the accumulate entry). `None` for refine-only blobs, whose
    /// IC-5 prologue slot becomes a trap.
    pub(crate) accumulate_vaddr: Option<u64>,
}

/// The result of transpiling an ELF: the code in GP instruction encoding
/// (plus bitmask and jump table) and the memory-section blobs at their linked
/// base addresses. [`link_elf_spi`] serializes exactly these fields.
pub(crate) struct TranspiledElf {
    code: Vec<u8>,
    bitmask: Vec<u8>,
    jump_table: Vec<u32>,
    /// RO data blob; its first byte is linked at `ro_base`.
    ro_data: Vec<u8>,
    ro_base: u64,
    /// RW data blob, its initialized part; its first byte is linked at
    /// `rw_base`.
    rw_data: Vec<u8>,
    rw_base: u64,
    /// Lowest rw section vaddr (real data starts here; `[rw_base, rw_min)`
    /// is zero padding).
    rw_min: u64,
    /// The rw span from `rw_base`: zeros past `rw_data`.
    rw_len: u64,
    /// Stack byte capacity (= the page-floored lowest ro vaddr, min 16 KiB).
    stack_size: u32,
    /// Zeroed heap pages beyond `rw_data`.
    heap_pages: u32,
    /// Each function's first PVM instruction, and its name, by offset.
    functions: crate::Functions,
}

/// `Z_Z` — the GP initialization zone size (2¹⁶).
pub(crate) const Z_Z: u64 = vos_pvm::PVM_ZONE_SIZE as u64;

/// Round `x` up to a multiple of the zone size `Z_Z`.
pub(crate) fn zone_round(x: u64) -> u64 {
    x.div_ceil(Z_Z) * Z_Z
}

/// Transpile an rv64em ELF into a **GP standard-program (SPI) blob** — the
/// format `vos_pvm::spi::parse_standard_program` consumes and
/// `vos_pvm::refine::execute_with` runs. The entry prologue places refine at
/// IC 0 and accumulate (or a trap) at IC 5.
///
/// Header-field derivation:
///
/// - **`s` (stack size, `E₃`)** = the page-floored lowest ro section vaddr,
///   minimum 16 KiB. `StandardProgram::layout` maps `page_round(s)` bytes
///   just below the argument zone with `φ1 = 0xFEFE_0000`; guest code is
///   SP-relative, so placement needs no linker cooperation.
/// - **`z` (heap pages, `E₂`)** includes every trailing all-zero read-write
///   page (normally `.bss`). Standard programs distinguish initialized bytes
///   from zero pages directly, so encoding those pages in `w` would only
///   inflate the artifact.
/// - **`o` (read-only data)** = the ro blob **re-based to the GP ro base
///   `Z_Z` = `0x1_0000`**: zero-prefix padding covers `[Z_Z, ro_base)`. An
///   ELF whose ro sections are linked below `Z_Z` is rejected — its embedded
///   absolute addresses could never resolve under the GP layout.
/// - **`w` (read-write data)** = the rw blob **re-based to the GP rw base
///   `2·Z_Z + zone_round(|o|)`** (leading zero padding stripped or added).
///   An ELF whose rw/bss sections are linked below that base is rejected.
///
/// Consequently `parse_standard_program(blob)?.layout(args)` lands every
/// data section at the vaddr it was linked at, so absolute data addresses
/// embedded in the translated code resolve identically. A guest targeting
/// this backend must therefore be linked against the GP map: `.rodata` at
/// `0x1_0000`, `.data`/`.bss` at `2·Z_Z + zone_round(|o|)` (`0x3_0000` when
/// `0 < |o| ≤ 64 KiB`, `0x2_0000` when there is no ro data). Code and stack
/// placement need no linker cooperation (code addresses are translated;
/// the stack is SP-relative).
pub fn link_elf_spi(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    spi_blob(transpile_elf(elf_data, Link::Whole)?)
}

/// [`link_elf_spi`], and each function's first PVM instruction in the
/// blob's code, with its name (demangled), by offset: what a profiler
/// names compiled code by.
pub fn link_elf_spi_with_symbols(
    elf_data: &[u8],
) -> Result<(Vec<u8>, crate::Functions), TranspileError> {
    let transpiled = transpile_elf(elf_data, Link::Named)?;
    let functions = transpiled.functions.clone();
    Ok((spi_blob(transpiled)?, functions))
}

/// Lay translated code and data out as a standard program.
pub(crate) fn spi_blob(t: TranspiledElf) -> Result<Vec<u8>, TranspileError> {
    // Re-base the ro blob from its linked base to the GP ro base Z_Z.
    let ro_data = if t.ro_data.is_empty() {
        Vec::new()
    } else if t.ro_base >= Z_Z {
        let mut v = vec![0u8; (t.ro_base - Z_Z) as usize];
        v.extend_from_slice(&t.ro_data);
        v
    } else {
        return Err(TranspileError::InvalidSection(format!(
            "SPI: read-only data linked at {:#x}, below the GP read-only base {Z_Z:#x}",
            t.ro_base,
        )));
    };

    // Re-base the rw blob to the GP rw base 2·Z_Z + zone_round(|o|): its
    // initialized bytes, and its whole span, zeros past them.
    let rw_spi_base = 2 * Z_Z + zone_round(ro_data.len() as u64);
    let (mut rw_data, rw_len) = if t.rw_len == 0 {
        (Vec::new(), 0)
    } else if t.rw_min < rw_spi_base {
        return Err(TranspileError::InvalidSection(format!(
            "SPI: read-write data linked at {:#x}, below the GP read-write base {rw_spi_base:#x} \
             (= 2 * Z_Z + zone_round(ro_size))",
            t.rw_min,
        )));
    } else if t.rw_base >= rw_spi_base {
        let padding = t.rw_base - rw_spi_base;
        if padding > limits::DATA {
            return Err(TranspileError::InvalidSection(format!(
                "SPI: read-write data linked at {:#x}, far past its GP base",
                t.rw_base
            )));
        }
        let mut v = vec![0u8; padding as usize];
        v.extend_from_slice(&t.rw_data);
        (v, t.rw_len + padding)
    } else {
        // rw_base < rw_spi_base <= rw_min: everything stripped is the blob's
        // own leading zero padding, so the data keeps its linked vaddr.
        let stripped = rw_spi_base - t.rw_base;
        let kept = t.rw_data.get(stripped as usize..).unwrap_or(&[]);
        (kept.to_vec(), t.rw_len - stripped)
    };

    // Standard programs encode zero-initialized memory as heap pages. Fold
    // the read-write blob's trailing zero pages (principally ELF NOBITS
    // `.bss`) into `z` while preserving the exact total mapped page count.
    let page_size = vos_pvm::PVM_PAGE_SIZE as usize;
    let original_rw_pages = usize::try_from(rw_len)
        .map_err(|_| TranspileError::InvalidSection("SPI: read-write span".into()))?
        .div_ceil(page_size);
    let compact_len = rw_data
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    rw_data.truncate(compact_len);
    let compact_rw_pages = compact_len.div_ceil(page_size);
    let reclaimed_zero_pages = original_rw_pages.saturating_sub(compact_rw_pages);
    let heap_pages = u32::try_from(reclaimed_zero_pages)
        .ok()
        .and_then(|reclaimed| t.heap_pages.checked_add(reclaimed))
        .ok_or_else(|| TranspileError::InvalidSection("SPI: heap page count overflow".into()))?;

    // Wire-width guards: |o|, |w|, s are E₃-encoded; z is E₂-encoded.
    for (what, len) in [("read-only", ro_data.len()), ("read-write", rw_data.len())] {
        if len >= 1 << 24 {
            return Err(TranspileError::InvalidSection(format!(
                "SPI: {what} data spans {len:#x} bytes, exceeding the E3 field width",
            )));
        }
    }
    if t.stack_size >= 1 << 24 {
        return Err(TranspileError::InvalidSection(format!(
            "SPI: stack size {:#x} exceeds the E3 field width",
            t.stack_size,
        )));
    }
    let heap_pages = u16::try_from(heap_pages).map_err(|_| {
        TranspileError::InvalidSection(format!(
            "SPI: heap page count {heap_pages} exceeds the E2 field width",
        ))
    })?;

    let blob = crate::spi::build_spi_blob(
        &ro_data,
        &rw_data,
        heap_pages,
        t.stack_size,
        &t.code,
        &t.bitmask,
        &t.jump_table,
    );

    // Fail-early self-check: the blob must re-parse and its layout must fit
    // the 32-bit guest address space (GP eq A.42's total-size guard).
    let prog = vos_pvm::spi::parse_standard_program(&blob).ok_or_else(|| {
        TranspileError::InvalidSection("SPI: emitted blob does not re-parse".into())
    })?;
    prog.layout(&[]).ok_or_else(|| {
        TranspileError::InvalidSection(
            "SPI: memory layout exceeds the 32-bit guest address space".into(),
        )
    })?;

    Ok(blob)
}

/// Translate an ELF into a GP-encoded program and its data sections.
fn transpile_elf(elf_data: &[u8], link: Link) -> Result<TranspiledElf, TranspileError> {
    transpile_with(&parse_linked_elf(elf_data)?, link).map(|(transpiled, _)| transpiled)
}

/// Translate a parsed ELF's code into PVM code with the GP entry prologue,
/// and rewrite its data's code pointers.
#[cfg(test)]
fn transpile_linked(elf: &LinkedElf) -> Result<TranspiledElf, TranspileError> {
    transpile_with(elf, Link::Whole).map(|(transpiled, _)| transpiled)
}

/// A djump address no jump table reaches, even, and not the halt address:
/// jumping to it panics.
pub(crate) const PRUNED: u32 = u32::MAX - 1;

/// How a parsed ELF is linked.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Link {
    /// Whole, as [`link_elf_spi`] links it.
    Whole,
    /// Whole, and each function's place named for a profiler.
    Named,
    /// A kernel, its code pruned to what its entry reaches: a trap follows
    /// each of its code sections, so none falls into another, a branch to
    /// code never translated reaches a trap, and a code pointer in its data
    /// to such code becomes [`PRUNED`].
    Kernel,
}

/// Translate a parsed ELF's code into PVM code with the GP entry prologue,
/// and rewrite its data's code pointers, as `link` links it: the program,
/// and each `ecalli` it emitted, by the address of its `ecall`.
pub(crate) fn transpile_with(
    elf: &LinkedElf,
    link: Link,
) -> Result<(TranspiledElf, Vec<(u64, u32)>), TranspileError> {
    let kernel = link == Link::Kernel;
    let mut ctx = TranslationContext::new(elf.is_64bit);
    ctx.code_ranges = elf.code_ranges.clone();
    ctx.trap_unresolved = kernel;

    // Emit the two-slot GP entry prologue. ICs are byte offsets into the code,
    // and a plain jump (opcode 40 + imm32) is exactly 5 bytes, so the two
    // jumps land at IC 0 and IC 5 respectively — the entry points a GP host
    // selects by starting the instruction counter at 0 (refine / is-authorized)
    // or 5 (accumulate). SP is no longer initialized here: the host owns it
    // (kernel installs φ[1]=stack_top from the blob's container metadata). Each
    // jump ends its basic block, so IC 5 begins a fresh block. Both fixups are
    // resolved after translation in apply_fixups() (RISC-V vaddr → PVM PC).
    //
    // IC 0 → refine body = the ELF entry point (e_entry / _start).
    ctx.emit_jump(elf.entry_vaddr);
    // Hard assert (not debug): the accumulate entry MUST begin at IC 5, so the
    // refine jump has to occupy exactly bytes 0..5. This is a consensus-visible
    // GP layout invariant — a one-time cost per link, kept in release builds so
    // a future change to the jump encoding can't silently misplace IC 5.
    assert_eq!(ctx.code.len(), 5, "refine jump must occupy IC 0..5");
    // IC 5 → accumulate body = exported `accumulate` symbol, or a trap for a
    // refine-only blob (an accumulate invocation must fail loud, not fall
    // through into the refine body).
    match elf.accumulate_vaddr {
        Some(vaddr) => ctx.emit_jump(vaddr),
        None => {
            ctx.emit_inst(0); // trap
        }
    }

    let targets: HashSet<u64> = elf
        .control_flow_targets
        .union(&direct_targets(elf))
        .copied()
        .collect();
    for (_file_off, vaddr, data) in &elf.code_sections {
        translate_section_linked(&mut ctx, data, *vaddr, elf, &targets)?;
        if kernel {
            ctx.emit_inst(0);
        }
    }
    ctx.apply_fixups();

    let mut ro_data = elf.ro_data.clone();
    let mut rw_data = elf.rw_data.clone();
    let pruned = kernel.then_some(PRUNED);
    rewrite_data_code_ptrs(elf, &mut ctx, &mut ro_data, &mut rw_data, pruned);

    crate::peephole_fuse_load_imm_alu(&mut ctx.code, &mut ctx.bitmask, &ctx.jump_table);
    crate::peephole_fuse_load_imm_memory(&mut ctx.code, &mut ctx.bitmask, &ctx.jump_table);
    // The pass may insert instructions: the functions' offsets move with it.
    let mut moved: Option<Vec<u32>> = None;
    crate::ensure_branch_targets_with_pc_map(
        &mut ctx.code,
        &mut ctx.bitmask,
        &mut ctx.jump_table,
        |offsets| moved = Some(offsets.to_vec()),
    );
    let mut functions: Vec<(u32, String)> = match link {
        Link::Named => elf
            .symbols
            .iter()
            .filter(|symbol| symbol.kind == STT_FUNC)
            .filter_map(|symbol| {
                let name = name_at(&elf.names, symbol.name);
                if name.is_empty() {
                    return None;
                }
                let at = *ctx.address_map.get(&symbol.value)?;
                let at = moved.as_ref().map_or(at, |offsets| offsets[at as usize]);
                Some((at, format!("{:#}", rustc_demangle::demangle(name))))
            })
            .collect(),
        Link::Whole | Link::Kernel => Vec::new(),
    };
    functions.sort();
    let host_calls = std::mem::take(&mut ctx.host_calls);

    let transpiled = TranspiledElf {
        code: ctx.code,
        bitmask: ctx.bitmask,
        jump_table: ctx.jump_table,
        ro_data,
        ro_base: elf.ro_base,
        rw_data,
        rw_base: elf.rw_base,
        rw_min: elf.rw_min,
        rw_len: elf.rw_len,
        stack_size: elf.stack_size,
        heap_pages: elf.heap_pages,
        functions,
    };
    Ok((transpiled, host_calls))
}

/// The most sections, symbols and relocations an ELF may hold, and the
/// address space its loaded sections must lie in: a parse is bounded by
/// them whatever the bytes claim.
pub mod limits {
    pub const SECTIONS: usize = 1 << 12;
    pub const SYMBOLS: usize = 1 << 20;
    pub const RELOCATIONS: usize = 1 << 22;
    /// Loaded sections lie below this: the PVM's addresses are 32 bits.
    pub const ADDRESS_SPACE: u64 = 1 << 32;
    /// The most bytes of read-only or initialized read-write data: what a
    /// standard program's `E3` fields encode.
    pub const DATA: u64 = 1 << 24;
}

/// `N` bytes of `data` at `at`, or an error naming `what`.
fn field<const N: usize>(data: &[u8], at: usize, what: &str) -> Result<[u8; N], TranspileError> {
    at.checked_add(N)
        .and_then(|end| data.get(at..end))
        .map(|bytes| bytes.try_into().expect("N bytes"))
        .ok_or_else(|| TranspileError::ElfParse(format!("{what} lies past the file's end")))
}

fn u16_at(data: &[u8], at: usize, what: &str) -> Result<u16, TranspileError> {
    field(data, at, what).map(u16::from_le_bytes)
}

fn u32_at(data: &[u8], at: usize, what: &str) -> Result<u32, TranspileError> {
    field(data, at, what).map(u32::from_le_bytes)
}

fn u64_at(data: &[u8], at: usize, what: &str) -> Result<u64, TranspileError> {
    field(data, at, what).map(u64::from_le_bytes)
}

/// `len` bytes of `data` at `offset`, if the file holds them.
fn span(data: &[u8], offset: u64, len: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(len).ok()?)?;
    data.get(start..end)
}

/// The longest name the linker reads: a longer one reads as empty.
const MAX_NAME: usize = 4096;

/// A NUL-terminated name at `offset` of a string table, or empty: so a
/// table without terminators costs a bounded read per name.
pub(crate) fn name_at(table: &[u8], offset: usize) -> &str {
    let Some(rest) = table.get(offset..) else {
        return "";
    };
    let rest = &rest[..rest.len().min(MAX_NAME + 1)];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(0);
    std::str::from_utf8(&rest[..end]).unwrap_or("")
}

/// Whether the name at `offset` of a string table is `name`.
pub(crate) fn name_is(table: &[u8], offset: usize, name: &[u8]) -> bool {
    table
        .get(offset..)
        .and_then(|rest| rest.strip_prefix(name))
        .is_some_and(|rest| rest.first() == Some(&0))
}

/// A section header's fields the linker reads.
struct SectionInfo {
    name_off: usize,
    sh_type: u32,
    flags: u64,
    addr: u64,
    file_off: u64,
    size: u64,
    link: usize,
    info: usize,
}

/// Parse ELF with full relocation info. Every field the bytes claim is
/// checked against the file and [`limits`]: a malformed ELF is refused,
/// never read out of bounds.
pub(crate) fn parse_linked_elf(data: &[u8]) -> Result<LinkedElf, TranspileError> {
    if data.len() < 64 || data[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err(TranspileError::ElfParse("not an ELF file".into()));
    }

    let is_64bit = match data[4] {
        1 => false,
        2 => true,
        _ => return Err(TranspileError::ElfParse("unsupported ELF class".into())),
    };

    if !is_64bit {
        return Err(TranspileError::ElfParse(
            "linker requires 64-bit ELF (rv64em)".into(),
        ));
    }

    // ELF64 header fields
    let e_entry = u64_at(data, 24, "the entry")?;
    let e_shoff = u64_at(data, 40, "the section table")?;
    let e_shentsize = u16_at(data, 58, "the section entry size")? as usize;
    let e_shnum = u16_at(data, 60, "the section count")? as usize;
    let e_shstrndx = u16_at(data, 62, "the section names' index")? as usize;
    if e_shnum > limits::SECTIONS {
        return Err(TranspileError::ElfParse(format!(
            "{e_shnum} sections, past {}",
            limits::SECTIONS
        )));
    }
    if e_shnum > 0 && e_shentsize < 64 {
        return Err(TranspileError::ElfParse(format!(
            "a section header of {e_shentsize} bytes"
        )));
    }

    // First pass: collect section metadata.
    let header = |index: usize| -> Option<usize> {
        let offset = usize::try_from(e_shoff).ok()?;
        offset.checked_add(index.checked_mul(e_shentsize)?)
    };
    let mut sections = Vec::with_capacity(e_shnum);
    for i in 0..e_shnum {
        let Some(sh) =
            header(i).filter(|sh| sh.checked_add(64).is_some_and(|end| end <= data.len()))
        else {
            break;
        };
        sections.push(SectionInfo {
            name_off: u32_at(data, sh, "a section's name")? as usize,
            sh_type: u32_at(data, sh + 4, "a section's type")?,
            flags: u64_at(data, sh + 8, "a section's flags")?,
            addr: u64_at(data, sh + 16, "a section's address")?,
            file_off: u64_at(data, sh + 24, "a section's offset")?,
            size: u64_at(data, sh + 32, "a section's size")?,
            link: u32_at(data, sh + 40, "a section's link")? as usize,
            info: u32_at(data, sh + 44, "a section's info")? as usize,
        });
    }

    // Section name string table
    let strtab: &[u8] = sections
        .get(e_shstrndx)
        .and_then(|names| span(data, names.file_off, names.size))
        .ok_or_else(|| TranspileError::ElfParse("no section names".into()))?;
    let get_name = |name_off: usize| -> &str { name_at(strtab, name_off) };

    // Collect code sections, ro sections, rw sections
    let mut code_sections = Vec::new();
    let mut ro_sections: Vec<(u64, usize, Vec<u8>)> = Vec::new();
    let mut rw_sections: Vec<(u64, usize, Option<Vec<u8>>)> = Vec::new();
    let mut rela_section_indices = Vec::new();
    let mut symtab_idx = None;
    let mut schema = None;

    for (i, s) in sections.iter().enumerate() {
        let name = get_name(s.name_off);
        let is_alloc = s.flags & 2 != 0;
        let is_exec = s.flags & 4 != 0;
        let is_write = s.flags & 1 != 0;

        if s.sh_type == 2 {
            // SYMTAB
            symtab_idx = Some(i);
        }
        if s.sh_type == 4 {
            // RELA
            rela_section_indices.push(i);
        }
        if !is_alloc || s.sh_type == 0 {
            continue;
        }
        if s.addr
            .checked_add(s.size)
            .is_none_or(|end| end > limits::ADDRESS_SPACE)
        {
            return Err(TranspileError::InvalidSection(format!(
                "{name} at {:#x}, {:#x} bytes, past the 32-bit address space",
                s.addr, s.size
            )));
        }
        let size = s.size as usize;
        let bytes = span(data, s.file_off, s.size);

        if is_exec {
            if let Some(bytes) = bytes {
                code_sections.push((s.file_off, s.addr, bytes.to_vec()));
            }
        } else if name.starts_with(".rodata")
            || name == ".srodata"
            || name.starts_with(".data.rel.ro")
            || name == ".vos_schema"
        {
            if let Some(bytes) = bytes {
                if name == ".vos_schema" {
                    schema = Some(bytes.to_vec());
                }
                ro_sections.push((s.addr, size, bytes.to_vec()));
            }
        } else if is_write {
            if s.sh_type == 8 {
                // NOBITS (.bss)
                rw_sections.push((s.addr, size, None));
            } else if let Some(bytes) = bytes {
                rw_sections.push((s.addr, size, Some(bytes.to_vec())));
            }
        }
    }

    // Parse symbol table: each symbol's value by its index, and the defined
    // ones, their names read only where needed.
    let mut values: Vec<u64> = Vec::new();
    let mut symbols: Vec<Symbol> = Vec::new();
    let mut names: Vec<u8> = Vec::new();
    let mut accumulate_vaddr = None;
    if let Some(si) = symtab_idx {
        let s = &sections[si];
        // Get associated string table
        let sym_strtab: &[u8] = sections
            .get(s.link)
            .and_then(|names| span(data, names.file_off, names.size))
            .ok_or_else(|| TranspileError::ElfParse("no symbol names".into()))?;
        // ELF64 symbol = 24 bytes
        let count = (s.size / 24) as usize;
        if count > limits::SYMBOLS {
            return Err(TranspileError::ElfParse(format!(
                "{count} symbols, past {}",
                limits::SYMBOLS
            )));
        }
        let table = span(data, s.file_off, s.size).unwrap_or(&[]);
        for entry in table.chunks_exact(24) {
            let st_name = u32::from_le_bytes(entry[0..4].try_into().expect("four bytes")) as usize;
            let st_info = entry[4];
            let st_value = u64::from_le_bytes(entry[8..16].try_into().expect("eight bytes"));
            let st_size = u64::from_le_bytes(entry[16..24].try_into().expect("eight bytes"));
            if st_value != 0 {
                symbols.push(Symbol {
                    value: st_value,
                    size: st_size,
                    kind: st_info & 0xf,
                    name: st_name,
                });
                // The exported `accumulate` entry symbol (the GP IC-5 slot).
                // A defined symbol has a nonzero code vaddr; an undefined
                // reference (value 0) is treated as absent so the blob stays
                // refine-only (IC 5 → trap).
                if accumulate_vaddr.is_none() && name_is(sym_strtab, st_name, b"accumulate") {
                    accumulate_vaddr = Some(st_value);
                }
            }
            values.push(st_value);
        }
        names = sym_strtab.to_vec();
    }

    // Compute PVM memory layout
    // PVM linear memory: [stack: 0..s) [ro: s..s+|o|) [rw: s+P(|o|)..] [heap...]
    // We set stack_size = minimum power-of-2 page boundary that contains all ro section addrs.
    let ro_min = ro_sections.iter().map(|(a, _, _)| *a).min().unwrap_or(0);
    let ro_max = ro_sections
        .iter()
        .map(|(a, sz, _)| *a + *sz as u64)
        .max()
        .unwrap_or(0);

    // Round ro_min down to page boundary for stack_size.
    // Minimum 4 pages (16KB) so the stack is usable even without rodata.
    let page_size: u64 = 4096;
    let stack_size = if ro_min > 0 {
        (ro_min / page_size) * page_size
    } else {
        4 * page_size
    };

    // Build ro_data blob: section data placed at (section_addr - stack_size) offset
    let ro_blob_size = ro_max.saturating_sub(stack_size);
    if ro_blob_size > limits::DATA {
        return Err(TranspileError::InvalidSection(format!(
            "read-only data spans {ro_blob_size:#x} bytes"
        )));
    }
    let mut ro_data = vec![0u8; ro_blob_size as usize];
    for (addr, sz, d) in &ro_sections {
        let Some(off) = addr.checked_sub(stack_size) else {
            continue;
        };
        let off = off as usize;
        if off + sz <= ro_data.len() {
            ro_data[off..off + sz].copy_from_slice(d);
        }
    }

    // RW data: placed after ro_data (with page rounding). Only the
    // initialized part is held; NOBITS pages beyond it are zeros the
    // program's heap pages hold, never bytes here.
    let ro_pages = ro_data.len().div_ceil(page_size as usize);
    let rw_pvm_base = stack_size + (ro_pages as u64 * page_size);
    let mut rw_data = Vec::new();
    let mut rw_base = rw_pvm_base;
    let mut rw_min = rw_pvm_base;
    let mut rw_len = 0;
    if !rw_sections.is_empty() {
        rw_min = rw_sections.iter().map(|(a, _, _)| *a).min().unwrap_or(0);
        let rw_max = rw_sections
            .iter()
            .map(|(a, sz, _)| *a + *sz as u64)
            .max()
            .unwrap_or(0);
        rw_base = rw_pvm_base.min(rw_min);
        rw_len = rw_max - rw_base;
        let initialized = rw_sections
            .iter()
            .filter(|(_, _, bytes)| bytes.is_some())
            .map(|(a, sz, _)| *a + *sz as u64)
            .max()
            .map_or(0, |end| end - rw_base);
        if initialized > limits::DATA {
            return Err(TranspileError::InvalidSection(format!(
                "read-write data spans {initialized:#x} bytes"
            )));
        }
        rw_data = vec![0u8; initialized as usize];
        for (addr, sz, d) in &rw_sections {
            let off = (*addr - rw_base) as usize;
            if let Some(d) = d
                && off + sz <= rw_data.len()
            {
                rw_data[off..off + sz].copy_from_slice(d);
            }
        }
    }

    // Parse relocations in two passes:
    // Pass 1: collect HI20 targets and CALL_PLT targets
    // Pass 2: resolve LO12 by looking up their paired HI20
    let mut hi20_targets: HashMap<u64, u64> = HashMap::new();
    let mut lo12_targets: HashMap<u64, u64> = HashMap::new();
    let mut call_targets: HashMap<u64, u64> = HashMap::new();

    // Temporary: collect LO12 entries for pass 2
    let mut lo12_entries: Vec<(u64, u64)> = Vec::new(); // (lo12_addr, hi20_addr)
    let mut abs64_relocs: Vec<(u64, u64, u8)> = Vec::new(); // (offset, target, entry_size)
    let mut sub32_relocs: Vec<(u64, u64)> = Vec::new();
    let mut data_relocs: Vec<(u64, u64)> = Vec::new();
    let mut symbol_refs: Vec<(u64, u64)> = Vec::new();
    let mut unknown_relocation = None;
    let mut data_relocation_ranges = Vec::new();
    let mut relocations = 0usize;
    // Code address ranges for detecting code pointers, sorted and merged.
    let code_ranges = merge_ranges(
        code_sections
            .iter()
            .map(|(_, vaddr, data)| (*vaddr, *vaddr + data.len() as u64))
            .collect(),
    );

    for &ri in &rela_section_indices {
        let rs = &sections[ri];
        let count = (rs.size / 24) as usize;
        relocations = relocations.saturating_add(count);
        if relocations > limits::RELOCATIONS {
            return Err(TranspileError::ElfParse(format!(
                "past {} relocations",
                limits::RELOCATIONS
            )));
        }
        // The section the relocations apply to: one not loaded, as debug
        // information, places no pointer in the program.
        let applies = sections
            .get(rs.info)
            .is_some_and(|target| target.flags & 2 != 0);
        let table = span(data, rs.file_off, rs.size).unwrap_or(&[]);
        for entry in table.chunks_exact(24) {
            let r_offset = u64::from_le_bytes(entry[0..8].try_into().expect("eight bytes"));
            let r_info = u64::from_le_bytes(entry[8..16].try_into().expect("eight bytes"));
            let r_addend = i64::from_le_bytes(entry[16..24].try_into().expect("eight bytes"));
            let r_type = (r_info & 0xFFFFFFFF) as u32;
            let r_sym = (r_info >> 32) as usize;

            let rtype = match RelocType::from_raw(r_type) {
                Some(t) => t,
                None => {
                    // Branches and jumps resolve within the code as linked.
                    if applies && !matches!(r_type, 16 | 17) {
                        unknown_relocation.get_or_insert(r_type);
                    }
                    continue;
                }
            };

            let sym_value = values.get(r_sym).copied().unwrap_or(0);

            let target_addr = (sym_value as i64).wrapping_add(r_addend) as u64;

            match rtype {
                RelocType::Abs32 | RelocType::Add32 | RelocType::Sub32 => {
                    data_relocation_ranges.push((r_offset, r_offset.saturating_add(4)));
                }
                RelocType::Abs64 => {
                    data_relocation_ranges.push((r_offset, r_offset.saturating_add(8)))
                }
                _ => {}
            }
            if applies
                && matches!(
                    rtype,
                    RelocType::Abs32 | RelocType::Abs64 | RelocType::Add32
                )
            {
                data_relocs.push((r_offset, target_addr));
            }
            if applies
                && matches!(
                    rtype,
                    RelocType::Abs32 | RelocType::Abs64 | RelocType::Add32 | RelocType::PcrelHi20
                )
            {
                symbol_refs.push((r_offset, sym_value));
            }

            match rtype {
                RelocType::Abs32 => {
                    let is_code_ptr = in_ranges(&code_ranges, target_addr);
                    if is_code_ptr {
                        abs64_relocs.push((r_offset, target_addr, 4));
                    }
                }
                RelocType::Abs64 => {
                    let is_code_ptr = in_ranges(&code_ranges, target_addr);
                    if is_code_ptr {
                        abs64_relocs.push((r_offset, target_addr, 8));
                    }
                }
                RelocType::Add32 => {
                    let is_code_ptr = in_ranges(&code_ranges, target_addr);
                    if is_code_ptr {
                        abs64_relocs.push((r_offset, target_addr, 4));
                    }
                }
                RelocType::Sub32 => {
                    // R_RISCV_SUB32: the subtracted address (typically table base).
                    sub32_relocs.push((r_offset, target_addr));
                }
                RelocType::CallPlt => {
                    call_targets.insert(r_offset, target_addr);
                }
                RelocType::PcrelHi20 => {
                    // target_addr is the resolved data/function address
                    hi20_targets.insert(r_offset, target_addr);
                }
                RelocType::PcrelLo12I | RelocType::PcrelLo12S => {
                    // sym_value is the address of the paired HI20 instruction.
                    // r_offset is the address of this LO12 instruction.
                    lo12_entries.push((r_offset, sym_value));
                }
            }
        }
    }

    let data_relocation_ranges = merge_ranges(data_relocation_ranges);

    // Pass 2: resolve LO12 targets by looking up paired HI20
    for (lo12_addr, hi20_addr) in lo12_entries {
        if let Some(&data_addr) = hi20_targets.get(&hi20_addr) {
            lo12_targets.insert(lo12_addr, data_addr);
        }
    }

    let mut control_flow_targets = HashSet::new();
    control_flow_targets.insert(e_entry);
    control_flow_targets.extend(accumulate_vaddr);
    control_flow_targets.extend(
        values
            .iter()
            .copied()
            .filter(|value| in_ranges(&code_ranges, *value)),
    );
    for (&call_site, &target) in &call_targets {
        control_flow_targets.insert(target);
        // CALL_PLT occupies AUIPC+JALR; execution resumes after both.
        control_flow_targets.insert(call_site.wrapping_add(8));
    }
    control_flow_targets.extend(abs64_relocs.iter().map(|(_, target, _)| *target));
    control_flow_targets.extend(
        hi20_targets
            .values()
            .copied()
            .filter(|target| in_ranges(&code_ranges, *target)),
    );
    let is_code_target = |target: u64| in_ranges(&code_ranges, target);

    // The data-pointer rewriter below accepts stripped linked ELFs whose only
    // reference to a function entry is a raw pointer or an orphan SUB32 table
    // value. Collect those exact accepted targets before translating code so
    // they receive the same predecessor-fusion barrier as symbolic entries.
    let absolute: HashSet<u64> = abs64_relocs.iter().map(|(vaddr, _, _)| *vaddr).collect();
    for &(data_vaddr, base_addr) in &sub32_relocs {
        if absolute.contains(&data_vaddr) {
            continue;
        }
        let bytes = data_vaddr
            .checked_sub(stack_size)
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|offset| offset.checked_add(4).map(|end| (offset, end)))
            .and_then(|(offset, end)| ro_data.get(offset..end))
            .or_else(|| {
                let offset = usize::try_from(data_vaddr.checked_sub(rw_base)?).ok()?;
                let end = offset.checked_add(4)?;
                rw_data.get(offset..end)
            });
        if let Some(bytes) = bytes {
            let relative = i32::from_le_bytes(bytes.try_into().expect("four-byte slice"));
            let target = (base_addr as i64).wrapping_add(i64::from(relative)) as u64;
            if is_code_target(target) {
                control_flow_targets.insert(target);
            }
        }
    }
    for (base, data) in [(stack_size, &ro_data), (rw_base, &rw_data)] {
        for (index, bytes) in data.chunks_exact(8).enumerate() {
            if overlaps_data_relocation(&data_relocation_ranges, base + index as u64 * 8, 8) {
                continue;
            }
            let target = u64::from_le_bytes(bytes.try_into().expect("eight-byte chunk"));
            if is_code_target(target) {
                control_flow_targets.insert(target);
            }
        }
    }

    for (_, base, code) in &code_sections {
        for (index, bytes) in code.chunks_exact(4).enumerate() {
            let address = *base + (index * 4) as u64;
            let instruction = u32::from_le_bytes(bytes.try_into().expect("four-byte chunk"));
            if instruction & 0x7f == 0x17
                && let Some(next_bytes) = code.get(index * 4 + 4..index * 4 + 8)
            {
                let next = u32::from_le_bytes(
                    next_bytes
                        .try_into()
                        .expect("adjacent four-byte instruction"),
                );
                let auipc_rd = (instruction >> 7) & 0x1f;
                let jalr_rs1 = (next >> 15) & 0x1f;
                if next & 0x7f == 0x67 && (next >> 12) & 0x7 == 0 && auipc_rd == jalr_rs1 {
                    let upper = (instruction & 0xffff_f000) as i32;
                    let lower = (next as i32) >> 20;
                    let target = address.wrapping_add_signed(i64::from(upper) + i64::from(lower));
                    if is_code_target(target) {
                        control_flow_targets.insert(target);
                    }
                }
                let addi_rd = (next >> 7) & 0x1f;
                if next & 0x7f == 0x13
                    && (next >> 12) & 0x7 == 0
                    && auipc_rd != 0
                    && addi_rd == auipc_rd
                    && jalr_rs1 == auipc_rd
                {
                    let upper = (instruction & 0xffff_f000) as i32;
                    let lower = (next as i32) >> 20;
                    let target = address.wrapping_add_signed(i64::from(upper) + i64::from(lower));
                    if is_code_target(target) {
                        control_flow_targets.insert(target);
                    }
                }
            }
            match instruction & 0x7f {
                0x6f => {
                    control_flow_targets
                        .insert(address.wrapping_add_signed(i64::from(decode_j_imm(instruction))));
                    if (instruction >> 7) & 0x1f != 0 {
                        control_flow_targets.insert(address + 4);
                    }
                }
                0x63 => {
                    control_flow_targets
                        .insert(address.wrapping_add_signed(i64::from(decode_b_imm(instruction))));
                }
                0x67 if (instruction >> 7) & 0x1f != 0 => {
                    control_flow_targets.insert(address + 4);
                }
                _ => {}
            }
        }
    }

    let heap_pages = 16u32; // 64KB heap

    Ok(LinkedElf {
        is_64bit,
        code_sections,
        ro_data,
        ro_base: stack_size,
        rw_data,
        rw_base,
        rw_min,
        rw_len,
        stack_size: stack_size as u32,
        heap_pages,
        symbols,
        names,
        data_relocs,
        symbol_refs,
        relocations,
        unknown_relocation,
        schema,
        hi20_targets,
        lo12_targets,
        call_targets,
        abs_code_ptrs: abs64_relocs,
        sub32_relocs,
        data_relocation_ranges,
        code_ranges,
        control_flow_targets,
        entry_vaddr: e_entry,
        accumulate_vaddr,
    })
}

/// Address ranges, sorted and merged where they overlap or touch: the bytes
/// relocations cover, or the code sections. Relocation metadata owns every
/// byte it covers, including the other half of an eight-byte heuristic
/// candidate and relocations to non-code addresses.
pub(crate) fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

/// Whether `address` lies in one of `ranges`, sorted and merged.
pub(crate) fn in_ranges(ranges: &[(u64, u64)], address: u64) -> bool {
    let index = ranges.partition_point(|&(start, _)| start <= address);
    index != 0 && address < ranges[index - 1].1
}

pub(crate) fn overlaps_data_relocation(ranges: &[(u64, u64)], address: u64, size: u8) -> bool {
    let end = address.saturating_add(u64::from(size));
    let index = ranges.partition_point(|&(start, _)| start < end);
    index != 0 && ranges[index - 1].1 > address
}

/// Rewrite code pointers in data sections (LLVM switch/jump tables, vtables).
///
/// Detects code pointers via:
/// 1. R_RISCV_32/64 absolute relocations targeting code sections
/// 2. R_RISCV_SUB32 relocations (relative jump table entries: value = target - table_base)
/// 3. Heuristic scan for 8-byte values in initialized data that match code addresses
///
/// Creates PVM jump table entries for each target and rewrites the data
/// so that the loaded values are valid PVM djump addresses. A target never
/// translated is left as it was, or with `pruned` given, becomes that
/// address, which no jump table reaches.
fn rewrite_data_code_ptrs(
    elf: &LinkedElf,
    ctx: &mut TranslationContext,
    ro_data: &mut [u8],
    rw_data: &mut [u8],
    pruned: Option<u32>,
) {
    let ro_base = elf.ro_base;
    let rw_base = elf.rw_base;
    let is_code_addr = |addr: u64| -> bool { in_ranges(&elf.code_ranges, addr) };

    struct Entry {
        data_vaddr: u64,
        rv_target: u64,
        size: u8,
        table_base_rv: Option<u64>,
    }
    let mut entries: Vec<Entry> = Vec::new();

    // From absolute relocations (R_RISCV_32/64/ADD32).
    // If a matching SUB32 exists at the same offset, this is a relative entry
    // (ADD32/SUB32 pair for jump tables). Use the SUB32 target as table base.
    // Each address's first SUB32, as a search of them in order finds it.
    let mut bases: HashMap<u64, u64> = HashMap::with_capacity(elf.sub32_relocs.len());
    for &(vaddr, base) in &elf.sub32_relocs {
        bases.entry(vaddr).or_insert(base);
    }
    for &(vaddr, target, size) in &elf.abs_code_ptrs {
        let table_base = bases.get(&vaddr).copied();
        entries.push(Entry {
            data_vaddr: vaddr,
            rv_target: target,
            size,
            table_base_rv: table_base,
        });
    }

    // The data addresses entries already rewrite.
    let mut seen: HashSet<u64> = entries.iter().map(|entry| entry.data_vaddr).collect();
    // SUB32 entries without matching ADD32 (shouldn't happen, but handle gracefully).
    for &(data_vaddr, base_addr) in &elf.sub32_relocs {
        if seen.contains(&data_vaddr) {
            continue; // Already handled via ADD32 pairing above
        }
        let at = |base: u64, data: &'_ [u8]| -> Option<[u8; 4]> {
            let off = usize::try_from(data_vaddr.checked_sub(base)?).ok()?;
            data.get(off..off.checked_add(4)?)?.try_into().ok()
        };
        let bytes = at(ro_base, ro_data).or_else(|| at(rw_base, rw_data));
        if let Some(bytes) = bytes {
            let val = i32::from_le_bytes(bytes);
            let target = (base_addr as i64).wrapping_add(i64::from(val)) as u64;
            if is_code_addr(target) {
                seen.insert(data_vaddr);
                entries.push(Entry {
                    data_vaddr,
                    rv_target: target,
                    size: 4,
                    table_base_rv: Some(base_addr),
                });
            }
        }
    }

    // Heuristic: 8-byte values in either initialized region that are code
    // addresses. Relocations normally cover these; the scan also supports
    // stripped-but-still-linked inputs.
    let initialized_regions = [(ro_base, &*ro_data), (rw_base, &*rw_data)];
    for (base, data) in initialized_regions {
        let mut off = 0;
        while off + 8 <= data.len() {
            if overlaps_data_relocation(&elf.data_relocation_ranges, base + off as u64, 8) {
                off += 8;
                continue;
            }
            let val = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            if is_code_addr(val) {
                let vaddr = base + off as u64;
                if seen.insert(vaddr) {
                    entries.push(Entry {
                        data_vaddr: vaddr,
                        rv_target: val,
                        size: 8,
                        table_base_rv: None,
                    });
                }
            }
            off += 8;
        }
    }

    if entries.is_empty() {
        return;
    }

    let targets: std::collections::HashSet<u64> = entries.iter().map(|e| e.rv_target).collect();
    let rv_to_jt = ctx.build_function_pointer_map(&targets);

    for entry in &entries {
        let Some(jt_addr) = rv_to_jt.get(&entry.rv_target).copied().or(pruned) else {
            continue;
        };
        let replacement = match (entry.size, entry.table_base_rv) {
            (8, _) => (jt_addr as u64).to_le_bytes().to_vec(),
            (4, None) => jt_addr.to_le_bytes().to_vec(),
            (4, Some(rv_base)) => {
                // Relative entry: code does `lw off, table(idx); add target,
                // off, base; jr target`.
                let pvm_base = ctx
                    .address_map
                    .get(&rv_base)
                    .copied()
                    .unwrap_or(rv_base as u32);
                let value = (jt_addr as i64 - pvm_base as i64) as i32;
                value.to_le_bytes().to_vec()
            }
            _ => continue,
        };
        let size = replacement.len();
        if let Some(off) = entry
            .data_vaddr
            .checked_sub(ro_base)
            .and_then(|off| usize::try_from(off).ok())
            .filter(|off| off.saturating_add(size) <= ro_data.len())
        {
            ro_data[off..off + size].copy_from_slice(&replacement);
        } else if let Some(off) = entry
            .data_vaddr
            .checked_sub(rw_base)
            .and_then(|off| usize::try_from(off).ok())
            .filter(|off| off.saturating_add(size) <= rw_data.len())
        {
            rw_data[off..off + size].copy_from_slice(&replacement);
        }
    }
}

/// Addresses that direct branches and jumps reach. Translation must not
/// carry fusion state into them: an incoming edge brings its own registers.
fn direct_targets(elf: &LinkedElf) -> HashSet<u64> {
    let mut targets = HashSet::new();
    for (_, base, data) in &elf.code_sections {
        for (index, word) in data.chunks_exact(4).enumerate() {
            let inst = u32::from_le_bytes(word.try_into().expect("four-byte chunk"));
            let offset = match inst & 0x7f {
                0x63 => crate::riscv::decode_b_imm(inst),
                0x6f => crate::riscv::decode_j_imm(inst),
                _ => continue,
            };
            let address = base + 4 * index as u64;
            targets.insert(address.wrapping_add_signed(i64::from(offset)));
        }
    }
    targets
}

/// Translate one code section. `targets` holds every address another
/// control-flow edge may enter.
fn translate_section_linked(
    ctx: &mut TranslationContext,
    data: &[u8],
    base_addr: u64,
    elf: &LinkedElf,
    targets: &HashSet<u64>,
) -> Result<(), TranspileError> {
    let mut offset = 0;
    while offset < data.len() {
        let rv_addr = base_addr + offset as u64;
        ctx.begin_instruction(rv_addr, targets.contains(&rv_addr))?;

        if offset + 4 > data.len() {
            break;
        }

        let inst = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        // Skip non-instruction bytes
        if inst & 0x3 != 0x3 {
            // Compressed instruction — not supported for rv64em
            return Err(TranspileError::UnsupportedInstruction {
                offset: rv_addr as usize,
                detail: "compressed instruction in rv64em ELF".into(),
            });
        }

        let opcode = inst & 0x7f;

        // Check for relocation overrides
        if opcode == 0x17 {
            // AUIPC
            let rd = ((inst >> 7) & 0x1f) as u8;

            if let Some(&target_addr) = elf.call_targets.get(&rv_addr) {
                // CALL_PLT: AUIPC+JALR pair for function call
                // Peek at JALR to get link register
                if offset + 8 <= data.len() {
                    if targets.contains(&(rv_addr + 4)) {
                        return Err(TranspileError::InvalidSection(format!(
                            "control-flow target {:#x} splits a relocated AUIPC+JALR call pair at {rv_addr:#x}",
                            rv_addr + 4
                        )));
                    }
                    let jalr = u32::from_le_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    let jalr_rd = ((jalr >> 7) & 0x1f) as u8;
                    let ret_addr = rv_addr + 8;

                    // This relocation override bypasses `translate_one`, so flush
                    // any LUI/AUIPC buffered by the linear predecessor before the
                    // call can transfer control. This also clears load-immediate
                    // fusion state: a later consumer must not fuse backwards across
                    // the emitted call and truncate its bytes.
                    ctx.flush_pending()?;
                    // Fused load_imm_jump: set return address and jump in one instruction
                    ctx.emit_call(jalr_rd, ret_addr, target_addr)?;
                    // Map the JALR address too
                    ctx.address_map.insert(rv_addr + 4, ctx.code.len() as u32);
                    offset += 8; // skip both AUIPC and JALR
                    continue;
                }
            }

            if let Some(&target_addr) = elf.hi20_targets.get(&rv_addr) {
                // PCREL_HI20: AUIPC for data reference.
                // Peek ahead: if the next instruction is a paired LO12 ADDI (nop),
                // skip it and set pending_load_imm to enable cascading fusion
                // with the instruction after (load_ind, store_ind, ALU, branch).
                let next_addr = rv_addr + 4;
                if offset + 8 <= data.len()
                    && let Some(&_) = elf.lo12_targets.get(&next_addr)
                {
                    if elf.control_flow_targets.contains(&next_addr) {
                        return Err(TranspileError::InvalidSection(
                            "control-flow target splits a relocated HI20+LO12 pair".into(),
                        ));
                    }
                    let next_inst = u32::from_le_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    let next_opcode = next_inst & 0x7f;
                    let next_funct3 = (next_inst >> 12) & 0x7;
                    let next_rd = ((next_inst >> 7) & 0x1f) as u8;
                    let next_rs1 = ((next_inst >> 15) & 0x1f) as u8;

                    if next_opcode == 0x13 && next_funct3 == 0 && next_rs1 == rd {
                        // LO12 ADDI: address is already complete from HI20.
                        // Emit load_imm into the ADDI's destination register
                        // and set pending_load_imm for cascading fusion.
                        let dest = if next_rd != 0 { next_rd } else { rd };
                        let pos = ctx.code.len();
                        // If target is a code address (function pointer), load
                        // a jump table address instead of the raw RISC-V address.
                        let load_val = if ctx.is_code_addr(target_addr) {
                            let jt_idx = ctx.jump_table.len();
                            ctx.jump_table.push(0);
                            ctx.return_fixups.push((jt_idx, target_addr));
                            ((jt_idx + 1) * 2) as i64
                        } else {
                            target_addr as i64
                        };
                        ctx.emit_load_imm(dest, load_val)?;
                        ctx.pending_load_imm = Some((dest, load_val, pos));
                        ctx.address_map.insert(next_addr, ctx.code.len() as u32);
                        offset += 8; // skip both AUIPC and ADDI
                        continue;
                    }
                }

                // No paired LO12 ADDI next — emit load_imm with pending tracking.
                // This enables fusion with the next load/store/ALU/branch via
                // pending_load_imm even when the LO12 is a LOAD or STORE directly.
                let pos = ctx.code.len();
                // If target is a code address, use jump table address.
                let load_val = if ctx.is_code_addr(target_addr) {
                    let jt_idx = ctx.jump_table.len();
                    ctx.jump_table.push(0);
                    ctx.return_fixups.push((jt_idx, target_addr));
                    ((jt_idx + 1) * 2) as i64
                } else {
                    target_addr as i64
                };
                ctx.emit_load_imm(rd, load_val)?;
                ctx.pending_load_imm = Some((rd, load_val, pos));
                offset += 4;
                continue;
            }
        }

        // Check if this instruction has a PCREL_LO12 relocation.
        // If so, the rs1 register already contains the full resolved address
        // (loaded by the paired AUIPC/HI20 above). Override immediate to 0
        // and route through translate_load/translate_store to enable fusion
        // with the pending_load_imm set by the HI20 handler above.
        if let Some(&_data_addr) = elf.lo12_targets.get(&rv_addr) {
            let rd = ((inst >> 7) & 0x1f) as u8;
            let rs1 = ((inst >> 15) & 0x1f) as u8;
            let funct3 = (inst >> 12) & 0x7;

            if opcode == 0x13 && funct3 == 0 {
                // ADDI rd, rs1, lo12 → address already loaded by HI20.
                // This path is reached when the HI20 peek-ahead didn't consume
                // this ADDI (e.g., non-adjacent HI20/LO12 pair).
                if rd != rs1 && rd != 0 {
                    let pvm_src = ctx.require_reg(rs1)?;
                    let pvm_dst = ctx.require_reg(rd)?;
                    ctx.emit_inst(100); // move_reg
                    ctx.emit_data(pvm_dst | (pvm_src << 4));
                } else {
                    ctx.emit_inst(1); // fallthrough
                }
                offset += 4;
                continue;
            } else if opcode == 0x03 {
                // LOAD rd, lo12(rs1) → route through translate_load with imm=0.
                // If pending_load_imm is set (from HI20), this fuses into a
                // direct load (load_* rd, addr) — saving one instruction.
                ctx.translate_load(funct3, rd, rs1, 0, rv_addr)?;
                offset += 4;
                continue;
            } else if opcode == 0x23 {
                // STORE rs2, lo12(rs1) → route through translate_store with imm=0.
                let rs2 = ((inst >> 20) & 0x1f) as u8;
                ctx.translate_store(funct3, rs1, rs2, 0, rv_addr)?;
                offset += 4;
                continue;
            }
            // Fallthrough: translate normally (shouldn't happen for well-formed code)
        }

        // Normal instruction translation
        let consumed = ctx.translate_instruction(data, offset, base_addr)?;
        offset += consumed;
    }

    // Flush any pending LUI/AUIPC at section boundary
    ctx.flush_pending()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos_pvm::{ExitReason, refine};

    #[test]
    fn relocation_interval_index_matches_byte_overlap() {
        let original = vec![(20, 24), (4, 8), (6, 14), (24, 28), (4, 8), (40, 48)];
        let merged = merge_ranges(original.clone());
        assert_eq!(merged, vec![(4, 14), (20, 28), (40, 48)]);
        for address in 0..56 {
            for size in 1..=8u8 {
                let expected = original
                    .iter()
                    .any(|&(start, end)| address < end && start < address + u64::from(size));
                assert_eq!(overlaps_data_relocation(&merged, address, size), expected);
            }
        }
        assert!(!overlaps_data_relocation(&[], 4, 8));
    }

    const TEXT_VADDR: u64 = 0x40_0000;
    const RA: u32 = 1;
    const SP: u32 = 2;
    const T0: u32 = 5;
    const T2: u32 = 7;
    const A0: u32 = 10;
    const A1: u32 = 11;
    const A2: u32 = 12;

    fn lui(rd: u32, imm20: u32) -> u32 {
        (imm20 << 12) | (rd << 7) | 0x37
    }

    fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
        ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0x13
    }

    fn auipc(rd: u32) -> u32 {
        (rd << 7) | 0x17
    }

    fn jalr(rd: u32, rs1: u32) -> u32 {
        (rs1 << 15) | (rd << 7) | 0x67
    }

    fn sd(rs2: u32, rs1: u32, imm: i32) -> u32 {
        let imm = imm as u32 & 0xfff;
        ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (3 << 12) | ((imm & 0x1f) << 7) | 0x23
    }

    fn assemble(insts: &[u32]) -> Vec<u8> {
        insts.iter().flat_map(|inst| inst.to_le_bytes()).collect()
    }

    fn ld(rd: u32, rs1: u32, imm: i32) -> u32 {
        ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (3 << 12) | (rd << 7) | 0x03
    }

    fn jal(rd: u32, offset: i32) -> u32 {
        let i = offset as u32;
        (((i >> 20) & 1) << 31)
            | (((i >> 1) & 0x3ff) << 21)
            | (((i >> 11) & 1) << 20)
            | (((i >> 12) & 0xff) << 12)
            | (rd << 7)
            | 0x6f
    }

    /// A linked ELF of `text` at `TEXT_VADDR`, whose code reaches twice as
    /// far as `text` does: the rest pruned, as a kernel's is.
    fn pruned(text: &[u8], ro_data: Vec<u8>, pointers: Vec<(u64, u64, u8)>) -> LinkedElf {
        let len = text.len() as u64;
        LinkedElf {
            is_64bit: true,
            code_sections: vec![(0, TEXT_VADDR, text.to_vec())],
            ro_data,
            ro_base: 0x1_0000,
            rw_data: Vec::new(),
            rw_base: 0x2_0000,
            rw_min: 0x2_0000,
            rw_len: 0,
            stack_size: 0x1_0000,
            heap_pages: 0,
            symbols: Vec::new(),
            names: Vec::new(),
            data_relocs: Vec::new(),
            symbol_refs: Vec::new(),
            relocations: pointers.len(),
            unknown_relocation: None,
            schema: None,
            hi20_targets: HashMap::new(),
            lo12_targets: HashMap::new(),
            call_targets: HashMap::new(),
            abs_code_ptrs: pointers,
            sub32_relocs: Vec::new(),
            data_relocation_ranges: Vec::new(),
            code_ranges: vec![(TEXT_VADDR, TEXT_VADDR + 2 * len + 0x1000)],
            control_flow_targets: HashSet::from([TEXT_VADDR]),
            entry_vaddr: TEXT_VADDR,
            accumulate_vaddr: None,
        }
    }

    /// A kernel's code pointer to code it pruned becomes an address no jump
    /// table reaches: jumping to it panics, never runs other code.
    #[test]
    fn a_pointer_into_pruned_code_cannot_be_jumped_to() {
        const T1: u32 = 6;
        let text = assemble(&[
            lui(T1, 0x10), // the pointer's address, the read-only base
            ld(T1, T1, 0), // the pointer
            jalr(RA, T1),  // call through it
            jalr(0, RA),
        ]);
        let target = TEXT_VADDR + 0x1000;
        let elf = pruned(
            &text,
            target.to_le_bytes().to_vec(),
            vec![(0x1_0000, target, 8)],
        );
        let (kernel, _) = transpile_with(&elf, Link::Kernel).expect("translates");
        assert_eq!(kernel.ro_data, u64::from(PRUNED).to_le_bytes());
        assert!(kernel.jump_table.len() * 2 < PRUNED as usize);
        let blob = spi_blob(kernel).expect("links");
        let invocation = refine::execute(&blob, &[], 10_000_000).expect("executes");
        assert_eq!(invocation.exit, ExitReason::Panic);
        // Linked whole, the pointer is left as it was.
        let (whole, _) = transpile_with(&elf, Link::Whole).expect("translates");
        assert_eq!(whole.ro_data, target.to_le_bytes());
    }

    /// A kernel's branch to code it pruned reaches a trap, and code that
    /// would fall off its end traps too.
    #[test]
    fn a_branch_into_pruned_code_traps() {
        let text = assemble(&[jal(0, 0x1000)]);
        let elf = pruned(&text, Vec::new(), Vec::new());
        let (kernel, _) = transpile_with(&elf, Link::Kernel).expect("translates");
        let blob = spi_blob(kernel).expect("links");
        let invocation = refine::execute(&blob, &[], 10_000_000).expect("executes");
        assert_eq!(invocation.exit, ExitReason::Panic);
        let falls = pruned(&assemble(&[addi(A0, A0, 1)]), Vec::new(), Vec::new());
        let (kernel, _) = transpile_with(&falls, Link::Kernel).expect("translates");
        let blob = spi_blob(kernel).expect("links");
        let invocation = refine::execute(&blob, &[], 10_000_000).expect("executes");
        assert_eq!(invocation.exit, ExitReason::Panic);
    }

    #[test]
    fn relocated_call_flushes_pending_lui_before_transfer() {
        const LIMIT: u64 = 8192;
        const CALL_SITE: u64 = TEXT_VADDR + 8;
        const RETURN_ADDR: u64 = TEXT_VADDR + 16;
        const CALLEE: u64 = TEXT_VADDR + 32;

        // The LUI is deliberately adjacent to the relocated AUIPC+JALR pair.
        // The callee snapshots A2 before the caller can execute another normal
        // instruction. If CALL_PLT bypasses the buffered-LUI flush, it observes
        // zero instead of LIMIT (the agent-runtime bytes_bounded failure mode).
        let text = assemble(&[
            addi(T2, RA, 0),  // preserve the host return address
            lui(A2, 2),       // buffered A2 = 8192
            auipc(T0),        // R_RISCV_CALL_PLT relocation lives here
            jalr(RA, T0),     // relocation override consumes this instruction
            addi(RA, T2, 0),  // restore the host return address
            addi(A0, SP, -8), // designate the callee's snapshot as output
            addi(A1, 0, 8),
            jalr(0, RA), // return to the host
            sd(A2, SP, -8),
            jalr(0, RA), // callee return
        ]);

        let elf = LinkedElf {
            is_64bit: true,
            code_sections: vec![(0, TEXT_VADDR, text.clone())],
            ro_data: Vec::new(),
            ro_base: 0x1_0000,
            rw_data: Vec::new(),
            rw_base: 0x2_0000,
            rw_min: 0x2_0000,
            rw_len: 0,
            stack_size: 0x1_0000,
            heap_pages: 0,
            symbols: Vec::new(),
            names: Vec::new(),
            data_relocs: Vec::new(),
            symbol_refs: Vec::new(),
            relocations: 1,
            unknown_relocation: None,
            schema: None,
            hi20_targets: HashMap::new(),
            lo12_targets: HashMap::new(),
            call_targets: HashMap::from([(CALL_SITE, CALLEE)]),
            abs_code_ptrs: Vec::new(),
            sub32_relocs: Vec::new(),
            data_relocation_ranges: Vec::new(),
            code_ranges: vec![(TEXT_VADDR, TEXT_VADDR + text.len() as u64)],
            control_flow_targets: HashSet::from([TEXT_VADDR, RETURN_ADDR, CALLEE]),
            entry_vaddr: TEXT_VADDR,
            accumulate_vaddr: None,
        };

        let mut ctx = TranslationContext::new(true);
        ctx.code_ranges = elf.code_ranges.clone();
        ctx.emit_jump(elf.entry_vaddr);
        ctx.emit_inst(0); // unused accumulate entry
        translate_section_linked(&mut ctx, &text, TEXT_VADDR, &elf, &elf.control_flow_targets)
            .expect("translates");
        ctx.apply_fixups();

        crate::peephole_fuse_load_imm_alu(&mut ctx.code, &mut ctx.bitmask, &ctx.jump_table);
        crate::peephole_fuse_load_imm_memory(&mut ctx.code, &mut ctx.bitmask, &ctx.jump_table);
        crate::ensure_branch_targets_are_block_starts(
            &mut ctx.code,
            &mut ctx.bitmask,
            &mut ctx.jump_table,
        );

        let blob = crate::spi::build_spi_blob(
            &[],
            &[],
            elf.heap_pages as u16,
            elf.stack_size,
            &ctx.code,
            &ctx.bitmask,
            &ctx.jump_table,
        );
        let invocation = refine::execute(&blob, &[], 10_000_000).expect("executes");

        assert_eq!(invocation.exit, ExitReason::Halt);
        assert_eq!(
            invocation
                .output_bounded(core::mem::size_of::<u64>())
                .as_deref(),
            Some(&LIMIT.to_le_bytes()[..]),
            "the callee must observe the LUI value before control transfers"
        );
    }
}

#[cfg(test)]
#[path = "linker_differential.rs"]
mod differential;
