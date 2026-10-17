//! An ELF linked into a standard program, its relocations followed, so
//! its code finds the data it references (`.rodata` constants, tables) and
//! its data the code it points at.
//!
//! The parse reads the ELF's sections and symbols ([`elf`]), lays its data
//! out ([`layout`]), reads its relocations ([`relocs`]) and finds where
//! control may enter its code ([`targets`]). Translation then turns each
//! instruction into PVM code, an AUIPC and the instruction completing its
//! address into one load of the final address, and rewrites the code
//! pointers in the data ([`translate`]).

mod elf;
mod layout;
mod relocs;
mod targets;
mod translate;

use std::collections::{BTreeMap, BTreeSet, HashSet};

use vos_pvm::instruction::Opcode;

use crate::TranspileError;
use crate::riscv::TranslationContext;

pub(crate) use elf::{name_at, name_is};
pub(crate) use layout::{Z_Z, spi_blob, zone_round};
pub(crate) use relocs::{in_ranges, merge_ranges, range_at};
pub(crate) use targets::{direct_targets, raw_code_pointers};

use elf::sections;
use layout::{HEAP_PAGES, layout};
use relocs::relocations;
use targets::control_flow_targets;
use translate::{rewrite_data_code_ptrs, translate_section_linked};

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
#[derive(Default)]
pub(crate) struct LinkedElf {
    /// All code sections: (file_offset, vaddr, data)
    pub(crate) code_sections: Vec<(u64, u64, Vec<u8>)>,
    /// RO data blob and the vaddr its first byte is linked at: the
    /// page-floored lowest ro section address, or 16 KiB without one. It
    /// is also the stack's size, so RO data is at the right PVM address.
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
    /// The `.vos_heap` section, the heap's arena: its address and size.
    pub(crate) heap: Option<(u64, u64)>,
    /// PCREL_HI20: AUIPC instruction vaddr → resolved data address.
    /// The AUIPC itself should emit load_imm with this address.
    pub(crate) hi20_targets: BTreeMap<u64, u64>,
    /// PCREL_LO12 instruction vaddrs whose paired HI20 is known. These
    /// instructions use the address already loaded by the AUIPC.
    pub(crate) lo12_sites: BTreeSet<u64>,
    /// CALL_PLT: AUIPC instruction vaddr → target function RISC-V vaddr.
    pub(crate) call_targets: BTreeMap<u64, u64>,
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

impl LinkedElf {
    /// The initialized data, each region by the address its first byte is
    /// linked at: the read-only data, then the read-write data's
    /// initialized part.
    pub(crate) fn initialized(&self) -> [(u64, &[u8]); 2] {
        [(self.ro_base, &self.ro_data), (self.rw_base, &self.rw_data)]
    }
}

#[cfg(test)]
impl LinkedElf {
    /// A linked ELF of `code` alone at `vaddr`, its entry, with the
    /// read-only base at 0x1_0000 and the read-write one at 0x2_0000. Its
    /// control-flow targets are the entry and what its direct branches and
    /// jumps reach, as [`parse_linked_elf`] finds them.
    pub(crate) fn text(vaddr: u64, code: Vec<u8>) -> Self {
        let len = code.len() as u64;
        let code_sections = vec![(0, vaddr, code)];
        Self {
            control_flow_targets: targets::direct_targets(&code_sections)
                .chain([vaddr])
                .collect(),
            code_sections,
            code_ranges: vec![(vaddr, vaddr + len)],
            ro_base: 0x1_0000,
            rw_base: 0x2_0000,
            rw_min: 0x2_0000,
            entry_vaddr: vaddr,
            ..Self::default()
        }
    }
}

/// The result of transpiling an ELF: the code in GP instruction encoding
/// (plus bitmask and jump table) and the memory-section blobs at their linked
/// base addresses. [`link_elf_spi`] serializes exactly these fields.
pub(crate) struct TranspiledElf {
    code: Vec<u8>,
    bitmask: Vec<u8>,
    jump_table: Vec<u32>,
    /// RO data blob; its first byte is linked at `ro_base`, which is also
    /// the stack's byte capacity.
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
    /// Zeroed heap pages beyond `rw_data`.
    heap_pages: u32,
    /// Each function's first PVM instruction, and its name, by offset.
    functions: crate::Functions,
    /// Each `ecalli` emitted, by the address of its `ecall`, and its id.
    pub(crate) host_calls: Vec<(u64, u32)>,
}

impl TranspiledElf {
    /// The pc of an instruction whose static jump or branch target is the
    /// halt address, if one is: only a dynamic jump through the halt entry
    /// reaches it, as the proof's halt selector does.
    pub(crate) fn static_halt_target(&self) -> Option<u64> {
        use vos_pvm::args::{Args, decode_args};
        (0..self.code.len())
            .filter(|&pc| self.bitmask.get(pc) == Some(&1))
            .find(|&pc| {
                let Some(opcode) = Opcode::from_byte(self.code[pc]) else {
                    return false;
                };
                let skip = vos_pvm::interpreter::skip_for_bitmask(&self.bitmask, pc);
                let target = match decode_args(&self.code, pc, skip, opcode.category()) {
                    Args::Offset { offset }
                    | Args::RegImmOffset { offset, .. }
                    | Args::TwoRegOffset { offset, .. } => offset,
                    _ => return false,
                };
                target as u32 as u64 == vos_pvm::PVM_HALT_ADDR
            })
            .map(|pc| pc as u64)
    }
}

/// Transpile an rv64em ELF into a **GP standard-program (SPI) blob** — the
/// format `vos_pvm::spi::parse_standard_program` consumes and
/// `vos_pvm::refine::execute_with` runs. The entry prologue places refine at
/// IC 0 and accumulate (or a trap) at IC 5.
///
/// Header-field derivation:
///
/// - **`s` (stack size, `E₃`)** = the page-floored lowest ro section vaddr,
///   or 16 KiB without one. `StandardProgram::layout` maps `page_round(s)` bytes
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
    spi_blob(transpile_with(&parse_linked_elf(elf_data)?, Link::Whole)?)
}

/// [`link_elf_spi`], and each function's first PVM instruction in the
/// blob's code, with its name (demangled), by offset: what a profiler
/// names compiled code by.
pub fn link_elf_spi_with_symbols(
    elf_data: &[u8],
) -> Result<(Vec<u8>, crate::Functions), TranspileError> {
    let mut transpiled = transpile_with(&parse_linked_elf(elf_data)?, Link::Named)?;
    let functions = std::mem::take(&mut transpiled.functions);
    Ok((spi_blob(transpiled)?, functions))
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
/// with each `ecalli` it emitted, by the address of its `ecall`.
pub(crate) fn transpile_with(elf: &LinkedElf, link: Link) -> Result<TranspiledElf, TranspileError> {
    let kernel = link == Link::Kernel;
    let mut ctx = TranslationContext::default();
    ctx.code_ranges = elf.code_ranges.clone();
    ctx.trap_unresolved = kernel;

    // Emit the two-slot GP entry prologue. ICs are byte offsets into the code,
    // and a plain jump (opcode 40 + imm32) is exactly 5 bytes, so the two
    // jumps land at IC 0 and IC 5 respectively — the entry points a GP host
    // selects by starting the instruction counter at 0 (refine / is-authorized)
    // or 5 (accumulate). SP is the host's (φ1 = stack top). Each jump ends
    // its basic block, so IC 5 begins a fresh block. Both fixups are resolved
    // after translation in apply_fixups() (RISC-V vaddr → PVM PC).
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
        None => ctx.emit_op(Opcode::Trap),
    }

    for (_file_off, vaddr, data) in &elf.code_sections {
        translate_section_linked(&mut ctx, data, *vaddr, elf)?;
        if kernel {
            ctx.emit_op(Opcode::Trap);
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
    crate::ensure_branch_targets_are_block_starts(
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

    Ok(TranspiledElf {
        code: ctx.code,
        bitmask: ctx.bitmask,
        jump_table: ctx.jump_table,
        ro_data,
        ro_base: elf.ro_base,
        rw_data,
        rw_base: elf.rw_base,
        rw_min: elf.rw_min,
        rw_len: elf.rw_len,
        heap_pages: elf.heap_pages,
        functions,
        host_calls: ctx.host_calls,
    })
}

/// Parse ELF with full relocation info. Every field the bytes claim is
/// checked against the file and [`elf::limits`]: a malformed ELF is refused,
/// never read out of bounds.
pub(crate) fn parse_linked_elf(data: &[u8]) -> Result<LinkedElf, TranspileError> {
    let elf = sections(data)?;
    let layout = layout(&elf.ro, &elf.rw)?;
    // Code address ranges for detecting code pointers, sorted and merged.
    let code_ranges = merge_ranges(
        elf.code
            .iter()
            .map(|(_, vaddr, data)| (*vaddr, *vaddr + data.len() as u64))
            .collect(),
    );
    let relocations = relocations(data, &elf, &code_ranges)?;
    let mut linked = LinkedElf {
        code_sections: elf.code,
        ro_data: layout.ro_data,
        ro_base: layout.ro_base,
        rw_data: layout.rw_data,
        rw_base: layout.rw_base,
        rw_min: layout.rw_min,
        rw_len: layout.rw_len,
        heap_pages: HEAP_PAGES,
        symbols: elf.symbols,
        names: elf.names,
        data_relocs: relocations.data_relocs,
        symbol_refs: relocations.symbol_refs,
        relocations: relocations.count,
        unknown_relocation: relocations.unknown,
        schema: elf.schema,
        heap: elf.heap,
        hi20_targets: relocations.hi20_targets,
        lo12_sites: relocations.lo12_sites,
        call_targets: relocations.call_targets,
        abs_code_ptrs: relocations.abs_code_ptrs,
        sub32_relocs: relocations.sub32_relocs,
        data_relocation_ranges: relocations.ranges,
        code_ranges,
        control_flow_targets: HashSet::new(),
        entry_vaddr: elf.entry,
        accumulate_vaddr: elf.accumulate,
    };
    linked.control_flow_targets = control_flow_targets(&linked, &elf.values);
    Ok(linked)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod differential;
