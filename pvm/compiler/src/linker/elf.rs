//! An ELF's header, section table and symbol table, every field read
//! within the file.

use crate::TranspileError;

use super::Symbol;

/// The most sections, symbols and relocations an ELF may hold, and the
/// address space its loaded sections must lie in: a parse is bounded by
/// them whatever the bytes claim.
pub(crate) mod limits {
    pub(crate) const SECTIONS: usize = 1 << 12;
    pub(crate) const SYMBOLS: usize = 1 << 20;
    pub(crate) const RELOCATIONS: usize = 1 << 22;
    /// Loaded sections lie below this: the PVM's addresses are 32 bits.
    pub(crate) const ADDRESS_SPACE: u64 = 1 << 32;
    /// The most bytes of read-only or initialized read-write data: what a
    /// standard program's `E3` fields encode.
    pub(crate) const DATA: u64 = 1 << 24;
}

/// The ELF header's length, and the least a section header's.
const ELF_HEADER: usize = 64;
const SECTION_HEADER: usize = 64;
/// The ELF classes: 32- and 64-bit.
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
/// Section types: an unused header, a symbol table, a string table,
/// relocations with addends, and a section the file holds no bytes of.
const SHT_NULL: u32 = 0;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_NOBITS: u32 = 8;
/// Section flags: written, loaded and executed.
const SHF_WRITE: u64 = 1;
pub(super) const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;
/// An `Elf64_Sym`'s and an `Elf64_Rela`'s length.
const SYMBOL_ENTRY: usize = 24;
pub(super) const RELA_ENTRY: usize = 24;

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
pub(super) fn span(data: &[u8], offset: u64, len: u64) -> Option<&[u8]> {
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

/// `data` with the names of its temporary symbols (`.L…`) zeroed in its
/// symbol table's string table: what a package's ELF hash covers. LLVM
/// names a module's private globals after the module's hash, which follows
/// its dependencies' source, and the transpiler reads no such name; the
/// rest of the bytes, the code, data, relocations and every other name,
/// stay. Refused unless those names lie in a string table of their own,
/// no other section's bytes and not the sections' names, and no other
/// name shares their bytes: the zeroed bytes are then only theirs, and
/// two packages the transpiler reads apart never hash alike.
pub(crate) fn without_temporary_names(data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    let parsed = sections(data)?;
    let mut kept = data.to_vec();
    let Some(symtab) = parsed.symtab.map(|index| &parsed.headers[index]) else {
        return Ok(kept);
    };
    let refused = |why: &str| TranspileError::ElfParse(format!("its symbols' names {why}"));
    let table = &parsed.headers[symtab.link];
    if table.sh_type != SHT_STRTAB
        || table.flags & SHF_ALLOC != 0
        || symtab.link == parsed.section_names
    {
        return Err(refused("are not in a string table of their own"));
    }
    let (from, to) = (table.file_off, table.file_off + table.size);
    let overlaps = parsed.headers.iter().enumerate().any(|(index, other)| {
        index != symtab.link
            && !matches!(other.sh_type, SHT_NULL | SHT_NOBITS)
            && other.size > 0
            && other.file_off < to
            && from < other.file_off.saturating_add(other.size)
    });
    if overlaps {
        return Err(refused("share bytes with another section"));
    }
    let names = &parsed.names;
    let entries = span(data, symtab.file_off, symtab.size).unwrap_or(&[]);
    let mut starts: Vec<usize> = entries
        .chunks_exact(SYMBOL_ENTRY)
        .map(|entry| u32::from_le_bytes(entry[0..4].try_into().expect("four bytes")) as usize)
        .filter(|&at| at < names.len())
        .collect();
    starts.sort_unstable();
    starts.dedup();
    // One pass in offset order: each name ends at the next NUL, and one
    // starting inside a name of the other kind shares its bytes.
    let base = from as usize;
    let (mut nul, mut temporary_end, mut named_end) = (0, 0, 0);
    for at in starts {
        nul = nul.max(at);
        nul += names[nul..]
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(names.len() - nul);
        let temporary = names[at..].starts_with(b".L");
        if at < if temporary { named_end } else { temporary_end } {
            return Err(refused("share bytes, a temporary one and another"));
        }
        if temporary {
            temporary_end = nul;
            kept[base + at..base + nul].fill(0);
        } else {
            named_end = nul;
        }
    }
    Ok(kept)
}

/// A section header's fields the linker reads.
pub(super) struct SectionInfo {
    name_off: usize,
    sh_type: u32,
    pub(super) flags: u64,
    addr: u64,
    pub(super) file_off: u64,
    pub(super) size: u64,
    link: usize,
    pub(super) info: usize,
}

/// What an ELF's header, section table and symbol table give the linker.
pub(super) struct Sections {
    /// The entry point, `e_entry`: refine's.
    pub(super) entry: u64,
    /// The section headers, by index.
    pub(super) headers: Vec<SectionInfo>,
    /// The code sections: file offset, vaddr and bytes.
    pub(super) code: Vec<(u64, u64, Vec<u8>)>,
    /// The read-only sections: vaddr, size and bytes.
    pub(super) ro: Vec<(u64, usize, Vec<u8>)>,
    /// The read-write sections: vaddr, size, and bytes but for NOBITS.
    pub(super) rw: Vec<(u64, usize, Option<Vec<u8>>)>,
    /// The relocation sections, by index.
    pub(super) relas: Vec<usize>,
    /// The `.vos_schema` section's bytes.
    pub(super) schema: Option<Vec<u8>>,
    /// The `.vos_heap` section, the heap's arena: its address and size.
    pub(super) heap: Option<(u64, u64)>,
    /// Each symbol's value, by its index.
    pub(super) values: Vec<u64>,
    /// The defined symbols, in the table's order, and their names' table.
    pub(super) symbols: Vec<Symbol>,
    pub(super) names: Vec<u8>,
    /// The exported `accumulate` symbol's address.
    pub(super) accumulate: Option<u64>,
    /// The symbol table's index, and the section names' table's.
    pub(super) symtab: Option<usize>,
    pub(super) section_names: usize,
}

/// Read the ELF header, the section table, and the symbol table.
pub(super) fn sections(data: &[u8]) -> Result<Sections, TranspileError> {
    if data.len() < ELF_HEADER || data[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err(TranspileError::ElfParse("not an ELF file".into()));
    }

    match data[4] {
        ELFCLASS64 => {}
        ELFCLASS32 => {
            return Err(TranspileError::ElfParse(
                "linker requires 64-bit ELF (rv64em)".into(),
            ));
        }
        _ => return Err(TranspileError::ElfParse("unsupported ELF class".into())),
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
    if e_shnum > 0 && e_shentsize < SECTION_HEADER {
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
        let Some(sh) = header(i).filter(|sh| {
            sh.checked_add(SECTION_HEADER)
                .is_some_and(|end| end <= data.len())
        }) else {
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
    let mut heap = None;
    // The bytes copied out of the file: at most its length, so sections
    // that share bytes cannot multiply them.
    let mut copied = 0usize;
    let mut copy = |bytes: &[u8]| {
        copied += bytes.len();
        if copied > data.len() {
            return Err(TranspileError::ElfParse(
                "its loaded sections share the file's bytes".into(),
            ));
        }
        Ok(bytes.to_vec())
    };

    for (i, s) in sections.iter().enumerate() {
        let name = get_name(s.name_off);
        let is_alloc = s.flags & SHF_ALLOC != 0;
        let is_exec = s.flags & SHF_EXECINSTR != 0;
        let is_write = s.flags & SHF_WRITE != 0;

        if s.sh_type == SHT_SYMTAB {
            symtab_idx = Some(i);
        }
        if s.sh_type == SHT_RELA {
            rela_section_indices.push(i);
        }
        if !is_alloc || s.sh_type == SHT_NULL {
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
                code_sections.push((s.file_off, s.addr, copy(bytes)?));
            }
        } else if name.starts_with(".rodata")
            || name == ".srodata"
            || name.starts_with(".data.rel.ro")
            || name == ".vos_schema"
        {
            if let Some(bytes) = bytes {
                let bytes = copy(bytes)?;
                if name == ".vos_schema" {
                    schema = Some(bytes.clone());
                }
                ro_sections.push((s.addr, size, bytes));
            }
        } else if is_write {
            if name == ".vos_heap" {
                heap = Some((s.addr, s.size));
            }
            if s.sh_type == SHT_NOBITS {
                rw_sections.push((s.addr, size, None));
            } else if let Some(bytes) = bytes {
                rw_sections.push((s.addr, size, Some(copy(bytes)?)));
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
        let count = (s.size / SYMBOL_ENTRY as u64) as usize;
        if count > limits::SYMBOLS {
            return Err(TranspileError::ElfParse(format!(
                "{count} symbols, past {}",
                limits::SYMBOLS
            )));
        }
        let table = span(data, s.file_off, s.size).unwrap_or(&[]);
        for entry in table.chunks_exact(SYMBOL_ENTRY) {
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

    Ok(Sections {
        entry: e_entry,
        headers: sections,
        code: code_sections,
        ro: ro_sections,
        rw: rw_sections,
        relas: rela_section_indices,
        schema,
        heap,
        values,
        symbols,
        names,
        accumulate: accumulate_vaddr,
        symtab: symtab_idx,
        section_names: e_shstrndx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOMY: &[u8] = include_bytes!("../../tests/fixtures/roomy.elf");

    /// `elf` with symbol `index`'s name at `at` of its string table.
    fn named(elf: &[u8], index: usize, at: usize) -> Vec<u8> {
        let parsed = sections(elf).unwrap();
        let symtab = &parsed.headers[parsed.symtab.unwrap()];
        let entry = symtab.file_off as usize + index * SYMBOL_ENTRY;
        let mut named = elf.to_vec();
        named[entry..entry + 4].copy_from_slice(&(at as u32).to_le_bytes());
        named
    }

    /// A name inside a temporary one, or a temporary one inside another
    /// name, would be zeroed with it: refused.
    #[test]
    fn a_name_sharing_a_temporary_ones_bytes_is_refused() {
        assert!(without_temporary_names(ROOMY).is_ok());
        let names = sections(ROOMY).unwrap().names;
        let temporary = names.windows(7).position(|w| w == b".Lanon.").unwrap();
        let inside = named(ROOMY, 1, temporary + 2);
        assert!(without_temporary_names(&inside).is_err());

        let named_at = names
            .windows(4)
            .position(|w| w == b"_RNv")
            .expect("a function's name");
        let mut around = named(ROOMY, 1, named_at);
        let table = sections(ROOMY).unwrap();
        let strtab = &table.headers[table.headers[table.symtab.unwrap()].link];
        let at = strtab.file_off as usize + named_at + 4;
        around[at..at + 2].copy_from_slice(b".L");
        let around = named(&around, 2, named_at + 4);
        assert!(without_temporary_names(&around).is_err());
    }

    /// Symbol names in the sections' names' table are refused.
    #[test]
    fn names_in_the_section_names_table_are_refused() {
        let parsed = sections(ROOMY).unwrap();
        let symtab = parsed.symtab.unwrap();
        // A section header's `sh_link`, 40 bytes in.
        let link = 40;
        let header = u64::from_le_bytes(ROOMY[40..48].try_into().unwrap()) as usize
            + symtab * SECTION_HEADER;
        let mut linked = ROOMY.to_vec();
        linked[header + link..header + link + 4]
            .copy_from_slice(&(parsed.section_names as u32).to_le_bytes());
        assert!(without_temporary_names(&linked).is_err());
    }
}
