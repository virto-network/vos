//! One ELF in, programs out: from the ELF an actor's crate builds, the
//! actor's program and one kernel per attestable method.
//!
//! - **The actor's program** is the ELF linked from its entry, `_start`, as
//!   [`crate::link_elf_spi`] links it. Its workflows are in it, routed by
//!   method.
//! - **A kernel** is the ELF linked from one attestable method's entry
//!   alone: the code its relocations reach from the entry (calls, PC-relative
//!   pairs, absolute data relocations, switch tables) and direct branches,
//!   and the data they reach, with an instruction-0 prologue that calls the
//!   entry and returns to the halt address. The entries are the ELF's table
//!   `VOS_ATTEST`, each an attestable method's id and its entry.
//!
//! **Reachability follows relocations,** so an ELF without them, or with a
//! relocation type the linker does not follow, is refused, as is one whose
//! code lies in more than one section. The heuristic scan for code-like
//! values in data may add targets, never prune one. A code pointer whose
//! target was pruned becomes an address no jump table reaches, and a branch
//! to pruned code reaches a trap: a missed target can only trap, never run
//! something else. A data object reached is kept whole, from the symbol at
//! or before its address to the next, or as far as a sized symbol covering
//! it reaches, and so is the object of the symbol a relocation names, where
//! its addend points elsewhere; data no reachable code names is zeros in
//! the kernel, its addresses unchanged.
//!
//! **A kernel makes no host call but the precompiles:** one whose reachable
//! code does is refused, naming the chain of functions from the entry to
//! the call.
//!
//! **Bounded work:** every lookup is logarithmic, and a kernel is built
//! from what its entry reaches alone, so a derivation's work grows with the
//! ELF once and with each kernel's reach and size, whatever the ELF claims.
//!
//! **Bit-reproducible:** the output's order comes from sorted sections,
//! symbols and addresses, never from a map's iteration, so the same ELF and
//! [`TRANSPILER_VERSION`] give the same bytes on any machine.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use crate::TranspileError;
use crate::linker::{
    Link, LinkedElf, STT_FUNC, Z_Z, in_ranges, merge_ranges, name_at, name_is,
    overlaps_data_relocation, parse_linked_elf, spi_blob, transpile_with, zone_round,
};
use crate::riscv::{decode_b_imm, decode_j_imm};

/// The derivation's version: it changes whenever the bytes it derives from
/// the same ELF may, so a derived program's hash is pinned per version.
pub const TRANSPILER_VERSION: u32 = 1;

/// The largest ELF a derivation reads: an install's body.
pub const MAX_ELF: usize = 64 << 20;

/// The most attestable methods an actor may have: a schema's methods.
const MAX_ATTESTABLES: usize = 1024;

/// The relocation types a derivation follows, in sections the program
/// loads: `R_RISCV_32` and `_64`, `_BRANCH` and `_JAL`, `_CALL_PLT`, the
/// PC-relative pairs, and `_ADD32` and `_SUB32`.
const FOLLOWED: [u32; 10] = [1, 2, 16, 17, 19, 23, 24, 25, 35, 39];

/// What an ELF derives: its actor's program, a kernel per attestable
/// method by its id in ascending order, the schema's section as the ELF's
/// `.vos_schema` holds it, and the version that derived them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derived {
    pub actor: Vec<u8>,
    pub kernels: Vec<(u32, Vec<u8>)>,
    pub schema: Vec<u8>,
    pub transpiler_version: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum DeriveError {
    #[error("the ELF holds {0} bytes, past {MAX_ELF}")]
    TooLarge(usize),
    #[error(transparent)]
    Transpile(#[from] TranspileError),
    #[error("the ELF holds no relocations: link it with `--emit-relocs`")]
    NoRelocations,
    #[error("the ELF holds relocation type {0}, which a derivation does not follow")]
    Relocation(u32),
    #[error("the ELF's code lies in {0} sections, not one")]
    CodeSections(usize),
    #[error("the ELF has no `.vos_schema` section")]
    NoSchema,
    #[error("the attestable methods' table: {0}")]
    Table(String),
    #[error("a kernel reaches code from {0:#x} to {1:#x}, which no code section holds whole")]
    Unreadable(u64, u64),
    #[error(
        "attestable method {method:#010x} makes host call {id:#x}, no precompile, through {}",
        chain.join(" -> ")
    )]
    HostCall {
        method: u32,
        id: u64,
        chain: Vec<String>,
    },
}

/// Derive an actor's program and its kernels from its ELF.
pub fn derive(elf: &[u8]) -> Result<Derived, DeriveError> {
    if elf.len() > MAX_ELF {
        return Err(DeriveError::TooLarge(elf.len()));
    }
    let linked = parse_linked_elf(elf)?;
    if linked.relocations == 0 {
        return Err(DeriveError::NoRelocations);
    }
    if let Some(kind) = linked
        .unknown_relocation
        .filter(|kind| !FOLLOWED.contains(kind))
    {
        return Err(DeriveError::Relocation(kind));
    }
    if linked.code_sections.len() > 1 {
        return Err(DeriveError::CodeSections(linked.code_sections.len()));
    }
    let schema = linked.schema.clone().ok_or(DeriveError::NoSchema)?;
    let (actor, _) = transpile_with(&linked, Link::Whole)?;
    let actor = spi_blob(actor)?;
    let graph = Graph::new(&linked);
    let kernels = attestables(&linked)?
        .into_iter()
        .map(|(method, entry)| Ok((method, kernel(&graph, method, entry)?)))
        .collect::<Result<_, DeriveError>>()?;
    Ok(Derived {
        actor,
        kernels,
        schema,
        transpiler_version: TRANSPILER_VERSION,
    })
}

/// The ELF's attestable methods and their entries, from its `VOS_ATTEST`
/// table, by method id: none without the table.
fn attestables(elf: &LinkedElf) -> Result<Vec<(u32, u64)>, DeriveError> {
    let table = |why: &str| DeriveError::Table(why.to_string());
    let Some(symbol) = elf
        .symbols
        .iter()
        .find(|symbol| name_is(&elf.names, symbol.name, b"VOS_ATTEST"))
    else {
        return Ok(Vec::new());
    };
    if !symbol.size.is_multiple_of(16) {
        return Err(table("its size is no whole number of entries"));
    }
    if symbol.size / 16 > MAX_ATTESTABLES as u64 {
        return Err(table(&format!(
            "{} entries, past {MAX_ATTESTABLES}",
            symbol.size / 16
        )));
    }
    let start = symbol
        .value
        .checked_sub(elf.ro_base)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or_else(|| table("it lies outside the read-only data"))?;
    let bytes = start
        .checked_add(symbol.size as usize)
        .and_then(|end| elf.ro_data.get(start..end))
        .ok_or_else(|| table("it lies outside the read-only data"))?;
    let entry_at = |index: usize| symbol.value + index as u64 * 16 + 8;
    let relocated: HashMap<u64, u64> = elf
        .data_relocs
        .iter()
        .copied()
        .filter(|&(at, _)| (entry_at(0)..entry_at(bytes.len() / 16)).contains(&at))
        .collect();
    let mut entries = BTreeMap::new();
    for (index, entry) in bytes.chunks_exact(16).enumerate() {
        let method = u64::from_le_bytes(entry[..8].try_into().expect("eight bytes"));
        let raw = u64::from_le_bytes(entry[8..].try_into().expect("eight bytes"));
        let address = relocated.get(&entry_at(index)).copied().unwrap_or(raw);
        let method = u32::try_from(method).map_err(|_| table("a method id past 32 bits"))?;
        if !in_ranges(&elf.code_ranges, address) {
            return Err(table(&format!("method {method:#010x}'s entry is no code")));
        }
        if entries.insert(method, address).is_some() {
            return Err(table(&format!("method {method:#010x} has two entries")));
        }
    }
    Ok(entries.into_iter().collect())
}

/// What reaches what in an ELF, sorted once: its functions and data
/// objects, the relocations and branches out of each, and what a kernel's
/// own linking needs of them, so each kernel takes only its reach.
struct Graph<'a> {
    elf: &'a LinkedElf,
    /// Each function symbol's start and its size, the largest at a start.
    functions: BTreeMap<u64, u64>,
    /// The data objects, sorted and disjoint, covering each data region.
    objects: Vec<(u64, u64)>,
    /// Calls and PC-relative pairs: where in code, and what they name.
    calls: BTreeMap<u64, u64>,
    pairs: BTreeMap<u64, u64>,
    /// The second halves of PC-relative pairs: where, and what they name.
    lows: BTreeMap<u64, u64>,
    /// Relocations placing an address in data: where, and what.
    data: Vec<(u64, u64)>,
    /// Relocations naming an address by a symbol: where, and the symbol's
    /// own value.
    symbols: Vec<(u64, u64)>,
    /// Where control may enter code: translation's fusion barriers.
    targets: BTreeSet<u64>,
    /// Code pointers in data, and SUB32 relocations, by where they lie.
    pointers: Vec<(u64, u64, u8)>,
    subtracted: Vec<(u64, u64)>,
}

impl<'a> Graph<'a> {
    fn new(elf: &'a LinkedElf) -> Self {
        let mut functions = BTreeMap::new();
        let mut objects = BTreeMap::new();
        for symbol in &elf.symbols {
            if in_ranges(&elf.code_ranges, symbol.value) {
                if symbol.kind == STT_FUNC {
                    let size = functions.entry(symbol.value).or_insert(0);
                    *size = (*size).max(symbol.size);
                }
            } else if region(elf, symbol.value).is_some() {
                let size = objects.entry(symbol.value).or_insert(0);
                *size = (*size).max(symbol.size);
            }
        }
        let sorted = |pairs: &HashMap<u64, u64>| pairs.iter().map(|(&at, &to)| (at, to)).collect();
        let mut data = elf.data_relocs.clone();
        data.sort_unstable();
        let mut symbols = elf.symbol_refs.clone();
        symbols.sort_unstable();
        let mut pointers = elf.abs_code_ptrs.clone();
        pointers.sort_by_key(|&(at, _, _)| at);
        let mut subtracted = elf.sub32_relocs.clone();
        subtracted.sort_by_key(|&(at, _)| at);
        Self {
            elf,
            functions,
            objects: blocks(elf, &objects),
            calls: sorted(&elf.call_targets),
            pairs: sorted(&elf.hi20_targets),
            lows: sorted(&elf.lo12_targets),
            data,
            symbols,
            targets: elf.control_flow_targets.iter().copied().collect(),
            pointers,
            subtracted,
        }
    }

    /// The code section holding `address`.
    fn section(&self, address: u64) -> Option<(u64, u64)> {
        let ranges = &self.elf.code_ranges;
        let index = ranges.partition_point(|&(lo, _)| lo <= address);
        let (lo, hi) = *ranges.get(index.checked_sub(1)?)?;
        (address < hi).then_some((lo, hi))
    }

    /// The function holding `address`: the function symbol at or before
    /// it, or its section's start, to as far as its size reaches when it
    /// covers the address, else to the next one, or its section's end.
    fn function(&self, address: u64) -> Option<(u64, u64)> {
        let (lo, hi) = self.section(address)?;
        let (start, size) = self
            .functions
            .range(lo..=address)
            .next_back()
            .map_or((lo, 0), |(&start, &size)| (start, size));
        let end = start.saturating_add(size).min(hi);
        if address < end {
            return Some((start, end));
        }
        let next = self
            .functions
            .range(start + 1..hi)
            .next()
            .map_or(hi, |(&next, _)| next);
        Some((start, next))
    }

    /// The data object holding `address`.
    fn object(&self, address: u64) -> Option<(u64, u64)> {
        let index = self.objects.partition_point(|&(start, _)| start <= address);
        let (start, end) = *self.objects.get(index.checked_sub(1)?)?;
        (address < end).then_some((start, end))
    }

    /// The function's name as the symbol table spells it, demangled.
    fn name(&self, start: u64) -> String {
        self.elf
            .symbols
            .iter()
            .filter(|symbol| symbol.value == start && symbol.kind == STT_FUNC)
            .map(|symbol| name_at(&self.elf.names, symbol.name))
            .find(|name| !name.is_empty())
            .map_or_else(
                || format!("{start:#x}"),
                |name| format!("{:#}", rustc_demangle::demangle(name)),
            )
    }

    /// The relocations' named addresses where they lie in `[start, end)`.
    fn named_in(relocations: &[(u64, u64)], start: u64, end: u64) -> impl Iterator<Item = u64> {
        let from = relocations.partition_point(|&(at, _)| at < start);
        relocations[from..]
            .iter()
            .take_while(move |&&(at, _)| at < end)
            .map(|&(_, to)| to)
    }

    /// What a function's code names: the calls and PC-relative pairs in
    /// it, and their symbols, its direct branches and jumps out of it, and
    /// the call and address pairs no relocation names, which the scan
    /// finds.
    fn named_by_code(&self, (start, end): (u64, u64)) -> Vec<u64> {
        let mut named: Vec<u64> = self
            .calls
            .range(start..end)
            .chain(self.pairs.range(start..end))
            .map(|(_, &to)| to)
            .chain(Self::named_in(&self.symbols, start, end))
            .collect();
        let Some(code) = self.code(start, end) else {
            return named;
        };
        let words: Vec<u32> = code
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().expect("four bytes")))
            .collect();
        for (index, &word) in words.iter().enumerate() {
            let address = start + index as u64 * 4;
            let offset = match word & 0x7f {
                0x6f => Some(i64::from(decode_j_imm(word))),
                0x63 => Some(i64::from(decode_b_imm(word))),
                _ => None,
            };
            if let Some(offset) = offset {
                named.push(address.wrapping_add_signed(offset));
            }
            // AUIPC then JALR or ADDI on its register: a call or an address
            // the scan finds.
            if word & 0x7f == 0x17
                && let Some(&next) = words.get(index + 1)
                && (next >> 15) & 0x1f == (word >> 7) & 0x1f
                && matches!(next & 0x707f, 0x67 | 0x13)
            {
                let upper = i64::from((word & 0xffff_f000) as i32);
                let lower = i64::from((next as i32) >> 20);
                named.push(address.wrapping_add_signed(upper + lower));
            }
        }
        named
    }

    /// What a data object names: its relocations' targets and symbols, and
    /// its aligned words no relocation covers that look like code
    /// addresses.
    fn named_by_data(&self, (start, end): (u64, u64)) -> Vec<u64> {
        let mut named: Vec<u64> = Self::named_in(&self.data, start, end)
            .chain(Self::named_in(&self.symbols, start, end))
            .collect();
        let Some((base, bytes)) = self.bytes(start) else {
            return named;
        };
        let end = end.min(base + bytes.len() as u64);
        let mut at = (start - base).div_ceil(8) * 8;
        while base + at + 8 <= end {
            let address = base + at;
            let word = usize::try_from(at)
                .ok()
                .and_then(|at| bytes.get(at..at + 8))
                .map(|word| u64::from_le_bytes(word.try_into().expect("eight bytes")));
            let covered = overlaps_data_relocation(&self.elf.data_relocation_ranges, address, 8);
            if let Some(word) = word
                && !covered
                && in_ranges(&self.elf.code_ranges, word)
            {
                named.push(word);
            }
            at += 8;
        }
        named
    }

    /// The code bytes from `start` to `end`, when one section holds them.
    fn code(&self, start: u64, end: u64) -> Option<&'a [u8]> {
        let (_, base, bytes) = self
            .elf
            .code_sections
            .iter()
            .find(|(_, base, bytes)| (*base..*base + bytes.len() as u64).contains(&start))?;
        bytes.get(usize::try_from(start - base).ok()?..usize::try_from(end - base).ok()?)
    }

    /// The initialized data region holding `address`: its base and bytes.
    fn bytes(&self, address: u64) -> Option<(u64, &'a [u8])> {
        let elf = self.elf;
        [(elf.ro_base, &elf.ro_data), (elf.rw_base, &elf.rw_data)]
            .into_iter()
            .find(|(base, bytes)| (*base..*base + bytes.len() as u64).contains(&address))
            .map(|(base, bytes)| (base, bytes.as_slice()))
    }
}

/// The data regions: the read-only data, and the read-write data with its
/// zeros.
fn regions(elf: &LinkedElf) -> [(u64, u64); 2] {
    [
        (elf.ro_base, elf.ro_base + elf.ro_data.len() as u64),
        (elf.rw_base, elf.rw_base + elf.rw_len),
    ]
}

/// The data region holding `address`.
fn region(elf: &LinkedElf, address: u64) -> Option<(u64, u64)> {
    regions(elf)
        .into_iter()
        .find(|&(lo, hi)| (lo..hi).contains(&address))
}

/// Each data region cut into objects at its symbols, `objects` by start
/// with their sizes: an object runs from its symbol to the next, or as far
/// as its size reaches, and a symbol inside a sized object is part of it.
/// So an object is kept whole, and an unnamed object with the one before.
fn blocks(elf: &LinkedElf, objects: &BTreeMap<u64, u64>) -> Vec<(u64, u64)> {
    let mut blocks = Vec::new();
    for (lo, hi) in regions(elf) {
        if lo >= hi {
            continue;
        }
        let (mut start, mut reach) = (lo, lo);
        for (&symbol, &size) in objects.range(lo..hi) {
            if symbol < reach {
                reach = reach.max(symbol.saturating_add(size).min(hi));
                continue;
            }
            if symbol > start {
                blocks.push((start, symbol));
            }
            start = symbol;
            reach = symbol.saturating_add(size).min(hi);
        }
        blocks.push((start, hi));
    }
    blocks.sort_unstable();
    blocks
}

/// What a kernel's entry reaches: each function by its range, with the
/// function it was reached from, and each data object by its range.
struct Reached {
    functions: BTreeMap<(u64, u64), Option<(u64, u64)>>,
    objects: BTreeSet<(u64, u64)>,
}

impl Reached {
    fn from(graph: &Graph, entry: u64) -> Self {
        let mut reached = Reached {
            functions: BTreeMap::new(),
            objects: BTreeSet::new(),
        };
        enum Node {
            Code((u64, u64)),
            Data((u64, u64)),
        }
        let mut queue = VecDeque::new();
        if let Some(function) = graph.function(entry) {
            reached.functions.insert(function, None);
            queue.push_back(Node::Code(function));
        }
        while let Some(node) = queue.pop_front() {
            let (from, named) = match node {
                Node::Code(function) => (Some(function), graph.named_by_code(function)),
                Node::Data(object) => (None, graph.named_by_data(object)),
            };
            for target in named {
                if let Some(function) = graph.function(target) {
                    if let Entry::Vacant(entry) = reached.functions.entry(function) {
                        entry.insert(from);
                        queue.push_back(Node::Code(function));
                    }
                } else if let Some(object) = graph.object(target)
                    && reached.objects.insert(object)
                {
                    queue.push_back(Node::Data(object));
                }
            }
        }
        reached
    }

    /// The functions from the entry to the one holding `address`, by name.
    fn chain(&self, graph: &Graph, address: u64) -> Vec<String> {
        let mut chain = Vec::new();
        let mut at = self
            .functions
            .keys()
            .find(|&&(start, end)| (start..end).contains(&address))
            .copied();
        while let Some(function) = at {
            chain.push(graph.name(function.0));
            at = self.functions.get(&function).copied().flatten();
        }
        chain.reverse();
        chain
    }
}

/// The items of `sorted`, ordered by where they lie, that lie in one of
/// `ranges`, sorted and disjoint: each found by a search, so the work grows
/// with what they hold.
fn within<T: Copy>(sorted: &[T], at: impl Fn(&T) -> u64, ranges: &[(u64, u64)]) -> Vec<T> {
    let mut kept = Vec::new();
    for &(start, end) in ranges {
        let from = sorted.partition_point(|item| at(item) < start);
        kept.extend(sorted[from..].iter().take_while(|item| at(item) < end));
    }
    kept
}

/// The ranges of `sorted`, sorted and disjoint, that overlap one of
/// `ranges`, sorted and disjoint.
fn overlapping(sorted: &[(u64, u64)], ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut kept: Vec<(u64, u64)> = Vec::new();
    for &(start, end) in ranges {
        let from = sorted.partition_point(|&(_, until)| until <= start);
        for &range in sorted[from..].iter().take_while(|&&(from, _)| from < end) {
            if kept.last() != Some(&range) {
                kept.push(range);
            }
        }
    }
    kept
}

/// The kernel of attestable `method`, whose entry is at `entry`: its code
/// and data what the entry reaches, linked with an instruction-0 prologue
/// that calls it.
fn kernel(graph: &Graph, method: u32, entry: u64) -> Result<Vec<u8>, DeriveError> {
    let elf = graph.elf;
    let reached = Reached::from(graph, entry);

    // The functions reached, adjacent ones as one span, so code that falls
    // from one into the next still does; then the prologue.
    let mut spans: Vec<(u64, u64)> = Vec::new();
    for &(start, end) in reached.functions.keys() {
        match spans.last_mut() {
            Some(last) if last.1 >= start => last.1 = last.1.max(end),
            _ => spans.push((start, end)),
        }
    }
    let mut code_sections = Vec::with_capacity(spans.len() + 1);
    for &(start, end) in &spans {
        let code = graph
            .code(start, end)
            .ok_or(DeriveError::Unreadable(start, end))?;
        code_sections.push((0, start, code.to_vec()));
    }
    let prologue = elf
        .code_ranges
        .iter()
        .map(|&(_, hi)| hi)
        .max()
        .unwrap_or(0)
        .next_multiple_of(16);
    code_sections.push((0, prologue, prologue_code()));

    // The data reached, the rest zeros: the read-only data as long as its
    // last object, in as many zones as the actor's, so the read-write data
    // stays where it was linked; the read-write data's initialized part as
    // far as its last object reaches.
    let objects = merge_ranges(reached.objects.iter().copied().collect());
    let kept = |address: u64, len: u64| {
        let index = objects.partition_point(|&(start, _)| start <= address);
        index != 0 && address.saturating_add(len) <= objects[index - 1].1
    };
    let masked = |base: u64, original: &[u8], least: u64| {
        let last = objects
            .iter()
            .filter(|&&(start, _)| start >= base && start < base + original.len() as u64)
            .map(|&(_, end)| end - base)
            .max()
            .unwrap_or(0);
        let len = last.max(least).min(original.len() as u64) as usize;
        let mut bytes = vec![0; len];
        for &(start, end) in &objects {
            let from = start.saturating_sub(base).min(len as u64) as usize;
            let to = end.saturating_sub(base).min(len as u64) as usize;
            bytes[from..to].copy_from_slice(&original[from..to]);
        }
        bytes
    };
    let least = match elf.ro_data.len() as u64 {
        0 => 0,
        len => {
            let padding = elf.ro_base.saturating_sub(Z_Z);
            (zone_round(padding + len) - Z_Z + 1)
                .saturating_sub(padding)
                .max(1)
        }
    };
    let ro_data = masked(elf.ro_base, &elf.ro_data, least);
    let rw_data = masked(elf.rw_base, &elf.rw_data, 0);

    // What the kernel's linking needs of the ELF's relocations, its own.
    let pairs = |map: &BTreeMap<u64, u64>| -> HashMap<u64, u64> {
        spans
            .iter()
            .flat_map(|&(start, end)| map.range(start..end).map(|(&at, &to)| (at, to)))
            .collect()
    };
    let mut call_targets = pairs(&graph.calls);
    call_targets.insert(prologue + 4, entry);
    let control_flow_targets: HashSet<u64> = spans
        .iter()
        .flat_map(|&(start, end)| graph.targets.range(start..end).copied())
        .chain([prologue, prologue + 12])
        .collect();
    let abs_code_ptrs = within(&graph.pointers, |&(at, _, _)| at, &objects)
        .into_iter()
        .filter(|&(at, _, size)| kept(at, u64::from(size)))
        .collect();
    let sub32_relocs = within(&graph.subtracted, |&(at, _)| at, &objects)
        .into_iter()
        .filter(|&(at, _)| kept(at, 4))
        .collect();
    let data_relocation_ranges = overlapping(&elf.data_relocation_ranges, &objects);
    let kernel = LinkedElf {
        is_64bit: elf.is_64bit,
        code_sections,
        ro_data,
        ro_base: elf.ro_base,
        rw_data,
        rw_base: elf.rw_base,
        rw_min: elf.rw_min,
        rw_len: elf.rw_len,
        stack_size: elf.stack_size,
        heap_pages: elf.heap_pages,
        symbols: Vec::new(),
        names: Vec::new(),
        data_relocs: Vec::new(),
        symbol_refs: Vec::new(),
        relocations: elf.relocations,
        unknown_relocation: None,
        schema: None,
        hi20_targets: pairs(&graph.pairs),
        lo12_targets: pairs(&graph.lows),
        call_targets,
        abs_code_ptrs,
        sub32_relocs,
        data_relocation_ranges,
        code_ranges: elf.code_ranges.clone(),
        control_flow_targets,
        entry_vaddr: prologue,
        accumulate_vaddr: None,
    };

    let (transpiled, host_calls) = transpile_with(&kernel, Link::Kernel)?;
    if let Some(&(address, id)) = host_calls
        .iter()
        .find(|&&(_, id)| !vos_pvm::precompile::is_precompile(u64::from(id)))
    {
        return Err(DeriveError::HostCall {
            method,
            id: u64::from(id),
            chain: reached.chain(graph, address),
        });
    }
    Ok(spi_blob(transpiled)?)
}

/// The prologue at a kernel's instruction 0, as an attestable program's
/// `_start`: keep the halt address, call the entry, and return to it.
fn prologue_code() -> Vec<u8> {
    const RA: u32 = 1;
    const S0: u32 = 8;
    let addi = |rd: u32, rs1: u32| (rs1 << 15) | (rd << 7) | 0x13;
    let jalr = |rd: u32, rs1: u32| (rs1 << 15) | (rd << 7) | 0x67;
    [
        addi(S0, RA),
        (RA << 7) | 0x17, // auipc ra, 0: the call to the entry
        jalr(RA, RA),
        addi(RA, S0),
        jalr(0, RA),
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect()
}
