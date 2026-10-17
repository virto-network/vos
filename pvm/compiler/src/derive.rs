//! One ELF in, programs out: from the ELF an actor's crate builds, the
//! actor's program and one kernel per attestable method.
//!
//! - **The actor's program** is the ELF linked from its entry, `_start`, as
//!   [`crate::link_elf_spi`] links it. Its workflows are in it, routed by
//!   method.
//! - **A kernel** is the ELF linked from one attestable method's entry
//!   alone: the code its relocations reach from the entry (calls, PC-relative
//!   pairs, absolute data relocations, switch tables) and direct branches,
//!   and the data they reach, with an instruction-0 prologue: it reads the
//!   method's arguments through the witness input into pages of its own,
//!   calls the entry on them, and returns to the halt address with the
//!   output in φ7 and φ8 and the io-hash in φ9 to φ12. The entries are the
//!   ELF's table `VOS_ATTEST`, each an attestable method's id and its entry.
//!
//! **A kernel's memory starts the same for every run:** its arguments are
//! read, not laid out, so the loader maps none and leaves φ8 at 0, and the
//! root of its initial memory is a constant of the kernel.
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
//! **A heap per kind of invocation:** an ELF's heap arena, its `.vos_heap`
//! section, ends its read-write data. The actor's program and each kernel
//! hold its first [`INVOCATION_HEAP`] bytes, all a handler or a kernel
//! maps; the pages past them, [`Derived::heap`], a workflow's machine maps
//! past its program's. So a kernel's memory, laid out by its program
//! alone, is the same whatever heap its actor declares.
//!
//! **A kernel makes no host call but the precompiles and its witness
//! input:** one whose reachable code does is refused, naming the chain of
//! functions from the entry to the call.
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
    Link, LinkedElf, STT_FUNC, Z_Z, direct_targets, in_ranges, merge_ranges, name_at, name_is,
    parse_linked_elf, range_at, raw_code_pointers, spi_blob, transpile_with, zone_round,
};
use crate::riscv::{self, decode_b_imm, decode_j_imm, op};

/// The derivation's version: it changes whenever the bytes it derives from
/// the same ELF may, so a derived program's hash is pinned per version.
pub const TRANSPILER_VERSION: u32 = 3;

/// The bytes of its actor's heap arena a handler's or a kernel's program
/// holds, [`vos_wire::abi::INVOCATION_HEAP`], the most the SDK's allocator
/// gives one: a workflow's machine maps the rest.
pub const INVOCATION_HEAP: u64 = vos_wire::abi::INVOCATION_HEAP as u64;

/// A page of the PVM's memory.
const PAGE: u64 = vos_pvm::PVM_PAGE_SIZE as u64;

/// The most bytes a kernel's arguments hold: an attest's, at most a
/// request's.
const ARGUMENTS: u64 = vos_wire::abi::cap::REQUEST as u64;

/// The pages a kernel's prologue reads its arguments into, past its
/// read-write data: room for one byte more than [`ARGUMENTS`], so an input
/// that fills them is too long, and the prologue traps.
const ARGUMENT_PAGES: u64 = (ARGUMENTS + 1).div_ceil(PAGE);

/// The largest ELF a derivation reads: an install's body.
pub const MAX_ELF: usize = 64 << 20;

/// The most attestable methods an actor may have: a schema's methods.
const MAX_ATTESTABLES: usize = 1024;

/// A `VOS_ATTEST` entry's length: a method's id, then its entry's address,
/// eight bytes each.
const ATTEST_ENTRY: u64 = 16;

/// What an ELF derives: its actor's program, a kernel per attestable
/// method by its id in ascending order, the schema's section as the ELF's
/// `.vos_schema` holds it, the pages of its heap the programs leave out,
/// and the version that derived them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derived {
    pub actor: Vec<u8>,
    pub kernels: Vec<(u32, Vec<u8>)>,
    /// Each kernel's shape, by its position in `kernels`.
    pub shapes: Vec<vos_wire::records::Shape>,
    pub schema: Vec<u8>,
    /// The pages of the actor's heap past its program's read-write data,
    /// which a workflow's machine maps there.
    pub heap: u32,
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
    #[error(
        "the heap's arena, `.vos_heap`, at {start:#x} for {size:#x} bytes, does not end the \
         read-write data at {end:#x} from a page: build with the guest's linker script"
    )]
    Heap { start: u64, size: u64, end: u64 },
    #[error("a kernel's instruction at {0:#x} jumps statically to the halt address")]
    HaltTarget(u64),
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
    let mut linked = parse_linked_elf(elf)?;
    if linked.relocations == 0 {
        return Err(DeriveError::NoRelocations);
    }
    if let Some(kind) = linked.unknown_relocation {
        return Err(DeriveError::Relocation(kind));
    }
    if linked.code_sections.len() > 1 {
        return Err(DeriveError::CodeSections(linked.code_sections.len()));
    }
    let schema = linked.schema.take().ok_or(DeriveError::NoSchema)?;
    let heap = invocation_heap(&mut linked)?;
    let actor = spi_blob(transpile_with(&linked, Link::Whole)?)?;
    let graph = Graph::new(&linked);
    let kernels: Vec<(u32, Vec<u8>)> = attestables(&linked)?
        .into_iter()
        .map(|(method, entry)| Ok((method, kernel(&graph, method, entry)?)))
        .collect::<Result<_, DeriveError>>()?;
    let shapes = kernels
        .iter()
        .map(|(_, kernel)| {
            crate::shape::kernel_shape(kernel).expect("a kernel is a standard program")
        })
        .collect();
    Ok(Derived {
        actor,
        kernels,
        shapes,
        schema,
        heap,
        transpiler_version: TRANSPILER_VERSION,
    })
}

/// Leave the heap's arena past [`INVOCATION_HEAP`] out of the read-write
/// data the ELF's programs hold: the pages left out, which a workflow's
/// machine maps. An arena that does not end that data, from a page, is
/// refused: its programs would not hold its first bytes alone.
fn invocation_heap(elf: &mut LinkedElf) -> Result<u32, DeriveError> {
    let Some((start, size)) = elf.heap else {
        return Ok(0);
    };
    let end = elf.rw_base + elf.rw_len;
    if start.saturating_add(size) != end || !start.is_multiple_of(PAGE) {
        return Err(DeriveError::Heap { start, size, end });
    }
    if size <= INVOCATION_HEAP {
        return Ok(0);
    }
    let kept = start + INVOCATION_HEAP;
    elf.rw_len = kept - elf.rw_base;
    Ok(((end.next_multiple_of(PAGE) - kept) / PAGE) as u32)
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
    if !symbol.size.is_multiple_of(ATTEST_ENTRY) {
        return Err(table("its size is no whole number of entries"));
    }
    if symbol.size / ATTEST_ENTRY > MAX_ATTESTABLES as u64 {
        return Err(table(&format!(
            "{} entries, past {MAX_ATTESTABLES}",
            symbol.size / ATTEST_ENTRY
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
    let entry_at = |index: usize| symbol.value + index as u64 * ATTEST_ENTRY + 8;
    let count = bytes.len() / ATTEST_ENTRY as usize;
    let relocated: HashMap<u64, u64> = elf
        .data_relocs
        .iter()
        .copied()
        .filter(|&(at, _)| (entry_at(0)..entry_at(count)).contains(&at))
        .collect();
    let mut entries = BTreeMap::new();
    for (index, entry) in bytes.chunks_exact(ATTEST_ENTRY as usize).enumerate() {
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
            data,
            symbols,
            targets: elf.control_flow_targets.iter().copied().collect(),
            pointers,
            subtracted,
        }
    }

    /// The code section holding `address`.
    fn section(&self, address: u64) -> Option<(u64, u64)> {
        range_at(&self.elf.code_ranges, address)
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
        range_at(&self.objects, address)
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
        let elf = self.elf;
        let mut named: Vec<u64> = elf
            .call_targets
            .range(start..end)
            .chain(elf.hi20_targets.range(start..end))
            .map(|(_, &to)| to)
            .chain(Self::named_in(&self.symbols, start, end))
            .collect();
        let Some(code) = self.code(start, end) else {
            return named;
        };
        for (index, word) in riscv::words(code).enumerate() {
            let address = start + index as u64 * 4;
            let offset = match riscv::opcode(word) {
                op::JAL => Some(i64::from(decode_j_imm(word))),
                op::BRANCH => Some(i64::from(decode_b_imm(word))),
                _ => None,
            };
            if let Some(offset) = offset {
                named.push(address.wrapping_add_signed(offset));
            }
            // AUIPC then JALR or ADDI on its register: a call or an address
            // the scan finds.
            if riscv::opcode(word) == op::AUIPC
                && let Some(next) = riscv::word_at(code, index * 4 + 4)
                && riscv::rs1(next) == riscv::rd(word)
                && riscv::funct3(next) == 0
                && matches!(riscv::opcode(next), op::JALR | op::OP_IMM)
            {
                named.push(riscv::auipc_pair_target(address, word, next));
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
        // The object's words, eight-byte aligned from its region's base.
        let first = (start - base).div_ceil(8) * 8;
        let last = end.min(base + bytes.len() as u64) - base;
        let words = usize::try_from(first)
            .ok()
            .zip(usize::try_from(last).ok())
            .and_then(|(first, last)| bytes.get(first..last))
            .unwrap_or(&[]);
        named.extend(
            raw_code_pointers(
                [(base + first, words)],
                &self.elf.data_relocation_ranges,
                &self.elf.code_ranges,
            )
            .map(|(_, target)| target),
        );
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
        self.elf
            .initialized()
            .into_iter()
            .find(|(base, bytes)| (*base..*base + bytes.len() as u64).contains(&address))
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
    /// Walk what `entry` reaches in `graph`.
    fn walk(graph: &Graph, entry: u64) -> Self {
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
    let reached = Reached::walk(graph, entry);

    // The functions reached, adjacent ones as one span, so code that falls
    // from one into the next still does; then the prologue.
    let spans = merge_ranges(reached.functions.keys().copied().collect());
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
    let arguments = argument_pages(elf)?;
    code_sections.push((0, prologue, prologue_code(arguments)));

    // The data reached, the rest zeros: the read-only data as long as its
    // last object, in as many zones as the actor's, so the read-write data
    // stays where it was linked; the read-write data's initialized part as
    // far as its last object reaches.
    let objects = merge_ranges(reached.objects.iter().copied().collect());
    let kept = |address: u64, len: u64| {
        range_at(&objects, address).is_some_and(|(_, end)| address.saturating_add(len) <= end)
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
    let pairs = |map: &BTreeMap<u64, u64>| -> BTreeMap<u64, u64> {
        spans
            .iter()
            .flat_map(|&(start, end)| map.range(start..end).map(|(&at, &to)| (at, to)))
            .collect()
    };
    let mut call_targets = pairs(&elf.call_targets);
    call_targets.insert(prologue + CALL_AT, entry);
    // The ELF's targets in the spans, the prologue's own, and where the
    // kernel's branches and jumps land, the prologue included, which the
    // ELF's targets cannot name: it lies past the ELF's code.
    let control_flow_targets: HashSet<u64> = spans
        .iter()
        .flat_map(|&(start, end)| graph.targets.range(start..end).copied())
        .chain([prologue, prologue + RETURN_AT])
        .chain(direct_targets(&code_sections))
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
        code_sections,
        ro_data,
        ro_base: elf.ro_base,
        rw_data,
        rw_base: elf.rw_base,
        rw_min: elf.rw_min,
        rw_len: elf.rw_len,
        relocations: elf.relocations,
        hi20_targets: pairs(&elf.hi20_targets),
        lo12_sites: spans
            .iter()
            .flat_map(|&(start, end)| elf.lo12_sites.range(start..end).copied())
            .collect(),
        call_targets,
        abs_code_ptrs,
        sub32_relocs,
        data_relocation_ranges,
        code_ranges: elf.code_ranges.clone(),
        control_flow_targets,
        entry_vaddr: prologue,
        // The argument pages, zeros past the read-write data, then the
        // linked program's own zero pages.
        heap_pages: elf.heap_pages + ARGUMENT_PAGES as u32,
        ..LinkedElf::default()
    };

    let transpiled = transpile_with(&kernel, Link::Kernel)?;
    if let Some(&(address, id)) = transpiled
        .host_calls
        .iter()
        .find(|&&(_, id)| !vos_pvm::precompile::is_kernel_call(u64::from(id)))
    {
        return Err(DeriveError::HostCall {
            method,
            id: u64::from(id),
            chain: reached.chain(graph, address),
        });
    }
    if let Some(pc) = transpiled.static_halt_target() {
        return Err(DeriveError::HaltTarget(pc));
    }
    let blob = spi_blob(transpiled)?;
    // The argument pages are where the prologue reads into: the first of
    // the read-write region's trailing zero pages.
    let [_, rw, _] = vos_pvm_program::StandardHeader::read(&blob)
        .and_then(|header| header.regions())
        .ok_or_else(|| TranspileError::InvalidSection("a kernel's layout".into()))?;
    let pages = u64::from(elf.heap_pages) + ARGUMENT_PAGES;
    if rw.base + rw.size != arguments + pages * PAGE {
        return Err(TranspileError::InvalidSection(format!(
            "a kernel's argument pages at {arguments:#x} are not its read-write data's last"
        ))
        .into());
    }
    Ok(blob)
}

/// Where a kernel derived from `elf` reads its arguments: the page past its
/// read-write data, where the standard layout places it, as
/// [`crate::linker::spi_blob`] lays the data out. Below 2^31, so the
/// prologue loads it with `lui` and `addi`.
fn argument_pages(elf: &LinkedElf) -> Result<u64, DeriveError> {
    let ro_len = match elf.ro_data.len() as u64 {
        0 => 0,
        len => elf.ro_base.saturating_sub(Z_Z) + len,
    };
    let rw_base = 2 * Z_Z + zone_round(ro_len);
    let rw_end = match elf.rw_len {
        0 => rw_base,
        len => elf.rw_base + len,
    };
    let arguments = rw_end.next_multiple_of(PAGE);
    if arguments + ARGUMENT_PAGES * PAGE > 1 << 31 {
        return Err(TranspileError::InvalidSection(format!(
            "a kernel's argument pages at {arguments:#x} lie past 2^31"
        ))
        .into());
    }
    Ok(arguments)
}

/// Where [`prologue_code`]'s call to the entry lies, and where the entry
/// returns to.
const CALL_AT: u64 = 76;
const RETURN_AT: u64 = 84;

/// The prologue at a kernel's instruction 0, as an attestable program's
/// `_start`. It keeps the halt address; reads the input through the
/// witness input into the argument pages at `arguments` until a call
/// returns 0, and traps if it filled them; calls the entry on the bytes
/// read, with 32 bytes of its stack for the io-hash; then returns to the
/// halt address with the entry's output in φ7 and φ8 and the io-hash in φ9
/// to φ12, eight little-endian bytes a register.
fn prologue_code(arguments: u64) -> Vec<u8> {
    const RA: u32 = 1;
    const SP: u32 = 2;
    const T0: u32 = 5;
    const T1: u32 = 6;
    const T2: u32 = 7;
    const S0: u32 = 8;
    const S1: u32 = 9;
    const A0: u32 = 10;
    const A1: u32 = 11;
    const A2: u32 = 12;
    let i_type = |opcode: u32, funct3: u32, rd: u32, rs1: u32, imm: i32| {
        ((imm as u32) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    };
    let addi = |rd, rs1, imm| i_type(op::OP_IMM, 0, rd, rs1, imm);
    let ld = |rd, rs1, imm| i_type(op::LOAD, 3, rd, rs1, imm);
    let jalr = |rd, rs1| i_type(op::JALR, 0, rd, rs1, 0);
    let r_type = |funct7: u32, rd: u32, rs1: u32, rs2: u32| {
        (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (rd << 7) | op::OP
    };
    let add = |rd, rs1, rs2| r_type(0, rd, rs1, rs2);
    let sub = |rd, rs1, rs2| r_type(0x20, rd, rs1, rs2);
    let branch = |funct3: u32, rs1: u32, rs2: u32, offset: i32| {
        let imm = offset as u32;
        ((imm >> 12 & 1) << 31)
            | ((imm >> 5 & 0x3f) << 25)
            | (rs2 << 20)
            | (rs1 << 15)
            | (funct3 << 12)
            | ((imm >> 1 & 0xf) << 8)
            | ((imm >> 11 & 1) << 7)
            | op::BRANCH
    };
    let jal = |rd: u32, offset: i32| {
        let imm = offset as u32;
        ((imm >> 20 & 1) << 31)
            | ((imm >> 1 & 0x3ff) << 21)
            | ((imm >> 11 & 1) << 20)
            | ((imm >> 12 & 0xff) << 12)
            | (rd << 7)
            | op::JAL
    };
    // `lui` and `addi`: a value below 2^31, its low twelve bits signed.
    let load = |rd: u32, value: u64| {
        let upper = ((value + 0x800) >> 12) as u32;
        let lower = (value as i32) - ((upper << 12) as i32);
        [(upper << 12) | (rd << 7) | op::LUI, addi(rd, rd, lower)]
    };
    const MARK: u32 = 0x801 << 20 | 1 << 12 | op::SYSTEM;
    const ECALL: u32 = op::SYSTEM;
    const UNIMP: u32 = 0xc000_1073;
    let [buffer_hi, buffer_lo] = load(S1, arguments);
    let [room_hi, room_lo] = load(T2, ARGUMENTS + 1);
    let code = [
        addi(S0, RA, 0), // 0: the halt address
        buffer_hi,       // 4: the argument pages
        buffer_lo,
        addi(T1, 0, 0), // 12: the bytes read
        room_hi,        // 16: their room
        room_lo,
        add(A0, S1, T1), // 24: the next read's destination
        sub(A1, T2, T1), // its capacity
        addi(T0, 0, vos_pvm::precompile::WITNESS_INPUT as i32),
        MARK,
        ECALL,                 // 40: the witness input
        branch(0, A0, 0, 12),  // 44: 0, the end of input: to 56
        add(T1, T1, A0),       // 48
        jal(0, -28),           // 52: to 24
        branch(7, T1, T2, 56), // 56: room filled, too long: to 112
        addi(A0, S1, 0),       // 60: the arguments
        addi(A1, T1, 0),       // their length
        addi(SP, SP, -32),     // 68: the io-hash's place
        addi(A2, SP, 0),
        (RA << 7) | op::AUIPC, // 76, CALL_AT: auipc ra, 0, the call to the entry
        jalr(RA, RA),
        ld(A2, SP, 0), // 84, RETURN_AT: the io-hash, φ9 to φ12
        ld(A2 + 1, SP, 8),
        ld(A2 + 2, SP, 16),
        ld(A2 + 3, SP, 24),
        addi(SP, SP, 32), // 100
        addi(RA, S0, 0),
        jalr(0, RA), // 108: to the halt address
        UNIMP,       // 112
    ];
    code.into_iter().flat_map(u32::to_le_bytes).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An entry that marks its next `ecall` and makes host call `id`, then
    /// returns.
    fn calling(id: i32) -> Vec<u8> {
        const CSRRW_MARK: u32 = 0x801 << 20 | 1 << 12 | 0x73;
        let li_t0 = ((id as u32) << 20) | 5 << 7 | op::OP_IMM;
        const ECALL: u32 = 0x73;
        const RET: u32 = 1 << 15 | op::JALR;
        [CSRRW_MARK, li_t0, ECALL, RET]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect()
    }

    /// Ids 110 to 114 are no precompile: a kernel that reaches one is
    /// refused, naming it, as one reaching any host call but a precompile
    /// is; one reaching BLAKE2b's, or its witness input, derives.
    #[test]
    fn a_kernel_reaching_an_unknown_id_is_refused() {
        const ENTRY: u64 = 0x10_0000;
        let derived = |id| {
            let elf = LinkedElf::text(ENTRY, calling(id));
            kernel(&Graph::new(&elf), 7, ENTRY)
        };
        for id in 110..=114 {
            match derived(id) {
                Err(DeriveError::HostCall {
                    method, id: called, ..
                }) => {
                    assert_eq!((method, called), (7, id as u64));
                }
                other => panic!("host call {id}: {:?}", other.map(|kernel| kernel.len())),
            }
        }
        for admitted in [
            vos_pvm::precompile::BLAKE2B_COMPRESS,
            vos_pvm::precompile::WITNESS_INPUT,
        ] {
            assert!(derived(admitted as i32).is_ok(), "{admitted:#x}");
        }
        assert!(matches!(
            derived(0x402),
            Err(DeriveError::HostCall { id: 0x402, .. })
        ));
    }
}
