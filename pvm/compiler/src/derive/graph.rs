//! What reaches what in an ELF, and what an entry reaches.

use super::*;

/// What reaches what in an ELF, sorted once: its functions and data
/// objects, the relocations and branches out of each, and what a kernel's
/// own linking needs of them, so each kernel takes only its reach.
pub(super) struct Graph<'a> {
    pub(super) elf: &'a LinkedElf,
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
    pub(super) targets: BTreeSet<u64>,
    /// Code pointers in data, and SUB32 relocations, by where they lie.
    pub(super) pointers: Vec<(u64, u64, u8)>,
    pub(super) subtracted: Vec<(u64, u64)>,
}

impl<'a> Graph<'a> {
    pub(super) fn new(elf: &'a LinkedElf) -> Self {
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
    pub(super) fn section(&self, address: u64) -> Option<(u64, u64)> {
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
    pub(super) fn object(&self, address: u64) -> Option<(u64, u64)> {
        range_at(&self.objects, address)
    }

    /// The function's name as the symbol table spells it, demangled.
    pub(super) fn name(&self, start: u64) -> String {
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
    pub(super) fn code(&self, start: u64, end: u64) -> Option<&'a [u8]> {
        let (_, base, bytes) = self
            .elf
            .code_sections
            .iter()
            .find(|(_, base, bytes)| (*base..*base + bytes.len() as u64).contains(&start))?;
        bytes.get(usize::try_from(start - base).ok()?..usize::try_from(end - base).ok()?)
    }

    /// The initialized data region holding `address`: its base and bytes.
    pub(super) fn bytes(&self, address: u64) -> Option<(u64, &'a [u8])> {
        self.elf
            .initialized()
            .into_iter()
            .find(|(base, bytes)| (*base..*base + bytes.len() as u64).contains(&address))
    }
}

/// The data regions: the read-only data, and the read-write data with its
/// zeros.
pub(super) fn regions(elf: &LinkedElf) -> [(u64, u64); 2] {
    [
        (elf.ro_base, elf.ro_base + elf.ro_data.len() as u64),
        (elf.rw_base, elf.rw_base + elf.rw_len),
    ]
}

/// The data region holding `address`.
pub(super) fn region(elf: &LinkedElf, address: u64) -> Option<(u64, u64)> {
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
pub(super) struct Reached {
    pub(super) functions: BTreeMap<(u64, u64), Option<(u64, u64)>>,
    pub(super) objects: BTreeSet<(u64, u64)>,
}

impl Reached {
    /// Walk what `entry` reaches in `graph`.
    pub(super) fn walk(graph: &Graph, entry: u64) -> Self {
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
    pub(super) fn chain(&self, graph: &Graph, address: u64) -> Vec<String> {
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
pub(super) fn within<T: Copy>(
    sorted: &[T],
    at: impl Fn(&T) -> u64,
    ranges: &[(u64, u64)],
) -> Vec<T> {
    let mut kept = Vec::new();
    for &(start, end) in ranges {
        let from = sorted.partition_point(|item| at(item) < start);
        kept.extend(sorted[from..].iter().take_while(|item| at(item) < end));
    }
    kept
}

/// The ranges of `sorted`, sorted and disjoint, that overlap one of
/// `ranges`, sorted and disjoint.
pub(super) fn overlapping(sorted: &[(u64, u64)], ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
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
