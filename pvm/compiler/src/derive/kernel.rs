//! A kernel linked from what its entry reaches.

use super::graph::{Reached, overlapping, within};
use super::prologue::Prologue;
use super::*;

/// The kernel of an attestable method's `entry`: its code and data what the
/// entry reaches, linked with an instruction-0 prologue that reads its input
/// and calls it.
pub(super) fn kernel(graph: &Graph, entry: &AttestEntry) -> Result<Vec<u8>, DeriveError> {
    let &AttestEntry {
        method,
        entry,
        input,
        device,
        ..
    } = entry;
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
    let arguments = argument_pages(elf, input)?;
    let head = Prologue::new(arguments, input);
    code_sections.push((0, prologue, head.code.clone()));

    let objects = merge_ranges(reached.objects.iter().copied().collect());
    let kept = |address: u64, len: u64| {
        range_at(&objects, address).is_some_and(|(_, end)| address.saturating_add(len) <= end)
    };
    let (ro_data, rw_data) = reached_data(elf, &objects);

    // What the kernel's linking needs of the ELF's relocations, its own.
    let pairs = |map: &BTreeMap<u64, u64>| -> BTreeMap<u64, u64> {
        spans
            .iter()
            .flat_map(|&(start, end)| map.range(start..end).map(|(&at, &to)| (at, to)))
            .collect()
    };
    let mut call_targets = pairs(&elf.call_targets);
    call_targets.insert(prologue + head.call_at, entry);
    // The ELF's targets in the spans, the prologue's own, and where the
    // kernel's branches and jumps land, the prologue included, which the
    // ELF's targets cannot name: it lies past the ELF's code.
    let control_flow_targets: HashSet<u64> = spans
        .iter()
        .flat_map(|&(start, end)| graph.targets.range(start..end).copied())
        .chain([prologue, prologue + head.return_at])
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
        heap_pages: elf.heap_pages + input.pages() as u32,
        ..LinkedElf::default()
    };

    let transpiled = transpile_with(&kernel, Link::Kernel)?;
    checked_blob(
        graph, &reached, method, device, transpiled, arguments, input,
    )
}

/// The data a kernel keeps of `elf`, `objects` the ranges it reaches, the
/// rest zeros: the read-only data as long as its last object, in as many
/// zones as the actor's, so the read-write data stays where it was
/// linked; the read-write data's initialized part as far as its last
/// object reaches.
fn reached_data(elf: &LinkedElf, objects: &[(u64, u64)]) -> (Vec<u8>, Vec<u8>) {
    let masked = |base: u64, original: &[u8], least: u64| {
        let last = objects
            .iter()
            .filter(|&&(start, _)| start >= base && start < base + original.len() as u64)
            .map(|&(_, end)| end - base)
            .max()
            .unwrap_or(0);
        let len = last.max(least).min(original.len() as u64) as usize;
        let mut bytes = vec![0; len];
        for &(start, end) in objects {
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
    (
        masked(elf.ro_base, &elf.ro_data, least),
        masked(elf.rw_base, &elf.rw_data, 0),
    )
}

/// The kernel of `method` as its blob, `transpiled` from its linked ELF:
/// refused if it makes a host call no kernel of its kind (a `device`
/// kernel's or a node's) may, jumps to the halt statically, or its argument
/// pages are not its read-write data's last.
fn checked_blob(
    graph: &Graph,
    reached: &Reached,
    method: u32,
    device: bool,
    transpiled: crate::linker::TranspiledElf,
    arguments: u64,
    input: Input,
) -> Result<Vec<u8>, DeriveError> {
    let admitted = if device {
        vos_pvm::precompile::is_device_kernel_call
    } else {
        vos_pvm::precompile::is_kernel_call
    };
    if let Some(&(address, id)) = transpiled
        .host_calls
        .iter()
        .find(|&&(_, id)| !admitted(u64::from(id)))
    {
        let chain = reached.chain(graph, address);
        return Err(
            if device && u64::from(id) == vos_pvm::precompile::BLAKE2B_COMPRESS {
                DeriveError::DeviceBlake2b { method, chain }
            } else {
                DeriveError::HostCall {
                    method,
                    id: u64::from(id),
                    chain,
                }
            },
        );
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
    let pages = u64::from(graph.elf.heap_pages) + input.pages();
    if rw.base + rw.size != arguments + pages * PAGE {
        return Err(TranspileError::InvalidSection(format!(
            "a kernel's argument pages at {arguments:#x} are not its read-write data's last"
        ))
        .into());
    }
    Ok(blob)
}

/// Where a kernel derived from `elf` reads its `input`: the page past its
/// read-write data, where the standard layout places it, as
/// [`crate::linker::spi_blob`] lays the data out. Below 2^31, so the
/// prologue loads it with `lui` and `addi`.
fn argument_pages(elf: &LinkedElf, input: Input) -> Result<u64, DeriveError> {
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
    if arguments + input.pages() * PAGE > 1 << 31 {
        return Err(TranspileError::InvalidSection(format!(
            "a kernel's argument pages at {arguments:#x} lie past 2^31"
        ))
        .into());
    }
    Ok(arguments)
}
