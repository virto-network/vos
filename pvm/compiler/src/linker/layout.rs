//! Where an ELF's data lies once linked, and the standard program it is
//! laid out as.

use vos_pvm_program::{CodeBlob, StandardProgram};

use crate::TranspileError;

use super::TranspiledElf;
use super::elf::limits;

/// Zeroed heap pages a linked program has past its data: 64 KiB.
pub(super) const HEAP_PAGES: u32 = 16;

/// `Z_Z` — the GP initialization zone size (2¹⁶).
pub(crate) const Z_Z: u64 = vos_pvm::PVM_ZONE_SIZE as u64;

/// Round `x` up to a multiple of the zone size `Z_Z`.
pub(crate) fn zone_round(x: u64) -> u64 {
    x.div_ceil(Z_Z) * Z_Z
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

    // |o|, |w| and s are E₃-encoded, z E₂-encoded: a field past its width
    // builds no program.
    let blob = vos_pvm_program::build_standard_program(&StandardProgram {
        ro_data,
        rw_data,
        heap_pages,
        stack_size: t.ro_base as u32,
        code: CodeBlob {
            jump_table: t.jump_table,
            code: t.code,
            bitmask: t.bitmask,
        },
    })
    .ok_or_else(|| TranspileError::InvalidSection("SPI: a field exceeds its wire width".into()))?;

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

/// Where an ELF's data lies once linked: the read-only blob and the
/// read-write one, each by the address its first byte is linked at.
pub(super) struct Layout {
    pub(super) ro_data: Vec<u8>,
    pub(super) ro_base: u64,
    pub(super) rw_data: Vec<u8>,
    pub(super) rw_base: u64,
    pub(super) rw_min: u64,
    pub(super) rw_len: u64,
}

/// Lay the read-only and read-write sections out as their blobs.
pub(super) fn layout(
    ro_sections: &[(u64, usize, Vec<u8>)],
    rw_sections: &[(u64, usize, Option<Vec<u8>>)],
) -> Result<Layout, TranspileError> {
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
    let page_size = u64::from(vos_pvm::PVM_PAGE_SIZE);
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
    for (addr, sz, d) in ro_sections {
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
        for (addr, sz, d) in rw_sections {
            let off = (*addr - rw_base) as usize;
            if let Some(d) = d
                && off + sz <= rw_data.len()
            {
                rw_data[off..off + sz].copy_from_slice(d);
            }
        }
    }

    Ok(Layout {
        ro_data,
        ro_base: stack_size,
        rw_data,
        rw_base,
        rw_min,
        rw_len,
    })
}
