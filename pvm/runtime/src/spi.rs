//! GP standard-program initialization (SPI) — the graypaper v0.7.2 blob format.
//!
//! This is the second of vos_pvm's two program-init front-ends. The native path
//! ([`crate::program`]) parses the `JAR\x02` capability manifest; this path
//! parses the GP *standard program* a service's code preimage decodes to, as
//! used by the `gp072_*` conformance vectors. The kernel selects between them
//! by sniffing the leading magic (see [`is_jar_manifest`]).
//!
//! Blob layout (GP Appendix A), after an optional metadata prefix:
//! ```text
//!   metadata:   E(|m|) ‖ m                 (JAM natural length ‖ bytes)
//!   program:    E₃(|o|) ‖ E₃(|w|) ‖ E₂(z) ‖ E₃(s) ‖ o ‖ w ‖ E₄(|c|) ‖ c
//! ```
//! where `o` = read-only data, `w` = read-write data, `z` = additional zeroed
//! heap pages, `s` = stack size (bytes), and `c` is a deblob-format code blob
//! whose length prefixes use the JAM natural encoding (the `compact` form).
//!
//! The parser mirrors `Jar.JAVM.Interpreter.initStandard`, the Lean spec
//! function that blessed the `gp072_*` vectors. It is byte-for-byte validated
//! against a real service preimage in `tests/spi.rs`.

use alloc::vec::Vec;

use crate::cap::Access;
use crate::program::{
    CapEntryType, CapManifestEntry, ParsedCodeBlob, build_blob, encode_code_blob, unpack_bitmask,
};
use crate::{PVM_HALT_ADDR, PVM_INIT_INPUT_SIZE, PVM_PAGE_SIZE, PVM_ZONE_SIZE};

/// Cap-table slot for the standard program's CODE cap.
pub(crate) const SPI_CODE_SLOT: u8 = 64;
/// Cap-table slots for the read-only, read-write, stack, and argument regions.
/// These sit above the protocol caps (1..=28) and below UNTYPED (254).
const SPI_RO_SLOT: u8 = 65;
const SPI_RW_SLOT: u8 = 66;
const SPI_STACK_SLOT: u8 = 67;
const SPI_ARGS_SLOT: u8 = 68;

/// `Z_P` — PVM page size (2¹²).
const Z_P: u64 = PVM_PAGE_SIZE as u64;
/// `Z_Z` — PVM initialization zone size (2¹⁶).
const Z_Z: u64 = PVM_ZONE_SIZE as u64;
/// `Z_I` — PVM initialization input size (2²⁴).
const Z_I: u64 = PVM_INIT_INPUT_SIZE as u64;
/// Full 32-bit address space size (2³²).
const ADDR_SPACE: u64 = 1 << 32;

/// A parsed GP standard program: the header lengths, the read-only/read-write
/// data sections, and the deblobbed code.
#[derive(Debug, Clone)]
pub struct StandardProgram {
    /// Read-only data section `o`.
    pub ro_data: Vec<u8>,
    /// Read-write (initialized heap) data section `w`.
    pub rw_data: Vec<u8>,
    /// Additional zeroed heap pages `z` beyond `rw_data`.
    pub heap_pages: u32,
    /// Stack size `s` in bytes.
    pub stack_size: u32,
    /// The deblobbed code (jump table, code bytes, unpacked bitmask).
    pub code: ParsedCodeBlob,
}

/// One initial memory region of a standard program's flat address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpiRegion {
    /// Base byte address (page-aligned).
    pub base: u64,
    /// Region size in bytes (page-rounded).
    pub size: u64,
    /// `true` = writable, `false` = read-only.
    pub writable: bool,
}

/// The GP memory layout and initial register file for a standard program.
///
/// Mirrors the layout of `initStandard` (GP eq A.42–A.43): read-only data at
/// `Z_Z`, read-write + heap after a zone gap, stack just below the argument
/// zone, and arguments in the top input zone.
#[derive(Debug, Clone)]
pub struct StandardLayout<'a> {
    /// Read-only region, initialized from `ro_data`.
    pub ro: SpiRegion,
    /// Read-write region (rw data followed by zeroed heap pages).
    pub rw: SpiRegion,
    /// Stack region (zeroed, writable).
    pub stack: SpiRegion,
    /// Argument region (read-only), initialized from `args`.
    pub args: SpiRegion,
    /// Base address of the read-only data (== `ro.base`).
    pub ro_data: &'a [u8],
    /// Base address of the read-write data (== `rw.base`).
    pub rw_data: &'a [u8],
    /// Arguments to copy into the argument region.
    pub args_data: &'a [u8],
    /// Top of the heap (first byte past the pre-mapped rw+heap region).
    pub heap_top: u64,
    /// Initial register file `φ` (GP eq A.43): 13 registers.
    pub registers: [u64; crate::PVM_REGISTER_COUNT],
}

/// Round `x` up to a multiple of the page size `Z_P`.
fn page_round(x: u64) -> u64 {
    x.div_ceil(Z_P) * Z_P
}

/// Round `x` up to a multiple of the zone size `Z_Z`.
fn zone_round(x: u64) -> u64 {
    x.div_ceil(Z_Z) * Z_Z
}

/// Decode a JAM natural (GP C.1) at `offset`. Returns `(value, bytes_consumed)`.
///
/// The length class is the number of leading 1-bits in the header byte; the
/// value's low bytes follow little-endian, its high bits ride in the header.
/// This is the inverse of `upstream_crypto::gp072_codec::encode_nat` and agrees
/// with the spec's `decodeJamNatural` on every value the two both accept.
pub fn read_nat(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let header = *data.get(offset)?;
    let l = header.leading_ones() as usize;
    if l == 0 {
        return Some((header as u64, 1));
    }
    if l >= 8 {
        // 0xFF prefix + 8 little-endian bytes.
        let bytes = data.get(offset + 1..offset + 9)?;
        return Some((u64::from_le_bytes(bytes.try_into().ok()?), 9));
    }
    let bytes = data.get(offset + 1..offset + 1 + l)?;
    let mut low = 0u64;
    for (i, &b) in bytes.iter().enumerate() {
        low |= (b as u64) << (8 * i);
    }
    let top = (header as u64) & ((1u64 << (8 - l)) - 1);
    Some((low | (top << (8 * l)), 1 + l))
}

/// Read `n` little-endian bytes as a `u64`.
fn read_le(data: &[u8], offset: usize, n: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + n)?;
    let mut v = 0u64;
    for (i, &b) in bytes.iter().enumerate() {
        v |= (b as u64) << (8 * i);
    }
    Some(v)
}

/// `true` if `blob` begins with the `JAR\x02` capability-manifest magic.
///
/// The kernel uses this to route a blob: manifest → [`crate::program`],
/// otherwise → the GP standard-program path here.
pub fn is_jar_manifest(blob: &[u8]) -> bool {
    blob.len() >= 4 && read_le(blob, 0, 4) == Some(crate::program::JAR_MAGIC as u64)
}

/// Strip a metadata prefix, if present. GP service preimages carry
/// `E(|m|) ‖ m` before the standard program; conformance-minimal blobs may
/// omit it. We detect a bare program by checking whether the first three
/// bytes read as a `ro_size` that would fit the blob — the same heuristic as
/// the spec's `skipMetadata`.
fn strip_metadata(blob: &[u8]) -> &[u8] {
    if blob.len() < 14 {
        return blob;
    }
    // A bare standard program starts with E₃(|o|); if that plus the 11-byte
    // header + a byte fits, treat the blob as already unprefixed.
    if let Some(ro_size) = read_le(blob, 0, 3)
        && ro_size + 14 <= blob.len() as u64
    {
        return blob;
    }
    match read_nat(blob, 0) {
        Some((meta_len, consumed)) => {
            let skip = consumed + meta_len as usize;
            if skip < blob.len() {
                &blob[skip..]
            } else {
                blob
            }
        }
        None => blob,
    }
}

/// Deblob a code section whose length prefixes use the JAM natural encoding
/// (the `compact` form GP standard programs use).
///
/// Format: `E(|j|) ‖ E₁(z) ‖ E(|c|) ‖ jump_table ‖ code ‖ packed_bitmask`,
/// where `z` is the jump-table entry width in bytes (1..=4).
fn deblob_compact(data: &[u8]) -> Option<ParsedCodeBlob> {
    let (jump_len, n1) = read_nat(data, 0)?;
    let mut offset = n1;
    let entry_size = *data.get(offset)? as usize;
    offset += 1;
    if entry_size == 0 || entry_size > 4 {
        return None;
    }
    let (code_len, n3) = read_nat(data, offset)?;
    offset += n3;
    let jump_len = jump_len as usize;
    let code_len = code_len as usize;

    let jt_bytes = jump_len.checked_mul(entry_size)?;
    if offset + jt_bytes > data.len() {
        return None;
    }
    let mut jump_table = Vec::with_capacity(jump_len);
    for _ in 0..jump_len {
        jump_table.push(read_le(data, offset, entry_size)? as u32);
        offset += entry_size;
    }

    if offset + code_len > data.len() {
        return None;
    }
    let code = data[offset..offset + code_len].to_vec();
    offset += code_len;

    let bitmask_bytes = code_len.div_ceil(8);
    if offset + bitmask_bytes > data.len() {
        return None;
    }
    let bitmask = unpack_bitmask(&data[offset..offset + bitmask_bytes], code_len);

    Some(ParsedCodeBlob {
        jump_table,
        code,
        bitmask,
    })
}

/// Parse a GP standard-program blob (after stripping any metadata prefix).
///
/// Returns `None` on any structural error (truncation, oversized fields, a
/// code section that does not deblob).
pub fn parse_standard_program(blob: &[u8]) -> Option<StandardProgram> {
    let blob = strip_metadata(blob);
    if blob.len() < 15 {
        return None;
    }

    // Header: E₃(|o|) ‖ E₃(|w|) ‖ E₂(z) ‖ E₃(s).
    let ro_size = read_le(blob, 0, 3)? as usize;
    let rw_size = read_le(blob, 3, 3)? as usize;
    let heap_pages = read_le(blob, 6, 2)? as u32;
    let stack_size = read_le(blob, 8, 3)? as u32;
    let mut offset = 11;

    if offset + ro_size > blob.len() {
        return None;
    }
    let ro_data = blob[offset..offset + ro_size].to_vec();
    offset += ro_size;

    if offset + rw_size > blob.len() {
        return None;
    }
    let rw_data = blob[offset..offset + rw_size].to_vec();
    offset += rw_size;

    // E₄(|c|) ‖ c.
    let code_len = read_le(blob, offset, 4)? as usize;
    offset += 4;
    if offset + code_len > blob.len() {
        return None;
    }
    let code = deblob_compact(&blob[offset..offset + code_len])?;

    Some(StandardProgram {
        ro_data,
        rw_data,
        heap_pages,
        stack_size,
        code,
    })
}

impl StandardProgram {
    /// Compute the GP memory layout and initial register file for this program
    /// given `args`. Returns `None` if the layout does not fit the 32-bit
    /// address space (GP eq A.42's total-size guard).
    pub fn layout<'a>(&'a self, args: &'a [u8]) -> Option<StandardLayout<'a>> {
        let ro_size = self.ro_data.len() as u64;
        let rw_size = self.rw_data.len() as u64;
        let stack_size = self.stack_size as u64;
        let args_size = args.len() as u64;

        let ro_zone = zone_round(ro_size);
        let ro_base = Z_Z;

        let rw_total = rw_size + self.heap_pages as u64 * Z_P;
        let rw_zone = zone_round(rw_total);
        let rw_base = 2 * Z_Z + ro_zone;

        // Total-size guard (GP eq A.42).
        let total = 5 * Z_Z + ro_zone + rw_zone + zone_round(stack_size) + Z_I;
        if total > ADDR_SPACE {
            return None;
        }

        let stack_top = ADDR_SPACE - 2 * Z_Z - Z_I;
        let stack_bottom = stack_top - page_round(stack_size);
        let arg_base = ADDR_SPACE - Z_Z - Z_I;
        let heap_top = rw_base + page_round(rw_total);

        let mut registers = [0u64; crate::PVM_REGISTER_COUNT];
        registers[0] = PVM_HALT_ADDR; // φ[0] = RA (halt address)
        registers[1] = stack_top; // φ[1] = SP (stack top)
        registers[7] = arg_base; // φ[7] = argument base
        registers[8] = args_size; // φ[8] = argument length

        Some(StandardLayout {
            ro: SpiRegion {
                base: ro_base,
                size: page_round(ro_size),
                writable: false,
            },
            rw: SpiRegion {
                base: rw_base,
                size: page_round(rw_total),
                writable: true,
            },
            stack: SpiRegion {
                base: stack_bottom,
                size: page_round(stack_size),
                writable: true,
            },
            args: SpiRegion {
                base: arg_base,
                size: page_round(args_size),
                writable: false,
            },
            ro_data: &self.ro_data,
            rw_data: &self.rw_data,
            args_data: args,
            heap_top,
            registers,
        })
    }
}

/// Translate a parsed standard program into an equivalent `JAR\x02` manifest
/// blob, so the existing capability-model kernel init can load it unchanged.
///
/// The GP flat-memory regions become DATA caps at their standard-program
/// addresses: read-only data at `Z_Z`, read-write + heap after a zone gap,
/// the stack just below the argument zone, and the arguments in the top input
/// zone. The deblobbed code becomes a CODE cap. Empty regions are omitted.
///
/// The manifest carries the layout's stack top so the kernel installs `φ[1]`;
/// the caller is responsible for the GP argument registers `φ[7]`/`φ[8]`,
/// which the JAR args convention does not reproduce for empty arguments.
///
/// Returns `None` if the layout does not fit the address space.
pub(crate) fn to_manifest_blob(prog: &StandardProgram, args: &[u8]) -> Option<Vec<u8>> {
    let layout = prog.layout(args)?;
    let code_data = encode_code_blob(&prog.code.code, &prog.code.bitmask, &prog.code.jump_table);

    // Data section: code sub-blob, then the ro / rw / args init bytes.
    let mut data_section = Vec::new();
    data_section.extend_from_slice(&code_data);
    let ro_off = data_section.len() as u32;
    data_section.extend_from_slice(&prog.ro_data);
    let rw_off = data_section.len() as u32;
    data_section.extend_from_slice(&prog.rw_data);
    let args_off = data_section.len() as u32;
    data_section.extend_from_slice(args);

    let base_page = |addr: u64| (addr / Z_P) as u32;
    let page_count = |size: u64| (size / Z_P) as u32;

    let mut caps = alloc::vec![CapManifestEntry {
        cap_index: SPI_CODE_SLOT,
        cap_type: CapEntryType::Code,
        base_page: 0,
        page_count: 0,
        init_access: Access::RO,
        data_offset: 0,
        data_len: code_data.len() as u32,
    }];

    let mut push_region = |slot: u8, region: SpiRegion, data_off: u32, data_len: u32| {
        if region.size == 0 {
            return;
        }
        caps.push(CapManifestEntry {
            cap_index: slot,
            cap_type: CapEntryType::Data,
            base_page: base_page(region.base),
            page_count: page_count(region.size),
            init_access: if region.writable {
                Access::RW
            } else {
                Access::RO
            },
            data_offset: data_off,
            data_len,
        });
    };

    push_region(SPI_RO_SLOT, layout.ro, ro_off, prog.ro_data.len() as u32);
    push_region(SPI_RW_SLOT, layout.rw, rw_off, prog.rw_data.len() as u32);
    push_region(SPI_STACK_SLOT, layout.stack, 0, 0);
    push_region(SPI_ARGS_SLOT, layout.args, args_off, args.len() as u32);

    let memory_pages: u32 = caps
        .iter()
        .filter(|c| c.cap_type == CapEntryType::Data)
        .map(|c| c.page_count)
        .sum();

    Some(build_blob(
        memory_pages,
        SPI_CODE_SLOT,
        layout.registers[1] as u32,
        &caps,
        &data_section,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Build a minimal but complete standard-program blob for a round-trip.
    fn build_blob(
        ro: &[u8],
        rw: &[u8],
        heap_pages: u16,
        stack_size: u32,
        code: &[u8],
        bitmask: &[u8],
    ) -> Vec<u8> {
        // Code sub-blob: E(|j|=0) ‖ z=1 ‖ E(|c|) ‖ code ‖ packed_bitmask.
        let mut cb = Vec::new();
        cb.push(0); // jump_len = 0 (1-byte nat)
        cb.push(1); // entry_size z
        // code_len as a nat: keep it small enough for the 1-byte form.
        assert!(code.len() < 128);
        cb.push(code.len() as u8);
        cb.extend_from_slice(code);
        let mut packed = vec![0u8; code.len().div_ceil(8)];
        for (i, &b) in bitmask.iter().enumerate() {
            if b != 0 {
                packed[i / 8] |= 1 << (i % 8);
            }
        }
        cb.extend_from_slice(&packed);

        let mut blob = Vec::new();
        blob.extend_from_slice(&(ro.len() as u32).to_le_bytes()[..3]);
        blob.extend_from_slice(&(rw.len() as u32).to_le_bytes()[..3]);
        blob.extend_from_slice(&heap_pages.to_le_bytes());
        blob.extend_from_slice(&stack_size.to_le_bytes()[..3]);
        blob.extend_from_slice(ro);
        blob.extend_from_slice(rw);
        blob.extend_from_slice(&(cb.len() as u32).to_le_bytes());
        blob.extend_from_slice(&cb);
        blob
    }

    #[test]
    fn read_nat_matches_reference_values() {
        // 1-byte, 2-byte, 3-byte forms.
        assert_eq!(read_nat(&[0x47], 0), Some((71, 1)));
        assert_eq!(read_nat(&[0x80, 0xB6], 0), Some((182, 2)));
        // 24792 = 0x60D8 -> 3-byte nat: header 0b110_00000 | high, then LE bytes.
        let (v, n) = read_nat(&[0xc0, 0xd8, 0x60], 0).unwrap();
        assert_eq!((v, n), (24792, 3));
    }

    #[test]
    fn parse_roundtrip_recovers_sections() {
        let ro = [0xAAu8; 40];
        let rw = [0xBBu8; 12];
        let code = [0u8, 1, 2]; // trap, fallthrough, unlikely
        let bitmask = [1u8, 1, 1];
        let blob = build_blob(&ro, &rw, 3, 4096, &code, &bitmask);

        let prog = parse_standard_program(&blob).expect("parse");
        assert_eq!(prog.ro_data, ro);
        assert_eq!(prog.rw_data, rw);
        assert_eq!(prog.heap_pages, 3);
        assert_eq!(prog.stack_size, 4096);
        assert_eq!(prog.code.code, code);
        assert_eq!(prog.code.bitmask, bitmask);
        assert!(prog.code.jump_table.is_empty());
    }

    #[test]
    fn layout_places_regions_per_gp() {
        let ro = [0xAAu8; 40];
        let rw = [0xBBu8; 12];
        let blob = build_blob(&ro, &rw, 3, 4096, &[0u8, 1, 2], &[1u8, 1, 1]);
        let prog = parse_standard_program(&blob).unwrap();
        let args = [0x11u8; 8];
        let l = prog.layout(&args).unwrap();

        // Read-only data sits at Z_Z; rw follows a zone gap after ro's zone.
        assert_eq!(l.ro.base, Z_Z);
        assert!(!l.ro.writable);
        assert_eq!(l.rw.base, 2 * Z_Z + zone_round(ro.len() as u64));
        assert!(l.rw.writable);
        // Stack and args live in the top input zone.
        let stack_top = ADDR_SPACE - 2 * Z_Z - Z_I;
        assert_eq!(l.stack.base, stack_top - page_round(4096));
        assert_eq!(l.args.base, ADDR_SPACE - Z_Z - Z_I);
        assert!(!l.args.writable);
        // Registers per GP eq A.43.
        assert_eq!(l.registers[0], PVM_HALT_ADDR);
        assert_eq!(l.registers[1], stack_top);
        assert_eq!(l.registers[7], l.args.base);
        assert_eq!(l.registers[8], args.len() as u64);
    }

    #[test]
    fn jar_manifest_is_detected() {
        let manifest = crate::program::build_simple_blob(&[0, 1, 0], &[1, 1, 1], &[]);
        assert!(is_jar_manifest(&manifest));
        // A standard program does not carry the JAR magic.
        let sp = build_blob(&[], &[], 0, 0, &[0u8, 1], &[1u8, 1]);
        assert!(!is_jar_manifest(&sp));
    }
}
