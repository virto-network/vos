//! The memory access's byte lookups.

use super::*;

/// The memory access, a byte at a time.
pub(super) fn memory_access(
    logup: &mut LogupTraceBuilder,
    component_trace: &ComponentTrace,
    lookup_elements: &AllLookupElements,
) {
    // Memory access lookups — byte-level (up to 8 entries per memory op)
    // `is_write` is the sum of the 3 store-class sub-flags
    // (IsStoreDirect + IsStoreImmAny + IsStoreInd).
    let mem_lookup: &MemoryAccessLookupElements = lookup_elements.as_ref();
    let is_store_direct_mem =
        crate::trace::original_base_column!(component_trace, Column::IsStoreDirect);
    let is_store_imm_any_mem =
        crate::trace::original_base_column!(component_trace, Column::IsStoreImmAny);
    let is_store_ind_mem = crate::trace::original_base_column!(component_trace, Column::IsStoreInd);
    let mem_addr = crate::trace::original_base_column!(component_trace, Column::MemAddr);
    let mem_value = crate::trace::original_base_column!(component_trace, Column::MemValue);
    let timestamp = crate::trace::original_base_column!(component_trace, Column::Timestamp);
    let mem_byte_active =
        crate::trace::original_base_column!(component_trace, Column::MemByteActive);
    let mem_byte_carry1 =
        crate::trace::original_base_column!(component_trace, Column::MemByteAddrCarry1);
    let mem_byte_carry2 =
        crate::trace::original_base_column!(component_trace, Column::MemByteAddrCarry2);
    let mem_byte_carry3 =
        crate::trace::original_base_column!(component_trace, Column::MemByteAddrCarry3);

    // For each byte offset 0..8, produce a byte-level lookup entry
    // Tuple: (addr+i [4], value_byte_i [1], timestamp[8], is_write[1])
    // Multiplicity: mem_byte_active[i] (1 if byte is within access size, 0 otherwise)
    //
    // The byte address is the CANONICAL little-endian decomposition of
    // `MemAddr + i`, carrying across address bytes via MemByteAddrCarry{1,2,3}
    // — a misaligned multi-byte access can cross a 256-byte boundary, so the
    // low byte alone (`addr[0] + i`) would overflow 255 and not match the
    // MemoryChip ledger. The carries telescope, so the numeric address is
    // always `base + i`; the ledger's canonical bytes pin them.
    for byte_idx in 0..8usize {
        let byte_offset = PackedBaseField::broadcast(BaseField::from(byte_idx as u32));
        let p256 = PackedBaseField::broadcast(BaseField::from(256));
        let mem_addr_c = mem_addr.clone();
        let mem_value_c = mem_value.clone();
        let timestamp_c = timestamp.clone();
        let c1 = mem_byte_carry1[byte_idx].clone();
        let c2 = mem_byte_carry2[byte_idx].clone();
        let c3 = mem_byte_carry3[byte_idx].clone();
        let is_sd_c = is_store_direct_mem[0].clone();
        let is_sia_c = is_store_imm_any_mem[0].clone();
        let is_si_c = is_store_ind_mem[0].clone();
        logup.add_to_relation_computed(
            mem_lookup,
            [mem_byte_active[byte_idx].clone()],
            |[active]| active.into(),
            15, // tuple: addr[4] + value[1] + timestamp[8] + is_write[1] + is_closing[1]
            |vec_idx| {
                let mut tuple = Vec::with_capacity(15);
                let cy1 = c1.at(vec_idx);
                let cy2 = c2.at(vec_idx);
                let cy3 = c3.at(vec_idx);
                // Canonical bytes of MemAddr + byte_idx, with carry.
                tuple.push(mem_addr_c[0].at(vec_idx) + byte_offset - p256 * cy1);
                tuple.push(mem_addr_c[1].at(vec_idx) + cy1 - p256 * cy2);
                tuple.push(mem_addr_c[2].at(vec_idx) + cy2 - p256 * cy3);
                tuple.push(mem_addr_c[3].at(vec_idx) + cy3);
                // value byte
                tuple.push(mem_value_c[byte_idx].at(vec_idx));
                // timestamp
                for col in &timestamp_c {
                    tuple.push(col.at(vec_idx));
                }
                // is_write = IsStoreDirect + IsStoreImmAny + IsStoreInd
                tuple.push(is_sd_c.at(vec_idx) + is_sia_c.at(vec_idx) + is_si_c.at(vec_idx));
                // is_closing = 0 (CpuChip never emits closing reads)
                tuple.push(PackedBaseField::broadcast(BaseField::from(0u32)));
                tuple
            },
        );
    }
}
