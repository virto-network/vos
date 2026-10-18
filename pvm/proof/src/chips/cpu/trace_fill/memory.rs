//! Loads and stores.

use super::*;

/// The memory instructions' flags.
pub(super) fn memory_flags(out: &mut Sinks, s: Step) {
    let Sinks { trace, .. } = out;
    let Step { row, step, flags } = s;
    // ── Memory access columns ──
    trace.fill_columns(row, flags.is_exit, Column::IsExit);
    trace.fill_columns(row, flags.is_load, Column::IsLoad);
    // IsStore is folded — sum of the 3 store sub-flags.
    // Signed-load flags + sign-bit pinning.
    trace.fill_columns(row, flags.is_load_i8, Column::IsLoadI8);
    trace.fill_columns(row, flags.is_load_i16, Column::IsLoadI16);
    trace.fill_columns(row, flags.is_load_i32, Column::IsLoadI32);
    // Per-size flags (cover both load and store variants).
    trace.fill_columns(row, flags.is_mem_size_1, Column::IsMemSize1);
    trace.fill_columns(row, flags.is_mem_size_2, Column::IsMemSize2);
    trace.fill_columns(row, flags.is_mem_size_4, Column::IsMemSize4);
    trace.fill_columns(row, flags.is_mem_size_8, Column::IsMemSize8);
    // Direct-store flag (StoreU8/16/32/64 only).
    trace.fill_columns(row, flags.is_store_direct, Column::IsStoreDirect);
    // Direct-load flag (LoadU8/I8/U16/I16/U32/I32/U64).
    trace.fill_columns(row, flags.is_load_direct, Column::IsLoadDirect);
    // Indirect-mem flag + MemAddr add-with-carry chain.
    trace.fill_columns(row, flags.is_mem_indirect, Column::IsMemIndirect);
    // StoreImm / StoreImmInd flags.
    trace.fill_columns(row, flags.is_store_imm_any, Column::IsStoreImmAny);
    trace.fill_columns(row, flags.is_store_imm_direct, Column::IsStoreImmDirect);
    // StoreInd flag + RegValA (regs_before[reg_a]).
    trace.fill_columns(row, flags.is_store_ind, Column::IsStoreInd);
    let reg_val_a_u64 = if flags.is_store_ind {
        step.regs_before[step.reg_a]
    } else {
        0
    };
    trace.fill_columns(row, reg_val_a_u64, Column::RegValA);
    // RotL64 flag.  RotL64's val_d gets rewritten to 2^n +
    // ShiftQuotient infra fires (gated on the IsShiftConstrained
    // above).
    trace.fill_columns(row, flags.is_rotate_l64, Column::IsRotateL64);
}

/// The memory access: its address, bytes and carries, and the protected-zone
/// witness; and the next timestamp.
pub(super) fn memory(out: &mut Sinks, s: Step, ops: &Operands) {
    let Sinks {
        trace, side_note, ..
    } = out;
    let Step { row, step, flags } = s;
    let Operands {
        val_b,
        result_bytes,
        ..
    } = *ops;
    let mut mem_addr_carry = [0u8; 4];
    if flags.is_mem_indirect {
        let val_b_bytes_le = val_b.to_le_bytes();
        let imm_bytes_le = step.imm.to_le_bytes();
        let mut c: u16 = 0;
        for i in 0..4 {
            let s = val_b_bytes_le[i] as u16 + imm_bytes_le[i] as u16 + c;
            c = s >> 8;
            mem_addr_carry[i] = c as u8;
        }
    }
    trace.fill_columns_bytes(row, &mem_addr_carry, Column::MemAddrCarry);
    let load_sign_src: u8 = if flags.is_load_i8 {
        result_bytes[0]
    } else if flags.is_load_i16 {
        result_bytes[1]
    } else if flags.is_load_i32 {
        result_bytes[3]
    } else {
        0
    };
    let load_sign_bit: u8 = (load_sign_src >> 7) & 1;
    let load_sign_hi: u8 = load_sign_src >> 4;
    let load_sign_lo: u8 = load_sign_src & 0xF;
    trace.fill_columns(row, load_sign_src, Column::LoadSignSrc);
    trace.fill_columns(row, load_sign_bit, Column::LoadSignBit);
    trace.fill_columns(row, load_sign_hi, Column::LoadSignHiNib);
    *side_note
        .bitwise_and_counts
        .entry((load_sign_hi, 8))
        .or_insert(0) += 1;
    *side_note
        .bitwise_and_counts
        .entry((load_sign_lo, 0xF))
        .or_insert(0) += 1;
    let mem = step.mem_read.as_ref().or(step.mem_write.as_ref());
    if let Some(m) = mem {
        trace.fill_columns_bytes(row, &m.address.to_le_bytes(), Column::MemAddr);
        trace.fill_columns(row, m.value, Column::MemValue);
        trace.fill_columns(row, m.size, Column::MemSize);
        let mut byte_active = [0u8; 8];
        for i in 0..m.size as usize {
            byte_active[i] = 1;
        }
        trace.fill_columns_bytes(row, &byte_active, Column::MemByteActive);
        // Per-byte address carry chain: byte `i` lives at `address + i`,
        // whose canonical little-endian bytes need carry propagation when
        // the access crosses a 256/65536/16M boundary (a misaligned
        // multi-byte access can). Emit the carries out of address bytes
        // 0,1,2 for each of the 8 byte offsets so the lookup tuple's
        // address matches the MemoryChip ledger's canonical decomposition.
        let mut c1 = [0u8; 8];
        let mut c2 = [0u8; 8];
        let mut c3 = [0u8; 8];
        let a0 = m.address & 0xff;
        let a1 = (m.address >> 8) & 0xff;
        let a2 = (m.address >> 16) & 0xff;
        for i in 0..8u32 {
            c1[i as usize] = ((a0 + i) >> 8) as u8;
            c2[i as usize] = ((a1 + c1[i as usize] as u32) >> 8) as u8;
            c3[i as usize] = ((a2 + c2[i as usize] as u32) >> 8) as u8;
        }
        trace.fill_columns_bytes(row, &c1, Column::MemByteAddrCarry1);
        trace.fill_columns_bytes(row, &c2, Column::MemByteAddrCarry2);
        trace.fill_columns_bytes(row, &c3, Column::MemByteAddrCarry3);
    }

    // Standard-v0.8 protected-zone / top-wrap witness.  The AIR selects
    // the carry for the authenticated opcode width, so derive the same
    // final-byte offset from classification rather than trusting
    // `MemAccess::size` here.
    let is_standard_mem = flags.is_load || flags.is_store;
    trace.fill_columns(row, is_standard_mem, Column::IsStandardMemH);
    let address = mem.map(|m| m.address).unwrap_or(0);
    let last_offset = if flags.is_mem_size_1 {
        0u32
    } else if flags.is_mem_size_2 {
        1
    } else if flags.is_mem_size_4 {
        3
    } else if flags.is_mem_size_8 {
        7
    } else {
        0
    };
    // MemByteAddrCarry3 is the carry INTO byte 3 from the lower 24 bits,
    // not the final carry out of the u32 address.  Keep this helper
    // identical to the AIR-selected carry column.
    let last_carry = ((u64::from(address & 0x00ff_ffff) + u64::from(last_offset)) >> 24) as u8;
    trace.fill_columns(row, last_carry, Column::MemLastAddrCarryH);

    // The two factors are bounded by 65535 and 256 respectively, so the
    // integer product is already the canonical M31 representative.
    let high_word = address >> 16;
    let no_wrap_factor = 256 - (address >> 24) - u32::from(last_carry);
    let range_product = high_word * no_wrap_factor;
    let range_product_f = stwo::core::fields::m31::BaseField::from(range_product);
    let range_inv_f = if range_product == 0 {
        stwo::core::fields::m31::BaseField::from(0u32)
    } else {
        range_product_f.inverse()
    };
    trace.fill_columns_base_field(row, &[range_product_f], Column::MemRangeProductH);
    trace.fill_columns_base_field(row, &[range_inv_f], Column::MemRangeInv);
    trace.fill_columns_base_field(
        row,
        &[range_product_f * range_inv_f],
        Column::MemRangeTimesInvH,
    );

    // NextTimestamp = timestamp + 1
    trace.fill_columns(row, step.timestamp + 1, Column::NextTimestamp);
    fill_ts_carry(trace, row, step.timestamp);
}
