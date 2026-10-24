//! The register accesses and the host calls.

use super::*;
use crate::chips::cpu::tuples::BLAKE2B_CALL_REGS;

/// The register accesses: the operands' reads, the result's write, the
/// host calls' register reads and the BLAKE2b call.
pub(super) fn registers(
    logup: &mut LogupTraceBuilder,
    row: &RowTrace<'_>,
    lookup_elements: &AllLookupElements,
) {
    let timestamp = &row.timestamp;
    // ── Register-memory producer emissions ──
    // Three potential register accesses per step: ValB read, ValD read,
    // Result write.  Each is gated by its Is* flag and emits a tuple
    // (reg_idx[1], value[8], timestamp[8]) matching RegisterMemoryChip's
    // ledger consumers.  Flags are 0 when the corresponding slot isn't
    // a register access (immediate source, or no register write).
    let reg_lookup: &RegisterMemoryLookupElements = lookup_elements.as_ref();
    let val_b_is_reg = &row.val_b_is_reg;
    let val_b_reg_idx = &row.val_b_reg_idx;
    let val_d_is_reg = &row.val_d_is_reg;
    let val_d_reg_idx = &row.val_d_reg_idx;
    let result_is_reg = &row.result_is_reg;
    let result_reg_idx = &row.result_reg_idx;
    let result_cols = &row.result;
    // is_write is the last register-tuple limb (binds reads vs writes — see
    // RegisterMemoryChip).  Constant per emission: 0 for reads, 1 for the
    // result write.
    let is_write_read = crate::trace::component::FinalizedColumn::Constant(BaseField::from(0u32));
    let is_write_write = crate::trace::component::FinalizedColumn::Constant(BaseField::from(1u32));
    {
        // Use RegValB (raw register value) rather than ValB so
        // 32-bit-truncated ops still emit the authentic register value.
        let reg_val_b_cols = &row.reg_val_b;
        let mut tuple: Vec<_> = vec![val_b_reg_idx[0].clone()];
        tuple.extend_from_slice(reg_val_b_cols);
        tuple.extend_from_slice(timestamp);
        tuple.push(is_write_read.clone());
        logup.add_to_relation_with(
            reg_lookup,
            [val_b_is_reg[0].clone()],
            |[active]| active.into(),
            &tuple,
        );
    }
    {
        // Use RegValD (raw register value) instead of ValD
        // (which gets rewritten to 2^shift_amount for shift ops).
        let reg_val_d_cols = &row.reg_val_d;
        let mut tuple: Vec<_> = vec![val_d_reg_idx[0].clone()];
        tuple.extend_from_slice(reg_val_d_cols);
        tuple.extend_from_slice(timestamp);
        tuple.push(is_write_read.clone());
        logup.add_to_relation_with(
            reg_lookup,
            [val_d_is_reg[0].clone()],
            |[active]| active.into(),
            &tuple,
        );
    }
    // RegValA producer (paired emission for parity).
    {
        let reg_val_a_cols = &row.reg_val_a;
        let reg_a_cols = &row.reg_a;
        let is_store_ind_col = &row.is_store_ind;
        let mut tuple: Vec<_> = vec![reg_a_cols[0].clone()];
        tuple.extend_from_slice(reg_val_a_cols);
        tuple.extend_from_slice(timestamp);
        tuple.push(is_write_read.clone());
        for _ in 0..2 {
            logup.add_to_relation_with(
                reg_lookup,
                [is_store_ind_col[0].clone()],
                |[active]| active.into(),
                &tuple,
            );
        }
    }
    {
        let mut tuple: Vec<_> = vec![result_reg_idx[0].clone()];
        tuple.extend_from_slice(result_cols);
        tuple.extend_from_slice(timestamp);
        tuple.push(is_write_write.clone());
        logup.add_to_relation_with(
            reg_lookup,
            [result_is_reg[0].clone()],
            |[active]| active.into(),
            &tuple,
        );
    }

    // The BLAKE2b call's register reads, a producer a slot
    // ([`BLAKE2B_CALL_REGS`]), only at a served call's step.
    let is_blake_ecall = &row.is_blake_ecall;
    let phi7 = &row.phi7;
    let phi10 = &row.phi10;
    let phi11 = &row.phi11;
    let phi12 = &row.phi12;
    let phi_cols: [_; 4] = [phi7.clone(), phi10.clone(), phi11.clone(), phi12.clone()];
    for (slot, &reg_idx) in BLAKE2B_CALL_REGS.iter().enumerate() {
        let idx_const = PackedBaseField::broadcast(BaseField::from(reg_idx));
        let val_c = phi_cols[slot].clone();
        let ts_c = timestamp.clone();
        logup.add_to_relation_computed(
            reg_lookup,
            [is_blake_ecall[0].clone()],
            |[active]| active.into(),
            18,
            move |v| {
                let mut t = Vec::with_capacity(18);
                t.push(idx_const);
                for c in &val_c {
                    t.push(c.at(v));
                }
                for c in &ts_c {
                    t.push(c.at(v));
                }
                // is_write = 0 (blake2b ECALL register accesses are reads).
                t.push(PackedBaseField::broadcast(BaseField::from(0u32)));
                t
            },
        );
    }

    // ── Blake2b call binding ──
    // Producer side: at any step where IsBlakeEcall is set, emit
    //   (phi10[0..4], phi11[0..4], phi12[0..8], phi7_bool, timestamp[0..8])
    // Blake2bChip emits the matching consumer at IsFirstOfCompression so
    // the tuple values must agree.
    let blake2b_call: &Blake2bCallLookupElements = lookup_elements.as_ref();
    let phi7_bool = &row.phi7_bool;
    {
        let mut tuple: Vec<_> = Vec::with_capacity(25);
        tuple.extend_from_slice(&phi10[0..4]);
        tuple.extend_from_slice(&phi11[0..4]);
        tuple.extend_from_slice(phi12);
        tuple.push(phi7_bool[0].clone());
        tuple.extend_from_slice(timestamp);
        logup.add_to_relation_with(
            blake2b_call,
            [is_blake_ecall[0].clone()],
            |[active]| active.into(),
            &tuple,
        );
    }

    // ── Witness-input register reads ──
    // Prover-side mirror of the mod.rs producers, in the same order: φ[7]
    // and φ[8], the call's destination and capacity, from the Phi10/Phi11
    // slots.
    {
        let is_witness = &row.is_witness_ecall;

        // Register-read producers: (reg_idx, value[8], ts[8], is_write=0).
        for (reg_idx, value) in [(7u32, phi10), (8u32, phi11)] {
            let mut tuple: Vec<_> = Vec::with_capacity(18);
            tuple.push(crate::trace::component::FinalizedColumn::Constant(
                BaseField::from(reg_idx),
            ));
            tuple.extend_from_slice(value);
            tuple.extend_from_slice(timestamp);
            tuple.push(is_write_read.clone());
            logup.add_to_relation_with(
                reg_lookup,
                [is_witness[0].clone()],
                |[active]| active.into(),
                &tuple,
            );
        }
    }
}

/// The witness input: its count compared with its capacity, and its call.
pub(super) fn witness_input(
    logup: &mut LogupTraceBuilder,
    row: &RowTrace<'_>,
    lookup_elements: &AllLookupElements,
) {
    let timestamp = &row.timestamp;
    let phi10 = &row.phi10;
    let phi11 = &row.phi11;
    // ── Witness input (prover-side mirror) ──
    // Two CompareLookup tuples (φ8, count, 0), then two WitnessCall tuples
    // (ts, φ7's low four bytes, count), the count combined from Result's
    // three low bytes.
    {
        let compare: &CompareLookupElements = lookup_elements.as_ref();
        let witness_call: &WitnessCallLookupElements = lookup_elements.as_ref();
        let is_witness = &row.is_witness_ecall;
        let non_empty = &row.witness_non_empty;
        let result = &row.result;
        let mut compare_tuple: Vec<_> = phi11.to_vec();
        compare_tuple.extend_from_slice(result);
        compare_tuple.push(crate::trace::component::FinalizedColumn::Constant(
            BaseField::from(0u32),
        ));
        for _ in 0..2 {
            logup.add_to_relation_with(
                compare,
                [is_witness[0].clone()],
                |[active]| active.into(),
                &compare_tuple,
            );
        }
        for _ in 0..2 {
            let (ts_c, destination_c, result_c) =
                (timestamp.clone(), phi10.clone(), result.clone());
            logup.add_to_relation_computed(
                witness_call,
                [non_empty[0].clone()],
                |[active]| active.into(),
                13,
                move |v| {
                    let mut t = Vec::with_capacity(13);
                    for c in &ts_c {
                        t.push(c.at(v));
                    }
                    for c in &destination_c[..4] {
                        t.push(c.at(v));
                    }
                    let byte = |i: usize| result_c[i].at(v);
                    t.push(
                        byte(0)
                            + byte(1) * PackedBaseField::broadcast(BaseField::from(1u32 << 8))
                            + byte(2) * PackedBaseField::broadcast(BaseField::from(1u32 << 16)),
                    );
                    t
                },
            );
        }
    }
}
