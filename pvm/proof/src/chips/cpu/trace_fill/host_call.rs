//! Host calls.

use super::*;

/// The BLAKE2b call's flag register: whether it is non-zero, the sum of its
/// bytes and the sum's inverse.
#[derive(Clone, Copy)]
pub(super) struct HostCall {
    pub phi7_bool: u8,
    pub phi7_sum: BaseField,
    pub phi7_inv: BaseField,
}

/// The host calls: the BLAKE2b call's registers and the witness input's count.
pub(super) fn host_call(out: &mut Sinks, s: Step, ops: &Operands) -> HostCall {
    let Sinks {
        trace,
        side_note,
        range_bytes,
        ..
    } = out;
    let Step { row, step, .. } = s;
    let Operands { is_witness, .. } = *ops;
    // ── Blake2b ECALL binding ──
    // Detect Ecalli with imm == ECALL_BLAKE2B_COMPRESS and snapshot the
    // regs_before values that the precompile reads.
    //
    // Register convention: the vos-pvm-precompiles shim puts
    // a0/a1/a2/a3 → h_ptr/m_ptr/t_low/f_flag, which grey-transpiler
    // maps to PVM φ[7/8/9/10].  The `Column::Phi*` names below are
    // semantic slot labels for the Blake2bCall lookup tuple — Phi10
    // holds h_ptr (sourced from φ[7]), Phi11 holds m_ptr (φ[8]),
    // Phi12 holds t_low (φ[9]), and Phi7 holds the full u64 of
    // f_flag (φ[10]).  The slot-to-register-index re-routing happens
    // in the ECALL_REG_IDXS array on the producer side; the Phi*
    // column names are kept as-is (they don't match the slot
    // semantics) to avoid renaming across files, at the cost of a
    // little local confusion (the column comments below carry the
    // slot's actual semantic meaning).
    // Only a served call selects a relation (`PvmStep::served_ecall`).
    let ecall = step.served_ecall();
    let is_blake_ecall = ecall == Some(ECALL_BLAKE2B_COMPRESS as u64);
    trace.fill_columns(row, is_blake_ecall, Column::IsBlakeEcall);
    // Witness input: its selector, whether its count is non-zero with
    // the count's inverse, and the comparison count ≤ φ8 CompareChip
    // proves.
    trace.fill_columns(row, is_witness, Column::IsWitnessEcall);
    if is_witness {
        use stwo::core::fields::m31::BaseField;
        let count = step.regs_after[7];
        trace.fill_columns(row, count != 0, Column::WitnessNonEmpty);
        if count != 0 {
            let inverse = BaseField::from(count as u32).inverse();
            trace.fill_columns_base_field(row, &[inverse], Column::WitnessCountInv);
            trace.fill_columns_base_field(
                row,
                &[BaseField::from(1u32)],
                Column::WitnessCountTimesInvH,
            );
        }
        let capacity = step.regs_before[8];
        let (capacity_bytes, count_bytes) = (capacity.to_le_bytes(), count.to_le_bytes());
        let mut cmp_sub_result = [0u8; WORD_SIZE];
        let mut cmp_carry = [0u8; WORD_SIZE];
        let mut carry: u16 = 1;
        for i in 0..WORD_SIZE {
            let sum = capacity_bytes[i] as u16 + (count_bytes[i] ^ 0xFF) as u16 + carry;
            cmp_sub_result[i] = (sum & 0xFF) as u8;
            cmp_carry[i] = (sum >> 8) as u8;
            carry = cmp_carry[i] as u16;
        }
        // CompareChip range-checks its subtraction's bytes.
        range_bytes.extend_from_slice(&cmp_sub_result);
        side_note
            .compare_entries
            .push(crate::side_note::CompareEntry {
                val_b: capacity,
                val_d: count,
                cmp_lt_flag: 1 - cmp_carry[WORD_SIZE - 1],
                cmp_sub_result,
                cmp_carry,
            });
    }
    // Phi10 slot ← h_ptr (a0 = x10 = PVM φ[7]).
    trace.fill_columns(row, step.regs_before[7], Column::Phi10);
    // Phi11 slot ← m_ptr (a1 = x11 = PVM φ[8]).
    trace.fill_columns(row, step.regs_before[8], Column::Phi11);
    // Phi12 slot ← t_low (a2 = x12 = PVM φ[9]).
    trace.fill_columns(row, step.regs_before[9], Column::Phi12);
    // Phi7 slot ← f_flag (a3 = x13 = PVM φ[10]).
    let phi7_u64 = step.regs_before[10];
    trace.fill_columns(row, phi7_u64, Column::Phi7);
    // Phi7 is non-zero exactly when its bytes' sum is: at most 2040,
    // it is its own field value, so its inverse witnesses it.
    let phi7_sum = BaseField::from(
        phi7_u64
            .to_le_bytes()
            .iter()
            .map(|&b| u32::from(b))
            .sum::<u32>(),
    );
    let phi7_bool: u8 = (phi7_u64 != 0).into();
    trace.fill_columns(row, phi7_bool, Column::Phi7Bool);
    let phi7_inv = if phi7_u64 != 0 {
        phi7_sum.inverse()
    } else {
        BaseField::from(0u32)
    };
    trace.fill_columns_base_field(row, &[phi7_inv], Column::Phi7Inv);
    HostCall {
        phi7_bool,
        phi7_sum,
        phi7_inv,
    }
}

/// The host call's acknowledgment.
pub(super) fn disposition(out: &mut Sinks, s: Step) {
    let Sinks { trace, .. } = out;
    let Step { row, step, .. } = s;
    // ── Host-call disposition ──
    // ECALLI retains its cause PC until the proof runtime handles it. The
    // AIR authenticates the opcode class and the committed precompile
    // dispatch before accepting this acknowledgment.
    trace.fill_columns(
        row,
        step.host_call_acknowledged,
        Column::HostCallAcknowledged,
    );
}
