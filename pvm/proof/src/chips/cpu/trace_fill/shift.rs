//! Shifts and rotates.

use super::*;

/// A shift's amount, and whether its operand is a power of two.
#[derive(Clone, Copy)]
pub(super) struct Shift {
    pub shift_amount: u8,
    pub is_shift_constrained: bool,
}

/// The shift amount and its complement for a rotate right.
pub(super) fn shift(out: &mut Sinks, s: Step, ops: &Operands) -> Shift {
    let Sinks { trace, .. } = out;
    let Step { row, flags, .. } = s;
    let Operands {
        val_d,
        saved_shift_amount,
        saved_shift_amount_compl,
        saved_shift_quotient_compl,
        ..
    } = *ops;
    // ── Shift auxiliary ──
    let shift_amount = if flags.is_shift {
        if flags.shift_op <= 2
            || flags.is_rotate_l64
            || flags.is_rotate_r64
            || flags.is_rotate_l32
            || flags.is_rotate_r32
        {
            saved_shift_amount // saved before val_d was replaced
        } else {
            let modulus = if flags.is_32bit { 32u64 } else { 64 };
            (val_d % modulus) as u8 // for non-constrained shifts, val_d is original
        }
    } else {
        0
    };
    trace.fill_columns(row, shift_amount, Column::ShiftAmount);
    // IsShiftConstrained covers all four rotate variants.  val_d
    // gets rewritten to a power of two; the val_d-vs-RegValD
    // cross-constraint then skips equality on those rows.
    let is_shift_constrained = (flags.is_shift && flags.shift_op <= 2)
        || flags.is_rotate_l64
        || flags.is_rotate_r64
        || flags.is_rotate_l32
        || flags.is_rotate_r32;
    trace.fill_columns(row, is_shift_constrained, Column::IsShiftConstrained);
    // Rotate flags + complementary shift columns.
    trace.fill_columns(row, flags.is_rotate_r64, Column::IsRotateR64);
    trace.fill_columns(row, flags.is_rotate_l32, Column::IsRotateL32);
    trace.fill_columns(row, flags.is_rotate_r32, Column::IsRotateR32);
    trace.fill_columns(row, flags.is_imm_alt, Column::IsImmAlt);
    trace.fill_columns(row, saved_shift_amount_compl, Column::ShiftAmountCompl);
    trace.fill_columns_bytes(
        row,
        &bits::<4>(saved_shift_quotient_compl),
        Column::ShiftQuotientCompl,
    );
    Shift {
        shift_amount,
        is_shift_constrained,
    }
}
