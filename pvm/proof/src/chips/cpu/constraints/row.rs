//! Every row's constraints: padding, and the timestamp chain.
use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Trace};
use crate::chips::cpu::columns::Column;
use crate::core::step::WORD_SIZE;

/// A padding row is no instruction: its flag bytes are zero.
pub(in crate::chips::cpu) fn padding<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);

    // ── A padding row is no instruction ──
    // Its flag bytes are zero, and with them every flag and every
    // emission gate: the byte-to-bits lookups, ungated, and the bytes'
    // recompositions pin each flag to its bit on every row, and the
    // remaining gates (the memory bytes, the precompile selectors, the
    // result write) follow from the flags below. So a padding row
    // emits nothing, wherever it sits.
    eval.add_constraint(is_pad[0].clone() * (is_pad[0].clone() - E::F::one()));
    for byte in [
        Column::FlagByte0,
        Column::FlagByte1,
        Column::FlagByte2,
        Column::FlagByte3,
        Column::FlagByte4,
        Column::FlagByte5,
        Column::FlagByte6,
        Column::FlagByte7,
        Column::FlagByte8,
        Column::FlagByte9,
    ] {
        eval.add_constraint(is_pad[0].clone() * trace_eval.column_eval::<1>(byte)[0].clone());
    }
}

/// Step-timestamp chaining: `NextTimestamp = Timestamp + 1`, limb by limb.
pub(in crate::chips::cpu) fn timestamp_chain<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
    let is_real = E::F::one() - is_pad[0].clone();
    // ── Step-timestamp chaining: NextTimestamp = Timestamp + 1 ──
    // Limb-canonical via a boolean carry chain.  The program-execution
    // lookup (further down) sequences steps as a multiset permutation
    // over (ts, pc) → (next_ts, next_pc) pairs anchored by the
    // ProgramBoundaryChip's (initial_ts, initial_pc) / (final_ts,
    // final_pc).  Without this binding the permutation also balances
    // disjoint timestamp cycles (rows producing/consuming each other at
    // attacker-chosen timestamps), letting a forged step emit a
    // register/memory tuple OUTSIDE [initial_ts, final_ts) — notably
    // ts = 0 or ts = closing_ts, which the boundary/closing chips reserve.
    // Chaining collapses the permutation to a single path from the
    // boundary-pinned initial timestamp to the final one, so every real
    // row's timestamp provably lies in [initial_ts, final_ts).  Limb 7
    // has no outgoing carry, so the increment cannot wrap; closing a
    // cycle would require every carry level to overflow (≥ 2^24 rows —
    // far above any trace).  Kept ahead of every `add_to_relation` so a
    // constraint failure unwinds cleanly (before the logup guard exists).
    {
        let timestamp = crate::trace::trace_eval!(trace_eval, Column::Timestamp);
        let next_ts = crate::trace::trace_eval!(trace_eval, Column::NextTimestamp);
        let ts_carry = crate::trace::trace_eval!(trace_eval, Column::TsCarry);
        let f256_ts = E::F::from(BaseField::from(256));
        for c in ts_carry.iter() {
            eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
        }
        eval.add_constraint(
            is_real.clone()
                * (next_ts[0].clone() + ts_carry[0].clone() * f256_ts.clone()
                    - timestamp[0].clone()
                    - E::F::one()),
        );
        for i in 1..7 {
            eval.add_constraint(
                is_real.clone()
                    * (next_ts[i].clone() + ts_carry[i].clone() * f256_ts.clone()
                        - timestamp[i].clone()
                        - ts_carry[i - 1].clone()),
            );
        }
        eval.add_constraint(
            is_real.clone() * (next_ts[7].clone() - timestamp[7].clone() - ts_carry[6].clone()),
        );
    }
}

/// Helpers other classes read: the Trap row, the address carries, the high popcount, a load's inactive bytes and the DivS remainder's sign.
pub(in crate::chips::cpu) fn shared_helpers<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
    let is_real = E::F::one() - is_pad[0].clone();
    let is_real_trap_h = crate::trace::trace_eval!(trace_eval, Column::IsRealTrapH);
    let is_64bit_popcount_hi_h = crate::trace::trace_eval!(trace_eval, Column::Is64bitPopcountHiH);
    let is_load_local_not_active_h =
        crate::trace::trace_eval!(trace_eval, Column::IsLoadLocalNotActiveH);
    let val_r_byte_indicator_h = crate::trace::trace_eval!(trace_eval, Column::ValRByteIndicatorH);
    let val_r_byte_ind_minus_1_h =
        crate::trace::trace_eval!(trace_eval, Column::ValRByteIndMinus1H);
    let val_r_part_nz_times_ind_h =
        crate::trace::trace_eval!(trace_eval, Column::ValRPartNZTimesIndH);
    let div_s_active_partial_h = crate::trace::trace_eval!(trace_eval, Column::DivSActivePartialH);
    let is_32bit = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
    let is_64bit = E::F::one() - is_32bit[0].clone();
    let div_by_zero_for_h = crate::trace::trace_eval!(trace_eval, Column::DivByZero);
    let is_div_s = crate::trace::trace_eval!(trace_eval, Column::IsDivS);
    // ── Residual helpers ──
    {
        let is_trap_col_top = crate::trace::trace_eval!(trace_eval, Column::IsTrap);
        let mem_addr_carry_top = crate::trace::trace_eval!(trace_eval, Column::MemAddrCarry);
        let is_load_local_top = crate::trace::trace_eval!(trace_eval, Column::IsLoad);
        let mem_byte_active_top = crate::trace::trace_eval!(trace_eval, Column::MemByteActive);
        let div_remainder_top = crate::trace::trace_eval!(trace_eval, Column::DivRemainder);
        let val_r_byte_inv_top = crate::trace::trace_eval!(trace_eval, Column::ValRByteInv);
        let val_r_partial_nz_top = crate::trace::trace_eval!(trace_eval, Column::ValRPartialNZ);
        let byte_popcount_top = crate::trace::trace_eval!(trace_eval, Column::BytePopcount);
        // Trap helper.
        eval.add_constraint(
            is_real_trap_h[0].clone() - is_real.clone() * is_trap_col_top[0].clone(),
        );
        // MemAddrCarry boolean per byte, enforced unconditionally.
        for i in 0..4 {
            eval.add_constraint(
                mem_addr_carry_top[i].clone() * (E::F::one() - mem_addr_carry_top[i].clone()),
            );
        }
        // Popcount-hi helper.
        let mut pop_hi_sum = byte_popcount_top[4].clone();
        for i in 5..WORD_SIZE {
            pop_hi_sum += byte_popcount_top[i].clone();
        }
        eval.add_constraint(is_64bit_popcount_hi_h[0].clone() - is_64bit.clone() * pop_hi_sum);
        // IsLoadLocal × (1 - MemByteActive[i]) per byte.
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                is_load_local_not_active_h[i].clone()
                    - is_load_local_top[0].clone() * (E::F::one() - mem_byte_active_top[i].clone()),
            );
        }
        // ValRByteIndicator + ByteIndMinus1 + PartNZTimesInd.
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                val_r_byte_indicator_h[i].clone()
                    - div_remainder_top[i].clone() * val_r_byte_inv_top[i].clone(),
            );
            eval.add_constraint(
                val_r_byte_ind_minus_1_h[i].clone()
                    - div_remainder_top[i].clone() * val_r_byte_indicator_h[i].clone()
                    + div_remainder_top[i].clone(),
            );
        }
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                val_r_part_nz_times_ind_h[i].clone()
                    - val_r_partial_nz_top[i - 1].clone() * val_r_byte_indicator_h[i].clone(),
            );
        }
        // DivS sign-of-r gate via 2-step helper chain:
        // IsDivSNotDbzH = is_div_s · (1 - div_by_zero)         (deg 2 def)
        // DivSActivePartialH = IsDivSNotDbzH · val_r_partial_nz[7]  (deg 2 def)
        let is_div_s_not_dbz_h = crate::trace::trace_eval!(trace_eval, Column::IsDivSNotDbzH);
        eval.add_constraint(
            is_div_s_not_dbz_h[0].clone()
                - is_div_s[0].clone() * (E::F::one() - div_by_zero_for_h[0].clone()),
        );
        eval.add_constraint(
            div_s_active_partial_h[0].clone()
                - is_div_s_not_dbz_h[0].clone() * val_r_partial_nz_top[WORD_SIZE - 1].clone(),
        );
    }
}

/// The next timestamp's limbs are bytes.
pub(in crate::chips::cpu) fn next_timestamp_bytes<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let range256_lookup = lookups.range256_lookup;
    let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
    let is_real = E::F::one() - is_pad[0].clone();
    // ── The next timestamp's limbs are bytes ──
    // The carry chain fixes the timestamp's field value, not its limbs:
    // a withheld carry leaves a limb of 256 that a successor carries on.
    // Eight emissions, kept last (CONSTRAINTS.md 2).
    {
        let next_ts = crate::trace::trace_eval!(trace_eval, Column::NextTimestamp);
        for limb in &next_ts {
            eval.add_to_relation(RelationEntry::new(
                range256_lookup,
                is_real.clone().into(),
                core::slice::from_ref(limb),
            ));
        }
    }
}
