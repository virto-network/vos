//! Every row's constraints: padding, and the timestamp chain.
use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Row};
use crate::chips::cpu::columns::Column;
use crate::core::step::WORD_SIZE;

/// A padding row is no instruction: its flag bytes are zero.
pub(in crate::chips::cpu) fn padding<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    // ── A padding row is no instruction ──
    // Its flag bytes are zero, and with them every flag and every
    // emission gate: the byte-to-bits lookups, ungated, and the bytes'
    // recompositions pin each flag to its bit on every row, and the
    // remaining gates (the memory bytes, the precompile selectors, the
    // result write) follow from the flags below. So a padding row
    // emits nothing, wherever it sits.
    eval.add_constraint(row.is_padding[0].clone() * (row.is_padding[0].clone() - E::F::one()));
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
        eval.add_constraint(row.is_padding[0].clone() * row.column(byte)[0].clone());
    }
}

/// Step-timestamp chaining: `NextTimestamp = Timestamp + 1`, limb by limb.
pub(in crate::chips::cpu) fn timestamp_chain<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    let is_real = E::F::one() - row.is_padding[0].clone();
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
        let f256_ts = E::F::from(BaseField::from(256));
        for c in row.ts_carry.iter() {
            eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
        }
        eval.add_constraint(
            is_real.clone()
                * (row.next_timestamp[0].clone() + row.ts_carry[0].clone() * f256_ts.clone()
                    - row.timestamp[0].clone()
                    - E::F::one()),
        );
        for i in 1..7 {
            eval.add_constraint(
                is_real.clone()
                    * (row.next_timestamp[i].clone() + row.ts_carry[i].clone() * f256_ts.clone()
                        - row.timestamp[i].clone()
                        - row.ts_carry[i - 1].clone()),
            );
        }
        eval.add_constraint(
            is_real.clone()
                * (row.next_timestamp[7].clone()
                    - row.timestamp[7].clone()
                    - row.ts_carry[6].clone()),
        );
    }
}

/// Helpers other classes read: the Trap row, the address carries, the high popcount, a load's inactive bytes and the DivS remainder's sign.
pub(in crate::chips::cpu) fn shared_helpers<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    let is_real = E::F::one() - row.is_padding[0].clone();
    let is_64bit = E::F::one() - row.is32_bit[0].clone();
    // ── Residual helpers ──
    {
        // Trap helper.
        eval.add_constraint(
            row.is_real_trap_h[0].clone() - is_real.clone() * row.is_trap[0].clone(),
        );
        // MemAddrCarry boolean per byte, enforced unconditionally.
        for i in 0..4 {
            eval.add_constraint(
                row.mem_addr_carry[i].clone() * (E::F::one() - row.mem_addr_carry[i].clone()),
            );
        }
        // Popcount-hi helper.
        let mut pop_hi_sum = row.byte_popcount[4].clone();
        for i in 5..WORD_SIZE {
            pop_hi_sum += row.byte_popcount[i].clone();
        }
        eval.add_constraint(row.is64bit_popcount_hi_h[0].clone() - is_64bit.clone() * pop_hi_sum);
        // IsLoadLocal × (1 - MemByteActive[i]) per byte.
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                row.is_load_local_not_active_h[i].clone()
                    - row.is_load[0].clone() * (E::F::one() - row.mem_byte_active[i].clone()),
            );
        }
        // ValRByteIndicator + ByteIndMinus1 + PartNZTimesInd.
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                row.val_r_byte_indicator_h[i].clone()
                    - row.div_remainder[i].clone() * row.val_r_byte_inv[i].clone(),
            );
            eval.add_constraint(
                row.val_r_byte_ind_minus1_h[i].clone()
                    - row.div_remainder[i].clone() * row.val_r_byte_indicator_h[i].clone()
                    + row.div_remainder[i].clone(),
            );
        }
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                row.val_r_part_nz_times_ind_h[i - 1].clone()
                    - row.val_r_partial_nz[i - 1].clone() * row.val_r_byte_indicator_h[i].clone(),
            );
        }
        // DivS sign-of-r gate via 2-step helper chain:
        // IsDivSNotDbzH = is_div_s · (1 - div_by_zero)         (deg 2 def)
        // DivSActivePartialH = IsDivSNotDbzH · val_r_partial_nz[7]  (deg 2 def)
        eval.add_constraint(
            row.is_div_s_not_dbz_h[0].clone()
                - row.is_div_s[0].clone() * (E::F::one() - row.div_by_zero[0].clone()),
        );
        eval.add_constraint(
            row.div_s_active_partial_h[0].clone()
                - row.is_div_s_not_dbz_h[0].clone() * row.val_r_partial_nz[WORD_SIZE - 1].clone(),
        );
    }
}

/// The next timestamp's limbs are bytes.
pub(in crate::chips::cpu) fn next_timestamp_bytes<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups,
) {
    let range256_lookup = &lookups.range256_lookup;
    let is_real = E::F::one() - row.is_padding[0].clone();
    // ── The next timestamp's limbs are bytes ──
    // The carry chain fixes the timestamp's field value, not its limbs:
    // a withheld carry leaves a limb of 256 that a successor carries on.
    // Eight emissions, kept last (CONSTRAINTS.md 2).
    {
        for limb in &row.next_timestamp {
            eval.add_to_relation(RelationEntry::new(
                range256_lookup,
                is_real.clone().into(),
                core::slice::from_ref(limb),
            ));
        }
    }
}
