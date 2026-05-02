//! CpuChip interaction-trace generation (Phase 47 split).
//!
//! Mirror of `cpu/mod.rs::add_constraints` on the prover side: every
//! lookup the verifier's `add_constraints` consumes/produces gets a
//! corresponding `logup.add_to_relation_with` here.  Multiplicities
//! and tuple shapes must match the constraint side byte-for-byte —
//! if the two diverge, the per-component logup sum is non-zero and
//! verification fails with "claimed logup sum is not zero".
//!
//! Adding a new lookup means: add the verifier-side emission in
//! cpu/mod.rs, then add the prover-side emission here, then run
//! the minimum sweep (CONSTRAINTS.md rule 6).

#![cfg(feature = "prover")]

use num_traits::One;
use stwo::{
    core::{fields::m31::BaseField, fields::qm31::SecureField, ColumnVec},
    prover::{
        backend::simd::SimdBackend,
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};

use crate::core::step::WORD_SIZE;
use crate::lookups::{
    AllLookupElements, BitcountLookupElements, BitwiseAndLookupElements,
    BitwiseLookupElements,
    Blake2bCallLookupElements, CompareLookupElements,
    DivRemLookupElements,
    JumpTableLookupElements, LogupTraceBuilder,
    MemoryAccessLookupElements, MultiplicationLookupElements,
    PopcountLookupElements, PowerOfTwoLookupElements,
    ProgramExecutionLookupElements, ProgramMemoryLookupElements,
    Range256LookupElements, RegisterMemoryLookupElements,
};
use crate::trace::component::ComponentTrace;

use super::columns::Column;

pub(super) fn generate_interaction_trace(
    component_trace: ComponentTrace,
    lookup_elements: &AllLookupElements,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);
        let is_pad = crate::trace::original_base_column!(component_trace, Column::IsPadding);
        let range256: &Range256LookupElements = lookup_elements.as_ref();

        // Range256 lookups for result bytes
        let result = crate::trace::original_base_column!(component_trace, Column::Result);
        for col in &result {
            logup.add_to_relation_with(
                range256,
                [is_pad[0].clone()],
                |[pad]| {
                    use stwo::prover::backend::simd::m31::PackedBaseField;
                    (PackedBaseField::one() - pad).into()
                },
                &[col.clone()],
            );
        }

        // Phase 54f: cmp_sub_result Range256 lookup moved to CompareChip.
        // Bind the per-op flag columns here — referenced by the
        // ProgramMemory consumer's closure-based slot overrides
        // (Phase 53d/53e folds) further below.
        let is_setltu_col = crate::trace::original_base_column!(component_trace, Column::IsSetLtU);
        let is_setlts_col = crate::trace::original_base_column!(component_trace, Column::IsSetLtS);
        let is_cmoviz_col = crate::trace::original_base_column!(component_trace, Column::IsCmovIz);
        let is_cmovnz_col = crate::trace::original_base_column!(component_trace, Column::IsCmovNz);
        let is_mins_col = crate::trace::original_base_column!(component_trace, Column::IsMinS);
        let is_minu_col = crate::trace::original_base_column!(component_trace, Column::IsMinU);
        let is_maxs_col = crate::trace::original_base_column!(component_trace, Column::IsMaxS);
        let is_maxu_col = crate::trace::original_base_column!(component_trace, Column::IsMaxU);
        let is_br_eq_col = crate::trace::original_base_column!(component_trace, Column::IsBrEq);
        let is_br_ne_col = crate::trace::original_base_column!(component_trace, Column::IsBrNe);
        let is_br_lt_u_col = crate::trace::original_base_column!(component_trace, Column::IsBrLtU);
        let is_br_ge_u_col = crate::trace::original_base_column!(component_trace, Column::IsBrGeU);
        let is_br_le_u_col = crate::trace::original_base_column!(component_trace, Column::IsBrLeU);
        let is_br_gt_u_col = crate::trace::original_base_column!(component_trace, Column::IsBrGtU);
        let is_br_lt_s_col = crate::trace::original_base_column!(component_trace, Column::IsBrLtS);
        let is_br_ge_s_col = crate::trace::original_base_column!(component_trace, Column::IsBrGeS);
        let is_br_le_s_col = crate::trace::original_base_column!(component_trace, Column::IsBrLeS);
        let is_br_gt_s_col = crate::trace::original_base_column!(component_trace, Column::IsBrGtS);

        // Memory access lookups — byte-level (up to 8 entries per memory op)
        // Phase 53f: IsStore folded — `is_write` is the sum of the 3
        // store-class sub-flags (IsStoreDirect + IsStoreImmAny + IsStoreInd).
        let mem_lookup: &MemoryAccessLookupElements = lookup_elements.as_ref();
        let is_store_direct_mem = crate::trace::original_base_column!(component_trace, Column::IsStoreDirect);
        let is_store_imm_any_mem = crate::trace::original_base_column!(component_trace, Column::IsStoreImmAny);
        let is_store_ind_mem = crate::trace::original_base_column!(component_trace, Column::IsStoreInd);
        let mem_addr = crate::trace::original_base_column!(component_trace, Column::MemAddr);
        let mem_value = crate::trace::original_base_column!(component_trace, Column::MemValue);
        let timestamp = crate::trace::original_base_column!(component_trace, Column::Timestamp);
        let mem_byte_active = crate::trace::original_base_column!(component_trace, Column::MemByteActive);

        // For each byte offset 0..8, produce a byte-level lookup entry
        // Tuple: (addr+i [4], value_byte_i [1], timestamp[8], is_write[1])
        // Multiplicity: mem_byte_active[i] (1 if byte is within access size, 0 otherwise)
        for byte_idx in 0..8usize {
            let byte_offset = PackedBaseField::broadcast(BaseField::from(byte_idx as u32));
            let mem_addr_c = mem_addr.clone();
            let mem_value_c = mem_value.clone();
            let timestamp_c = timestamp.clone();
            let is_sd_c = is_store_direct_mem[0].clone();
            let is_sia_c = is_store_imm_any_mem[0].clone();
            let is_si_c = is_store_ind_mem[0].clone();
            logup.add_to_relation_computed(
                mem_lookup,
                [mem_byte_active[byte_idx].clone()],
                |[active]| active.into(),
                14, // tuple size: addr[4] + value[1] + timestamp[8] + is_write[1]
                |vec_idx| {
                    let mut tuple = Vec::with_capacity(14);
                    // addr + byte_idx (add offset to low byte)
                    tuple.push(mem_addr_c[0].at(vec_idx) + byte_offset);
                    for j in 1..4 { tuple.push(mem_addr_c[j].at(vec_idx)); }
                    // value byte
                    tuple.push(mem_value_c[byte_idx].at(vec_idx));
                    // timestamp
                    for col in &timestamp_c { tuple.push(col.at(vec_idx)); }
                    // is_write = IsStoreDirect + IsStoreImmAny + IsStoreInd
                    tuple.push(is_sd_c.at(vec_idx) + is_sia_c.at(vec_idx) + is_si_c.at(vec_idx));
                    tuple
                },
            );
        }

        // Program execution lookup: consume (ts, pc), produce (ts+1, next_pc)
        let prog_exec: &ProgramExecutionLookupElements = lookup_elements.as_ref();
        let pc = crate::trace::original_base_column!(component_trace, Column::Pc);
        let next_pc_col = crate::trace::original_base_column!(component_trace, Column::NextPc);
        let next_ts = crate::trace::original_base_column!(component_trace, Column::NextTimestamp);
        {
            let mut consume_tuple: Vec<_> = timestamp.to_vec();
            consume_tuple.extend_from_slice(&pc);
            logup.add_to_relation_with(
                prog_exec,
                [is_pad[0].clone()],
                |[pad]| {
                    use stwo::prover::backend::simd::m31::PackedBaseField;
                    (-(PackedBaseField::one() - pad)).into()
                },
                &consume_tuple,
            );
        }
        {
            let mut produce_tuple: Vec<_> = next_ts.to_vec();
            produce_tuple.extend_from_slice(&next_pc_col);
            logup.add_to_relation_with(
                prog_exec,
                [is_pad[0].clone()],
                |[pad]| {
                    use stwo::prover::backend::simd::m31::PackedBaseField;
                    (PackedBaseField::one() - pad).into()
                },
                &produce_tuple,
            );
        }

        // Phase 54e: bitwise-op nibble emissions moved to BitwiseChip.
        // CpuChip still emits Phase 17 sign-bit nibble pinning lookups
        // (and paired range checks) against BitwiseAndLookup further
        // below — keep the binding + the sixteen constant so those
        // sites resolve.
        let bitwise_and: &BitwiseAndLookupElements = lookup_elements.as_ref();
        let sixteen = PackedBaseField::broadcast(BaseField::from(16));

        // Power-of-two lookup: (shift_amount, val_d[8]) when shift is constrained.
        // Phase 35 / 36 split: classic emission keyed on ShiftAmount with
        // multiplicity `is_shift_c · (1 − is_rotate_r64 − is_rotate_r32)`,
        // plus a new emission keyed on ShiftAmountCompl with multiplicity
        // `is_rotate_r64 + is_rotate_r32`.
        let pow2_lookup: &PowerOfTwoLookupElements = lookup_elements.as_ref();
        let shift_amount_col = crate::trace::original_base_column!(component_trace, Column::ShiftAmount);
        let is_shift_constrained = crate::trace::original_base_column!(component_trace, Column::IsShiftConstrained);
        let is_rotate_r64_col_pow2 = crate::trace::original_base_column!(component_trace, Column::IsRotateR64);
        let is_rotate_r32_col_pow2 = crate::trace::original_base_column!(component_trace, Column::IsRotateR32);
        let shift_amount_compl_col = crate::trace::original_base_column!(component_trace, Column::ShiftAmountCompl);
        let val_d_cols = crate::trace::original_base_column!(component_trace, Column::ValD);
        {
            let mut tuple: Vec<_> = vec![shift_amount_col[0].clone()];
            tuple.extend_from_slice(&val_d_cols);
            logup.add_to_relation_with(
                pow2_lookup,
                [is_shift_constrained[0].clone(), is_rotate_r64_col_pow2[0].clone(), is_rotate_r32_col_pow2[0].clone()],
                |[shc, r64, r32]| (shc - r64 - r32).into(),
                &tuple,
            );
        }
        // Phase 35 / 36: separate PowerOfTwo emission for RotR64 / RotR32
        // keyed on ShiftAmountCompl.
        {
            let mut tuple: Vec<_> = vec![shift_amount_compl_col[0].clone()];
            tuple.extend_from_slice(&val_d_cols);
            logup.add_to_relation_with(
                pow2_lookup,
                [is_rotate_r64_col_pow2[0].clone(), is_rotate_r32_col_pow2[0].clone()],
                |[r64, r32]| (r64 + r32).into(),
                &tuple,
            );
        }

        // Phase 33: Popcount lookup — per-byte (val_d[i], BytePopcount[i]) on
        // CountSetBits rows.  Mirror of the verifier-side emission.
        {
            let popcount_lookup: &PopcountLookupElements = lookup_elements.as_ref();
            let is_count_set_bits_col = crate::trace::original_base_column!(component_trace, Column::IsCountSetBits);
            let byte_popcount_col = crate::trace::original_base_column!(component_trace, Column::BytePopcount);
            for i in 0..WORD_SIZE {
                logup.add_to_relation_with(
                    popcount_lookup,
                    [is_count_set_bits_col[0].clone()],
                    |[active]| active.into(),
                    &[val_d_cols[i].clone(), byte_popcount_col[i].clone()],
                );
            }
        }

        // Phase 34: Bitcount lookup — per-byte (val_d[i], BitOpLzByte[i],
        // BitOpTzByte[i]) on LZ/TZ rows.  Multiplicity = is_lzb + is_tzb.
        {
            let bitcount_lookup: &BitcountLookupElements = lookup_elements.as_ref();
            let is_lzb_col = crate::trace::original_base_column!(component_trace, Column::IsLzb);
            let is_tzb_col = crate::trace::original_base_column!(component_trace, Column::IsTzb);
            let lz_col = crate::trace::original_base_column!(component_trace, Column::BitOpLzByte);
            let tz_col = crate::trace::original_base_column!(component_trace, Column::BitOpTzByte);
            for i in 0..WORD_SIZE {
                logup.add_to_relation_with(
                    bitcount_lookup,
                    [is_lzb_col[0].clone(), is_tzb_col[0].clone()],
                    |[lz, tz]| (lz + tz).into(),
                    &[val_d_cols[i].clone(), lz_col[i].clone(), tz_col[i].clone()],
                );
            }
        }

        // ── Register-memory producer emissions (Phase 9d) ──
        // Three potential register accesses per step: ValB read, ValD read,
        // Result write.  Each is gated by its Is* flag and emits a tuple
        // (reg_idx[1], value[8], timestamp[8]) matching RegisterMemoryChip's
        // ledger consumers.  Flags are 0 when the corresponding slot isn't
        // a register access (immediate source, or no register write).
        let reg_lookup: &RegisterMemoryLookupElements = lookup_elements.as_ref();
        let val_b_is_reg = crate::trace::original_base_column!(component_trace, Column::ValBIsReg);
        let val_b_reg_idx = crate::trace::original_base_column!(component_trace, Column::ValBRegIdx);
        let val_d_is_reg = crate::trace::original_base_column!(component_trace, Column::ValDIsReg);
        let val_d_reg_idx = crate::trace::original_base_column!(component_trace, Column::ValDRegIdx);
        let result_is_reg = crate::trace::original_base_column!(component_trace, Column::ResultIsReg);
        let result_reg_idx = crate::trace::original_base_column!(component_trace, Column::ResultRegIdx);
        let result_cols = crate::trace::original_base_column!(component_trace, Column::Result);
        {
            // Phase 9g: use RegValB (raw register value) rather than ValB so
            // 32-bit-truncated ops still emit the authentic register value.
            let reg_val_b_cols = crate::trace::original_base_column!(component_trace, Column::RegValB);
            let mut tuple: Vec<_> = vec![val_b_reg_idx[0].clone()];
            tuple.extend_from_slice(&reg_val_b_cols);
            tuple.extend_from_slice(&timestamp);
            logup.add_to_relation_with(
                reg_lookup,
                [val_b_is_reg[0].clone()],
                |[active]| active.into(),
                &tuple,
            );
        }
        {
            // Phase 9f: use RegValD (raw register value) instead of ValD
            // (which gets rewritten to 2^shift_amount for shift ops).
            let reg_val_d_cols = crate::trace::original_base_column!(component_trace, Column::RegValD);
            let mut tuple: Vec<_> = vec![val_d_reg_idx[0].clone()];
            tuple.extend_from_slice(&reg_val_d_cols);
            tuple.extend_from_slice(&timestamp);
            logup.add_to_relation_with(
                reg_lookup,
                [val_d_is_reg[0].clone()],
                |[active]| active.into(),
                &tuple,
            );
        }
        // Phase 28: RegValA producer (paired emission for parity).
        {
            let reg_val_a_cols = crate::trace::original_base_column!(component_trace, Column::RegValA);
            let reg_a_cols = crate::trace::original_base_column!(component_trace, Column::RegA);
            let is_store_ind_col = crate::trace::original_base_column!(component_trace, Column::IsStoreInd);
            let mut tuple: Vec<_> = vec![reg_a_cols[0].clone()];
            tuple.extend_from_slice(&reg_val_a_cols);
            tuple.extend_from_slice(&timestamp);
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
            tuple.extend_from_slice(&result_cols);
            tuple.extend_from_slice(&timestamp);
            logup.add_to_relation_with(
                reg_lookup,
                [result_is_reg[0].clone()],
                |[active]| active.into(),
                &tuple,
            );
        }

        // ── Phase 9e: blake2b ECALL register reads (φ[7], [10], [11], [12]) ──
        // 4 extra register-memory producers emitted only at blake2b ECALL
        // steps.  Values come from the dedicated Phi7/Phi10/Phi11/Phi12
        // columns; indices are hardcoded constants.
        let is_blake_ecall = crate::trace::original_base_column!(component_trace, Column::IsBlakeEcall);
        let phi7 = crate::trace::original_base_column!(component_trace, Column::Phi7);
        let phi10 = crate::trace::original_base_column!(component_trace, Column::Phi10);
        let phi11 = crate::trace::original_base_column!(component_trace, Column::Phi11);
        let phi12 = crate::trace::original_base_column!(component_trace, Column::Phi12);
        use stwo::prover::backend::simd::m31::PackedBaseField;
        const ECALL_REG_IDXS: [u32; 4] = [7, 10, 11, 12];
        let phi_cols: [_; 4] = [
            phi7.clone(),
            phi10.clone(),
            phi11.clone(),
            phi12.clone(),
        ];
        for (slot, &reg_idx) in ECALL_REG_IDXS.iter().enumerate() {
            let idx_const = PackedBaseField::broadcast(BaseField::from(reg_idx));
            let val_c = phi_cols[slot].clone();
            let ts_c = timestamp.clone();
            logup.add_to_relation_computed(
                reg_lookup,
                [is_blake_ecall[0].clone()],
                |[active]| active.into(),
                17,
                move |v| {
                    let mut t = Vec::with_capacity(17);
                    t.push(idx_const);
                    for c in &val_c { t.push(c.at(v)); }
                    for c in &ts_c { t.push(c.at(v)); }
                    t
                },
            );
        }

        // ── Blake2b call binding (Phase 8c) ──
        // Producer side: at any step where IsBlakeEcall is set, emit
        //   (phi10[0..4], phi11[0..4], phi12[0..8], phi7_bool, timestamp[0..8])
        // Blake2bChip emits the matching consumer at IsFirstOfCompression so
        // the tuple values must agree.
        let blake2b_call: &Blake2bCallLookupElements = lookup_elements.as_ref();
        let phi7_bool = crate::trace::original_base_column!(component_trace, Column::Phi7Bool);
        {
            let mut tuple: Vec<_> = Vec::with_capacity(25);
            tuple.extend_from_slice(&phi10[0..4]);
            tuple.extend_from_slice(&phi11[0..4]);
            tuple.extend_from_slice(&phi12);
            tuple.push(phi7_bool[0].clone());
            tuple.extend_from_slice(&timestamp);
            logup.add_to_relation_with(
                blake2b_call,
                [is_blake_ecall[0].clone()],
                |[active]| active.into(),
                &tuple,
            );
        }

        // ── BitManip SE nibble lookups (Phase 12b-2) ──
        // 4 emissions paired with verifier-side (2a, 2b, 3a, 3b).  Last block
        // before finalize() so they pair within themselves.
        {
            let is_se8 = crate::trace::original_base_column!(component_trace, Column::IsSignExt8);
            let is_se16 = crate::trace::original_base_column!(component_trace, Column::IsSignExt16);
            let se_bit = crate::trace::original_base_column!(component_trace, Column::SignExtBit);
            let se_hi = crate::trace::original_base_column!(component_trace, Column::SignExtSrcHiNib);
            let eight_p = PackedBaseField::broadcast(BaseField::from(8));
            let fifteen_p = PackedBaseField::broadcast(BaseField::from(15));
            let val_d_0 = val_d_cols[0].clone();
            let val_d_1 = val_d_cols[1].clone();

            let hi_2a = se_hi[0].clone();
            let bit_2a = se_bit[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [is_se8[0].clone()],
                |[m]| m.into(),
                3,
                |i| vec![hi_2a.at(i), eight_p, bit_2a.at(i) * eight_p],
            );
            let hi_2b = se_hi[0].clone();
            let bit_2b = se_bit[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [is_se16[0].clone()],
                |[m]| m.into(),
                3,
                |i| vec![hi_2b.at(i), eight_p, bit_2b.at(i) * eight_p],
            );
            let hi_3a = se_hi[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [is_se8[0].clone()],
                |[m]| m.into(),
                3,
                |i| {
                    let lo = val_d_0.at(i) - hi_3a.at(i) * sixteen;
                    vec![lo, fifteen_p, lo]
                },
            );
            let hi_3b = se_hi[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [is_se16[0].clone()],
                |[m]| m.into(),
                3,
                |i| {
                    let lo = val_d_1.at(i) - hi_3b.at(i) * sixteen;
                    vec![lo, fifteen_p, lo]
                },
            );
        }

        // ── Phase 13b/c: ProgramMemory consumer (prover-side, 2 paired, 38 limbs) ──
        {
            let prog_mem: &ProgramMemoryLookupElements = lookup_elements.as_ref();
            let pc = crate::trace::original_base_column!(component_trace, Column::Pc);
            let opcode = crate::trace::original_base_column!(component_trace, Column::Opcode);
            let skip_len = crate::trace::original_base_column!(component_trace, Column::SkipLen);
            let reg_a = crate::trace::original_base_column!(component_trace, Column::RegA);
            let reg_b = crate::trace::original_base_column!(component_trace, Column::RegB);
            let reg_d = crate::trace::original_base_column!(component_trace, Column::RegD);
            let imm_bytes = crate::trace::original_base_column!(component_trace, Column::ImmBytes);
            let f_is_add = crate::trace::original_base_column!(component_trace, Column::IsAdd);
            let f_is_sub = crate::trace::original_base_column!(component_trace, Column::IsSub);
            let f_is_mul = crate::trace::original_base_column!(component_trace, Column::IsMul);
            // Phase 53: IsMulUpper folded into (mu_uu+mu_su+mu_ss).
            // The prog_mem tuple slot is filled via a closure
            // override below since the column no longer exists.
            // Phase 53c: IsBitwise folded; sum below via closure override.
            let f_is_and = crate::trace::original_base_column!(component_trace, Column::IsAnd);
            let f_is_or = crate::trace::original_base_column!(component_trace, Column::IsOr);
            let f_is_xor = crate::trace::original_base_column!(component_trace, Column::IsXor);
            let f_is_and_inv = crate::trace::original_base_column!(component_trace, Column::IsAndInv);
            let f_is_or_inv = crate::trace::original_base_column!(component_trace, Column::IsOrInv);
            let f_is_xnor = crate::trace::original_base_column!(component_trace, Column::IsXnor);
            let f_is_shift = crate::trace::original_base_column!(component_trace, Column::IsShift);
            // Phase 53d: IsCompare folded; closure override below.
            let f_is_move = crate::trace::original_base_column!(component_trace, Column::IsMove);
            let f_is_32bit = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
            // Phase 53e: IsBranch folded; closure override below.
            let f_is_jump = crate::trace::original_base_column!(component_trace, Column::IsJump);
            let f_is_div_rem = crate::trace::original_base_column!(component_trace, Column::IsDivRem);
            let f_is_load = crate::trace::original_base_column!(component_trace, Column::IsLoad);
            // Phase 53f: IsStore folded; closure override below.
            let f_is_exit = crate::trace::original_base_column!(component_trace, Column::IsExit);
            let f_is_neg_add = crate::trace::original_base_column!(component_trace, Column::IsNegAdd);
            let f_is_reverse_bytes = crate::trace::original_base_column!(component_trace, Column::IsReverseBytes);
            let f_is_zero_ext_16 = crate::trace::original_base_column!(component_trace, Column::IsZeroExt16);
            let f_is_sign_ext_8 = crate::trace::original_base_column!(component_trace, Column::IsSignExt8);
            let f_is_sign_ext_16 = crate::trace::original_base_column!(component_trace, Column::IsSignExt16);
            let f_is_trap = crate::trace::original_base_column!(component_trace, Column::IsTrap);
            let f_is_jump_ind = crate::trace::original_base_column!(component_trace, Column::IsJumpInd);
            let f_is_load_imm_jump_ind = crate::trace::original_base_column!(component_trace, Column::IsLoadImmJumpInd);
            let f_is_mul_upper_uu = crate::trace::original_base_column!(component_trace, Column::IsMulUpperUU);
            let f_is_mul_upper_su = crate::trace::original_base_column!(component_trace, Column::IsMulUpperSU);
            let f_is_mul_upper_ss = crate::trace::original_base_column!(component_trace, Column::IsMulUpperSS);
            let f_is_div_s = crate::trace::original_base_column!(component_trace, Column::IsDivS);
            let f_is_load_i8 = crate::trace::original_base_column!(component_trace, Column::IsLoadI8);
            let f_is_load_i16 = crate::trace::original_base_column!(component_trace, Column::IsLoadI16);
            let f_is_load_i32 = crate::trace::original_base_column!(component_trace, Column::IsLoadI32);
            let f_is_mem_size_1 = crate::trace::original_base_column!(component_trace, Column::IsMemSize1);
            let f_is_mem_size_2 = crate::trace::original_base_column!(component_trace, Column::IsMemSize2);
            let f_is_mem_size_4 = crate::trace::original_base_column!(component_trace, Column::IsMemSize4);
            let f_is_mem_size_8 = crate::trace::original_base_column!(component_trace, Column::IsMemSize8);
            let f_is_store_direct = crate::trace::original_base_column!(component_trace, Column::IsStoreDirect);
            let f_is_load_direct = crate::trace::original_base_column!(component_trace, Column::IsLoadDirect);
            let f_is_mem_indirect = crate::trace::original_base_column!(component_trace, Column::IsMemIndirect);
            let f_is_store_imm_any = crate::trace::original_base_column!(component_trace, Column::IsStoreImmAny);
            let f_is_store_imm_direct = crate::trace::original_base_column!(component_trace, Column::IsStoreImmDirect);
            let f_is_store_ind = crate::trace::original_base_column!(component_trace, Column::IsStoreInd);
            let f_is_rotate_l64 = crate::trace::original_base_column!(component_trace, Column::IsRotateL64);
            let f_is_count_set_bits = crate::trace::original_base_column!(component_trace, Column::IsCountSetBits);
            let f_is_lzb = crate::trace::original_base_column!(component_trace, Column::IsLzb);
            let f_is_tzb = crate::trace::original_base_column!(component_trace, Column::IsTzb);
            let f_is_rotate_r64 = crate::trace::original_base_column!(component_trace, Column::IsRotateR64);
            let f_is_rotate_l32 = crate::trace::original_base_column!(component_trace, Column::IsRotateL32);
            let f_is_rotate_r32 = crate::trace::original_base_column!(component_trace, Column::IsRotateR32);
            let f_is_rotate_r_imm_alt = crate::trace::original_base_column!(component_trace, Column::IsRotateRImmAlt);
            let imm_y_for_lookup = crate::trace::original_base_column!(component_trace, Column::ImmYBytes);
            let branch_target_for_lookup = crate::trace::original_base_column!(
                component_trace, Column::BranchTarget
            );
            let is_pad_col = crate::trace::original_base_column!(component_trace, Column::IsPadding);

            let mut tuple: Vec<_> = pc.to_vec();
            tuple.push(opcode[0].clone());
            tuple.push(skip_len[0].clone());
            tuple.push(reg_a[0].clone());
            tuple.push(reg_b[0].clone());
            tuple.push(reg_d[0].clone());
            tuple.extend_from_slice(&imm_bytes);
            tuple.push(f_is_add[0].clone());
            tuple.push(f_is_sub[0].clone());
            tuple.push(f_is_mul[0].clone());
            // Phase 53: placeholder for the folded IsMulUpper slot;
            // overridden in the closure below to (mu_uu+mu_su+mu_ss).
            tuple.push(crate::trace::component::FinalizedColumn::Constant(BaseField::from(0)));
            // Phase 53c: placeholder for the folded IsBitwise slot.
            tuple.push(crate::trace::component::FinalizedColumn::Constant(BaseField::from(0)));
            tuple.push(f_is_shift[0].clone());
            // Phase 53d: placeholder for the folded IsCompare slot.
            tuple.push(crate::trace::component::FinalizedColumn::Constant(BaseField::from(0)));
            tuple.push(f_is_move[0].clone());
            tuple.push(f_is_32bit[0].clone());
            // Phase 53e: placeholder for the folded IsBranch slot.
            tuple.push(crate::trace::component::FinalizedColumn::Constant(BaseField::from(0)));
            tuple.push(f_is_jump[0].clone());
            tuple.push(f_is_div_rem[0].clone());
            tuple.push(f_is_load[0].clone());
            // Phase 53f: placeholder for the folded IsStore slot.
            tuple.push(crate::trace::component::FinalizedColumn::Constant(BaseField::from(0)));
            tuple.push(f_is_exit[0].clone());
            tuple.push(f_is_neg_add[0].clone());
            tuple.push(f_is_reverse_bytes[0].clone());
            tuple.push(f_is_zero_ext_16[0].clone());
            tuple.push(f_is_sign_ext_8[0].clone());
            tuple.push(f_is_sign_ext_16[0].clone());
            tuple.push(f_is_trap[0].clone());
            tuple.push(f_is_jump_ind[0].clone());
            tuple.push(f_is_load_imm_jump_ind[0].clone());
            tuple.push(f_is_mul_upper_uu[0].clone());
            tuple.push(f_is_mul_upper_su[0].clone());
            tuple.push(f_is_mul_upper_ss[0].clone());
            tuple.push(f_is_div_s[0].clone());
            tuple.push(f_is_load_i8[0].clone());
            tuple.push(f_is_load_i16[0].clone());
            tuple.push(f_is_load_i32[0].clone());
            tuple.push(f_is_mem_size_1[0].clone());
            tuple.push(f_is_mem_size_2[0].clone());
            tuple.push(f_is_mem_size_4[0].clone());
            tuple.push(f_is_mem_size_8[0].clone());
            tuple.push(f_is_store_direct[0].clone());
            tuple.push(f_is_load_direct[0].clone());
            tuple.push(f_is_mem_indirect[0].clone());
            tuple.push(f_is_store_imm_any[0].clone());
            tuple.push(f_is_store_imm_direct[0].clone());
            tuple.push(f_is_store_ind[0].clone());
            tuple.push(f_is_rotate_l64[0].clone());
            tuple.push(f_is_count_set_bits[0].clone());
            tuple.push(f_is_lzb[0].clone());
            tuple.push(f_is_tzb[0].clone());
            tuple.push(f_is_rotate_r64[0].clone());
            tuple.push(f_is_rotate_l32[0].clone());
            tuple.push(f_is_rotate_r32[0].clone());
            tuple.push(f_is_rotate_r_imm_alt[0].clone());
            tuple.extend_from_slice(&imm_y_for_lookup);
            tuple.extend_from_slice(&branch_target_for_lookup);

            // Phase 53/53c/53d/53e/53f: folded slot indices in the tuple
            // (pc[4] + opcode + skip_len + 3·reg + imm[8] + is_add
            // + is_sub + is_mul = 20; +1 for is_mul_upper, etc.).
            const IS_MUL_UPPER_SLOT: usize = 20;
            const IS_BITWISE_SLOT: usize = 21;
            const IS_COMPARE_SLOT: usize = 23;
            const IS_BRANCH_SLOT: usize = 26;
            const IS_STORE_SLOT: usize = 30;
            // Two paired emissions, multiplicity = is_real = 1 - is_padding.
            for _ in 0..2 {
                let is_pad = is_pad_col[0].clone();
                let mu_uu_c = f_is_mul_upper_uu[0].clone();
                let mu_su_c = f_is_mul_upper_su[0].clone();
                let mu_ss_c = f_is_mul_upper_ss[0].clone();
                let bw_and_c = f_is_and[0].clone();
                let bw_or_c = f_is_or[0].clone();
                let bw_xor_c = f_is_xor[0].clone();
                let bw_andinv_c = f_is_and_inv[0].clone();
                let bw_orinv_c = f_is_or_inv[0].clone();
                let bw_xnor_c = f_is_xnor[0].clone();
                let cmp_setltu_c = is_setltu_col[0].clone();
                let cmp_setlts_c = is_setlts_col[0].clone();
                let cmp_cmoviz_c = is_cmoviz_col[0].clone();
                let cmp_cmovnz_c = is_cmovnz_col[0].clone();
                let cmp_mins_c = is_mins_col[0].clone();
                let cmp_minu_c = is_minu_col[0].clone();
                let cmp_maxs_c = is_maxs_col[0].clone();
                let cmp_maxu_c = is_maxu_col[0].clone();
                let br_eq_c = is_br_eq_col[0].clone();
                let br_ne_c = is_br_ne_col[0].clone();
                let br_lt_u_c = is_br_lt_u_col[0].clone();
                let br_ge_u_c = is_br_ge_u_col[0].clone();
                let br_le_u_c = is_br_le_u_col[0].clone();
                let br_gt_u_c = is_br_gt_u_col[0].clone();
                let br_lt_s_c = is_br_lt_s_col[0].clone();
                let br_ge_s_c = is_br_ge_s_col[0].clone();
                let br_le_s_c = is_br_le_s_col[0].clone();
                let br_gt_s_c = is_br_gt_s_col[0].clone();
                let st_dir_c = f_is_store_direct[0].clone();
                let st_imm_any_c = f_is_store_imm_any[0].clone();
                let st_ind_c = f_is_store_ind[0].clone();
                logup.add_to_relation_computed(
                    prog_mem,
                    [is_pad],
                    |[p]| {
                        let one_packed = stwo::prover::backend::simd::m31::PackedBaseField::broadcast(BaseField::from(1));
                        (one_packed - p).into()
                    },
                    tuple.len(),
                    {
                        let tuple_clone: Vec<_> = tuple.clone();
                        move |i| {
                            let mut t: Vec<_> = tuple_clone.iter().map(|c| c.at(i)).collect();
                            t[IS_MUL_UPPER_SLOT] = mu_uu_c.at(i) + mu_su_c.at(i) + mu_ss_c.at(i);
                            t[IS_BITWISE_SLOT] = bw_and_c.at(i) + bw_or_c.at(i) + bw_xor_c.at(i)
                                + bw_andinv_c.at(i) + bw_orinv_c.at(i) + bw_xnor_c.at(i);
                            t[IS_COMPARE_SLOT] = cmp_setltu_c.at(i) + cmp_setlts_c.at(i)
                                + cmp_cmoviz_c.at(i) + cmp_cmovnz_c.at(i)
                                + cmp_mins_c.at(i) + cmp_minu_c.at(i)
                                + cmp_maxs_c.at(i) + cmp_maxu_c.at(i);
                            t[IS_BRANCH_SLOT] = br_eq_c.at(i) + br_ne_c.at(i)
                                + br_lt_u_c.at(i) + br_ge_u_c.at(i)
                                + br_le_u_c.at(i) + br_gt_u_c.at(i)
                                + br_lt_s_c.at(i) + br_ge_s_c.at(i)
                                + br_le_s_c.at(i) + br_gt_s_c.at(i);
                            t[IS_STORE_SLOT] = st_dir_c.at(i) + st_imm_any_c.at(i) + st_ind_c.at(i);
                            t
                        }
                    },
                );
            }
        }

        // ── Phase 13d: JumpTable consumer (prover-side, 2 paired, 8 limbs) ──
        {
            let jt: &JumpTableLookupElements = lookup_elements.as_ref();
            let is_jump_ind_col = crate::trace::original_base_column!(component_trace, Column::IsJumpInd);
            let jump_ind_addr = crate::trace::original_base_column!(component_trace, Column::JumpIndAddr);
            let next_pc_col = crate::trace::original_base_column!(component_trace, Column::NextPc);

            let mut tuple: Vec<_> = jump_ind_addr.to_vec();
            tuple.extend_from_slice(&next_pc_col);

            for _ in 0..2 {
                logup.add_to_relation_with(
                    jt,
                    [is_jump_ind_col[0].clone()],
                    |[m]| m.into(),
                    &tuple,
                );
            }
        }

        // ── Phase 13d-loadimmjumpind: JumpTable consumer for LoadImmJumpInd ──
        {
            let jt: &JumpTableLookupElements = lookup_elements.as_ref();
            let is_lij_col = crate::trace::original_base_column!(component_trace, Column::IsLoadImmJumpInd);
            let lij_addr = crate::trace::original_base_column!(component_trace, Column::LoadImmJumpIndAddr);
            let next_pc_col = crate::trace::original_base_column!(component_trace, Column::NextPc);

            let mut tuple: Vec<_> = lij_addr.to_vec();
            tuple.extend_from_slice(&next_pc_col);

            for _ in 0..2 {
                logup.add_to_relation_with(
                    jt,
                    [is_lij_col[0].clone()],
                    |[m]| m.into(),
                    &tuple,
                );
            }
        }

        // ── Phase 17: sign-bit nibble lookups (8 emissions) ──
        // Mirrors the verifier-side block placed just before
        // finalize_logup_in_pairs.  Same tuple shape, same multiplicity
        // (is_real per row), same emission order.
        {
            let is_pad_col = crate::trace::original_base_column!(component_trace, Column::IsPadding);
            let sign_src_b = crate::trace::original_base_column!(component_trace, Column::SignSrcB);
            let sign_src_d = crate::trace::original_base_column!(component_trace, Column::SignSrcD);
            let sign_src_q = crate::trace::original_base_column!(component_trace, Column::SignSrcQ);
            let sign_src_r = crate::trace::original_base_column!(component_trace, Column::SignSrcR);
            let sign_b_hi = crate::trace::original_base_column!(component_trace, Column::SignBHiNib);
            let sign_d_hi = crate::trace::original_base_column!(component_trace, Column::SignDHiNib);
            let sign_q_hi = crate::trace::original_base_column!(component_trace, Column::SignQHiNib);
            let sign_r_hi = crate::trace::original_base_column!(component_trace, Column::SignRHiNib);
            let sign_bit_b = crate::trace::original_base_column!(component_trace, Column::SignBitB);
            let sign_bit_d = crate::trace::original_base_column!(component_trace, Column::SignBitD);
            let sign_bit_q = crate::trace::original_base_column!(component_trace, Column::SignBitQ);
            let sign_bit_r = crate::trace::original_base_column!(component_trace, Column::SignBitR);

            let one_p = PackedBaseField::broadcast(BaseField::from(1));
            let eight_p = PackedBaseField::broadcast(BaseField::from(8));
            let fifteen_p = PackedBaseField::broadcast(BaseField::from(15));
            let sixteen_p = PackedBaseField::broadcast(BaseField::from(16));

            // Emit (hi, 8, 8·bit) and (src - 16·hi, 0xF, same) for each
            // sign bit, in the same order as the verifier-side block:
            // B → D → Q → R, hi-pin first then lo-range each.
            let hi_b = sign_b_hi[0].clone();
            let bit_b = sign_bit_b[0].clone();
            let pad_b1 = is_pad_col[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [pad_b1],
                |[p]| (one_p - p).into(),
                3,
                |i| vec![hi_b.at(i), eight_p, bit_b.at(i) * eight_p],
            );
            let src_b = sign_src_b[0].clone();
            let hi_b2 = sign_b_hi[0].clone();
            let pad_b2 = is_pad_col[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [pad_b2],
                |[p]| (one_p - p).into(),
                3,
                |i| {
                    let lo = src_b.at(i) - hi_b2.at(i) * sixteen_p;
                    vec![lo, fifteen_p, lo]
                },
            );

            let hi_d = sign_d_hi[0].clone();
            let bit_d = sign_bit_d[0].clone();
            let pad_d1 = is_pad_col[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [pad_d1],
                |[p]| (one_p - p).into(),
                3,
                |i| vec![hi_d.at(i), eight_p, bit_d.at(i) * eight_p],
            );
            let src_d = sign_src_d[0].clone();
            let hi_d2 = sign_d_hi[0].clone();
            let pad_d2 = is_pad_col[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [pad_d2],
                |[p]| (one_p - p).into(),
                3,
                |i| {
                    let lo = src_d.at(i) - hi_d2.at(i) * sixteen_p;
                    vec![lo, fifteen_p, lo]
                },
            );

            let hi_q = sign_q_hi[0].clone();
            let bit_q = sign_bit_q[0].clone();
            let pad_q1 = is_pad_col[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [pad_q1],
                |[p]| (one_p - p).into(),
                3,
                |i| vec![hi_q.at(i), eight_p, bit_q.at(i) * eight_p],
            );
            let src_q = sign_src_q[0].clone();
            let hi_q2 = sign_q_hi[0].clone();
            let pad_q2 = is_pad_col[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [pad_q2],
                |[p]| (one_p - p).into(),
                3,
                |i| {
                    let lo = src_q.at(i) - hi_q2.at(i) * sixteen_p;
                    vec![lo, fifteen_p, lo]
                },
            );

            let hi_r = sign_r_hi[0].clone();
            let bit_r = sign_bit_r[0].clone();
            let pad_r1 = is_pad_col[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [pad_r1],
                |[p]| (one_p - p).into(),
                3,
                |i| vec![hi_r.at(i), eight_p, bit_r.at(i) * eight_p],
            );
            let src_r = sign_src_r[0].clone();
            let hi_r2 = sign_r_hi[0].clone();
            let pad_r2 = is_pad_col[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [pad_r2],
                |[p]| (one_p - p).into(),
                3,
                |i| {
                    let lo = src_r.at(i) - hi_r2.at(i) * sixteen_p;
                    vec![lo, fifteen_p, lo]
                },
            );

            // Phase 19: SignBitResult — pin to bit 7 of result[3].
            let result_cols = crate::trace::original_base_column!(component_trace, Column::Result);
            let sign_bit_result_col = crate::trace::original_base_column!(component_trace, Column::SignBitResult);
            let result_hi_col = crate::trace::original_base_column!(component_trace, Column::ResultHiNib);
            let hi_res = result_hi_col[0].clone();
            let bit_res = sign_bit_result_col[0].clone();
            let pad_res1 = is_pad_col[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [pad_res1],
                |[p]| (one_p - p).into(),
                3,
                |i| vec![hi_res.at(i), eight_p, bit_res.at(i) * eight_p],
            );
            let src_res = result_cols[3].clone();
            let hi_res2 = result_hi_col[0].clone();
            let pad_res2 = is_pad_col[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [pad_res2],
                |[p]| (one_p - p).into(),
                3,
                |i| {
                    let lo = src_res.at(i) - hi_res2.at(i) * sixteen_p;
                    vec![lo, fifteen_p, lo]
                },
            );

            // Phase 20: LoadSignBit — pin to bit 7 of LoadSignSrc.
            let load_sign_src = crate::trace::original_base_column!(component_trace, Column::LoadSignSrc);
            let load_sign_bit_col = crate::trace::original_base_column!(component_trace, Column::LoadSignBit);
            let load_sign_hi_col = crate::trace::original_base_column!(component_trace, Column::LoadSignHiNib);
            let hi_load = load_sign_hi_col[0].clone();
            let bit_load = load_sign_bit_col[0].clone();
            let pad_load1 = is_pad_col[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [pad_load1],
                |[p]| (one_p - p).into(),
                3,
                |i| vec![hi_load.at(i), eight_p, bit_load.at(i) * eight_p],
            );
            let src_load = load_sign_src[0].clone();
            let hi_load2 = load_sign_hi_col[0].clone();
            let pad_load2 = is_pad_col[0].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [pad_load2],
                |[p]| (one_p - p).into(),
                3,
                |i| {
                    let lo = src_load.at(i) - hi_load2.at(i) * sixteen_p;
                    vec![lo, fifteen_p, lo]
                },
            );

        }

        // Phase 21: range-check DivCmpDiff bytes via Range256.
        {
            let range256_p21: &Range256LookupElements = lookup_elements.as_ref();
            let is_pad_col_p21 = crate::trace::original_base_column!(component_trace, Column::IsPadding);
            let div_cmp_diff_cols = crate::trace::original_base_column!(component_trace, Column::DivCmpDiff);
            for col in &div_cmp_diff_cols {
                logup.add_to_relation_with(
                    range256_p21,
                    [is_pad_col_p21[0].clone()],
                    |[pad]| {
                        use stwo::prover::backend::simd::m31::PackedBaseField;
                        (PackedBaseField::one() - pad).into()
                    },
                    &[col.clone()],
                );
            }
        }

        // Phase 30: range-check AbsCmpDiff bytes via Range256.
        {
            let range256_p30: &Range256LookupElements = lookup_elements.as_ref();
            let is_pad_col_p30 = crate::trace::original_base_column!(component_trace, Column::IsPadding);
            let abs_cmp_diff_cols = crate::trace::original_base_column!(component_trace, Column::AbsCmpDiff);
            for col in &abs_cmp_diff_cols {
                logup.add_to_relation_with(
                    range256_p30,
                    [is_pad_col_p30[0].clone()],
                    |[pad]| {
                        use stwo::prover::backend::simd::m31::PackedBaseField;
                        (PackedBaseField::one() - pad).into()
                    },
                    &[col.clone()],
                );
            }
        }

        // ── Phase 54a/b/c/d: MultiplicationLookup producer (prover-side mirror) ──
        // Tuple (35 limbs): val_b[8] + val_d[8] + result[8] +
        //   sign_bit_b + sign_bit_d + 4 rotate flags + 5 mul flags.
        {
            let mul_p54: &MultiplicationLookupElements = lookup_elements.as_ref();
            let f_is_mul_p54 = crate::trace::original_base_column!(component_trace, Column::IsMul);
            let f_mu_uu_p54 = crate::trace::original_base_column!(component_trace, Column::IsMulUpperUU);
            let f_mu_su_p54 = crate::trace::original_base_column!(component_trace, Column::IsMulUpperSU);
            let f_mu_ss_p54 = crate::trace::original_base_column!(component_trace, Column::IsMulUpperSS);
            let f_is_32bit_p54 = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
            let f_rot_l64_p54 = crate::trace::original_base_column!(component_trace, Column::IsRotateL64);
            let f_rot_r64_p54 = crate::trace::original_base_column!(component_trace, Column::IsRotateR64);
            let f_rot_l32_p54 = crate::trace::original_base_column!(component_trace, Column::IsRotateL32);
            let f_rot_r32_p54 = crate::trace::original_base_column!(component_trace, Column::IsRotateR32);
            let val_b_p54 = crate::trace::original_base_column!(component_trace, Column::ValB);
            let val_d_p54 = crate::trace::original_base_column!(component_trace, Column::ValD);
            let result_p54 = crate::trace::original_base_column!(component_trace, Column::Result);
            let sign_bit_b_p54 = crate::trace::original_base_column!(component_trace, Column::SignBitB);
            let sign_bit_d_p54 = crate::trace::original_base_column!(component_trace, Column::SignBitD);

            // Slot 30 (= 3*8 + 6) is IsMulLo; override via the closure.
            const IS_MUL_LO_SLOT: usize = 30;
            let mut tuple_p54: Vec<_> = Vec::with_capacity(35);
            tuple_p54.extend_from_slice(&val_b_p54);
            tuple_p54.extend_from_slice(&val_d_p54);
            tuple_p54.extend_from_slice(&result_p54);
            tuple_p54.push(sign_bit_b_p54[0].clone());
            tuple_p54.push(sign_bit_d_p54[0].clone());
            tuple_p54.push(f_rot_l64_p54[0].clone());
            tuple_p54.push(f_rot_r64_p54[0].clone());
            tuple_p54.push(f_rot_l32_p54[0].clone());
            tuple_p54.push(f_rot_r32_p54[0].clone());
            tuple_p54.push(crate::trace::component::FinalizedColumn::Constant(BaseField::from(0)));
            tuple_p54.push(f_mu_uu_p54[0].clone());
            tuple_p54.push(f_mu_su_p54[0].clone());
            tuple_p54.push(f_mu_ss_p54[0].clone());
            tuple_p54.push(f_is_32bit_p54[0].clone());

            for _ in 0..2 {
                let is_mul_c = f_is_mul_p54[0].clone();
                let mu_uu_c = f_mu_uu_p54[0].clone();
                let mu_su_c = f_mu_su_p54[0].clone();
                let mu_ss_c = f_mu_ss_p54[0].clone();
                logup.add_to_relation_computed(
                    mul_p54,
                    [f_is_mul_p54[0].clone()],
                    |[m]| m.into(),
                    35,
                    {
                        let tuple_clone: Vec<_> = tuple_p54.clone();
                        move |i| {
                            let mut t: Vec<_> = tuple_clone.iter().map(|c| c.at(i)).collect();
                            t[IS_MUL_LO_SLOT] = is_mul_c.at(i)
                                - mu_uu_c.at(i)
                                - mu_su_c.at(i)
                                - mu_ss_c.at(i);
                            t
                        }
                    },
                );
            }
        }

        // ── Phase 54g: DivRemLookup producer (prover-side mirror) ──
        {
            let divrem_p54g: &DivRemLookupElements = lookup_elements.as_ref();
            let val_b_p54g = crate::trace::original_base_column!(component_trace, Column::ValB);
            let val_d_p54g = crate::trace::original_base_column!(component_trace, Column::ValD);
            let dq_p54g = crate::trace::original_base_column!(component_trace, Column::DivQuotient);
            let dr_p54g = crate::trace::original_base_column!(component_trace, Column::DivRemainder);
            let dch_p54g = crate::trace::original_base_column!(component_trace, Column::DivCorrHi);
            let dbz_p54g = crate::trace::original_base_column!(component_trace, Column::DivByZero);
            let is_dr_p54g = crate::trace::original_base_column!(component_trace, Column::IsDivRem);
            let is_32_p54g = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
            let mut tuple_p54g: Vec<_> = val_b_p54g.to_vec();
            tuple_p54g.extend_from_slice(&val_d_p54g);
            tuple_p54g.extend_from_slice(&dq_p54g);
            tuple_p54g.extend_from_slice(&dr_p54g);
            tuple_p54g.extend_from_slice(&dch_p54g);
            tuple_p54g.push(is_dr_p54g[0].clone());
            tuple_p54g.push(dbz_p54g[0].clone());
            tuple_p54g.push(is_32_p54g[0].clone());
            for _ in 0..2 {
                logup.add_to_relation_with(
                    divrem_p54g,
                    [is_dr_p54g[0].clone()],
                    |[m]| m.into(),
                    &tuple_p54g,
                );
            }
        }

        // ── Phase 54f: CompareLookup producer (prover-side mirror) ──
        // Tuple (17 limbs): val_b[8] + val_d[8] + cmp_lt_flag.
        // Multiplicity = is_compare + is_branch (= sum of 18 sub-flags).
        {
            let compare_p54f: &CompareLookupElements = lookup_elements.as_ref();
            let val_b_p54f = crate::trace::original_base_column!(component_trace, Column::ValB);
            let val_d_p54f = crate::trace::original_base_column!(component_trace, Column::ValD);
            let cmp_lt_p54f = crate::trace::original_base_column!(component_trace, Column::CmpLtFlag);
            let is_setltu = crate::trace::original_base_column!(component_trace, Column::IsSetLtU);
            let is_setlts = crate::trace::original_base_column!(component_trace, Column::IsSetLtS);
            let is_cmoviz = crate::trace::original_base_column!(component_trace, Column::IsCmovIz);
            let is_cmovnz = crate::trace::original_base_column!(component_trace, Column::IsCmovNz);
            let is_mins = crate::trace::original_base_column!(component_trace, Column::IsMinS);
            let is_minu = crate::trace::original_base_column!(component_trace, Column::IsMinU);
            let is_maxs = crate::trace::original_base_column!(component_trace, Column::IsMaxS);
            let is_maxu = crate::trace::original_base_column!(component_trace, Column::IsMaxU);
            let is_br_eq = crate::trace::original_base_column!(component_trace, Column::IsBrEq);
            let is_br_ne = crate::trace::original_base_column!(component_trace, Column::IsBrNe);
            let is_br_lt_u = crate::trace::original_base_column!(component_trace, Column::IsBrLtU);
            let is_br_ge_u = crate::trace::original_base_column!(component_trace, Column::IsBrGeU);
            let is_br_le_u = crate::trace::original_base_column!(component_trace, Column::IsBrLeU);
            let is_br_gt_u = crate::trace::original_base_column!(component_trace, Column::IsBrGtU);
            let is_br_lt_s = crate::trace::original_base_column!(component_trace, Column::IsBrLtS);
            let is_br_ge_s = crate::trace::original_base_column!(component_trace, Column::IsBrGeS);
            let is_br_le_s = crate::trace::original_base_column!(component_trace, Column::IsBrLeS);
            let is_br_gt_s = crate::trace::original_base_column!(component_trace, Column::IsBrGtS);
            let mut tuple_p54f: Vec<_> = val_b_p54f.to_vec();
            tuple_p54f.extend_from_slice(&val_d_p54f);
            tuple_p54f.push(cmp_lt_p54f[0].clone());
            for _ in 0..2 {
                logup.add_to_relation_with(
                    compare_p54f,
                    [
                        is_setltu[0].clone(), is_setlts[0].clone(),
                        is_cmoviz[0].clone(), is_cmovnz[0].clone(),
                        is_mins[0].clone(), is_minu[0].clone(),
                        is_maxs[0].clone(), is_maxu[0].clone(),
                        is_br_eq[0].clone(), is_br_ne[0].clone(),
                        is_br_lt_u[0].clone(), is_br_ge_u[0].clone(),
                        is_br_le_u[0].clone(), is_br_gt_u[0].clone(),
                        is_br_lt_s[0].clone(), is_br_ge_s[0].clone(),
                        is_br_le_s[0].clone(), is_br_gt_s[0].clone(),
                    ],
                    |[a, b, c, d, e, f, g, h, br_eq, br_ne, br_lt_u, br_ge_u, br_le_u, br_gt_u, br_lt_s, br_ge_s, br_le_s, br_gt_s]|
                        (a + b + c + d + e + f + g + h
                            + br_eq + br_ne + br_lt_u + br_ge_u + br_le_u + br_gt_u
                            + br_lt_s + br_ge_s + br_le_s + br_gt_s).into(),
                    &tuple_p54f,
                );
            }
        }

        // ── Phase 54e: BitwiseLookup producer (prover-side mirror) ──
        // Tuple (30 limbs): val_b[8] + val_d[8] + result[8] + 6 sub-flags.
        {
            let bitwise_p54e: &BitwiseLookupElements = lookup_elements.as_ref();
            let val_b_p54e = crate::trace::original_base_column!(component_trace, Column::ValB);
            let val_d_p54e = crate::trace::original_base_column!(component_trace, Column::ValD);
            let result_p54e = crate::trace::original_base_column!(component_trace, Column::Result);
            let f_and = crate::trace::original_base_column!(component_trace, Column::IsAnd);
            let f_or = crate::trace::original_base_column!(component_trace, Column::IsOr);
            let f_xor = crate::trace::original_base_column!(component_trace, Column::IsXor);
            let f_andinv = crate::trace::original_base_column!(component_trace, Column::IsAndInv);
            let f_orinv = crate::trace::original_base_column!(component_trace, Column::IsOrInv);
            let f_xnor = crate::trace::original_base_column!(component_trace, Column::IsXnor);
            let mut tuple_p54e: Vec<_> = val_b_p54e.to_vec();
            tuple_p54e.extend_from_slice(&val_d_p54e);
            tuple_p54e.extend_from_slice(&result_p54e);
            tuple_p54e.push(f_and[0].clone());
            tuple_p54e.push(f_or[0].clone());
            tuple_p54e.push(f_xor[0].clone());
            tuple_p54e.push(f_andinv[0].clone());
            tuple_p54e.push(f_orinv[0].clone());
            tuple_p54e.push(f_xnor[0].clone());
            for _ in 0..2 {
                logup.add_to_relation_with(
                    bitwise_p54e,
                    [
                        f_and[0].clone(), f_or[0].clone(), f_xor[0].clone(),
                        f_andinv[0].clone(), f_orinv[0].clone(), f_xnor[0].clone(),
                    ],
                    |[a, b, c, d, e, f]| (a + b + c + d + e + f).into(),
                    &tuple_p54e,
                );
            }
        }

        logup.finalize()
    }
