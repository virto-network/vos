#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{
        fields::qm31::SecureField,
        ColumnVec,
    },
    prover::{
        backend::simd::SimdBackend,
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::core::step::WORD_SIZE;
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::FinalizedTrace,
    component::ComponentTrace,
};

use crate::{
    framework::{BuiltInComponent},
    lookups::{BitcountLookupElements, BitwiseAndLookupElements, BitwiseLookupElements, Blake2bCallLookupElements, ByteToBitsLookupElements, CompareLookupElements, DivRemLookupElements, JumpTableLookupElements, MemoryAccessLookupElements, MultiplicationLookupElements, PopcountLookupElements, PowerOfTwoLookupElements, ProgramExecutionLookupElements, ProgramMemoryLookupElements, Range256LookupElements, RegisterMemoryLookupElements, },
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::AllLookupElements;
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub(crate) mod classify;
mod columns;
mod reg_access;
// Phase 47 split: trace fill + interaction-trace generation moved into
// their own files.  add_constraints (the AIR) stays in mod.rs.
#[cfg(feature = "prover")]
mod trace_fill;
#[cfg(feature = "prover")]
mod interaction;

use columns::{Column, PreprocessedColumn};
pub(crate) use reg_access::step_reg_accesses;
pub(crate) use classify::classify_opcode_for_program_memory;

pub struct CpuChip;

// ── Trace generation ───────────────────────────────────────────────────────

impl BuiltInComponent for CpuChip {
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 2; // max degree 4 (flag * flag * flag * linear)

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        Range256LookupElements,
        MemoryAccessLookupElements,
        ProgramExecutionLookupElements,
        BitwiseAndLookupElements,
        PowerOfTwoLookupElements,
        Blake2bCallLookupElements,
        RegisterMemoryLookupElements,
        ProgramMemoryLookupElements,
        (JumpTableLookupElements, PopcountLookupElements, BitcountLookupElements, MultiplicationLookupElements, BitwiseLookupElements, CompareLookupElements, DivRemLookupElements, ByteToBitsLookupElements),
    );


    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            Range256LookupElements,
            MemoryAccessLookupElements,
            ProgramExecutionLookupElements,
            BitwiseAndLookupElements,
            PowerOfTwoLookupElements,
            Blake2bCallLookupElements,
            RegisterMemoryLookupElements,
            ProgramMemoryLookupElements,
            (JumpTableLookupElements, PopcountLookupElements, BitcountLookupElements, MultiplicationLookupElements, BitwiseLookupElements, CompareLookupElements, DivRemLookupElements, ByteToBitsLookupElements),
        ),
    ) {
        let (range256_lookup, mem_lookup, prog_exec_lookup, bitwise_and_lookup, pow2_lookup, blake2b_call_lookup, reg_lookup, prog_mem_lookup, (jump_table_lookup, popcount_lookup, bitcount_lookup, mul_lookup, bitwise_lookup, compare_lookup, divrem_lookup, byte_to_bits_lookup)) = lookup_elements;
        // bitwise_and_lookup is no longer emitted by CpuChip (Phase 54e
        // moved nibble emissions to BitwiseChip).
        let _ = bitwise_and_lookup;
        let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
        let is_real = E::F::one() - is_pad[0].clone();

        let is_add = crate::trace::trace_eval!(trace_eval, Column::IsAdd);
        let is_sub = crate::trace::trace_eval!(trace_eval, Column::IsSub);
        let is_mul = crate::trace::trace_eval!(trace_eval, Column::IsMul);
        // Phase 53c: IsBitwise folded — sum expression below.
        let is_shift = crate::trace::trace_eval!(trace_eval, Column::IsShift);
        // Phase 53d: IsCompare folded — sum-expression closure used
        // at every reader site below.  Sub-flag readers are defined
        // further down at function scope.

        let is_move = crate::trace::trace_eval!(trace_eval, Column::IsMove);
        let is_neg_add = crate::trace::trace_eval!(trace_eval, Column::IsNegAdd);
        let is_32bit = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
        let is_64bit = E::F::one() - is_32bit[0].clone();
        let is_and_flag = crate::trace::trace_eval!(trace_eval, Column::IsAnd);
        let is_or_flag = crate::trace::trace_eval!(trace_eval, Column::IsOr);
        let is_xor_flag = crate::trace::trace_eval!(trace_eval, Column::IsXor);
        let is_and_inv_flag = crate::trace::trace_eval!(trace_eval, Column::IsAndInv);
        let is_or_inv_flag = crate::trace::trace_eval!(trace_eval, Column::IsOrInv);
        let is_xnor_flag = crate::trace::trace_eval!(trace_eval, Column::IsXnor);

        let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
        let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
        let result = crate::trace::trace_eval!(trace_eval, Column::Result);
        // Phase 19: high bytes of `result` on 32-bit ALU rows now equal
        // 0xFF · SignBitResult (sign-extension), matching the
        // interpreter's `q as i64 as u64`.  SignBitResult is pinned by
        // a nibble-AND lookup at the end of add_constraints to bit 7
        // of result[3].
        let sign_bit_result_p19 = crate::trace::trace_eval!(trace_eval, Column::SignBitResult);
        let f_ff_p19: E::F = E::F::from(BaseField::from(255));
        let carry = crate::trace::trace_eval!(trace_eval, Column::Carry);
        // Phase 54b: MulCarry/MulCarryHi moved to MulChip.
        // Phase 54d: MulHigh moved to MulChip.
        // Phase 54e: AndResult moved to BitwiseChip.
        // Phase 54f: CmpCarry moved to CompareChip.
        let cmp_lt_flag = crate::trace::trace_eval!(trace_eval, Column::CmpLtFlag);
        let cmp_lt_s_flag = crate::trace::trace_eval!(trace_eval, Column::CmpLtSFlag);
        // Phase 53e: IsBranch folded — sum of the 10 IsBr* sub-flags.
        // The sub-flag bindings used to live in the branch-constraint
        // block (~line 1641); pull them up here so `is_branch_e()` is
        // in scope at every reader site.
        let is_br_eq = crate::trace::trace_eval!(trace_eval, Column::IsBrEq);
        let is_br_ne = crate::trace::trace_eval!(trace_eval, Column::IsBrNe);
        let is_br_lt_u = crate::trace::trace_eval!(trace_eval, Column::IsBrLtU);
        let is_br_ge_u = crate::trace::trace_eval!(trace_eval, Column::IsBrGeU);
        let is_br_le_u = crate::trace::trace_eval!(trace_eval, Column::IsBrLeU);
        let is_br_gt_u = crate::trace::trace_eval!(trace_eval, Column::IsBrGtU);
        let is_br_lt_s = crate::trace::trace_eval!(trace_eval, Column::IsBrLtS);
        let is_br_ge_s = crate::trace::trace_eval!(trace_eval, Column::IsBrGeS);
        let is_br_le_s = crate::trace::trace_eval!(trace_eval, Column::IsBrLeS);
        let is_br_gt_s = crate::trace::trace_eval!(trace_eval, Column::IsBrGtS);
        let is_branch_e = || -> E::F {
            is_br_eq[0].clone() + is_br_ne[0].clone()
                + is_br_lt_u[0].clone() + is_br_ge_u[0].clone()
                + is_br_le_u[0].clone() + is_br_gt_u[0].clone()
                + is_br_lt_s[0].clone() + is_br_ge_s[0].clone()
                + is_br_le_s[0].clone() + is_br_gt_s[0].clone()
        };
        // Phase 53f: IsStore folded — sum of the 3 store-class sub-flags.
        let is_store_direct_e = crate::trace::trace_eval!(trace_eval, Column::IsStoreDirect);
        let is_store_imm_any_e = crate::trace::trace_eval!(trace_eval, Column::IsStoreImmAny);
        let is_store_ind_e = crate::trace::trace_eval!(trace_eval, Column::IsStoreInd);
        let is_store_e = || -> E::F {
            is_store_direct_e[0].clone()
                + is_store_imm_any_e[0].clone()
                + is_store_ind_e[0].clone()
        };
        let is_set_lt_u_flag = crate::trace::trace_eval!(trace_eval, Column::IsSetLtU);
        let is_set_lt_s_flag = crate::trace::trace_eval!(trace_eval, Column::IsSetLtS);
        let is_cmov_iz_flag = crate::trace::trace_eval!(trace_eval, Column::IsCmovIz);
        let is_cmov_nz_flag = crate::trace::trace_eval!(trace_eval, Column::IsCmovNz);
        // Phase 53d: drop the underscores — these now feed the
        // IsCompare sum expression (was: declared but unused).
        let is_min_s_flag = crate::trace::trace_eval!(trace_eval, Column::IsMinS);
        let is_min_u_flag = crate::trace::trace_eval!(trace_eval, Column::IsMinU);
        let is_max_s_flag = crate::trace::trace_eval!(trace_eval, Column::IsMaxS);
        let is_max_u_flag = crate::trace::trace_eval!(trace_eval, Column::IsMaxU);
        // Phase 53d: IsCompare = sum of the 8 compare sub-flags above.
        let is_compare_e = || -> E::F {
            is_set_lt_u_flag[0].clone() + is_set_lt_s_flag[0].clone()
                + is_cmov_iz_flag[0].clone() + is_cmov_nz_flag[0].clone()
                + is_min_s_flag[0].clone() + is_min_u_flag[0].clone()
                + is_max_s_flag[0].clone() + is_max_u_flag[0].clone()
        };

        let f256 = E::F::from(BaseField::from(256u32));
        let f255 = E::F::from(BaseField::from(255u32));

        // ════════════════════════════════════════════════════════════════════
        // ADD: result[i] + carry[i]*256 = val_b[i] + val_d[i] + carry[i-1]
        // ════════════════════════════════════════════════════════════════════
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 { E::F::zero() } else { carry[i - 1].clone() };
            let c = result[i].clone() + carry[i].clone() * f256.clone()
                - val_b[i].clone() - val_d[i].clone() - carry_in;
            if i < 4 {
                eval.add_constraint(is_add[0].clone() * c);
            } else {
                eval.add_constraint(is_add[0].clone() * is_64bit.clone() * c);
            }
        }
        // Phase 19: `result[4..8] = 0xFF · SignBitResult` on 32-bit
        // Add rows (was: `= 0`).  Matches the interpreter's
        // `sign_extend_32` of the low-32 sum.
        for i in 4..WORD_SIZE {
            eval.add_constraint(
                is_add[0].clone() * is_32bit[0].clone()
                    * (result[i].clone() - f_ff_p19.clone() * sign_bit_result_p19[0].clone())
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // SUB: two's complement addition a + ~b + 1
        // ════════════════════════════════════════════════════════════════════
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 { E::F::one() } else { carry[i - 1].clone() };
            let c_normal = result[i].clone() + carry[i].clone() * f256.clone()
                - val_b[i].clone() - f255.clone() + val_d[i].clone() - carry_in.clone();
            let c_neg = result[i].clone() + carry[i].clone() * f256.clone()
                - val_d[i].clone() - f255.clone() + val_b[i].clone() - carry_in;
            if i < 4 {
                eval.add_constraint(is_sub[0].clone() * (E::F::one() - is_neg_add[0].clone()) * c_normal);
                eval.add_constraint(is_sub[0].clone() * is_neg_add[0].clone() * c_neg);
            } else {
                eval.add_constraint(is_sub[0].clone() * is_64bit.clone() * (E::F::one() - is_neg_add[0].clone()) * c_normal);
                eval.add_constraint(is_sub[0].clone() * is_64bit.clone() * is_neg_add[0].clone() * c_neg);
            }
        }
        for i in 4..WORD_SIZE {
            eval.add_constraint(
                is_sub[0].clone() * is_32bit[0].clone()
                    * (result[i].clone() - f_ff_p19.clone() * sign_bit_result_p19[0].clone())
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // MUL: schoolbook carry chain — Phase 54b: moved to MulChip.
        // CpuChip still witnesses UnsignedProductLow/Hi/MulHigh (used by
        // result-variant binding below); their values are pinned by
        // lookup balance to MulChip's carry-chain-pinned witnesses.
        // ════════════════════════════════════════════════════════════════════
        let mu_uu_p53 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperUU);
        let mu_su_p53 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSU);
        let mu_ss_p53 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSS);
        let is_mul_upper_e = || -> E::F {
            mu_uu_p53[0].clone() + mu_su_p53[0].clone() + mu_ss_p53[0].clone()
        };
        let is_mul_low = E::F::one() - is_mul_upper_e();
        // Phase 54c/d: UnsignedProductLow + UnsignedProductHi + MulHigh
        // moved to MulChip; result-variant binding (Phase 32/36) now
        // lives there.  CpuChip keeps the 32-bit sign-extension on
        // result high bytes since it reads only result + sign_bit_result
        // (both still on CpuChip).
        // 32-bit mul: upper result limbs (i ∈ 4..8) = 0xFF · SignBitResult
        // (Phase 19 sign-extension).
        for i in 4..WORD_SIZE {
            eval.add_constraint(
                is_mul[0].clone() * is_32bit[0].clone()
                    * (result[i].clone() - f_ff_p19.clone() * sign_bit_result_p19[0].clone())
            );
        }
        // Suppress unused-warning for is_mul_low / is_64bit until later
        // mul-related sites need them.
        let _ = (is_mul_low, &is_64bit);

        {
            // Phase 40: pin val_b ↔ ImmBytes on RotR64ImmAlt /
            // RotR32ImmAlt rows.  These swap the operand convention
            // (immediate is the rotated value, register is the shift
            // amount), so val_b is no longer a register read — the
            // standard val_b ↔ reg_val_b cross-constraint is
            // inactive (val_b_is_reg=0).  Without this constraint
            // val_b would be effectively unbound.
            //
            // Shape mirrors the val_b cross-constraint:
            //   - low 4 bytes: val_b[i] = ImmBytes[i] always.
            //   - high 4 bytes: match ImmBytes when not truncated;
            //     zero when truncated (32-bit ImmAlt has IsTruncated
            //     = is_32bit · is_mul = 1, which masks val_b high
            //     bytes to 0 in trace fill, while ImmBytes carries
            //     the sign-extended bytes from step.imm.to_le_bytes()).
            let f_is_rotate_r_imm_alt_p40 = crate::trace::trace_eval!(trace_eval, Column::IsRotateRImmAlt);
            let imm_bytes_p40 = crate::trace::trace_eval!(trace_eval, Column::ImmBytes);
            let is_truncated_p40 = crate::trace::trace_eval!(trace_eval, Column::IsTruncated);
            for i in 0..4 {
                eval.add_constraint(
                    f_is_rotate_r_imm_alt_p40[0].clone()
                        * (val_b[i].clone() - imm_bytes_p40[i].clone())
                );
            }
            for i in 4..WORD_SIZE {
                eval.add_constraint(
                    f_is_rotate_r_imm_alt_p40[0].clone()
                        * (E::F::one() - is_truncated_p40[0].clone())
                        * (val_b[i].clone() - imm_bytes_p40[i].clone())
                );
                eval.add_constraint(
                    f_is_rotate_r_imm_alt_p40[0].clone()
                        * is_truncated_p40[0].clone()
                        * val_b[i].clone()
                );
            }

            // Phase 36 / 37: pin val_d high 4 bytes = 0 on ALL 32-bit
            // shift-constrained rows.  Combined with the PowerOfTwo
            // lookup (table covers shifts [0, 63]), this forces
            // ShiftAmount / ShiftAmountCompl ∈ [0, 31] uniquely —
            // necessary for soundness because the mod-32 shift
            // identity admits two valid byte-bounded shift amounts
            // otherwise (e.g., reg_val_d = 32 → ShiftAmount = 0 with
            // ShiftQuotient = 1, or ShiftAmount = 32 with
            // ShiftQuotient = 0; the first gives val_d = 1, the
            // second val_d = 2^32, and the schoolbook produces
            // different results between the two).
            //
            // Phase 36 originally scoped this to RotL32/RotR32 only,
            // leaving the same gap open for ShloL32/ShloR32/SharR32
            // (and their Imm/ImmAlt variants).  Phase 37 widens the
            // gate to `is_32bit · is_shift_c` so all 32-bit
            // shift-constrained rows are covered.
            let is_shift_c_p37 = crate::trace::trace_eval!(trace_eval, Column::IsShiftConstrained);
            let is_32_shift_c = is_32bit[0].clone() * is_shift_c_p37[0].clone();
            for i in 4..WORD_SIZE {
                eval.add_constraint(
                    is_32_shift_c.clone() * val_d[i].clone()
                );
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 54c: Phase 12c MulUpper SS/SU sign-correction moved to
        // MulChip.  CpuChip's mu_uu/mu_su/mu_ss flags + sign_bit_b/d
        // values are sent through the MultiplicationLookup tuple so
        // MulChip's relocated constraint binds against them.  CpuChip's
        // result on `is_mul_upper` rows is consumed by MulChip's sign-
        // correction chain (which proves it equals unsigned_product_hi
        // − sa·val_d − sb·val_b mod 2^64).
        // ════════════════════════════════════════════════════════════════════

        // ════════════════════════════════════════════════════════════════════
        // Phase 54e: BITWISE result-binding moved to BitwiseChip.
        // CpuChip's `result` on bitwise rows is bound via the
        // BitwiseLookup tuple (val_b, val_d, result + 6 sub-flags) to
        // BitwiseChip's `result`, which is pinned by BitwiseChip's
        // per-op identity + the 16 nibble-AND lookups.
        // ════════════════════════════════════════════════════════════════════

        // ════════════════════════════════════════════════════════════════════
        // COMPARE: SetLtU via subtraction carry analysis
        // cmp_carry chain: val_b + ~val_d + 1 (same as sub)
        // cmp_lt_flag = 1 - cmp_carry[7] (unsigned: a < b iff no final carry)
        // For SetLtU (compare_op=0): result = cmp_lt_flag (zero-extended to 64-bit)
        // For SetLtS (compare_op=1): needs sign bit analysis (prover-trusted for now)
        // For CmovIz/Nz, Min/Max: prover-trusted (constrained result via execution semantics)
        // ════════════════════════════════════════════════════════════════════
        let is_cmp_or_branch = is_compare_e() + is_branch_e();
        // Phase 54f: cmp_carry chain + cmp_lt_flag derivation moved to
        // CompareChip.  CpuChip's cmp_lt_flag is bound via the
        // CompareLookup tuple to CompareChip's pinned value.
        // Constrain cmp_lt_s_flag via sign-bit analysis (also for branches)
        {
            let sign_b_b = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
            let sign_b_d = crate::trace::trace_eval!(trace_eval, Column::SignBitD);
            let signs_differ = sign_b_b[0].clone() + sign_b_d[0].clone()
                - E::F::from(BaseField::from(2u32)) * sign_b_b[0].clone() * sign_b_d[0].clone();
            let expected_s = signs_differ.clone() * sign_b_b[0].clone()
                + (E::F::one() - signs_differ) * cmp_lt_flag[0].clone();
            eval.add_constraint(
                is_cmp_or_branch.clone() * (cmp_lt_s_flag[0].clone() - expected_s)
            );
        }
        // Compare sub-ops use per-op flag columns (degree-2 to degree-4 constraints)
        {
            let val_d_is_zero = crate::trace::trace_eval!(trace_eval, Column::ValDIsZero);

            // Constrain val_d_is_zero: if flag=1, all val_d limbs must be 0
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_compare_e() * val_d_is_zero[0].clone() * val_d[i].clone()
                );
            }

            // SetLtU: result = cmp_lt_flag (zero-extended)
            eval.add_constraint(
                is_set_lt_u_flag[0].clone() * (result[0].clone() - cmp_lt_flag[0].clone())
            );
            for i in 1..WORD_SIZE {
                eval.add_constraint(is_set_lt_u_flag[0].clone() * result[i].clone());
            }

            // SetLtS: result = cmp_lt_s_flag (zero-extended)
            {
                let cmp_lt_s_flag = crate::trace::trace_eval!(trace_eval, Column::CmpLtSFlag);
                let sign_b = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
                let sign_d = crate::trace::trace_eval!(trace_eval, Column::SignBitD);

                let signs_differ = sign_b[0].clone() + sign_d[0].clone()
                    - E::F::from(BaseField::from(2u32)) * sign_b[0].clone() * sign_d[0].clone();
                let expected_s = signs_differ.clone() * sign_b[0].clone()
                    + (E::F::one() - signs_differ) * cmp_lt_flag[0].clone();
                eval.add_constraint(
                    is_set_lt_s_flag[0].clone() * (cmp_lt_s_flag[0].clone() - expected_s)
                );

                eval.add_constraint(
                    is_set_lt_s_flag[0].clone() * (result[0].clone() - cmp_lt_s_flag[0].clone())
                );
                for i in 1..WORD_SIZE {
                    eval.add_constraint(is_set_lt_s_flag[0].clone() * result[i].clone());
                }
            }

            // CmovIz: if val_d==0, result=val_b
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_cmov_iz_flag[0].clone()
                    * val_d_is_zero[0].clone() * (result[i].clone() - val_b[i].clone())
                );
            }

            // CmovNz: if val_d!=0, result=val_b
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_cmov_nz_flag[0].clone()
                    * (E::F::one() - val_d_is_zero[0].clone()) * (result[i].clone() - val_b[i].clone())
                );
            }

            // MinU: result = (val_b < val_d) ? val_b : val_d
            for i in 0..WORD_SIZE {
                let expected = cmp_lt_flag[0].clone() * val_b[i].clone()
                    + (E::F::one() - cmp_lt_flag[0].clone()) * val_d[i].clone();
                eval.add_constraint(is_min_u_flag[0].clone() * (result[i].clone() - expected));
            }

            // MaxU: result = (val_b < val_d) ? val_d : val_b
            for i in 0..WORD_SIZE {
                let expected = cmp_lt_flag[0].clone() * val_d[i].clone()
                    + (E::F::one() - cmp_lt_flag[0].clone()) * val_b[i].clone();
                eval.add_constraint(is_max_u_flag[0].clone() * (result[i].clone() - expected));
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // SHIFT: prover-computed result checked via inverse relationship
        // For ShloL (shift_op=0): result = (val_b << shift_amount) mod 2^64
        //   Equivalently: result = val_b * 2^shift_amount mod 2^64
        //   We can't constrain multiplication by a power of 2 easily without
        //   a power-of-2 lookup table. Shifts remain prover-trusted for now.
        //   The result bytes are range-checked which prevents arbitrary values
        //   but doesn't prove the shift relationship.
        // ════════════════════════════════════════════════════════════════════
        let _ = is_shift;

        // ════════════════════════════════════════════════════════════════════
        // DIVREM: quotient * divisor + remainder = dividend
        // dividend = val_b, divisor = val_d
        // For div (op 0,1): result = quotient. For rem (op 2,3): result = remainder.
        // When divisor == 0 (div_by_zero=1): constraint bypassed (special result).
        // ════════════════════════════════════════════════════════════════════
        let is_div_rem = crate::trace::trace_eval!(trace_eval, Column::IsDivRem);
        let div_rem_op = crate::trace::trace_eval!(trace_eval, Column::DivRemOp);
        let div_quotient = crate::trace::trace_eval!(trace_eval, Column::DivQuotient);
        let div_remainder = crate::trace::trace_eval!(trace_eval, Column::DivRemainder);
        // Phase 54g: DivMulCarry + DivMulCarryHi moved to DivRemChip.
        let div_by_zero = crate::trace::trace_eval!(trace_eval, Column::DivByZero);
        let is_div_s = crate::trace::trace_eval!(trace_eval, Column::IsDivS);
        let div_corr_hi = crate::trace::trace_eval!(trace_eval, Column::DivCorrHi);

        // Gate: only constrain when is_div_rem=1 and div_by_zero=0
        let div_active = is_div_rem[0].clone() * (E::F::one() - div_by_zero[0].clone());

        // Phase 54g: divrem schoolbook (q·d + r = b) carry chain moved
        // to DivRemChip.  CpuChip's q/r/div_corr_hi/val_b/val_d/
        // is_div_rem/div_by_zero/is_32bit values flow through the
        // DivRemLookup tuple; DivRemChip's AIR pins q·d + r ≡ b mod 2^64
        // (low byte) and ≡ div_corr_hi mod 2^64 (high byte).  CpuChip
        // keeps the DivS sign-correction chain (it consumes div_corr_hi
        // and div_corr_carry directly).

        // DivCorrHi must be 0 on non-DivS rows (so the 64-bit schoolbook's
        // high-byte `expected` collapses back to 0 for DivU).  Holds
        // unconditionally — even on padding / non-divrem rows DivCorrHi is
        // filled to 0 so the constraint is trivially satisfied.
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                (E::F::one() - is_div_s[0].clone()) * div_corr_hi[i].clone()
            );
        }

        // Phase 16: DivS sign-correction carry chain.
        //
        //   high(q_u·d_u + r_u) ≡ sq·d_u + sd·q_u + sr − sa  (mod 2^64)
        //
        // where sa = SignBitB (dividend), sd = SignBitD (divisor),
        //       sq = SignBitQ (quotient), sr = SignBitR (remainder).
        //
        // Encoded byte-wise as a non-negative addition (sr/sa are scalar
        // sign bits contributing only at byte 0):
        //
        //   div_corr_hi[i] + div_corr_carry[i]·256 + (i==0 ? sa : 0)
        //     = sq·val_d[i] + sd·div_quotient[i] + carry_in + (i==0 ? sr : 0)
        //
        // Carry-out at byte 7 is the 64-bit overflow, discarded.
        // Gated on is_div_s · (1 − div_by_zero) · is_64bit; on DivU rows
        // the constraint is dormant and DivCorrHi=0 is enforced separately.
        // 32-bit DivS still hits the original "expected high = 0" via the
        // 32-bit schoolbook below — negative DivS32 / RemS32 remains
        // unbound and is left for a follow-up.
        {
            let div_corr_carry = crate::trace::trace_eval!(trace_eval, Column::DivCorrCarry);
            let sign_bit_q = crate::trace::trace_eval!(trace_eval, Column::SignBitQ);
            let sign_bit_r = crate::trace::trace_eval!(trace_eval, Column::SignBitR);
            // Reuse SignBitB / SignBitD already declared elsewhere in
            // add_constraints (also referenced by Phase 12c MulUpper).
            let sign_bit_b_div = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
            let sign_bit_d_div = crate::trace::trace_eval!(trace_eval, Column::SignBitD);
            let div_s_active = is_div_s[0].clone()
                * (E::F::one() - div_by_zero[0].clone())
                * is_64bit.clone();
            for i in 0..WORD_SIZE {
                let carry_in = if i == 0 {
                    E::F::zero()
                } else {
                    div_corr_carry[i - 1].clone()
                };
                let extra_lhs = if i == 0 { sign_bit_b_div[0].clone() } else { E::F::zero() };
                let extra_rhs = if i == 0 { sign_bit_r[0].clone() } else { E::F::zero() };
                eval.add_constraint(
                    div_s_active.clone() * (
                        div_corr_hi[i].clone()
                            + div_corr_carry[i].clone() * f256.clone()
                            + extra_lhs
                            - sign_bit_q[0].clone() * val_d[i].clone()
                            - sign_bit_d_div[0].clone() * div_quotient[i].clone()
                            - carry_in
                            - extra_rhs
                    )
                );
            }
        }

        // Phase 18: DivS sign-correction carry chain (32-bit version).
        //
        //   high_32(q_u·d_u + r_u) ≡ sq·d_u + sd·q_u + sr − sa  (mod 2^32)
        //
        // Same shape as the 64-bit chain but over 4 bytes.  Note that
        // the 32-bit signs sa/sd/sq/sr come from val_b[3] / val_d[3] /
        // div_quotient[3] / div_remainder[3] respectively — Phase 17
        // already pinned SignBitB/D via the Is32Bit multiplex; Phase 18
        // adds the matching multiplex for SignBitQ/R via SignSrcQ /
        // SignSrcR (so on 32-bit DivS rows SignBitQ correctly tracks
        // bit 7 of div_quotient[3], not the always-zero byte 7).
        // Gated on is_div_s · ¬div_by_zero · is_32bit; DivCorrHi[0..4]
        // and DivCorrCarry[0..4] are the active range here.
        {
            let div_corr_carry = crate::trace::trace_eval!(trace_eval, Column::DivCorrCarry);
            let sign_bit_q = crate::trace::trace_eval!(trace_eval, Column::SignBitQ);
            let sign_bit_r = crate::trace::trace_eval!(trace_eval, Column::SignBitR);
            let sign_bit_b_div = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
            let sign_bit_d_div = crate::trace::trace_eval!(trace_eval, Column::SignBitD);
            let div_s32_active = is_div_s[0].clone()
                * (E::F::one() - div_by_zero[0].clone())
                * is_32bit[0].clone();
            for i in 0..4 {
                let carry_in = if i == 0 {
                    E::F::zero()
                } else {
                    div_corr_carry[i - 1].clone()
                };
                let extra_lhs = if i == 0 { sign_bit_b_div[0].clone() } else { E::F::zero() };
                let extra_rhs = if i == 0 { sign_bit_r[0].clone() } else { E::F::zero() };
                eval.add_constraint(
                    div_s32_active.clone() * (
                        div_corr_hi[i].clone()
                            + div_corr_carry[i].clone() * f256.clone()
                            + extra_lhs
                            - sign_bit_q[0].clone() * val_d[i].clone()
                            - sign_bit_d_div[0].clone() * div_quotient[i].clone()
                            - carry_in
                            - extra_rhs
                    )
                );
            }
        }

        // Phase 54g: 32-bit divrem schoolbook moved to DivRemChip.

        // For div ops (op 0,1): result = quotient
        // div_rem_op ∈ {0,1} for div. Gate: op*(op-1) = 0 when op=0 or op=1.
        // Use: (op-2)*(op-3) is nonzero for op=0,1 and zero for op=2,3.
        let drop2 = div_rem_op[0].clone() - E::F::from(BaseField::from(2u32));
        let drop3 = div_rem_op[0].clone() - E::F::from(BaseField::from(3u32));
        let gate_div = drop2.clone() * drop3.clone(); // nonzero when op=0 or op=1
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                div_active.clone() * gate_div.clone() * (result[i].clone() - div_quotient[i].clone())
            );
        }

        // For rem ops (op 2,3): result = remainder
        let gate_rem = div_rem_op[0].clone() * (div_rem_op[0].clone() - E::F::one());  // nonzero when op=2 or op=3
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                div_active.clone() * gate_rem.clone() * (result[i].clone() - div_remainder[i].clone())
            );
        }

        // 32-bit: upper result limbs = 0
        for i in 4..WORD_SIZE {
            eval.add_constraint(
                is_div_rem[0].clone() * is_32bit[0].clone()
                    * (result[i].clone() - f_ff_p19.clone() * sign_bit_result_p19[0].clone())
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 21: DivU quotient-uniqueness (r < d)
        //
        // Without this, the schoolbook `q·d + r = b` alone is satisfied
        // by (q, r), (q−1, r+d), (q−2, r+2d), …  A malicious prover
        // could write `q' = q − 1`, `r' = r + d` and the AIR would
        // accept — the wrong quotient ends up in the destination
        // register.  Adding `r < d` (equivalently `val_d > div_remainder`)
        // forces the unique Euclidean pair.
        //
        // Encoded as the carry chain for `val_d − 1 − div_remainder`
        // (= `val_d + ~div_remainder` with carry_in[0] = 0).  The top
        // carry is 1 iff `val_d > div_remainder`.  Range-check on
        // DivCmpDiff bytes (via BitwiseAnd `(diff, 0xFF, diff)`) is
        // emitted alongside the Phase 17/19/20 sign-bit nibble lookup
        // block.  DivCmpCarry boolean-constrained on every real row.
        //
        // Gate: `is_div_rem · ¬div_by_zero · ¬is_div_s`.  DivS r<d
        // uniqueness needs |r| < |d| with sign analysis; deferred.
        {
            let div_cmp_diff = crate::trace::trace_eval!(trace_eval, Column::DivCmpDiff);
            let div_cmp_carry = crate::trace::trace_eval!(trace_eval, Column::DivCmpCarry);
            // Boolean carry on every real row (so the range is forced
            // even on non-divrem rows where DivCmpCarry is unused).
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_real.clone() * div_cmp_carry[i].clone()
                        * (E::F::one() - div_cmp_carry[i].clone())
                );
            }
            // Carry chain (gated on divrem-no-divzero-no-divs).
            let div_u_active = is_div_rem[0].clone()
                * (E::F::one() - div_by_zero[0].clone())
                * (E::F::one() - is_div_s[0].clone());
            let f_255_p21: E::F = E::F::from(BaseField::from(255));
            for i in 0..WORD_SIZE {
                let carry_in = if i == 0 {
                    E::F::zero()
                } else {
                    div_cmp_carry[i - 1].clone()
                };
                eval.add_constraint(
                    div_u_active.clone() * (
                        div_cmp_diff[i].clone()
                            + div_cmp_carry[i].clone() * f256.clone()
                            - val_d[i].clone()
                            - f_255_p21.clone()
                            + div_remainder[i].clone()
                            - carry_in
                    )
                );
            }
            // Top carry must be 1 (val_d > div_remainder, i.e. r < d).
            eval.add_constraint(
                div_u_active * (E::F::one() - div_cmp_carry[WORD_SIZE - 1].clone())
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 29: byte-wise val_d zero-check + DivByZero result binding
        //
        // Closes two related soundness gaps with shared infrastructure:
        //   (a) ValDIsZero ⇔ (val_d == 0) — both directions pinned, so
        //       CmovIz / CmovNz fire as the interpreter does.  Pre-phase
        //       only the `=1 ⇒ val_d=0` direction was constrained
        //       (gated on is_compare).
        //   (b) DivByZero result binding: on `is_div_rem · div_by_zero`
        //       rows the schoolbook is bypassed; we now also bind
        //       result = u64::MAX (div ops) or result = val_b (rem ops),
        //       matching the interpreter's div-by-zero convention.
        //
        // Mechanism — byte-wise inversion witness + cumulative OR:
        //   ByteIndicator[i] = val_d[i] · ByteInv[i]    (degree 2)
        //   constrained by   val_d[i] · (ByteIndicator[i] − 1) = 0
        //   which forces ByteIndicator[i] = 1 when val_d[i] ≠ 0
        //   (because ByteInv[i] must equal 1/val_d[i]) and accepts
        //   any ByteIndicator value when val_d[i] = 0 — but the
        //   prover only gains by setting it to 0 there (the OR doesn't
        //   short-circuit otherwise).  PartialNZ accumulates OR:
        //     PartialNZ[0]   = ByteIndicator[0]
        //     PartialNZ[i]   = PartialNZ[i-1] + ByteIndicator[i]
        //                      − PartialNZ[i-1] · ByteIndicator[i]
        //   PartialNZ[7] = 1 ↔ any byte non-zero ↔ val_d ≠ 0.
        //   ValDIsZero = 1 − PartialNZ[7].
        {
            let val_d_byte_inv = crate::trace::trace_eval!(trace_eval, Column::ValDByteInv);
            let val_d_partial_nz = crate::trace::trace_eval!(trace_eval, Column::ValDPartialNZ);
            let val_d_is_zero_p29 = crate::trace::trace_eval!(trace_eval, Column::ValDIsZero);
            let div_by_zero_p29 = crate::trace::trace_eval!(trace_eval, Column::DivByZero);

            // Per-byte indicator constraint.  Forces the prover to
            // set ByteInv[i] = 1/val_d[i] whenever val_d[i] ≠ 0
            // (else `val_d[i] · ByteInv[i]` would be != 1, making
            // `val_d[i] · (val_d[i]·ByteInv[i] − 1) ≠ 0`).
            // For val_d[i] = 0 the constraint is trivially satisfied;
            // the prover can pick any ByteInv[i].
            for i in 0..WORD_SIZE {
                let byte_indicator = val_d[i].clone() * val_d_byte_inv[i].clone();
                eval.add_constraint(
                    is_real.clone() * val_d[i].clone()
                        * (byte_indicator - E::F::one())
                );
            }

            // PartialNZ recurrence.  Each PartialNZ[i] is a column; the
            // constraint pins it to the OR of (PartialNZ[i-1],
            // ByteIndicator[i]).  Degree 3 (column · column · column).
            // PartialNZ[0] = ByteIndicator[0].
            eval.add_constraint(
                is_real.clone()
                    * (val_d_partial_nz[0].clone()
                        - val_d[0].clone() * val_d_byte_inv[0].clone())
            );
            for i in 1..WORD_SIZE {
                let byte_indicator = val_d[i].clone() * val_d_byte_inv[i].clone();
                let or_expr = val_d_partial_nz[i - 1].clone()
                    + byte_indicator.clone()
                    - val_d_partial_nz[i - 1].clone() * byte_indicator;
                eval.add_constraint(
                    is_real.clone() * (val_d_partial_nz[i].clone() - or_expr)
                );
            }

            // ValDIsZero = 1 − PartialNZ[7].
            eval.add_constraint(
                is_real.clone()
                    * (val_d_is_zero_p29[0].clone()
                        + val_d_partial_nz[WORD_SIZE - 1].clone()
                        - E::F::one())
            );

            // DivByZero = is_div_rem · ValDIsZero.  On non-divrem rows
            // DivByZero must be 0; on divrem rows it must equal
            // ValDIsZero (which now correctly tracks val_d==0).
            eval.add_constraint(
                is_real.clone()
                    * (div_by_zero_p29[0].clone()
                        - is_div_rem[0].clone() * val_d_is_zero_p29[0].clone())
            );

            // DivByZero result binding.  On `is_div_rem · div_by_zero`
            // rows the schoolbook is bypassed (div_active = 0); the
            // interpreter writes u64::MAX for div and the dividend
            // for rem.  Reuse the existing `gate_div` (op ∈ {0,1})
            // and `gate_rem` (op ∈ {2,3}) expressions from the
            // schoolbook block above.
            let f_ff_p29: E::F = E::F::from(BaseField::from(255));
            let drop2 = div_rem_op[0].clone() - E::F::from(BaseField::from(2u32));
            let drop3 = div_rem_op[0].clone() - E::F::from(BaseField::from(3u32));
            let gate_div_p29 = drop2.clone() * drop3;
            let gate_rem_p29 = div_rem_op[0].clone() * (div_rem_op[0].clone() - E::F::one());
            let dbz_active = is_div_rem[0].clone() * div_by_zero_p29[0].clone();
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    dbz_active.clone() * gate_div_p29.clone()
                        * (result[i].clone() - f_ff_p29.clone())
                );
                eval.add_constraint(
                    dbz_active.clone() * gate_rem_p29.clone()
                        * (result[i].clone() - val_b[i].clone())
                );
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 30: DivS |r| < |d| uniqueness
        //
        // Phase 21 closed `r < d` for DivU; signed div needs the
        // analogous `|r| < |d|` (the magnitude half of PVM's signed
        // Euclidean uniqueness).  Mechanism: two's-complement
        // conditional negation chains compute |val_d| and
        // |div_remainder| into AbsD / AbsR (active when SignBit = 1),
        // then a Phase-21-style `(AbsD − 1 − AbsR) ≥ 0` chain pins
        // `|val_d| > |div_remainder|`.
        //
        // Conditional negation per value X (one of val_d, div_remainder):
        //   SignBitX = 0: Abs[i] = X[i],  AbsCarry[i] = 0.
        //   SignBitX = 1: Abs[i] + AbsCarry[i]·256 = (255 − X[i]) + carry_in
        //                 with carry_in[0] = 1, carry_in[i>0] = AbsCarry[i-1].
        //
        // Out of scope (deferred): `sign(r) = sign(b)` (or r = 0) — the
        // other half of signed Euclidean uniqueness.  Without it a
        // prover could swap (q, r) for (q − 1, r + d) when sign(r)
        // and sign(d) differ AND |r + d| < |d|; closing it requires a
        // byte-wise zero-check on div_remainder analogous to Phase
        // 29's val_d zero-check.
        {
            let sign_bit_d_p30 = crate::trace::trace_eval!(trace_eval, Column::SignBitD);
            let sign_bit_r_p30 = crate::trace::trace_eval!(trace_eval, Column::SignBitR);
            let abs_d = crate::trace::trace_eval!(trace_eval, Column::AbsD);
            let abs_d_carry = crate::trace::trace_eval!(trace_eval, Column::AbsDCarry);
            let abs_r = crate::trace::trace_eval!(trace_eval, Column::AbsR);
            let abs_r_carry = crate::trace::trace_eval!(trace_eval, Column::AbsRCarry);
            let abs_cmp_diff = crate::trace::trace_eval!(trace_eval, Column::AbsCmpDiff);
            let abs_cmp_carry = crate::trace::trace_eval!(trace_eval, Column::AbsCmpCarry);

            // Booleans (gated is_real so range is forced even on
            // non-DivS rows where the chains are dormant).
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_real.clone() * abs_d_carry[i].clone()
                        * (E::F::one() - abs_d_carry[i].clone())
                );
                eval.add_constraint(
                    is_real.clone() * abs_r_carry[i].clone()
                        * (E::F::one() - abs_r_carry[i].clone())
                );
                eval.add_constraint(
                    is_real.clone() * abs_cmp_carry[i].clone()
                        * (E::F::one() - abs_cmp_carry[i].clone())
                );
            }

            // Conditional negation for AbsD.
            //   Positive (SignBitD = 0): AbsD = val_d, AbsDCarry = 0.
            //   Negative (SignBitD = 1):
            //     AbsD[i] + AbsDCarry[i]·256 = (255 − val_d[i]) + carry_in
            //     with carry_in[0] = 1.
            let f_255_p30: E::F = E::F::from(BaseField::from(255));
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_real.clone()
                        * (E::F::one() - sign_bit_d_p30[0].clone())
                        * (abs_d[i].clone() - val_d[i].clone())
                );
                eval.add_constraint(
                    is_real.clone()
                        * (E::F::one() - sign_bit_d_p30[0].clone())
                        * abs_d_carry[i].clone()
                );
                let neg_carry_in = if i == 0 {
                    E::F::one()
                } else {
                    abs_d_carry[i - 1].clone()
                };
                eval.add_constraint(
                    is_real.clone()
                        * sign_bit_d_p30[0].clone()
                        * (
                            abs_d[i].clone()
                                + abs_d_carry[i].clone() * f256.clone()
                                - f_255_p30.clone()
                                + val_d[i].clone()
                                - neg_carry_in
                        )
                );
            }

            // Same shape for AbsR.
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_real.clone()
                        * (E::F::one() - sign_bit_r_p30[0].clone())
                        * (abs_r[i].clone() - div_remainder[i].clone())
                );
                eval.add_constraint(
                    is_real.clone()
                        * (E::F::one() - sign_bit_r_p30[0].clone())
                        * abs_r_carry[i].clone()
                );
                let neg_carry_in = if i == 0 {
                    E::F::one()
                } else {
                    abs_r_carry[i - 1].clone()
                };
                eval.add_constraint(
                    is_real.clone()
                        * sign_bit_r_p30[0].clone()
                        * (
                            abs_r[i].clone()
                                + abs_r_carry[i].clone() * f256.clone()
                                - f_255_p30.clone()
                                + div_remainder[i].clone()
                                - neg_carry_in
                        )
                );
            }

            // Comparison chain: AbsD > AbsR  iff  (AbsD − 1 − AbsR) ≥ 0.
            // Encoded as `AbsD + ~AbsR` (carry_in[0] = 0); top carry = 1
            // on |val_d| > |div_remainder| rows.  Mirrors Phase 21.
            for i in 0..WORD_SIZE {
                let carry_in = if i == 0 {
                    E::F::zero()
                } else {
                    abs_cmp_carry[i - 1].clone()
                };
                eval.add_constraint(
                    is_real.clone() * (
                        abs_cmp_diff[i].clone()
                            + abs_cmp_carry[i].clone() * f256.clone()
                            - abs_d[i].clone()
                            - f_255_p30.clone()
                            + abs_r[i].clone()
                            - carry_in
                    )
                );
            }

            // Top carry forced to 1 on `is_div_s · ¬div_by_zero` rows.
            let div_s_active_p30 = is_div_s[0].clone()
                * (E::F::one() - div_by_zero[0].clone());
            eval.add_constraint(
                div_s_active_p30
                    * (E::F::one() - abs_cmp_carry[WORD_SIZE - 1].clone())
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 31: DivS sign-of-r uniqueness (`sign(r) = sign(b)` when r ≠ 0)
        //
        // Mirrors Phase 29's byte-wise zero-check pattern but on
        // `div_remainder`.  PartialNZ accumulates OR of byte-
        // indicators; PartialNZ[7] = 1 ↔ div_remainder ≠ 0.
        //
        // Final constraint:
        //   is_div_s · ¬div_by_zero · ValRPartialNZ[7] ·
        //                                  (SignBitR − SignBitB) = 0
        // forces SignBitR = SignBitB whenever the remainder is non-
        // zero, matching PVM's round-toward-zero convention where
        // sign(r) = sign(b).  Combined with Phase 30's |r| < |d|,
        // DivS uniqueness is now complete: there's exactly one (q, r)
        // pair satisfying both bounds + the schoolbook + Phase 16
        // sign-correction.
        {
            let val_r_byte_inv = crate::trace::trace_eval!(trace_eval, Column::ValRByteInv);
            let val_r_partial_nz = crate::trace::trace_eval!(trace_eval, Column::ValRPartialNZ);
            let sign_bit_b_p31 = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
            let sign_bit_r_p31 = crate::trace::trace_eval!(trace_eval, Column::SignBitR);

            // Per-byte indicator constraint.  `div_remainder[i]·
            // ByteInv[i]` must equal 1 whenever div_remainder[i] ≠ 0;
            // when div_remainder[i] = 0 the constraint is trivially
            // satisfied.
            for i in 0..WORD_SIZE {
                let byte_indicator = div_remainder[i].clone() * val_r_byte_inv[i].clone();
                eval.add_constraint(
                    is_real.clone() * div_remainder[i].clone()
                        * (byte_indicator - E::F::one())
                );
            }

            // PartialNZ recurrence (degree 3).
            eval.add_constraint(
                is_real.clone()
                    * (val_r_partial_nz[0].clone()
                        - div_remainder[0].clone() * val_r_byte_inv[0].clone())
            );
            for i in 1..WORD_SIZE {
                let byte_indicator = div_remainder[i].clone() * val_r_byte_inv[i].clone();
                let or_expr = val_r_partial_nz[i - 1].clone()
                    + byte_indicator.clone()
                    - val_r_partial_nz[i - 1].clone() * byte_indicator;
                eval.add_constraint(
                    is_real.clone() * (val_r_partial_nz[i].clone() - or_expr)
                );
            }

            // Sign-of-r constraint.  Degree 4 (is_div_s · ¬div_by_zero
            // · PartialNZ[7] · (SignBitR − SignBitB) — four degree-1
            // factors, well within CpuChip's plain-constraint bound).
            let div_s_active_p31 = is_div_s[0].clone()
                * (E::F::one() - div_by_zero[0].clone());
            eval.add_constraint(
                div_s_active_p31
                    * val_r_partial_nz[WORD_SIZE - 1].clone()
                    * (sign_bit_r_p31[0].clone() - sign_bit_b_p31[0].clone())
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // MOVE: result = val_d
        // ════════════════════════════════════════════════════════════════════
        for i in 0..WORD_SIZE {
            eval.add_constraint(is_move[0].clone() * (result[i].clone() - val_d[i].clone()));
        }

        // ════════════════════════════════════════════════════════════════════
        // BITMANIP — REVERSE_BYTES: result[i] = val_d[7-i]
        // ════════════════════════════════════════════════════════════════════
        let is_reverse_bytes = crate::trace::trace_eval!(trace_eval, Column::IsReverseBytes);
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                is_reverse_bytes[0].clone()
                    * (result[i].clone() - val_d[WORD_SIZE - 1 - i].clone())
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // BITMANIP — ZERO_EXTEND_16: result[0..2] = val_d[0..2]; result[2..8] = 0
        // ════════════════════════════════════════════════════════════════════
        let is_zero_ext_16 = crate::trace::trace_eval!(trace_eval, Column::IsZeroExt16);
        eval.add_constraint(
            is_zero_ext_16[0].clone() * (result[0].clone() - val_d[0].clone())
        );
        eval.add_constraint(
            is_zero_ext_16[0].clone() * (result[1].clone() - val_d[1].clone())
        );
        for i in 2..WORD_SIZE {
            eval.add_constraint(is_zero_ext_16[0].clone() * result[i].clone());
        }

        // ════════════════════════════════════════════════════════════════════
        // BITMANIP — SIGN_EXTEND_8 / SIGN_EXTEND_16  (ground constraints only;
        // the sign-bit-pinning AND lookups live just before finalize_logup
        // — see "Sign-extend nibble lookups" near end of add_constraints).
        // ════════════════════════════════════════════════════════════════════
        let is_sign_ext_8 = crate::trace::trace_eval!(trace_eval, Column::IsSignExt8);
        let is_sign_ext_16 = crate::trace::trace_eval!(trace_eval, Column::IsSignExt16);
        let sign_ext_bit = crate::trace::trace_eval!(trace_eval, Column::SignExtBit);
        let _sign_ext_hi_nib_unused = crate::trace::trace_eval!(trace_eval, Column::SignExtSrcHiNib);
        let is_sign_ext = is_sign_ext_8[0].clone() + is_sign_ext_16[0].clone();
        let ff_se: E::F = E::F::from(BaseField::from(255));

        // SignExtBit ∈ {0, 1}.
        eval.add_constraint(
            is_sign_ext.clone()
                * sign_ext_bit[0].clone()
                * (sign_ext_bit[0].clone() - E::F::one()),
        );
        // SE8 + SE16 both copy byte 0.
        eval.add_constraint(
            is_sign_ext.clone() * (result[0].clone() - val_d[0].clone()),
        );
        // SE16 also copies byte 1.
        eval.add_constraint(
            is_sign_ext_16[0].clone() * (result[1].clone() - val_d[1].clone()),
        );
        // SE8: bytes 1..8 = 0xFF · sign_bit.
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                is_sign_ext_8[0].clone()
                    * (result[i].clone() - ff_se.clone() * sign_ext_bit[0].clone()),
            );
        }
        // SE16: bytes 2..8 = 0xFF · sign_bit.
        for i in 2..WORD_SIZE {
            eval.add_constraint(
                is_sign_ext_16[0].clone()
                    * (result[i].clone() - ff_se.clone() * sign_ext_bit[0].clone()),
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // PHASE 33 — BITMANIP CountSetBits (CSB64 / CSB32):
        //   result[0] = sum(BytePopcount[0..N])  (N = 4 if Is32Bit else 8)
        //   result[1..8] = 0
        //   per-byte popcount lookup `(val_d[i], BytePopcount[i]) ∈ popcount`
        //     emitted further below near the other lookups.
        // ════════════════════════════════════════════════════════════════════
        let is_count_set_bits = crate::trace::trace_eval!(trace_eval, Column::IsCountSetBits);
        let byte_popcount = crate::trace::trace_eval!(trace_eval, Column::BytePopcount);
        // 64-bit case: result[0] = sum of all 8 byte-popcount witnesses.
        // 32-bit case: result[0] = sum of low 4 byte-popcount witnesses.
        // is_64bit was defined at the top of add_constraints as 1 - is_32bit.
        let mut sum_lo4 = byte_popcount[0].clone();
        for i in 1..4 {
            sum_lo4 += byte_popcount[i].clone();
        }
        let mut sum_hi4 = byte_popcount[4].clone();
        for i in 5..WORD_SIZE {
            sum_hi4 += byte_popcount[i].clone();
        }
        // Combined sum: sum_lo4 + (1 - is_32bit) · sum_hi4.
        // result[0] - that_sum = 0, gated on is_count_set_bits.
        eval.add_constraint(
            is_count_set_bits[0].clone()
                * (result[0].clone() - sum_lo4 - is_64bit.clone() * sum_hi4)
        );
        // High bytes of result are zero on CSB rows (popcount ≤ 64 fits in result[0]).
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                is_count_set_bits[0].clone() * result[i].clone()
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // PHASE 34 — BITMANIP LeadingZeroBits / TrailingZeroBits 32 / 64.
        //
        // Per-byte LZ/TZ are bound via a separate (byte, lz, tz) lookup
        // (BitcountChip, 256-row preprocessed table).  The result formula
        // uses Phase 29's `ValDPartialNZ` (LSB-direction prefix-OR) for
        // TZ, and a new `ValDPartialNZMsb[8]` (MSB-direction prefix-OR)
        // plus `ValDPartialNZMsbLo[4]` (MSB over low-4-bytes only) for
        // LZ.  All three chains piggyback on Phase 29's `ValDByteInv` to
        // compute byte indicators.
        //
        // First-non-zero indicator at position i: `is_first_nz[i] =
        //   partial[i] − partial[i-1]` (with partial[-1] := 0).  For a
        //   non-zero val_d this is 1 at exactly one index k (the first
        //   non-zero byte) and 0 elsewhere; for val_d = 0 it's 0 at all
        //   positions.  Sum_{i} is_first_nz[i] = partial[last]
        //   (telescoping), so when val_d = 0 the default 64/32 fallback
        //   is gated on `1 − partial[last]`.
        //
        // Result formulas:
        //   TZ64: result[0] = sum_{i=0..7} is_first_nz[i] · (8·i + TzByte[i])
        //                     + (1 − partial[7]) · 64
        //   TZ32: result[0] = sum_{i=0..3} is_first_nz[i] · (8·i + TzByte[i])
        //                     + (1 − partial[3]) · 32
        //   LZ64: result[0] = sum_{i=0..7} is_first_nz_msb[i] · (8·(7−i)
        //                       + LzByte[i])
        //                     + (1 − partial_msb[0]) · 64
        //   LZ32: result[0] = sum_{i=0..3} is_first_nz_msb_lo[i] · (8·(3−i)
        //                       + LzByte[i])
        //                     + (1 − partial_msb_lo[0]) · 32
        // ════════════════════════════════════════════════════════════════════
        let is_lzb = crate::trace::trace_eval!(trace_eval, Column::IsLzb);
        let is_tzb = crate::trace::trace_eval!(trace_eval, Column::IsTzb);
        let bit_op_lz_byte = crate::trace::trace_eval!(trace_eval, Column::BitOpLzByte);
        let bit_op_tz_byte = crate::trace::trace_eval!(trace_eval, Column::BitOpTzByte);
        let val_d_partial_nz_p34 = crate::trace::trace_eval!(trace_eval, Column::ValDPartialNZ);
        let val_d_partial_nz_msb = crate::trace::trace_eval!(trace_eval, Column::ValDPartialNZMsb);
        let val_d_partial_nz_msb_lo = crate::trace::trace_eval!(trace_eval, Column::ValDPartialNZMsbLo);
        let val_d_byte_inv_p34 = crate::trace::trace_eval!(trace_eval, Column::ValDByteInv);

        // ── ValDPartialNZMsb[8] recurrence (MSB direction over all 8 bytes).
        // partial_msb[7] = byte_indicator[7];
        // partial_msb[i] = partial_msb[i+1] OR byte_indicator[i].
        eval.add_constraint(
            is_real.clone()
                * (val_d_partial_nz_msb[7].clone()
                    - val_d[7].clone() * val_d_byte_inv_p34[7].clone())
        );
        for i in (0..7).rev() {
            let byte_ind = val_d[i].clone() * val_d_byte_inv_p34[i].clone();
            let or_expr = val_d_partial_nz_msb[i + 1].clone()
                + byte_ind.clone()
                - val_d_partial_nz_msb[i + 1].clone() * byte_ind;
            eval.add_constraint(
                is_real.clone() * (val_d_partial_nz_msb[i].clone() - or_expr)
            );
        }

        // ── ValDPartialNZMsbLo[4] recurrence (MSB direction over low 4
        //   bytes only — for LZ32, where high bytes of val_d are ignored).
        // partial_msb_lo[3] = byte_indicator[3];
        // partial_msb_lo[i] = partial_msb_lo[i+1] OR byte_indicator[i].
        eval.add_constraint(
            is_real.clone()
                * (val_d_partial_nz_msb_lo[3].clone()
                    - val_d[3].clone() * val_d_byte_inv_p34[3].clone())
        );
        for i in (0..3).rev() {
            let byte_ind = val_d[i].clone() * val_d_byte_inv_p34[i].clone();
            let or_expr = val_d_partial_nz_msb_lo[i + 1].clone()
                + byte_ind.clone()
                - val_d_partial_nz_msb_lo[i + 1].clone() * byte_ind;
            eval.add_constraint(
                is_real.clone() * (val_d_partial_nz_msb_lo[i].clone() - or_expr)
            );
        }

        // ── TZ result binding ──
        // is_first_nz[0] = partial[0]; is_first_nz[i] = partial[i] − partial[i-1].
        let mut tz_lo4 = E::F::zero();
        let mut tz_hi4 = E::F::zero();
        for i in 0..WORD_SIZE {
            let prev = if i == 0 {
                E::F::zero()
            } else {
                val_d_partial_nz_p34[i - 1].clone()
            };
            let is_first_nz = val_d_partial_nz_p34[i].clone() - prev;
            let term = is_first_nz
                * (E::F::from(BaseField::from(8u32 * i as u32))
                    + bit_op_tz_byte[i].clone());
            if i < 4 {
                tz_lo4 += term;
            } else {
                tz_hi4 += term;
            }
        }
        // 64-bit branch: tz_lo4 + tz_hi4 + (1 - partial[7]) · 64.
        // 32-bit branch: tz_lo4 + (1 - partial[3]) · 32.
        let tz_default_64 = E::F::from(BaseField::from(64u32))
            * (E::F::one() - val_d_partial_nz_p34[7].clone());
        let tz_default_32 = E::F::from(BaseField::from(32u32))
            * (E::F::one() - val_d_partial_nz_p34[3].clone());
        let tz_expr = tz_lo4
            + is_64bit.clone() * (tz_hi4 + tz_default_64)
            + is_32bit[0].clone() * tz_default_32;
        eval.add_constraint(
            is_tzb[0].clone() * (result[0].clone() - tz_expr)
        );

        // ── LZ result binding ──
        // is_first_nz_msb[i] = partial_msb[i] − partial_msb[i+1] (with
        //   partial_msb[8] := 0 for i = 7).
        // is_first_nz_msb_lo[i] over the LOW 4 bytes uses partial_msb_lo
        //   (which spans only bytes 0..3), with partial_msb_lo[4] := 0
        //   for i = 3.
        let mut lz_64 = E::F::zero();
        for i in 0..WORD_SIZE {
            let next = if i + 1 < WORD_SIZE {
                val_d_partial_nz_msb[i + 1].clone()
            } else {
                E::F::zero()
            };
            let is_first_nz_msb = val_d_partial_nz_msb[i].clone() - next;
            // For LZ64: position contribution is 8·(7 − i).
            let pos_weight = 8u32 * (7 - i as u32);
            let term = is_first_nz_msb
                * (E::F::from(BaseField::from(pos_weight))
                    + bit_op_lz_byte[i].clone());
            lz_64 += term;
        }
        let lz_default_64 = E::F::from(BaseField::from(64u32))
            * (E::F::one() - val_d_partial_nz_msb[0].clone());
        // LZ32 sums over bytes 0..3 with position contribution 8·(3 − i).
        let mut lz_32 = E::F::zero();
        for i in 0..4 {
            let next = if i + 1 < 4 {
                val_d_partial_nz_msb_lo[i + 1].clone()
            } else {
                E::F::zero()
            };
            let is_first_nz_msb_lo = val_d_partial_nz_msb_lo[i].clone() - next;
            let pos_weight = 8u32 * (3 - i as u32);
            let term = is_first_nz_msb_lo
                * (E::F::from(BaseField::from(pos_weight))
                    + bit_op_lz_byte[i].clone());
            lz_32 += term;
        }
        let lz_default_32 = E::F::from(BaseField::from(32u32))
            * (E::F::one() - val_d_partial_nz_msb_lo[0].clone());
        let lz_expr = is_64bit.clone() * (lz_64 + lz_default_64)
            + is_32bit[0].clone() * (lz_32 + lz_default_32);
        eval.add_constraint(
            is_lzb[0].clone() * (result[0].clone() - lz_expr)
        );

        // High bytes of result are zero on LZ/TZ rows.
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                (is_lzb[0].clone() + is_tzb[0].clone()) * result[i].clone()
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // CONTROL FLOW: constrain next_pc based on branch/jump
        // ════════════════════════════════════════════════════════════════════
        let is_jump = crate::trace::trace_eval!(trace_eval, Column::IsJump);
        let branch_taken = crate::trace::trace_eval!(trace_eval, Column::BranchTaken);
        let branch_target = crate::trace::trace_eval!(trace_eval, Column::BranchTarget);
        let next_pc = crate::trace::trace_eval!(trace_eval, Column::NextPc);
        let _pc = crate::trace::trace_eval!(trace_eval, Column::Pc);
        let _skip_len = crate::trace::trace_eval!(trace_eval, Column::SkipLen);

        // Sequential next PC = pc + 1 + skip_len (as a 4-byte value)
        // For simplicity, constrain the low byte: seq_next_pc[0] = pc[0] + 1 + skip_len
        // Full multi-byte addition would need a carry chain on 4 bytes.
        // For now: constrain that next_pc equals either branch_target (taken) or sequential (not taken).

        // For unconditional jumps: next_pc = branch_target
        for i in 0..4 {
            eval.add_constraint(
                is_jump[0].clone() * (next_pc[i].clone() - branch_target[i].clone())
            );
        }

        // For conditional branches:
        //   branch_taken=1 → next_pc = branch_target
        //   branch_taken=0 → next_pc = pc + 1 + skip_len (sequential)
        // Constraint: is_branch * branch_taken * (next_pc - branch_target) = 0
        for i in 0..4 {
            eval.add_constraint(
                is_branch_e() * branch_taken[0].clone()
                * (next_pc[i].clone() - branch_target[i].clone())
            );
        }

        // branch_taken must be boolean
        eval.add_constraint(
            is_branch_e() * branch_taken[0].clone() * (E::F::one() - branch_taken[0].clone())
        );

        // ── Branch condition constraints ──
        // Phase 53e: branch sub-flag bindings moved up to function
        // scope (line ~134) so `is_branch_e()` is reachable from
        // earlier sites (line ~620 cmp+branch range gate).
        let byte_eq_cols = crate::trace::trace_eval!(trace_eval, Column::ByteEq);
        let byte_diff_inv = crate::trace::trace_eval!(trace_eval, Column::ByteDiffInv);

        // TEST 3: full byte_eq constraint
        for i in 0..WORD_SIZE {
            let diff = val_b[i].clone() - val_d[i].clone();
            eval.add_constraint(
                is_branch_e() * byte_eq_cols[i].clone()
                * (E::F::one() - byte_eq_cols[i].clone())
            );
            eval.add_constraint(
                is_branch_e() * byte_eq_cols[i].clone() * diff.clone()
            );
            eval.add_constraint(
                is_branch_e() * (E::F::one() - byte_eq_cols[i].clone())
                * (diff * byte_diff_inv[i].clone() - E::F::one())
            );
        }

        // Equality: EqFlag = AND of all byte_eq[i]. Expressed as:
        //   EqFlag = byte_eq[0] * byte_eq[1] * ... * byte_eq[7]  (degree 8, too high)
        // Instead, use: eq_flag = 1 iff sum of (1 - byte_eq[i]) = 0
        // Since each (1 - byte_eq[i]) ∈ {0,1}, the sum is 0 iff all byte_eq[i]=1.
        // sum ∈ [0,8]. Use an eq_flag witness + sum*inv constraint similar to byte_eq.
        // For simplicity, constrain BranchEq/BranchNe using the bytewise eq flags directly:
        //   BranchEq taken ⇔ all byte_eq[i] = 1
        //   This is equivalent to: branch_taken * (1 - byte_eq[i]) = 0 for all i (if taken, all must be equal)
        //   AND: (1 - branch_taken) * (sum (1 - byte_eq[i])) = (1 - branch_taken) * (something nonzero)
        // Simpler: introduce EqFlag column... but we don't have one.
        //
        // Per-byte constraints for eq/ne:
        //   is_br_eq * branch_taken * (1 - byte_eq[i]) = 0 (if eq branch taken, all bytes equal)
        //   is_br_ne * (1 - branch_taken) * (1 - byte_eq[i]) = 0 (if ne branch NOT taken, all bytes equal)
        // The converse (val_b == val_d ⇒ branch_taken_eq = 1) is benign in
        // PVM semantics: branch_taken is the prover's witness for "PC took
        // the offset path", not "the comparison succeeded".  When target ==
        // sequential_next_pc the two coincide regardless, so a flipped
        // branch_taken witness produces the same next_pc and the rest of
        // the trace is unaffected.  See the loose-corner test in
        // tests/control_flow_negative.rs.
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                is_br_eq[0].clone() * branch_taken[0].clone()
                * (E::F::one() - byte_eq_cols[i].clone())
            );
            eval.add_constraint(
                is_br_ne[0].clone() * (E::F::one() - branch_taken[0].clone())
                * (E::F::one() - byte_eq_cols[i].clone())
            );
        }

        // Unsigned Lt: branch_taken = cmp_lt_flag
        eval.add_constraint(
            is_br_lt_u[0].clone() * (branch_taken[0].clone() - cmp_lt_flag[0].clone())
        );
        // Unsigned Ge: branch_taken = 1 - cmp_lt_flag
        eval.add_constraint(
            is_br_ge_u[0].clone() * (branch_taken[0].clone() - (E::F::one() - cmp_lt_flag[0].clone()))
        );
        // Signed Lt: branch_taken = cmp_lt_s_flag
        eval.add_constraint(
            is_br_lt_s[0].clone() * (branch_taken[0].clone() - cmp_lt_s_flag[0].clone())
        );
        // Signed Ge: branch_taken = 1 - cmp_lt_s_flag
        eval.add_constraint(
            is_br_ge_s[0].clone() * (branch_taken[0].clone() - (E::F::one() - cmp_lt_s_flag[0].clone()))
        );
        // EqFlag: constrain val_b == val_d flag
        let eq_flag = crate::trace::trace_eval!(trace_eval, Column::EqFlag);
        // eq_flag boolean
        eval.add_constraint(
            is_cmp_or_branch.clone() * eq_flag[0].clone() * (E::F::one() - eq_flag[0].clone())
        );
        // Phase 54f: eq_flag=1 ⇒ val_b[i] = val_d[i] (byte-wise).
        // Reformulated to read val_b/val_d directly so cmp_sub_result
        // can live on CompareChip.  Equivalent soundness — both arms
        // pin "val_b == val_d byte-wise" iff eq_flag=1.
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                is_cmp_or_branch.clone() * eq_flag[0].clone()
                    * (val_b[i].clone() - val_d[i].clone())
            );
        }
        // eq_flag=0 ⇒ cmp_lt_flag or NOT equal. Constrain: eq_flag + cmp_lt_flag <= 1 wouldn't work.
        // Use: (1 - eq_flag) means at least one sub_result byte is non-zero.
        // Sufficient for Le/Gt: branch_taken = cmp_lt_flag + eq_flag for LeU (≤ = < OR ==)
        // This is sound because eq_flag=1 forces all sub_result=0 (proven above).

        // Unsigned Le: branch_taken = cmp_lt_flag + eq_flag - cmp_lt_flag*eq_flag (OR)
        // Simpler since cmp_lt_flag and eq_flag can't both be 1 (if lt, not equal):
        // branch_taken = cmp_lt_flag + eq_flag
        eval.add_constraint(
            is_br_le_u[0].clone() * (branch_taken[0].clone() - cmp_lt_flag[0].clone() - eq_flag[0].clone())
        );
        // Unsigned Gt: branch_taken = 1 - (cmp_lt_flag + eq_flag)
        eval.add_constraint(
            is_br_gt_u[0].clone() * (branch_taken[0].clone() - E::F::one() + cmp_lt_flag[0].clone() + eq_flag[0].clone())
        );
        // Signed Le: branch_taken = cmp_lt_s_flag + eq_flag
        eval.add_constraint(
            is_br_le_s[0].clone() * (branch_taken[0].clone() - cmp_lt_s_flag[0].clone() - eq_flag[0].clone())
        );
        // Signed Gt: branch_taken = 1 - (cmp_lt_s_flag + eq_flag)
        eval.add_constraint(
            is_br_gt_s[0].clone() * (branch_taken[0].clone() - E::F::one() + cmp_lt_s_flag[0].clone() + eq_flag[0].clone())
        );

        // Sequential PC: next_pc = pc + 1 + skip_len (4-byte addition with carry)
        // Fires for: non-jump AND (non-branch OR branch-not-taken)
        // is_sequential = (1 - is_jump) * (1 - is_branch * branch_taken)
        //              = 1 - is_jump - is_branch*branch_taken + is_jump*is_branch*branch_taken
        // Since is_jump and is_branch are mutually exclusive, is_jump*is_branch=0, so:
        // is_sequential = 1 - is_jump - is_branch*branch_taken
        // But we can also just constrain each case separately:
        // For byte 0: next_pc[0] + pc_carry[0]*256 = pc[0] + 1 + skip_len
        // For byte i>0: next_pc[i] + pc_carry[i]*256 = pc[i] + pc_carry[i-1]
        // For byte 3: next_pc[3] = pc[3] + pc_carry[2] (no overflow for valid programs)
        {
            let pc = crate::trace::trace_eval!(trace_eval, Column::Pc);
            let skip_len = crate::trace::trace_eval!(trace_eval, Column::SkipLen);
            let pc_carry = crate::trace::trace_eval!(trace_eval, Column::PcCarry);
            let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
            let is_exit = crate::trace::trace_eval!(trace_eval, Column::IsExit);
            let is_sequential = E::F::one() - is_pad[0].clone()
                - is_jump[0].clone()
                - is_branch_e() * branch_taken[0].clone()
                - is_exit[0].clone();

            // Byte 0: next_pc[0] + carry[0]*256 = pc[0] + 1 + skip_len
            eval.add_constraint(
                is_sequential.clone() * (
                    next_pc[0].clone() + pc_carry[0].clone() * f256.clone()
                    - pc[0].clone() - E::F::one() - skip_len[0].clone()
                )
            );
            // Bytes 1,2: next_pc[i] + carry[i]*256 = pc[i] + carry[i-1]
            for i in 1..3 {
                eval.add_constraint(
                    is_sequential.clone() * (
                        next_pc[i].clone() + pc_carry[i].clone() * f256.clone()
                        - pc[i].clone() - pc_carry[i - 1].clone()
                    )
                );
            }
            // Byte 3: next_pc[3] = pc[3] + carry[2]
            eval.add_constraint(
                is_sequential.clone() * (
                    next_pc[3].clone() - pc[3].clone() - pc_carry[2].clone()
                )
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // Range256 checks for result byte limbs
        // ════════════════════════════════════════════════════════════════════
        for i in 0..WORD_SIZE {
            eval.add_to_relation(RelationEntry::new(
                range256_lookup,
                is_real.clone().into(),
                &[result[i].clone()],
            ));
        }

        // Phase 54f: Range256 checks for cmp_sub_result moved to CompareChip.

        // ════════════════════════════════════════════════════════════════════
        // Memory access lookup (producer side)
        // ════════════════════════════════════════════════════════════════════
        // Phase 53f: IsStore folded — `is_store_e()` is the sum.
        let mem_addr = crate::trace::trace_eval!(trace_eval, Column::MemAddr);
        let mem_value = crate::trace::trace_eval!(trace_eval, Column::MemValue);
        let timestamp = crate::trace::trace_eval!(trace_eval, Column::Timestamp);
        let mem_byte_active = crate::trace::trace_eval!(trace_eval, Column::MemByteActive);

        // Byte-level memory lookups: one per byte offset
        for byte_idx in 0..WORD_SIZE {
            let byte_offset = E::F::from(BaseField::from(byte_idx as u32));
            let mut tuple: Vec<E::F> = Vec::with_capacity(14);
            // addr + byte_idx
            tuple.push(mem_addr[0].clone() + byte_offset);
            for j in 1..4 { tuple.push(mem_addr[j].clone()); }
            // value byte
            tuple.push(mem_value[byte_idx].clone());
            // timestamp
            tuple.extend_from_slice(&timestamp);
            // is_write
            tuple.push(is_store_e());

            eval.add_to_relation(RelationEntry::new(
                mem_lookup,
                mem_byte_active[byte_idx].clone().into(),
                &tuple,
            ));
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 22: pin MemByteActive to a prefix-1 pattern of length MemSize
        //
        // Until Phase 22 the AIR only used MemByteActive as the lookup
        // multiplicity for byte-level memory accesses; its shape was
        // prover-witnessed.  A malicious prover could set MemByteActive
        // to a non-prefix pattern (e.g. [1,0,1,0,...]) or pick MemSize
        // inconsistent with the active-byte count.  Phase 22 forces:
        //   1. each MemByteActive[i] is boolean,
        //   2. monotonic (active[i+1]=1 ⇒ active[i]=1) — prefix-1 shape,
        //   3. MemSize equals the number of active bytes,
        //   4. MemSize ∈ {0, 1, 2, 4, 8}  (the valid PVM access widths).
        //
        // Combined, these uniquely determine MemByteActive from MemSize.
        // Out of scope: pinning MemSize itself to the opcode-canonical
        // size (would need IsLoadU8/U16/U32/U64 + IsStoreU8/U16/U32/U64
        // flags through ProgramMemoryChip).
        {
            let mem_size = crate::trace::trace_eval!(trace_eval, Column::MemSize);
            // Boolean per byte.  Gate by is_real so padding rows
            // (MemByteActive = 0) trivially satisfy this without
            // forcing extra zeros.
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_real.clone()
                        * mem_byte_active[i].clone()
                        * (E::F::one() - mem_byte_active[i].clone())
                );
            }
            // Monotonicity: active[i+1] = 1 ⇒ active[i] = 1.  Encoded
            // as `active[i+1] · (1 - active[i]) = 0`.
            for i in 0..WORD_SIZE - 1 {
                eval.add_constraint(
                    is_real.clone()
                        * mem_byte_active[i + 1].clone()
                        * (E::F::one() - mem_byte_active[i].clone())
                );
            }
            // MemSize equals the count of active bytes.
            let mut active_sum = E::F::zero();
            for i in 0..WORD_SIZE {
                active_sum += mem_byte_active[i].clone();
            }
            eval.add_constraint(
                is_real.clone() * (mem_size[0].clone() - active_sum)
            );
            // Phase 23: pin MemSize to opcode-canonical width via
            // per-size flags pinned by ProgramMemoryChip.  Closes the
            // gap deferred at the end of Phase 22 (the degree-6 valid-
            // size polynomial was too high; using flag-based formulation
            // brings the degree down to 1).  Each flag IsMemSize*  is
            // bound to the canonical opcode decoding via the
            // ProgramMemory tuple, and exactly one is set on a memory-
            // op row (load OR store), all zero on non-memory rows.
            let f_is_mem_size_1_l = crate::trace::trace_eval!(trace_eval, Column::IsMemSize1);
            let f_is_mem_size_2_l = crate::trace::trace_eval!(trace_eval, Column::IsMemSize2);
            let f_is_mem_size_4_l = crate::trace::trace_eval!(trace_eval, Column::IsMemSize4);
            let f_is_mem_size_8_l = crate::trace::trace_eval!(trace_eval, Column::IsMemSize8);
            let canonical_size = f_is_mem_size_1_l[0].clone()
                + f_is_mem_size_2_l[0].clone() * E::F::from(BaseField::from(2u32))
                + f_is_mem_size_4_l[0].clone() * E::F::from(BaseField::from(4u32))
                + f_is_mem_size_8_l[0].clone() * E::F::from(BaseField::from(8u32));
            eval.add_constraint(
                is_real.clone() * (mem_size[0].clone() - canonical_size)
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // Program execution lookup: step sequencing
        // ════════════════════════════════════════════════════════════════════
        {
            let pc_col = crate::trace::trace_eval!(trace_eval, Column::Pc);
            let next_pc_col = crate::trace::trace_eval!(trace_eval, Column::NextPc);
            let timestamp = crate::trace::trace_eval!(trace_eval, Column::Timestamp);
            let next_ts = crate::trace::trace_eval!(trace_eval, Column::NextTimestamp);

            // Consume (timestamp, pc)
            let mut consume_tuple: Vec<E::F> = timestamp.to_vec();
            consume_tuple.extend_from_slice(&pc_col);
            eval.add_to_relation(RelationEntry::new(
                prog_exec_lookup,
                (-is_real.clone()).into(),
                &consume_tuple,
            ));

            // Produce (next_timestamp, next_pc)
            let mut produce_tuple: Vec<E::F> = next_ts.to_vec();
            produce_tuple.extend_from_slice(&next_pc_col);
            eval.add_to_relation(RelationEntry::new(
                prog_exec_lookup,
                is_real.clone().into(),
                &produce_tuple,
            ));
        }

        // Phase 54e: BitwiseAndLookup nibble emissions moved to
        // BitwiseChip.  CpuChip emits the BitwiseLookup producer
        // (paired) just before finalize_logup_in_pairs.

        // Power-of-two lookup: proves val_d = 2^shift_amount for constrained shifts.
        //
        // Phase 35 / 36 split: gate the classic emission on
        //   is_shift_c · (1 − is_rotate_r64 − is_rotate_r32)
        // so RotR64 + RotR32 rows fall through.  For those rows val_d
        // gets pinned to `2^ShiftAmountCompl` instead, via a second
        // emission keyed on `ShiftAmountCompl` and gated on
        // `is_rotate_r64 + is_rotate_r32`.  Classic-shift and RotL64 /
        // RotL32 rows use the first emission with ShiftAmount = n_real.
        let is_rotate_r64_pow2 = crate::trace::trace_eval!(trace_eval, Column::IsRotateR64);
        let is_rotate_r32_pow2 = crate::trace::trace_eval!(trace_eval, Column::IsRotateR32);
        let shift_amount_compl_pow2 = crate::trace::trace_eval!(trace_eval, Column::ShiftAmountCompl);
        {
            let shift_amount = crate::trace::trace_eval!(trace_eval, Column::ShiftAmount);
            let is_shift_c = crate::trace::trace_eval!(trace_eval, Column::IsShiftConstrained);
            let mut tuple: Vec<E::F> = vec![shift_amount[0].clone()];
            tuple.extend_from_slice(&val_d);
            // Multiplicity: is_shift_c · (1 − is_rotate_r64 − is_rotate_r32).
            let mult = is_shift_c[0].clone()
                * (E::F::one()
                    - is_rotate_r64_pow2[0].clone()
                    - is_rotate_r32_pow2[0].clone());
            eval.add_to_relation(RelationEntry::new(
                pow2_lookup,
                mult.into(),
                &tuple,
            ));
        }
        // Phase 35 / 36: separate PowerOfTwo emission for RotR64 + RotR32
        // keyed on ShiftAmountCompl.
        {
            let mut tuple: Vec<E::F> = vec![shift_amount_compl_pow2[0].clone()];
            tuple.extend_from_slice(&val_d);
            let mult = is_rotate_r64_pow2[0].clone() + is_rotate_r32_pow2[0].clone();
            eval.add_to_relation(RelationEntry::new(
                pow2_lookup,
                mult.into(),
                &tuple,
            ));
        }

        // Phase 33: Popcount lookup — per-byte (val_d[i], BytePopcount[i]) on
        // CountSetBits rows.  Emitted for all 8 bytes of val_d regardless of
        // is_32bit; the result-binding sums only the relevant bytes.  The
        // PopcountChip's preprocessed table holds the canonical (byte,
        // popcount(byte)) for byte ∈ [0, 256).  Producer multiplicity =
        // is_count_set_bits per byte.
        {
            for i in 0..WORD_SIZE {
                let tuple = vec![val_d[i].clone(), byte_popcount[i].clone()];
                eval.add_to_relation(RelationEntry::new(
                    popcount_lookup,
                    is_count_set_bits[0].clone().into(),
                    &tuple,
                ));
            }
        }

        // Phase 34: Bitcount lookup — per-byte (val_d[i], BitOpLzByte[i],
        // BitOpTzByte[i]) on LZ/TZ rows.  Producer multiplicity =
        // is_lzb + is_tzb (mutually exclusive — at most one is 1 per row).
        {
            for i in 0..WORD_SIZE {
                let tuple = vec![
                    val_d[i].clone(),
                    bit_op_lz_byte[i].clone(),
                    bit_op_tz_byte[i].clone(),
                ];
                eval.add_to_relation(RelationEntry::new(
                    bitcount_lookup,
                    (is_lzb[0].clone() + is_tzb[0].clone()).into(),
                    &tuple,
                ));
            }
        }

        // Register-memory producers (Phase 9d): mirror of the interaction
        // trace emissions in the same order (ValB read → ValD read → Result
        // write) so finalize_logup_in_pairs pairs correctly.
        {
            let val_b_is_reg = crate::trace::trace_eval!(trace_eval, Column::ValBIsReg);
            let val_b_reg_idx = crate::trace::trace_eval!(trace_eval, Column::ValBRegIdx);
            let val_d_is_reg = crate::trace::trace_eval!(trace_eval, Column::ValDIsReg);
            let val_d_reg_idx = crate::trace::trace_eval!(trace_eval, Column::ValDRegIdx);
            let result_is_reg = crate::trace::trace_eval!(trace_eval, Column::ResultIsReg);
            let result_reg_idx = crate::trace::trace_eval!(trace_eval, Column::ResultRegIdx);
            let result_c = crate::trace::trace_eval!(trace_eval, Column::Result);

            // Phase 9g: RegValB carries the full u64 register value; ValB
            // may be truncated (for 32-bit ALU ops).  Producer uses RegValB.
            let reg_val_b = crate::trace::trace_eval!(trace_eval, Column::RegValB);
            let mut tuple: Vec<E::F> = vec![val_b_reg_idx[0].clone()];
            for b in &reg_val_b { tuple.push(b.clone()); }
            for ts in &timestamp { tuple.push(ts.clone()); }
            eval.add_to_relation(RelationEntry::new(
                reg_lookup,
                val_b_is_reg[0].clone().into(),
                &tuple,
            ));

            // Phase 9f: RegValD (raw reg_b value) drives the ledger, not ValD
            // (which gets rewritten to 2^shift_amount for shift ops).
            let reg_val_d = crate::trace::trace_eval!(trace_eval, Column::RegValD);
            let mut tuple: Vec<E::F> = vec![val_d_reg_idx[0].clone()];
            for b in &reg_val_d { tuple.push(b.clone()); }
            for ts in &timestamp { tuple.push(ts.clone()); }
            eval.add_to_relation(RelationEntry::new(
                reg_lookup,
                val_d_is_reg[0].clone().into(),
                &tuple,
            ));

            // Phase 28: RegValA producer for StoreInd source value.
            // Emitted as a paired duplicate (mirrors the prog_mem
            // pattern from Phase 13b/13c) so pair-parity stays even;
            // RegisterMemoryChip pushes the val_a_read entry twice
            // to match.  Tuple uses RegA directly as the index
            // (reg_a is already a column on every row, decoded from
            // the opcode by Phase 13b's ProgramMemory binding).
            let reg_val_a = crate::trace::trace_eval!(trace_eval, Column::RegValA);
            let reg_a_col = crate::trace::trace_eval!(trace_eval, Column::RegA);
            let is_store_ind_col = crate::trace::trace_eval!(trace_eval, Column::IsStoreInd);
            let mut tuple_a: Vec<E::F> = vec![reg_a_col[0].clone()];
            for b in &reg_val_a { tuple_a.push(b.clone()); }
            for ts in &timestamp { tuple_a.push(ts.clone()); }
            eval.add_to_relation(RelationEntry::new(
                reg_lookup,
                is_store_ind_col[0].clone().into(),
                &tuple_a,
            ));
            eval.add_to_relation(RelationEntry::new(
                reg_lookup,
                is_store_ind_col[0].clone().into(),
                &tuple_a,
            ));

            // Phase 9g: IsTruncated is 1 iff Is32Bit AND (IsAdd + IsSub +
            // IsMul + IsDivRem).  Validity constraint ties it to the op flags
            // so a prover can't flip it independently.
            let is_truncated = crate::trace::trace_eval!(trace_eval, Column::IsTruncated);
            eval.add_constraint(
                is_real.clone() * is_truncated[0].clone() * (is_truncated[0].clone() - E::F::one())
            );
            let trunc_sum = is_add[0].clone() + is_sub[0].clone()
                + is_mul[0].clone() + is_div_rem[0].clone();
            eval.add_constraint(
                is_real.clone()
                    * (is_truncated[0].clone() - is_32bit[0].clone() * trunc_sum)
            );

            // ValB byte-wise cross-constraint.  ValB is not affected by shifts.
            //   - low 4 bytes: ValB[i] == RegValB[i] whenever ValBIsReg=1
            //   - upper 4 bytes: match when NOT truncated, zero when truncated.
            for i in 0..4 {
                eval.add_constraint(
                    is_real.clone() * val_b_is_reg[0].clone()
                        * (val_b[i].clone() - reg_val_b[i].clone())
                );
            }
            for i in 4..WORD_SIZE {
                eval.add_constraint(
                    is_real.clone() * val_b_is_reg[0].clone()
                        * (E::F::one() - is_truncated[0].clone())
                        * (val_b[i].clone() - reg_val_b[i].clone())
                );
                eval.add_constraint(
                    is_real.clone() * val_b_is_reg[0].clone()
                        * is_truncated[0].clone() * val_b[i].clone()
                );
            }

            // ValD byte-wise cross-constraint.  Skip shift rows (handled by
            // the ShiftQuotient identity below).
            let is_shift_c = crate::trace::trace_eval!(trace_eval, Column::IsShiftConstrained);
            let non_shift_gate = is_real.clone()
                * val_d_is_reg[0].clone()
                * (E::F::one() - is_shift_c[0].clone());
            for i in 0..4 {
                eval.add_constraint(
                    non_shift_gate.clone() * (val_d[i].clone() - reg_val_d[i].clone())
                );
            }
            for i in 4..WORD_SIZE {
                eval.add_constraint(
                    non_shift_gate.clone()
                        * (E::F::one() - is_truncated[0].clone())
                        * (val_d[i].clone() - reg_val_d[i].clone())
                );
                eval.add_constraint(
                    non_shift_gate.clone()
                        * is_truncated[0].clone()
                        * val_d[i].clone()
                );
            }

            // Shift-amount identity: RegValD = ShiftAmount + modulus · ShiftQuotient.
            // Combine bytes into field elements, pick modulus from Is32Bit
            // (32 if 32-bit shift, 64 otherwise — expressible as 32 · (2 - is_32bit)).
            let shift_q = crate::trace::trace_eval!(trace_eval, Column::ShiftQuotient);
            let is_32b = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
            let reg_val_d_field = crate::framework::eval::combine_le_u64::<E>(&reg_val_d);
            let shift_q_field = crate::framework::eval::combine_le_u64::<E>(&shift_q);
            let shift_amount_e = crate::trace::trace_eval!(trace_eval, Column::ShiftAmount);
            let two = E::F::from(BaseField::from(2u32));
            let thirty_two = E::F::from(BaseField::from(32u32));
            let modulus = thirty_two * (two - is_32b[0].clone());
            // Gated on ValDIsReg too: for 32-bit shifts the ValD read is
            // skipped (truncated_32bit) and RegValD = 0, so the constraint
            // must not fire there — 9g will extend this.
            eval.add_constraint(
                is_real.clone()
                    * val_d_is_reg[0].clone()
                    * is_shift_c[0].clone()
                    * (reg_val_d_field.clone() - shift_amount_e[0].clone() - modulus * shift_q_field)
            );

            // Phase 35 / 36: complementary shift-amount identity for
            // RotR64 / RotR32 rows.
            //   reg_val_d + ShiftAmountCompl = modulus · ShiftQuotientCompl.
            // modulus = 32 if Is32Bit else 64.  Combined with the
            // ShiftAmountCompl ∈ [0, 31 or 0, 63] bound (pow2 table
            // size + the val_d-high-bytes-zero constraint for 32-bit),
            // this uniquely determines ShiftAmountCompl = (modulus −
            // n_real) mod modulus.
            let shift_q_compl = crate::trace::trace_eval!(trace_eval, Column::ShiftQuotientCompl);
            let shift_amount_compl = crate::trace::trace_eval!(trace_eval, Column::ShiftAmountCompl);
            let is_rotate_r64_p35_id = crate::trace::trace_eval!(trace_eval, Column::IsRotateR64);
            let is_rotate_r32_p36_id = crate::trace::trace_eval!(trace_eval, Column::IsRotateR32);
            let shift_q_compl_field = crate::framework::eval::combine_le_u64::<E>(&shift_q_compl);
            // Same modulus expression as the classic shift identity.
            let two_compl = E::F::from(BaseField::from(2u32));
            let thirty_two_compl = E::F::from(BaseField::from(32u32));
            let modulus_compl = thirty_two_compl * (two_compl - is_32b[0].clone());
            let is_rotate_r_either = is_rotate_r64_p35_id[0].clone()
                + is_rotate_r32_p36_id[0].clone();
            eval.add_constraint(
                is_real.clone()
                    * is_rotate_r_either
                    * (reg_val_d_field + shift_amount_compl[0].clone()
                        - modulus_compl * shift_q_compl_field)
            );

            let mut tuple: Vec<E::F> = vec![result_reg_idx[0].clone()];
            for b in &result_c { tuple.push(b.clone()); }
            for ts in &timestamp { tuple.push(ts.clone()); }
            eval.add_to_relation(RelationEntry::new(
                reg_lookup,
                result_is_reg[0].clone().into(),
                &tuple,
            ));

            // IsReg flags must be boolean.
            eval.add_constraint(
                is_real.clone() * val_b_is_reg[0].clone() * (val_b_is_reg[0].clone() - E::F::one())
            );
            eval.add_constraint(
                is_real.clone() * val_d_is_reg[0].clone() * (val_d_is_reg[0].clone() - E::F::one())
            );
            eval.add_constraint(
                is_real.clone() * result_is_reg[0].clone() * (result_is_reg[0].clone() - E::F::one())
            );
        }

        // ── Phase 9e: blake2b ECALL register-read producers + Phi7Bool tie ──
        {
            let is_blake_ecall = crate::trace::trace_eval!(trace_eval, Column::IsBlakeEcall);
            let phi7 = crate::trace::trace_eval!(trace_eval, Column::Phi7);
            let phi7_inv = crate::trace::trace_eval!(trace_eval, Column::Phi7Inv);
            let phi7_bool = crate::trace::trace_eval!(trace_eval, Column::Phi7Bool);
            let phi10 = crate::trace::trace_eval!(trace_eval, Column::Phi10);
            let phi11 = crate::trace::trace_eval!(trace_eval, Column::Phi11);
            let phi12 = crate::trace::trace_eval!(trace_eval, Column::Phi12);

            const ECALL_REG_IDXS: [u32; 4] = [7, 10, 11, 12];
            let phi_cols: [&[E::F]; 4] = [&phi7, &phi10, &phi11, &phi12];
            for (slot, &reg_idx) in ECALL_REG_IDXS.iter().enumerate() {
                let mut tuple: Vec<E::F> = Vec::with_capacity(17);
                tuple.push(E::F::from(BaseField::from(reg_idx)));
                for c in phi_cols[slot] { tuple.push(c.clone()); }
                for c in &timestamp { tuple.push(c.clone()); }
                eval.add_to_relation(RelationEntry::new(
                    reg_lookup,
                    is_blake_ecall[0].clone().into(),
                    &tuple,
                ));
            }

            // Phi7Bool ↔ Phi7 (the u64-combined field value) tie, gated only
            // by is_real (at non-ECALL rows the Phi7Bool is still consistent
            // with Phi7 because trace gen derives both from regs_before[7]).
            let phi7_field = crate::framework::eval::combine_le_u64::<E>(&phi7);
            let phi7_inv_field = crate::framework::eval::combine_le_u64::<E>(&phi7_inv);
            // Phi7Bool is boolean.
            eval.add_constraint(
                is_real.clone() * phi7_bool[0].clone() * (phi7_bool[0].clone() - E::F::one())
            );
            // If Phi7Bool = 0, then Phi7 (as field) = 0.
            eval.add_constraint(
                is_real.clone()
                    * (E::F::one() - phi7_bool[0].clone())
                    * phi7_field.clone()
            );
            // If Phi7Bool = 1, then Phi7 · Phi7Inv = 1 (so Phi7 is non-zero).
            eval.add_constraint(
                is_real.clone()
                    * phi7_bool[0].clone()
                    * (phi7_field * phi7_inv_field - E::F::one())
            );
        }

        // Blake2b call binding (Phase 8c): mirror of the prover-side producer.
        {
            let is_blake_ecall = crate::trace::trace_eval!(trace_eval, Column::IsBlakeEcall);
            let phi10 = crate::trace::trace_eval!(trace_eval, Column::Phi10);
            let phi11 = crate::trace::trace_eval!(trace_eval, Column::Phi11);
            let phi12 = crate::trace::trace_eval!(trace_eval, Column::Phi12);
            let phi7_bool = crate::trace::trace_eval!(trace_eval, Column::Phi7Bool);
            let mut tuple: Vec<E::F> = Vec::with_capacity(25);
            for i in 0..4 { tuple.push(phi10[i].clone()); }
            for i in 0..4 { tuple.push(phi11[i].clone()); }
            for i in 0..WORD_SIZE { tuple.push(phi12[i].clone()); }
            tuple.push(phi7_bool[0].clone());
            for i in 0..WORD_SIZE { tuple.push(timestamp[i].clone()); }
            eval.add_to_relation(RelationEntry::new(
                blake2b_call_lookup,
                is_blake_ecall[0].clone().into(),
                &tuple,
            ));

            // Phi7Bool must be boolean (0 or 1) at all real rows, gated by
            // is_real so padding rows aren't constrained.
            eval.add_constraint(
                is_real.clone() * phi7_bool[0].clone() * (phi7_bool[0].clone() - E::F::one())
            );
            // IsBlakeEcall must be boolean too.
            eval.add_constraint(
                is_real.clone() * is_blake_ecall[0].clone() * (is_blake_ecall[0].clone() - E::F::one())
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // BITMANIP — SignExtend8/16 nibble lookups (Phase 12b-2)
        //
        // Placed immediately before finalize_logup_in_pairs so the 4 emissions
        // (2a, 2b, 3a, 3b) pair within themselves and don't reshuffle existing
        // pair constraints.  Reshuffling could push a downstream pair past the
        // chip's degree bound — reasoning detailed in the 12-investigate note.
        //
        // Tuples (degree-1 each, kept simple to stay within bound):
        //   (2a) gated on IsSE8: (SignExtSrcHiNib, 8, 8·SignExtBit)
        //   (2b) gated on IsSE16: same tuple
        //   (3a) gated on IsSE8: (val_d[0] - 16·SignExtSrcHiNib, 0xF, same)
        //   (3b) gated on IsSE16: (val_d[1] - 16·SignExtSrcHiNib, 0xF, same)
        // ════════════════════════════════════════════════════════════════════
        {
            let sign_ext_hi_nib = crate::trace::trace_eval!(trace_eval, Column::SignExtSrcHiNib);
            let sixteen_se: E::F = E::F::from(BaseField::from(16));
            let eight_se: E::F = E::F::from(BaseField::from(8));
            let fifteen_se: E::F = E::F::from(BaseField::from(15));
            // (2a)
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_sign_ext_8[0].clone().into(),
                &[
                    sign_ext_hi_nib[0].clone(),
                    eight_se.clone(),
                    sign_ext_bit[0].clone() * eight_se.clone(),
                ],
            ));
            // (2b)
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_sign_ext_16[0].clone().into(),
                &[
                    sign_ext_hi_nib[0].clone(),
                    eight_se.clone(),
                    sign_ext_bit[0].clone() * eight_se,
                ],
            ));
            // (3a)
            let lo_8 = val_d[0].clone() - sign_ext_hi_nib[0].clone() * sixteen_se.clone();
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_sign_ext_8[0].clone().into(),
                &[lo_8.clone(), fifteen_se.clone(), lo_8],
            ));
            // (3b)
            let lo_16 = val_d[1].clone() - sign_ext_hi_nib[0].clone() * sixteen_se;
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_sign_ext_16[0].clone().into(),
                &[lo_16.clone(), fifteen_se, lo_16],
            ));
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 13b/c + 55b: program-memory consumer (pc + opcode + regs + imm
        //                                              + 6 packed flag bytes
        //                                              + imm_y + branch_target)
        //
        // Per real CpuChip step, demand the full instruction tuple from
        // ProgramMemoryChip's preprocessed table.  Phase 13b bound
        // (pc, opcode, skip_len, regs, imm); 13c extended with the 48
        // category/sub-category flags so a prover can't clear flags to
        // skip per-op constraints.  Phase 55b packs the 48 flag bits into
        // 6 bytes on both sides — the prog_mem tuple now sends 6 bytes
        // instead of 48 bits, and 6 byte-to-bits lookups (next block)
        // bind individual flag columns / sum-of-sub-flags expressions to
        // the matching bit slot in each FlagByteI.
        //
        // Pair-parity (CONSTRAINTS.md rule 1): two paired emissions with
        // identical multiplicity and tuple.  ProgramMemoryChip doubles its
        // multiplicity column.
        {
            let pc = crate::trace::trace_eval!(trace_eval, Column::Pc);
            let opcode = crate::trace::trace_eval!(trace_eval, Column::Opcode);
            let skip_len = crate::trace::trace_eval!(trace_eval, Column::SkipLen);
            let reg_a = crate::trace::trace_eval!(trace_eval, Column::RegA);
            let reg_b = crate::trace::trace_eval!(trace_eval, Column::RegB);
            let reg_d = crate::trace::trace_eval!(trace_eval, Column::RegD);
            let imm = crate::trace::trace_eval!(trace_eval, Column::ImmBytes);
            let fb0 = crate::trace::trace_eval!(trace_eval, Column::FlagByte0);
            let fb1 = crate::trace::trace_eval!(trace_eval, Column::FlagByte1);
            let fb2 = crate::trace::trace_eval!(trace_eval, Column::FlagByte2);
            let fb3 = crate::trace::trace_eval!(trace_eval, Column::FlagByte3);
            let fb4 = crate::trace::trace_eval!(trace_eval, Column::FlagByte4);
            let fb5 = crate::trace::trace_eval!(trace_eval, Column::FlagByte5);
            let imm_y_for_lookup = crate::trace::trace_eval!(trace_eval, Column::ImmYBytes);
            let branch_target_for_lookup = crate::trace::trace_eval!(
                trace_eval, Column::BranchTarget
            );

            let mut tuple: Vec<E::F> = pc.to_vec();
            tuple.push(opcode[0].clone());
            tuple.push(skip_len[0].clone());
            tuple.push(reg_a[0].clone());
            tuple.push(reg_b[0].clone());
            tuple.push(reg_d[0].clone());
            tuple.extend_from_slice(&imm);
            tuple.push(fb0[0].clone());
            tuple.push(fb1[0].clone());
            tuple.push(fb2[0].clone());
            tuple.push(fb3[0].clone());
            tuple.push(fb4[0].clone());
            tuple.push(fb5[0].clone());
            // Phase 13d-loadimmjumpind: bind ImmYBytes to canonical imm_y
            // (low 4 bytes) for LoadImmJumpInd; 0 for ops without a second
            // immediate.  Tracer writes 0 to imm_y for those, so balanced.
            tuple.extend_from_slice(&imm_y_for_lookup);
            // Phase 15-branch-target-fix: bind BranchTarget to its canonical
            // (pc + sign_extend(offset)) for static jumps/branches.  For
            // JumpInd/LoadImmJumpInd and non-branch ops, the canonical is 0;
            // the tracer also writes 0 to BranchTarget for those (see
            // decode_branch_target's default arm), so the lookup balances
            // without gating.
            tuple.extend_from_slice(&branch_target_for_lookup);

            // Paired emissions; ProgramMemoryChip's mult = 2·count_at_pc.
            eval.add_to_relation(RelationEntry::new(
                prog_mem_lookup,
                is_real.clone().into(),
                &tuple,
            ));
            eval.add_to_relation(RelationEntry::new(
                prog_mem_lookup,
                is_real.clone().into(),
                &tuple,
            ));
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 55b: byte-to-bits decomposition lookups
        //
        // Per real CpuChip step, emit 6 lookups against ByteToBitsChip's
        // 256-row table.  Each tuple is `(FlagByteI, bit0, bit1, ..., bit7)`
        // where bit_j is either an individual flag column or a sum-of-
        // sub-flags expression for the 5 folded category slots
        // (is_mul_upper / is_bitwise / is_compare / is_branch / is_store).
        // Composed with the prog_mem balance (which pins each FlagByteI to
        // canonical), this constrains every individual flag column /
        // sum expression to its canonical value at every real step.
        //
        // 6 emissions per row keep `finalize_logup_in_pairs`'s parity
        // even.  Multiplicity = is_real on every emission.
        //
        // Bit layout per byte (matches `pack_flags` in
        // chips/program_memory.rs and the canonical 48-flag layout in
        // `classify_opcode_for_program_memory`).
        {
            let fb0 = crate::trace::trace_eval!(trace_eval, Column::FlagByte0);
            let fb1 = crate::trace::trace_eval!(trace_eval, Column::FlagByte1);
            let fb2 = crate::trace::trace_eval!(trace_eval, Column::FlagByte2);
            let fb3 = crate::trace::trace_eval!(trace_eval, Column::FlagByte3);
            let fb4 = crate::trace::trace_eval!(trace_eval, Column::FlagByte4);
            let fb5 = crate::trace::trace_eval!(trace_eval, Column::FlagByte5);
            // Reread/define individual-flag bit expressions for each byte.
            // Most flags live in module-scope `let`s near the top of
            // add_constraints; the rest are local to this block.
            let f_is_jump_p55 = crate::trace::trace_eval!(trace_eval, Column::IsJump);
            let f_is_div_rem_p55 = crate::trace::trace_eval!(trace_eval, Column::IsDivRem);
            let f_is_load_p55 = crate::trace::trace_eval!(trace_eval, Column::IsLoad);
            let f_is_exit_p55 = crate::trace::trace_eval!(trace_eval, Column::IsExit);
            let f_is_reverse_bytes_p55 = crate::trace::trace_eval!(trace_eval, Column::IsReverseBytes);
            let f_is_zero_ext_16_p55 = crate::trace::trace_eval!(trace_eval, Column::IsZeroExt16);
            let f_is_sign_ext_8_p55 = crate::trace::trace_eval!(trace_eval, Column::IsSignExt8);
            let f_is_sign_ext_16_p55 = crate::trace::trace_eval!(trace_eval, Column::IsSignExt16);
            let f_is_trap_p55 = crate::trace::trace_eval!(trace_eval, Column::IsTrap);
            let f_is_jump_ind_p55 = crate::trace::trace_eval!(trace_eval, Column::IsJumpInd);
            let f_is_load_imm_jump_ind_p55 = crate::trace::trace_eval!(trace_eval, Column::IsLoadImmJumpInd);
            let f_is_mul_upper_uu_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperUU);
            let f_is_mul_upper_su_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSU);
            let f_is_mul_upper_ss_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSS);
            let f_is_div_s_p55 = crate::trace::trace_eval!(trace_eval, Column::IsDivS);
            let f_is_load_i8_p55 = crate::trace::trace_eval!(trace_eval, Column::IsLoadI8);
            let f_is_load_i16_p55 = crate::trace::trace_eval!(trace_eval, Column::IsLoadI16);
            let f_is_load_i32_p55 = crate::trace::trace_eval!(trace_eval, Column::IsLoadI32);
            let f_is_mem_size_1_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMemSize1);
            let f_is_mem_size_2_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMemSize2);
            let f_is_mem_size_4_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMemSize4);
            let f_is_mem_size_8_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMemSize8);
            let f_is_load_direct_p55 = crate::trace::trace_eval!(trace_eval, Column::IsLoadDirect);
            let f_is_mem_indirect_p55 = crate::trace::trace_eval!(trace_eval, Column::IsMemIndirect);
            let f_is_store_imm_direct_p55 = crate::trace::trace_eval!(trace_eval, Column::IsStoreImmDirect);
            let f_is_rotate_l64_p55 = crate::trace::trace_eval!(trace_eval, Column::IsRotateL64);
            let f_is_count_set_bits_p55 = crate::trace::trace_eval!(trace_eval, Column::IsCountSetBits);
            let f_is_lzb_p55 = crate::trace::trace_eval!(trace_eval, Column::IsLzb);
            let f_is_tzb_p55 = crate::trace::trace_eval!(trace_eval, Column::IsTzb);
            let f_is_rotate_r64_p55 = crate::trace::trace_eval!(trace_eval, Column::IsRotateR64);
            let f_is_rotate_l32_p55 = crate::trace::trace_eval!(trace_eval, Column::IsRotateL32);
            let f_is_rotate_r32_p55 = crate::trace::trace_eval!(trace_eval, Column::IsRotateR32);
            let f_is_rotate_r_imm_alt_p55 = crate::trace::trace_eval!(trace_eval, Column::IsRotateRImmAlt);

            // Sum expressions for the 5 folded category slots.
            let mu_sum_e = f_is_mul_upper_uu_p55[0].clone()
                + f_is_mul_upper_su_p55[0].clone()
                + f_is_mul_upper_ss_p55[0].clone();
            let bw_sum_e = is_and_flag[0].clone() + is_or_flag[0].clone()
                + is_xor_flag[0].clone() + is_and_inv_flag[0].clone()
                + is_or_inv_flag[0].clone() + is_xnor_flag[0].clone();
            let cmp_sum_e = is_compare_e();
            let br_sum_e = is_branch_e();
            let st_sum_e = is_store_e();

            // byte 0: (FlagByte0, is_add, is_sub, is_mul, MU_SUM, BW_SUM,
            //          is_shift, CMP_SUM, is_move)
            let tuple0: Vec<E::F> = vec![
                fb0[0].clone(),
                is_add[0].clone(), is_sub[0].clone(), is_mul[0].clone(),
                mu_sum_e.clone(), bw_sum_e.clone(),
                is_shift[0].clone(), cmp_sum_e.clone(), is_move[0].clone(),
            ];
            // byte 1: (FlagByte1, is_32bit, BR_SUM, is_jump, is_div_rem,
            //          is_load, ST_SUM, is_exit, is_neg_add)
            let tuple1: Vec<E::F> = vec![
                fb1[0].clone(),
                is_32bit[0].clone(), br_sum_e.clone(), f_is_jump_p55[0].clone(),
                f_is_div_rem_p55[0].clone(), f_is_load_p55[0].clone(),
                st_sum_e.clone(), f_is_exit_p55[0].clone(), is_neg_add[0].clone(),
            ];
            // byte 2: (FlagByte2, is_reverse_bytes, is_zero_ext_16,
            //          is_sign_ext_8, is_sign_ext_16, is_trap, is_jump_ind,
            //          is_load_imm_jump_ind, is_mul_upper_uu)
            let tuple2: Vec<E::F> = vec![
                fb2[0].clone(),
                f_is_reverse_bytes_p55[0].clone(), f_is_zero_ext_16_p55[0].clone(),
                f_is_sign_ext_8_p55[0].clone(), f_is_sign_ext_16_p55[0].clone(),
                f_is_trap_p55[0].clone(), f_is_jump_ind_p55[0].clone(),
                f_is_load_imm_jump_ind_p55[0].clone(), f_is_mul_upper_uu_p55[0].clone(),
            ];
            // byte 3: (FlagByte3, is_mul_upper_su, is_mul_upper_ss, is_div_s,
            //          is_load_i8, is_load_i16, is_load_i32,
            //          is_mem_size_1, is_mem_size_2)
            let tuple3: Vec<E::F> = vec![
                fb3[0].clone(),
                f_is_mul_upper_su_p55[0].clone(), f_is_mul_upper_ss_p55[0].clone(),
                f_is_div_s_p55[0].clone(),
                f_is_load_i8_p55[0].clone(), f_is_load_i16_p55[0].clone(),
                f_is_load_i32_p55[0].clone(),
                f_is_mem_size_1_p55[0].clone(), f_is_mem_size_2_p55[0].clone(),
            ];
            // byte 4: (FlagByte4, is_mem_size_4, is_mem_size_8,
            //          is_store_direct, is_load_direct, is_mem_indirect,
            //          is_store_imm_any, is_store_imm_direct, is_store_ind)
            let tuple4: Vec<E::F> = vec![
                fb4[0].clone(),
                f_is_mem_size_4_p55[0].clone(), f_is_mem_size_8_p55[0].clone(),
                is_store_direct_e[0].clone(), f_is_load_direct_p55[0].clone(),
                f_is_mem_indirect_p55[0].clone(),
                is_store_imm_any_e[0].clone(), f_is_store_imm_direct_p55[0].clone(),
                is_store_ind_e[0].clone(),
            ];
            // byte 5: (FlagByte5, is_rotate_l64, is_count_set_bits,
            //          is_lzb, is_tzb, is_rotate_r64, is_rotate_l32,
            //          is_rotate_r32, is_rotate_r_imm_alt)
            let tuple5: Vec<E::F> = vec![
                fb5[0].clone(),
                f_is_rotate_l64_p55[0].clone(), f_is_count_set_bits_p55[0].clone(),
                f_is_lzb_p55[0].clone(), f_is_tzb_p55[0].clone(),
                f_is_rotate_r64_p55[0].clone(), f_is_rotate_l32_p55[0].clone(),
                f_is_rotate_r32_p55[0].clone(), f_is_rotate_r_imm_alt_p55[0].clone(),
            ];

            for t in [&tuple0, &tuple1, &tuple2, &tuple3, &tuple4, &tuple5] {
                eval.add_to_relation(RelationEntry::new(
                    byte_to_bits_lookup,
                    is_real.clone().into(),
                    t,
                ));
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 13e-redux: terminal-row constraint gated on per-opcode IsTrap
        //
        // Forbids a real successor row after Trap.  The first attempt (Phase
        // 13e) gated on IsExit but that flag is shared with Ecalli (which
        // legitimately has successors after blake2b hostcalls) and with
        // JumpInd / LoadImmJumpInd (dynamic dispatch — also has successors).
        // The narrower IsTrap flag fires only on Opcode::Trap.
        //
        // Reads the *next* row's IsPadding via `trace_eval_next_row!` (the
        // IsPadding column is `#[mask_next_row]`).  When the current row is
        // a real Trap, the next row's IsPadding must be 1.
        {
            let is_padding_next = crate::trace::trace_eval_next_row!(
                trace_eval, Column::IsPadding
            );
            let is_trap_col = crate::trace::trace_eval!(trace_eval, Column::IsTrap);
            // Boolean witness.
            eval.add_constraint(
                is_trap_col[0].clone() * (E::F::one() - is_trap_col[0].clone())
            );
            // Terminal: real Trap forbids successor real row.
            eval.add_constraint(
                is_real.clone() * is_trap_col[0].clone()
                    * (E::F::one() - is_padding_next[0].clone())
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 13d: JumpInd target binding via JumpTableChip
        //
        // (1) Carry-chain constraint: pin JumpIndAddr to (val_b + imm) low 32 bits.
        //   For each byte i in 0..4:
        //     is_jump_ind · (jump_ind_addr[i] + carry[i]·256
        //                    - val_b[i] - imm_bytes[i] - carry_in[i]) = 0
        //   carry_in[0] = 0; carry_in[i>0] = carry[i-1]; carry[3] is the
        //   32-bit overflow, discarded.
        //
        // (2) JumpTableChip lookup: emit (jump_ind_addr[4], next_pc[4]) per
        //   JumpInd row, paired (2 emissions, ProgramMemoryChip-style mult
        //   doubling).  Multiplicity = is_jump_ind (degree 1).
        //
        // The producer side (JumpTableChip) commits via preprocessed Addr +
        // Target columns to `(2*(idx+1), jump_table[idx])` per program-
        // defined entry, so the lookup balances iff next_pc =
        // jump_table[(val_b+imm)/2 - 1] — exactly the runtime djump.
        {
            let is_jump_ind_col = crate::trace::trace_eval!(trace_eval, Column::IsJumpInd);
            let jump_ind_addr = crate::trace::trace_eval!(trace_eval, Column::JumpIndAddr);
            let jump_ind_carry = crate::trace::trace_eval!(trace_eval, Column::JumpIndCarry);
            let imm_bytes_col = crate::trace::trace_eval!(trace_eval, Column::ImmBytes);
            let next_pc_col = crate::trace::trace_eval!(trace_eval, Column::NextPc);
            // Boolean witness.
            eval.add_constraint(
                is_jump_ind_col[0].clone()
                    * (E::F::one() - is_jump_ind_col[0].clone())
            );
            for i in 0..4 {
                let carry_in: E::F = if i == 0 {
                    E::F::zero()
                } else {
                    jump_ind_carry[i - 1].clone()
                };
                eval.add_constraint(
                    is_jump_ind_col[0].clone() * (
                        jump_ind_addr[i].clone()
                            + jump_ind_carry[i].clone() * f256.clone()
                            - val_b[i].clone()
                            - imm_bytes_col[i].clone()
                            - carry_in
                    )
                );
            }
            // Paired JumpTable consumer (mult = is_jump_ind on each emission;
            // ProgramMemory-style pair doubling so the per-pair degree stays
            // bounded).  Tuple = (jump_ind_addr[4], next_pc[4]) — pinned to
            // ((val_b+imm) low 32 bits, runtime-jumped target) for JumpInd.
            let mut jt_tuple: Vec<E::F> = jump_ind_addr.to_vec();
            jt_tuple.extend_from_slice(&next_pc);
            eval.add_to_relation(RelationEntry::new(
                jump_table_lookup,
                is_jump_ind_col[0].clone().into(),
                &jt_tuple,
            ));
            eval.add_to_relation(RelationEntry::new(
                jump_table_lookup,
                is_jump_ind_col[0].clone().into(),
                &jt_tuple,
            ));
            let _ = next_pc_col; // reuse outer next_pc
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 13d-loadimmjumpind: LoadImmJumpInd target binding via JumpTable
        //
        // Same chip lookup as JumpInd, but with a different addr formula.
        // At runtime: addr = (regs[rb] + imm_y) mod 2^32, then djump.
        // val_d = regs[rb] for TwoRegTwoImm (default arm in trace fill),
        // imm_y is the new ImmYBytes column (bound to canonical via
        // prog_mem tuple).
        //
        // Carry chain: pin LoadImmJumpIndAddr to (val_d + imm_y) low 32.
        // Lookup: (LoadImmJumpIndAddr, NextPc) ∈ jump_table.
        //
        // Note: the load-side `regs[ra] = imm_x` is NOT yet bound — that's
        // a separate concern that needs the existing `is_move` family
        // extended.  Filed as a follow-up.
        {
            let is_lij_col = crate::trace::trace_eval!(trace_eval, Column::IsLoadImmJumpInd);
            let lij_addr = crate::trace::trace_eval!(trace_eval, Column::LoadImmJumpIndAddr);
            let lij_carry = crate::trace::trace_eval!(trace_eval, Column::LoadImmJumpIndCarry);
            let imm_y_bytes = crate::trace::trace_eval!(trace_eval, Column::ImmYBytes);
            // Boolean witness.
            eval.add_constraint(
                is_lij_col[0].clone() * (E::F::one() - is_lij_col[0].clone())
            );
            // Carry chain: lij_addr = val_d + imm_y_bytes (low 32 bits).
            for i in 0..4 {
                let carry_in: E::F = if i == 0 {
                    E::F::zero()
                } else {
                    lij_carry[i - 1].clone()
                };
                eval.add_constraint(
                    is_lij_col[0].clone() * (
                        lij_addr[i].clone()
                            + lij_carry[i].clone() * f256.clone()
                            - val_d[i].clone()
                            - imm_y_bytes[i].clone()
                            - carry_in
                    )
                );
            }
            // Paired JumpTable consumer.
            let mut lij_tuple: Vec<E::F> = lij_addr.to_vec();
            lij_tuple.extend_from_slice(&next_pc);
            eval.add_to_relation(RelationEntry::new(
                jump_table_lookup,
                is_lij_col[0].clone().into(),
                &lij_tuple,
            ));
            eval.add_to_relation(RelationEntry::new(
                jump_table_lookup,
                is_lij_col[0].clone().into(),
                &lij_tuple,
            ));
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 15-load-result: bind Result to MemValue on Load steps
        //
        // For each byte i, on a load step (is_load=1), if byte i is within
        // the load's width (mem_byte_active[i]=1), result[i] must equal
        // mem_value[i].  Closes the gap where forging
        // step.regs_after[dest_reg] on a Load wasn't caught when no later
        // step read the destination register: previously the AIR linked
        // Result to the register-memory ledger and MemValue to the memory
        // ledger separately, but never equated them within the load step.
        //
        // Inactive bytes (i >= MemSize): unsigned loads must be 0,
        // signed loads must be 0xFF · sign_bit_of_top_active_byte.
        // Phase 20 closes this gap — see "Phase 20: signed-load
        // inactive-byte sign-extension" block below for the
        // pinning + per-byte equality constraint.
        let is_load_local = crate::trace::trace_eval!(trace_eval, Column::IsLoad);
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                is_load_local[0].clone()
                    * mem_byte_active[i].clone()
                    * (result[i].clone() - mem_value[i].clone()),
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 24: bind MemValue ↔ val_b on Direct stores
        //
        // For StoreU8 / StoreU16 / StoreU32 / StoreU64 (the OneRegOneImm
        // category) the trace fill's default arm puts `regs[ra]` into
        // val_b — that's the source value the interpreter writes to
        // memory.  Pre-Phase-24 the AIR didn't bind MemValue to any
        // register or immediate, so a prover could write any byte
        // string to memory on a Store row regardless of regs[ra].
        // The active-byte equality is enough: inactive bytes (i ≥
        // MemSize) of MemValue aren't read by the memory chip
        // (mem_byte_active[i]=0 zeros their lookup multiplicity).
        //
        // Coverage caveat: StoreInd* / StoreImm* / StoreImmInd* leave
        // the source value in different places (regs[ra] for
        // StoreInd, imm_y for StoreImm/StoreImmInd) that aren't in
        // val_b — those bindings need their own follow-ups.
        {
            let is_store_direct_local = crate::trace::trace_eval!(trace_eval, Column::IsStoreDirect);
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_store_direct_local[0].clone()
                        * mem_byte_active[i].clone()
                        * (mem_value[i].clone() - val_b[i].clone()),
                );
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 28: bind MemValue ↔ RegValA on indirect register-source stores
        //
        // For StoreInd[U][8/16/32/64] (TwoRegOneImm), val_b holds
        // the *base* register `regs[rb]` — not the value being
        // stored.  The value is `regs[ra]`, which lands in the new
        // RegValA column (filled in trace fill on StoreInd rows;
        // bound to the actual register snapshot via the paired
        // register-memory ledger producer in the Phase 9 block).
        //
        // Per-byte equality on active bytes:
        //   IsStoreInd · mem_byte_active[i] · (mem_value[i] −
        //                                      reg_val_a[i]) = 0
        {
            let is_store_ind_p28 = crate::trace::trace_eval!(trace_eval, Column::IsStoreInd);
            let reg_val_a_p28 = crate::trace::trace_eval!(trace_eval, Column::RegValA);
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_store_ind_p28[0].clone()
                        * mem_byte_active[i].clone()
                        * (mem_value[i].clone() - reg_val_a_p28[i].clone()),
                );
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 25: bind MemAddr ↔ ImmBytes[0..4] on direct loads/stores
        //
        // For LoadU8/I8/U16/I16/U32/I32/U64 and StoreU8/16/32/64
        // (the OneRegOneImm-category direct memory ops) the runtime
        // address is just the immediate (`addr = imm` per
        // javm/src/vm.rs's RegImm-arm impls).  The interpreter uses
        // `let addr = imm as u32`, so MemAddr's 4 bytes are the low
        // 4 bytes of the canonical immediate.  ImmBytes is already
        // pinned to that immediate by Phase 13b's ProgramMemory
        // tuple, so the binding is a 4-byte equality.
        //
        // Pre-Phase-25 MemAddr was prover-witnessed; combined with
        // Phase 24's MemValue ↔ val_b binding, a malicious prover
        // could store the right value at the wrong address (or
        // load from the wrong address, returning a value that
        // happens to be there).  Phase 25 closes the address half
        // for direct ops; indirect addressing (`addr = regs[r] + imm`,
        // covers LoadInd* / StoreInd* / StoreImmInd*) needs a
        // separate carry-chain binding (deferred).
        {
            let is_load_direct_local = crate::trace::trace_eval!(trace_eval, Column::IsLoadDirect);
            let is_store_direct_local = crate::trace::trace_eval!(trace_eval, Column::IsStoreDirect);
            // Phase 27 widens this to also cover StoreImm direct
            // (TwoImm with `addr = imm_x`).  step.imm = imm_x for
            // TwoImm, so ImmBytes already pins the address bytes.
            let is_store_imm_direct_local = crate::trace::trace_eval!(trace_eval, Column::IsStoreImmDirect);
            let imm_bytes_local = crate::trace::trace_eval!(trace_eval, Column::ImmBytes);
            let direct_mem_active = is_load_direct_local[0].clone()
                + is_store_direct_local[0].clone()
                + is_store_imm_direct_local[0].clone();
            for i in 0..4 {
                eval.add_constraint(
                    direct_mem_active.clone()
                        * (mem_addr[i].clone() - imm_bytes_local[i].clone())
                );
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 27: bind MemValue ↔ ImmYBytes on StoreImm / StoreImmInd
        //
        // For all 8 immediate-source store opcodes (StoreImm[U] and
        // StoreImmInd[U] of width 1/2/4/8) the value written to
        // memory is `imm_y`.  ImmYBytes already carries the low 4
        // bytes of step.imm_y on every row (filled in Phase
        // 13d-loadimmjumpind's trace fill, pinned in
        // ProgramMemoryChip via ImmYCanon).  Per-byte equality on
        // active bytes:
        //   IsStoreImmAny · mem_byte_active[i] · (mem_value[i] −
        //                                          imm_y_bytes[i]) = 0
        // for `i ∈ 0..4`.
        //
        // Out of scope (deferred): MemSize=8 stores' imm_y high 4
        // bytes — would need an ImmYBytesHi[4] column pinned in
        // prog_mem analogous to ImmYCanon.  StoreImmU64 and
        // StoreImmIndU64 with imm_y > 2^32 are therefore still
        // partially prover-trusted (high 4 bytes of value
        // unbound).  The low 4 bytes of MemValue ARE bound.
        {
            let is_store_imm_any_local = crate::trace::trace_eval!(trace_eval, Column::IsStoreImmAny);
            let imm_y_bytes_local = crate::trace::trace_eval!(trace_eval, Column::ImmYBytes);
            for i in 0..4 {
                eval.add_constraint(
                    is_store_imm_any_local[0].clone()
                        * mem_byte_active[i].clone()
                        * (mem_value[i].clone() - imm_y_bytes_local[i].clone())
                );
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 26: bind MemAddr ↔ (val_b + ImmBytes) mod 2^32 on indirect ops
        //
        // For LoadInd[U/I][8/16/32/64], StoreInd[U][8/16/32/64], and
        // StoreImmInd[U][8/16/32/64] the runtime address is
        // `regs[base] + imm` (where base = rb for the TwoRegOneImm
        // pair, ra for OneRegTwoImm).  In every case the trace fill
        // puts the base register's value into val_b — TwoRegOneImm's
        // arm gives `val_b = regs[reg_b]`, OneRegTwoImm falls
        // through to the default arm `val_b = regs[reg_a]` and
        // reg_a is decoded as the base for OneRegTwoImm — so a
        // single uniform formula works:
        //
        //   MemAddr = (val_b + ImmBytes) mod 2^32
        //
        // Encoded as a 4-byte add-with-carry chain, mirroring the
        // existing JumpIndAddr / LoadImmJumpIndAddr patterns.
        // Carry-out at byte 3 is the 32-bit overflow, discarded.
        // Per-byte carry boolean (val_b[i] + ImmBytes[i] + carry_in
        // ≤ 511 with carry_in ≤ 1, so carry_out ≤ 1).
        {
            let is_mem_indirect_local = crate::trace::trace_eval!(trace_eval, Column::IsMemIndirect);
            let mem_addr_carry = crate::trace::trace_eval!(trace_eval, Column::MemAddrCarry);
            let imm_bytes_local = crate::trace::trace_eval!(trace_eval, Column::ImmBytes);
            // Boolean carry per byte (gated by is_real so range is
            // forced even on non-indirect rows where the chain is
            // dormant).
            for i in 0..4 {
                eval.add_constraint(
                    is_real.clone() * mem_addr_carry[i].clone()
                        * (E::F::one() - mem_addr_carry[i].clone())
                );
            }
            // Add-with-carry chain (gated on is_mem_indirect).
            for i in 0..4 {
                let carry_in = if i == 0 {
                    E::F::zero()
                } else {
                    mem_addr_carry[i - 1].clone()
                };
                eval.add_constraint(
                    is_mem_indirect_local[0].clone() * (
                        mem_addr[i].clone()
                            + mem_addr_carry[i].clone() * f256.clone()
                            - val_b[i].clone()
                            - imm_bytes_local[i].clone()
                            - carry_in
                    )
                );
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 20: signed-load inactive-byte sign-extension
        //
        // For load rows, every inactive byte (mem_byte_active[i] = 0)
        // must equal 0xFF · LoadSignBit:
        //   - Unsigned loads: IsLoadI8 = IsLoadI16 = IsLoadI32 = 0 →
        //     LoadSignSrc = 0 → LoadSignBit = 0 → result[i] = 0.
        //   - Signed loads: LoadSignSrc multiplexes the highest active
        //     byte (result[0] for I8, result[1] for I16, result[3] for
        //     I32); LoadSignBit pins to its bit 7 via a nibble-AND
        //     lookup (block placed alongside Phase 17 sign-bit pins).
        //     result[i] = 0xFF · LoadSignBit for all inactive bytes.
        //
        // This closes the gap where a prover could write garbage into
        // the high bytes of a load result.  The interpreter writes 0
        // (unsigned) / 0xFF (signed-extended) per the JAVM spec.
        {
            let f_is_load_i8 = crate::trace::trace_eval!(trace_eval, Column::IsLoadI8);
            let f_is_load_i16 = crate::trace::trace_eval!(trace_eval, Column::IsLoadI16);
            let f_is_load_i32 = crate::trace::trace_eval!(trace_eval, Column::IsLoadI32);
            let load_sign_src = crate::trace::trace_eval!(trace_eval, Column::LoadSignSrc);
            let load_sign_bit = crate::trace::trace_eval!(trace_eval, Column::LoadSignBit);

            // Boolean witnesses + at-most-one-active.
            for f in [&f_is_load_i8, &f_is_load_i16, &f_is_load_i32] {
                eval.add_constraint(f[0].clone() * (E::F::one() - f[0].clone()));
            }
            // Mutex: sum ≤ 1.  Combined with each being boolean and
            // gated to only fire on signed-load opcodes (via the
            // ProgramMemory consumer pinning the canonical decoding),
            // exactly one is 1 on a signed-load row.

            // LoadSignSrc multiplex.
            eval.add_constraint(
                load_sign_src[0].clone()
                    - f_is_load_i8[0].clone() * result[0].clone()
                    - f_is_load_i16[0].clone() * result[1].clone()
                    - f_is_load_i32[0].clone() * result[3].clone()
            );

            // Inactive-byte binding for all loads: result[i] = 0xFF · LoadSignBit
            // when mem_byte_active[i] = 0.  Skip i=0 (always active for any
            // non-zero MemSize, so mem_byte_active[0] = 1 ⇒ gate = 0).
            let f_ff_p20: E::F = E::F::from(BaseField::from(255));
            for i in 1..WORD_SIZE {
                eval.add_constraint(
                    is_load_local[0].clone()
                        * (E::F::one() - mem_byte_active[i].clone())
                        * (result[i].clone() - f_ff_p20.clone() * load_sign_bit[0].clone())
                );
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 17: pin SignBitB / SignBitD / SignBitQ / SignBitR to bit 7
        // of their respective source bytes via nibble-AND lookups.  Closes
        // the soundness gap shared with Phase 12c — until now those four
        // sign bits were prover-witnessed with no in-circuit tie to the
        // actual byte's bit 7, so a malicious prover could lie on rows
        // where the AIR uses them (signed compare/branch, MulUpper SS/SU,
        // DivS sign-correction).
        //
        // For each (sign_bit, source_byte, hi_nib) triple we emit:
        //   (hi_nib, 8, 8·sign_bit) — pins sign_bit = bit 3 of hi_nib.
        //   (source − 16·hi_nib, 0xF, source − 16·hi_nib) — range-checks
        //     the low nibble (forces it ∈ [0, 15] AND lo&0xF = lo, which
        //     pins the decomposition source = 16·hi_nib + lo).
        // Together: sign_bit = bit 7 of source.
        //
        // Source bytes:
        //   SignBitB → SignSrcB = (1−Is32Bit)·val_b[7] + Is32Bit·val_b[3]
        //   SignBitD → SignSrcD = (1−Is32Bit)·val_d[7] + Is32Bit·val_d[3]
        //   SignBitQ → div_quotient[7]  (DivS chain is is_64bit-only)
        //   SignBitR → div_remainder[7]
        //
        // Multiplicity = is_real on every row (8 emissions × is_real).
        // Tuple shape stays degree-1, so we hit the BitwiseLookupChip with
        // 8 emissions per real row; bitwise_and_counts is charged
        // accordingly.  Even-emission block, placed last → no pair-shape
        // reshuffle (CONSTRAINTS.md rule 2).
        //
        // Ground constraint: pin SignSrcB / SignSrcD / SignSrcQ /
        // SignSrcR to the canonical Is32Bit-multiplexed source byte.
        {
            let is_32bit_local = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
            let sign_src_b = crate::trace::trace_eval!(trace_eval, Column::SignSrcB);
            let sign_src_d = crate::trace::trace_eval!(trace_eval, Column::SignSrcD);
            let sign_src_q = crate::trace::trace_eval!(trace_eval, Column::SignSrcQ);
            let sign_src_r = crate::trace::trace_eval!(trace_eval, Column::SignSrcR);
            let div_quotient_local = crate::trace::trace_eval!(trace_eval, Column::DivQuotient);
            let div_remainder_local = crate::trace::trace_eval!(trace_eval, Column::DivRemainder);
            let one_minus_32 = E::F::one() - is_32bit_local[0].clone();
            eval.add_constraint(
                is_real.clone() * (
                    sign_src_b[0].clone()
                        - one_minus_32.clone() * val_b[7].clone()
                        - is_32bit_local[0].clone() * val_b[3].clone()
                )
            );
            eval.add_constraint(
                is_real.clone() * (
                    sign_src_d[0].clone()
                        - one_minus_32.clone() * val_d[7].clone()
                        - is_32bit_local[0].clone() * val_d[3].clone()
                )
            );
            eval.add_constraint(
                is_real.clone() * (
                    sign_src_q[0].clone()
                        - one_minus_32.clone() * div_quotient_local[7].clone()
                        - is_32bit_local[0].clone() * div_quotient_local[3].clone()
                )
            );
            eval.add_constraint(
                is_real.clone() * (
                    sign_src_r[0].clone()
                        - one_minus_32 * div_remainder_local[7].clone()
                        - is_32bit_local[0].clone() * div_remainder_local[3].clone()
                )
            );
        }

        // Sign-bit nibble lookups (last lookup block before finalize).
        {
            let sign_src_b = crate::trace::trace_eval!(trace_eval, Column::SignSrcB);
            let sign_src_d = crate::trace::trace_eval!(trace_eval, Column::SignSrcD);
            let sign_b_hi = crate::trace::trace_eval!(trace_eval, Column::SignBHiNib);
            let sign_d_hi = crate::trace::trace_eval!(trace_eval, Column::SignDHiNib);
            let sign_q_hi = crate::trace::trace_eval!(trace_eval, Column::SignQHiNib);
            let sign_r_hi = crate::trace::trace_eval!(trace_eval, Column::SignRHiNib);
            let sign_bit_b = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
            let sign_bit_d = crate::trace::trace_eval!(trace_eval, Column::SignBitD);
            let sign_bit_q = crate::trace::trace_eval!(trace_eval, Column::SignBitQ);
            let sign_bit_r = crate::trace::trace_eval!(trace_eval, Column::SignBitR);
            let sign_src_q = crate::trace::trace_eval!(trace_eval, Column::SignSrcQ);
            let sign_src_r = crate::trace::trace_eval!(trace_eval, Column::SignSrcR);
            let eight_p17: E::F = E::F::from(BaseField::from(8));
            let sixteen_p17: E::F = E::F::from(BaseField::from(16));
            let fifteen_p17: E::F = E::F::from(BaseField::from(15));

            // SignBitB: (hi_b, 8, 8·bit_b), (src_b − 16·hi_b, 0xF, same).
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[
                    sign_b_hi[0].clone(),
                    eight_p17.clone(),
                    sign_bit_b[0].clone() * eight_p17.clone(),
                ],
            ));
            let lo_b = sign_src_b[0].clone() - sign_b_hi[0].clone() * sixteen_p17.clone();
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[lo_b.clone(), fifteen_p17.clone(), lo_b],
            ));

            // SignBitD.
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[
                    sign_d_hi[0].clone(),
                    eight_p17.clone(),
                    sign_bit_d[0].clone() * eight_p17.clone(),
                ],
            ));
            let lo_d = sign_src_d[0].clone() - sign_d_hi[0].clone() * sixteen_p17.clone();
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[lo_d.clone(), fifteen_p17.clone(), lo_d],
            ));

            // SignBitQ — source is the multiplexed SignSrcQ (Phase 18:
            // div_quotient[7] in 64-bit, div_quotient[3] in 32-bit).
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[
                    sign_q_hi[0].clone(),
                    eight_p17.clone(),
                    sign_bit_q[0].clone() * eight_p17.clone(),
                ],
            ));
            let lo_q = sign_src_q[0].clone() - sign_q_hi[0].clone() * sixteen_p17.clone();
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[lo_q.clone(), fifteen_p17.clone(), lo_q],
            ));

            // SignBitR — source is SignSrcR (multiplexed).
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[
                    sign_r_hi[0].clone(),
                    eight_p17.clone(),
                    sign_bit_r[0].clone() * eight_p17.clone(),
                ],
            ));
            let lo_r = sign_src_r[0].clone() - sign_r_hi[0].clone() * sixteen_p17.clone();
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[lo_r.clone(), fifteen_p17.clone(), lo_r],
            ));

            // Phase 19: SignBitResult — pin to bit 7 of result[3].  No
            // Is32Bit multiplex needed: on 64-bit rows the result-
            // sign-extension constraint we'll add below is gated on
            // is_32bit and won't fire, so SignBitResult's value is
            // unused.  Keeping the same shape as the other 4 sign-bit
            // pins keeps the lookup-pair structure uniform.
            let sign_bit_result = crate::trace::trace_eval!(trace_eval, Column::SignBitResult);
            let result_hi = crate::trace::trace_eval!(trace_eval, Column::ResultHiNib);
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[
                    result_hi[0].clone(),
                    eight_p17.clone(),
                    sign_bit_result[0].clone() * eight_p17.clone(),
                ],
            ));
            let lo_res = result[3].clone() - result_hi[0].clone() * sixteen_p17.clone();
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[lo_res.clone(), fifteen_p17.clone(), lo_res],
            ));

            // Phase 20: LoadSignBit — pin to bit 7 of LoadSignSrc.
            let load_sign_bit_pin = crate::trace::trace_eval!(trace_eval, Column::LoadSignBit);
            let load_sign_hi = crate::trace::trace_eval!(trace_eval, Column::LoadSignHiNib);
            let load_sign_src_pin = crate::trace::trace_eval!(trace_eval, Column::LoadSignSrc);
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[
                    load_sign_hi[0].clone(),
                    eight_p17.clone(),
                    load_sign_bit_pin[0].clone() * eight_p17.clone(),
                ],
            ));
            let lo_load = load_sign_src_pin[0].clone() - load_sign_hi[0].clone() * sixteen_p17.clone();
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[lo_load.clone(), fifteen_p17.clone(), lo_load],
            ));

            let _ = sixteen_p17; // already consumed via lo_load
        }

        // Phase 21: range-check DivCmpDiff bytes via Range256 (the
        // BitwiseLookupChip handles only nibbles, so byte-range needs
        // the dedicated 256-entry table).  Placed at end before the
        // sign-bit nibble lookups would otherwise have ended.  8
        // emissions per real row, gated by is_real, even count.
        {
            let div_cmp_diff_p21 = crate::trace::trace_eval!(trace_eval, Column::DivCmpDiff);
            for i in 0..WORD_SIZE {
                eval.add_to_relation(RelationEntry::new(
                    range256_lookup,
                    is_real.clone().into(),
                    &[div_cmp_diff_p21[i].clone()],
                ));
            }
        }

        // Phase 30: range-check AbsCmpDiff bytes via Range256.  Same
        // pattern as Phase 21 — 8 emissions per real row, even count.
        {
            let abs_cmp_diff_p30 = crate::trace::trace_eval!(trace_eval, Column::AbsCmpDiff);
            for i in 0..WORD_SIZE {
                eval.add_to_relation(RelationEntry::new(
                    range256_lookup,
                    is_real.clone().into(),
                    &[abs_cmp_diff_p30[i].clone()],
                ));
            }
        }

        // ── Phase 54a/b/c/d: MultiplicationLookup producer ──
        // Tuple (35 limbs): val_b[8] + val_d[8] + result[8] +
        //   sign_bit_b + sign_bit_d + 4 rotate flags + 5 mul flags.
        // MulChip consumes the same tuple per real row.  Moved to MulChip:
        //   - schoolbook carry chain (54b): pins upl/uph/mul_high.
        //   - sign correction (54c): pins result for is_mul_upper rows.
        //   - result-variant dispatch (54d): pins result for non-upper
        //     mul rows from upl ± mul_high based on rotate flags.
        {
            let f_is_mul_p54 = crate::trace::trace_eval!(trace_eval, Column::IsMul);
            let f_mu_uu_p54 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperUU);
            let f_mu_su_p54 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSU);
            let f_mu_ss_p54 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSS);
            let f_is_32bit_p54 = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
            let f_rot_l64_p54 = crate::trace::trace_eval!(trace_eval, Column::IsRotateL64);
            let f_rot_r64_p54 = crate::trace::trace_eval!(trace_eval, Column::IsRotateR64);
            let f_rot_l32_p54 = crate::trace::trace_eval!(trace_eval, Column::IsRotateL32);
            let f_rot_r32_p54 = crate::trace::trace_eval!(trace_eval, Column::IsRotateR32);
            let val_b_p54 = crate::trace::trace_eval!(trace_eval, Column::ValB);
            let val_d_p54 = crate::trace::trace_eval!(trace_eval, Column::ValD);
            let result_p54 = crate::trace::trace_eval!(trace_eval, Column::Result);
            let sign_bit_b_p54 = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
            let sign_bit_d_p54 = crate::trace::trace_eval!(trace_eval, Column::SignBitD);
            let is_mul_lo_e = f_is_mul_p54[0].clone()
                - f_mu_uu_p54[0].clone()
                - f_mu_su_p54[0].clone()
                - f_mu_ss_p54[0].clone();
            let mut tuple_p54: Vec<E::F> = Vec::with_capacity(35);
            tuple_p54.extend_from_slice(&val_b_p54);
            tuple_p54.extend_from_slice(&val_d_p54);
            tuple_p54.extend_from_slice(&result_p54);
            tuple_p54.push(sign_bit_b_p54[0].clone());
            tuple_p54.push(sign_bit_d_p54[0].clone());
            tuple_p54.push(f_rot_l64_p54[0].clone());
            tuple_p54.push(f_rot_r64_p54[0].clone());
            tuple_p54.push(f_rot_l32_p54[0].clone());
            tuple_p54.push(f_rot_r32_p54[0].clone());
            tuple_p54.push(is_mul_lo_e);
            tuple_p54.push(f_mu_uu_p54[0].clone());
            tuple_p54.push(f_mu_su_p54[0].clone());
            tuple_p54.push(f_mu_ss_p54[0].clone());
            tuple_p54.push(f_is_32bit_p54[0].clone());
            for _ in 0..2 {
                eval.add_to_relation(RelationEntry::new(
                    mul_lookup,
                    f_is_mul_p54[0].clone().into(),
                    &tuple_p54,
                ));
            }
        }

        // ── Phase 54g: DivRemLookup producer ──
        // Tuple (43 limbs): val_b[8] + val_d[8] + div_quotient[8] +
        //   div_remainder[8] + div_corr_hi[8] + is_div_rem +
        //   div_by_zero + is_32bit.  Multiplicity = is_div_rem.
        {
            let val_b_p54g = crate::trace::trace_eval!(trace_eval, Column::ValB);
            let val_d_p54g = crate::trace::trace_eval!(trace_eval, Column::ValD);
            let dq_p54g = crate::trace::trace_eval!(trace_eval, Column::DivQuotient);
            let dr_p54g = crate::trace::trace_eval!(trace_eval, Column::DivRemainder);
            let dch_p54g = crate::trace::trace_eval!(trace_eval, Column::DivCorrHi);
            let dbz_p54g = crate::trace::trace_eval!(trace_eval, Column::DivByZero);
            let is_dr_p54g = crate::trace::trace_eval!(trace_eval, Column::IsDivRem);
            let is_32_p54g = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
            let mut tuple_p54g: Vec<E::F> = Vec::with_capacity(43);
            tuple_p54g.extend_from_slice(&val_b_p54g);
            tuple_p54g.extend_from_slice(&val_d_p54g);
            tuple_p54g.extend_from_slice(&dq_p54g);
            tuple_p54g.extend_from_slice(&dr_p54g);
            tuple_p54g.extend_from_slice(&dch_p54g);
            tuple_p54g.push(is_dr_p54g[0].clone());
            tuple_p54g.push(dbz_p54g[0].clone());
            tuple_p54g.push(is_32_p54g[0].clone());
            for _ in 0..2 {
                eval.add_to_relation(RelationEntry::new(
                    divrem_lookup,
                    is_dr_p54g[0].clone().into(),
                    &tuple_p54g,
                ));
            }
        }

        // ── Phase 54f: CompareLookup producer ──
        // Tuple (17 limbs): val_b[8] + val_d[8] + cmp_lt_flag.
        // Multiplicity = is_compare + is_branch.  Two paired emissions.
        {
            let val_b_p54f = crate::trace::trace_eval!(trace_eval, Column::ValB);
            let val_d_p54f = crate::trace::trace_eval!(trace_eval, Column::ValD);
            let cmp_lt_p54f = crate::trace::trace_eval!(trace_eval, Column::CmpLtFlag);
            let mut tuple_p54f: Vec<E::F> = Vec::with_capacity(17);
            tuple_p54f.extend_from_slice(&val_b_p54f);
            tuple_p54f.extend_from_slice(&val_d_p54f);
            tuple_p54f.push(cmp_lt_p54f[0].clone());
            for _ in 0..2 {
                eval.add_to_relation(RelationEntry::new(
                    compare_lookup,
                    is_cmp_or_branch.clone().into(),
                    &tuple_p54f,
                ));
            }
        }

        // ── Phase 54e: BitwiseLookup producer ──
        // Tuple (30 limbs): val_b[8] + val_d[8] + result[8] + 6 sub-flags.
        // Multiplicity = is_bitwise_e (sum of 6 sub-flags).  Two paired
        // emissions for finalize_logup_in_pairs.
        {
            let val_b_p54e = crate::trace::trace_eval!(trace_eval, Column::ValB);
            let val_d_p54e = crate::trace::trace_eval!(trace_eval, Column::ValD);
            let result_p54e = crate::trace::trace_eval!(trace_eval, Column::Result);
            let f_and = crate::trace::trace_eval!(trace_eval, Column::IsAnd);
            let f_or = crate::trace::trace_eval!(trace_eval, Column::IsOr);
            let f_xor = crate::trace::trace_eval!(trace_eval, Column::IsXor);
            let f_andinv = crate::trace::trace_eval!(trace_eval, Column::IsAndInv);
            let f_orinv = crate::trace::trace_eval!(trace_eval, Column::IsOrInv);
            let f_xnor = crate::trace::trace_eval!(trace_eval, Column::IsXnor);
            let is_bitwise_p54e = f_and[0].clone() + f_or[0].clone() + f_xor[0].clone()
                + f_andinv[0].clone() + f_orinv[0].clone() + f_xnor[0].clone();
            let mut tuple_p54e: Vec<E::F> = Vec::with_capacity(30);
            tuple_p54e.extend_from_slice(&val_b_p54e);
            tuple_p54e.extend_from_slice(&val_d_p54e);
            tuple_p54e.extend_from_slice(&result_p54e);
            tuple_p54e.push(f_and[0].clone());
            tuple_p54e.push(f_or[0].clone());
            tuple_p54e.push(f_xor[0].clone());
            tuple_p54e.push(f_andinv[0].clone());
            tuple_p54e.push(f_orinv[0].clone());
            tuple_p54e.push(f_xnor[0].clone());
            for _ in 0..2 {
                eval.add_to_relation(RelationEntry::new(
                    bitwise_lookup,
                    is_bitwise_p54e.clone().into(),
                    &tuple_p54e,
                ));
            }
        }

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for CpuChip {
    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        trace_fill::generate_main_trace(side_note)
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        interaction::generate_interaction_trace(component_trace, lookup_elements)
    }
}
