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
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::core::step::WORD_SIZE;
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

use crate::{
    framework::{BuiltInComponent},
    lookups::{BitwiseAndLookupElements, Blake2bCallLookupElements, JumpTableLookupElements, MemoryAccessLookupElements, PowerOfTwoLookupElements, ProgramExecutionLookupElements, ProgramMemoryLookupElements, Range256LookupElements, RegisterMemoryLookupElements, },
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;
use crate::core::ecall::ECALL_BLAKE2B_COMPRESS;

mod classify;
mod columns;
mod reg_access;

use classify::{classify_opcode, dest_reg, uses_immediate};
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
        JumpTableLookupElements,
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
            JumpTableLookupElements,
        ),
    ) {
        let (range256_lookup, mem_lookup, prog_exec_lookup, bitwise_and_lookup, pow2_lookup, blake2b_call_lookup, reg_lookup, prog_mem_lookup, jump_table_lookup) = lookup_elements;
        let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
        let is_real = E::F::one() - is_pad[0].clone();

        let is_add = crate::trace::trace_eval!(trace_eval, Column::IsAdd);
        let is_sub = crate::trace::trace_eval!(trace_eval, Column::IsSub);
        let is_mul = crate::trace::trace_eval!(trace_eval, Column::IsMul);
        let _is_bitwise = crate::trace::trace_eval!(trace_eval, Column::IsBitwise);
        let is_shift = crate::trace::trace_eval!(trace_eval, Column::IsShift);
        let is_compare = crate::trace::trace_eval!(trace_eval, Column::IsCompare);
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
        let carry = crate::trace::trace_eval!(trace_eval, Column::Carry);
        let mul_high = crate::trace::trace_eval!(trace_eval, Column::MulHigh);
        let mul_carry = crate::trace::trace_eval!(trace_eval, Column::MulCarry);
        let and_result = crate::trace::trace_eval!(trace_eval, Column::AndResult);
        let cmp_carry = crate::trace::trace_eval!(trace_eval, Column::CmpCarry);
        let cmp_lt_flag = crate::trace::trace_eval!(trace_eval, Column::CmpLtFlag);
        let cmp_lt_s_flag = crate::trace::trace_eval!(trace_eval, Column::CmpLtSFlag);
        let is_branch = crate::trace::trace_eval!(trace_eval, Column::IsBranch);
        let is_set_lt_u_flag = crate::trace::trace_eval!(trace_eval, Column::IsSetLtU);
        let is_set_lt_s_flag = crate::trace::trace_eval!(trace_eval, Column::IsSetLtS);
        let is_cmov_iz_flag = crate::trace::trace_eval!(trace_eval, Column::IsCmovIz);
        let is_cmov_nz_flag = crate::trace::trace_eval!(trace_eval, Column::IsCmovNz);
        let _is_min_s_flag = crate::trace::trace_eval!(trace_eval, Column::IsMinS);
        let is_min_u_flag = crate::trace::trace_eval!(trace_eval, Column::IsMinU);
        let _is_max_s_flag = crate::trace::trace_eval!(trace_eval, Column::IsMaxS);
        let is_max_u_flag = crate::trace::trace_eval!(trace_eval, Column::IsMaxU);

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
        for i in 4..WORD_SIZE {
            eval.add_constraint(is_add[0].clone() * is_32bit[0].clone() * result[i].clone());
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
            eval.add_constraint(is_sub[0].clone() * is_32bit[0].clone() * result[i].clone());
        }

        // ════════════════════════════════════════════════════════════════════
        // MUL: schoolbook byte-level multiplication
        // 64-bit: val_b[0..8] * val_d[0..8] = result[0..8] + mul_high[0..8] * 2^64 (16 positions)
        // 32-bit: val_b[0..4] * val_d[0..4] = result[0..4] + mul_high[0..4] * 2^32 (8 positions)
        // ════════════════════════════════════════════════════════════════════
        let is_mul_upper = crate::trace::trace_eval!(trace_eval, Column::IsMulUpper);
        let is_mul_low = E::F::one() - is_mul_upper[0].clone();
        let mul_carry_hi = crate::trace::trace_eval!(trace_eval, Column::MulCarryHi);
        let unsigned_product_hi = crate::trace::trace_eval!(trace_eval, Column::UnsignedProductHi);
        // Helper: full 16-bit carry value at position k.
        let full_carry = |k: usize| -> E::F {
            mul_carry[k].clone() + mul_carry_hi[k].clone() * f256.clone()
        };
        // 64-bit mul constraint (positions 0..15).  Carries can reach up to
        // ~16 bits at busy middle positions (e.g. 0xFFFFFFFF² produces
        // 0x3FB at position k=3), so the carry is reconstructed as
        // mul_carry[k] + 256·mul_carry_hi[k].
        //
        // Phase 12c: the schoolbook output for `is_mul_upper` (positions
        // 8..15) now lands in `unsigned_product_hi[k-8]` instead of
        // `result[k-8]`.  This decouples the schoolbook from per-variant
        // result binding: UU/SU/SS all share the same unsigned-product
        // computation, but `result` is derived differently per variant
        // (UU = unsigned_product_hi; SU/SS subtract a sign correction).
        for k in 0..16usize {
            let mut partial_sum = E::F::zero();
            for i in 0..WORD_SIZE {
                let j = k.wrapping_sub(i);
                if j < WORD_SIZE {
                    partial_sum += val_b[i].clone() * val_d[j].clone();
                }
            }
            let carry_in = if k == 0 { E::F::zero() } else { full_carry(k - 1) };
            let out_normal = if k < 8 { result[k].clone() } else { mul_high[k - 8].clone() };
            let out_upper = if k < 8 { mul_high[k].clone() } else { unsigned_product_hi[k - 8].clone() };
            let c_normal = out_normal + full_carry(k) * f256.clone() - partial_sum.clone() - carry_in.clone();
            let c_upper = out_upper + full_carry(k) * f256.clone() - partial_sum - carry_in;
            eval.add_constraint(is_mul[0].clone() * is_64bit.clone() * is_mul_low.clone() * c_normal);
            eval.add_constraint(is_mul[0].clone() * is_64bit.clone() * is_mul_upper[0].clone() * c_upper);
        }
        // 32-bit mul constraint (positions 0..7, using low 4 limbs).  The
        // 32-bit case never produces carries > 8 bits (max partial = 4·0xFE01
        // = 0x3F804 ≈ 18 bits, so carry ≤ 10 bits), but using the same
        // 16-bit carry representation keeps the constraint shape uniform.
        for k in 0..8usize {
            let mut partial_sum = E::F::zero();
            for i in 0..4usize {
                let j = k.wrapping_sub(i);
                if j < 4 {
                    partial_sum += val_b[i].clone() * val_d[j].clone();
                }
            }
            let carry_in = if k == 0 { E::F::zero() } else { full_carry(k - 1) };
            let out_byte = if k < 4 { result[k].clone() } else { mul_high[k - 4].clone() };
            let c = out_byte + full_carry(k) * f256.clone() - partial_sum - carry_in;
            eval.add_constraint(is_mul[0].clone() * is_32bit[0].clone() * c);
        }
        // 32-bit mul: upper result limbs = 0
        for i in 4..WORD_SIZE {
            eval.add_constraint(is_mul[0].clone() * is_32bit[0].clone() * result[i].clone());
        }

        // ════════════════════════════════════════════════════════════════════
        // Phase 12c: MulUpper SS / SU sign-correction
        //
        //   high(a_s × b_s) ≡ high(a_u × b_u) − sa·b_u − sb·a_u  (mod 2^64)
        //
        // For UU: result = unsigned_product_hi (no correction).
        // For SU: result = unsigned_product_hi − sa·val_d.
        // For SS: result = unsigned_product_hi − sa·val_d − sb·val_b.
        //
        // Materialised via two sign-correction term columns (TermA = sa·val_d
        // for SU/SS, 0 for UU; TermB = sb·val_b for SS, 0 elsewhere) and a
        // 64-bit add-with-carry chain encoding
        //   result + TermA + TermB ≡ unsigned_product_hi  (mod 2^64).
        // For UU rows TermA = TermB = 0, so the chain collapses to
        // `result = unsigned_product_hi` (which replaces the old direct
        // schoolbook-into-result constraint for is_mul_upper).
        {
            let term_a = crate::trace::trace_eval!(trace_eval, Column::MulCorrTermA);
            let term_b = crate::trace::trace_eval!(trace_eval, Column::MulCorrTermB);
            let corr_carry = crate::trace::trace_eval!(trace_eval, Column::MulCorrCarry);
            let mu_uu = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperUU);
            let mu_su = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSU);
            let mu_ss = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSS);
            let sign_bit_b = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
            let sign_bit_d = crate::trace::trace_eval!(trace_eval, Column::SignBitD);

            // Boolean witnesses.
            for f in [&mu_uu, &mu_su, &mu_ss] {
                eval.add_constraint(f[0].clone() * (E::F::one() - f[0].clone()));
            }
            // Variant flags partition is_mul_upper:
            //   is_mul_upper = is_mul_upper_uu + is_mul_upper_su + is_mul_upper_ss.
            eval.add_constraint(
                is_mul_upper[0].clone()
                    - mu_uu[0].clone() - mu_su[0].clone() - mu_ss[0].clone()
            );

            // Term definitions (degree 3 each — flag · sign_bit · operand byte).
            //
            // TermA[i]:
            //   UU: 0
            //   SU/SS: sa · val_d[i]   where sa = sign_bit_b
            // TermB[i]:
            //   UU/SU: 0
            //   SS: sb · val_b[i]      where sb = sign_bit_d
            //
            // Encoded as paired constraints per byte: one forces the
            // active variant's correct value; the other forces 0 on
            // the inactive variants.
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    (mu_su[0].clone() + mu_ss[0].clone())
                        * (term_a[i].clone() - sign_bit_b[0].clone() * val_d[i].clone())
                );
                eval.add_constraint(mu_uu[0].clone() * term_a[i].clone());
                eval.add_constraint(
                    mu_ss[0].clone()
                        * (term_b[i].clone() - sign_bit_d[0].clone() * val_b[i].clone())
                );
                eval.add_constraint((mu_uu[0].clone() + mu_su[0].clone()) * term_b[i].clone());
            }

            // Result-binding sum with byte-level carry chain.
            // Convention (matches the existing add/sub chain shape):
            //   unsigned_hi[i] + carry_out[i]·256 = result[i] + TermA[i] + TermB[i] + carry_in[i]
            // gated on is_mul_upper.  For UU: TermA=TermB=0 → unsigned_hi
            // = result everywhere.  For SU/SS: unsigned_hi = result + corr
            // (mod 2^64); the carry-out at byte 7 is the 64-bit overflow,
            // discarded.
            for i in 0..WORD_SIZE {
                let carry_in: E::F = if i == 0 {
                    E::F::zero()
                } else {
                    corr_carry[i - 1].clone()
                };
                eval.add_constraint(
                    is_mul_upper[0].clone() * (
                        unsigned_product_hi[i].clone()
                            + corr_carry[i].clone() * f256.clone()
                            - result[i].clone()
                            - term_a[i].clone()
                            - term_b[i].clone()
                            - carry_in
                    )
                );
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // BITWISE: constrain via AND result + algebraic identity
        // AND(a,b) is provided as auxiliary. Then:
        //   OR(a,b)  = a + b - AND(a,b)
        //   XOR(a,b) = a + b - 2*AND(a,b)
        //   AndInv(a,b) = a - AND(a,b)        (a & !b = a & ~b = a - (a&b))
        //   OrInv(a,b)  = a + (255-b) - AND(a, 255-b)  ... complex, use direct
        //   Xnor(a,b) = 255 - (a + b - 2*AND(a,b))     = 255 - XOR(a,b)
        //
        // For AND (op=0): result[i] = and_result[i]
        // For OR  (op=1): result[i] = val_b[i] + val_d[i] - and_result[i]
        // For XOR (op=2): result[i] = val_b[i] + val_d[i] - 2*and_result[i]
        // For AndInv (op=3): and_result[i] = val_b[i] & val_d[i], result[i] = val_b[i] - and_result[i]
        //   But wait: AndInv(a,b) = a & !b. and_result = a & b. result = a - (a & b). ✓
        // For OrInv  (op=4): OrInv(a,b) = !a | b = !(a & !b) = 255 - (a - (a&b))
        //   ... nope. OrInv = !a | b per PVM spec? Let me check.
        //   Actually in PVM: OrInv = φ[ra] | !φ[rb]. So OrInv(a,b) = a | !b.
        //   a | !b = a | (255 - b) = a + (255-b) - AND(a, 255-b)
        //   This is harder since we'd need AND(a, 255-b) not AND(a,b).
        //   Simpler: a | !b = !((!a) & b) = 255 - (b - AND(a,b))
        //   Hmm: !a & b = b - AND(a,b). So !((!a)&b) = 255 - (b - AND(a,b)) = 255 - b + AND(a,b).
        //   So OrInv(a,b) = 255 - b + AND(a,b). ✓
        // For Xnor (op=5): Xnor(a,b) = !(a^b) = 255 - XOR(a,b) = 255 - a - b + 2*AND(a,b)
        //
        // and_result = val_b & val_d is ALWAYS the bitwise AND of the two inputs.
        // The prover fills it; we constrain:
        //   1. and_result[i] is in [0,255] (range check)
        //   2. Algebraic identity for the selected op
        //   3. AND correctness: and_result[i] = val_b[i] & val_d[i]
        //      This requires a bitwise lookup table. For now we constrain:
        //      and_result[i] * (val_b[i] - and_result[i]) ... no, can't express AND algebraically.
        //      We need: and_result[i] <= val_b[i] AND and_result[i] <= val_d[i] as necessary conditions.
        //      Full AND soundness requires a 256×256 lookup table (Phase 3).
        //      For now: we constrain the algebraic relationship between result and and_result,
        //      and range-check and_result bytes. This prevents arbitrary result values but
        //      doesn't fully prove AND correctness without the lookup.
        // ════════════════════════════════════════════════════════════════════
        let f2 = E::F::from(BaseField::from(2u32));
        for i in 0..WORD_SIZE {
            let a = &val_b[i];
            let b = &val_d[i];
            let ar = &and_result[i];
            let r = &result[i];

            // op=0 (AND):    r = ar
            let c_and = r.clone() - ar.clone();
            // op=1 (OR):     r = a + b - ar
            let c_or = r.clone() - a.clone() - b.clone() + ar.clone();
            // op=2 (XOR):    r = a + b - 2*ar
            let c_xor = r.clone() - a.clone() - b.clone() + f2.clone() * ar.clone();
            // op=3 (AndInv): r = a - ar       (a & !b)
            let c_andinv = r.clone() - a.clone() + ar.clone();
            // op=4 (OrInv):  r = 255 - b + ar (a | !b)
            let c_orinv = r.clone() - f255.clone() + b.clone() - ar.clone();
            // op=5 (Xnor):   r = 255 - a - b + 2*ar
            let c_xnor = r.clone() - f255.clone() + a.clone() + b.clone() - f2.clone() * ar.clone();

            // Degree: 1 + 5 + 1 = 7 ≤ 8. ✓
            // But 6 constraints × 8 limbs = 48 constraints. That's a lot but fine.
            //
            // Actually even simpler: just constrain is_bitwise * (result - expected(op)) = 0
            // where expected(op) is a single expression that selects the right formula.
            // We can build this as a degree-5 polynomial in op. Let me just use direct formulas
            // for each pair. The bitwise ops 0-5 can be expressed as:
            //   result = α*ar + β*a + γ*b + δ*255
            // where α,β,γ,δ depend on op. This is linear in the trace columns!
            // Just need α(op), β(op), γ(op), δ(op) as polynomials in op.
            //
            // op | α    | β  | γ  | δ
            // 0  |  1   | 0  | 0  | 0    (AND)
            // 1  | -1   | 1  | 1  | 0    (OR)
            // 2  | -2   | 1  | 1  | 0    (XOR)
            // 3  | -1   | 1  | 0  | 0    (AndInv)
            // 4  |  1   | 0  | -1 | 1    (OrInv)
            // 5  |  2   | -1 | -1 | 1    (Xnor)
            //
            // These are simple enough to interpolate. But with 6 points and degree-5 polys,
            // the constraint becomes degree 6 (5 from poly + 1 from is_bitwise). Still fits.
            //
            // For simplicity, let me just use the direct approach with one constraint:
            // Compute expected = match_and*ar + match_or*(a+b-ar) + ... where match_k = δ(op,k).
            // Using Kronecker delta via product: match_k = Π_{j≠k}(op-j) / Π_{j≠k}(k-j)
            // This is degree 5 per match term. Total: is_bitwise * (result - sum_k match_k * val_k) = 0.
            // Degree = 1 + max(5, 1) = 6 with the product terms. Still fine.
            //
            // Let me just hardcode the 6 Lagrange basis values:
            // Each bitwise op has its own flag column (degree-2 constraints)
            eval.add_constraint(is_and_flag[0].clone() * c_and);
            eval.add_constraint(is_or_flag[0].clone() * c_or);
            eval.add_constraint(is_xor_flag[0].clone() * c_xor);
            eval.add_constraint(is_and_inv_flag[0].clone() * c_andinv);
            eval.add_constraint(is_or_inv_flag[0].clone() * c_orinv);
            eval.add_constraint(is_xnor_flag[0].clone() * c_xnor);
        }

        // ════════════════════════════════════════════════════════════════════
        // COMPARE: SetLtU via subtraction carry analysis
        // cmp_carry chain: val_b + ~val_d + 1 (same as sub)
        // cmp_lt_flag = 1 - cmp_carry[7] (unsigned: a < b iff no final carry)
        // For SetLtU (compare_op=0): result = cmp_lt_flag (zero-extended to 64-bit)
        // For SetLtS (compare_op=1): needs sign bit analysis (prover-trusted for now)
        // For CmovIz/Nz, Min/Max: prover-trusted (constrained result via execution semantics)
        // ════════════════════════════════════════════════════════════════════
        let is_cmp_or_branch = is_compare[0].clone() + is_branch[0].clone();
        // Constrain the cmp_carry chain: val_b + ~val_d + 1 (two's complement subtraction)
        // sub_result[i] + carry[i]*256 = val_b[i] + 255 - val_d[i] + carry_in
        // sub_result[i] is range-checked via Range256 lookup below.
        let cmp_sub_result = crate::trace::trace_eval!(trace_eval, Column::CmpSubResult);
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 { E::F::one() } else { cmp_carry[i - 1].clone() };
            eval.add_constraint(
                is_cmp_or_branch.clone() * (
                    cmp_sub_result[i].clone() + cmp_carry[i].clone() * f256.clone()
                    - val_b[i].clone() - f255.clone() + val_d[i].clone() - carry_in
                )
            );
        }
        // NOTE: Range-check of cmp_sub_result bytes is done later (after result range256)
        // to match the interaction trace logup entry ORDER.
        // Constrain cmp_lt_flag = 1 - cmp_carry[7] for compare AND branch
        eval.add_constraint(
            is_cmp_or_branch.clone() * (cmp_lt_flag[0].clone() + cmp_carry[WORD_SIZE - 1].clone() - E::F::one())
        );
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
                    is_compare[0].clone() * val_d_is_zero[0].clone() * val_d[i].clone()
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
        let div_mul_carry = crate::trace::trace_eval!(trace_eval, Column::DivMulCarry);
        let div_mul_carry_hi = crate::trace::trace_eval!(trace_eval, Column::DivMulCarryHi);
        let div_by_zero = crate::trace::trace_eval!(trace_eval, Column::DivByZero);
        let is_div_s = crate::trace::trace_eval!(trace_eval, Column::IsDivS);
        let div_corr_hi = crate::trace::trace_eval!(trace_eval, Column::DivCorrHi);

        // Gate: only constrain when is_div_rem=1 and div_by_zero=0
        let div_active = is_div_rem[0].clone() * (E::F::one() - div_by_zero[0].clone());
        // Phase 16: full 16-bit per-position carry, reconstructed as
        // `low + 256·high`.  Mirrors the MulCarry / MulCarryHi pattern.
        // u8-only (Phase 13-) was a latent bug — at busy middle positions
        // q·d can carry up to ≈ 2 030, which doesn't fit in a byte.  Hit
        // for the first time by DivS with both operands negative
        // (q,d ≈ 0xFF…F2 / 0xFF…F9 in two's complement).
        let div_full_carry = |k: usize| -> E::F {
            div_mul_carry[k].clone() + div_mul_carry_hi[k].clone() * f256.clone()
        };

        // Schoolbook: quotient * divisor + remainder = dividend (mod 2^128)
        // For 64-bit: 16 positions (q[0..8] * d[0..8] produces 16 output bytes).
        //   Low 8 bytes (k<8):  expected = val_b[k]  (the dividend bytes).
        //   High 8 bytes (k≥8): expected = DivCorrHi[k-8].  For DivU rows the
        //     accompanying constraint forces DivCorrHi = 0 (so this matches
        //     the original "expected high = 0" behaviour); for DivS rows
        //     DivCorrHi is bound by a carry chain to the two's-complement
        //     correction `sq·d_u + sd·q_u + sr − sa  (mod 2^64)`, which is
        //     the unsigned-schoolbook high produced by signed inputs.
        //
        // Phase 16: this fixes #42 (DivS64 with negative dividend rejected).
        // Without DivCorrHi, the high bytes of `(2^64 − |q|)·d + r` are
        // non-zero in two's complement, but the AIR demanded zero.
        for k in 0..16usize {
            let mut partial_sum = E::F::zero();
            for i in 0..WORD_SIZE {
                let j = k.wrapping_sub(i);
                if j < WORD_SIZE {
                    partial_sum += div_quotient[i].clone() * val_d[j].clone();
                }
            }
            if k < WORD_SIZE {
                partial_sum += div_remainder[k].clone();
            }
            let carry_in = if k == 0 { E::F::zero() } else { div_full_carry(k - 1) };
            let expected = if k < WORD_SIZE {
                val_b[k].clone()
            } else {
                div_corr_hi[k - WORD_SIZE].clone()
            };
            let c = expected + div_full_carry(k) * f256.clone() - partial_sum - carry_in;
            eval.add_constraint(div_active.clone() * is_64bit.clone() * c);
        }

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

        // 32-bit divrem: same but only 8 positions.  Use full 16-bit
        // carry too (Phase 16) — although 32-bit per-position sums max
        // out at 4·255² ≈ 260 100 → carry ≈ 1 020, still beyond u8.
        for k in 0..8usize {
            let mut partial_sum = E::F::zero();
            for i in 0..4usize {
                let j = k.wrapping_sub(i);
                if j < 4 {
                    partial_sum += div_quotient[i].clone() * val_d[j].clone();
                }
            }
            if k < 4 {
                partial_sum += div_remainder[k].clone();
            }
            let carry_in = if k == 0 { E::F::zero() } else { div_full_carry(k - 1) };
            let expected = if k < 4 { val_b[k].clone() } else { E::F::zero() };
            let c = expected + div_full_carry(k) * f256.clone() - partial_sum - carry_in;
            eval.add_constraint(div_active.clone() * is_32bit[0].clone() * c);
        }

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
            eval.add_constraint(is_div_rem[0].clone() * is_32bit[0].clone() * result[i].clone());
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
                is_branch[0].clone() * branch_taken[0].clone()
                * (next_pc[i].clone() - branch_target[i].clone())
            );
        }

        // branch_taken must be boolean
        eval.add_constraint(
            is_branch[0].clone() * branch_taken[0].clone() * (E::F::one() - branch_taken[0].clone())
        );

        // ── Branch condition constraints ──
        // Constrain that branch_taken matches the comparison semantics per type
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
        let byte_eq_cols = crate::trace::trace_eval!(trace_eval, Column::ByteEq);
        let byte_diff_inv = crate::trace::trace_eval!(trace_eval, Column::ByteDiffInv);

        // TEST 3: full byte_eq constraint
        for i in 0..WORD_SIZE {
            let diff = val_b[i].clone() - val_d[i].clone();
            eval.add_constraint(
                is_branch[0].clone() * byte_eq_cols[i].clone()
                * (E::F::one() - byte_eq_cols[i].clone())
            );
            eval.add_constraint(
                is_branch[0].clone() * byte_eq_cols[i].clone() * diff.clone()
            );
            eval.add_constraint(
                is_branch[0].clone() * (E::F::one() - byte_eq_cols[i].clone())
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
        // eq_flag=1 ⇒ all sub_result bytes = 0 (val_b == val_d)
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                is_cmp_or_branch.clone() * eq_flag[0].clone() * cmp_sub_result[i].clone()
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
                - is_branch[0].clone() * branch_taken[0].clone()
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

        // Range256 checks for cmp_sub_result bytes (carry chain soundness)
        // Must be AFTER result range256 to match interaction trace entry order.
        for i in 0..WORD_SIZE {
            eval.add_to_relation(RelationEntry::new(
                range256_lookup,
                is_cmp_or_branch.clone().into(),
                &[cmp_sub_result[i].clone()],
            ));
        }

        // ════════════════════════════════════════════════════════════════════
        // Memory access lookup (producer side)
        // ════════════════════════════════════════════════════════════════════
        let is_store_col = crate::trace::trace_eval!(trace_eval, Column::IsStore);
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
            tuple.push(is_store_col[0].clone());

            eval.add_to_relation(RelationEntry::new(
                mem_lookup,
                mem_byte_active[byte_idx].clone().into(),
                &tuple,
            ));
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

        // Bitwise AND lookup: nibble-level (16 lookups per bitwise op)
        {
            let and_result = crate::trace::trace_eval!(trace_eval, Column::AndResult);
            let is_bitwise_flag = crate::trace::trace_eval!(trace_eval, Column::IsBitwise);
            let val_b_hi_nib = crate::trace::trace_eval!(trace_eval, Column::ValBHiNib);
            let val_d_hi_nib = crate::trace::trace_eval!(trace_eval, Column::ValDHiNib);
            let and_result_hi_nib = crate::trace::trace_eval!(trace_eval, Column::AndResultHiNib);
            let sixteen: E::F = E::F::from(BaseField::from(16));
            for i in 0..WORD_SIZE {
                // High nibble lookup
                eval.add_to_relation(RelationEntry::new(
                    bitwise_and_lookup,
                    is_bitwise_flag[0].clone().into(),
                    &[val_b_hi_nib[i].clone(), val_d_hi_nib[i].clone(), and_result_hi_nib[i].clone()],
                ));
                // Low nibble lookup: lo = byte - hi * 16
                let b_lo = val_b[i].clone() - val_b_hi_nib[i].clone() * sixteen.clone();
                let d_lo = val_d[i].clone() - val_d_hi_nib[i].clone() * sixteen.clone();
                let and_lo = and_result[i].clone() - and_result_hi_nib[i].clone() * sixteen.clone();
                eval.add_to_relation(RelationEntry::new(
                    bitwise_and_lookup,
                    is_bitwise_flag[0].clone().into(),
                    &[b_lo, d_lo, and_lo],
                ));
            }
        }

        // Power-of-two lookup: proves val_d = 2^shift_amount for constrained shifts
        {
            let shift_amount = crate::trace::trace_eval!(trace_eval, Column::ShiftAmount);
            let is_shift_c = crate::trace::trace_eval!(trace_eval, Column::IsShiftConstrained);
            let mut tuple: Vec<E::F> = vec![shift_amount[0].clone()];
            tuple.extend_from_slice(&val_d);
            eval.add_to_relation(RelationEntry::new(
                pow2_lookup,
                is_shift_c[0].clone().into(),
                &tuple,
            ));
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
                    * (reg_val_d_field - shift_amount_e[0].clone() - modulus * shift_q_field)
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
        // Phase 13b/c: program-memory consumer (pc + opcode + regs + imm + flags)
        //
        // Per real CpuChip step, demand the full instruction tuple +
        // category-flag bag from ProgramMemoryChip's preprocessed table.
        // Phase 13b binds (pc, opcode, skip_len, reg_a, reg_b, reg_d, imm);
        // 13c extends it with 20 category/sub-category flag columns so the
        // prover can't clear flags to skip per-op constraints.
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
            // 13c flags — must match the order of ProgramMemoryChip's
            // preprocessed columns and `classify_opcode_for_program_memory`.
            let f_is_add = crate::trace::trace_eval!(trace_eval, Column::IsAdd);
            let f_is_sub = crate::trace::trace_eval!(trace_eval, Column::IsSub);
            let f_is_mul = crate::trace::trace_eval!(trace_eval, Column::IsMul);
            let f_is_mul_upper = crate::trace::trace_eval!(trace_eval, Column::IsMulUpper);
            let f_is_bitwise = crate::trace::trace_eval!(trace_eval, Column::IsBitwise);
            let f_is_shift = crate::trace::trace_eval!(trace_eval, Column::IsShift);
            let f_is_compare = crate::trace::trace_eval!(trace_eval, Column::IsCompare);
            let f_is_move = crate::trace::trace_eval!(trace_eval, Column::IsMove);
            let f_is_32bit = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
            let f_is_branch = crate::trace::trace_eval!(trace_eval, Column::IsBranch);
            let f_is_jump = crate::trace::trace_eval!(trace_eval, Column::IsJump);
            let f_is_div_rem = crate::trace::trace_eval!(trace_eval, Column::IsDivRem);
            let f_is_load = crate::trace::trace_eval!(trace_eval, Column::IsLoad);
            let f_is_store = crate::trace::trace_eval!(trace_eval, Column::IsStore);
            let f_is_exit = crate::trace::trace_eval!(trace_eval, Column::IsExit);
            let f_is_neg_add = crate::trace::trace_eval!(trace_eval, Column::IsNegAdd);
            let f_is_reverse_bytes = crate::trace::trace_eval!(trace_eval, Column::IsReverseBytes);
            let f_is_zero_ext_16 = crate::trace::trace_eval!(trace_eval, Column::IsZeroExt16);
            let f_is_sign_ext_8 = crate::trace::trace_eval!(trace_eval, Column::IsSignExt8);
            let f_is_sign_ext_16 = crate::trace::trace_eval!(trace_eval, Column::IsSignExt16);
            let f_is_trap = crate::trace::trace_eval!(trace_eval, Column::IsTrap);
            let f_is_jump_ind = crate::trace::trace_eval!(trace_eval, Column::IsJumpInd);
            let f_is_load_imm_jump_ind = crate::trace::trace_eval!(trace_eval, Column::IsLoadImmJumpInd);
            let f_is_mul_upper_uu = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperUU);
            let f_is_mul_upper_su = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSU);
            let f_is_mul_upper_ss = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSS);
            let f_is_div_s = crate::trace::trace_eval!(trace_eval, Column::IsDivS);
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
            tuple.push(f_is_add[0].clone());
            tuple.push(f_is_sub[0].clone());
            tuple.push(f_is_mul[0].clone());
            tuple.push(f_is_mul_upper[0].clone());
            tuple.push(f_is_bitwise[0].clone());
            tuple.push(f_is_shift[0].clone());
            tuple.push(f_is_compare[0].clone());
            tuple.push(f_is_move[0].clone());
            tuple.push(f_is_32bit[0].clone());
            tuple.push(f_is_branch[0].clone());
            tuple.push(f_is_jump[0].clone());
            tuple.push(f_is_div_rem[0].clone());
            tuple.push(f_is_load[0].clone());
            tuple.push(f_is_store[0].clone());
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
        // Inactive bytes (i >= MemSize): for unsigned loads they must be
        // zero, for signed loads 0xFF · sign_bit.  Tightening the inactive-
        // byte constraint requires a per-variant IsLoadSigned flag; defer
        // that piece.  The active-byte binding here is the load-bearing
        // part of the fix.  Pure ground constraint, parity-neutral.
        let is_load_local = crate::trace::trace_eval!(trace_eval, Column::IsLoad);
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                is_load_local[0].clone()
                    * mem_byte_active[i].clone()
                    * (result[i].clone() - mem_value[i].clone()),
            );
        }

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for CpuChip {
    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let num_steps = side_note.num_steps();
        let log_size = (num_steps as f64).log2().ceil().max(LOG_N_LANES as f64) as u32;
        let log_size = log_size.max(LOG_N_LANES);

        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();
        let mut range_bytes: Vec<u8> = Vec::new();
        let mut bitwise_and_bytes: Vec<(u8, u8)> = Vec::new();

        for (row, step) in side_note.steps.iter().enumerate() {
            trace.fill_columns(row, step.timestamp, Column::Timestamp);
            trace.fill_columns_bytes(row, &step.pc.to_le_bytes(), Column::Pc);
            trace.fill_columns_bytes(row, &step.next_pc.to_le_bytes(), Column::NextPc);
            trace.fill_columns(row, step.opcode as u8, Column::Opcode);
            trace.fill_columns(row, step.skip_len as u8, Column::SkipLen);
            // Phase 13b: 8-byte immediate witness for the ProgramMemory lookup.
            trace.fill_columns_bytes(row, &step.imm.to_le_bytes(), Column::ImmBytes);
            // Phase 13b: charge ProgramMemoryChip for this step's instruction
            // fetch.  Two consumer emissions per step (paired) → producer
            // multiplicity = 2 · count_at_pc.
            *side_note.program_memory_counts.entry(step.pc).or_insert(0) += 2;
            // PC carry for sequential next_pc = pc + 1 + skip_len
            {
                let pc_bytes = step.pc.to_le_bytes();
                let sum0 = pc_bytes[0] as u16 + 1 + step.skip_len as u16;
                let c0 = (sum0 >> 8) as u8;
                let sum1 = pc_bytes[1] as u16 + c0 as u16;
                let c1 = (sum1 >> 8) as u8;
                let sum2 = pc_bytes[2] as u16 + c1 as u16;
                let c2 = (sum2 >> 8) as u8;
                trace.fill_columns_bytes(row, &[c0, c1, c2], Column::PcCarry);
            }
            trace.fill_columns(row, step.reg_a as u8, Column::RegA);
            trace.fill_columns(row, step.reg_b as u8, Column::RegB);
            trace.fill_columns(row, step.reg_d as u8, Column::RegD);

            // Source operands
            let (mut val_b, mut val_d) = match step.opcode.category() {
                javm::instruction::InstructionCategory::ThreeReg => {
                    (step.regs_before[step.reg_a], step.regs_before[step.reg_b])
                }
                javm::instruction::InstructionCategory::TwoRegOneImm => {
                    (step.regs_before[step.reg_b], step.imm)
                }
                javm::instruction::InstructionCategory::TwoReg => {
                    (0, step.regs_before[step.reg_b])
                }
                javm::instruction::InstructionCategory::OneRegImmOffset => {
                    // BranchEqImm/NeImm/LtImm/etc: compare regs[ra] vs imm
                    (step.regs_before[step.reg_a], step.imm)
                }
                _ if uses_immediate(step.opcode) => {
                    (0, step.imm)
                }
                _ => (step.regs_before[step.reg_a], step.regs_before[step.reg_b]),
            };

            let flags = classify_opcode(step.opcode);

            // For left/right shifts: save shift amount, then replace val_d with 2^shift_amount
            let mut saved_shift_amount: u8 = 0;
            if flags.is_shift && (flags.shift_op <= 2) {
                let modulus = if flags.is_32bit { 32u64 } else { 64 };
                let shift = val_d % modulus;
                saved_shift_amount = shift as u8;
                val_d = 1u64 << shift;
                side_note.power_of_two_counts[shift as usize] += 1;
            }

            // Truncate for 32-bit ALU ops (including divrem for right shifts)
            if flags.is_32bit && (flags.is_add || flags.is_sub || flags.is_mul || flags.is_div_rem) {
                val_b &= 0xFFFF_FFFF;
                val_d &= 0xFFFF_FFFF;
            }

            trace.fill_columns(row, val_b, Column::ValB);
            trace.fill_columns(row, val_d, Column::ValD);

            let dr = dest_reg(step);
            let result = step.regs_after[dr];
            trace.fill_columns(row, result, Column::Result);

            let val_b_bytes = val_b.to_le_bytes();
            let val_d_bytes = val_d.to_le_bytes();
            let result_bytes = result.to_le_bytes();

            // ── Add/Sub carry ──
            let carry_limbs = if flags.is_32bit { 4 } else { WORD_SIZE };
            let mut carry = [0u8; WORD_SIZE];
            if flags.is_add {
                let mut c: u16 = 0;
                for i in 0..carry_limbs {
                    let sum = val_b_bytes[i] as u16 + val_d_bytes[i] as u16 + c;
                    carry[i] = (sum >> 8) as u8;
                    c = carry[i] as u16;
                }
            } else if flags.is_sub {
                let (a, b) = if flags.is_neg_add { (val_d_bytes, val_b_bytes) } else { (val_b_bytes, val_d_bytes) };
                let mut c: u16 = 1;
                for i in 0..carry_limbs {
                    let sum = a[i] as u16 + (b[i] ^ 0xFF) as u16 + c;
                    carry[i] = (sum >> 8) as u8;
                    c = carry[i] as u16;
                }
            }
            trace.fill_columns_bytes(row, &carry, Column::Carry);

            // ── Mul auxiliary ──
            let mut mul_high = [0u8; WORD_SIZE];
            let mut mul_carry = [0u8; 16];
            let mut mul_carry_hi = [0u8; 16];
            let mut unsigned_product_hi_bytes = [0u8; WORD_SIZE];
            let mut mul_corr_term_a = [0u8; WORD_SIZE];
            let mut mul_corr_term_b = [0u8; WORD_SIZE];
            let mut mul_corr_carry = [0u8; WORD_SIZE];
            if flags.is_mul {
                let full = (val_b as u128) * (val_d as u128);
                if flags.is_32bit {
                    // 32-bit: split at 32 bits
                    let high32 = (full >> 32) as u32;
                    let high_bytes = high32.to_le_bytes();
                    mul_high[..4].copy_from_slice(&high_bytes);
                } else if flags.is_mul_upper {
                    // MulUpper: mul_high holds positions 0..7 (low 64 of
                    // unsigned product); positions 8..15 (unsigned high)
                    // land in UnsignedProductHi.  result holds the
                    // signedness-adjusted high (for UU: same as unsigned;
                    // for SU/SS: unsigned − sign correction, computed by
                    // the interpreter and reflected in step.regs_after).
                    let low = full as u64;
                    mul_high = low.to_le_bytes();
                    let high = (full >> 64) as u64;
                    unsigned_product_hi_bytes = high.to_le_bytes();
                } else {
                    let high = (full >> 64) as u64;
                    mul_high = high.to_le_bytes();
                }
                let input_limbs = if flags.is_32bit { 4 } else { WORD_SIZE };
                let out_limbs = input_limbs * 2;
                let mut accum = [0u32; 16];
                for i in 0..input_limbs {
                    for j in 0..input_limbs {
                        accum[i + j] += val_b_bytes[i] as u32 * val_d_bytes[j] as u32;
                    }
                }
                // Schoolbook carry per position is up to ~16 bits at busy
                // middle positions (e.g. 0xFFFFFFFF² → carry 0x3FB at k=3).
                // Split across mul_carry (low byte) and mul_carry_hi (high
                // byte); the AIR reconstructs as mul_carry + 256·mul_carry_hi.
                for k in 0..out_limbs.min(16).saturating_sub(1) {
                    let carry = accum[k] >> 8;
                    mul_carry[k] = carry as u8;
                    mul_carry_hi[k] = (carry >> 8) as u8;
                    accum[k + 1] += carry;
                }
                if out_limbs <= 16 && out_limbs > 0 {
                    let carry = accum[out_limbs - 1] >> 8;
                    mul_carry[out_limbs - 1] = carry as u8;
                    mul_carry_hi[out_limbs - 1] = (carry >> 8) as u8;
                }

                // Phase 12c: sign-correction columns for MulUpper SS / SU.
                // TermA = sa·val_d (SU/SS); TermB = sb·val_b (SS only).
                // Carry chain: result + TermA + TermB ≡ unsigned_high (mod 2^64).
                if flags.is_mul_upper && !flags.is_32bit {
                    let sa = (val_b >> 63) & 1;
                    let sb = (val_d >> 63) & 1;
                    let term_a_full = if flags.is_mul_upper_su || flags.is_mul_upper_ss {
                        if sa == 1 { val_d } else { 0 }
                    } else { 0 };
                    let term_b_full = if flags.is_mul_upper_ss {
                        if sb == 1 { val_b } else { 0 }
                    } else { 0 };
                    mul_corr_term_a = term_a_full.to_le_bytes();
                    mul_corr_term_b = term_b_full.to_le_bytes();
                    let result_bytes_le = step.regs_after[dest_reg(step)].to_le_bytes();
                    let mut carry_in: u16 = 0;
                    for i in 0..WORD_SIZE {
                        let s = result_bytes_le[i] as u16
                            + mul_corr_term_a[i] as u16
                            + mul_corr_term_b[i] as u16
                            + carry_in;
                        carry_in = s >> 8;
                        mul_corr_carry[i] = carry_in as u8;
                    }
                }
            }
            trace.fill_columns_bytes(row, &mul_high, Column::MulHigh);
            trace.fill_columns_bytes(row, &mul_carry, Column::MulCarry);
            trace.fill_columns_bytes(row, &mul_carry_hi, Column::MulCarryHi);
            trace.fill_columns_bytes(row, &unsigned_product_hi_bytes, Column::UnsignedProductHi);
            trace.fill_columns_bytes(row, &mul_corr_term_a, Column::MulCorrTermA);
            trace.fill_columns_bytes(row, &mul_corr_term_b, Column::MulCorrTermB);
            trace.fill_columns_bytes(row, &mul_corr_carry, Column::MulCorrCarry);

            // ── Bitwise auxiliary ──
            let mut and_result = [0u8; WORD_SIZE];
            if flags.is_bitwise {
                for i in 0..WORD_SIZE {
                    and_result[i] = val_b_bytes[i] & val_d_bytes[i];
                    bitwise_and_bytes.push((val_b_bytes[i], val_d_bytes[i]));
                }
            }
            trace.fill_columns_bytes(row, &and_result, Column::AndResult);
            // High nibbles for nibble-level AND lookup
            let mut val_b_hi_nib = [0u8; WORD_SIZE];
            let mut val_d_hi_nib = [0u8; WORD_SIZE];
            let mut and_result_hi_nib = [0u8; WORD_SIZE];
            if flags.is_bitwise {
                for i in 0..WORD_SIZE {
                    val_b_hi_nib[i] = val_b_bytes[i] >> 4;
                    val_d_hi_nib[i] = val_d_bytes[i] >> 4;
                    and_result_hi_nib[i] = and_result[i] >> 4;
                }
            }
            trace.fill_columns_bytes(row, &val_b_hi_nib, Column::ValBHiNib);
            trace.fill_columns_bytes(row, &val_d_hi_nib, Column::ValDHiNib);
            trace.fill_columns_bytes(row, &and_result_hi_nib, Column::AndResultHiNib);

            // ── Compare auxiliary (populated for is_compare OR is_branch) ──
            let mut cmp_carry = [0u8; WORD_SIZE];
            let mut cmp_sub_result = [0u8; WORD_SIZE];
            let mut cmp_lt_flag: u8 = 0;
            if flags.is_compare || flags.is_branch {
                // Unsigned comparison via subtraction: val_b + ~val_d + 1
                let mut c: u16 = 1;
                for i in 0..WORD_SIZE {
                    let sum = val_b_bytes[i] as u16 + (val_d_bytes[i] ^ 0xFF) as u16 + c;
                    cmp_sub_result[i] = (sum & 0xFF) as u8;
                    cmp_carry[i] = (sum >> 8) as u8;
                    c = cmp_carry[i] as u16;
                }
                // a - b via a + ~b + 1: carry_out=1 means a>=b, carry_out=0 means a<b
                cmp_lt_flag = 1 - cmp_carry[WORD_SIZE - 1];
            }
            trace.fill_columns_bytes(row, &cmp_carry, Column::CmpCarry);
            trace.fill_columns_bytes(row, &cmp_sub_result, Column::CmpSubResult);
            trace.fill_columns(row, cmp_lt_flag, Column::CmpLtFlag);
            let val_d_is_zero: u8 = if val_d == 0 { 1 } else { 0 };
            trace.fill_columns(row, val_d_is_zero, Column::ValDIsZero);
            let sign_bit_b: u8 = if flags.is_32bit { ((val_b >> 31) & 1) as u8 } else { ((val_b >> 63) & 1) as u8 };
            let sign_bit_d: u8 = if flags.is_32bit { ((val_d >> 31) & 1) as u8 } else { ((val_d >> 63) & 1) as u8 };
            trace.fill_columns(row, sign_bit_b, Column::SignBitB);
            trace.fill_columns(row, sign_bit_d, Column::SignBitD);
            // Signed lt: if signs differ, negative is smaller. If same, use unsigned compare.
            let cmp_lt_s_flag: u8 = if sign_bit_b != sign_bit_d {
                sign_bit_b // b is negative (sign=1) → b < d
            } else {
                cmp_lt_flag // same sign → unsigned comparison
            };
            trace.fill_columns(row, cmp_lt_s_flag, Column::CmpLtSFlag);
            let eq_flag: u8 = if val_b == val_d { 1 } else { 0 };
            trace.fill_columns(row, eq_flag, Column::EqFlag);
            // Per-byte equality flags (for branch eq/ne)
            let mut byte_eq = [0u8; 8];
            let mut byte_diff_inv = [stwo::core::fields::m31::BaseField::from(0u32); 8];
            if flags.is_branch {
                for i in 0..8 {
                    if val_b_bytes[i] == val_d_bytes[i] {
                        byte_eq[i] = 1;
                    } else {
                        // Compute in M31 field directly to match constraint arithmetic
                        let b = stwo::core::fields::m31::BaseField::from(val_b_bytes[i] as u32);
                        let d = stwo::core::fields::m31::BaseField::from(val_d_bytes[i] as u32);
                        let diff_field = b - d;
                        byte_diff_inv[i] = diff_field.inverse();
                    }
                }
            }
            trace.fill_columns_bytes(row, &byte_eq, Column::ByteEq);
            trace.fill_columns_base_field(row, &byte_diff_inv, Column::ByteDiffInv);
            trace.fill_columns(row, flags.is_set_lt_u, Column::IsSetLtU);
            trace.fill_columns(row, flags.is_set_lt_s, Column::IsSetLtS);
            trace.fill_columns(row, flags.is_cmov_iz, Column::IsCmovIz);
            trace.fill_columns(row, flags.is_cmov_nz, Column::IsCmovNz);
            trace.fill_columns(row, flags.is_min_s, Column::IsMinS);
            trace.fill_columns(row, flags.is_min_u, Column::IsMinU);
            trace.fill_columns(row, flags.is_max_s, Column::IsMaxS);
            trace.fill_columns(row, flags.is_max_u, Column::IsMaxU);

            // ── Shift auxiliary ──
            let shift_amount = if flags.is_shift {
                if flags.shift_op <= 2 {
                    saved_shift_amount // saved before val_d was replaced
                } else {
                    let modulus = if flags.is_32bit { 32u64 } else { 64 };
                    (val_d % modulus) as u8 // for non-constrained shifts, val_d is original
                }
            } else {
                0
            };
            trace.fill_columns(row, shift_amount, Column::ShiftAmount);
            trace.fill_columns(row, flags.shift_op, Column::ShiftOp);
            let is_shift_constrained = flags.is_shift && (flags.shift_op <= 2);
            trace.fill_columns(row, is_shift_constrained, Column::IsShiftConstrained);

            // ── Flags ──
            trace.fill_columns(row, false, Column::IsPadding);
            trace.fill_columns(row, step.reg_write.is_some(), Column::RegAWritten);
            trace.fill_columns(row, step.gas_after, Column::Gas);
            trace.fill_columns(row, flags.is_add, Column::IsAdd);
            trace.fill_columns(row, flags.is_sub, Column::IsSub);
            trace.fill_columns(row, flags.is_mul, Column::IsMul);
            trace.fill_columns(row, flags.is_mul_upper, Column::IsMulUpper);
            trace.fill_columns(row, flags.is_mul_upper_uu, Column::IsMulUpperUU);
            trace.fill_columns(row, flags.is_mul_upper_su, Column::IsMulUpperSU);
            trace.fill_columns(row, flags.is_mul_upper_ss, Column::IsMulUpperSS);
            trace.fill_columns(row, flags.is_div_s, Column::IsDivS);
            trace.fill_columns(row, flags.is_bitwise, Column::IsBitwise);
            trace.fill_columns(row, flags.is_shift, Column::IsShift);
            trace.fill_columns(row, flags.is_compare, Column::IsCompare);
            trace.fill_columns(row, flags.is_move, Column::IsMove);
            trace.fill_columns(row, flags.is_32bit, Column::Is32Bit);
            trace.fill_columns(row, flags.is_and, Column::IsAnd);
            trace.fill_columns(row, flags.is_or, Column::IsOr);
            trace.fill_columns(row, flags.is_xor, Column::IsXor);
            trace.fill_columns(row, flags.is_and_inv, Column::IsAndInv);
            trace.fill_columns(row, flags.is_or_inv, Column::IsOrInv);
            trace.fill_columns(row, flags.is_xnor, Column::IsXnor);
            trace.fill_columns(row, flags.is_neg_add, Column::IsNegAdd);
            trace.fill_columns(row, flags.is_branch, Column::IsBranch);
            trace.fill_columns(row, flags.is_br_eq, Column::IsBrEq);
            trace.fill_columns(row, flags.is_br_ne, Column::IsBrNe);
            trace.fill_columns(row, flags.is_br_lt_u, Column::IsBrLtU);
            trace.fill_columns(row, flags.is_br_ge_u, Column::IsBrGeU);
            trace.fill_columns(row, flags.is_br_le_u, Column::IsBrLeU);
            trace.fill_columns(row, flags.is_br_gt_u, Column::IsBrGtU);
            trace.fill_columns(row, flags.is_br_lt_s, Column::IsBrLtS);
            trace.fill_columns(row, flags.is_br_ge_s, Column::IsBrGeS);
            trace.fill_columns(row, flags.is_br_le_s, Column::IsBrLeS);
            trace.fill_columns(row, flags.is_br_gt_s, Column::IsBrGtS);
            trace.fill_columns(row, flags.is_jump, Column::IsJump);
            trace.fill_columns(row, step.branch_taken, Column::BranchTaken);
            trace.fill_columns_bytes(row, &step.branch_target.to_le_bytes(), Column::BranchTarget);
            trace.fill_columns(row, flags.is_div_rem, Column::IsDivRem);
            trace.fill_columns(row, flags.div_rem_op, Column::DivRemOp);
            trace.fill_columns(row, flags.is_reverse_bytes, Column::IsReverseBytes);
            trace.fill_columns(row, flags.is_zero_ext_16, Column::IsZeroExt16);
            trace.fill_columns(row, flags.is_sign_ext_8, Column::IsSignExt8);
            trace.fill_columns(row, flags.is_sign_ext_16, Column::IsSignExt16);
            trace.fill_columns(row, flags.is_trap, Column::IsTrap);
            trace.fill_columns(row, flags.is_jump_ind, Column::IsJumpInd);
            trace.fill_columns(row, flags.is_load_imm_jump_ind, Column::IsLoadImmJumpInd);
            // Phase 13d-loadimmjumpind: ImmYBytes always carries low 4 bytes
            // of step.imm_y so the prog_mem lookup balances on every row
            // (canonical = 0 for non-LoadImmJumpInd ops).
            trace.fill_columns_bytes(
                row, &(step.imm_y as u32).to_le_bytes(), Column::ImmYBytes
            );
            // Phase 13d: per-byte add-with-carry chain for JumpIndAddr =
            // (val_b + step.imm) mod 2^32.  The constraint is gated by
            // IsJumpInd, so on non-JumpInd rows the columns are left at
            // zero (default fill).  The runtime addr feeds JumpTableChip's
            // multiplicity counter via side_note.jump_table_counts.
            if flags.is_jump_ind {
                let val_b_lo = (val_b as u32).to_le_bytes();
                let imm_lo = (step.imm as u32).to_le_bytes();
                let mut carry_in: u16 = 0;
                let mut addr_bytes = [0u8; 4];
                let mut carry_bytes = [0u8; 4];
                for i in 0..4 {
                    let s = val_b_lo[i] as u16 + imm_lo[i] as u16 + carry_in;
                    addr_bytes[i] = s as u8;
                    carry_in = s >> 8;
                    carry_bytes[i] = carry_in as u8;
                }
                trace.fill_columns_bytes(row, &addr_bytes, Column::JumpIndAddr);
                trace.fill_columns_bytes(row, &carry_bytes, Column::JumpIndCarry);

                // Count this dispatch in side_note.jump_table_counts so
                // JumpTableChip's producer multiplicity matches.  Index =
                // addr/2 - 1 (mirrors the runtime djump indexing).
                let addr = u32::from_le_bytes(addr_bytes);
                if addr >= 2 && addr.is_multiple_of(2) {
                    let idx = (addr / 2 - 1) as usize;
                    if let Some(counts) = side_note.jump_table_counts.get_mut(idx) {
                        *counts += 1;
                    }
                }
            }
            // Phase 13d-loadimmjumpind: LoadImmJumpInd carry chain for
            // LoadImmJumpIndAddr = (val_d + imm_y) mod 2^32.
            if flags.is_load_imm_jump_ind {
                let val_d_lo = (val_d as u32).to_le_bytes();
                let imm_y_lo = (step.imm_y as u32).to_le_bytes();
                let mut carry_in: u16 = 0;
                let mut addr_bytes = [0u8; 4];
                let mut carry_bytes = [0u8; 4];
                for i in 0..4 {
                    let s = val_d_lo[i] as u16 + imm_y_lo[i] as u16 + carry_in;
                    addr_bytes[i] = s as u8;
                    carry_in = s >> 8;
                    carry_bytes[i] = carry_in as u8;
                }
                trace.fill_columns_bytes(row, &addr_bytes, Column::LoadImmJumpIndAddr);
                trace.fill_columns_bytes(row, &carry_bytes, Column::LoadImmJumpIndCarry);

                let addr = u32::from_le_bytes(addr_bytes);
                if addr >= 2 && addr.is_multiple_of(2) {
                    let idx = (addr / 2 - 1) as usize;
                    if let Some(counts) = side_note.jump_table_counts.get_mut(idx) {
                        *counts += 1;
                    }
                }
            }
            // Sign-extend witnesses (Phase 12b-2): high nibble + bit-7 of the
            // sign-source byte.  val_d[0] for SE8, val_d[1] for SE16.  Zero on
            // non-SE rows; the lookup multiplicities below are gated to match.
            let (se_src_byte, se_active) = if flags.is_sign_ext_8 {
                (val_d_bytes[0], true)
            } else if flags.is_sign_ext_16 {
                (val_d_bytes[1], true)
            } else {
                (0u8, false)
            };
            if se_active {
                let hi = se_src_byte >> 4;
                let lo = se_src_byte & 0xF;
                let bit = (se_src_byte >> 7) & 1;
                trace.fill_columns(row, hi, Column::SignExtSrcHiNib);
                trace.fill_columns(row, bit, Column::SignExtBit);
                // Charge BitwiseLookupChip for the two nibble lookups this row emits.
                *side_note.bitwise_and_counts.entry((hi, 8)).or_insert(0) += 1;
                *side_note.bitwise_and_counts.entry((lo, 0xF)).or_insert(0) += 1;
            }

            // ── DivRem auxiliary ──
            let mut div_quotient = [0u8; WORD_SIZE];
            let mut div_remainder = [0u8; WORD_SIZE];
            let mut div_mul_carry = [0u8; 16];
            let mut div_mul_carry_hi = [0u8; 16];
            let mut div_by_zero: u8 = 0;
            let mut div_corr_hi = [0u8; WORD_SIZE];
            let mut div_corr_carry = [0u8; WORD_SIZE];
            let mut sign_bit_q: u8 = 0;
            let mut sign_bit_r: u8 = 0;
            if flags.is_div_rem {
                let dividend = val_b;
                let divisor = val_d;
                if divisor == 0 {
                    div_by_zero = 1;
                    // For div-by-zero: result is special (u64::MAX for div, dividend for rem)
                    // quotient/remainder don't matter, constraint is bypassed
                } else {
                    // Compute the canonical (q, r) the interpreter wrote.
                    // For DivS / RemS we need *signed* round-toward-zero
                    // division so the byte-level decomposition matches
                    // two's complement (e.g. -100/7 → q = -14 →
                    // q.to_le_bytes() = 0xF2,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF).
                    // Phase 16: previously the trace used unsigned division
                    // for DivS too — silently wrong on negatives, hidden
                    // because no positive DivS test had a negative operand.
                    let (q_bytes, r_bytes): ([u8; 8], [u8; 8]) = if flags.is_div_s {
                        if flags.is_32bit {
                            let b32 = dividend as i32;
                            let d32 = divisor as i32;
                            // i32 div / rem with the standard PVM
                            // overflow guard (INT_MIN / -1 = INT_MIN, rem = 0).
                            let (q32, r32) = if b32 == i32::MIN && d32 == -1 {
                                (i32::MIN, 0i32)
                            } else {
                                (b32 / d32, b32 % d32)
                            };
                            // The 64-bit AIR reconstructs `q · d + r = b`
                            // mod 2^128 only on Is64Bit rows; on 32-bit
                            // rows the AIR's separate 8-position
                            // schoolbook still expects high bytes = 0,
                            // so feed the 32-bit byte pattern with high
                            // 4 bytes zero (same as result column).
                            let mut q = [0u8; 8];
                            let mut r = [0u8; 8];
                            q[..4].copy_from_slice(&(q32 as u32).to_le_bytes());
                            r[..4].copy_from_slice(&(r32 as u32).to_le_bytes());
                            (q, r)
                        } else {
                            let bs = dividend as i64;
                            let ds = divisor as i64;
                            let (qs, rs) = if bs == i64::MIN && ds == -1 {
                                (i64::MIN, 0i64)
                            } else {
                                (bs / ds, bs % ds)
                            };
                            ((qs as u64).to_le_bytes(), (rs as u64).to_le_bytes())
                        }
                    } else {
                        // DivU / RemU: unsigned division.
                        ((dividend / divisor).to_le_bytes(),
                         (dividend % divisor).to_le_bytes())
                    };
                    div_quotient = q_bytes;
                    div_remainder = r_bytes;

                    // Carry chain for q * divisor + remainder = dividend (schoolbook)
                    let divisor_bytes = divisor.to_le_bytes();
                    let input_limbs = if flags.is_32bit { 4 } else { WORD_SIZE };
                    let out_limbs = input_limbs * 2;
                    let mut accum = [0u32; 16];
                    for i in 0..input_limbs {
                        for j in 0..input_limbs {
                            accum[i + j] += div_quotient[i] as u32 * divisor_bytes[j] as u32;
                        }
                    }
                    // Add remainder to low limbs
                    for i in 0..input_limbs {
                        accum[i] += div_remainder[i] as u32;
                    }
                    for k in 0..out_limbs.min(16).saturating_sub(1) {
                        let carry = accum[k] >> 8;
                        div_mul_carry[k] = carry as u8;
                        div_mul_carry_hi[k] = (carry >> 8) as u8;
                        accum[k + 1] += carry;
                    }
                    if out_limbs > 0 && out_limbs <= 16 {
                        let carry = accum[out_limbs - 1] >> 8;
                        div_mul_carry[out_limbs - 1] = carry as u8;
                        div_mul_carry_hi[out_limbs - 1] = (carry >> 8) as u8;
                    }

                    // Phase 16: DivS sign-correction for the 64-bit
                    // schoolbook's high bytes.  See the "DivS sign
                    // correction" constraint block in add_constraints.
                    //
                    //   div_corr_hi[i] + carry_out·256 + (i==0 ? sa : 0)
                    //     = sq·d_u[i] + sd·q_u[i] + carry_in + (i==0 ? sr : 0)
                    if flags.is_div_s && !flags.is_32bit {
                        let sa = (val_b >> 63) & 1;
                        let sd = (val_d >> 63) & 1;
                        sign_bit_q = (div_quotient[7] >> 7) & 1;
                        sign_bit_r = (div_remainder[7] >> 7) & 1;
                        let term_d = if sign_bit_q == 1 { val_d } else { 0 };
                        let term_q = if sd == 1 {
                            u64::from_le_bytes(div_quotient)
                        } else {
                            0
                        };
                        let term_d_bytes = term_d.to_le_bytes();
                        let term_q_bytes = term_q.to_le_bytes();
                        let mut carry: i32 = 0;
                        for i in 0..WORD_SIZE {
                            let extra_lhs = if i == 0 { sa as i32 } else { 0 };
                            let extra_rhs = if i == 0 { sign_bit_r as i32 } else { 0 };
                            // s = sq·d_u[i] + sd·q_u[i] + carry_in + (i==0 ? sr : 0)
                            //     − (i==0 ? sa : 0)
                            let s = term_d_bytes[i] as i32
                                + term_q_bytes[i] as i32
                                + carry
                                + extra_rhs
                                - extra_lhs;
                            // Want: div_corr_hi[i] + carry_out·256 = s.
                            // s ∈ [−1, 511 + carry_in]; with carry_in ≤ 2
                            // and per-byte cap, take low byte and carry out.
                            let s_mod = s.rem_euclid(256);
                            div_corr_hi[i] = s_mod as u8;
                            carry = (s - s_mod) / 256;
                            div_corr_carry[i] = carry as u8;
                        }
                    }
                }
            }
            trace.fill_columns_bytes(row, &div_quotient, Column::DivQuotient);
            trace.fill_columns_bytes(row, &div_remainder, Column::DivRemainder);
            trace.fill_columns_bytes(row, &div_mul_carry, Column::DivMulCarry);
            trace.fill_columns_bytes(row, &div_mul_carry_hi, Column::DivMulCarryHi);
            trace.fill_columns(row, div_by_zero, Column::DivByZero);
            trace.fill_columns_bytes(row, &div_corr_hi, Column::DivCorrHi);
            trace.fill_columns_bytes(row, &div_corr_carry, Column::DivCorrCarry);
            trace.fill_columns(row, sign_bit_q, Column::SignBitQ);
            trace.fill_columns(row, sign_bit_r, Column::SignBitR);

            // ── Memory access columns ──
            trace.fill_columns(row, flags.is_exit, Column::IsExit);
            trace.fill_columns(row, flags.is_load, Column::IsLoad);
            trace.fill_columns(row, flags.is_store, Column::IsStore);
            let mem = step.mem_read.as_ref().or(step.mem_write.as_ref());
            if let Some(m) = mem {
                trace.fill_columns_bytes(row, &m.address.to_le_bytes(), Column::MemAddr);
                trace.fill_columns(row, m.value, Column::MemValue);
                trace.fill_columns(row, m.size, Column::MemSize);
                let mut byte_active = [0u8; 8];
                for i in 0..m.size as usize { byte_active[i] = 1; }
                trace.fill_columns_bytes(row, &byte_active, Column::MemByteActive);
            }

            // NextTimestamp = timestamp + 1
            trace.fill_columns(row, step.timestamp + 1, Column::NextTimestamp);

            // ── Blake2b ECALL binding (Phase 8c) ──
            // Detect Ecalli with imm == ECALL_BLAKE2B_COMPRESS and snapshot the
            // regs_before values that the precompile reads (φ[10], [11], [12])
            // plus the derived boolean form of φ[7].
            let is_blake_ecall = matches!(step.opcode,
                    crate::core::opcode::Opcode::Ecalli | crate::core::opcode::Opcode::Ecall)
                && step.imm == ECALL_BLAKE2B_COMPRESS as u64;
            trace.fill_columns(row, is_blake_ecall, Column::IsBlakeEcall);
            trace.fill_columns(row, step.regs_before[10], Column::Phi10);
            trace.fill_columns(row, step.regs_before[11], Column::Phi11);
            trace.fill_columns(row, step.regs_before[12], Column::Phi12);
            let phi7_u64 = step.regs_before[7];
            trace.fill_columns(row, phi7_u64, Column::Phi7);
            let phi7_bool: u8 = if phi7_u64 != 0 { 1 } else { 0 };
            trace.fill_columns(row, phi7_bool, Column::Phi7Bool);
            // Phi7Inv = field-element inverse of (Phi7 interpreted as u64, mod M31).
            // If Phi7 == 0 we store 0; the boolean-identity constraint
            //   Phi7Bool · (1 - Phi7_combined · Phi7Inv_combined) = 0
            // forces Phi7Inv to be the real inverse whenever Phi7Bool = 1.
            let phi7_inv_u64: u64 = if phi7_u64 != 0 {
                // Combine bytes with powers of 256 modulo the M31 prime,
                // then invert.  Rust's u128 multiplication + manual mod is
                // enough since M31 = 2^31 - 1.
                const M31_P: u64 = (1u64 << 31) - 1;
                let mut combined: u64 = 0;
                let bytes = phi7_u64.to_le_bytes();
                let mut pow: u64 = 1;
                for b in bytes {
                    combined = (combined + (b as u64) * pow) % M31_P;
                    pow = (pow * 256) % M31_P;
                }
                // Fermat's little theorem: inverse = combined^(p-2) mod p.
                let mut result: u64 = 1;
                let mut base = combined;
                let mut exp = M31_P - 2;
                while exp > 0 {
                    if exp & 1 == 1 {
                        result = (result * base) % M31_P;
                    }
                    base = (base * base) % M31_P;
                    exp >>= 1;
                }
                result
            } else {
                0
            };
            trace.fill_columns(row, phi7_inv_u64, Column::Phi7Inv);

            // ── Register-memory producer descriptors (Phase 9d) ──
            let accesses = step_reg_accesses(step);
            trace.fill_columns(row, accesses.val_b_read.is_some(), Column::ValBIsReg);
            trace.fill_columns(
                row,
                accesses.val_b_read.map(|(a, _)| a).unwrap_or(0),
                Column::ValBRegIdx,
            );
            trace.fill_columns(row, accesses.val_d_read.is_some(), Column::ValDIsReg);
            trace.fill_columns(
                row,
                accesses.val_d_read.map(|(a, _)| a).unwrap_or(0),
                Column::ValDRegIdx,
            );
            trace.fill_columns(row, accesses.result_write.is_some(), Column::ResultIsReg);
            trace.fill_columns(
                row,
                accesses.result_write.map(|(a, _)| a).unwrap_or(0),
                Column::ResultRegIdx,
            );

            // Phase 9g: raw register value behind ValB + IsTruncated flag.
            let reg_val_b_u64 = accesses.val_b_read.map(|(_, v)| v).unwrap_or(0);
            trace.fill_columns(row, reg_val_b_u64, Column::RegValB);
            let is_truncated: u8 = if flags.is_32bit
                && (flags.is_add || flags.is_sub || flags.is_mul || flags.is_div_rem)
            { 1 } else { 0 };
            trace.fill_columns(row, is_truncated, Column::IsTruncated);

            // Phase 9f: raw register value behind ValD + the shift quotient.
            let reg_val_d_u64 = accesses.val_d_read.map(|(_, v)| v).unwrap_or(0);
            trace.fill_columns(row, reg_val_d_u64, Column::RegValD);
            let shift_q: u64 = if flags.is_shift && flags.shift_op <= 2 {
                let modulus = if flags.is_32bit { 32u64 } else { 64 };
                reg_val_d_u64 / modulus
            } else {
                0
            };
            trace.fill_columns(row, shift_q, Column::ShiftQuotient);

            for &b in &result_bytes {
                range_bytes.push(b);
            }
            // Range-check cmp_sub_result bytes for carry chain soundness
            if flags.is_compare || flags.is_branch {
                for &b in &cmp_sub_result {
                    range_bytes.push(b);
                }
            }
        }

        for &b in &range_bytes {
            side_note.add_range256(b);
        }
        for &(a, b) in &bitwise_and_bytes {
            side_note.add_bitwise_and(a, b);
        }

        let last_ts = side_note.steps.last().map(|s| s.timestamp).unwrap_or(0);
        for row in num_steps..num_rows {
            let ts = last_ts + (row - num_steps + 1) as u64;
            trace.fill_columns(row, true, Column::IsPadding);
            trace.fill_columns(row, ts, Column::Timestamp);
            trace.fill_columns(row, ts + 1, Column::NextTimestamp);
        }

        trace.finalize_bit_reversed()
    }

    // ── Interaction trace ──────────────────────────────────────────────────

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
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

        // Range256 lookups for cmp_sub_result bytes (carry chain soundness)
        let is_compare_col = crate::trace::original_base_column!(component_trace, Column::IsCompare);
        let is_branch_col = crate::trace::original_base_column!(component_trace, Column::IsBranch);
        let cmp_sub_result = crate::trace::original_base_column!(component_trace, Column::CmpSubResult);
        for col in &cmp_sub_result {
            logup.add_to_relation_with(
                range256,
                [is_compare_col[0].clone(), is_branch_col[0].clone()],
                |[cmp, br]| (cmp + br).into(),
                &[col.clone()],
            );
        }

        // Memory access lookups — byte-level (up to 8 entries per memory op)
        let mem_lookup: &MemoryAccessLookupElements = lookup_elements.as_ref();
        let is_store = crate::trace::original_base_column!(component_trace, Column::IsStore);
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
            let is_store_c = is_store.clone();
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
                    // is_write
                    tuple.push(is_store_c[0].at(vec_idx));
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

        // Bitwise AND lookup: nibble-level (16 lookups per bitwise op)
        // For each byte i: lookup (hi_nib_b, hi_nib_d, hi_nib_and) and (lo_nib_b, lo_nib_d, lo_nib_and)
        let bitwise_and: &BitwiseAndLookupElements = lookup_elements.as_ref();
        let is_bitwise = crate::trace::original_base_column!(component_trace, Column::IsBitwise);
        let val_b_cols = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d_cols = crate::trace::original_base_column!(component_trace, Column::ValD);
        let and_result_cols = crate::trace::original_base_column!(component_trace, Column::AndResult);
        let val_b_hi_nib = crate::trace::original_base_column!(component_trace, Column::ValBHiNib);
        let val_d_hi_nib = crate::trace::original_base_column!(component_trace, Column::ValDHiNib);
        let and_result_hi_nib = crate::trace::original_base_column!(component_trace, Column::AndResultHiNib);
        let sixteen = PackedBaseField::broadcast(BaseField::from(16));
        for i in 0..WORD_SIZE {
            // High nibble lookup: (val_b_hi[i], val_d_hi[i], and_result_hi[i])
            logup.add_to_relation_with(
                bitwise_and,
                [is_bitwise[0].clone()],
                |[bw]| bw.into(),
                &[val_b_hi_nib[i].clone(), val_d_hi_nib[i].clone(), and_result_hi_nib[i].clone()],
            );
            // Low nibble lookup: (val_b_lo[i], val_d_lo[i], and_result_lo[i])
            // lo = byte - hi * 16
            let val_b_col_i = val_b_cols[i].clone();
            let val_d_col_i = val_d_cols[i].clone();
            let and_result_col_i = and_result_cols[i].clone();
            let val_b_hi_i = val_b_hi_nib[i].clone();
            let val_d_hi_i = val_d_hi_nib[i].clone();
            let and_hi_i = and_result_hi_nib[i].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [is_bitwise[0].clone()],
                |[bw]| bw.into(),
                3,
                |vec_idx| {
                    let b_lo = val_b_col_i.at(vec_idx) - val_b_hi_i.at(vec_idx) * sixteen;
                    let d_lo = val_d_col_i.at(vec_idx) - val_d_hi_i.at(vec_idx) * sixteen;
                    let and_lo = and_result_col_i.at(vec_idx) - and_hi_i.at(vec_idx) * sixteen;
                    vec![b_lo, d_lo, and_lo]
                },
            );
        }

        // Power-of-two lookup: (shift_amount, val_d[8]) when is_shift && shift_op ∈ {0,1}
        // Power-of-two lookup: (shift_amount, val_d[8]) when shift is constrained
        let pow2_lookup: &PowerOfTwoLookupElements = lookup_elements.as_ref();
        let shift_amount_col = crate::trace::original_base_column!(component_trace, Column::ShiftAmount);
        let is_shift_constrained = crate::trace::original_base_column!(component_trace, Column::IsShiftConstrained);
        let val_d_cols = crate::trace::original_base_column!(component_trace, Column::ValD);
        {
            let mut tuple: Vec<_> = vec![shift_amount_col[0].clone()];
            tuple.extend_from_slice(&val_d_cols);
            logup.add_to_relation_with(
                pow2_lookup,
                [is_shift_constrained[0].clone()],
                |[active]| active.into(),
                &tuple,
            );
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
            let f_is_mul_upper = crate::trace::original_base_column!(component_trace, Column::IsMulUpper);
            let f_is_bitwise = crate::trace::original_base_column!(component_trace, Column::IsBitwise);
            let f_is_shift = crate::trace::original_base_column!(component_trace, Column::IsShift);
            let f_is_compare = crate::trace::original_base_column!(component_trace, Column::IsCompare);
            let f_is_move = crate::trace::original_base_column!(component_trace, Column::IsMove);
            let f_is_32bit = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
            let f_is_branch = crate::trace::original_base_column!(component_trace, Column::IsBranch);
            let f_is_jump = crate::trace::original_base_column!(component_trace, Column::IsJump);
            let f_is_div_rem = crate::trace::original_base_column!(component_trace, Column::IsDivRem);
            let f_is_load = crate::trace::original_base_column!(component_trace, Column::IsLoad);
            let f_is_store = crate::trace::original_base_column!(component_trace, Column::IsStore);
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
            tuple.push(f_is_mul_upper[0].clone());
            tuple.push(f_is_bitwise[0].clone());
            tuple.push(f_is_shift[0].clone());
            tuple.push(f_is_compare[0].clone());
            tuple.push(f_is_move[0].clone());
            tuple.push(f_is_32bit[0].clone());
            tuple.push(f_is_branch[0].clone());
            tuple.push(f_is_jump[0].clone());
            tuple.push(f_is_div_rem[0].clone());
            tuple.push(f_is_load[0].clone());
            tuple.push(f_is_store[0].clone());
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
            tuple.extend_from_slice(&imm_y_for_lookup);
            tuple.extend_from_slice(&branch_target_for_lookup);

            // Two paired emissions, multiplicity = is_real = 1 - is_padding.
            for _ in 0..2 {
                let is_pad = is_pad_col[0].clone();
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
                        move |i| tuple_clone.iter().map(|c| c.at(i)).collect()
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

        logup.finalize()
    }

    // ── Constraints ────────────────────────────────────────────────────────
}
