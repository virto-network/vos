//! Shared p25519 FieldOpRow per-row constraint emitter.
//!
//! Lifted out of `chips/ristretto/mod.rs` so both `RistrettoChip`
//! (variable-base ladder) and `RistrettoFixedBaseConsumerChip`
//! (comb-method running sum) can pin identical FieldOpRow algebra
//! without duplicating ~400 lines of constraint code.
//!
//! What this emits (mirrors mod.rs's R1c-3..R1c-5-b blocks):
//!   - Helper-defining constraints for the deg-flatten witness columns
//!     (RealAddH, RealSubH, RealMulH, ProducerGateH, ConsumerAGateH,
//!     ConsumerBGateH, MulPartialSum[0..64]).
//!   - Boolean checks on every flag + carry-chain bit.
//!   - Real-row partition: exactly one of is_add/is_sub/is_mul/
//!     is_input/is_output is 1 on real rows.
//!   - Add chain (R1c-3): byte-sum + conditional p-reduction.
//!   - Final-form check (R1c-3-bis): chain closure `out < p`.
//!   - Sub chain (R1c-3-quat): two-sided forward-carry.
//!   - Schoolbook mul chain (R1c-4-b).
//!   - Pass-1 reduction `lo + 38·hi` (R1c-5-b).
//!   - Pass-2 reduction `pass1_lo + 38·pass1_hi`.
//!   - Top-bit fold + final FieldOut binding for is_mul rows.
//!
//! What this does NOT emit (chip-specific, stays in caller):
//!   - Range256 byte-range lookups.
//!   - Register-file (inter-row) producer/consumer relations.
//!   - Boundary lookups to ECALL or other chips.
//!
//! `eval.finalize_logup*()` is also the caller's responsibility — this
//! helper emits no relation entries, only `add_constraint` calls.

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

/// p25519 byte constants — `p = 2²⁵⁵ - 19`, little-endian.  Mirror of
/// `mod.rs::P_BYTE_CONSTS`; both sites agree byte-by-byte (cross-checked
/// against `field::P_BYTES` at compile time in mod.rs).
pub const P_BYTE_CONSTS: [u8; 32] = {
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

/// Borrowed view over the per-row witness columns the FieldOp algebra
/// references.  Caller materializes each column via `trace_eval!`
/// (returning `[E::F; N]`) and passes a slice of the array.
pub struct FieldOpRefs<'a, F> {
    /// Operand a (32 bytes LE).
    pub field_a: &'a [F],
    /// Operand b (32 bytes LE).
    pub field_b: &'a [F],
    /// Output a OP b mod p (32 bytes LE).
    pub field_out: &'a [F],
    /// Pre-reduction byte sum on is_add rows (32).
    pub add_intermediate: &'a [F],
    /// Per-position carry chain of `a + b` on is_add rows (32, each ∈ {0,1}).
    pub add_carry: &'a [F],
    /// Borrow chain for the conditional `intermediate − is_overflow·p` step (32, each ∈ {0,1}).
    pub sub_borrow: &'a [F],
    /// Final-form `p − out − 1 ≥ 0` borrow chain (32, each ∈ {0,1}).
    pub final_form_borrow: &'a [F],
    /// Sub-chain borrow for `out + b` (is_sub rows; 32 each ∈ {0,1}).
    pub sub_chain_borrow: &'a [F],
    /// Sub-chain carry for `a + is_underflow·p` (is_sub rows; 32 each ∈ {0,1}).
    pub sub_chain_carry_aip: &'a [F],
    /// Schoolbook unreduced 64-byte product (is_mul rows).
    pub mul_product: &'a [F],
    /// Schoolbook carry chain low byte per position (64).
    pub mul_carry: &'a [F],
    pub mul_carry_mid: &'a [F],
    pub mul_carry_hi: &'a [F],
    /// Pass-1 fold lo (32) and 2-byte hi.
    pub pass1_lo: &'a [F],
    pub pass1_hi: &'a [F],
    pub pass1_carry: &'a [F],
    pub pass1_carry_mid: &'a [F],
    /// Pass-2 fold (32) + 1-bit overflow + 32-byte carry chain.
    pub pass2_lo: &'a [F],
    pub pass2_carry_out: &'a [F],
    pub pass2_carry: &'a [F],
    /// Top-bit + after-top-bit fold.
    pub pass2_top_bit: &'a [F],
    pub after_top_bit: &'a [F],
    pub after_top_carry: &'a [F],
    /// Op classifier flags (1 cell each).
    pub is_overflow: &'a [F],
    pub is_add: &'a [F],
    pub is_sub: &'a [F],
    pub is_mul: &'a [F],
    pub is_input: &'a [F],
    pub is_output: &'a [F],
    pub is_real: &'a [F],
    /// Phase I-ristretto deg-flatten helpers (1 cell each).
    pub real_add_h: &'a [F],
    pub real_sub_h: &'a [F],
    pub real_mul_h: &'a [F],
    pub producer_gate_h: &'a [F],
    pub consumer_a_gate_h: &'a [F],
    pub consumer_b_gate_h: &'a [F],
    /// Schoolbook partial-sum helper (64).
    pub mul_partial_sum: &'a [F],
}

/// Emit all the FieldOp per-row constraints.  Caller is responsible for
/// chip-specific lookup emissions and `finalize_logup*()`.
///
/// Constraint degree ≤ 2 throughout (matches `LOG_CONSTRAINT_DEGREE_BOUND
/// = 1`'s actual-degree-2 budget after deg-flatten).  The mul-row
/// schoolbook chain factors `MulPartialSum[k]` (deg 1 helper) × `RealMulH`
/// (deg 1 helper) so the gated body sits at deg 2.
pub fn add_field_op_constraints<E: EvalAtRow>(eval: &mut E, r: &FieldOpRefs<'_, E::F>) {
    let f256: E::F = E::F::from(BaseField::from(256u32));
    let f38: E::F = E::F::from(BaseField::from(38u32));
    let f65536: E::F = E::F::from(BaseField::from(65536u32));
    let f128: E::F = E::F::from(BaseField::from(128u32));

    let a = r.field_a;
    let b = r.field_b;
    let out = r.field_out;
    let interm = r.add_intermediate;
    let carry = r.add_carry;
    let borrow = r.sub_borrow;
    let ff_brw = r.final_form_borrow;
    let sub_chain_brw = r.sub_chain_borrow;
    let sub_chain_aip = r.sub_chain_carry_aip;
    let mul_product = r.mul_product;
    let mul_carry = r.mul_carry;
    let mul_carry_mid = r.mul_carry_mid;
    let mul_carry_hi = r.mul_carry_hi;
    let pass1_lo = r.pass1_lo;
    let pass1_hi = r.pass1_hi;
    let pass1_carry = r.pass1_carry;
    let pass1_carry_mid = r.pass1_carry_mid;
    let pass2_lo = r.pass2_lo;
    let pass2_carry_out = r.pass2_carry_out;
    let pass2_carry = r.pass2_carry;
    let pass2_top_bit = r.pass2_top_bit;
    let after_top_bit = r.after_top_bit;
    let after_top_carry = r.after_top_carry;
    let is_ovf = r.is_overflow;
    let is_add = r.is_add;
    let is_sub = r.is_sub;
    let is_mul = r.is_mul;
    let is_input = r.is_input;
    let is_output = r.is_output;
    let is_real = r.is_real;
    let real_add_h = r.real_add_h;
    let real_sub_h = r.real_sub_h;
    let real_mul_h = r.real_mul_h;
    let producer_gate_h = r.producer_gate_h;
    let consumer_a_gate_h = r.consumer_a_gate_h;
    let consumer_b_gate_h = r.consumer_b_gate_h;
    let mul_partial_sum = r.mul_partial_sum;

    // ── Phase I-ristretto deg-flatten helpers ──
    eval.add_constraint(real_add_h[0].clone() - is_real[0].clone() * is_add[0].clone());
    eval.add_constraint(real_sub_h[0].clone() - is_real[0].clone() * is_sub[0].clone());
    eval.add_constraint(real_mul_h[0].clone() - is_real[0].clone() * is_mul[0].clone());
    eval.add_constraint(
        producer_gate_h[0].clone() - is_real[0].clone() * (E::F::one() - is_output[0].clone()),
    );
    eval.add_constraint(
        consumer_a_gate_h[0].clone() - is_real[0].clone() * (E::F::one() - is_input[0].clone()),
    );
    eval.add_constraint(
        consumer_b_gate_h[0].clone()
            - consumer_a_gate_h[0].clone() * (E::F::one() - is_output[0].clone()),
    );
    // MulPartialSum[k] = Σ_{i+j=k, i,j<32} a[i]·b[j].
    for k in 0..64usize {
        let mut psum = E::F::zero();
        for i in 0..32usize {
            let j = k.wrapping_sub(i);
            if j < 32 {
                psum += a[i].clone() * b[j].clone();
            }
        }
        eval.add_constraint(mul_partial_sum[k].clone() - psum);
    }

    // ── Boolean flags + carry-chain bits ──
    for flag in [is_ovf, is_add, is_sub, is_mul, is_input, is_output, is_real] {
        eval.add_constraint(flag[0].clone() * (E::F::one() - flag[0].clone()));
    }
    for c in carry.iter() {
        eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
    }
    for c in borrow.iter() {
        eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
    }
    for c in ff_brw.iter() {
        eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
    }
    for c in sub_chain_brw.iter() {
        eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
    }
    for c in sub_chain_aip.iter() {
        eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
    }

    // ── Real-row partition: exactly one op flag is 1 on real rows ──
    eval.add_constraint(
        is_real[0].clone()
            * (is_add[0].clone()
                + is_sub[0].clone()
                + is_mul[0].clone()
                + is_input[0].clone()
                + is_output[0].clone()
                - E::F::one()),
    );
    let not_real = E::F::one() - is_real[0].clone();
    eval.add_constraint(not_real.clone() * is_add[0].clone());
    eval.add_constraint(not_real.clone() * is_sub[0].clone());
    eval.add_constraint(not_real.clone() * is_mul[0].clone());
    eval.add_constraint(not_real.clone() * is_input[0].clone());
    eval.add_constraint(not_real * is_output[0].clone());

    // ── R1c-3: byte-wise sum chain (is_add rows) ──
    for i in 0..32 {
        let carry_in = if i == 0 {
            E::F::zero()
        } else {
            carry[i - 1].clone()
        };
        let lhs = interm[i].clone() + carry[i].clone() * f256.clone();
        let rhs = a[i].clone() + b[i].clone() + carry_in;
        eval.add_constraint(real_add_h[0].clone() * (lhs - rhs));
    }

    // ── R1c-3: conditional-reduction sub-chain (is_add rows) ──
    for i in 0..32 {
        let p_i = E::F::from(BaseField::from(P_BYTE_CONSTS[i] as u32));
        let borrow_in = if i == 0 {
            E::F::zero()
        } else {
            borrow[i - 1].clone()
        };
        let constraint = interm[i].clone() - is_ovf[0].clone() * p_i - borrow_in
            + borrow[i].clone() * f256.clone()
            - out[i].clone();
        eval.add_constraint(real_add_h[0].clone() * constraint);
    }

    // ── R1c-3-bis: final-form `out < p` chain closure (real rows) ──
    eval.add_constraint(is_real[0].clone() * ff_brw[31].clone());

    // ── R1c-3-quat: is_sub two-sided carry chain ──
    for i in 0..32 {
        let p_i = E::F::from(BaseField::from(P_BYTE_CONSTS[i] as u32));
        let cy_obb_in = if i == 0 {
            E::F::zero()
        } else {
            sub_chain_brw[i - 1].clone()
        };
        let cy_aip_in = if i == 0 {
            E::F::zero()
        } else {
            sub_chain_aip[i - 1].clone()
        };
        let constraint = out[i].clone() + b[i].clone() + cy_obb_in
            - sub_chain_brw[i].clone() * f256.clone()
            - a[i].clone()
            - is_ovf[0].clone() * p_i
            - cy_aip_in
            + sub_chain_aip[i].clone() * f256.clone();
        eval.add_constraint(real_sub_h[0].clone() * constraint);
    }
    // Closure: cy_obb[31] = cy_aip[31] (integer equality `out + b = a + is_uf·p`).
    eval.add_constraint(
        real_sub_h[0].clone() * (sub_chain_brw[31].clone() - sub_chain_aip[31].clone()),
    );

    // ── R1c-4-b: schoolbook 256×256 multiplication chain ──
    let full_carry = |k: usize| -> E::F {
        mul_carry[k].clone()
            + mul_carry_mid[k].clone() * f256.clone()
            + mul_carry_hi[k].clone() * f65536.clone()
    };
    for k in 0usize..64 {
        let carry_in = if k == 0 {
            E::F::zero()
        } else {
            full_carry(k - 1)
        };
        let constraint = mul_partial_sum[k].clone() + carry_in
            - mul_product[k].clone()
            - full_carry(k) * f256.clone();
        eval.add_constraint(real_mul_h[0].clone() * constraint);
    }
    // Closure: full_carry(63) = 0.
    eval.add_constraint(real_mul_h[0].clone() * full_carry(63));

    // ── R1c-5-b: pass-1 reduction `lo + 38·hi` ──
    let pass1_full_carry = |k: usize| -> E::F {
        pass1_carry[k].clone() + pass1_carry_mid[k].clone() * f256.clone()
    };
    let pass1_hi_value = || -> E::F { pass1_hi[0].clone() + pass1_hi[1].clone() * f256.clone() };
    for k in 0..32 {
        let carry_in = if k == 0 {
            E::F::zero()
        } else {
            pass1_full_carry(k - 1)
        };
        let constraint = pass1_lo[k].clone() + pass1_full_carry(k) * f256.clone()
            - mul_product[k].clone()
            - f38.clone() * mul_product[k + 32].clone()
            - carry_in;
        eval.add_constraint(real_mul_h[0].clone() * constraint);
    }
    eval.add_constraint(real_mul_h[0].clone() * (pass1_full_carry(31) - pass1_hi_value()));

    // ── R1c-5-b: pass-2 reduction `pass1_lo + 38·pass1_hi` ──
    for k in 0..32 {
        let carry_in = if k == 0 {
            E::F::zero()
        } else {
            pass2_carry[k - 1].clone()
        };
        let inject_byte = match k {
            0 => f38.clone() * pass1_hi[0].clone(),
            1 => f38.clone() * pass1_hi[1].clone(),
            _ => E::F::zero(),
        };
        let constraint = pass2_lo[k].clone() + pass2_carry[k].clone() * f256.clone()
            - pass1_lo[k].clone()
            - inject_byte
            - carry_in;
        eval.add_constraint(real_mul_h[0].clone() * constraint);
    }
    eval.add_constraint(
        real_mul_h[0].clone() * (pass2_carry[31].clone() - pass2_carry_out[0].clone()),
    );

    // ── R1c-5-b: top-bit fold (+ 38·pass2_carry_out + 19·pass2_top_bit) ──
    let inject0_after = f38.clone() * pass2_carry_out[0].clone()
        + E::F::from(BaseField::from(19u32)) * pass2_top_bit[0].clone();
    for k in 0..32 {
        let carry_in = if k == 0 {
            E::F::zero()
        } else {
            after_top_carry[k - 1].clone()
        };
        let inject = if k == 0 {
            inject0_after.clone()
        } else {
            E::F::zero()
        };
        let bit_strip = if k == 31 {
            f128.clone() * pass2_top_bit[0].clone()
        } else {
            E::F::zero()
        };
        let constraint = after_top_bit[k].clone() + after_top_carry[k].clone() * f256.clone()
            - pass2_lo[k].clone()
            - inject
            - carry_in
            + bit_strip;
        eval.add_constraint(real_mul_h[0].clone() * constraint);
    }
    eval.add_constraint(real_mul_h[0].clone() * after_top_carry[31].clone());

    // pass2_carry_out, pass2_top_bit ∈ {0, 1}.
    eval.add_constraint(
        pass2_carry_out[0].clone() * (E::F::one() - pass2_carry_out[0].clone()),
    );
    eval.add_constraint(pass2_top_bit[0].clone() * (E::F::one() - pass2_top_bit[0].clone()));

    // ── R1c-5-b: final FieldOut = after_top_bit − is_overflow·p (is_mul rows) ──
    for i in 0..32 {
        let p_i = E::F::from(BaseField::from(P_BYTE_CONSTS[i] as u32));
        let borrow_in = if i == 0 {
            E::F::zero()
        } else {
            borrow[i - 1].clone()
        };
        let constraint = after_top_bit[i].clone() - is_ovf[0].clone() * p_i - borrow_in
            + borrow[i].clone() * f256.clone()
            - out[i].clone();
        eval.add_constraint(real_mul_h[0].clone() * constraint);
    }
}
