//! The compression core's constraints.

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::PreprocessedAirColumn;
use crate::lookups::{BitwiseAndByteLookupElements, Range256LookupElements};
use crate::trace::eval::TraceEval;

use super::Blake2bSchedule;
use crate::chips::blake2b::columns::CompressionColumns;
use crate::chips::blake2b::consts::{G_INDICES, IV};

/// The columns of a compression row the core's constraints read.
struct Core<F> {
    is_real: [F; 1],
    gate_h: [F; 1],
    init_gate_h: [F; 1],
    output_gate_h: [F; 1],
    a_in: [F; 8],
    b_in: [F; 8],
    c_in: [F; 8],
    d_in: [F; 8],
    mx: [F; 8],
    my: [F; 8],
    a1: [F; 8],
    carry1: [F; 8],
    and1: [F; 8],
    c1: [F; 8],
    carry2: [F; 8],
    and2: [F; 8],
    a_out: [F; 8],
    carry3: [F; 8],
    and3: [F; 8],
    c_out: [F; 8],
    carry4: [F; 8],
    and4: [F; 8],
    b_out: [F; 8],
    rot63_carry: [F; 8],
    d_out: [F; 8],
    v: [[F; 8]; 16],
    h: [[F; 8]; 8],
    t: [F; 16],
    f: [F; 1],
    and_t_lo: [F; 8],
    and_t_hi: [F; 8],
}

impl<F: Clone> Core<F> {
    fn read<P: PreprocessedAirColumn, C: CompressionColumns, E: EvalAtRow<F = F>>(
        trace_eval: &TraceEval<P, C, E>,
    ) -> Self {
        Self {
            is_real: trace_eval.column_eval(C::IS_REAL),
            gate_h: trace_eval.column_eval(C::GATE_H),
            init_gate_h: trace_eval.column_eval(C::INIT_GATE_H),
            output_gate_h: trace_eval.column_eval(C::OUTPUT_GATE_H),
            a_in: trace_eval.column_eval(C::A_IN),
            b_in: trace_eval.column_eval(C::B_IN),
            c_in: trace_eval.column_eval(C::C_IN),
            d_in: trace_eval.column_eval(C::D_IN),
            mx: trace_eval.column_eval(C::MX),
            my: trace_eval.column_eval(C::MY),
            a1: trace_eval.column_eval(C::A1),
            carry1: trace_eval.column_eval(C::CARRY1),
            and1: trace_eval.column_eval(C::AND1),
            c1: trace_eval.column_eval(C::C1),
            carry2: trace_eval.column_eval(C::CARRY2),
            and2: trace_eval.column_eval(C::AND2),
            a_out: trace_eval.column_eval(C::A_OUT),
            carry3: trace_eval.column_eval(C::CARRY3),
            and3: trace_eval.column_eval(C::AND3),
            c_out: trace_eval.column_eval(C::C_OUT),
            carry4: trace_eval.column_eval(C::CARRY4),
            and4: trace_eval.column_eval(C::AND4),
            b_out: trace_eval.column_eval(C::B_OUT),
            rot63_carry: trace_eval.column_eval(C::ROT63_CARRY),
            d_out: trace_eval.column_eval(C::D_OUT),
            v: core::array::from_fn(|k| trace_eval.column_eval(C::V[k])),
            h: core::array::from_fn(|k| trace_eval.column_eval(C::H[k])),
            t: trace_eval.column_eval(C::T),
            f: trace_eval.column_eval(C::F),
            and_t_lo: trace_eval.column_eval(C::AND_T_LO),
            and_t_hi: trace_eval.column_eval(C::AND_T_HI),
        }
    }
}

/// The blake2b compression arithmetic core: G-function steps, nibble-AND
/// derivations, carry / rotation bounds, V-state row chaining, message
/// authentication, initial-state derivation, and the row-95 output
/// derivation — together with the BitwiseAnd / Range256 lookups those
/// witnesses require, plus the GateH / InitGateH / OutputGateH helper
/// definitions.  Shared verbatim by `Blake2bChip` (which adds the
/// memory-ledger + CPU-call bindings) and `Blake2bBoundaryChip` (which adds
/// its own IsReal anchor + Blake2bCompression producer instead).  Does NOT
/// finalize the logup.
pub(in crate::chips::blake2b) fn add_compression_core<
    P: PreprocessedAirColumn,
    C: CompressionColumns,
    E: EvalAtRow,
>(
    eval: &mut E,
    trace_eval: &TraceEval<P, C, E>,
    sched: &Blake2bSchedule<E::F>,
    range256_lookup: &Range256LookupElements,
    bitwise_lookup: &BitwiseAndByteLookupElements,
) {
    let core = Core::read(trace_eval);
    gate_helpers(eval, &core, sched);
    g_function(eval, &core);
    and_lookups(eval, &core, bitwise_lookup);
    range_lookups(eval, &core, range256_lookup);
    carry_bounds(eval, trace_eval, &core);
    d_out(eval, &core);
    row_chaining(eval, trace_eval, &core, sched);
    message(eval, trace_eval, &core, sched);
    initial_state(eval, trace_eval, &core);
    constant_inputs(eval, trace_eval, &core);
    output(eval, trace_eval, &core, bitwise_lookup);
}

/// The gate helpers: `GateH`, `InitGateH` and `OutputGateH` are `IsReal`
/// times the schedule's selectors, so every gated constraint after them
/// stays at degree 2.
fn gate_helpers<E: EvalAtRow>(eval: &mut E, core: &Core<E::F>, sched: &Blake2bSchedule<E::F>) {
    let Core {
        is_real,
        gate_h,
        init_gate_h,
        output_gate_h,
        ..
    } = core;
    let is_first = &sched.is_first;
    let is_last = &sched.is_last;
    let f1_top = E::F::one();
    eval.add_constraint(
        gate_h[0].clone() - is_real[0].clone() * (f1_top.clone() - is_last[0].clone()),
    );
    eval.add_constraint(init_gate_h[0].clone() - is_real[0].clone() * is_first[0].clone());
    eval.add_constraint(output_gate_h[0].clone() - is_real[0].clone() * is_last[0].clone());
}

/// The G function's additions and rotations, steps 1 to 8.
fn g_function<E: EvalAtRow>(eval: &mut E, core: &Core<E::F>) {
    let Core {
        is_real,
        a_in,
        b_in,
        c_in,
        d_in,
        mx,
        my,
        a1,
        carry1,
        and1,
        c1,
        carry2,
        and2,
        a_out,
        carry3,
        and3,
        c_out,
        carry4,
        and4,
        b_out,
        rot63_carry,
        ..
    } = core;
    let f256 = E::F::from(BaseField::from(256u32));
    let f2 = E::F::from(BaseField::from(2u32));
    // ── Step 1: a1 = a_in + b_in + mx (3-input addition) ──
    for i in 0..8 {
        let carry_in = if i == 0 {
            E::F::zero()
        } else {
            carry1[i - 1].clone()
        };
        eval.add_constraint(
            is_real[0].clone()
                * (a1[i].clone() + carry1[i].clone() * f256.clone()
                    - a_in[i].clone()
                    - b_in[i].clone()
                    - mx[i].clone()
                    - carry_in),
        );
    }

    // ── Step 2: xor1 = d ^ a1, d1 = xor1 >>> 32 (byte permutation) ──
    // xor1[i] = d_in[i] + a1[i] - 2*and1[i]
    // d1[i] = xor1[(i+4)%8]

    // ── Step 3: c1 = c_in + d1 ──
    // d1[i] = xor1[(i+4)%8] = d_in[(i+4)%8] + a1[(i+4)%8] - 2*and1[(i+4)%8]
    for i in 0..8 {
        let carry_in = if i == 0 {
            E::F::zero()
        } else {
            carry2[i - 1].clone()
        };
        let j = (i + 4) % 8; // byte permutation for >>>32
        let d1_i = d_in[j].clone() + a1[j].clone() - f2.clone() * and1[j].clone();
        eval.add_constraint(
            is_real[0].clone()
                * (c1[i].clone() + carry2[i].clone() * f256.clone()
                    - c_in[i].clone()
                    - d1_i
                    - carry_in),
        );
    }

    // ── Step 4: xor2 = b ^ c1, b1 = xor2 >>> 24 ──
    // b1[i] = xor2[(i+3)%8] = b_in[(i+3)%8] + c1[(i+3)%8] - 2*and2[(i+3)%8]

    // ── Step 5: a_out = a1 + b1 + my ──
    for i in 0..8 {
        let carry_in = if i == 0 {
            E::F::zero()
        } else {
            carry3[i - 1].clone()
        };
        let j = (i + 3) % 8; // byte permutation for >>>24
        let b1_i = b_in[j].clone() + c1[j].clone() - f2.clone() * and2[j].clone();
        eval.add_constraint(
            is_real[0].clone()
                * (a_out[i].clone() + carry3[i].clone() * f256.clone()
                    - a1[i].clone()
                    - b1_i
                    - my[i].clone()
                    - carry_in),
        );
    }

    // ── Step 6: xor3 = d1 ^ a_out, d_out = xor3 >>> 16 ──
    // d1[i] = d_in[(i+4)%8] + a1[(i+4)%8] - 2*and1[(i+4)%8] (from step 2)
    // d_out[i] = xor3[(i+2)%8]

    // ── Step 7: c_out = c1 + d_out ──
    for i in 0..8 {
        let carry_in = if i == 0 {
            E::F::zero()
        } else {
            carry4[i - 1].clone()
        };
        // d_out[i] = xor3[(i+2)%8] where xor3[k] = d1[k] + a_out[k] - 2*and3[k]
        // d1[k] = d_in[(k+4)%8] + a1[(k+4)%8] - 2*and1[(k+4)%8]
        let k = (i + 2) % 8; // byte perm for >>>16
        let j = (k + 4) % 8; // byte perm for >>>32 (d1)
        let d1_k = d_in[j].clone() + a1[j].clone() - f2.clone() * and1[j].clone();
        let d_out_i = d1_k + a_out[k].clone() - f2.clone() * and3[k].clone();
        eval.add_constraint(
            is_real[0].clone()
                * (c_out[i].clone() + carry4[i].clone() * f256.clone()
                    - c1[i].clone()
                    - d_out_i
                    - carry_in),
        );
    }

    // ── Step 8: xor4 = b1 ^ c_out, b_out = xor4 >>> 63 ──
    // >>>63 = left rotate by 1. At byte level:
    //   b_out[i] = ((xor4[i] << 1) | (xor4[(i+7)%8] >> 7)) & 0xFF
    // = (xor4[i] * 2 + rot63_carry[(i+7)%8]) mod 256
    // where rot63_carry[j] = xor4[j] >> 7 (high bit)
    for i in 0..8 {
        let j = (i + 3) % 8; // b1 byte perm (>>>24)
        let b1_i = b_in[j].clone() + c1[j].clone() - f2.clone() * and2[j].clone();
        let xor4_i = b1_i + c_out[i].clone() - f2.clone() * and4[i].clone();
        let prev_carry = rot63_carry[(i + 7) % 8].clone();
        // b_out[i] + rot63_overflow * 256 = xor4[i] * 2 + prev_carry
        // But rot63_carry[i] = xor4[i] >> 7, so xor4[i] * 2 + prev_carry can be:
        // If xor4[i] < 128: result = xor4[i]*2 + prev_carry, carry_out = 0
        // If xor4[i] >= 128: result = xor4[i]*2 + prev_carry - 256, carry_out = 1
        // Constraint: b_out[i] + rot63_carry[i] * 256 = xor4[i] * 2 + prev_carry
        eval.add_constraint(
            is_real[0].clone()
                * (b_out[i].clone() + rot63_carry[i].clone() * f256.clone()
                    - f2.clone() * xor4_i
                    - prev_carry),
        );
    }
}

/// The byte-wide AND lookups the G function's XORs and the initial
/// state's `T` read.
fn and_lookups<E: EvalAtRow>(
    eval: &mut E,
    core: &Core<E::F>,
    bitwise_lookup: &BitwiseAndByteLookupElements,
) {
    let Core {
        is_real,
        d_in,
        a1,
        and1,
        b_in,
        c1,
        and2,
        a_out,
        and3,
        c_out,
        and4,
        ..
    } = core;
    let f2 = E::F::from(BaseField::from(2u32));

    // ── Byte-wide AND lookups ────────────────────────────────
    // Mirror of generate_interaction_trace: for each byte i, emit 6 byte
    // lookups in the exact order (And1, And2, And3, And4, AndTLo, AndTHi)
    // into BitwiseAndByteChip.  The operands' byte-ness comes free from table
    // membership; finalize_logup_in_pairs batches consecutive entries, so the
    // ordering MUST match the prover side.
    let t_e = &core.t;
    let and_t_lo_e = &core.and_t_lo;
    let and_t_hi_e = &core.and_t_hi;
    for i in 0..8 {
        // And1 = D_in & A1
        eval.add_to_relation(RelationEntry::new(
            bitwise_lookup,
            is_real[0].clone().into(),
            &[d_in[i].clone(), a1[i].clone(), and1[i].clone()],
        ));
        // And2 = B_in & C1
        eval.add_to_relation(RelationEntry::new(
            bitwise_lookup,
            is_real[0].clone().into(),
            &[b_in[i].clone(), c1[i].clone(), and2[i].clone()],
        ));
        // And3 = D1 & A_out, D1[i] = D_in[j] + A1[j] - 2·And1[j], j=(i+4)%8
        let j3 = (i + 4) % 8;
        let d1_i = d_in[j3].clone() + a1[j3].clone() - f2.clone() * and1[j3].clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_lookup,
            is_real[0].clone().into(),
            &[d1_i, a_out[i].clone(), and3[i].clone()],
        ));
        // And4 = B1 & C_out, B1[i] = B_in[j] + C1[j] - 2·And2[j], j=(i+3)%8
        let j4 = (i + 3) % 8;
        let b1_i = b_in[j4].clone() + c1[j4].clone() - f2.clone() * and2[j4].clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_lookup,
            is_real[0].clone().into(),
            &[b1_i, c_out[i].clone(), and4[i].clone()],
        ));

        // ── AndTLo = IV[4] & T[i] (IV[4] const a-side) ──
        let iv4_byte = IV[4].to_le_bytes()[i];
        let iv4_f = E::F::from(BaseField::from(iv4_byte as u32));
        eval.add_to_relation(RelationEntry::new(
            bitwise_lookup,
            is_real[0].clone().into(),
            &[iv4_f, t_e[i].clone(), and_t_lo_e[i].clone()],
        ));
        // ── AndTHi = IV[5] & T[8+i] ──
        let iv5_byte = IV[5].to_le_bytes()[i];
        let iv5_f = E::F::from(BaseField::from(iv5_byte as u32));
        eval.add_to_relation(RelationEntry::new(
            bitwise_lookup,
            is_real[0].clone().into(),
            &[iv5_f, t_e[8 + i].clone(), and_t_hi_e[i].clone()],
        ));
    }
}

/// The Range256 lookups of the byte columns no AND lookup covers.
fn range_lookups<E: EvalAtRow>(
    eval: &mut E,
    core: &Core<E::F>,
    range256_lookup: &Range256LookupElements,
) {
    let is_real = &core.is_real;
    // ── Range256 for non-AND-covered byte columns ──
    // Must match the prover-side order from generate_interaction_trace.
    let a_in_e = &core.a_in;
    let c_in_e = &core.c_in;
    let mx_e = &core.mx;
    let my_e = &core.my;
    let b_out_e = &core.b_out;
    for col in [&a_in_e, &c_in_e, &mx_e, &my_e, &b_out_e] {
        for i in 0..8 {
            eval.add_to_relation(RelationEntry::new(
                range256_lookup,
                is_real[0].clone().into(),
                &[col[i].clone()],
            ));
        }
    }

    // NOTE: finalize_logup_in_pairs is called at the very end of this
    // method so output-derivation relation entries are included in the pairing.
}

/// The carries' and the rotation carry's bounds.
fn carry_bounds<P: PreprocessedAirColumn, C: CompressionColumns, E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &TraceEval<P, C, E>,
    core: &Core<E::F>,
) {
    let Core {
        is_real,
        carry1,
        carry2,
        carry3,
        carry4,
        rot63_carry,
        ..
    } = core;
    let f2 = E::F::from(BaseField::from(2u32));

    // ── Carry / rot-carry bounds (helper-flattened) ──
    // 3-input additions (steps 1, 5) produce Carry ∈ {0,1,2}: a+b+c+cin ≤ 767.
    // 2-input additions (steps 3, 7) produce Carry ∈ {0,1}: a+b+cin ≤ 511.
    // Rot63Carry is the top bit of xor4, bounded to {0,1}.
    //
    // Original formulation `is_real · c · (c-1) · (c-2)` (deg 4) and
    // `is_real · c · (c-1)` (deg 3) flattened via XcM1 / Full helper
    // columns (`Column::Carry{1,2,3,4}XcM1`, `Carry{1,3}Full`, `Rot63XcM1`).
    let f1 = E::F::one();
    let carry1_xcm1 = trace_eval.column_eval::<8>(C::CARRY1_XCM1);
    let carry1_full = trace_eval.column_eval::<8>(C::CARRY1_FULL);
    let carry3_xcm1 = trace_eval.column_eval::<8>(C::CARRY3_XCM1);
    let carry3_full = trace_eval.column_eval::<8>(C::CARRY3_FULL);
    let carry2_xcm1 = trace_eval.column_eval::<8>(C::CARRY2_XCM1);
    let carry4_xcm1 = trace_eval.column_eval::<8>(C::CARRY4_XCM1);
    let rot63_xcm1 = trace_eval.column_eval::<8>(C::ROT63_XCM1);
    for i in 0..8 {
        // Carry1: degree-4 → degree-2 via 2 helpers.
        let c1_v = carry1[i].clone();
        eval.add_constraint(carry1_xcm1[i].clone() - c1_v.clone() * (c1_v.clone() - f1.clone()));
        eval.add_constraint(carry1_full[i].clone() - carry1_xcm1[i].clone() * (c1_v - f2.clone()));
        eval.add_constraint(is_real[0].clone() * carry1_full[i].clone());

        // Carry3: same.
        let c3_v = carry3[i].clone();
        eval.add_constraint(carry3_xcm1[i].clone() - c3_v.clone() * (c3_v.clone() - f1.clone()));
        eval.add_constraint(carry3_full[i].clone() - carry3_xcm1[i].clone() * (c3_v - f2.clone()));
        eval.add_constraint(is_real[0].clone() * carry3_full[i].clone());

        // Carry2: degree-3 → degree-2 via 1 helper.
        let c2_v = carry2[i].clone();
        eval.add_constraint(carry2_xcm1[i].clone() - c2_v.clone() * (c2_v - f1.clone()));
        eval.add_constraint(is_real[0].clone() * carry2_xcm1[i].clone());

        // Carry4: same.
        let c4_v = carry4[i].clone();
        eval.add_constraint(carry4_xcm1[i].clone() - c4_v.clone() * (c4_v - f1.clone()));
        eval.add_constraint(is_real[0].clone() * carry4_xcm1[i].clone());

        // Rot63Carry: same.
        let r_v = rot63_carry[i].clone();
        eval.add_constraint(rot63_xcm1[i].clone() - r_v.clone() * (r_v - f1.clone()));
        eval.add_constraint(is_real[0].clone() * rot63_xcm1[i].clone());
    }
}

/// `DOut`, the G function's last rotation, as a column.
fn d_out<E: EvalAtRow>(eval: &mut E, core: &Core<E::F>) {
    let Core {
        is_real,
        d_in,
        a1,
        and1,
        a_out,
        and3,
        ..
    } = core;
    let f2 = E::F::from(BaseField::from(2u32));

    // ── D_out reification ──
    // d_out[i] = xor3[(i+2)%8] where xor3[k] = d1[k] + a_out[k] - 2·and3[k]
    // and d1[k] = d_in[(k+4)%8] + a1[(k+4)%8] - 2·and1[(k+4)%8].
    // Reify so it can flow into V_next[di] via the row-chain update.
    let d_out = &core.d_out;
    for i in 0..8 {
        let k = (i + 2) % 8;
        let j = (k + 4) % 8;
        let d1_k = d_in[j].clone() + a1[j].clone() - f2.clone() * and1[j].clone();
        let xor3_k = d1_k + a_out[k].clone() - f2.clone() * and3[k].clone();
        eval.add_constraint(is_real[0].clone() * (d_out[i].clone() - xor3_k));
    }
}

/// Row chaining: a row's G inputs are the V state's slots its G index
/// names, and the next row's V state is this one's after the G call.
fn row_chaining<P: PreprocessedAirColumn, C: CompressionColumns, E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &TraceEval<P, C, E>,
    core: &Core<E::F>,
    sched: &Blake2bSchedule<E::F>,
) {
    let Core {
        is_real,
        gate_h,
        a_in,
        b_in,
        c_in,
        d_in,
        a_out,
        b_out,
        c_out,
        d_out,
        ..
    } = core;
    // ── Row chaining: preprocessed schedule + V-state inputs and update ──
    // IsGIdx[j] (preprocessed) = 1 iff (r % 8) == j.  G_INDICES[j] gives the
    // 4 touched slots (ai,bi,ci,di) for that G-call.  IsLastOfCompression
    // (preprocessed) = 1 iff r is the 95th row of some compression.
    let is_gidx = &sched.is_gidx;

    let v_cols = &core.v;
    let v_cols_next: [[E::F; 8]; 16] =
        core::array::from_fn(|k| trace_eval.column_eval_next_row::<8>(C::V[k]));

    // Input match (helper-flattened): a_in[i] = V[G_INDICES[j][0]][i]
    // when IsGIdx[j]=1, etc.  Written as a_in[i] = Σ_j IsGIdx[j] · V[G_INDICES[j][0]][i]
    // and routed through `InMatch{A,B,C,D}` sum helpers so the gate × sum product
    // sits at degree 2 instead of 3.
    let in_match_a = trace_eval.column_eval::<8>(C::IN_MATCH_A);
    let in_match_b = trace_eval.column_eval::<8>(C::IN_MATCH_B);
    let in_match_c = trace_eval.column_eval::<8>(C::IN_MATCH_C);
    let in_match_d = trace_eval.column_eval::<8>(C::IN_MATCH_D);
    for i in 0..8 {
        let mut exp_a = E::F::zero();
        let mut exp_b = E::F::zero();
        let mut exp_c = E::F::zero();
        let mut exp_d = E::F::zero();
        for (j, &[aj, bj, cj, dj]) in G_INDICES.iter().enumerate() {
            exp_a += is_gidx[j][0].clone() * v_cols[aj][i].clone();
            exp_b += is_gidx[j][0].clone() * v_cols[bj][i].clone();
            exp_c += is_gidx[j][0].clone() * v_cols[cj][i].clone();
            exp_d += is_gidx[j][0].clone() * v_cols[dj][i].clone();
        }
        // Helper-defining (deg 2): InMatchX[i] = Σ IsGIdx[j] · V[…][i].
        eval.add_constraint(in_match_a[i].clone() - exp_a);
        eval.add_constraint(in_match_b[i].clone() - exp_b);
        eval.add_constraint(in_match_c[i].clone() - exp_c);
        eval.add_constraint(in_match_d[i].clone() - exp_d);
        // Main (deg 2): is_real · (input_byte - InMatchX[i]) = 0.
        eval.add_constraint(is_real[0].clone() * (a_in[i].clone() - in_match_a[i].clone()));
        eval.add_constraint(is_real[0].clone() * (b_in[i].clone() - in_match_b[i].clone()));
        eval.add_constraint(is_real[0].clone() * (c_in[i].clone() - in_match_c[i].clone()));
        eval.add_constraint(is_real[0].clone() * (d_in[i].clone() - in_match_d[i].clone()));
    }

    // V_next update (helper-flattened): for slot k
    // at byte i, V_next[k][i] equals
    //   Σ_j IsGIdx[j] · (a_out/b_out/c_out/d_out if k is touched by G_j,
    //                    else V[k]).
    // Gated by is_real · (1 - is_last_of_compression) so the constraint
    // does not cross a compression boundary or fire on padding.
    // Gate substitution: gate ← GateH.
    let gate = gate_h[0].clone();
    let v_next_sum: [[E::F; 8]; 16] =
        core::array::from_fn(|k| trace_eval.column_eval::<8>(C::V_NEXT_SUM[k]));
    for k in 0..16 {
        for i in 0..8 {
            let mut update = E::F::zero();
            for (j, &[aj, bj, cj, dj]) in G_INDICES.iter().enumerate() {
                let contribution = if k == aj {
                    a_out[i].clone()
                } else if k == bj {
                    b_out[i].clone()
                } else if k == cj {
                    c_out[i].clone()
                } else if k == dj {
                    d_out[i].clone()
                } else {
                    v_cols[k][i].clone()
                };
                update += is_gidx[j][0].clone() * contribution;
            }
            // Helper-defining (deg 2): VNextSumK[i] = Σ_j IsGIdx[j] · contribution_j(k, i).
            eval.add_constraint(v_next_sum[k][i].clone() - update);
            // Main (deg 2): GateH · (V_next[k][i] - VNextSumK[i]) = 0.
            eval.add_constraint(
                gate.clone() * (v_cols_next[k][i].clone() - v_next_sum[k][i].clone()),
            );
        }
    }
}

/// Message authentication: `Mx` and `My` are the message slots the
/// schedule selects, and the message is constant within a compression.
fn message<P: PreprocessedAirColumn, C: CompressionColumns, E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &TraceEval<P, C, E>,
    core: &Core<E::F>,
    sched: &Blake2bSchedule<E::F>,
) {
    let Core {
        is_real,
        gate_h,
        mx,
        my,
        ..
    } = core;
    let gate = gate_h[0].clone();
    // ── Message authentication ──────────────────────────────
    // M[0..16] witness columns hold the message for this compression.
    // IsMxSlot_k / IsMySlot_k preprocessed selectors encode
    // SIGMA[round][2·g_idx] and SIGMA[round][2·g_idx + 1], so Mx / My
    // become a linear combination of the 16 M slots weighted by the
    // selectors.  Inter-row M_k_next = M_k keeps the message constant
    // across the 96 rows of a single compression.
    let m_cols: [[E::F; 8]; 16] = core::array::from_fn(|k| trace_eval.column_eval::<8>(C::M[k]));
    let m_cols_next: [[E::F; 8]; 16] =
        core::array::from_fn(|k| trace_eval.column_eval_next_row::<8>(C::M[k]));
    let is_mx_slot = &sched.is_mx_slot;
    let is_my_slot = &sched.is_my_slot;

    // Mx / My selection from M by preprocessed selector
    // (helper-flattened).
    let mx_slot_sum = trace_eval.column_eval::<8>(C::MX_SLOT_SUM);
    let my_slot_sum = trace_eval.column_eval::<8>(C::MY_SLOT_SUM);
    for i in 0..8 {
        let mut exp_mx = E::F::zero();
        let mut exp_my = E::F::zero();
        for k in 0..16 {
            exp_mx += is_mx_slot[k][0].clone() * m_cols[k][i].clone();
            exp_my += is_my_slot[k][0].clone() * m_cols[k][i].clone();
        }
        // Helper-defining (deg 2): SlotSum[i] = Σ_k IsXSlot[k] · M[k][i].
        eval.add_constraint(mx_slot_sum[i].clone() - exp_mx);
        eval.add_constraint(my_slot_sum[i].clone() - exp_my);
        // Main (deg 2): is_real · (mx[i] - MxSlotSum[i]) = 0.
        eval.add_constraint(is_real[0].clone() * (mx[i].clone() - mx_slot_sum[i].clone()));
        eval.add_constraint(is_real[0].clone() * (my[i].clone() - my_slot_sum[i].clone()));
    }

    // Inter-row: M[k] stays constant within a compression.  Gate identical
    // to the V-state update so message slots reset at compression boundary.
    for k in 0..16 {
        for i in 0..8 {
            eval.add_constraint(gate.clone() * (m_cols_next[k][i].clone() - m_cols[k][i].clone()));
        }
    }
}

/// The initial state: on a compression's first row the V state is `H`,
/// the IV and the IV mixed with `T` and `F`.
fn initial_state<P: PreprocessedAirColumn, C: CompressionColumns, E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &TraceEval<P, C, E>,
    core: &Core<E::F>,
) {
    let Core {
        is_real,
        init_gate_h,
        ..
    } = core;
    let v_cols = &core.v;
    let f1 = E::F::one();
    let f2 = E::F::from(BaseField::from(2u32));

    // ── Initial state derivation + compression-input consistency ────
    // H, T, F are replicated on every row of a compression (inter-row
    // equality below) so we can anchor the V state at row 0 of a
    // compression to the Blake2b initial state:
    //   V[0..8][i]  = H_k[i]
    //   V[8..12][i] = IV[k-8][i]
    //   V[12][i]    = IV[4][i] XOR T[i]
    //                 = IV[4][i] + T[i] - 2·AndTLo[i]
    //   V[13][i]    = IV[5][i] XOR T[8+i]
    //                 = IV[5][i] + T[8+i] - 2·AndTHi[i]
    //   V[14][i]    = IV[6][i] XOR (F ? 0xFF : 0)
    //                 = IV[6][i] + F·(255 - 2·IV[6][i])
    //   V[15][i]    = IV[7][i]
    let h_cols = &core.h;
    let t_e = &core.t;
    let f_e = &core.f;
    let and_t_lo_e = &core.and_t_lo;
    let and_t_hi_e = &core.and_t_hi;

    // F ∈ {0,1} (helper-flattened).
    let f_bound_h = trace_eval.column_eval::<1>(C::F_BOUND_H);
    eval.add_constraint(f_bound_h[0].clone() - f_e[0].clone() * (f_e[0].clone() - f1.clone()));
    eval.add_constraint(is_real[0].clone() * f_bound_h[0].clone());

    // Gate substitution: init_gate ← InitGateH.
    let init_gate = init_gate_h[0].clone();
    let f255 = E::F::from(BaseField::from(255u32));
    for i in 0..8 {
        let iv4_i = E::F::from(BaseField::from(IV[4].to_le_bytes()[i] as u32));
        let iv5_i = E::F::from(BaseField::from(IV[5].to_le_bytes()[i] as u32));
        let iv6_i = E::F::from(BaseField::from(IV[6].to_le_bytes()[i] as u32));
        let iv7_i = E::F::from(BaseField::from(IV[7].to_le_bytes()[i] as u32));
        let iv0_i = E::F::from(BaseField::from(IV[0].to_le_bytes()[i] as u32));
        let iv1_i = E::F::from(BaseField::from(IV[1].to_le_bytes()[i] as u32));
        let iv2_i = E::F::from(BaseField::from(IV[2].to_le_bytes()[i] as u32));
        let iv3_i = E::F::from(BaseField::from(IV[3].to_le_bytes()[i] as u32));
        // V[0..8] = H_k
        for k in 0..8 {
            eval.add_constraint(init_gate.clone() * (v_cols[k][i].clone() - h_cols[k][i].clone()));
        }
        // V[8..12] = IV[0..4]
        eval.add_constraint(init_gate.clone() * (v_cols[8][i].clone() - iv0_i.clone()));
        eval.add_constraint(init_gate.clone() * (v_cols[9][i].clone() - iv1_i.clone()));
        eval.add_constraint(init_gate.clone() * (v_cols[10][i].clone() - iv2_i.clone()));
        eval.add_constraint(init_gate.clone() * (v_cols[11][i].clone() - iv3_i.clone()));
        // V[12] = IV[4] XOR T[i] via XOR identity using AndTLo.
        let v12_expected = iv4_i.clone() + t_e[i].clone() - f2.clone() * and_t_lo_e[i].clone();
        eval.add_constraint(init_gate.clone() * (v_cols[12][i].clone() - v12_expected));
        // V[13] = IV[5] XOR T[8+i] via XOR identity using AndTHi.
        let v13_expected = iv5_i.clone() + t_e[8 + i].clone() - f2.clone() * and_t_hi_e[i].clone();
        eval.add_constraint(init_gate.clone() * (v_cols[13][i].clone() - v13_expected));
        // V[14] = IV[6] XOR (F·0xFF).
        // = IV[6] + F·0xFF - 2·F·IV[6]  (since F∈{0,1}, F·IV[6] = AND(IV[6], F·0xFF))
        // = IV[6]·(1 - 2F) + 255F
        let v14_expected =
            iv6_i.clone() + f_e[0].clone() * (f255.clone() - f2.clone() * iv6_i.clone());
        eval.add_constraint(init_gate.clone() * (v_cols[14][i].clone() - v14_expected));
        // V[15] = IV[7]
        eval.add_constraint(init_gate.clone() * (v_cols[15][i].clone() - iv7_i.clone()));
    }
}

/// `H`, `T` and `F` are constant within a compression.
fn constant_inputs<P: PreprocessedAirColumn, C: CompressionColumns, E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &TraceEval<P, C, E>,
    core: &Core<E::F>,
) {
    let gate = core.gate_h[0].clone();
    let h_cols = &core.h;
    let t_e = &core.t;
    let f_e = &core.f;
    // ── Inter-row: H, T, F stay constant within a compression ──
    let h_cols_next: [[E::F; 8]; 8] =
        core::array::from_fn(|k| trace_eval.column_eval_next_row::<8>(C::H[k]));
    let t_e_next = trace_eval.column_eval_next_row::<16>(C::T);
    let f_e_next = trace_eval.column_eval_next_row::<1>(C::F);
    for k in 0..8 {
        for i in 0..8 {
            eval.add_constraint(gate.clone() * (h_cols_next[k][i].clone() - h_cols[k][i].clone()));
        }
    }
    for i in 0..16 {
        eval.add_constraint(gate.clone() * (t_e_next[i].clone() - t_e[i].clone()));
    }
    eval.add_constraint(gate.clone() * (f_e_next[0].clone() - f_e[0].clone()));
}

/// The output, on a compression's last row: `H` XOR the two halves of
/// the V state after the G call, through byte-wide AND lookups.
fn output<P: PreprocessedAirColumn, C: CompressionColumns, E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &TraceEval<P, C, E>,
    core: &Core<E::F>,
    bitwise_lookup: &BitwiseAndByteLookupElements,
) {
    let Core {
        output_gate_h,
        a_out,
        b_out,
        c_out,
        d_out,
        ..
    } = core;
    let v_cols = &core.v;
    let h_cols = &core.h;
    let f2 = E::F::from(BaseField::from(2u32));

    // ── Output derivation at row 95 of each compression ──
    // output[i][j] = H[i][j] XOR V_after[i][j] XOR V_after[i+8][j]
    //              = H[i][j] + V_after[i][j] - 2·OutAnd1[i*8+j]
    //                         + V_after[i+8][j] - 2·OutAnd2[i*8+j]
    // V_after[k][j] is an expression: at row 95 IsGIdx_7=1, so
    //   V_after[3] ← a_out, V_after[4] ← b_out,
    //   V_after[9] ← c_out, V_after[14] ← d_out,  else V[k].
    let output_e = trace_eval.column_eval::<64>(C::OUTPUT);
    let out_and1_e = trace_eval.column_eval::<64>(C::OUT_AND1);
    let out_and2_e = trace_eval.column_eval::<64>(C::OUT_AND2);
    // Gate substitution: output_gate ← OutputGateH.
    let output_gate = output_gate_h[0].clone();

    // V_after source picker for the constraint side (mirror of the
    // interaction-trace v_after_byte closure).
    let v_after_e = |k: usize, byte: usize| -> E::F {
        match k {
            3 => a_out[byte].clone(),
            4 => b_out[byte].clone(),
            9 => c_out[byte].clone(),
            14 => d_out[byte].clone(),
            _ => v_cols[k][byte].clone(),
        }
    };

    for word in 0..8 {
        for byte in 0..8 {
            let slot = word * 8 + byte;
            let v1 = v_after_e(word, byte);
            let v2 = v_after_e(word + 8, byte);
            let h_b = h_cols[word][byte].clone();

            // Output derivation (gated at row 95).
            let expected_out = h_b.clone() + v1.clone() - f2.clone() * out_and1_e[slot].clone()
                + v2.clone()
                - f2.clone() * out_and2_e[slot].clone();
            eval.add_constraint(output_gate.clone() * (output_e[slot].clone() - expected_out));

            // OutAnd1 = H & V_after (byte lookup).
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                output_gate.clone().into(),
                &[h_b.clone(), v1.clone(), out_and1_e[slot].clone()],
            ));
            // OutAnd2 = Xor1 & V_after[word+8], Xor1 = H + v1 - 2·OutAnd1 (byte lookup).
            let xor1 = h_b.clone() + v1.clone() - f2.clone() * out_and1_e[slot].clone();
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                output_gate.clone().into(),
                &[xor1, v2.clone(), out_and2_e[slot].clone()],
            ));
        }
    }
}
