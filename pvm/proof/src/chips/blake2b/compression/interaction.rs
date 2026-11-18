//! The compression core's interaction trace.

use alloc::vec;
use stwo::core::fields::m31::BaseField;
use stwo::prover::backend::simd::m31::PackedBaseField;

use crate::lookups::LogupTraceBuilder;
use crate::lookups::{BitwiseAndByteLookupElements, Range256LookupElements};
use crate::trace::component::ComponentTrace;

use super::ScheduleColumns;
use crate::chips::blake2b::columns::CompressionColumns;
use crate::chips::blake2b::consts::IV;

pub(in crate::chips::blake2b) fn add_compression_interaction_core<
    P: ScheduleColumns,
    C: CompressionColumns,
>(
    logup: &mut LogupTraceBuilder,
    component_trace: &ComponentTrace,
    range256: &Range256LookupElements,
    bitwise: &BitwiseAndByteLookupElements,
) {
    let is_real = component_trace.original_base_column::<1, _>(C::IS_REAL);
    let a_in = component_trace.original_base_column::<8, _>(C::A_IN);
    let c_in = component_trace.original_base_column::<8, _>(C::C_IN);
    let mx = component_trace.original_base_column::<8, _>(C::MX);
    let my = component_trace.original_base_column::<8, _>(C::MY);
    let b_out = component_trace.original_base_column::<8, _>(C::B_OUT);
    let d_in = component_trace.original_base_column::<8, _>(C::D_IN);
    let a1 = component_trace.original_base_column::<8, _>(C::A1);
    let and1 = component_trace.original_base_column::<8, _>(C::AND1);
    let b_in = component_trace.original_base_column::<8, _>(C::B_IN);
    let c1 = component_trace.original_base_column::<8, _>(C::C1);
    let and2 = component_trace.original_base_column::<8, _>(C::AND2);
    let a_out = component_trace.original_base_column::<8, _>(C::A_OUT);
    let and3 = component_trace.original_base_column::<8, _>(C::AND3);
    let c_out = component_trace.original_base_column::<8, _>(C::C_OUT);
    let d_out = component_trace.original_base_column::<8, _>(C::D_OUT);
    let and4 = component_trace.original_base_column::<8, _>(C::AND4);
    let t_cols = component_trace.original_base_column::<16, _>(C::T);
    let and_t_lo_cols = component_trace.original_base_column::<8, _>(C::AND_T_LO);
    let and_t_hi_cols = component_trace.original_base_column::<8, _>(C::AND_T_HI);

    let two = PackedBaseField::broadcast(BaseField::from(2));

    // For each byte i, emit 6 byte-wide AND lookups in order:
    //   And1, And2, And3, And4, AndTLo, AndTHi
    // The constraint-side emission MUST match this order exactly.
    for i in 0..8usize {
        // ── And1 = D_in & A1 ──
        logup.add_to_relation_with(
            bitwise,
            [is_real[0].clone()],
            |[r]| r.into(),
            &[d_in[i].clone(), a1[i].clone(), and1[i].clone()],
        );

        // ── And2 = B_in & C1 ──
        logup.add_to_relation_with(
            bitwise,
            [is_real[0].clone()],
            |[r]| r.into(),
            &[b_in[i].clone(), c1[i].clone(), and2[i].clone()],
        );

        // ── And3 = D1 & A_out, D1[i] = D_in[j] + A1[j] - 2·And1[j], j=(i+4)%8 ──
        let j3 = (i + 4) % 8;
        let (d_in_j, a1_j, and1_j) = (d_in[j3].clone(), a1[j3].clone(), and1[j3].clone());
        let (a_out_i, and3_i) = (a_out[i].clone(), and3[i].clone());
        logup.add_to_relation_computed(
            bitwise,
            [is_real[0].clone()],
            |[r]| r.into(),
            3,
            move |v| {
                let d1_i = d_in_j.at(v) + a1_j.at(v) - two * and1_j.at(v);
                vec![d1_i, a_out_i.at(v), and3_i.at(v)]
            },
        );

        // ── And4 = B1 & C_out, B1[i] = B_in[j] + C1[j] - 2·And2[j], j=(i+3)%8 ──
        let j4 = (i + 3) % 8;
        let (b_in_j, c1_j, and2_j) = (b_in[j4].clone(), c1[j4].clone(), and2[j4].clone());
        let (c_out_i, and4_i) = (c_out[i].clone(), and4[i].clone());
        logup.add_to_relation_computed(
            bitwise,
            [is_real[0].clone()],
            |[r]| r.into(),
            3,
            move |v| {
                let b1_i = b_in_j.at(v) + c1_j.at(v) - two * and2_j.at(v);
                vec![b1_i, c_out_i.at(v), and4_i.at(v)]
            },
        );

        // ── AndTLo = IV[4] & T[i] (IV[4] const a-side) ──
        let iv4_bcast = PackedBaseField::broadcast(BaseField::from(IV[4].to_le_bytes()[i] as u32));
        {
            let t_i = t_cols[i].clone();
            let and_i = and_t_lo_cols[i].clone();
            logup.add_to_relation_computed(
                bitwise,
                [is_real[0].clone()],
                |[r]| r.into(),
                3,
                move |v| vec![iv4_bcast, t_i.at(v), and_i.at(v)],
            );
        }

        // ── AndTHi = IV[5] & T[8+i] ──
        let iv5_bcast = PackedBaseField::broadcast(BaseField::from(IV[5].to_le_bytes()[i] as u32));
        {
            let t_i = t_cols[8 + i].clone();
            let and_i = and_t_hi_cols[i].clone();
            logup.add_to_relation_computed(
                bitwise,
                [is_real[0].clone()],
                |[r]| r.into(),
                3,
                move |v| vec![iv5_bcast, t_i.at(v), and_i.at(v)],
            );
        }
    }

    // ── Range256 lookups for non-AND-constrained byte columns ──
    // A_in, C_in, Mx, My, B_out.  Issued in a fixed (column, byte) order
    // that the constraint side mirrors.
    for col_cols in [&a_in, &c_in, &mx, &my, &b_out] {
        for i in 0..8 {
            logup.add_to_relation_with(
                range256,
                [is_real[0].clone()],
                |[r]| r.into(),
                &[col_cols[i].clone()],
            );
        }
    }

    // ── Output-derivation byte-wide AND lookups ──────
    // Fire only at IsLastOfCompression · IsReal.  128 byte ANDs per row
    // (OutAnd1 = H & V_after, OutAnd2 = Xor1 & V_after[+8]); non-last rows
    // have multiplicity 0.
    //
    // Snapshot V[0..16] and H[0..8] columns upfront — we dispatch by
    // numeric index below because the column-fetch macro requires a
    // literal path.
    let is_last_pp = component_trace.preprocessed_base_column::<1, P>(P::IS_LAST);
    let out_and1_cols = component_trace.original_base_column::<64, _>(C::OUT_AND1);
    let out_and2_cols = component_trace.original_base_column::<64, _>(C::OUT_AND2);
    let h_by_word: [_; 8] = [
        component_trace.original_base_column::<8, _>(C::H[0]),
        component_trace.original_base_column::<8, _>(C::H[1]),
        component_trace.original_base_column::<8, _>(C::H[2]),
        component_trace.original_base_column::<8, _>(C::H[3]),
        component_trace.original_base_column::<8, _>(C::H[4]),
        component_trace.original_base_column::<8, _>(C::H[5]),
        component_trace.original_base_column::<8, _>(C::H[6]),
        component_trace.original_base_column::<8, _>(C::H[7]),
    ];
    let v_by_slot: [_; 16] = [
        component_trace.original_base_column::<8, _>(C::V[0]),
        component_trace.original_base_column::<8, _>(C::V[1]),
        component_trace.original_base_column::<8, _>(C::V[2]),
        component_trace.original_base_column::<8, _>(C::V[3]),
        component_trace.original_base_column::<8, _>(C::V[4]),
        component_trace.original_base_column::<8, _>(C::V[5]),
        component_trace.original_base_column::<8, _>(C::V[6]),
        component_trace.original_base_column::<8, _>(C::V[7]),
        component_trace.original_base_column::<8, _>(C::V[8]),
        component_trace.original_base_column::<8, _>(C::V[9]),
        component_trace.original_base_column::<8, _>(C::V[10]),
        component_trace.original_base_column::<8, _>(C::V[11]),
        component_trace.original_base_column::<8, _>(C::V[12]),
        component_trace.original_base_column::<8, _>(C::V[13]),
        component_trace.original_base_column::<8, _>(C::V[14]),
        component_trace.original_base_column::<8, _>(C::V[15]),
    ];

    // G_INDICES[7] = [3, 4, 9, 14] — at row 95 (g_idx=7, always true at
    // IsLastOfCompression) slot k is touched iff k ∈ {3,4,9,14}:
    //   slot 3 ← a_out;  slot 4 ← b_out;
    //   slot 9 ← c_out;  slot 14 ← d_out;
    //   else slot k keeps V[k].
    // Pick the column for V_after[slot][byte] — element type mirrors
    // whatever `original_base_column!` returns (a FinalizedColumn clone).
    let v_after_byte = |k: usize, byte: usize| match k {
        3 => a_out[byte].clone(),
        4 => b_out[byte].clone(),
        9 => c_out[byte].clone(),
        14 => d_out[byte].clone(),
        _ => v_by_slot[k][byte].clone(),
    };

    let two = PackedBaseField::broadcast(BaseField::from(2));
    for word in 0..8 {
        for byte in 0..8 {
            let slot = word * 8 + byte;
            let v1_src = v_after_byte(word, byte);
            let v2_src = v_after_byte(word + 8, byte);
            let h_b = h_by_word[word][byte].clone();

            // OutAnd1 = H & V_after (byte lookup).
            {
                let h_b2 = h_b.clone();
                let v1_src2 = v1_src.clone();
                let and1_s = out_and1_cols[slot].clone();
                logup.add_to_relation_computed(
                    bitwise,
                    [is_real[0].clone(), is_last_pp[0].clone()],
                    |[r, l]| (r * l).into(),
                    3,
                    move |v| vec![h_b2.at(v), v1_src2.at(v), and1_s.at(v)],
                );
            }
            // OutAnd2 = Xor1 & V_after[+8], Xor1 = H + v1 - 2·OutAnd1 (byte lookup).
            {
                let h_b2 = h_b.clone();
                let v1_src2 = v1_src.clone();
                let v2_src2 = v2_src.clone();
                let and1_s = out_and1_cols[slot].clone();
                let and2_s = out_and2_cols[slot].clone();
                logup.add_to_relation_computed(
                    bitwise,
                    [is_real[0].clone(), is_last_pp[0].clone()],
                    |[r, l]| (r * l).into(),
                    3,
                    move |v| {
                        let xor1_v = h_b2.at(v) + v1_src2.at(v) - two * and1_s.at(v);
                        vec![xor1_v, v2_src2.at(v), and2_s.at(v)]
                    },
                );
            }
        }
    }
}
