//! The compression core's preprocessed schedule and main-trace witness.

use alloc::vec::Vec;

use crate::side_note::SideNote;
use crate::trace::builder::TraceBuilder;

use super::ScheduleColumns;
use crate::chips::blake2b::Blake2bCall;
use crate::chips::blake2b::columns::CompressionColumns;
use crate::chips::blake2b::consts::{G_INDICES, IV, SIGMA};
use crate::chips::blake2b::trace::{GRow, fill_output_witnesses, g_traced, row_v_after};

/// Fill the deterministic compression schedule into a chip's preprocessed
/// trace builder: `r mod 8` picks the G-index, `r mod 96` the position in a
/// compression, SIGMA the Mx/My message-slot selectors.  Generic over the
/// chip's `PreprocessedColumn` so Blake2bChip and Blake2bBoundaryChip emit
/// the same schedule under their own distinct prefixes.  Does NOT finalize —
/// the caller may add further preprocessed columns (e.g. the boundary chip's
/// ContinuityGate) before finalizing.
pub(in crate::chips::blake2b) fn fill_schedule_preprocessed<P: ScheduleColumns>(
    trace: &mut TraceBuilder<P>,
) {
    let num_rows = trace.num_rows();
    for row in 0..num_rows {
        let g_idx = row % 8;
        trace.fill_columns(row, true, P::IS_GIDX[g_idx]);
        let pos_in_compression = row % 96;
        if pos_in_compression == 0 {
            trace.fill_columns(row, true, P::IS_FIRST);
        }
        if pos_in_compression == 95 {
            trace.fill_columns(row, true, P::IS_LAST);
        }
        // Derive mx_idx / my_idx from SIGMA: round = (r%96)/8, g_idx = r%8.
        let round = pos_in_compression / 8;
        let mx_idx = SIGMA[round][2 * g_idx];
        let my_idx = SIGMA[round][2 * g_idx + 1];
        trace.fill_columns(row, true, P::IS_MX_SLOT[mx_idx]);
        trace.fill_columns(row, true, P::IS_MY_SLOT[my_idx]);
    }
}

pub(in crate::chips::blake2b) fn build_compression_rows(
    calls: &[Blake2bCall],
    mem_ops: &[crate::core::tracing::Blake2bMemOp],
) -> Vec<GRow> {
    let mut rows: Vec<GRow> = Vec::new();
    for (call_idx, call) in calls.iter().enumerate() {
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&call.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= call.t as u64;
        v[13] ^= (call.t >> 64) as u64;
        if call.f {
            v[14] = !v[14];
        }

        // ECALL-binding data for this compression, if a matching
        // blake2b_mem_op was recorded by the tracer.
        let mem_op = mem_ops.get(call_idx);
        let h_ptr = mem_op.map(|o| o.h_ptr).unwrap_or(0).to_le_bytes();
        let m_ptr = mem_op.map(|o| o.m_ptr).unwrap_or(0).to_le_bytes();
        let call_ts_u = mem_op.map(|o| o.ts).unwrap_or(0);
        let call_ts = call_ts_u.to_le_bytes();

        for round in 0..12 {
            let s = &SIGMA[round];
            for g_idx in 0..8 {
                let [ai, bi, ci, di] = G_INDICES[g_idx];
                let mx = call.m[s[2 * g_idx]];
                let my = call.m[s[2 * g_idx + 1]];

                let mut row = g_traced(
                    &v, &call.m, &call.h, call.t, call.f, v[ai], v[bi], v[ci], v[di], mx, my,
                );

                v[ai] = u64::from_le_bytes(row.a_out);
                v[bi] = u64::from_le_bytes(row.b_out);
                v[ci] = u64::from_le_bytes(row.c_out);
                v[di] = u64::from_le_bytes(row.d_out);

                // Final G-call of this compression → populate
                // output witnesses from the just-updated v.
                if round == 11 && g_idx == 7 {
                    fill_output_witnesses(&mut row, &v);
                }

                // ECALL-binding fields, constant across 96 rows.
                row.h_ptr = h_ptr;
                row.m_ptr = m_ptr;
                row.call_ts = call_ts;

                rows.push(row);
            }
        }
    }
    rows
}

pub(in crate::chips::blake2b) fn fill_compression_trace<C: CompressionColumns>(
    trace: &mut TraceBuilder<C>,
    side_note: &mut SideNote,
    rows: &[GRow],
) {
    for (row_idx, r) in rows.iter().enumerate() {
        trace.fill_columns_bytes(row_idx, &r.a_in, C::A_IN);
        trace.fill_columns_bytes(row_idx, &r.b_in, C::B_IN);
        trace.fill_columns_bytes(row_idx, &r.c_in, C::C_IN);
        trace.fill_columns_bytes(row_idx, &r.d_in, C::D_IN);
        trace.fill_columns_bytes(row_idx, &r.mx, C::MX);
        trace.fill_columns_bytes(row_idx, &r.my, C::MY);
        trace.fill_columns_bytes(row_idx, &r.a1, C::A1);
        trace.fill_columns_bytes(row_idx, &r.carry1, C::CARRY1);
        trace.fill_columns_bytes(row_idx, &r.and1, C::AND1);
        trace.fill_columns_bytes(row_idx, &r.c1, C::C1);
        trace.fill_columns_bytes(row_idx, &r.carry2, C::CARRY2);
        trace.fill_columns_bytes(row_idx, &r.and2, C::AND2);
        trace.fill_columns_bytes(row_idx, &r.a_out, C::A_OUT);
        trace.fill_columns_bytes(row_idx, &r.carry3, C::CARRY3);
        trace.fill_columns_bytes(row_idx, &r.and3, C::AND3);
        trace.fill_columns_bytes(row_idx, &r.c_out, C::C_OUT);
        trace.fill_columns_bytes(row_idx, &r.carry4, C::CARRY4);
        trace.fill_columns_bytes(row_idx, &r.and4, C::AND4);
        trace.fill_columns_bytes(row_idx, &r.b_out, C::B_OUT);
        trace.fill_columns_bytes(row_idx, &r.rot63_carry, C::ROT63_CARRY);
        trace.fill_columns_bytes(row_idx, &r.d_out, C::D_OUT);
        for k in 0..16 {
            trace.fill_columns_bytes(row_idx, &r.v[k], C::V[k]);
        }
        for k in 0..16 {
            trace.fill_columns_bytes(row_idx, &r.m[k], C::M[k]);
        }
        // Compression-level inputs.
        for k in 0..8 {
            trace.fill_columns_bytes(row_idx, &r.h[k], C::H[k]);
        }
        trace.fill_columns_bytes(row_idx, &r.t, C::T);
        trace.fill_columns(row_idx, r.f, C::F);
        trace.fill_columns_bytes(row_idx, &r.and_t_lo, C::AND_T_LO);
        trace.fill_columns_bytes(row_idx, &r.and_t_hi, C::AND_T_HI);
        // Output-derivation witnesses (0 on non-last rows).
        trace.fill_columns_bytes(row_idx, &r.output, C::OUTPUT);
        trace.fill_columns_bytes(row_idx, &r.out_and1, C::OUT_AND1);
        trace.fill_columns_bytes(row_idx, &r.out_and2, C::OUT_AND2);
        trace.fill_columns(row_idx, true, C::IS_REAL);

        // Carry-bound helpers.  Carries c ∈ {0,1,2}
        // for Carry1/3 and ∈ {0,1} for Carry2/4/Rot63 — see DESIGN
        // notes on `C::CARRY1_XCM1` etc.  XcM1 = c·(c-1) is 0 for
        // c ∈ {0,1} and 2 for c=2.  Full = XcM1·(c-2) is 0 for any
        // valid c (so the runtime values are always 0; the helpers
        // exist purely to flatten the constraint degree).  All math
        // in i32 to dodge u8 underflow on `c - 1` when c=0.
        let xcm1 = |c: u8| -> u8 {
            let c = c as i32;
            (c * (c - 1)) as u8
        };
        let full = |c: u8| -> u8 {
            let c = c as i32;
            (c * (c - 1) * (c - 2)) as u8
        };
        let mut c1_xcm1 = [0u8; 8];
        let mut c1_full = [0u8; 8];
        let mut c3_xcm1 = [0u8; 8];
        let mut c3_full = [0u8; 8];
        let mut c2_xcm1 = [0u8; 8];
        let mut c4_xcm1 = [0u8; 8];
        let mut rot_xcm1 = [0u8; 8];
        for i in 0..8 {
            c1_xcm1[i] = xcm1(r.carry1[i]);
            c1_full[i] = full(r.carry1[i]);
            c3_xcm1[i] = xcm1(r.carry3[i]);
            c3_full[i] = full(r.carry3[i]);
            c2_xcm1[i] = xcm1(r.carry2[i]);
            c4_xcm1[i] = xcm1(r.carry4[i]);
            rot_xcm1[i] = xcm1(r.rot63_carry[i]);
        }
        trace.fill_columns_bytes(row_idx, &c1_xcm1, C::CARRY1_XCM1);
        trace.fill_columns_bytes(row_idx, &c1_full, C::CARRY1_FULL);
        trace.fill_columns_bytes(row_idx, &c3_xcm1, C::CARRY3_XCM1);
        trace.fill_columns_bytes(row_idx, &c3_full, C::CARRY3_FULL);
        trace.fill_columns_bytes(row_idx, &c2_xcm1, C::CARRY2_XCM1);
        trace.fill_columns_bytes(row_idx, &c4_xcm1, C::CARRY4_XCM1);
        trace.fill_columns_bytes(row_idx, &rot_xcm1, C::ROT63_XCM1);

        // F-bound helper.  F ∈ {0,1} ⇒ F·(F-1) = 0.
        trace.fill_columns(row_idx, false, C::F_BOUND_H);

        // Input-match sum helpers.  Exactly one
        // `IsGIdx[j_active] = 1` per row, so the sum equals the active
        // V slot's byte — which is what `r.{a,b,c,d}_in` already hold.
        trace.fill_columns_bytes(row_idx, &r.a_in, C::IN_MATCH_A);
        trace.fill_columns_bytes(row_idx, &r.b_in, C::IN_MATCH_B);
        trace.fill_columns_bytes(row_idx, &r.c_in, C::IN_MATCH_C);
        trace.fill_columns_bytes(row_idx, &r.d_in, C::IN_MATCH_D);

        // Mx / My slot-selection helpers.  Exactly
        // one IsMxSlot[k_mx] = 1 per row (k_mx = SIGMA[round][2·g_idx]),
        // so MxSlotSum[i] = M[k_mx][i] = mx[i].  Same shape for My.
        trace.fill_columns_bytes(row_idx, &r.mx, C::MX_SLOT_SUM);
        trace.fill_columns_bytes(row_idx, &r.my, C::MY_SLOT_SUM);

        // V_next sum helpers.  At row r with
        // j_active = row_idx % 8, the sum collapses to v_after[k][i]
        // where v_after equals r.v with G_INDICES[j_active] slots
        // replaced by the G-call outputs.
        let g_idx_active = row_idx % 8;
        let [ai_v, bi_v, ci_v, di_v] = G_INDICES[g_idx_active];
        let mut v_after_bytes = r.v;
        v_after_bytes[ai_v] = r.a_out;
        v_after_bytes[bi_v] = r.b_out;
        v_after_bytes[ci_v] = r.c_out;
        v_after_bytes[di_v] = r.d_out;
        for k in 0..16 {
            trace.fill_columns_bytes(row_idx, &v_after_bytes[k], C::V_NEXT_SUM[k]);
        }

        // Gate helpers.  Each row, IsReal=1 here, so
        // the helper values reduce to the preprocessed selector value:
        //   GateH        = 1 - is_last     (1 except at row 95)
        //   InitGateH    = is_first        (1 only at row 0)
        //   OutputGateH  = is_last         (1 only at row 95)
        // Padding rows have IsReal=0, so all helpers are 0 there
        // (default trace fill).  Constraints below tie these to the
        // algebraic expressions at the AIR level.
        let pos = row_idx % 96;
        let is_first = pos == 0;
        let is_last = pos == 95;
        trace.fill_columns(row_idx, !is_last, C::GATE_H);
        trace.fill_columns(row_idx, is_first, C::INIT_GATE_H);
        trace.fill_columns(row_idx, is_last, C::OUTPUT_GATE_H);

        // Emit per-byte AND counts into the BitwiseAndByteChip table — one
        // increment per byte lookup (the constraint / interaction sides emit
        // one byte lookup per AND).
        //
        // And3 A-side is d1[k] = (d^a1 rotated right 32) = xor byte at
        // position (k+4)%8.  We reconstruct the true byte value from the
        // trace columns via the XOR identity d_in + a1 - 2·and1 so the
        // multiplicity table stays in sync with the constraint-side
        // derivation.  Same story for And4 A-side (b1).
        for i in 0..8 {
            side_note.add_bitwise_and_byte(r.d_in[i], r.a1[i]);
            side_note.add_bitwise_and_byte(r.b_in[i], r.c1[i]);
            let k3 = (i + 4) % 8;
            let d1_i = r.d_in[k3] ^ r.a1[k3];
            side_note.add_bitwise_and_byte(d1_i, r.a_out[i]);
            let k4 = (i + 3) % 8;
            let b1_i = r.b_in[k4] ^ r.c1[k4];
            side_note.add_bitwise_and_byte(b1_i, r.c_out[i]);
            // Initial-state XOR witnesses: IV[4]/IV[5] are constants.
            let iv4 = IV[4].to_le_bytes();
            let iv5 = IV[5].to_le_bytes();
            side_note.add_bitwise_and_byte(iv4[i], r.t[i]);
            side_note.add_bitwise_and_byte(iv5[i], r.t[8 + i]);
        }

        // Range-check the inputs/outputs that are not covered by an AND
        // lookup.  D_in/B_in/A1/C1/A_out/C_out/And{1-4} and the derived
        // D1/B1 are all byte-AND-lookup-constrained (byte-ness from table
        // membership).  The remaining bytes need an explicit Range256 consumer:
        //   A_in, C_in, Mx, My — add-chain operands read by the prover
        //   B_out — rotation output derived from xor4
        for i in 0..8 {
            side_note.add_range256(r.a_in[i]);
            side_note.add_range256(r.c_in[i]);
            side_note.add_range256(r.mx[i]);
            side_note.add_range256(r.my[i]);
            side_note.add_range256(r.b_out[i]);
        }

        // Output-derivation AND counts — only at the last row of each compression.
        // 64 OutAnd1 bytes (H & V_after[0..8]) + 64 OutAnd2 bytes (Xor1 &
        // V_after[8..16]) = 128 byte-AND multiplicity increments.
        if row_idx % 96 == 95 {
            let v_after = row_v_after(r);
            for word in 0..8 {
                for byte in 0..8 {
                    let h_b = r.h[word][byte];
                    let v1 = v_after[word][byte];
                    let v2 = v_after[word + 8][byte];
                    let xor1 = h_b ^ v1;
                    side_note.add_bitwise_and_byte(h_b, v1);
                    side_note.add_bitwise_and_byte(xor1, v2);
                }
            }
        }
    }
}
