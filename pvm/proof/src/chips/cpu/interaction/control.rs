//! Program execution and the dynamic jumps.

use super::*;

/// The step's program-execution pair: `(ts, pc)` consumed, `(ts + 1, next_pc)`
/// produced.
pub(super) fn program_execution(
    logup: &mut LogupTraceBuilder,
    row: &RowTrace<'_>,
    lookup_elements: &AllLookupElements,
) {
    let is_pad = &row.is_padding;
    let timestamp = &row.timestamp;
    // Program execution lookup: consume (ts, pc), produce (ts+1, next_pc)
    let prog_exec: &ProgramExecutionLookupElements = lookup_elements.as_ref();
    let pc = &row.pc;
    let next_pc_col = &row.next_pc;
    let next_ts = &row.next_timestamp;
    {
        let mut consume_tuple: Vec<_> = timestamp.to_vec();
        consume_tuple.extend_from_slice(pc);
        logup.add_to_relation_with(
            prog_exec,
            [is_pad[0].clone()],
            |[pad]| (-(PackedBaseField::one() - pad)).into(),
            &consume_tuple,
        );
    }
    {
        let mut produce_tuple: Vec<_> = next_ts.to_vec();
        produce_tuple.extend_from_slice(next_pc_col);
        logup.add_to_relation_with(
            prog_exec,
            [is_pad[0].clone()],
            |[pad]| (PackedBaseField::one() - pad).into(),
            &produce_tuple,
        );
    }
}

/// The dynamic jumps' JumpTable lookups.
pub(super) fn jump_table(
    logup: &mut LogupTraceBuilder,
    row: &RowTrace<'_>,
    lookup_elements: &AllLookupElements,
) {
    // ── JumpTable consumer (prover-side, 2 paired, 8 limbs) ──
    {
        let jt: &JumpTableLookupElements = lookup_elements.as_ref();
        let is_jump_ind_col = &row.is_jump_ind;
        let is_halt_jump_ind = &row.is_halt_jump_ind;
        let jump_ind_addr = &row.jump_ind_addr;
        let next_pc_col = &row.next_pc;

        let mut tuple: Vec<_> = jump_ind_addr.to_vec();
        tuple.extend_from_slice(next_pc_col);

        for _ in 0..2 {
            logup.add_to_relation_with(
                jt,
                [is_jump_ind_col[0].clone(), is_halt_jump_ind[0].clone()],
                |[is_jump, is_halt]| (is_jump - is_halt).into(),
                &tuple,
            );
        }
    }

    // ── JumpTable consumer for LoadImmJumpInd ──
    {
        let jt: &JumpTableLookupElements = lookup_elements.as_ref();
        let is_lij_col = &row.is_load_imm_jump_ind;
        let is_halt_lij = &row.is_halt_load_imm_jump_ind;
        let lij_addr = &row.load_imm_jump_ind_addr;
        let next_pc_col = &row.next_pc;

        let mut tuple: Vec<_> = lij_addr.to_vec();
        tuple.extend_from_slice(next_pc_col);

        for _ in 0..2 {
            logup.add_to_relation_with(
                jt,
                [is_lij_col[0].clone(), is_halt_lij[0].clone()],
                |[is_jump, is_halt]| (is_jump - is_halt).into(),
                &tuple,
            );
        }
    }
}
