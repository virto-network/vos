//! Host calls: continuation, the BLAKE2b call and the witness-input call.
use alloc::vec::Vec;

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Trace};
use crate::chips::cpu::columns::Column;
use crate::core::step::WORD_SIZE;

/// Host-call continuation.
pub(in crate::chips::cpu) fn host_call_continuation<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
) {
    let f256 = E::F::from(BaseField::from(256u32));
    // ── Host-call continuation ──
    //
    // IsExit also covers Trap and dynamic jumps. Subtracting their
    // authenticated per-opcode flags leaves exactly Ecalli. A host call
    // either remains at its cause PC and terminates the trace, or carries
    // an explicit acknowledgment and advances sequentially.
    {
        let is_exit = crate::trace::trace_eval!(trace_eval, Column::IsExit);
        let is_trap = crate::trace::trace_eval!(trace_eval, Column::IsTrap);
        let is_jump_ind = crate::trace::trace_eval!(trace_eval, Column::IsJumpInd);
        let is_load_imm_jump_ind = crate::trace::trace_eval!(trace_eval, Column::IsLoadImmJumpInd);
        let acknowledged = crate::trace::trace_eval!(trace_eval, Column::HostCallAcknowledged);
        let precompile_dispatch =
            crate::trace::trace_eval!(trace_eval, Column::HostCallPrecompileDispatch);
        let is_blake = crate::trace::trace_eval!(trace_eval, Column::IsBlakeEcall);
        let is_witness = crate::trace::trace_eval!(trace_eval, Column::IsWitnessEcall);
        let pc = crate::trace::trace_eval!(trace_eval, Column::Pc);
        let next_pc = crate::trace::trace_eval!(trace_eval, Column::NextPc);
        let skip_len = crate::trace::trace_eval!(trace_eval, Column::SkipLen);
        let pc_carry = crate::trace::trace_eval!(trace_eval, Column::PcCarry);

        let soft_host = is_exit[0].clone()
            - is_trap[0].clone()
            - is_jump_ind[0].clone()
            - is_load_imm_jump_ind[0].clone();

        eval.add_constraint(acknowledged[0].clone() * (E::F::one() - acknowledged[0].clone()));
        eval.add_constraint(acknowledged[0].clone() * (E::F::one() - soft_host.clone()));

        // ProgramMemory commits the exact cryptographic dispatch ID, which
        // is non-zero only for an ECALLI identifier the proof runtime
        // handles. An acknowledged call selects exactly one precompile
        // relation, and its weighted selector must equal that
        // authenticated ID, so only a supported call can be acknowledged.
        // A call that is not acknowledged selects no relation.
        let precompile_selector_sum = is_blake[0].clone() + is_witness[0].clone();
        eval.add_constraint(precompile_selector_sum - acknowledged[0].clone());
        let selected_dispatch = is_blake[0].clone() * E::F::from(BaseField::from(100u32))
            + is_witness[0].clone() * E::F::from(BaseField::from(101u32));
        eval.add_constraint(
            selected_dispatch - acknowledged[0].clone() * precompile_dispatch[0].clone(),
        );

        let seq_pc = [
            pc[0].clone() + E::F::one() + skip_len[0].clone() - pc_carry[0].clone() * f256.clone(),
            pc[1].clone() + pc_carry[0].clone() - pc_carry[1].clone() * f256.clone(),
            pc[2].clone() + pc_carry[1].clone() - pc_carry[2].clone() * f256.clone(),
            pc[3].clone() + pc_carry[2].clone(),
        ];
        for i in 0..4 {
            eval.add_constraint(
                soft_host.clone() * (next_pc[i].clone() - pc[i].clone())
                    - acknowledged[0].clone() * (seq_pc[i].clone() - pc[i].clone()),
            );
        }

        // A Standard host call not acknowledged by the committed proof
        // runtime is a real exit, so it cannot be followed by another
        // real row. Acknowledged rows may end a segment at resume_pc.
        //
        // A precompile call may stay unacknowledged: an inner machine's
        // is left to its agent, and a host without precompiles answers
        // it. A call the machine fails to serve (a pointer past 32 bits,
        // an inaccessible range) ends its run the same way, at its cause
        // PC, so a proof states only that the run stopped there; the
        // host's policy tells a pending call from the panic, and a
        // kernel's proof is read only to its halt.
        let is_padding_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsPadding);
        eval.add_constraint(
            (soft_host - acknowledged[0].clone()) * (E::F::one() - is_padding_next[0].clone()),
        );
    }
}

/// The BLAKE2b call: its register reads, the Phi7Bool tie and the call binding.
pub(in crate::chips::cpu) fn blake2b_call<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let blake2b_call_lookup = lookups.blake2b_call_lookup;
    let reg_lookup = lookups.reg_lookup;
    let real_not_phi7_bool_h = crate::trace::trace_eval!(trace_eval, Column::RealNotPhi7BoolH);
    let real_phi7_bool_h = crate::trace::trace_eval!(trace_eval, Column::RealPhi7BoolH);
    let phi7_times_inv_h = crate::trace::trace_eval!(trace_eval, Column::Phi7TimesInvH);
    let timestamp = crate::trace::trace_eval!(trace_eval, Column::Timestamp);
    // ── blake2b ECALL register-read producers + Phi7Bool tie ──
    {
        let is_blake_ecall = crate::trace::trace_eval!(trace_eval, Column::IsBlakeEcall);
        let phi7 = crate::trace::trace_eval!(trace_eval, Column::Phi7);
        let phi10 = crate::trace::trace_eval!(trace_eval, Column::Phi10);
        let phi11 = crate::trace::trace_eval!(trace_eval, Column::Phi11);
        let phi12 = crate::trace::trace_eval!(trace_eval, Column::Phi12);

        // Slot → PVM register index for the ECALL register-read
        // producer.  The `Column::Phi*` names don't match their actual
        // sources, which are:
        //   Phi7  ← φ[10] (f_flag)
        //   Phi10 ← φ[7]  (h_ptr)
        //   Phi11 ← φ[8]  (m_ptr)
        //   Phi12 ← φ[9]  (t_low)
        // See `trace_fill.rs` for the full mapping.
        const ECALL_REG_IDXS: [u32; 4] = [10, 7, 8, 9];
        let phi_cols: [&[E::F]; 4] = [&phi7, &phi10, &phi11, &phi12];
        for (slot, &reg_idx) in ECALL_REG_IDXS.iter().enumerate() {
            let mut tuple: Vec<E::F> = Vec::with_capacity(18);
            tuple.push(E::F::from(BaseField::from(reg_idx)));
            for c in phi_cols[slot] {
                tuple.push(c.clone());
            }
            for c in &timestamp {
                tuple.push(c.clone());
            }
            tuple.push(E::F::from(BaseField::from(0u32))); // is_write = 0 (read)
            eval.add_to_relation(RelationEntry::new(
                reg_lookup,
                is_blake_ecall[0].clone().into(),
                &tuple,
            ));
        }

        // Phi7Bool ↔ Phi7 (its bytes' sum, zero exactly when the
        // register is) tie, gated only by is_real.
        // Phi7Bool is boolean on every row (`registers::register_helpers`).
        // If Phi7Bool = 0, then Phi7's bytes are 0.
        let phi7_sum = phi7
            .iter()
            .fold(E::F::zero(), |sum, byte| sum + byte.clone());
        eval.add_constraint(real_not_phi7_bool_h[0].clone() * phi7_sum);
        // If Phi7Bool = 1, then Phi7 · Phi7Inv = 1 — body lifted into
        // Phi7TimesInvH so the gate × body is deg 2.
        eval.add_constraint(
            real_phi7_bool_h[0].clone() * (phi7_times_inv_h[0].clone() - E::F::one()),
        );
    }

    // Blake2b call binding: mirror of the prover-side producer.
    {
        let is_blake_ecall = crate::trace::trace_eval!(trace_eval, Column::IsBlakeEcall);
        let phi10 = crate::trace::trace_eval!(trace_eval, Column::Phi10);
        let phi11 = crate::trace::trace_eval!(trace_eval, Column::Phi11);
        let phi12 = crate::trace::trace_eval!(trace_eval, Column::Phi12);
        let phi7_bool = crate::trace::trace_eval!(trace_eval, Column::Phi7Bool);
        let mut tuple: Vec<E::F> = Vec::with_capacity(25);
        for i in 0..4 {
            tuple.push(phi10[i].clone());
        }
        for i in 0..4 {
            tuple.push(phi11[i].clone());
        }
        for i in 0..WORD_SIZE {
            tuple.push(phi12[i].clone());
        }
        tuple.push(phi7_bool[0].clone());
        for i in 0..WORD_SIZE {
            tuple.push(timestamp[i].clone());
        }
        eval.add_to_relation(RelationEntry::new(
            blake2b_call_lookup,
            is_blake_ecall[0].clone().into(),
            &tuple,
        ));

        // The pointers are 32-bit: the machine refuses a call whose
        // φ7 or φ8 is past 2^32, and the call tuple carries their low
        // four bytes only.
        for i in 4..WORD_SIZE {
            eval.add_constraint(is_blake_ecall[0].clone() * phi10[i].clone());
            eval.add_constraint(is_blake_ecall[0].clone() * phi11[i].clone());
        }

        // Phi7Bool and IsBlakeEcall are boolean on every row
        // (`registers::register_helpers`).
    }
}

/// The witness-input call's register reads.
pub(in crate::chips::cpu) fn witness_input_reads<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let reg_lookup = lookups.reg_lookup;
    let timestamp = crate::trace::trace_eval!(trace_eval, Column::Timestamp);
    // ── Witness-input register reads ──
    // The call reads φ[7] and φ[8], its destination and capacity, from
    // the Phi10/Phi11 slots (= regs_before[7,8], filled every row); the
    // register-read producers bind those snapshots to the register file
    // at the step ts. Two emissions keep finalize_logup_in_pairs
    // balanced.
    {
        let is_witness = crate::trace::trace_eval!(trace_eval, Column::IsWitnessEcall);
        let phi10 = crate::trace::trace_eval!(trace_eval, Column::Phi10); // φ[7]
        let phi11 = crate::trace::trace_eval!(trace_eval, Column::Phi11); // φ[8]

        // Register-read producers (reg_idx, value[8], ts[8], is_write=0).
        for (reg_idx, value) in [(7u32, &phi10), (8u32, &phi11)] {
            let mut tuple: Vec<E::F> = Vec::with_capacity(18);
            tuple.push(E::F::from(BaseField::from(reg_idx)));
            for c in value.iter() {
                tuple.push(c.clone());
            }
            for c in &timestamp {
                tuple.push(c.clone());
            }
            tuple.push(E::F::from(BaseField::from(0u32))); // is_write = 0 (read)
            eval.add_to_relation(RelationEntry::new(
                reg_lookup,
                is_witness[0].clone().into(),
                &tuple,
            ));
        }
    }
}

/// The witness-input call's binding.
pub(in crate::chips::cpu) fn witness_input<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let compare_lookup = lookups.compare_lookup;
    let witness_call_lookup = lookups.witness_call_lookup;
    let result = crate::trace::trace_eval!(trace_eval, Column::Result);
    let timestamp = crate::trace::trace_eval!(trace_eval, Column::Timestamp);
    // ── Witness input ──
    // An acknowledged witness-input row reads φ7, the destination, and
    // φ8, the capacity (the register reads above); writes its count to
    // φ7 and nothing else: the generic Result write, pinned here to
    // register 7, a count below 2^24, and, when it writes bytes, the
    // destination below 2^32.
    // Its count is at most φ8, as CompareChip proves of the tuple
    // (φ8, count, lt = 0). A non-zero count hands (ts, destination,
    // count) to WitnessInputChip, which writes exactly the bytes
    // [destination, destination + count) at ts, and nothing else.
    // Four emissions, two paired blocks, kept last (CONSTRAINTS.md 2).
    {
        let is_witness = crate::trace::trace_eval!(trace_eval, Column::IsWitnessEcall);
        let non_empty = crate::trace::trace_eval!(trace_eval, Column::WitnessNonEmpty);
        let count_inv = crate::trace::trace_eval!(trace_eval, Column::WitnessCountInv);
        let count_times_inv = crate::trace::trace_eval!(trace_eval, Column::WitnessCountTimesInvH);
        let result_is_reg = crate::trace::trace_eval!(trace_eval, Column::ResultIsReg);
        let result_reg_idx = crate::trace::trace_eval!(trace_eval, Column::ResultRegIdx);
        let destination = crate::trace::trace_eval!(trace_eval, Column::Phi10);
        let capacity = crate::trace::trace_eval!(trace_eval, Column::Phi11);
        let f256 = E::F::from(BaseField::from(256u32));
        let count = result[0].clone()
            + result[1].clone() * f256.clone()
            + result[2].clone() * f256.clone() * f256;

        // The count is φ7's write, and below 2^24, so it is its own
        // field value.
        eval.add_constraint(is_witness[0].clone() * (E::F::one() - result_is_reg[0].clone()));
        eval.add_constraint(
            is_witness[0].clone() * (result_reg_idx[0].clone() - E::F::from(BaseField::from(7u32))),
        );
        for byte in &result[3..WORD_SIZE] {
            eval.add_constraint(is_witness[0].clone() * byte.clone());
        }
        // A call that writes bytes writes them below 2^32; one that
        // writes none may name any destination, as the live call does.
        for byte in &destination[4..WORD_SIZE] {
            eval.add_constraint(non_empty[0].clone() * byte.clone());
        }
        // WitnessNonEmpty: a witness row's count is non-zero exactly
        // when it is set.
        eval.add_constraint(non_empty[0].clone() * (E::F::one() - non_empty[0].clone()));
        eval.add_constraint(non_empty[0].clone() * (E::F::one() - is_witness[0].clone()));
        eval.add_constraint((is_witness[0].clone() - non_empty[0].clone()) * count.clone());
        eval.add_constraint(count_times_inv[0].clone() - count.clone() * count_inv[0].clone());
        eval.add_constraint(non_empty[0].clone() * (count_times_inv[0].clone() - E::F::one()));

        // count ≤ capacity: CompareChip proves capacity < count false.
        let mut compare: Vec<E::F> = Vec::with_capacity(17);
        compare.extend_from_slice(&capacity);
        compare.extend_from_slice(&result);
        compare.push(E::F::zero());
        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                compare_lookup,
                is_witness[0].clone().into(),
                &compare,
            ));
        }
        // The call WitnessInputChip writes: (ts, destination, count).
        let mut call: Vec<E::F> = Vec::with_capacity(13);
        call.extend_from_slice(&timestamp);
        call.extend_from_slice(&destination[..4]);
        call.push(count);
        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                witness_call_lookup,
                non_empty[0].clone().into(),
                &call,
            ));
        }
    }
}
