//! Host calls: continuation, the BLAKE2b call and the witness-input call.
use alloc::vec::Vec;

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Row};
use crate::chips::cpu::tuples::BLAKE2B_CALL_REGS;
use crate::core::step::WORD_SIZE;

/// Host-call continuation.
pub(in crate::chips::cpu) fn host_call_continuation<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    let f256 = E::F::from(BaseField::from(256u32));
    // ── Host-call continuation ──
    //
    // IsExit also covers Trap and dynamic jumps. Subtracting their
    // authenticated per-opcode flags leaves exactly Ecalli. A host call
    // either remains at its cause PC and terminates the trace, or carries
    // an explicit acknowledgment and advances sequentially.
    {
        let soft_host = row.is_exit[0].clone()
            - row.is_trap[0].clone()
            - row.is_jump_ind[0].clone()
            - row.is_load_imm_jump_ind[0].clone();

        eval.add_constraint(
            row.host_call_acknowledged[0].clone()
                * (E::F::one() - row.host_call_acknowledged[0].clone()),
        );
        eval.add_constraint(
            row.host_call_acknowledged[0].clone() * (E::F::one() - soft_host.clone()),
        );

        // ProgramMemory commits the exact cryptographic dispatch ID, which
        // is non-zero only for an ECALLI identifier the proof runtime
        // handles. An acknowledged call selects exactly one precompile
        // relation, and its weighted selector must equal that
        // authenticated ID, so only a supported call can be acknowledged.
        // A call that is not acknowledged selects no relation.
        let precompile_selector_sum =
            row.is_blake_ecall[0].clone() + row.is_witness_ecall[0].clone();
        eval.add_constraint(precompile_selector_sum - row.host_call_acknowledged[0].clone());
        let selected_dispatch = row.is_blake_ecall[0].clone() * E::F::from(BaseField::from(100u32))
            + row.is_witness_ecall[0].clone() * E::F::from(BaseField::from(101u32));
        eval.add_constraint(
            selected_dispatch
                - row.host_call_acknowledged[0].clone()
                    * row.host_call_precompile_dispatch[0].clone(),
        );

        let seq_pc = [
            row.pc[0].clone() + E::F::one() + row.skip_len[0].clone()
                - row.pc_carry[0].clone() * f256.clone(),
            row.pc[1].clone() + row.pc_carry[0].clone() - row.pc_carry[1].clone() * f256.clone(),
            row.pc[2].clone() + row.pc_carry[1].clone() - row.pc_carry[2].clone() * f256.clone(),
            row.pc[3].clone() + row.pc_carry[2].clone(),
        ];
        for i in 0..4 {
            eval.add_constraint(
                soft_host.clone() * (row.next_pc[i].clone() - row.pc[i].clone())
                    - row.host_call_acknowledged[0].clone()
                        * (seq_pc[i].clone() - row.pc[i].clone()),
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
        eval.add_constraint(
            (soft_host - row.host_call_acknowledged[0].clone())
                * (E::F::one() - row.is_padding_next[0].clone()),
        );
    }
}

/// The BLAKE2b call: its register reads, the Phi7Bool tie and the call binding.
pub(in crate::chips::cpu) fn blake2b_call<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups,
) {
    let blake2b_call_lookup = &lookups.blake2b_call_lookup;
    let reg_lookup = &lookups.reg_lookup;
    // ── blake2b ECALL register-read producers + Phi7Bool tie ──
    {
        // Each slot's register read ([`BLAKE2B_CALL_REGS`]).
        let phi_cols: [&[E::F]; 4] = [&row.phi7, &row.phi10, &row.phi11, &row.phi12];
        for (slot, &reg_idx) in BLAKE2B_CALL_REGS.iter().enumerate() {
            let mut tuple: Vec<E::F> = Vec::with_capacity(18);
            tuple.push(E::F::from(BaseField::from(reg_idx)));
            for c in phi_cols[slot] {
                tuple.push(c.clone());
            }
            for c in &row.timestamp {
                tuple.push(c.clone());
            }
            tuple.push(E::F::from(BaseField::from(0u32))); // is_write = 0 (read)
            eval.add_to_relation(RelationEntry::new(
                reg_lookup,
                row.is_blake_ecall[0].clone().into(),
                &tuple,
            ));
        }

        // Phi7Bool ↔ Phi7 (its bytes' sum, zero exactly when the
        // register is) tie, gated only by is_real.
        // Phi7Bool is boolean on every row (`registers::register_helpers`).
        // If Phi7Bool = 0, then Phi7's bytes are 0.
        let phi7_sum = row
            .phi7
            .iter()
            .fold(E::F::zero(), |sum, byte| sum + byte.clone());
        eval.add_constraint(row.real_not_phi7_bool_h[0].clone() * phi7_sum);
        // If Phi7Bool = 1, then Phi7 · Phi7Inv = 1 — body lifted into
        // Phi7TimesInvH so the gate × body is deg 2.
        eval.add_constraint(
            row.real_phi7_bool_h[0].clone() * (row.phi7_times_inv_h[0].clone() - E::F::one()),
        );
    }

    // Blake2b call binding: mirror of the prover-side producer.
    {
        let mut tuple: Vec<E::F> = Vec::with_capacity(25);
        for i in 0..4 {
            tuple.push(row.phi10[i].clone());
        }
        for i in 0..4 {
            tuple.push(row.phi11[i].clone());
        }
        for i in 0..WORD_SIZE {
            tuple.push(row.phi12[i].clone());
        }
        tuple.push(row.phi7_bool[0].clone());
        for i in 0..WORD_SIZE {
            tuple.push(row.timestamp[i].clone());
        }
        eval.add_to_relation(RelationEntry::new(
            blake2b_call_lookup,
            row.is_blake_ecall[0].clone().into(),
            &tuple,
        ));

        // The pointers are 32-bit: the machine refuses a call whose
        // φ7 or φ8 is past 2^32, and the call tuple carries their low
        // four bytes only.
        for i in 4..WORD_SIZE {
            eval.add_constraint(row.is_blake_ecall[0].clone() * row.phi10[i].clone());
            eval.add_constraint(row.is_blake_ecall[0].clone() * row.phi11[i].clone());
        }

        // Phi7Bool and IsBlakeEcall are boolean on every row
        // (`registers::register_helpers`).
    }
}

/// The witness-input call's register reads.
pub(in crate::chips::cpu) fn witness_input_reads<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups,
) {
    let reg_lookup = &lookups.reg_lookup;
    // ── Witness-input register reads ──
    // The call reads φ[7] and φ[8], its destination and capacity, from
    // the Phi10/Phi11 slots (= regs_before[7,8], filled every row); the
    // register-read producers bind those snapshots to the register file
    // at the step ts. Two emissions keep finalize_logup_in_pairs
    // balanced.
    {
        // Register-read producers (reg_idx, value[8], ts[8], is_write=0):
        // φ[7] in Phi10, φ[8] in Phi11.
        for (reg_idx, value) in [(7u32, &row.phi10), (8u32, &row.phi11)] {
            let mut tuple: Vec<E::F> = Vec::with_capacity(18);
            tuple.push(E::F::from(BaseField::from(reg_idx)));
            for c in value.iter() {
                tuple.push(c.clone());
            }
            for c in &row.timestamp {
                tuple.push(c.clone());
            }
            tuple.push(E::F::from(BaseField::from(0u32))); // is_write = 0 (read)
            eval.add_to_relation(RelationEntry::new(
                reg_lookup,
                row.is_witness_ecall[0].clone().into(),
                &tuple,
            ));
        }
    }
}

/// The witness-input call's binding.
pub(in crate::chips::cpu) fn witness_input<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups,
) {
    let compare_lookup = &lookups.compare_lookup;
    let witness_call_lookup = &lookups.witness_call_lookup;
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
        let f256 = E::F::from(BaseField::from(256u32));
        let count = row.result[0].clone()
            + row.result[1].clone() * f256.clone()
            + row.result[2].clone() * f256.clone() * f256;

        // The count is φ7's write, and below 2^24, so it is its own
        // field value.
        eval.add_constraint(
            row.is_witness_ecall[0].clone() * (E::F::one() - row.result_is_reg[0].clone()),
        );
        eval.add_constraint(
            row.is_witness_ecall[0].clone()
                * (row.result_reg_idx[0].clone() - E::F::from(BaseField::from(7u32))),
        );
        for byte in &row.result[3..WORD_SIZE] {
            eval.add_constraint(row.is_witness_ecall[0].clone() * byte.clone());
        }
        // A call that writes bytes writes them below 2^32; one that
        // writes none may name any destination, as the live call does.
        for byte in &row.phi10[4..WORD_SIZE] {
            eval.add_constraint(row.witness_non_empty[0].clone() * byte.clone());
        }
        // WitnessNonEmpty: a witness row's count is non-zero exactly
        // when it is set.
        eval.add_constraint(
            row.witness_non_empty[0].clone() * (E::F::one() - row.witness_non_empty[0].clone()),
        );
        eval.add_constraint(
            row.witness_non_empty[0].clone() * (E::F::one() - row.is_witness_ecall[0].clone()),
        );
        eval.add_constraint(
            (row.is_witness_ecall[0].clone() - row.witness_non_empty[0].clone()) * count.clone(),
        );
        eval.add_constraint(
            row.witness_count_times_inv_h[0].clone()
                - count.clone() * row.witness_count_inv[0].clone(),
        );
        eval.add_constraint(
            row.witness_non_empty[0].clone()
                * (row.witness_count_times_inv_h[0].clone() - E::F::one()),
        );

        // count ≤ capacity: CompareChip proves capacity < count false.
        let mut compare: Vec<E::F> = Vec::with_capacity(17);
        compare.extend_from_slice(&row.phi11);
        compare.extend_from_slice(&row.result);
        compare.push(E::F::zero());
        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                compare_lookup,
                row.is_witness_ecall[0].clone().into(),
                &compare,
            ));
        }
        // The call WitnessInputChip writes: (ts, destination, count).
        let mut call: Vec<E::F> = Vec::with_capacity(13);
        call.extend_from_slice(&row.timestamp);
        call.extend_from_slice(&row.phi10[..4]);
        call.push(count);
        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                witness_call_lookup,
                row.witness_non_empty[0].clone().into(),
                &call,
            ));
        }
    }
}
