//! The recursion seams on a `format::SEGMENT` proof: the recorded transcript, the
//! step-by-step extraction and the OODS reconstruction replay the same
//! verifier transcript.

use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::framework_access::boundary_relation_challenges;
use vos_pvm_proof::poseidon2::PermKind;
use vos_pvm_proof::{
    SideNote, extract_recursion_data, prove_format, reconstruct_oods_for_recursion,
    record_canonical_transcript,
};

/// Six chained Add64s and a trap.
fn side_note() -> SideNote {
    let mut code = Vec::new();
    let mut bitmask = Vec::new();
    for register in 2..8 {
        code.extend_from_slice(&[Opcode::Add64 as u8, 0x10 | (register - 1), register]);
        bitmask.extend_from_slice(&[1, 0, 0]);
    }
    code.push(Opcode::Trap as u8);
    bitmask.push(1);
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[0] = 100;
    registers[1] = 1;
    let memory = vec![0u8; 4 * 1024 * 1024];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        memory.clone(),
        10_000,
    );
    let mut tracing = TracingPvm::new(pvm);
    tracing.run();
    SideNote::new(tracing.into_trace(), code, bitmask).with_memory(memory)
}

#[test]
fn the_seams_replay_one_transcript_on_a_format_35_proof() {
    let mut side_note = side_note();
    let proof = prove_format(&mut side_note, &SEGMENT).expect("proves");
    let stark = proof.stark_proof.clone();
    let vos_pvm_proof::StarkProofAny::Poseidon2M31(stark) = stark else {
        panic!("format 35 proves on the Poseidon2-M31 channel");
    };

    let recorded = record_canonical_transcript(&proof);
    let data = extract_recursion_data(&proof);
    let oods = reconstruct_oods_for_recursion(&proof);

    let key = |records: &[vos_pvm_proof::poseidon2::PermRecord]| {
        records
            .iter()
            .map(|record| (record.kind, record.input, record.output, record.first_chunk))
            .collect::<Vec<_>>()
    };
    assert_eq!(data.transcript.prefix_len, recorded.prefix_len);
    assert_eq!(key(&data.transcript.records), key(&recorded.records));
    assert!(
        recorded.records[recorded.prefix_len..]
            .iter()
            .any(|record| record.kind == PermKind::Squeeze)
    );

    assert_eq!(oods.random_coeff, data.random_coeff);
    assert_eq!(
        boundary_relation_challenges(&oods.lookup_elements),
        boundary_relation_challenges(&data.lookup_elements)
    );
    assert_eq!(oods.comps.len(), proof.num_components);
    assert_eq!(oods.component_masks.len(), proof.num_components);

    assert_eq!(
        data.fold_alphas.len(),
        1 + stark.fri_proof.inner_layers.len()
    );
    assert!(!data.query_positions.is_empty());
    assert!(data.query_positions.len() <= SEGMENT.params.n_queries);
    assert_eq!(data.first_layer_evals.len(), data.query_positions.len());
    assert_eq!(data.tree_heights.len(), 4);
}
