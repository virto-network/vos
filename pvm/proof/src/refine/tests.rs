use alloc::vec;
use alloc::vec::Vec;

use super::*;

fn standard_program_with_rw(code: &[u8], starts: &[usize], rw_data: &[u8]) -> Vec<u8> {
    let mut packed = vec![0u8; code.len().div_ceil(8)];
    for &index in starts {
        packed[index / 8] |= 1 << (index % 8);
    }
    let mut code_blob = vec![0, 1, code.len() as u8];
    code_blob.extend_from_slice(code);
    code_blob.extend_from_slice(&packed);

    let mut blob = Vec::new();
    blob.extend_from_slice(&[0; 3]);
    blob.extend_from_slice(&(rw_data.len() as u32).to_le_bytes()[..3]);
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&4096u32.to_le_bytes()[..3]);
    blob.extend_from_slice(rw_data);
    blob.extend_from_slice(&(code_blob.len() as u32).to_le_bytes());
    blob.extend_from_slice(&code_blob);
    blob
}

fn inner_program() -> Vec<u8> {
    // host(42), then trap.
    vec![0, 1, 3, 10, 42, 0, 0b0000_0101]
}

fn nested_fixture() -> (Vec<u8>, Vec<u8>, u64) {
    const RW_BASE: u32 = 2 * vos_pvm::PVM_ZONE_SIZE;
    let mut frame = [0u8; 112];
    frame[..8].copy_from_slice(&100_000u64.to_le_bytes());
    let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
    // machine(args), r8 <- RW_BASE, invoke(machine 0, frame), halt.
    let code = [10, 9, 51, 8, b0, b1, b2, 10, 13, 50, 0];
    (
        standard_program_with_rw(&code, &[0, 2, 7, 9], &frame),
        inner_program(),
        1_000_000,
    )
}

#[test]
fn direct_observation_builds_canonical_nested_sparse_slices() {
    let (outer, arguments, gas) = nested_fixture();
    let trace = trace_refine(&outer, &arguments, gas).expect("trace nested Refine");

    assert_eq!(trace.outer_program, refine_program_id(&outer));
    assert_eq!(
        trace.arguments_commitment,
        refine_arguments_commitment(&arguments)
    );
    assert_eq!(trace.gas_limit, gas);
    assert_eq!(trace.slices.len(), 4);
    assert_eq!(trace.host_boundaries.len(), 2);
    assert_eq!(
        trace
            .slices
            .iter()
            .map(|slice| slice.order)
            .collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
    assert!(matches!(
        trace.slices[0].identity,
        RefineMachineId::Outer { program } if program == refine_program_id(&outer)
    ));
    assert!(matches!(
        trace.slices[2].identity,
        RefineMachineId::Inner { slot: 0, generation: 0, program }
            if program == refine_program_id(&arguments)
    ));
    assert_eq!(
        trace
            .host_boundaries
            .iter()
            .map(|boundary| (boundary.call, boundary.slices_before, boundary.slices_after))
            .collect::<Vec<_>>(),
        [(9, 1, 1), (13, 2, 3)]
    );
    assert_ne!(
        trace.host_boundaries[1].state_before,
        trace.host_boundaries[1].state_after
    );
    assert_ne!(
        trace.host_boundaries[1].registers_before,
        trace.host_boundaries[1].registers_after
    );

    for slice in &trace.slices {
        assert!(slice.side_note.initial_memory.is_empty());
        let image = slice
            .side_note
            .sparse_initial_memory
            .as_ref()
            .expect("Refine slices use sparse memory");
        // The standard layout reserves guard space near the top of the
        // 32-bit address space, so its mapped span is just under 4 GiB.
        // What matters here is that the witness stays page-sparse rather
        // than materialising that multi-GiB logical image.
        assert!(image.span() > 4_000_000_000);
        assert!(image.pages().len() < 16);
    }
    assert_eq!(trace.slices[0].side_note.steps[0].timestamp, 1);
    assert_eq!(trace.slices[1].side_note.steps[0].timestamp, 2);
    assert_eq!(trace.slices[2].side_note.steps[0].timestamp, 1);
    assert_eq!(trace.slices[3].side_note.steps[0].timestamp, 4);
    assert!(alloc::sync::Arc::ptr_eq(
        &trace.slices[0].side_note.code,
        &trace.slices[1].side_note.code,
    ));
    assert!(alloc::sync::Arc::ptr_eq(
        &trace.slices[1].side_note.code,
        &trace.slices[3].side_note.code,
    ));

    let metrics = prover::collector_metrics_for(&outer, &arguments, gas).unwrap();
    assert_eq!(metrics.static_program_copies, 2);
    assert_eq!(metrics.program_identity_hashes, 1);
    assert_eq!(
        metrics.static_location_checks,
        trace
            .slices
            .iter()
            .map(|slice| slice.side_note.steps.len())
            .sum::<usize>()
    );
    // Outer memory is scanned once; the inner is scanned at entry and
    // once more after its invocation mutates the invoke frame.
    assert_eq!(metrics.full_value_scans, 3);
    assert_eq!(metrics.full_permission_scans, 2);
}

/// An inner machine's BLAKE2b call exits to its outer machine, which
/// serves it in place with its own call before resuming the inner one:
/// the inner slice ends at the unacknowledged call, the outer slice holds
/// the acknowledged one, and the whole refine proves and verifies.
#[test]
fn a_refine_serving_an_inner_precompile_proves() {
    const RW_BASE: u32 = 2 * vos_pvm::PVM_ZONE_SIZE;
    let mut rw = vec![0u8; 112 + 64 + 128];
    rw[..8].copy_from_slice(&100_000u64.to_le_bytes());
    rw[8..16].copy_from_slice(&vos_pvm::PVM_HALT_ADDR.to_le_bytes());
    let le = |value: u32| -> [u8; 3] {
        let [b0, b1, b2, _] = value.to_le_bytes();
        [b0, b1, b2]
    };
    let [f0, f1, f2] = le(RW_BASE);
    let [h0, h1, h2] = le(RW_BASE + 112);
    let [m0, m1, m2] = le(RW_BASE + 176);
    // machine(args); invoke it to its call; compress in place with φ7..φ10
    // on the outer machine's own buffers; invoke it again to its halt;
    // halt.
    let code = [
        10, 9, // machine
        51, 8, f0, f1, f2, // φ8 <- the frame
        10, 13, // invoke
        51, 7, h0, h1, h2, // φ7 <- h
        51, 8, m0, m1, m2, // φ8 <- m
        51, 9, 0, // φ9 <- 0
        51, 10, 1, // φ10 <- 1
        10, 0x00, 0x04, // BLAKE2b
        51, 7, 0, // φ7 <- machine 0
        51, 8, f0, f1, f2, // φ8 <- the frame
        10, 13, // invoke
        50, 0, // halt
    ];
    let starts = [0, 2, 7, 9, 14, 19, 22, 25, 28, 31, 36, 38];
    let outer = standard_program_with_rw(&code, &starts, &rw);
    // BLAKE2b, then return to the halt address in φ0.
    let inner = vec![0, 1, 5, 10, 0x00, 0x04, 50, 0, 0b0000_1001];

    let trace = trace_refine(&outer, &inner, 1_000_000).expect("trace");
    assert_eq!(trace.result, RefineSliceExit::Halt);
    let blake = |slice: &RefineTraceSlice| {
        slice
            .side_note
            .steps
            .iter()
            .filter(|step| {
                step.opcode == crate::core::opcode::Opcode::Ecalli
                    && step.imm == crate::core::ecall::ECALL_BLAKE2B_COMPRESS as u64
            })
            .map(|step| step.host_call_acknowledged)
            .collect::<Vec<_>>()
    };
    let calls: Vec<(bool, Vec<bool>)> = trace
        .slices
        .iter()
        .map(|slice| {
            let inner = matches!(slice.identity, RefineMachineId::Inner { .. });
            (inner, blake(slice))
        })
        .filter(|(_, calls)| !calls.is_empty())
        .collect();
    assert_eq!(
        calls,
        [(true, vec![false]), (false, vec![true])],
        "the inner call left to its outer machine, which serves it"
    );
    let bundle = prove_refine(trace).expect("prove");
    verify_refine_bundle_replayed(&bundle, &outer, &inner, 1_000_000).expect("verify");
}

#[test]
fn input_identity_binds_exact_bytes_and_gas() {
    let (outer, arguments, gas) = nested_fixture();
    let trace = trace_refine(&outer, &arguments, gas).unwrap();
    let mut changed = arguments.clone();
    changed[4] ^= 1;
    assert_ne!(
        trace.arguments_commitment,
        refine_arguments_commitment(&changed)
    );
    assert_ne!(trace.outer_program, refine_program_id(&arguments));
    assert_ne!(gas, gas + 1);
}

#[test]
fn observed_trace_returns_the_exact_same_run_output() {
    const RW_BASE: u32 = 2 * vos_pvm::PVM_ZONE_SIZE;
    let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
    // a0 <- RW_BASE, a1 <- 3, a2..a5 <- 1..=4, halt.
    let code = [
        51, 7, b0, b1, b2, 51, 8, 3, 0, 0, 51, 9, 1, 0, 0, 51, 10, 2, 0, 0, 51, 11, 3, 0, 0, 51,
        12, 4, 0, 0, 50, 0,
    ];
    let outer = standard_program_with_rw(&code, &[0, 5, 10, 15, 20, 25, 30], b"out");

    let observed = trace_refine_observed(&outer, b"args", 1_000_000, 3).unwrap();
    let mut expected_public_io = [0u8; 32];
    for (index, word) in [1u64, 2, 3, 4].iter().enumerate() {
        expected_public_io[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    assert_eq!(observed.trace.result, RefineSliceExit::Halt);
    assert_eq!(observed.output, b"out");
    assert_eq!(observed.public_io, expected_public_io);
    assert!(matches!(
        trace_refine_observed(&outer, b"args", 1_000_000, 2),
        Err(RefineTraceError::OutputUnavailable)
    ));

    let (trace, output) = trace_refine_with_output(&outer, b"args", 1_000_000, 3).unwrap();

    assert_eq!(trace.result, RefineSliceExit::Halt);
    assert_eq!(output.as_deref(), Some(b"out".as_slice()));
    assert_ne!(refine_trace_execution_commitment(&trace), [0; 32]);

    let (bounded_trace, bounded_output) =
        trace_refine_with_output(&outer, b"args", 1_000_000, 2).unwrap();
    assert_eq!(bounded_output, None);
    assert_eq!(
        refine_trace_execution_commitment(&bounded_trace),
        refine_trace_execution_commitment(&trace),
        "the allocation ceiling must not change the observed execution",
    );
}

#[test]
fn observation_records_every_standard_host_boundary() {
    const RW_BASE: u32 = 2 * vos_pvm::PVM_ZONE_SIZE;
    let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
    // Calls 9..12 can safely report errors from their zero/unknown inputs.
    // Point INVOKE at a writable frame, then call 13 and 14 and halt.
    let code = [
        10, 9, 10, 10, 10, 11, 10, 12, 51, 8, b0, b1, b2, 10, 13, 10, 14, 50, 0,
    ];
    let outer = standard_program_with_rw(&code, &[0, 2, 4, 6, 8, 13, 15, 17], &[0; 112]);
    let trace = trace_refine(&outer, &[], 1_000_000).unwrap();

    assert_eq!(
        trace
            .host_boundaries
            .iter()
            .map(|boundary| boundary.call)
            .collect::<Vec<_>>(),
        [9, 10, 11, 12, 13, 14]
    );
    assert_eq!(trace.slices.len(), 7);
    for (index, boundary) in trace.host_boundaries.iter().enumerate() {
        assert_eq!(boundary.slices_before, index as u32 + 1);
        assert_eq!(boundary.slices_after, boundary.slices_before);
    }
    assert_eq!(trace.result, RefineSliceExit::Halt);
}

#[test]
fn prove_preflights_slice_cardinality_without_proving() {
    let identity = RefineMachineId::Outer {
        program: RefineProgramId([0; 32]),
    };
    let slices = (0..=MAX_REFINE_PROOF_SLICES)
        .map(|order| RefineTraceSlice {
            order: order as u32,
            identity,
            entry_state: [0; 32],
            observed_exit_state: [0; 32],
            exit: RefineSliceExit::Halt,
            side_note: crate::SideNote::new(Vec::new(), Vec::new(), Vec::new()),
        })
        .collect();
    let trace = RefineTraceBundle {
        outer_program: identity.program(),
        arguments_commitment: [0; 32],
        gas_limit: 0,
        slices,
        host_boundaries: Vec::new(),
        result: RefineSliceExit::Halt,
    };
    assert!(matches!(
        prove_refine(trace),
        Err(RefineTraceError::Observation(message))
            if message.contains("cardinality")
    ));
}

#[test]
fn proof_generation_numbers_reject_previous_formats() {
    assert_eq!(crate::PROOF_FORMAT_VERSION, 24);
    // Every number before the registry's, and 25, the retired Poseidon2-M31
    // variant of 24, are unregistered.
    for previous in (0..=23).chain([25]) {
        assert!(crate::format::lookup(previous).is_none(), "{previous}");
    }
}

#[test]
fn transcript_integers_have_one_canonical_little_endian_encoding() {
    let mut encoded = Vec::new();
    put_u32(&mut encoded, 0x7856_3412);
    put_u64(&mut encoded, 0xf0de_bc9a_7856_3412);
    assert_eq!(
        encoded,
        [
            0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        ]
    );
}
