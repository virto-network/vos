use vos_pvm_proof::{
    MAX_REFINE_CHILD_COMPONENTS, MAX_REFINE_HOST_BOUNDARIES, PcsConfig,
    REFINE_BUNDLE_FORMAT_VERSION, RefineHostBoundary, RefineMachineId, RefineProgramId,
    RefineProofBundle, RefineSliceExit, RefineTraceError, production_pcs_config_mobile,
    prove_refine, refine_arguments_commitment, refine_bundle_cardinality_is_valid,
    refine_bundle_commitment, refine_program_id, trace_refine, verify_refine_bundle_replayed,
};
use vos_pvm_proof_verifier::{
    CommitmentHash, RefineBundleVerification, RefineProgramCommitmentResolver,
    verify_refine_bundle_authenticated,
};

struct TrustedPrograms(
    Vec<(
        RefineMachineId,
        u32,
        u32,
        Vec<u32>,
        PcsConfig,
        CommitmentHash,
    )>,
);

impl TrustedPrograms {
    fn from_bundle(bundle: &RefineProofBundle) -> Self {
        Self(
            bundle
                .slices
                .iter()
                .map(|slice| {
                    (
                        slice.identity,
                        slice.proof.format_version,
                        slice.proof.component_mask,
                        slice.proof.log_sizes.clone(),
                        slice.proof.pcs_config,
                        slice.proof.stark_proof.commitments[0],
                    )
                })
                .collect(),
        )
    }
}

impl RefineProgramCommitmentResolver for TrustedPrograms {
    fn resolve_preprocessed_commitment(
        &self,
        identity: RefineMachineId,
        proof_format_version: u32,
        component_mask: u32,
        log_sizes: &[u32],
        pcs_config: &PcsConfig,
    ) -> Option<CommitmentHash> {
        self.0
            .iter()
            .find(|(candidate, format, mask, sizes, config, _)| {
                *candidate == identity
                    && *format == proof_format_version
                    && *mask == component_mask
                    && sizes == log_sizes
                    && config == pcs_config
            })
            .map(|(_, _, _, _, _, commitment)| *commitment)
    }
}

struct ResolverMustNotRun;

impl RefineProgramCommitmentResolver for ResolverMustNotRun {
    fn resolve_preprocessed_commitment(
        &self,
        _identity: RefineMachineId,
        _proof_format_version: u32,
        _component_mask: u32,
        _log_sizes: &[u32],
        _pcs_config: &PcsConfig,
    ) -> Option<CommitmentHash> {
        panic!("cardinality preflight must precede resolver callbacks")
    }
}

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

fn nested_fixture() -> (Vec<u8>, Vec<u8>, u64) {
    const RW_BASE: u32 = 2 * vos_pvm::PVM_ZONE_SIZE;
    let mut frame = [0u8; 112];
    frame[..8].copy_from_slice(&100_000u64.to_le_bytes());
    let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
    // machine(args), r8 <- RW_BASE, invoke(machine 0, frame), halt.
    let code = [10, 9, 51, 8, b0, b1, b2, 10, 13, 50, 0];
    let inner = vec![0, 1, 3, 10, 42, 0, 0b0000_0101];
    (
        standard_program_with_rw(&code, &[0, 2, 7, 9], &frame),
        inner,
        1_000_000,
    )
}

fn reseal(bundle: &mut RefineProofBundle) {
    bundle.transcript_commitment = refine_bundle_commitment(bundle);
}

fn assert_replay_mismatch(
    bundle: &RefineProofBundle,
    outer: &[u8],
    arguments: &[u8],
    gas: u64,
    expected: &'static str,
) {
    assert!(matches!(
        verify_refine_bundle_replayed(bundle, outer, arguments, gas),
        Err(RefineTraceError::ReplayMismatch(field)) if field == expected
    ));
}

#[test]
fn oversized_boundaries_reject_before_hashing_or_resolving_without_proofs() {
    let boundary = RefineHostBoundary {
        call: 9,
        slices_before: 1,
        slices_after: 1,
        state_before: [0; 32],
        state_after: [0; 32],
        registers_before: [0; 13],
        registers_after: [0; 13],
    };
    let bundle = RefineProofBundle {
        format_version: REFINE_BUNDLE_FORMAT_VERSION,
        outer_program: RefineProgramId([0; 32]),
        arguments_commitment: [0; 32],
        gas_limit: 0,
        slices: Vec::new(),
        host_boundaries: vec![boundary; MAX_REFINE_HOST_BOUNDARIES + 1],
        result: RefineSliceExit::Halt,
        transcript_commitment: [0; 32],
    };
    assert!(!refine_bundle_cardinality_is_valid(&bundle));
    assert!(
        verify_refine_bundle_authenticated(
            &bundle,
            RefineProgramId([0; 32]),
            [0; 32],
            0,
            &ResolverMustNotRun,
        )
        .is_err()
    );
}

#[test]
fn nested_bundle_verifies_only_with_replay_and_rejects_hostile_edits() {
    let (outer, arguments, gas) = nested_fixture();
    let bundle = prove_refine(trace_refine(&outer, &arguments, gas).unwrap())
        .expect("prove nested Refine closure");
    let mut changed_order = bundle.clone();
    changed_order.slices[0].order = changed_order.slices[0].order.wrapping_add(1);
    assert_ne!(
        refine_bundle_commitment(&changed_order),
        bundle.transcript_commitment,
        "a changed u32 transcript field must change the bundle commitment"
    );
    let mut changed_vector = bundle.clone();
    changed_vector.host_boundaries.swap(0, 1);
    assert_ne!(
        refine_bundle_commitment(&changed_vector),
        bundle.transcript_commitment,
        "ordered boundary-vector identity must be commitment-sensitive"
    );
    let mut changed_components = bundle.clone();
    changed_components.slices[0].proof.num_components += 1;
    assert_ne!(
        refine_bundle_commitment(&changed_components),
        bundle.transcript_commitment,
        "child component cardinality is part of the authenticated proof shape"
    );
    let mut changed_sums = bundle.clone();
    changed_sums.slices[0].proof.claimed_sums.clear();
    assert_ne!(
        refine_bundle_commitment(&changed_sums),
        bundle.transcript_commitment,
        "child claimed sums are part of the authenticated proof transcript"
    );
    // Stand-in for an authenticated program catalog: capture it from the
    // honest admitted bundle before applying any hostile edits below.
    let trusted_programs = TrustedPrograms::from_bundle(&bundle);

    // A valid proof for the exact same outer program and AIR/PCS shape, but
    // a different initial gas budget, cannot be substituted for this
    // execution. This is deliberately a same-program proof substitution:
    // only exact deterministic replay distinguishes the witnesses.
    let alternate_bundle = prove_refine(trace_refine(&outer, &arguments, gas + 1).unwrap())
        .expect("prove alternate Refine closure");
    assert_eq!(
        bundle.slices[0].proof.component_mask,
        alternate_bundle.slices[0].proof.component_mask
    );
    assert_eq!(
        bundle.slices[0].proof.log_sizes,
        alternate_bundle.slices[0].proof.log_sizes
    );
    assert_ne!(
        bundle.slices[0].proof.stark_proof.commitments[1],
        alternate_bundle.slices[0].proof.stark_proof.commitments[1],
        "different gas witnesses must produce different main-trace commitments"
    );
    let mut substituted_execution = bundle.clone();
    substituted_execution.slices[0].proof = alternate_bundle.slices[0].proof.clone();
    reseal(&mut substituted_execution);
    assert_replay_mismatch(
        &substituted_execution,
        &outer,
        &arguments,
        gas,
        "child proof does not bind exact replay trace",
    );

    // The trusted resolver key includes every PCS field. STANDARD, MOBILE,
    // and explicit lifting profiles cannot alias the same catalog entry.
    let mut wrong_mobile = bundle.clone();
    wrong_mobile.slices[0].proof.pcs_config = production_pcs_config_mobile();
    wrong_mobile.slices[0].proof.stark_proof.0.config = production_pcs_config_mobile();
    reseal(&mut wrong_mobile);
    assert!(
        verify_refine_bundle_authenticated(
            &wrong_mobile,
            refine_program_id(&outer),
            refine_arguments_commitment(&arguments),
            gas,
            &trusted_programs,
        )
        .is_err()
    );
    let mut wrong_lifting = bundle.clone();
    wrong_lifting.slices[0].proof.pcs_config.lifting_log_size = Some(30);
    wrong_lifting.slices[0]
        .proof
        .stark_proof
        .0
        .config
        .lifting_log_size = Some(30);
    reseal(&mut wrong_lifting);
    assert!(
        verify_refine_bundle_authenticated(
            &wrong_lifting,
            refine_program_id(&outer),
            refine_arguments_commitment(&arguments),
            gas,
            &trusted_programs,
        )
        .is_err()
    );

    let mut oversized_shape = bundle.clone();
    oversized_shape.slices[0]
        .proof
        .log_sizes
        .resize(MAX_REFINE_CHILD_COMPONENTS + 1, 0);
    assert!(!refine_bundle_cardinality_is_valid(&oversized_shape));
    assert!(
        verify_refine_bundle_authenticated(
            &oversized_shape,
            refine_program_id(&outer),
            refine_arguments_commitment(&arguments),
            gas,
            &ResolverMustNotRun,
        )
        .is_err(),
        "child shape cardinality must reject before hashing or resolver callbacks"
    );

    let mut oversized_nested = bundle.clone();
    let sample = oversized_nested.slices[0].proof.stark_proof.sampled_values[0][0][0];
    oversized_nested.slices[0]
        .proof
        .stark_proof
        .0
        .sampled_values[0][0]
        .resize(
            vos_pvm_proof::proof::MAX_PROOF_SAMPLES_PER_COLUMN + 1,
            sample,
        );
    let preclone = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_refine_bundle_authenticated(
            &oversized_nested,
            refine_program_id(&outer),
            refine_arguments_commitment(&arguments),
            gas,
            &ResolverMustNotRun,
        )
    }));
    assert!(preclone.is_ok(), "hostile nested vector must not panic");
    assert!(preclone.unwrap().is_err());

    // Forge claimed-small logs plus a correspondingly undersized explicit
    // lifting domain. The cheap child preflight accepts its own claimed
    // shape; exact replay discovers the larger real trace before any Stwo
    // domain/commit constructor can assert.
    let mut undersized_replay_lifting = bundle.clone();
    undersized_replay_lifting.slices[0].proof.log_sizes.fill(4);
    undersized_replay_lifting.slices[0]
        .proof
        .pcs_config
        .lifting_log_size = Some(8);
    undersized_replay_lifting.slices[0]
        .proof
        .stark_proof
        .0
        .config
        .lifting_log_size = Some(8);
    reseal(&mut undersized_replay_lifting);
    let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_refine_bundle_replayed(&undersized_replay_lifting, &outer, &arguments, gas)
    }));
    assert!(replay.is_ok(), "undersized replay lifting must not panic");
    assert!(replay.unwrap().is_err());

    verify_refine_bundle_replayed(&bundle, &outer, &arguments, gas)
        .expect("exact deterministic replay closes host semantics");
    assert_eq!(
        verify_refine_bundle_authenticated(
            &bundle,
            refine_program_id(&outer),
            refine_arguments_commitment(&arguments),
            gas,
            &trusted_programs,
        )
        .unwrap(),
        RefineBundleVerification::ReplayRequired {
            transcript_commitment: bundle.transcript_commitment,
        }
    );

    // A transcript can authenticate forged native state just as well as
    // honest state. Structural verification therefore explicitly requires
    // replay, while exact replay rejects the mutation.
    let mut forged_after = bundle.clone();
    forged_after.host_boundaries[1].state_after[0] ^= 1;
    reseal(&mut forged_after);
    assert!(matches!(
        verify_refine_bundle_authenticated(
            &forged_after,
            refine_program_id(&outer),
            refine_arguments_commitment(&arguments),
            gas,
            &trusted_programs,
        )
        .unwrap(),
        RefineBundleVerification::ReplayRequired { .. }
    ));
    assert_replay_mismatch(&forged_after, &outer, &arguments, gas, "host boundaries");

    // Omitting the actual INVOKE child can remain structurally plausible
    // (e.g. an unknown-machine result), but exact replay detects the omission.
    let mut missing_child = bundle.clone();
    missing_child.slices.remove(2);
    missing_child.slices[2].order = 2;
    missing_child.host_boundaries[1].slices_after = 2;
    reseal(&mut missing_child);
    assert!(matches!(
        verify_refine_bundle_authenticated(
            &missing_child,
            refine_program_id(&outer),
            refine_arguments_commitment(&arguments),
            gas,
            &trusted_programs,
        )
        .unwrap(),
        RefineBundleVerification::ReplayRequired { .. }
    ));
    assert_replay_mismatch(&missing_child, &outer, &arguments, gas, "host boundaries");

    let mut reordered = bundle.clone();
    reordered.slices.swap(1, 2);
    reseal(&mut reordered);
    assert!(
        verify_refine_bundle_authenticated(
            &reordered,
            refine_program_id(&outer),
            refine_arguments_commitment(&arguments),
            gas,
            &trusted_programs,
        )
        .is_err()
    );
    assert_replay_mismatch(&reordered, &outer, &arguments, gas, "machine slice");

    for identity in [
        RefineMachineId::Inner {
            slot: 1,
            generation: 0,
            program: refine_program_id(&arguments),
        },
        RefineMachineId::Inner {
            slot: 0,
            generation: 1,
            program: refine_program_id(&arguments),
        },
        RefineMachineId::Inner {
            slot: 0,
            generation: 0,
            program: refine_program_id(&outer),
        },
    ] {
        let mut swapped_identity = bundle.clone();
        swapped_identity.slices[2].identity = identity;
        reseal(&mut swapped_identity);
        assert!(
            verify_refine_bundle_authenticated(
                &swapped_identity,
                refine_program_id(&outer),
                refine_arguments_commitment(&arguments),
                gas,
                &trusted_programs,
            )
            .is_err(),
            "trusted program commitments must reject relabelled child proofs"
        );
        assert_replay_mismatch(&swapped_identity, &outer, &arguments, gas, "machine slice");
    }

    let mut missing_boundary = bundle.clone();
    missing_boundary.host_boundaries.remove(0);
    reseal(&mut missing_boundary);
    assert!(
        verify_refine_bundle_authenticated(
            &missing_boundary,
            refine_program_id(&outer),
            refine_arguments_commitment(&arguments),
            gas,
            &trusted_programs,
        )
        .is_err()
    );

    let mut orphan_inner = bundle.clone();
    orphan_inner.host_boundaries[1].slices_after = 2;
    reseal(&mut orphan_inner);
    assert!(
        verify_refine_bundle_authenticated(
            &orphan_inner,
            refine_program_id(&outer),
            refine_arguments_commitment(&arguments),
            gas,
            &trusted_programs,
        )
        .is_err()
    );

    let mut wrong_result = bundle.clone();
    wrong_result.result = RefineSliceExit::Trap;
    reseal(&mut wrong_result);
    assert!(
        verify_refine_bundle_authenticated(
            &wrong_result,
            refine_program_id(&outer),
            refine_arguments_commitment(&arguments),
            gas,
            &trusted_programs,
        )
        .is_err()
    );
    assert_replay_mismatch(&wrong_result, &outer, &arguments, gas, "slice/result shape");

    let mut unknown_bundle_version = bundle.clone();
    unknown_bundle_version.format_version += 1;
    reseal(&mut unknown_bundle_version);
    assert!(
        verify_refine_bundle_authenticated(
            &unknown_bundle_version,
            refine_program_id(&outer),
            refine_arguments_commitment(&arguments),
            gas,
            &trusted_programs,
        )
        .is_err()
    );
    assert_replay_mismatch(
        &unknown_bundle_version,
        &outer,
        &arguments,
        gas,
        "bundle format version",
    );

    let mut old_bundle_version = bundle.clone();
    old_bundle_version.format_version = 1;
    reseal(&mut old_bundle_version);
    assert!(
        verify_refine_bundle_authenticated(
            &old_bundle_version,
            refine_program_id(&outer),
            refine_arguments_commitment(&arguments),
            gas,
            &trusted_programs,
        )
        .is_err()
    );
    assert_replay_mismatch(
        &old_bundle_version,
        &outer,
        &arguments,
        gas,
        "bundle format version",
    );

    for old_format in [16, 17, 18, 19] {
        let mut old_child = bundle.clone();
        old_child.slices[0].proof.format_version = old_format;
        reseal(&mut old_child);
        assert!(
            verify_refine_bundle_authenticated(
                &old_child,
                refine_program_id(&outer),
                refine_arguments_commitment(&arguments),
                gas,
                &trusted_programs,
            )
            .is_err()
        );
        assert_replay_mismatch(&old_child, &outer, &arguments, gas, "bundle cardinality");
    }

    let mut no_commitment = bundle.clone();
    no_commitment.slices[0]
        .proof
        .stark_proof
        .0
        .commitments
        .clear();
    reseal(&mut no_commitment);
    assert!(
        verify_refine_bundle_authenticated(
            &no_commitment,
            refine_program_id(&outer),
            refine_arguments_commitment(&arguments),
            gas,
            &trusted_programs,
        )
        .is_err()
    );

    assert_replay_mismatch(&bundle, &outer, &arguments, gas + 1, "arguments/gas");
    let mut divergent_arguments = arguments.clone();
    divergent_arguments[0] ^= 1;
    assert_replay_mismatch(&bundle, &outer, &divergent_arguments, gas, "arguments/gas");
    assert!(
        verify_refine_bundle_authenticated(
            &bundle,
            refine_program_id(&arguments),
            refine_arguments_commitment(&arguments),
            gas,
            &trusted_programs,
        )
        .is_err()
    );
}
