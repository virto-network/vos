//! Physical generic-service PVM integration gate.
//!
//! Build the service and actor guests first with:
//! `just build-v2-pvm-test-artifacts`.
//!
//! Missing guests are hard failures: these tests are a consensus-path gate,
//! not optional smoke tests.

use std::path::PathBuf;
use vos::v2::{
    AccumulateRequestV2, AccumulationEnvelopeV2, AccumulationResultV2, ActorGenesisV2, ActorId,
    ActorWriteV2, AuthorizationEvidenceV2, BlobRefV2, ConsistencyBaseV2, ConsistencyModeV2,
    DeploymentId, GasAccountingV2, Hash, ImportedActorV2, ImportedBlobV2, ImportedProgramV2,
    InvocationId, JamServiceV2, LocalJamStoreV2, MethodPolicyV2, NoRefineProtocolHostV2, Origin,
    ProgramId, PublishedEffectsV2, RefineImportsV2, RefineOutputV2, ReplyRecordV2, RootServiceId,
    ServiceGenesisV2, ServiceIdentityV2, ServicePvmErrorV2, ServicePvmV2, TransitionV2, V2Wire,
    WorkEnvelopeV2,
};
use vos::{Decode, Encode, value::Msg};

const CANONICAL_SERVICE_PVM: &[u8] = include_bytes!("../../services/vos-service/vos-service.pvm");
const SERVICE_BUILD_CONFIG: &str = include_str!("../../services/vos-service/.cargo/config.toml");
const SERVICE_RUSTC_WRAPPER: &str = include_str!("../../services/vos-service/rustc-remap.sh");

fn required_elf(relative_path: &str, build_command: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "required guest ELF is unavailable at {}: {error}\nbuild it with `{build_command}`",
            path.display()
        )
    })
}

#[test]
#[should_panic(expected = "required guest ELF is unavailable")]
fn missing_required_guest_is_a_hard_failure() {
    required_elf(
        "tests/fixtures/definitely-missing-v2-guest.elf",
        "just build-v2-pvm-test-artifacts",
    );
}

fn service_elf() -> Vec<u8> {
    required_elf(
        "../services/vos-service/target/riscv64em-javm/release/vos_service.elf",
        "just build-v2-pvm-test-artifacts",
    )
}

#[test]
fn canonical_service_artifact_has_the_protocol_identity() {
    assert_eq!(
        ProgramId::of_pvm(CANONICAL_SERVICE_PVM),
        vos::v2::VOS_SERVICE_PROGRAM_ID
    );
    ServicePvmV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
    )
    .expect("committed service PVM has the canonical Refine/Accumulate entries");
}

#[test]
fn canonical_service_artifact_matches_a_fresh_build() {
    let elf = service_elf();
    let fresh = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    assert!(
        fresh == CANONICAL_SERVICE_PVM,
        "fresh vos-service build differs: fresh ProgramId {:?}, committed ProgramId {:?}",
        ProgramId::of_pvm(&fresh),
        ProgramId::of_pvm(CANONICAL_SERVICE_PVM)
    );
}

#[test]
fn canonical_service_build_pins_path_independent_crate_identity() {
    assert!(SERVICE_BUILD_CONFIG.contains("rustc-wrapper = \"./rustc-remap.sh\""));
    assert!(SERVICE_BUILD_CONFIG.contains("-Zremap-cwd-prefix=."));
    assert!(SERVICE_RUSTC_WRAPPER.contains("-Cmetadata=vos-service-v2"));
    assert!(SERVICE_RUSTC_WRAPPER.contains("--remap-path-prefix=$repository_root=vos-source"));
}

fn greeter_elf() -> Vec<u8> {
    required_elf(
        "../examples/actors/greeter/target/riscv64em-javm/release/greeter.elf",
        "just build-v2-pvm-test-artifacts",
    )
}

fn probe_elf() -> Vec<u8> {
    required_elf(
        "../examples/actors/probe/target/riscv64em-javm/release/probe.elf",
        "just build-v2-pvm-test-artifacts",
    )
}

fn crdt_counter_v2_elf() -> Vec<u8> {
    required_elf(
        "tests/fixtures/crdt-counter-v2/target/riscv64em-javm/release/crdt_counter_v2_fixture.elf",
        "just build-v2-pvm-test-artifacts",
    )
}

fn actor_pvm(result: u64) -> Vec<u8> {
    let mut assembler = grey_transpiler::assembler::Assembler::new();
    assembler
        .load_imm_64(grey_transpiler::assembler::Reg::A0, result)
        .ecalli(0);
    assembler.build()
}

fn work(actor_program: ProgramId, state: BlobRefV2) -> WorkEnvelopeV2 {
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("start").encode());
    WorkEnvelopeV2 {
        service: ServiceIdentityV2 {
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: ProgramId([3; 32]),
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        },
        invocation: InvocationId([4; 32]),
        workflow_step: 0,
        target: ActorId([5; 32]),
        target_program: actor_program,
        method: "start".into(),
        arguments: message,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        consistency: ConsistencyModeV2::Local,
        base: ConsistencyBaseV2::Linear {
            revision: 0,
            state_root: Hash([8; 32]),
        },
        base_causal_height: None,
        imported_actors: vec![ImportedActorV2 {
            actor: ActorId([5; 32]),
            program: actor_program,
            state,
            causal_states: vec![],
            continuation: None,
        }],
        imported_blobs: vec![],
        proof_requested: false,
    }
}

#[test]
fn canonical_guest_refine_runs_at_ic0_and_returns_nested_transition() {
    let elf = service_elf();
    let actor_elf = greeter_elf();
    let pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvmV2::new(pvm.clone(), ProgramId::of_pvm(&pvm))
        .expect("generic service has the GP IC0/IC5 entries");
    let actor = grey_transpiler::link_elf(&actor_elf).expect("canonical actor ELF transpiles");
    let actor_program = ProgramId::of_pvm(&actor);
    let state_bytes = Vec::new();
    let state = BlobRefV2::of_bytes(&state_bytes);
    let work = work(actor_program, state.clone());
    let imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor,
        }],
        blobs: vec![ImportedBlobV2 {
            reference: state,
            bytes: state_bytes,
        }],
    };

    let output = service
        .refine_actor_tree(
            &work.encode(),
            &imports,
            10_000_000,
            &NoRefineProtocolHostV2,
        )
        .expect("generic Refine completes");
    let transition = RefineOutputV2::decode(&output.bytes)
        .expect("Refine returns RefineOutputV2")
        .transition;
    assert_eq!(transition.service, work.service);
    assert_eq!(transition.consumed_input, work.input_id());
    assert_eq!(transition.target_program, work.target_program);
    assert_eq!(transition.base, work.base);
    assert_eq!(transition.writes.len(), 1);
    assert_eq!(transition.writes[0].actor, work.target);
    assert_eq!(transition.writes[0].key, vos::lifecycle::STATE_KEY_BYTES);
    assert!(
        transition.writes[0]
            .value
            .as_ref()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(
        transition.reply.as_ref().map(|reply| reply.call_id),
        Some(work.invocation.root_reply_id())
    );
}

#[test]
fn nested_actor_input_is_bounded_before_entering_the_compact_guest_heap() {
    let actor_elf = greeter_elf();
    let actor = grey_transpiler::link_elf(&actor_elf).expect("canonical actor ELF transpiles");
    let actor_program = ProgramId::of_pvm(&actor);
    let state_bytes = vec![0; vos::v2::ACTOR_SLICE_INPUT_MAX_BYTES];
    let state = BlobRefV2::of_bytes(&state_bytes);
    let work = work(actor_program, state.clone());
    let imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor,
        }],
        blobs: vec![ImportedBlobV2 {
            reference: state,
            bytes: state_bytes,
        }],
    };
    let service = ServicePvmV2::new(
        CANONICAL_SERVICE_PVM.to_vec(),
        vos::v2::VOS_SERVICE_PROGRAM_ID,
    )
    .expect("canonical service program");

    assert_eq!(
        service.refine_actor_tree(
            &work.encode(),
            &imports,
            10_000_000,
            &NoRefineProtocolHostV2,
        ),
        Err(ServicePvmErrorV2::ActorInputTooLarge)
    );
}

#[test]
fn canonical_crdt_slice_refines_and_accumulates_without_native_apply() {
    let service_elf = service_elf();
    let actor_elf = crdt_counter_v2_elf();
    let service_pvm = vos::v2::transpile_service_elf(&service_elf).unwrap();
    let actor_pvm = grey_transpiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let mut work = work(actor_program, initial.clone());
    work.method = "increment".into();
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("increment").with("amount", 2u64).encode());
    work.arguments = message;
    work.consistency = ConsistencyModeV2::Crdt;
    work.base = ConsistencyBaseV2::Crdt { heads: vec![] };
    work.base_causal_height = Some(0);

    let imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor_pvm.clone(),
        }],
        blobs: vec![ImportedBlobV2 {
            reference: initial.clone(),
            bytes: initial_bytes.clone(),
        }],
    };
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
    let mut service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        host,
        1_000_000_000,
        1_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        service: work.service.clone(),
        consistency: ConsistencyModeV2::Crdt,
        actors: vec![ActorGenesisV2 {
            actor: work.target,
            parent: None,
            program: actor_program,
            initial_state: initial.clone(),
            crdt: true,
            methods: vec![MethodPolicyV2 {
                method: "increment".into(),
                schema: Hash([44; 32]),
                policy: Hash([45; 32]),
                public: true,
                attested: false,
            }],
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([46; 32]),
            authenticator: vec![1],
        },
    });
    assert!(matches!(
        service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Installed(_)
    ));

    let refined = service.refine_actor_tree(&work, &imports).unwrap();
    assert!(refined.transition.writes.is_empty());
    let change = refined.transition.crdt_change.as_ref().unwrap();
    assert_eq!(change.causal_height, 1);
    assert_eq!(change.operations.len(), 1);
    assert_eq!(change.materializations.len(), 1);
    assert_eq!(refined.exported_blobs.len(), 1);
    assert_eq!(
        refined.exported_blobs[0].reference,
        change.materializations[0].state
    );
    let cid = change.cid();
    let apply = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
        work: work.clone(),
        transition: refined.transition.clone(),
        provided_blobs: refined.exported_blobs.clone(),
    });
    let applied = service.accumulate(&apply).unwrap().result;
    let AccumulationResultV2::Accepted {
        receipt,
        published,
        duplicate,
    } = applied
    else {
        panic!("CRDT transition rejected")
    };
    assert!(!duplicate);
    assert_eq!(receipt.resulting_crdt_heads, vec![cid]);
    assert!(published.reply.is_some());
    assert!(
        service
            .accumulate_host()
            .blob(&refined.exported_blobs[0].reference)
            .is_some()
    );

    let duplicate = service.accumulate(&apply).unwrap().result;
    let AccumulationResultV2::Accepted {
        published,
        duplicate,
        ..
    } = duplicate
    else {
        panic!("CRDT retry rejected")
    };
    assert!(duplicate);
    assert_eq!(published, PublishedEffectsV2::default());

    // Refine a concurrent sibling from the same empty causal base after the
    // first branch has committed. CRDT Accumulate preserves both heads.
    let mut right_work = work.clone();
    right_work.invocation = InvocationId([47; 32]);
    let mut right_message = vec![vos::value::TAG_DYNAMIC];
    right_message.extend_from_slice(&Msg::new("increment").with("amount", 3u64).encode());
    right_work.arguments = right_message;
    let right_refined = service.refine_actor_tree(&right_work, &imports).unwrap();
    let right_cid = right_refined.transition.crdt_change.as_ref().unwrap().cid();
    let right = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: right_work,
            transition: right_refined.transition.clone(),
            provided_blobs: right_refined.exported_blobs.clone(),
        }))
        .unwrap()
        .result;
    let AccumulationResultV2::Accepted { receipt, .. } = right else {
        panic!("concurrent CRDT branch rejected")
    };
    let mut heads = vec![cid, right_cid];
    heads.sort();
    assert_eq!(receipt.resulting_crdt_heads, heads);

    // Supply the exact frontier materializations in content order. The
    // generated actor merger folds both counters before the handler observes
    // state, so 2 + 3 + 4 is returned and materialized as one causal child.
    let mut frontier = vec![
        refined.exported_blobs[0].clone(),
        right_refined.exported_blobs[0].clone(),
    ];
    frontier.sort_by_key(|blob| blob.reference.hash);
    let mut merge_work = work;
    merge_work.invocation = InvocationId([48; 32]);
    merge_work.base = ConsistencyBaseV2::Crdt {
        heads: heads.clone(),
    };
    merge_work.base_causal_height = Some(1);
    merge_work.imported_actors[0].state = frontier[0].reference.clone();
    merge_work.imported_actors[0].causal_states = frontier[1..]
        .iter()
        .map(|blob| blob.reference.clone())
        .collect();
    let mut merge_message = vec![vos::value::TAG_DYNAMIC];
    merge_message.extend_from_slice(&Msg::new("increment").with("amount", 4u64).encode());
    merge_work.arguments = merge_message;
    let merge_imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor_pvm,
        }],
        blobs: frontier,
    };
    let merged = service
        .refine_actor_tree(&merge_work, &merge_imports)
        .unwrap();
    let reply = merged.transition.reply.as_ref().unwrap();
    assert_eq!(vos::value::Value::decode(&reply.result).as_i64(), Some(9));
    let merged_cid = merged.transition.crdt_change.as_ref().unwrap().cid();
    let accepted = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: merge_work,
            transition: merged.transition,
            provided_blobs: merged.exported_blobs,
        }))
        .unwrap()
        .result;
    let AccumulationResultV2::Accepted { receipt, .. } = accepted else {
        panic!("merged CRDT child rejected")
    };
    assert_eq!(receipt.resulting_crdt_heads, vec![merged_cid]);
}

#[test]
fn canonical_crdt_resume_rebinds_the_post_await_change_identity() {
    let service_elf = service_elf();
    let actor_elf = crdt_counter_v2_elf();
    let service_pvm = vos::v2::transpile_service_elf(&service_elf).unwrap();
    let actor_pvm = grey_transpiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let mut first_work = work(actor_program, initial.clone());
    first_work.invocation = InvocationId([49; 32]);
    first_work.method = "increment_around_yield".into();
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(
        &Msg::new("increment_around_yield")
            .with("amount", 2u64)
            .encode(),
    );
    first_work.arguments = message;
    first_work.consistency = ConsistencyModeV2::Crdt;
    first_work.base = ConsistencyBaseV2::Crdt { heads: vec![] };
    first_work.base_causal_height = Some(0);

    let first_imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor_pvm.clone(),
        }],
        blobs: vec![ImportedBlobV2 {
            reference: initial.clone(),
            bytes: initial_bytes.clone(),
        }],
    };
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
    let mut service = JamServiceV2::new(
        service_pvm.clone(),
        ProgramId::of_pvm(&service_pvm),
        NoRefineProtocolHostV2,
        host,
        1_000_000_000,
        1_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        service: first_work.service.clone(),
        consistency: ConsistencyModeV2::Crdt,
        actors: vec![ActorGenesisV2 {
            actor: first_work.target,
            parent: None,
            program: actor_program,
            initial_state: initial,
            crdt: true,
            methods: vec![MethodPolicyV2 {
                method: "increment_around_yield".into(),
                schema: Hash([50; 32]),
                policy: Hash([51; 32]),
                public: true,
                attested: false,
            }],
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([52; 32]),
            authenticator: vec![1],
        },
    });
    assert!(matches!(
        service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Installed(_)
    ));

    let first = service
        .refine_actor_tree(&first_work, &first_imports)
        .unwrap();
    assert!(first.transition.reply.is_none());
    let first_change = first.transition.crdt_change.as_ref().unwrap();
    assert_eq!(first_change.operations.len(), 1);
    assert_eq!(first_change.operations[0].ordinal, 0);
    let first_change_id = first_change.id;
    let first_cid = first_change.cid();
    let state = first_change.materializations[0].state.clone();
    let continuation = first.transition.continuations[0]
        .replacement
        .clone()
        .expect("first slice publishes a continuation");
    let first_result = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: first_work.clone(),
            transition: first.transition,
            provided_blobs: first.exported_blobs.clone(),
        }))
        .unwrap()
        .result;
    assert!(matches!(
        first_result,
        AccumulationResultV2::Accepted {
            duplicate: false,
            ..
        }
    ));

    let mut second_work = first_work;
    second_work.workflow_step = 1;
    second_work.base = ConsistencyBaseV2::Crdt {
        heads: vec![first_cid],
    };
    second_work.base_causal_height = Some(1);
    second_work.imported_actors[0].state = state;
    second_work.imported_actors[0].continuation = Some(continuation);
    let second_imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor_pvm,
        }],
        blobs: first.exported_blobs,
    };
    let second = service
        .refine_actor_tree(&second_work, &second_imports)
        .unwrap();
    let second_change = second.transition.crdt_change.as_ref().unwrap();
    assert_ne!(second_change.id, first_change_id);
    assert_eq!(second_change.operations.len(), 1);
    assert_eq!(
        second_change.operations[0].id,
        second_change.id.operation(
            second_work.target,
            second_change.operations[0].dispatch_ordinal,
            second_change.operations[0].field,
            0,
        )
    );
    assert_eq!(
        second
            .transition
            .reply
            .as_ref()
            .and_then(|reply| vos::value::Value::decode(&reply.result).as_i64()),
        Some(4)
    );
    assert_eq!(
        second.transition.continuations[0].replacement, None,
        "the resumed slice consumes its durable continuation"
    );
    let second_cid = second_change.cid();
    let accepted = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: second_work,
            transition: second.transition,
            provided_blobs: second.exported_blobs,
        }))
        .unwrap()
        .result;
    let AccumulationResultV2::Accepted { receipt, .. } = accepted else {
        panic!("resumed CRDT slice rejected")
    };
    assert_eq!(receipt.resulting_crdt_heads, vec![second_cid]);
}

#[test]
fn canonical_guest_rejects_a_nested_actor_without_the_reply_abi() {
    let elf = service_elf();
    let pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvmV2::new(pvm.clone(), ProgramId::of_pvm(&pvm)).unwrap();
    let actor = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor);
    let state_bytes = Vec::new();
    let state = BlobRefV2::of_bytes(&state_bytes);
    let work = work(actor_program, state.clone());
    let imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor,
        }],
        blobs: vec![ImportedBlobV2 {
            reference: state,
            bytes: state_bytes,
        }],
    };

    assert_eq!(
        service.refine_actor_tree(
            &work.encode(),
            &imports,
            10_000_000,
            &NoRefineProtocolHostV2,
        ),
        Err(ServicePvmErrorV2::Panic)
    );
}

#[test]
fn actor_tree_refuses_to_replay_a_continuation_from_pc_zero() {
    let elf = service_elf();
    let pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvmV2::new(pvm.clone(), ProgramId::of_pvm(&pvm)).unwrap();
    let actor = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor);
    let state_bytes = Vec::new();
    let state = BlobRefV2::of_bytes(&state_bytes);
    let continuation_bytes = b"portable-kernel-snapshot".to_vec();
    let continuation = BlobRefV2::of_bytes(&continuation_bytes);
    let mut work = work(actor_program, state.clone());
    work.imported_actors[0].continuation = Some(continuation.clone());
    let mut blobs = vec![
        ImportedBlobV2 {
            reference: state,
            bytes: state_bytes,
        },
        ImportedBlobV2 {
            reference: continuation,
            bytes: continuation_bytes,
        },
    ];
    blobs.sort_by_key(|blob| blob.reference.hash);
    let imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor,
        }],
        blobs,
    };

    assert_eq!(
        service.refine_actor_tree(
            &work.encode(),
            &imports,
            10_000_000,
            &NoRefineProtocolHostV2,
        ),
        Err(ServicePvmErrorV2::InvalidContinuation)
    );
}

#[test]
fn yielding_actor_restores_exactly_after_restart() {
    let service_elf = service_elf();
    let actor_elf = probe_elf();
    let service_pvm = vos::v2::transpile_service_elf(&service_elf).unwrap();
    let service_program = ProgramId::of_pvm(&service_pvm);
    let service = ServicePvmV2::new(service_pvm.clone(), service_program).unwrap();
    let actor = grey_transpiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRefV2::of_bytes(&initial_state);
    let mut first_work = work(actor_program, initial_state_ref.clone());
    let mut ping = vec![vos::value::TAG_DYNAMIC];
    ping.extend_from_slice(&Msg::new("ping").encode());
    first_work.method = "ping".into();
    first_work.arguments = ping;
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_state.clone()), initial_state_ref);
    assert_eq!(host.import_program(actor.clone()), actor_program);
    let mut committed = JamServiceV2::new(
        service_pvm,
        service_program,
        NoRefineProtocolHostV2,
        host,
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        service: first_work.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: first_work.target,
            parent: None,
            program: actor_program,
            initial_state: initial_state_ref.clone(),
            crdt: false,
            methods: vec![MethodPolicyV2 {
                method: "ping".into(),
                schema: Hash([32; 32]),
                policy: Hash([33; 32]),
                public: true,
                attested: false,
            }],
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([34; 32]),
            authenticator: vec![35],
        },
    });
    let installed = committed.accumulate(&install).unwrap();
    let AccumulationResultV2::Installed(installed) = installed.result else {
        panic!("guest install rejected")
    };
    first_work.base = ConsistencyBaseV2::Linear {
        revision: 0,
        state_root: installed.resulting_state_root.unwrap(),
    };
    let first_imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor.clone(),
        }],
        blobs: vec![ImportedBlobV2 {
            reference: initial_state_ref,
            bytes: initial_state,
        }],
    };

    let first_output = service
        .refine_actor_tree_with_backend(
            &first_work.encode(),
            &first_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    let deterministic_retry = service
        .refine_actor_tree_with_backend(
            &first_work.encode(),
            &first_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    assert_eq!(
        deterministic_retry, first_output,
        "checkpoint bytes and transition must be deterministic"
    );
    let recompiled_first = service
        .refine_actor_tree_with_backend(
            &first_work.encode(),
            &first_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceRecompiler,
        )
        .unwrap();
    assert_eq!(
        recompiled_first, first_output,
        "interpreter and recompiler checkpoints must be identical"
    );
    let refined_first = RefineOutputV2::decode(&first_output.bytes).unwrap();
    let first = refined_first.transition;
    let mut first_candidate_blobs = refined_first.candidate_blobs;
    first_candidate_blobs.extend(first_output.exported_blobs.clone());
    first_candidate_blobs.sort_by_key(|blob| blob.reference.hash);
    first_candidate_blobs.dedup();
    assert!(first.reply.is_none(), "yield must not publish a reply");
    assert_eq!(first.continuations.len(), 1);
    let first_continuation = first.continuations[0].replacement.clone().unwrap();
    assert_eq!(first.exported_blobs, vec![first_continuation.clone()]);
    assert_eq!(first_output.exported_blobs.len(), 1);
    assert_eq!(first_output.exported_blobs[0].reference, first_continuation);
    let checkpoint_state = first
        .writes
        .iter()
        .find(|write| write.key == vos::lifecycle::STATE_KEY_BYTES)
        .and_then(|write| write.value.clone())
        .expect("checkpoint commits the mutation before await");
    assert_eq!(u32::decode(&checkpoint_state), 1);
    let checkpoint_outcome = committed
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: first_work.clone(),
            transition: first.clone(),
            provided_blobs: first_candidate_blobs,
        }))
        .unwrap();
    let AccumulationResultV2::Accepted {
        receipt: checkpoint_receipt,
        published,
        duplicate,
    } = checkpoint_outcome.result
    else {
        panic!("guest rejected the transition emitted by its own Refine entry")
    };
    assert!(!duplicate);
    assert!(published.reply.is_none());
    let checkpoint_state_ref = BlobRefV2::of_bytes(&checkpoint_state);
    assert_eq!(
        committed.accumulate_host().blob(&checkpoint_state_ref),
        Some(checkpoint_state.as_slice()),
        "guest Accumulate must durably record the checkpoint state"
    );

    // Simulate a process restart after Accumulate committed slice 0. Only
    // canonical programs, the committed state, and the continuation blob are
    // supplied to the next Refine invocation.
    let mut resumed_work = first_work.clone();
    resumed_work.workflow_step = 1;
    resumed_work.base = ConsistencyBaseV2::Linear {
        revision: checkpoint_receipt.sequence,
        state_root: checkpoint_receipt.resulting_state_root.unwrap(),
    };
    resumed_work.imported_actors[0].state = checkpoint_state_ref.clone();
    resumed_work.imported_actors[0].continuation = Some(first_continuation.clone());
    let mut resumed_blobs = vec![
        ImportedBlobV2 {
            reference: checkpoint_state_ref,
            bytes: checkpoint_state,
        },
        first_output.exported_blobs[0].clone(),
    ];
    resumed_blobs.sort_by_key(|blob| blob.reference.hash);
    let resumed_imports = RefineImportsV2 {
        programs: vec![ImportedProgramV2 {
            program: actor_program,
            pvm: actor,
        }],
        blobs: resumed_blobs,
    };

    let resumed_output = service
        .refine_actor_tree_with_backend(
            &resumed_work.encode(),
            &resumed_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    let recompiled_resumed = service
        .refine_actor_tree_with_backend(
            &resumed_work.encode(),
            &resumed_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceRecompiler,
        )
        .unwrap();
    assert_eq!(
        recompiled_resumed, resumed_output,
        "interpreter and recompiler resumes must be identical"
    );
    let refined_resumed = RefineOutputV2::decode(&resumed_output.bytes).unwrap();
    let resumed = refined_resumed.transition;
    let mut resumed_candidate_blobs = refined_resumed.candidate_blobs;
    resumed_candidate_blobs.extend(resumed_output.exported_blobs.clone());
    resumed_candidate_blobs.sort_by_key(|blob| blob.reference.hash);
    resumed_candidate_blobs.dedup();
    assert!(
        resumed.reply.is_some(),
        "handler completes after exact resume"
    );
    assert_eq!(resumed.consumed_input, resumed_work.input_id());
    assert_eq!(resumed.base, resumed_work.base);
    assert_eq!(resumed.continuations.len(), 1);
    assert_eq!(
        resumed.continuations[0].expected,
        Some(first_continuation.hash)
    );
    assert_eq!(resumed.continuations[0].replacement, None);
    assert!(resumed_output.exported_blobs.is_empty());
    let resumed_state = resumed
        .writes
        .iter()
        .find(|write| write.key == vos::lifecycle::STATE_KEY_BYTES)
        .and_then(|write| write.value.as_ref())
        .expect("resumed actor reports its retained state");
    assert_eq!(
        u32::decode(resumed_state),
        1,
        "code before .await must not execute again"
    );
    let committed_before_resume = committed.accumulate_host().snapshot();
    let completed = committed
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: resumed_work,
            transition: resumed.clone(),
            provided_blobs: resumed_candidate_blobs,
        }))
        .unwrap();
    let AccumulationResultV2::Accepted {
        receipt,
        published,
        duplicate,
    } = completed.result
    else {
        panic!("guest rejected its own resumed transition")
    };
    assert!(!duplicate);
    assert_eq!(receipt.sequence, checkpoint_receipt.sequence + 1);
    assert_eq!(published.reply, resumed.reply);
    assert!(
        !committed
            .accumulate_host()
            .snapshot()
            .same_service_state(&committed_before_resume)
    );
    let resumed_state_ref = BlobRefV2::of_bytes(resumed_state);
    assert_eq!(
        committed.accumulate_host().blob(&resumed_state_ref),
        Some(resumed_state.as_slice())
    );
}

#[test]
fn canonical_guest_accumulate_installs_applies_and_deduplicates_at_ic5() {
    let elf = service_elf();
    let pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = b"canonical actor bytes".to_vec();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"initial actor state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed_work = work(actor_program, initial.clone());
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = JamServiceV2::new(
        pvm.clone(),
        ProgramId::of_pvm(&pvm),
        NoRefineProtocolHostV2,
        host,
        100_000_000,
        5_000_000_000,
    )
    .unwrap();

    let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
        service: seed_work.service.clone(),
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed_work.target,
            parent: None,
            program: actor_program,
            initial_state: initial.clone(),
            crdt: false,
            methods: vec![MethodPolicyV2 {
                method: "start".into(),
                schema: Hash([32; 32]),
                policy: Hash([33; 32]),
                public: true,
                attested: false,
            }],
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([34; 32]),
            authenticator: vec![35],
        },
    });
    let installed_output = service
        .accumulate(&install)
        .expect("guest install completes");
    let AccumulationResultV2::Installed(installed) = installed_output.result else {
        panic!("guest install rejected")
    };
    assert_eq!(service.accumulate_host().commit_sequence(), 1);
    let installed_rows = service.accumulate_host().row_count();

    let mut work = seed_work;
    work.base = ConsistencyBaseV2::Linear {
        revision: 0,
        state_root: installed.resulting_state_root.unwrap(),
    };
    let transition = TransitionV2 {
        service: work.service.clone(),
        consumed_input: work.input_id(),
        target_program: work.target_program,
        base: work.base.clone(),
        writes: vec![ActorWriteV2 {
            actor: work.target,
            key: vos::lifecycle::STATE_KEY_BYTES.to_vec(),
            value: Some(b"committed actor state".to_vec()),
        }],
        crdt_change: None,
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(ReplyRecordV2 {
            call_id: work.invocation.root_reply_id(),
            producer: work.target,
            result: b"committed reply".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let apply = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
        work,
        transition: transition.clone(),
        provided_blobs: vec![],
    });
    let applied_output = service.accumulate(&apply).expect("guest apply completes");
    let AccumulationResultV2::Accepted {
        receipt,
        published,
        duplicate,
    } = applied_output.result
    else {
        panic!("guest apply rejected")
    };
    assert!(!duplicate);
    assert_eq!(receipt.sequence, 1);
    assert_eq!(published.reply, transition.reply);
    assert!(service.accumulate_host().row_count() > installed_rows);
    assert_eq!(service.accumulate_host().commit_sequence(), 2);
    let committed_state = BlobRefV2::of_bytes(b"committed actor state");
    assert_eq!(
        service.accumulate_host().blob(&committed_state),
        Some(b"committed actor state".as_slice())
    );

    let snapshot_after_apply = service.accumulate_host().snapshot();
    let duplicate_output = service.accumulate(&apply).expect("guest retry completes");
    let AccumulationResultV2::Accepted {
        published,
        duplicate,
        ..
    } = duplicate_output.result
    else {
        panic!("guest retry rejected")
    };
    assert!(duplicate);
    assert_eq!(published, PublishedEffectsV2::default());
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&snapshot_after_apply)
    );
    assert_eq!(
        service.accumulate_host().commit_sequence(),
        2,
        "a read-only duplicate transaction must not commit"
    );
}

#[test]
fn physical_guest_install_rejects_an_unavailable_actor_program() {
    let elf = service_elf();
    let pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_program = ProgramId::of_pvm(b"canonical actor bytes not imported into the service");
    let initial_bytes = b"initial actor state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed_work = work(actor_program, initial.clone());
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    let mut service = JamServiceV2::new(
        pvm.clone(),
        ProgramId::of_pvm(&pvm),
        NoRefineProtocolHostV2,
        host,
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let genesis = ServiceGenesisV2 {
        service: seed_work.service,
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed_work.target,
            parent: None,
            program: actor_program,
            initial_state: initial,
            crdt: false,
            methods: vec![MethodPolicyV2 {
                method: "start".into(),
                schema: Hash([32; 32]),
                policy: Hash([33; 32]),
                public: true,
                attested: false,
            }],
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([34; 32]),
            authenticator: vec![35],
        },
    };

    assert_eq!(
        service
            .accumulate(&AccumulateRequestV2::Install(genesis))
            .unwrap()
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::WrongProgram)
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 0);
    assert_eq!(service.accumulate_host().row_count(), 0);
}

#[test]
fn physical_guest_rejects_the_missing_preimage_length_sentinel() {
    let elf = service_elf();
    let pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = b"available canonical actor bytes".to_vec();
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let seed_work = work(
        actor_program,
        BlobRefV2 {
            hash: Hash([30; 32]),
            len: u64::MAX,
        },
    );
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_program(actor_pvm), actor_program);
    let mut service = JamServiceV2::new(
        pvm.clone(),
        ProgramId::of_pvm(&pvm),
        NoRefineProtocolHostV2,
        host,
        100_000_000,
        5_000_000_000,
    )
    .unwrap();
    let genesis = ServiceGenesisV2 {
        service: seed_work.service,
        consistency: ConsistencyModeV2::Local,
        actors: vec![ActorGenesisV2 {
            actor: seed_work.target,
            parent: None,
            program: actor_program,
            initial_state: seed_work.imported_actors[0].state.clone(),
            crdt: false,
            methods: vec![],
        }],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([31; 32]),
            authenticator: vec![32],
        },
    };

    assert_eq!(
        service
            .accumulate(&AccumulateRequestV2::Install(genesis))
            .unwrap()
            .result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::NonCanonical)
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 0);
    assert_eq!(service.accumulate_host().row_count(), 0);
    assert_eq!(service.accumulate_host().blob_count(), 0);
}

#[test]
fn malformed_guest_accumulate_returns_a_rejection_without_storage_effects() {
    let elf = service_elf();
    let pvm = vos::v2::transpile_service_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvmV2::new(pvm.clone(), ProgramId::of_pvm(&pvm)).unwrap();
    let mut host = LocalJamStoreV2::default();

    let output = service
        .accumulate(b"not a v2 request", 10_000_000, &mut host)
        .unwrap();
    assert_eq!(
        AccumulationResultV2::decode(&output.bytes).unwrap(),
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::NonCanonical)
    );
    assert_eq!(host.row_count(), 0);
    assert_eq!(host.blob_count(), 0);
}
