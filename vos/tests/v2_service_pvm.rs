//! Physical generic-service PVM integration gate.
//!
//! Build the guest first with:
//! `cd services/vos-service && cargo +nightly actor`.

use std::path::PathBuf;
use vos::attestation::AttestationStatementV3;
use vos::v2::{
    AccumulateRequestV2, AccumulatedReplyV2, AccumulationEnvelopeV2, AccumulationReceiptV2,
    AccumulationResultV2, ActorGenesisV2, ActorId, ActorWriteV2, AllowPublic,
    AuthorizationEvidenceV2, BlobRefV2, ConsistencyBaseV2, ConsistencyModeV2, ContinuationChangeV2,
    ContinuationSnapshotV2, DeploymentId, GasAccountingV2, Hash, ImportedActorV2, ImportedBlobV2,
    ImportedProgramV2, InMemoryServiceState, InvocationId, JamServiceV2, LocalJamStoreV2,
    LocalWorkRequestV2, LocalWorkSchedulerV2, MessageRecordV2, MethodPolicyV2,
    NoRefineProtocolHostV2, Origin, ProgramId, ProofCommitmentV2, ProofVerificationRequestV2,
    PublishedEffectsV2, RefineImportsV2, RefineOutputV2, ReplyRecordV2, RootServiceId,
    ScheduleErrorV2, ServiceGenesisV2, ServiceIdentityV2, ServicePvmErrorV2, ServicePvmV2,
    SubjectId, TransitionV2, V2Wire, WorkEnvelopeV2,
};
use vos::{Decode, Encode, value::Msg};

fn service_elf() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../services/vos-service/target/riscv64em-javm/release/vos_service.elf");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: build the generic guest first with `cd services/vos-service && cargo +nightly actor` ({})",
                path.display()
            );
            None
        }
    }
}

fn greeter_elf() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/actors/greeter/target/riscv64em-javm/release/greeter.elf");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: build the actor first with `cd examples/actors/greeter && cargo +nightly actor` ({})",
                path.display()
            );
            None
        }
    }
}

fn probe_elf() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/actors/probe/target/riscv64em-javm/release/probe.elf");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: build the actor first with `cd examples/actors/probe && cargo +nightly actor` ({})",
                path.display()
            );
            None
        }
    }
}

fn crdt_counter_v2_elf() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "tests/fixtures/crdt-counter-v2/target/riscv64em-javm/release/crdt_counter_v2_fixture.elf",
    );
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: build the v2 CRDT fixture with `cd vos/tests/fixtures/crdt-counter-v2 && cargo +nightly actor` ({})",
                path.display()
            );
            None
        }
    }
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
            space: vos::v2::SpaceId([0; 32]),
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: ProgramId([3; 32]),
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        },
        invocation: InvocationId([4; 32]),
        workflow_step: 0,
        logical_timeslot: 1,
        target: ActorId([5; 32]),
        target_program: actor_program,
        method: "start".into(),
        arguments: message,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        awaited_reply: None,
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
    let Some(elf) = service_elf() else {
        return;
    };
    let Some(actor_elf) = greeter_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
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
fn canonical_crdt_slice_refines_and_accumulates_without_native_apply() {
    let (Some(service_elf), Some(actor_elf)) = (service_elf(), crdt_counter_v2_elf()) else {
        return;
    };
    let service_pvm = grey_transpiler::link_elf(&service_elf).unwrap();
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

    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm), actor_program);
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
            name: "counter".into(),
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
    let AccumulateRequestV2::Install(genesis) = &install else {
        unreachable!()
    };
    service.accumulate_host_mut().allow_install(genesis);
    assert!(matches!(
        service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Installed(_)
    ));

    let scheduled = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: work.invocation,
            workflow_step: 0,
            logical_timeslot: work.logical_timeslot,
            target: work.target,
            method: work.method.clone(),
            arguments: work.arguments.clone(),
            origin: work.origin,
            authorization: work.authorization.clone(),
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .expect("scheduler imports the empty CRDT frontier");
    assert_eq!(scheduled.work, work);
    let imports = scheduled.imports;

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

    // The scheduler walks both complete branches and imports the exact
    // materialization frontier. The generated actor merger folds both counters
    // before the handler observes state, so 2 + 3 + 4 becomes 9.
    let mut merge_message = vec![vos::value::TAG_DYNAMIC];
    merge_message.extend_from_slice(&Msg::new("increment").with("amount", 4u64).encode());
    let merge = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([48; 32]),
            workflow_step: 0,
            logical_timeslot: work.logical_timeslot,
            target: work.target,
            method: work.method.clone(),
            arguments: merge_message,
            origin: work.origin,
            authorization: work.authorization.clone(),
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
            imported_blobs: vec![],
            proof_requested: false,
        },
    )
    .expect("scheduler imports both concurrent CRDT heads");
    let merge_work = merge.work;
    let merge_imports = merge.imports;
    assert_eq!(merge_work.base, ConsistencyBaseV2::Crdt { heads });
    assert_eq!(merge_work.base_causal_height, Some(1));
    assert_eq!(merge_work.imported_actors[0].causal_states.len(), 1);
    assert_eq!(merge_imports.blobs.len(), 2);
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
fn canonical_guest_rejects_a_nested_actor_without_the_reply_abi() {
    let Some(elf) = service_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
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
    let Some(elf) = service_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
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
    let (Some(service_elf), Some(actor_elf)) = (service_elf(), probe_elf()) else {
        return;
    };
    let service_pvm = grey_transpiler::link_elf(&service_elf).unwrap();
    let service = ServicePvmV2::new(service_pvm.clone(), ProgramId::of_pvm(&service_pvm)).unwrap();
    let actor = grey_transpiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRefV2::of_bytes(&initial_state);
    let mut first_work = work(actor_program, initial_state_ref.clone());
    let mut ping = vec![vos::value::TAG_DYNAMIC];
    ping.extend_from_slice(&Msg::new("ping").encode());
    first_work.method = "ping".into();
    first_work.arguments = ping;
    let mut committed =
        InMemoryServiceState::new(first_work.service.clone(), ConsistencyModeV2::Local);
    committed.install_actor(first_work.target, actor_program);
    committed.make_blob_available(initial_state_ref.hash);
    first_work.base = committed.current_base();
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
    let first = RefineOutputV2::decode(&first_output.bytes)
        .unwrap()
        .transition;
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
    assert_eq!(
        committed.row(first_work.target, vos::lifecycle::STATE_KEY_BYTES),
        None
    );
    assert_eq!(committed.continuation(first_work.target), None);
    for artifact in &first_output.exported_blobs {
        committed.make_blob_available(artifact.reference.hash);
    }
    let checkpoint_outcome = committed
        .accumulate(&first_work, &first, &AllowPublic)
        .unwrap();
    assert!(checkpoint_outcome.published.reply.is_none());
    assert_eq!(
        committed.row(first_work.target, vos::lifecycle::STATE_KEY_BYTES),
        Some(checkpoint_state.as_slice())
    );
    assert_eq!(
        committed.continuation(first_work.target),
        Some(&first_continuation)
    );

    // Simulate a process restart after Accumulate committed slice 0. Only
    // canonical programs, the committed state, and the continuation blob are
    // supplied to the next Refine invocation.
    let checkpoint_state_ref = BlobRefV2::of_bytes(&checkpoint_state);
    committed.make_blob_available(checkpoint_state_ref.hash);
    let mut resumed_work = first_work.clone();
    resumed_work.workflow_step = 1;
    resumed_work.base = committed.current_base();
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
    let resumed = RefineOutputV2::decode(&resumed_output.bytes)
        .unwrap()
        .transition;
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
    assert_eq!(
        committed.continuation(first_work.target),
        Some(&first_continuation),
        "Refine cannot delete durable continuation state"
    );
    let completed = committed
        .accumulate(&resumed_work, &resumed, &AllowPublic)
        .unwrap();
    assert_eq!(completed.published.reply, resumed.reply);
    assert_eq!(committed.continuation(first_work.target), None);
    assert_eq!(
        committed.row(first_work.target, vos::lifecycle::STATE_KEY_BYTES),
        Some(resumed_state.as_slice())
    );
}

#[test]
fn awaited_reply_is_injected_at_the_exact_machine_boundary() {
    let (Some(service_elf), Some(actor_elf)) = (service_elf(), probe_elf()) else {
        return;
    };
    let service_pvm = grey_transpiler::link_elf(&service_elf).unwrap();
    let service = ServicePvmV2::new(service_pvm.clone(), ProgramId::of_pvm(&service_pvm)).unwrap();
    let actor = grey_transpiler::link_elf(&actor_elf).unwrap();
    let actor_program = ProgramId::of_pvm(&actor);
    let initial_state = Vec::new();
    let initial_state_ref = BlobRefV2::of_bytes(&initial_state);
    let mut first_work = work(actor_program, initial_state_ref.clone());
    let mut request = vec![vos::value::TAG_DYNAMIC];
    request.extend_from_slice(&Msg::new("await_peer").encode());
    first_work.method = "await_peer".into();
    first_work.arguments = request;
    let mut committed =
        InMemoryServiceState::new(first_work.service.clone(), ConsistencyModeV2::Local);
    committed.install_actor(first_work.target, actor_program);
    committed.make_blob_available(initial_state_ref.hash);
    first_work.base = committed.current_base();
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
    assert_eq!(
        service
            .refine_actor_tree_with_backend(
                &first_work.encode(),
                &first_imports,
                100_000_000,
                &NoRefineProtocolHostV2,
                javm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        first_output,
        "both JAR backends must capture the same awaited-call boundary"
    );
    let first = RefineOutputV2::decode(&first_output.bytes)
        .unwrap()
        .transition;
    assert!(first.reply.is_none());
    assert_eq!(first.outbox.len(), 1);
    let call_id = first_work.invocation.call_id(0);
    assert_eq!(first.outbox[0].call_id, call_id);
    assert_eq!(first.outbox[0].to, ActorId([44; 32]));
    assert_eq!(first.outbox[0].deadline_timeslot, Some(100));
    let first_continuation = first.continuations[0].replacement.clone().unwrap();
    let continuation = ContinuationSnapshotV2::decode(&first_output.exported_blobs[0].bytes)
        .expect("checkpoint exports the exact continuation envelope");
    assert_eq!(continuation.await_ordinal, 0);
    assert_eq!(continuation.pending_call, Some(call_id));
    let checkpoint_state = first
        .writes
        .iter()
        .find(|write| write.key == vos::lifecycle::STATE_KEY_BYTES)
        .and_then(|write| write.value.clone())
        .expect("pre-await mutation is part of the checkpoint transition");
    assert_eq!(u32::decode(&checkpoint_state), 1);

    for artifact in &first_output.exported_blobs {
        committed.make_blob_available(artifact.reference.hash);
    }
    committed
        .accumulate(&first_work, &first, &AllowPublic)
        .expect("checkpoint and durable outbox commit atomically");
    let checkpoint_state_ref = BlobRefV2::of_bytes(&checkpoint_state);
    committed.make_blob_available(checkpoint_state_ref.hash);

    let reply = ReplyRecordV2 {
        call_id,
        producer: ActorId([44; 32]),
        result: vos::value::Value::U32(7).encode(),
    };
    let mut remote_service = first_work.service.clone();
    remote_service.root_service = RootServiceId([45; 32]);
    remote_service.deployment = DeploymentId([46; 32]);
    let awaited_reply = AccumulatedReplyV2 {
        receipt: AccumulationReceiptV2 {
            service: remote_service,
            accepted_transition: Hash([47; 32]),
            reply_commitment: Some(reply.commitment()),
            resulting_state_root: Some(Hash([48; 32])),
            resulting_crdt_heads: vec![],
            sequence: 3,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        },
        reply,
    };
    let mut resumed_work = first_work.clone();
    resumed_work.workflow_step = 1;
    resumed_work.logical_timeslot = 2;
    resumed_work.base = committed.current_base();
    resumed_work.awaited_reply = Some(awaited_reply.clone());
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

    let mut wrong_work = resumed_work.clone();
    let wrong_reply = wrong_work.awaited_reply.as_mut().unwrap();
    wrong_reply.reply.call_id = InvocationId([49; 32]).call_id(0);
    wrong_reply.receipt.reply_commitment = Some(wrong_reply.reply.commitment());
    assert_eq!(
        service.refine_actor_tree_with_backend(
            &wrong_work.encode(),
            &resumed_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        ),
        Err(ServicePvmErrorV2::ContinuationMismatch),
        "a different accumulated CallId cannot resume this machine"
    );

    let resumed_output = service
        .refine_actor_tree_with_backend(
            &resumed_work.encode(),
            &resumed_imports,
            100_000_000,
            &NoRefineProtocolHostV2,
            javm::PvmBackend::ForceInterpreter,
        )
        .unwrap();
    assert_eq!(
        service
            .refine_actor_tree_with_backend(
                &resumed_work.encode(),
                &resumed_imports,
                100_000_000,
                &NoRefineProtocolHostV2,
                javm::PvmBackend::ForceRecompiler,
            )
            .unwrap(),
        resumed_output,
        "both JAR backends must inject the same reply into the same snapshot"
    );
    let resumed = RefineOutputV2::decode(&resumed_output.bytes)
        .unwrap()
        .transition;
    assert!(resumed.outbox.is_empty());
    assert_eq!(resumed.continuations.len(), 1);
    assert_eq!(
        resumed.continuations[0].expected,
        Some(first_continuation.hash)
    );
    assert_eq!(resumed.continuations[0].replacement, None);
    let resumed_state = resumed
        .writes
        .iter()
        .find(|write| write.key == vos::lifecycle::STATE_KEY_BYTES)
        .and_then(|write| write.value.as_ref())
        .expect("post-await state is returned by the original handler");
    assert_eq!(
        u32::decode(resumed_state),
        8,
        "pre-await code runs once and the committed reply is observed once"
    );
    assert_eq!(
        resumed
            .reply
            .as_ref()
            .map(|reply| vos::value::Value::decode(&reply.result)),
        Some(vos::value::Value::U32(8))
    );
}

#[test]
fn canonical_guest_accumulate_installs_applies_and_deduplicates_at_ic5() {
    let Some(elf) = service_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
    let actor_pvm = actor_pvm(0);
    let actor_program = ProgramId::of_pvm(&actor_pvm);
    let initial_bytes = b"initial actor state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed_work = work(actor_program, initial.clone());
    let mut host = LocalJamStoreV2::default();
    assert_eq!(host.import_blob(initial_bytes), initial);
    assert_eq!(host.import_program(actor_pvm.clone()), actor_program);
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
        actors: vec![
            ActorGenesisV2 {
                actor: seed_work.target,
                name: "root".into(),
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
            },
            ActorGenesisV2 {
                actor: ActorId([36; 32]),
                name: "child".into(),
                parent: Some(seed_work.target),
                program: actor_program,
                initial_state: initial.clone(),
                crdt: false,
                methods: vec![],
            },
        ],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: vos::v2::SystemCapabilityId([34; 32]),
            authenticator: vec![35],
        },
    });
    assert_eq!(
        service.accumulate(&install).unwrap().result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::Unauthorized)
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 0);
    let AccumulateRequestV2::Install(genesis) = &install else {
        unreachable!()
    };
    service.accumulate_host_mut().allow_install(genesis);
    let installed_output = service
        .accumulate(&install)
        .expect("guest install completes");
    let AccumulationResultV2::Installed(installed) = installed_output.result else {
        panic!("guest install rejected")
    };
    assert_eq!(service.accumulate_host().commit_sequence(), 1);
    assert_eq!(
        LocalWorkSchedulerV2::resolve_root(service.accumulate_host(), "root").unwrap(),
        Some(seed_work.target)
    );
    assert_eq!(
        LocalWorkSchedulerV2::resolve_child(service.accumulate_host(), seed_work.target, "child")
            .unwrap(),
        Some(ActorId([36; 32]))
    );
    assert_eq!(
        LocalWorkSchedulerV2::resolve_root(service.accumulate_host(), "child").unwrap(),
        None,
        "a child name cannot escape into the root namespace"
    );
    let installed_rows = service.accumulate_host().row_count();

    let request = LocalWorkRequestV2 {
        invocation: seed_work.invocation,
        workflow_step: 0,
        logical_timeslot: seed_work.logical_timeslot,
        target: seed_work.target,
        method: seed_work.method.clone(),
        arguments: seed_work.arguments.clone(),
        origin: seed_work.origin,
        authorization: seed_work.authorization.clone(),
        causal_parent: None,
        parent_call: None,
        awaited_reply: None,
        imported_blobs: vec![],
        proof_requested: false,
    };
    let prepared = LocalWorkSchedulerV2::prepare(service.accumulate_host(), request.clone())
        .expect("scheduler reads the installed guest state");
    assert_eq!(prepared.work.service, seed_work.service);
    assert_eq!(prepared.work.target_program, actor_program);
    assert_eq!(
        prepared.work.base,
        ConsistencyBaseV2::Linear {
            revision: 0,
            state_root: installed.resulting_state_root.unwrap(),
        }
    );
    assert_eq!(prepared.work.imported_actors[0].state, initial);
    assert_eq!(prepared.imports.programs[0].pvm, actor_pvm);
    let work = prepared.work;
    let continuation = ContinuationSnapshotV2 {
        snapshot_version: vos::v2::SNAPSHOT_VERSION,
        jar_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        vos_abi: vos::v2::ABI_VERSION,
        service: work.service.clone(),
        invocation: work.invocation,
        checkpoint_step: 0,
        actor: work.target,
        actor_program,
        await_ordinal: 0,
        pending_call: None,
        kernel_snapshot: vec![1],
    };
    let continuation_bytes = continuation.encode();
    let continuation_ref = BlobRefV2::of_bytes(&continuation_bytes);
    let caller_invocation = InvocationId([70; 32]);
    let call_id = caller_invocation.call_id(0);
    let inbox = MessageRecordV2 {
        call_id,
        caller_invocation,
        await_ordinal: 0,
        from: ActorId([71; 32]),
        to: work.target,
        parent: None,
        payload: work.arguments.clone(),
        authorization: AuthorizationEvidenceV2::Public,
        deadline_timeslot: Some(100),
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
        continuations: vec![ContinuationChangeV2 {
            actor: work.target,
            expected: None,
            replacement: Some(continuation_ref.clone()),
        }],
        inbox: vec![inbox.clone()],
        outbox: vec![],
        reply: None,
        exported_blobs: vec![continuation_ref.clone()],
        gas: GasAccountingV2::default(),
        proof: None,
    };

    let mut forbidden_attested_work = work.clone();
    forbidden_attested_work.proof_requested = true;
    let forbidden = service
        .accumulate(&AccumulateRequestV2::PrepareAttested(
            AccumulationEnvelopeV2 {
                work: forbidden_attested_work,
                transition: transition.clone(),
                provided_blobs: vec![ImportedBlobV2 {
                    reference: continuation_ref.clone(),
                    bytes: continuation_bytes.clone(),
                }],
            },
        ))
        .expect("a suspending attested transition returns a stable rejection");
    assert_eq!(
        forbidden.result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::InvalidWorkflowTransition)
    );
    assert_eq!(service.accumulate_host().commit_sequence(), 1);

    let apply = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
        work: work.clone(),
        transition: transition.clone(),
        provided_blobs: vec![ImportedBlobV2 {
            reference: continuation_ref.clone(),
            bytes: continuation_bytes,
        }],
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
    let snapshot_after_duplicate = service.accumulate_host().snapshot();
    assert!(snapshot_after_duplicate.same_service_state(&snapshot_after_apply));
    assert_eq!(
        service.accumulate_host().commit_sequence(),
        2,
        "a read-only duplicate transaction must not commit"
    );

    let restarted = LocalJamStoreV2::from_snapshot(service.accumulate_host().snapshot());
    assert_eq!(
        LocalWorkSchedulerV2::prepare_inbox(&restarted, call_id, 50),
        Err(ScheduleErrorV2::ActorBusy(work.target))
    );
    assert_eq!(
        LocalWorkSchedulerV2::prepare_inbox(&restarted, call_id, 100),
        Err(ScheduleErrorV2::DeadlineExpired(call_id))
    );
    let mut queued = request.clone();
    queued.invocation = InvocationId([99; 32]);
    assert_eq!(
        LocalWorkSchedulerV2::prepare(&restarted, queued),
        Err(ScheduleErrorV2::ActorBusy(work.target))
    );

    let mut resume = request;
    resume.workflow_step = 1;
    let resumed = LocalWorkSchedulerV2::prepare(&restarted, resume)
        .expect("restart reconstructs the next exact continuation slice");
    assert_eq!(
        resumed.work.base,
        ConsistencyBaseV2::Linear {
            revision: 1,
            state_root: receipt.resulting_state_root.unwrap(),
        }
    );
    assert_eq!(
        resumed.work.imported_actors[0].continuation,
        Some(continuation_ref)
    );
    assert_eq!(
        resumed.imports.blobs.len(),
        2,
        "state and continuation bytes are both imported after restart"
    );

    let resumed_transition = TransitionV2 {
        service: resumed.work.service.clone(),
        consumed_input: resumed.work.input_id(),
        target_program: resumed.work.target_program,
        base: resumed.work.base.clone(),
        writes: vec![],
        crdt_change: None,
        continuations: vec![ContinuationChangeV2 {
            actor: resumed.work.target,
            expected: Some(
                resumed.work.imported_actors[0]
                    .continuation
                    .as_ref()
                    .unwrap()
                    .hash,
            ),
            replacement: None,
        }],
        inbox: vec![],
        outbox: vec![],
        reply: None,
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let completed = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: resumed.work,
            transition: resumed_transition,
            provided_blobs: vec![],
        }))
        .unwrap()
        .result;
    assert!(matches!(completed, AccumulationResultV2::Accepted { .. }));

    let delivered = LocalWorkSchedulerV2::prepare_inbox(service.accumulate_host(), call_id, 50)
        .expect("queued inbox becomes runnable only after the actor is idle");
    assert_eq!(delivered.work.invocation, InvocationId::for_call(call_id));
    assert_eq!(delivered.work.parent_call, Some(call_id));
    assert_eq!(delivered.work.causal_parent, Some(caller_invocation));
    assert_eq!(delivered.work.origin, Origin::Actor(inbox.from));
    assert_eq!(delivered.work.authorization, inbox.authorization);
    let delivered_transition = TransitionV2 {
        service: delivered.work.service.clone(),
        consumed_input: delivered.work.input_id(),
        target_program: delivered.work.target_program,
        base: delivered.work.base.clone(),
        writes: vec![],
        crdt_change: None,
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(vos::v2::ReplyRecordV2 {
            call_id,
            producer: delivered.work.target,
            result: b"durable inbox reply".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let delivered_result = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: delivered.work.clone(),
            transition: delivered_transition,
            provided_blobs: vec![],
        }))
        .expect("guest commits delivery and consumes the inbox atomically");
    assert!(matches!(
        delivered_result.result,
        AccumulationResultV2::Accepted {
            published: PublishedEffectsV2 { reply: Some(_), .. },
            duplicate: false,
            ..
        }
    ));
    assert_eq!(
        LocalWorkSchedulerV2::prepare_inbox(service.accumulate_host(), call_id, 51).unwrap_err(),
        ScheduleErrorV2::MissingInbox(call_id),
        "a committed delivery cannot be scheduled from its inbox again"
    );

    let private_credential = b"private member credential".to_vec();
    let witness = service
        .accumulate_host_mut()
        .import_blob(private_credential.clone());
    let credential_commitment =
        Hash::digest(b"vos/credential-commitment/v2", &[&private_credential]);
    let proof_work = LocalWorkSchedulerV2::prepare(
        service.accumulate_host(),
        LocalWorkRequestV2 {
            invocation: InvocationId([110; 32]),
            workflow_step: 0,
            logical_timeslot: 51,
            target: delivered.work.target,
            method: delivered.work.method.clone(),
            arguments: delivered.work.arguments.clone(),
            origin: Origin::Member(SubjectId([111; 32])),
            authorization: AuthorizationEvidenceV2::PrivateCredential {
                policy: Hash([33; 32]),
                credential_commitment,
                witness: witness.clone(),
            },
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
            imported_blobs: vec![witness],
            proof_requested: true,
        },
    )
    .expect("scheduler imports a private role witness without disclosing it")
    .work;
    let attested_call = proof_work.invocation.call_id(0);
    let mut proof_transition = TransitionV2 {
        service: proof_work.service.clone(),
        consumed_input: proof_work.input_id(),
        target_program: proof_work.target_program,
        base: proof_work.base.clone(),
        writes: vec![],
        crdt_change: None,
        continuations: vec![],
        inbox: vec![],
        outbox: vec![],
        reply: Some(vos::v2::ReplyRecordV2 {
            call_id: attested_call,
            producer: proof_work.target,
            result: b"attested reply".to_vec(),
        }),
        exported_blobs: vec![],
        gas: GasAccountingV2::default(),
        proof: None,
    };
    let before_prepare = service.accumulate_host().snapshot();
    let mut denied_work = proof_work.clone();
    let AuthorizationEvidenceV2::PrivateCredential { policy, .. } = &mut denied_work.authorization
    else {
        unreachable!()
    };
    *policy = Hash([200; 32]);
    let denied = service
        .accumulate(&AccumulateRequestV2::PrepareAttested(
            AccumulationEnvelopeV2 {
                work: denied_work,
                transition: proof_transition.clone(),
                provided_blobs: vec![],
            },
        ))
        .expect("a private credential with the wrong policy is rejected");
    assert_eq!(
        denied.result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::Unauthorized)
    );
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_prepare)
    );

    let prepared = service
        .accumulate(&AccumulateRequestV2::PrepareAttested(
            AccumulationEnvelopeV2 {
                work: proof_work.clone(),
                transition: proof_transition.clone(),
                provided_blobs: vec![],
            },
        ))
        .expect("guest predicts the attested receipt without committing");
    let AccumulationResultV2::Prepared(predicted) = prepared.result else {
        panic!("guest did not prepare the attested transition")
    };
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_prepare)
    );

    let policy = MethodPolicyV2 {
        method: "start".into(),
        schema: Hash([32; 32]),
        policy: Hash([33; 32]),
        public: true,
        attested: false,
    };
    let statement = AttestationStatementV3::for_transition(
        &proof_work,
        &proof_transition,
        &policy,
        predicted.clone(),
    )
    .unwrap();
    let proof_bytes = b"canonical proof bytes".to_vec();
    let proof_blob = BlobRefV2::of_bytes(&proof_bytes);
    let proof = ProofCommitmentV2 {
        statement: statement.commitment(),
        trace: Hash([101; 32]),
        proof_blob: proof_blob.clone(),
        statement_version: vos::v2::ATTESTATION_STATEMENT_VERSION,
    };
    let verification = ProofVerificationRequestV2 {
        actor_program: proof_work.target_program,
        execution_semantics: proof_work.service.execution_semantics,
        statement: proof.statement,
        trace: proof.trace,
        proof_blob: proof_blob.clone(),
    };
    let before_invalid_proof = service.accumulate_host().snapshot();
    let mut unavailable_transition = proof_transition.clone();
    unavailable_transition.proof = Some(proof.clone());
    let unavailable = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: proof_work.clone(),
            transition: unavailable_transition,
            provided_blobs: vec![ImportedBlobV2 {
                reference: proof_blob.clone(),
                bytes: proof_bytes.clone(),
            }],
        }))
        .expect("an unavailable proof verifier fails closed");
    assert_eq!(
        unavailable.result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::ProofUnavailable)
    );
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_invalid_proof)
    );

    service.accumulate_host_mut().allow_proof(&verification);
    let mut tampered_transition = proof_transition.clone();
    let mut tampered_proof = proof.clone();
    tampered_proof.statement = Hash([102; 32]);
    tampered_transition.proof = Some(tampered_proof);
    let tampered = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: proof_work.clone(),
            transition: tampered_transition,
            provided_blobs: vec![ImportedBlobV2 {
                reference: proof_blob.clone(),
                bytes: proof_bytes.clone(),
            }],
        }))
        .expect("a tampered statement returns a stable rejection");
    assert_eq!(
        tampered.result,
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::InvalidProof)
    );
    assert!(
        service
            .accumulate_host()
            .snapshot()
            .same_service_state(&before_invalid_proof)
    );

    proof_transition.proof = Some(proof.clone());
    let proved = service
        .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: proof_work,
            transition: proof_transition,
            provided_blobs: vec![ImportedBlobV2 {
                reference: proof_blob,
                bytes: proof_bytes,
            }],
        }))
        .expect("guest validates the proof before committing");
    let result = proved.result;
    let AccumulationResultV2::Accepted {
        receipt,
        published,
        duplicate: false,
    } = result.clone()
    else {
        panic!("proved transition was not accepted: {result:?}")
    };
    assert_eq!(receipt, predicted);
    assert_eq!(published.proof, Some(proof));
}

#[test]
fn malformed_guest_accumulate_returns_a_rejection_without_storage_effects() {
    let Some(elf) = service_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
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
