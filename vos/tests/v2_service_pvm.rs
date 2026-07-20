//! Physical generic-service PVM integration gate.
//!
//! Build the guest first with:
//! `cd services/vos-service && cargo +nightly actor`.

use std::{collections::BTreeMap, path::PathBuf};

use javm::kernel::InvocationKernel;
use vos::v2::{
    AccumulateProtocolHostV2, AccumulateRequestV2, AccumulateTransactionV2, AccumulationEnvelopeV2,
    AccumulationResultV2, ActorGenesisV2, ActorId, ActorWriteV2, AllowPublic,
    AuthorizationEvidenceV2, BlobRefV2, ConsistencyBaseV2, ConsistencyModeV2, DeploymentId,
    GasAccountingV2, Hash, ImportedActorV2, ImportedBlobV2, ImportedProgramV2,
    InMemoryServiceState, InvocationId, MethodPolicyV2, NoRefineProtocolHostV2, Origin, ProgramId,
    PublishedEffectsV2, RefineImportsV2, ReplyRecordV2, RootServiceId, ServiceGenesisV2,
    ServiceIdentityV2, ServicePvmErrorV2, ServicePvmV2, TransitionV2, V2Wire, WorkEnvelopeV2,
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
        imported_actors: vec![ImportedActorV2 {
            actor: ActorId([5; 32]),
            program: actor_program,
            state,
            continuation: None,
        }],
        imported_blobs: vec![],
        proof_requested: false,
    }
}

#[derive(Clone, Default)]
struct DurableAccumulateHost {
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
    preimages: BTreeMap<[u8; 32], Vec<u8>>,
    commits: usize,
}

struct DurableTransaction {
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
    preimages: BTreeMap<[u8; 32], Vec<u8>>,
}

impl AccumulateTransactionV2 for DurableTransaction {
    fn handle(
        &mut self,
        slot: u8,
        registers: &[u64; 13],
        kernel: &mut InvocationKernel,
    ) -> Result<[u64; 2], ServicePvmErrorV2> {
        use vos::abi::{error, hostcall};

        let read = |kernel: &InvocationKernel, address: u64, len: u64| {
            let address = u32::try_from(address).ok()?;
            let len = u32::try_from(len).ok()?;
            kernel.read_data_cap_window(address, len)
        };
        match slot as u32 {
            hostcall::STORAGE_R => {
                let key = read(kernel, registers[7], registers[8])
                    .ok_or(ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                let Some(value) = self.rows.get(&key) else {
                    return Ok([error::HOST_NONE, 0]);
                };
                let capacity = usize::try_from(registers[10])
                    .map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                let copy_len = value.len().min(capacity);
                if copy_len != 0
                    && !kernel.write_data_cap_window(
                        u32::try_from(registers[9])
                            .map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?,
                        &value[..copy_len],
                    )
                {
                    return Err(ServicePvmErrorV2::AccumulateHostRejected(slot));
                }
                Ok([value.len() as u64, 0])
            }
            hostcall::STORAGE_W => {
                let key = read(kernel, registers[7], registers[8])
                    .ok_or(ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                let value = read(kernel, registers[9], registers[10])
                    .ok_or(ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                if value.is_empty() {
                    self.rows.remove(&key);
                } else {
                    self.rows.insert(key, value);
                }
                Ok([error::HOST_OK, 0])
            }
            hostcall::PREIMAGE_LOOKUP => {
                let hash: [u8; 32] = read(kernel, registers[7], 32)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                let Some(value) = self.preimages.get(&hash) else {
                    return Ok([error::HOST_NONE, 0]);
                };
                let capacity = usize::try_from(registers[9])
                    .map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                let copy_len = value.len().min(capacity);
                if copy_len != 0
                    && !kernel.write_data_cap_window(
                        u32::try_from(registers[8])
                            .map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?,
                        &value[..copy_len],
                    )
                {
                    return Err(ServicePvmErrorV2::AccumulateHostRejected(slot));
                }
                Ok([value.len() as u64, 0])
            }
            hostcall::PREIMAGE_PROVIDE => {
                let hash: [u8; 32] = read(kernel, registers[7], 32)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                let value = read(kernel, registers[8], registers[9])
                    .ok_or(ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                if BlobRefV2::of_bytes(&value).hash.0 != hash {
                    return Ok([error::HOST_WHAT, 0]);
                }
                self.preimages.insert(hash, value);
                Ok([error::HOST_OK, 0])
            }
            _ => Err(ServicePvmErrorV2::AccumulateHostRejected(slot)),
        }
    }
}

impl AccumulateProtocolHostV2 for DurableAccumulateHost {
    type Transaction = DurableTransaction;

    fn begin(&mut self) -> Result<Self::Transaction, ServicePvmErrorV2> {
        Ok(DurableTransaction {
            rows: self.rows.clone(),
            preimages: self.preimages.clone(),
        })
    }

    fn commit(&mut self, transaction: Self::Transaction) -> Result<(), ServicePvmErrorV2> {
        self.rows = transaction.rows;
        self.preimages = transaction.preimages;
        self.commits += 1;
        Ok(())
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
    let transition = TransitionV2::decode(&output.bytes).expect("Refine returns TransitionV2");
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
    let first = TransitionV2::decode(&first_output.bytes).unwrap();
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
    let resumed = TransitionV2::decode(&resumed_output.bytes).unwrap();
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
fn canonical_guest_accumulate_installs_applies_and_deduplicates_at_ic5() {
    let Some(elf) = service_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvmV2::new(pvm.clone(), ProgramId::of_pvm(&pvm)).unwrap();
    let actor_program = ProgramId([31; 32]);
    let initial_bytes = b"initial actor state".to_vec();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let seed_work = work(actor_program, initial.clone());
    let mut host = DurableAccumulateHost::default();
    host.preimages.insert(initial.hash.0, initial_bytes);

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
        .accumulate(&install.encode(), 5_000_000_000, &mut host)
        .expect("guest install completes");
    let AccumulationResultV2::Installed(installed) =
        AccumulationResultV2::decode(&installed_output.bytes).unwrap()
    else {
        panic!("guest install rejected")
    };
    assert_eq!(host.commits, 1);
    let installed_rows = host.rows.len();

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
    });
    let applied_output = service
        .accumulate(&apply.encode(), 5_000_000_000, &mut host)
        .expect("guest apply completes");
    let AccumulationResultV2::Accepted {
        receipt,
        published,
        duplicate,
    } = AccumulationResultV2::decode(&applied_output.bytes).unwrap()
    else {
        panic!("guest apply rejected")
    };
    assert!(!duplicate);
    assert_eq!(receipt.sequence, 1);
    assert_eq!(published.reply, transition.reply);
    assert!(host.rows.len() > installed_rows);
    assert_eq!(host.commits, 2);
    assert!(
        host.preimages
            .values()
            .any(|bytes| bytes == b"committed actor state")
    );

    let rows_after_apply = host.rows.clone();
    let preimages_after_apply = host.preimages.clone();
    let duplicate_output = service
        .accumulate(&apply.encode(), 5_000_000_000, &mut host)
        .expect("guest retry completes");
    let AccumulationResultV2::Accepted {
        published,
        duplicate,
        ..
    } = AccumulationResultV2::decode(&duplicate_output.bytes).unwrap()
    else {
        panic!("guest retry rejected")
    };
    assert!(duplicate);
    assert_eq!(published, PublishedEffectsV2::default());
    assert_eq!(host.rows, rows_after_apply);
    assert_eq!(host.preimages, preimages_after_apply);
    assert_eq!(
        host.commits, 3,
        "a read-only duplicate transaction may commit"
    );
}

#[test]
fn malformed_guest_accumulate_returns_a_rejection_without_storage_effects() {
    let Some(elf) = service_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvmV2::new(pvm.clone(), ProgramId::of_pvm(&pvm)).unwrap();
    let mut host = DurableAccumulateHost::default();

    let output = service
        .accumulate(b"not a v2 request", 10_000_000, &mut host)
        .unwrap();
    assert_eq!(
        AccumulationResultV2::decode(&output.bytes).unwrap(),
        AccumulationResultV2::Rejected(vos::v2::AccumulationRejectionV2::NonCanonical)
    );
    assert!(host.rows.is_empty());
    assert!(host.preimages.is_empty());
}
