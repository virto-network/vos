//! Physical generic-service PVM integration gate.
//!
//! Build the guest first with:
//! `cd services/vos-service && cargo +nightly actor`.

use std::path::PathBuf;

use javm::kernel::InvocationKernel;
use vos::v2::{
    AccumulateProtocolHostV2, AccumulateTransactionV2, ActorId, AuthorizationEvidenceV2, BlobRefV2,
    ConsistencyBaseV2, ConsistencyModeV2, DeploymentId, Hash, ImportedActorV2, ImportedBlobV2,
    ImportedProgramV2, InvocationId, NoRefineProtocolHostV2, Origin, ProgramId, RefineImportsV2,
    RootServiceId, ServiceIdentityV2, ServicePvmErrorV2, ServicePvmV2, TransitionV2, V2Wire,
    WorkEnvelopeV2,
};
use vos::{Encode, value::Msg};

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

struct FailClosedAccumulateHost {
    committed: bool,
}

struct EmptyTransaction;

impl AccumulateTransactionV2 for EmptyTransaction {
    fn handle(
        &mut self,
        slot: u8,
        _registers: &[u64; 13],
        _kernel: &mut InvocationKernel,
    ) -> Result<[u64; 2], ServicePvmErrorV2> {
        Err(ServicePvmErrorV2::AccumulateHostRejected(slot))
    }
}

impl AccumulateProtocolHostV2 for FailClosedAccumulateHost {
    type Transaction = EmptyTransaction;

    fn begin(&mut self) -> Result<Self::Transaction, ServicePvmErrorV2> {
        Ok(EmptyTransaction)
    }

    fn commit(&mut self, _transaction: Self::Transaction) -> Result<(), ServicePvmErrorV2> {
        self.committed = true;
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
    assert_eq!(transition.consumed_input, work.invocation);
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
        Err(ServicePvmErrorV2::UnsupportedContinuation)
    );
}

#[test]
fn unfinished_guest_accumulate_traps_without_committing() {
    let Some(elf) = service_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvmV2::new(pvm.clone(), ProgramId::of_pvm(&pvm)).unwrap();
    let mut host = FailClosedAccumulateHost { committed: false };

    assert_eq!(
        service.accumulate(&[], 10_000_000, &mut host),
        Err(ServicePvmErrorV2::Panic)
    );
    assert!(!host.committed);
}
