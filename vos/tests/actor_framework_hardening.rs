//! Focused physical-PVM regressions for actor framework trust boundaries.

use std::path::PathBuf;
use vos::Encode;
use vos::service::{
    ActorId, AuthorizationEvidence, BlobRef, ConsistencyBase, ConsistencyMode, DeploymentId,
    GasSchedule, Hash, ImportedActor, ImportedBlob, ImportedProgram, InvocationId,
    NoRefineProtocolHost, Origin, ProgramId, RefineImports, RefineOutput, RootServiceId,
    ServiceIdentity, ServicePvm, ServicePvmError, ServiceWire, SpaceId, WorkEnvelope,
};
use vos::value::Msg;

const TEST_GAS_SCHEDULE: GasSchedule = GasSchedule::new(1_000_000_000, 5_000_000_000);

fn required_elf(relative_path: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "required framework-hardening guest ELF is unavailable at {}: {error}\n\
             build it with `cargo actor` in vos/tests/fixtures/greeter",
            path.display()
        )
    })
}

fn work(actor_program: ProgramId, state: BlobRef) -> WorkEnvelope {
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&Msg::new("start").encode());
    WorkEnvelope {
        external_actors: vec![],
        service: ServiceIdentity {
            space: SpaceId([0; 32]),
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: TEST_GAS_SCHEDULE,
        },
        invocation: InvocationId([4; 32]),
        workflow_step: 0,
        logical_timeslot: 1,
        target: ActorId([5; 32]),
        target_deployment: DeploymentId([2; 32]),
        target_program: actor_program,
        private_arguments: None,
        method: "start".into(),
        arguments: message,
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidence::Public,
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        consistency: ConsistencyMode::Local,
        base: ConsistencyBase::Linear {
            revision: 0,
            state_root: Hash([8; 32]),
        },
        base_causal_height: None,
        imported_actors: vec![ImportedActor {
            actor: ActorId([5; 32]),
            name: "root".into(),
            parent: None,
            deployment: DeploymentId([2; 32]),
            program: actor_program,
            task_dependencies: vec![],
            state,
            causal_states: vec![],
            continuation: None,
            storage_rows: vec![],
        }],
        imported_blobs: vec![],
        proof_requested: false,
    }
}

#[test]
fn corrupt_nonempty_state_traps_without_replacement_while_absent_state_creates() {
    let service_elf = required_elf("../target/pinned-production-artifacts/vos_service.elf");
    let service_pvm =
        vos::service::transpile_service_elf(&service_elf).expect("generic service ELF transpiles");
    let service = ServicePvm::new(service_pvm.clone(), ProgramId::of_pvm(&service_pvm))
        .expect("generic service has the GP IC0/IC5 entries");
    let actor_elf = required_elf("tests/fixtures/greeter/target/riscv64em-vos/release/greeter.elf");
    let actor = vos_pvm_compiler::link_elf(&actor_elf).expect("canonical actor ELF transpiles");
    let actor_program = ProgramId::of_pvm(&actor);

    let corrupt_bytes = vec![0xff, 0x00, 0x01];
    let corrupt = BlobRef::of_bytes(&corrupt_bytes);
    let corrupt_work = work(actor_program, corrupt.clone());
    let corrupt_imports = RefineImports {
        programs: vec![ImportedProgram {
            program: actor_program,
            pvm: actor.clone(),
        }],
        blobs: vec![ImportedBlob {
            reference: corrupt,
            bytes: corrupt_bytes,
        }],
        private_blobs: vec![],
    };
    assert!(
        matches!(
            service.refine_actor_tree(
                &corrupt_work.encode(),
                &corrupt_imports,
                100_000_000,
                &NoRefineProtocolHost,
            ),
            Err(ServicePvmError::Panic { .. })
        ),
        "a non-empty invalid archive must trap before it can emit replacement state"
    );

    let absent_bytes = Vec::new();
    let absent = BlobRef::of_bytes(&absent_bytes);
    let absent_work = work(actor_program, absent.clone());
    let absent_imports = RefineImports {
        programs: vec![ImportedProgram {
            program: actor_program,
            pvm: actor,
        }],
        blobs: vec![ImportedBlob {
            reference: absent,
            bytes: absent_bytes,
        }],
        private_blobs: vec![],
    };
    let output = service
        .refine_actor_tree(
            &absent_work.encode(),
            &absent_imports,
            100_000_000,
            &NoRefineProtocolHost,
        )
        .expect("a genuinely absent actor state creates the actor");
    let transition = RefineOutput::decode(&output.bytes)
        .expect("fresh actor Refine returns a transition")
        .transition;
    assert!(transition.writes.iter().any(|write| {
        write.actor == absent_work.target
            && write.key == vos::lifecycle::STATE_KEY_BYTES
            && write.value.as_ref().is_some_and(|state| !state.is_empty())
    }));
}
