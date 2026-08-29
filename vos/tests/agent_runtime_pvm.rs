use vos::agent::driver::{AgentDriver, MemoryAgentStore};
use vos::agent::execution::{ActorExecutionStatus, ActorInvocation};
use vos::agent::host::AgentHost;
use vos::agent::wire::{RuntimeCall, RuntimeReturn, RuntimeState, decode_standard_runtime_state};
use vos::agent::{
    ActorEntry, ActorInitialState, AgentConfig, AgentIdentity, AgentProfile, AgentReplica,
    InstallActor, LaneSet, LifecycleReply, LifecycleRequest, MethodMode, ReplicaRole,
    RuntimeCapabilities, RuntimeRequirements, STANDARD_RUNTIME_PROGRAM_ID,
};
use vos::service::{
    ActorId, AgentId, BlobRef, DeploymentId, Hash, InvocationId, NodeId, PrincipalId, ProducerId,
    ProgramId, ServiceWire, SpaceId,
};
use vos_pvm::ExitReason;
use vos_pvm::refine_host::RefineContext;

const AGENT_RUNTIME_PVM: &[u8] = include_bytes!("../../vosx/blobs/agent_runtime.pvm");
const GAS: u64 = 1_000_000_000;

fn config_for(agent: AgentId) -> AgentConfig {
    let owner = PrincipalId([1; 32]);
    AgentConfig {
        identity: AgentIdentity {
            space: SpaceId([2; 32]),
            agent,
            owner,
            profile: AgentProfile::Local,
            runtime_deployment: DeploymentId([4; 32]),
            runtime_program: STANDARD_RUNTIME_PROGRAM_ID,
            runtime_producer: ProducerId([5; 32]),
        },
        runtime_package: BlobRef {
            hash: Hash([6; 32]),
            len: AGENT_RUNTIME_PVM.len() as u64,
        },
        capabilities: RuntimeCapabilities::standard(),
        replicas: vec![AgentReplica {
            node: NodeId([7; 32]),
            principal: owner,
            role: ReplicaRole::Voter,
        }],
    }
}

fn config() -> AgentConfig {
    config_for(AgentId([3; 32]))
}

fn invoke(call: RuntimeCall) -> RuntimeReturn {
    let invocation = RefineContext::load(AGENT_RUNTIME_PVM, &call.encode(), GAS)
        .expect("load bundled agent runtime")
        .run();
    let program = vos_pvm::spi::parse_standard_program(AGENT_RUNTIME_PVM).unwrap();
    let pc = invocation.pc as usize;
    let opcode = vos_pvm::instruction::Opcode::from_byte(program.code.code[pc]);
    let next = program.code.bitmask[pc + 1..]
        .iter()
        .position(|start| *start != 0)
        .map_or(program.code.code.len(), |delta| pc + 1 + delta);
    let args = opcode.map(|opcode| {
        vos_pvm::args::decode_args(&program.code.code, pc, next - pc - 1, opcode.category())
    });
    assert_eq!(
        invocation.exit,
        ExitReason::Halt,
        "agent runtime exited at instruction counter {} ({opcode:?}, {args:?}, registers {:?})",
        invocation.pc,
        invocation.registers,
    );
    RuntimeReturn::decode(&invocation.output().expect("valid output window"))
        .expect("decode runtime return")
}

#[test]
fn bundled_runtime_identity_is_pinned() {
    assert_eq!(
        ProgramId::of_pvm(AGENT_RUNTIME_PVM),
        STANDARD_RUNTIME_PROGRAM_ID
    );
}

#[test]
fn bundled_runtime_persists_an_empty_agent_between_invocations() {
    let config = config();
    let created = invoke(RuntimeCall {
        state: RuntimeState::default(),
        request: LifecycleRequest::Create(config.clone()),
    });
    assert_eq!(
        created.result,
        Ok(LifecycleReply::Created(config.identity.clone()))
    );
    assert!(!created.state.is_empty());

    let inspected = invoke(RuntimeCall {
        state: created.state,
        request: LifecycleRequest::Inspect {
            after: None,
            limit: 16,
        },
    });
    assert_eq!(
        inspected.result,
        Ok(LifecycleReply::Directory(vos::agent::ActorDirectoryPage {
            entries: Vec::new(),
            next: None,
        }))
    );
}

#[test]
fn host_driver_atomically_creates_and_reopens_an_empty_agent() {
    let config = config();
    let mut driver = AgentDriver::create_or_open(
        AGENT_RUNTIME_PVM.to_vec(),
        config.clone(),
        MemoryAgentStore::default(),
    )
    .expect("create agent");
    assert_eq!(driver.image().revision, 1);
    assert_eq!(
        driver
            .lifecycle(LifecycleRequest::Inspect {
                after: None,
                limit: 16,
            })
            .expect("inspect agent"),
        LifecycleReply::Directory(vos::agent::ActorDirectoryPage {
            entries: Vec::new(),
            next: None,
        })
    );
    assert_eq!(driver.image().revision, 1, "inspection is not a commit");

    let store = driver.into_store();
    let reopened = AgentDriver::create_or_open(AGENT_RUNTIME_PVM.to_vec(), config, store)
        .expect("reopen agent");
    assert_eq!(reopened.image().revision, 1);
}

#[test]
fn multi_agent_host_discovers_empty_agents_after_restart() {
    struct RemoveOnDrop(std::path::PathBuf);
    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("vos-agent-host-{}-{unique}", std::process::id()));
    let _remove = RemoveOnDrop(directory.clone());
    let runtime = |program: ProgramId| {
        (program == STANDARD_RUNTIME_PROGRAM_ID).then(|| AGENT_RUNTIME_PVM.to_vec())
    };
    let mut host = AgentHost::open(&directory, runtime).expect("open empty agent host");
    let first = AgentId([0x31; 32]);
    let second = AgentId([0x32; 32]);
    host.create(config_for(first)).expect("create first agent");
    host.create(config_for(second))
        .expect("create second agent");
    assert_eq!(host.len(), 2);
    assert_eq!(
        host.identities()
            .map(|identity| identity.agent)
            .collect::<Vec<_>>(),
        vec![first, second]
    );
    drop(host);

    let reopened = AgentHost::open(&directory, runtime).expect("reopen agent host");
    assert_eq!(reopened.len(), 2);
    assert_eq!(reopened.revision(first), Some(1));
    assert_eq!(reopened.revision(second), Some(1));
}

fn static_actor_pvm() -> Vec<u8> {
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    // Actor output: Done, one byte of next state, then one reply byte.
    let output = vec![0, 1, 0, 0, 0, 0x2a, 0x63];
    let mut actor = Assembler::new();
    actor
        .set_rw_data(output.clone())
        .load_imm_64(Reg::A0, 2 * u64::from(vos_pvm::PVM_ZONE_SIZE))
        .load_imm_64(Reg::A1, output.len() as u64)
        .jump_ind(Reg::RA, 0);
    actor.build_standard()
}

#[test]
fn installed_actor_executes_inside_the_bundled_runtime() {
    let config = config();
    let mut driver = AgentDriver::create_or_open(
        AGENT_RUNTIME_PVM.to_vec(),
        config.clone(),
        MemoryAgentStore::default(),
    )
    .expect("create agent");
    let actor_pvm = static_actor_pvm();
    let program = ProgramId::of_pvm(&actor_pvm);
    let actor = ActorId::top_level(config.identity.agent, "counter");
    let deployment = DeploymentId([0x44; 32]);
    driver
        .lifecycle(LifecycleRequest::Install(InstallActor {
            entry: ActorEntry {
                actor,
                name: "counter".into(),
                parent: None,
                deployment,
                program,
                lanes: LaneSet::of(vos::agent::StateLane::Linear),
                suspended: false,
            },
            producer: ProducerId([0x55; 32]),
            package: BlobRef::of_bytes(b"signed-counter-package"),
            initial_state: ActorInitialState {
                linear: None,
                merge: None,
                local: None,
            },
            requirements: RuntimeRequirements {
                lanes: LaneSet::of(vos::agent::StateLane::Linear),
                scheduling: false,
                proofs: false,
            },
        }))
        .expect("install actor");

    let reply = driver
        .invoke(ActorInvocation {
            invocation: InvocationId([0x66; 32]),
            actor,
            deployment,
            program,
            mode: MethodMode::Linear,
            message: vec![0x77],
            actor_pvm,
            availability: Vec::new(),
            gas: 10_000_000,
        })
        .expect("invoke actor");
    assert_eq!(reply.status, ActorExecutionStatus::Done);
    assert_eq!(reply.reply, vec![0x63]);
    assert_eq!(driver.image().revision, 3);

    let state = decode_standard_runtime_state(&driver.image().runtime_state).unwrap();
    assert_eq!(
        state.actors[0].lane_state.linear.as_deref(),
        Some(&[0x2a][..])
    );
    assert!(state.actors[0].lane_state.merge.as_deref() == Some(&[][..]));
    assert!(state.actors[0].lane_state.local.as_deref() == Some(&[][..]));
}
