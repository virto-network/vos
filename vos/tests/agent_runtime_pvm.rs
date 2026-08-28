use vos::agent::driver::{AgentDriver, MemoryAgentStore};
use vos::agent::wire::{RuntimeCall, RuntimeReturn};
use vos::agent::{
    AgentConfig, AgentIdentity, AgentProfile, AgentReplica, LifecycleReply, LifecycleRequest,
    ReplicaRole, RuntimeCapabilities, STANDARD_RUNTIME_PROGRAM_ID,
};
use vos::service::{
    AgentId, BlobRef, DeploymentId, Hash, NodeId, PrincipalId, ProducerId, ProgramId, ServiceWire,
    SpaceId,
};
use vos_pvm::ExitReason;
use vos_pvm::refine_host::RefineContext;

const AGENT_RUNTIME_PVM: &[u8] = include_bytes!("../../vosx/blobs/agent_runtime.pvm");
const GAS: u64 = 1_000_000_000;

fn config() -> AgentConfig {
    let owner = PrincipalId([1; 32]);
    AgentConfig {
        identity: AgentIdentity {
            space: SpaceId([2; 32]),
            agent: AgentId([3; 32]),
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
        state: Vec::new(),
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
