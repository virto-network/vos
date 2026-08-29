use std::path::PathBuf;
use std::process::Command;

use vos::agent::driver::{AgentDriver, MemoryAgentStore};
use vos::agent::execution::{ActorExecutionStatus, ActorInvocation};
use vos::agent::package::Package;
use vos::agent::{
    ActorEntry, ActorInitialState, AgentConfig, AgentIdentity, AgentProfile, AgentReplica,
    InstallActor, LifecycleRequest, PackageKind, ReplicaRole, RuntimeCapabilities,
    STANDARD_RUNTIME_PROGRAM_ID,
};
use vos::service::{
    ActorId, AgentId, BlobRef, DeploymentId, InvocationId, NodeId, PrincipalId, ProducerId,
    ServiceWire, SpaceId,
};
use vos::{Decode, Encode};

const AGENT_RUNTIME_PVM: &[u8] = include_bytes!("../blobs/agent_runtime.pvm");

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "vosx-agent-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn dynamic_message(method: &str, name: &str, value: u64) -> Vec<u8> {
    let encoded = vos::value::Msg::new(method).with(name, value).encode();
    let mut payload = vec![vos::value::TAG_DYNAMIC];
    payload.extend_from_slice(&encoded);
    payload
}

#[test]
fn canonical_actor_package_installs_and_executes_in_an_empty_agent() {
    let temp = TempDir::new("build");
    let out = temp.0.join("dist");
    let config = temp.0.join("config");
    let status = Command::new(env!("CARGO_BIN_EXE_vosx"))
        .args(["build", "../examples/actors/counter", "--out-dir"])
        .arg(&out)
        .env("XDG_CONFIG_HOME", config)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("run vosx build");
    assert!(status.success());

    let package_bytes = std::fs::read(out.join("Counter.vos")).unwrap();
    let package = Package::decode(&package_bytes).unwrap();
    package.validate().unwrap();
    let PackageKind::Actor { requirements } = package.manifest.kind else {
        panic!("counter must be an actor package")
    };

    let owner = PrincipalId([1; 32]);
    let agent = AgentId([2; 32]);
    let agent_config = AgentConfig {
        identity: AgentIdentity {
            space: SpaceId([3; 32]),
            agent,
            owner,
            profile: AgentProfile::Local,
            runtime_deployment: DeploymentId([4; 32]),
            runtime_program: STANDARD_RUNTIME_PROGRAM_ID,
            runtime_producer: ProducerId([5; 32]),
        },
        runtime_package: BlobRef::of_bytes(AGENT_RUNTIME_PVM),
        capabilities: RuntimeCapabilities::standard(),
        replicas: vec![AgentReplica {
            node: NodeId([6; 32]),
            principal: owner,
            role: ReplicaRole::Voter,
        }],
    };
    let mut driver = AgentDriver::create_or_open(
        AGENT_RUNTIME_PVM.to_vec(),
        agent_config,
        MemoryAgentStore::default(),
    )
    .unwrap();
    let actor = ActorId::top_level(agent, "counter");
    let deployment = package.deployment_id();
    driver
        .lifecycle(LifecycleRequest::Install(InstallActor {
            entry: ActorEntry {
                actor,
                name: "counter".into(),
                parent: None,
                deployment,
                program: package.manifest.program,
                lanes: requirements.lanes,
                suspended: false,
            },
            producer: package.deployment_signature.producer,
            package: BlobRef::of_bytes(&package_bytes),
            initial_state: ActorInitialState {
                linear: None,
                merge: None,
                local: None,
            },
            requirements,
        }))
        .unwrap();

    for (index, (by, expected)) in [(2, 2), (3, 5)].into_iter().enumerate() {
        let reply = driver
            .invoke(ActorInvocation {
                invocation: InvocationId([0x20 + index as u8; 32]),
                actor,
                deployment,
                program: package.manifest.program,
                mode: vos::agent::MethodMode::Linear,
                message: dynamic_message("increment", "by", by),
                actor_pvm: package.pvm.clone(),
                availability: Vec::new(),
                gas: 1_000_000_000,
            })
            .unwrap();
        assert_eq!(reply.status, ActorExecutionStatus::Done);
        assert_eq!(
            vos::value::Value::decode(&reply.reply).as_u64(),
            Some(expected)
        );
    }
}
