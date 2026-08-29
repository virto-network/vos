use std::path::PathBuf;
use std::process::Command;

use vos::agent::driver::{AgentDriver, AgentDriverError, FileAgentStore};
use vos::agent::execution::{ActorExecutionError, ActorExecutionStatus, ActorInvocation};
use vos::agent::package::{Ed25519PackageVerifier, Package};
use vos::agent::{
    ActorInitialState, AgentConfig, AgentIdentity, AgentProfile, AgentReplica, PackageKind,
    ReplicaRole, RuntimeCapabilities, STANDARD_RUNTIME_PROGRAM_ID,
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
    let verified = package.clone().verify(&Ed25519PackageVerifier).unwrap();
    let PackageKind::Actor { .. } = package.manifest.kind else {
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
    let image = temp.0.join("counter.agent-image");
    let mut driver = AgentDriver::create_or_open(
        AGENT_RUNTIME_PVM.to_vec(),
        agent_config.clone(),
        FileAgentStore::new(&image),
    )
    .unwrap();
    let actor = ActorId::top_level(agent, "counter");
    let deployment = package.deployment_id();
    driver
        .install_actor(
            "counter".into(),
            None,
            &verified,
            ActorInitialState {
                linear: None,
                merge: None,
                local: None,
            },
        )
        .unwrap();

    let first = ActorInvocation {
        invocation: InvocationId([0x20; 32]),
        actor,
        deployment,
        program: package.manifest.program,
        mode: vos::agent::MethodMode::Linear,
        message: dynamic_message("increment", "by", 2),
        availability: Vec::new(),
        gas: 1_000_000_000,
    };
    let first_reply = driver.invoke(first.clone()).unwrap();
    assert_eq!(first_reply.status, ActorExecutionStatus::Done);
    assert_eq!(
        vos::value::Value::decode(&first_reply.reply).as_u64(),
        Some(2)
    );
    let committed_revision = driver.image().revision;

    drop(driver);
    let mut driver = AgentDriver::create_or_open(
        AGENT_RUNTIME_PVM.to_vec(),
        agent_config.clone(),
        FileAgentStore::new(&image),
    )
    .expect("reopen agent with its durable actor catalog");
    assert_eq!(driver.invoke(first.clone()).unwrap(), first_reply);
    assert_eq!(driver.image().revision, committed_revision);

    let mut divergent = first.clone();
    divergent.message = dynamic_message("increment", "by", 99);
    assert_eq!(
        driver.invoke(divergent),
        Err(AgentDriverError::Execution(
            ActorExecutionError::DivergentInvocation
        ))
    );

    driver.acknowledge_invocation(&first).unwrap();
    let second = ActorInvocation {
        invocation: InvocationId([0x21; 32]),
        message: dynamic_message("increment", "by", 3),
        ..first
    };
    let second_reply = driver.invoke(second).unwrap();
    assert_eq!(
        vos::value::Value::decode(&second_reply.reply).as_u64(),
        Some(5)
    );
}
