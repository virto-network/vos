use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use vos::agent::authority::{AgentAuthorityBinding, AgentAuthorityClaim, AgentAuthorityReceipt};
use vos::agent::driver::{AgentDriver, AgentDriverError, AgentTrustProvider, FileAgentStore};
use vos::agent::execution::{
    ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
    ActorInvocationAuth,
};
use vos::agent::package::{Ed25519PackageVerifier, Package, PackageManifest};
use vos::agent::{
    AgentConfig, AgentIdentity, AgentProfile, AgentReplica, LifecycleRequest, MethodMode,
    PackageKind, ReplicaRole, RuntimeCapabilities, STANDARD_RUNTIME_PROGRAM_ID, StateLane,
};
use vos::service::{
    ActorId, AgentId, BlobRef, CapabilityId, CredentialId, DeploymentId, DeploymentSignature, Hash,
    InvocationId, NodeId, Origin, PrincipalId, ProducerId, ServiceWire, SpaceId, SubjectId,
    artifact_hash, task_dependencies_hash,
};
use vos::{Decode, Encode};

const AGENT_RUNTIME_PVM: &[u8] = include_bytes!("../blobs/agent_runtime.pvm");

struct TempDir(PathBuf);

const TEST_INVOCATION_AUTHORITY_KEY: &[u8] = b"vos-agent-test-invocation-authority";
const TEST_RUNTIME_PACKAGE_KEY: &[u8] = b"vos-agent-e2e-runtime-package-key";

struct TestTrust;

impl AgentTrustProvider for TestTrust {
    fn current_logical_slot(&self) -> Option<u64> {
        Some(15)
    }

    fn verify_authority(&self, _: &AgentAuthorityBinding, _: &[u8], _: &[u8]) -> bool {
        true
    }

    fn verify_invocation(
        &self,
        agent: &AgentConfig,
        authorization_message: &[u8],
        evidence: &[u8],
    ) -> bool {
        vos::service::Hash::digest(
            b"vos/agent/test-invocation-authorization",
            &[
                TEST_INVOCATION_AUTHORITY_KEY,
                &agent.identity.space.0,
                &agent.identity.agent.0,
                &agent.authority.commitment().0,
                authorization_message,
            ],
        )
        .0 == evidence
    }

    fn verify_package(&self, agent: &AgentConfig, package: &Package) -> bool {
        // This fixture deliberately trusts only the two spaces constructed
        // below. Actor packages still need their real Ed25519 deployment
        // signature; the synthetic runtime package uses a deterministic test
        // signature so caller-controlled, merely well-formed packages are not
        // accidentally treated as trusted provenance.
        if agent.identity.space != SpaceId([3; 32]) && agent.identity.space != SpaceId([0x33; 32]) {
            return false;
        }
        match package.manifest.kind {
            PackageKind::Actor { .. } => package.verify_signature(&Ed25519PackageVerifier).is_ok(),
            PackageKind::AgentRuntime { .. } => {
                package.deployment_signature.public_key == TEST_RUNTIME_PACKAGE_KEY
                    && package.deployment_signature.producer
                        == ProducerId::of_public_key(TEST_RUNTIME_PACKAGE_KEY)
                    && package.deployment_signature.signature == runtime_package_signature(package)
            }
        }
    }
}

fn trust() -> Arc<dyn AgentTrustProvider> {
    Arc::new(TestTrust)
}

fn runtime_package_signature(package: &Package) -> Vec<u8> {
    Hash::digest(
        b"vos/agent/test-runtime-package-signature",
        &[TEST_RUNTIME_PACKAGE_KEY, &package.signing_message()],
    )
    .0
    .to_vec()
}

fn runtime_package() -> Package {
    let interfaces = b"agent-runtime-lifecycle".to_vec();
    let schemas = b"agent-runtime-state".to_vec();
    let mut package = Package {
        manifest: PackageManifest {
            name: "standard-agent-runtime".into(),
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            kind: vos::agent::PackageKind::AgentRuntime {
                abi: vos::agent::RUNTIME_ABI_ID,
                capabilities: RuntimeCapabilities::standard(),
            },
            program: STANDARD_RUNTIME_PROGRAM_ID,
            interfaces_hash: artifact_hash(b"interfaces", &interfaces),
            role_policies_hash: artifact_hash(b"role-policies", &[]),
            schemas_hash: artifact_hash(b"schemas", &schemas),
            agent_schema_hash: artifact_hash(b"agent-schema", &[]),
            dependencies_hash: task_dependencies_hash(&[]),
        },
        pvm: AGENT_RUNTIME_PVM.to_vec(),
        generated_interfaces: interfaces,
        role_policies: Vec::new(),
        schemas,
        agent_schema: Vec::new(),
        task_dependencies: Vec::new(),
        diagnostics: None,
        deployment_signature: DeploymentSignature {
            producer: ProducerId::of_public_key(TEST_RUNTIME_PACKAGE_KEY),
            public_key: TEST_RUNTIME_PACKAGE_KEY.to_vec(),
            signature: Vec::new(),
        },
    };
    package.deployment_signature.signature = runtime_package_signature(&package);
    package
}

fn invocation_evidence(config: &AgentConfig, invocation: &ActorInvocation) -> vos::service::Hash {
    vos::service::Hash::digest(
        b"vos/agent/test-invocation-authorization",
        &[
            TEST_INVOCATION_AUTHORITY_KEY,
            &config.identity.space.0,
            &config.identity.agent.0,
            &config.authority.commitment().0,
            &invocation.authorization_message().0,
        ],
    )
}

fn invoke(
    driver: &mut AgentDriver<FileAgentStore>,
    invocation: ActorInvocation,
) -> Result<ActorExecutionReply, AgentDriverError> {
    let evidence = invocation_evidence(&driver.image().config, &invocation);
    driver.invoke(invocation, &evidence.0)
}

fn acknowledge(
    driver: &mut AgentDriver<FileAgentStore>,
    invocation: ActorInvocation,
) -> Result<(), AgentDriverError> {
    let evidence = invocation_evidence(&driver.image().config, &invocation);
    driver.acknowledge_invocation(invocation, &evidence.0)
}

fn authority_receipt(
    config: &AgentConfig,
    request: &LifecycleRequest,
    capability: &str,
    sequence: u64,
) -> AgentAuthorityReceipt {
    AgentAuthorityReceipt {
        claim: AgentAuthorityClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: config.identity.owner,
            credential: CredentialId([0x33; 32]),
            capability: CapabilityId::named(capability),
            operation: request.commitment(),
            sequence,
            valid_from: 10,
            valid_until: 20,
        },
        signature: vec![1],
    }
}

fn creation_receipt(config: &AgentConfig) -> AgentAuthorityReceipt {
    let request = LifecycleRequest::Create(config.clone());
    let mut receipt = authority_receipt(
        config,
        &request,
        vos::agent::authority::CAPABILITY_AGENT_CREATE_LOCAL,
        1,
    );
    receipt.claim.credential = CredentialId([0x32; 32]);
    receipt
}

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

fn dynamic_no_args(method: &str) -> Vec<u8> {
    let mut payload = vec![vos::value::TAG_DYNAMIC];
    payload.extend_from_slice(&vos::value::Msg::new(method).encode());
    payload
}

fn dynamic_string(method: &str, name: &str, value: String) -> Vec<u8> {
    let mut payload = vec![vos::value::TAG_DYNAMIC];
    payload.extend_from_slice(&vos::value::Msg::new(method).with(name, value).encode());
    payload
}

fn dynamic_task(id: u64, text: String) -> Vec<u8> {
    let mut payload = vec![vos::value::TAG_DYNAMIC];
    payload.extend_from_slice(
        &vos::value::Msg::new("add_task")
            .with("id", id)
            .with("text", text)
            .encode(),
    );
    payload
}

#[test]
fn canonical_actor_package_installs_and_executes_in_an_empty_agent() {
    let temp = TempDir::new("build");
    let out = temp.0.join("dist");
    let config = temp.0.join("config");
    let status = Command::new(env!("CARGO_BIN_EXE_vosx"))
        .args(["agent", "build", "../examples/actors/counter", "--out-dir"])
        .arg(&out)
        .env("XDG_CONFIG_HOME", config)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("run vosx build");
    assert!(status.success());

    let package_bytes = std::fs::read(out.join("Counter.vos")).unwrap();
    assert_eq!(package_bytes.get(..4), Some(b"VOSK".as_slice()));
    let package = Package::decode(&package_bytes).unwrap();
    package.validate().unwrap();
    let PackageKind::Actor { .. } = package.manifest.kind else {
        panic!("counter must be an actor package")
    };

    let wrong_service_build = Command::new(env!("CARGO_BIN_EXE_vosx"))
        .args(["build", "../examples/actors/counter", "--out-dir"])
        .arg(temp.0.join("wrong-service"))
        .env("XDG_CONFIG_HOME", temp.0.join("wrong-service-config"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("reject an agent guest on the service build path");
    assert!(!wrong_service_build.status.success());
    assert!(
        String::from_utf8_lossy(&wrong_service_build.stderr)
            .contains("compiled for AgentActor, but this build requires ServiceActor")
    );

    let owner = PrincipalId([1; 32]);
    let agent = AgentId([2; 32]);
    let runtime = runtime_package();
    let agent_config = AgentConfig {
        identity: AgentIdentity {
            space: SpaceId([3; 32]),
            agent,
            owner,
            profile: AgentProfile::Local,
            runtime_deployment: runtime.deployment_id(),
            runtime_program: runtime.manifest.program,
            runtime_producer: runtime.deployment_signature.producer,
        },
        authority: vos::agent::authority::AgentAuthorityBinding {
            agent: AgentId([7; 32]),
            actor: ActorId([8; 32]),
            deployment: DeploymentId([9; 32]),
            program: vos::service::ProgramId([10; 32]),
            producer: ProducerId::of_public_key(b"authority-key"),
            public_key: b"authority-key".to_vec(),
        },
        runtime_package: BlobRef::of_bytes(&runtime.encode()),
        capabilities: RuntimeCapabilities::standard(),
        replicas: vec![AgentReplica {
            node: NodeId([6; 32]),
            principal: owner,
            role: ReplicaRole::Voter,
        }],
    };
    let image = temp.0.join("counter.agent-image");
    let mut driver = AgentDriver::create(
        runtime,
        agent_config.clone(),
        FileAgentStore::new(&image),
        trust(),
        &creation_receipt(&agent_config),
    )
    .unwrap();
    let actor = ActorId::top_level(agent, "counter");
    let deployment = package.deployment_id();
    let install = driver
        .actor_install_request("counter".into(), None, &package)
        .unwrap();
    let receipt = authority_receipt(
        &agent_config,
        &install,
        vos::agent::authority::CAPABILITY_ACTOR_INSTALL,
        2,
    );
    driver
        .install_actor(&receipt, "counter".into(), None, &package)
        .unwrap();

    let first = ActorInvocation {
        invocation: InvocationId([0x20; 32]),
        actor,
        deployment,
        program: package.manifest.program,
        mode: vos::agent::MethodMode::Linear,
        auth: ActorInvocationAuth::anonymous(),
        message: dynamic_message("increment", "by", 2),
        availability: Vec::new(),
        gas: 1_000_000_000,
    };
    let first_reply = invoke(&mut driver, first.clone()).unwrap();
    assert_eq!(first_reply.status, ActorExecutionStatus::Done);
    assert_eq!(
        vos::value::Value::decode(&first_reply.reply).as_u64(),
        Some(2)
    );
    let committed_revision = driver.image().revision;

    drop(driver);
    let interrupted_stage = image
        .with_extension("agent-catalog")
        .join("packages")
        .join(format!("{}.next", "ff".repeat(32)));
    std::fs::write(&interrupted_stage, b"interrupted package staging").unwrap();
    let mut driver = AgentDriver::open(FileAgentStore::new(&image), trust())
        .expect("reopen agent with its durable actor catalog");
    assert!(
        !interrupted_stage.exists(),
        "reopen reconciles ownerless crash staging"
    );
    assert_eq!(invoke(&mut driver, first.clone()).unwrap(), first_reply);
    assert_eq!(driver.image().revision, committed_revision);

    let mut divergent = first.clone();
    divergent.message = dynamic_message("increment", "by", 99);
    assert_eq!(
        invoke(&mut driver, divergent),
        Err(AgentDriverError::Execution(
            ActorExecutionError::DivergentInvocation
        ))
    );

    acknowledge(&mut driver, first.clone()).unwrap();
    let second = ActorInvocation {
        invocation: InvocationId([0x21; 32]),
        message: dynamic_message("increment", "by", 3),
        ..first
    };
    let second_reply = invoke(&mut driver, second.clone()).unwrap();
    assert_eq!(
        vos::value::Value::decode(&second_reply.reply).as_u64(),
        Some(5)
    );
    acknowledge(&mut driver, second).unwrap();

    let suspend = LifecycleRequest::Suspend(actor);
    let receipt = authority_receipt(
        &agent_config,
        &suspend,
        vos::agent::authority::CAPABILITY_ACTOR_LIFECYCLE,
        3,
    );
    assert!(driver.suspend_actor(&receipt, actor).unwrap().suspended);

    let resume = LifecycleRequest::Resume(actor);
    let receipt = authority_receipt(
        &agent_config,
        &resume,
        vos::agent::authority::CAPABILITY_ACTOR_LIFECYCLE,
        4,
    );
    assert!(!driver.resume_actor(&receipt, actor).unwrap().suspended);

    let remove = LifecycleRequest::RemoveLeaf {
        actor,
        expected_deployment: deployment,
    };
    let receipt = authority_receipt(
        &agent_config,
        &remove,
        vos::agent::authority::CAPABILITY_ACTOR_LIFECYCLE,
        5,
    );
    driver.remove_actor(&receipt, actor, deployment).unwrap();
    assert!(driver.inspect(None, 16).unwrap().entries.is_empty());
    assert!(!driver.catalog_cleanup_pending());
    for kind in ["packages", "programs", "schemas", "policies"] {
        let directory = image.with_extension("agent-catalog").join(kind);
        let expected = usize::from(matches!(kind, "packages" | "programs"));
        assert_eq!(
            std::fs::read_dir(directory).unwrap().count(),
            expected,
            "successful actor removal retires its {kind} artifacts while retaining the runtime closure"
        );
    }
}

#[test]
fn mixed_actor_enforces_signed_modes_and_commits_only_the_owned_lane() {
    let temp = TempDir::new("mixed");
    let out = temp.0.join("dist");
    let config_home = temp.0.join("config");
    let status = Command::new(env!("CARGO_BIN_EXE_vosx"))
        .args([
            "agent",
            "build",
            "../examples/actors/shared-board",
            "--out-dir",
        ])
        .arg(&out)
        .env("XDG_CONFIG_HOME", config_home)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("build the mixed actor package");
    assert!(status.success());

    let status = Command::new(env!("CARGO_BIN_EXE_vosx"))
        .args([
            "agent",
            "build",
            "../tests/fixtures/actors/lane-isolation",
            "--out-dir",
        ])
        .arg(&out)
        .env("XDG_CONFIG_HOME", temp.0.join("isolation-config"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("build the cross-lane adversarial fixture");
    assert!(status.success());

    let package_bytes = std::fs::read(out.join("Board.vos")).unwrap();
    assert_eq!(package_bytes.get(..4), Some(b"VOSK".as_slice()));
    let package = Package::decode(&package_bytes).unwrap();
    package.validate().unwrap();
    let schema = vos::agent::schema::decode(&package.agent_schema).unwrap();
    assert!(schema.lanes().contains(StateLane::Linear));
    assert!(schema.lanes().contains(StateLane::Merge));
    assert!(!schema.lanes().contains(StateLane::Local));
    assert_eq!(schema.method("set_title").unwrap().mode, MethodMode::Linear);
    assert_eq!(schema.method("add_task").unwrap().mode, MethodMode::Merge);
    let metadata = vos::metadata::decode(&package.schemas).expect("public actor metadata");
    let moderator_role = metadata
        .messages
        .iter()
        .find(|method| method.name == "set_title")
        .and_then(|method| method.actor_role)
        .expect("set_title carries the signed moderator gate");

    let owner = PrincipalId([0x31; 32]);
    let agent = AgentId([0x32; 32]);
    let runtime = runtime_package();
    let agent_config = AgentConfig {
        identity: AgentIdentity {
            space: SpaceId([0x33; 32]),
            agent,
            owner,
            profile: AgentProfile::Local,
            runtime_deployment: runtime.deployment_id(),
            runtime_program: runtime.manifest.program,
            runtime_producer: runtime.deployment_signature.producer,
        },
        authority: vos::agent::authority::AgentAuthorityBinding {
            agent: AgentId([0x36; 32]),
            actor: ActorId([0x37; 32]),
            deployment: DeploymentId([0x38; 32]),
            program: vos::service::ProgramId([0x39; 32]),
            producer: ProducerId::of_public_key(b"mixed-authority-key"),
            public_key: b"mixed-authority-key".to_vec(),
        },
        runtime_package: BlobRef::of_bytes(&runtime.encode()),
        capabilities: RuntimeCapabilities::standard(),
        replicas: vec![AgentReplica {
            node: NodeId([0x3a; 32]),
            principal: owner,
            role: ReplicaRole::Voter,
        }],
    };
    let image = temp.0.join("board.agent-image");
    let mut driver = AgentDriver::create(
        runtime,
        agent_config.clone(),
        FileAgentStore::new(&image),
        trust(),
        &creation_receipt(&agent_config),
    )
    .unwrap();
    let actor = ActorId::top_level(agent, "board");
    let deployment = package.deployment_id();
    let install = driver
        .actor_install_request("board".into(), None, &package)
        .unwrap();
    let receipt = authority_receipt(
        &agent_config,
        &install,
        vos::agent::authority::CAPABILITY_ACTOR_INSTALL,
        2,
    );
    driver
        .install_actor(&receipt, "board".into(), None, &package)
        .unwrap();

    let escape_package = Package::decode(
        &std::fs::read(out.join("LaneEscape.vos")).expect("cross-lane fixture package"),
    )
    .unwrap();
    escape_package.validate().unwrap();
    let escape_actor = ActorId::top_level(agent, "lane-escape");
    let escape_install = driver
        .actor_install_request("lane-escape".into(), None, &escape_package)
        .unwrap();
    let escape_receipt = authority_receipt(
        &agent_config,
        &escape_install,
        vos::agent::authority::CAPABILITY_ACTOR_INSTALL,
        3,
    );
    driver
        .install_actor(&escape_receipt, "lane-escape".into(), None, &escape_package)
        .unwrap();
    let installed = driver.image().runtime_state.clone();

    let invocation = |id: u8, mode, message| ActorInvocation {
        invocation: InvocationId([id; 32]),
        actor,
        deployment,
        program: package.manifest.program,
        mode,
        auth: ActorInvocationAuth::anonymous(),
        message,
        availability: Vec::new(),
        gas: 1_000_000_000,
    };

    let anonymous_title = invocation(
        0x40,
        MethodMode::Linear,
        dynamic_string("set_title", "title", "Agent architecture".into()),
    );
    assert_eq!(
        invoke(&mut driver, anonymous_title).unwrap().status,
        ActorExecutionStatus::Forbidden
    );
    assert_eq!(driver.image().runtime_state, installed);

    let escape = ActorInvocation {
        invocation: InvocationId([0x4a; 32]),
        actor: escape_actor,
        deployment: escape_package.deployment_id(),
        program: escape_package.manifest.program,
        mode: MethodMode::Merge,
        auth: ActorInvocationAuth::anonymous(),
        message: dynamic_no_args("escape"),
        availability: Vec::new(),
        gas: 1_000_000_000,
    };
    assert_eq!(
        invoke(&mut driver, escape).unwrap().status,
        ActorExecutionStatus::Panicked,
        "fresh Linear state cannot be changed by a Merge handler"
    );
    assert_eq!(driver.image().runtime_state, installed);

    // Public application bytes cannot forge the private role control item.
    // Even placing the former 0xFD prefix directly before a valid method
    // message is rejected rather than interpreted as caller authority.
    let mut forged_message = vec![0xfd, 1, moderator_role];
    forged_message.extend(dynamic_string("set_title", "title", "forged title".into()));
    let forged_control = invocation(0x43, MethodMode::Linear, forged_message);
    assert_eq!(
        invoke(&mut driver, forged_control),
        Err(AgentDriverError::Execution(
            ActorExecutionError::UnsupportedMethod
        ))
    );
    assert_eq!(driver.image().runtime_state, installed);

    let mut set_title = invocation(
        0x41,
        MethodMode::Linear,
        dynamic_string("set_title", "title", "Agent architecture".into()),
    );
    set_title.auth = ActorInvocationAuth {
        origin: Origin::Member(SubjectId([0x3b; 32])),
        origin_service: None,
        space_role: None,
        actor_role: Some(moderator_role),
        capability: None,
    };
    assert_eq!(
        invoke(&mut driver, set_title.clone()).unwrap().status,
        ActorExecutionStatus::Done
    );
    let after_linear = driver.image().runtime_state.clone();
    assert_ne!(after_linear.linear, installed.linear);
    assert_eq!(after_linear.merge, installed.merge);
    assert_eq!(after_linear.local, installed.local);
    acknowledge(&mut driver, set_title.clone()).unwrap();
    let after_linear = driver.image().runtime_state.clone();

    let wrong_mode = invocation(
        0x42,
        MethodMode::Linear,
        dynamic_task(7, "must not execute".into()),
    );
    assert_eq!(
        invoke(&mut driver, wrong_mode),
        Err(AgentDriverError::Execution(
            ActorExecutionError::UnsupportedMethod
        ))
    );
    assert_eq!(driver.image().runtime_state, after_linear);

    // Correct method name but incomplete arguments reaches the actor guest;
    // a skipped typed dispatch must fail without committing a lane.
    let wrong_arguments = invocation(
        0x44,
        MethodMode::Merge,
        dynamic_message("add_task", "id", 9),
    );
    let revision = driver.image().revision;
    assert_eq!(
        invoke(&mut driver, wrong_arguments).unwrap().status,
        ActorExecutionStatus::Panicked
    );
    assert_eq!(driver.image().revision, revision);
    assert_eq!(driver.image().runtime_state, after_linear);

    let add_task = invocation(
        0x45,
        MethodMode::Merge,
        dynamic_task(1, "A task large enough to cross the FETCH probe".repeat(32)),
    );
    let add_task_reply = invoke(&mut driver, add_task.clone()).unwrap();
    assert_eq!(add_task_reply.status, ActorExecutionStatus::Done);
    assert_eq!(
        vos::value::Value::decode(&add_task_reply.reply).as_str(),
        Some("Agent architecture"),
        "Merge execution reads the non-default pinned Linear lane"
    );
    let after_merge = driver.image().runtime_state.clone();
    assert_eq!(after_merge.linear, after_linear.linear);
    assert_ne!(after_merge.merge, after_linear.merge);
    assert_eq!(after_merge.local, after_linear.local);
    acknowledge(&mut driver, add_task.clone()).unwrap();
    let after_merge = driver.image().runtime_state.clone();

    let edit_count = invocation(0x46, MethodMode::Query, dynamic_no_args("edit_count"));
    assert_eq!(
        vos::value::Value::decode(&invoke(&mut driver, edit_count).unwrap().reply,).as_i64(),
        Some(1)
    );
    assert_eq!(driver.image().runtime_state, after_merge);

    let committed_revision = driver.image().revision;

    drop(driver);
    let mut driver = AgentDriver::open(FileAgentStore::new(&image), trust())
        .expect("reopen both replicated lanes and deployment schema");
    assert_eq!(driver.image().revision, committed_revision);

    let title = invocation(0x47, MethodMode::Query, dynamic_no_args("title"));
    assert_eq!(
        vos::value::Value::decode(&invoke(&mut driver, title).unwrap().reply,).as_str(),
        Some("Agent architecture")
    );
}
