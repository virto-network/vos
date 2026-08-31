use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use vos::agent::authority::{
    ActorInvocationClaim, ActorInvocationReceipt, AgentAuthorityBinding, AgentAuthorityClaim,
    AgentAuthorityReceipt, ed25519_public_key_wire,
};
use vos::agent::contract::RuntimePackageContract;
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

const TEST_RUNTIME_PACKAGE_KEY: &[u8] = b"vos-agent-e2e-runtime-package-key";
const TEST_AUTHORITY_SEED: [u8; 32] = [0x43; 32];

struct TestTrust;

impl AgentTrustProvider for TestTrust {
    fn current_logical_slot(&self) -> Option<u64> {
        Some(15)
    }

    fn authority_for_space(&self, space: SpaceId) -> Option<AgentAuthorityBinding> {
        match space {
            SpaceId(value) if value == [3; 32] => Some(authority_binding(
                AgentId([7; 32]),
                ActorId([8; 32]),
                DeploymentId([9; 32]),
                vos::service::ProgramId([10; 32]),
            )),
            SpaceId(value) if value == [0x33; 32] => Some(authority_binding(
                AgentId([0x36; 32]),
                ActorId([0x37; 32]),
                DeploymentId([0x38; 32]),
                vos::service::ProgramId([0x39; 32]),
            )),
            _ => None,
        }
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
            execution_semantics: vos::agent::EXECUTION_SEMANTICS_ID,
            kind: vos::agent::PackageKind::AgentRuntime {
                contract: RuntimePackageContract::canonical(),
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

fn authority_signing_key() -> SigningKey {
    SigningKey::from_bytes(&TEST_AUTHORITY_SEED)
}

fn authority_binding(
    agent: AgentId,
    actor: ActorId,
    deployment: DeploymentId,
    program: vos::service::ProgramId,
) -> AgentAuthorityBinding {
    let key = authority_signing_key();
    let public_key = ed25519_public_key_wire(key.verifying_key().to_bytes());
    AgentAuthorityBinding {
        agent,
        actor,
        deployment,
        program,
        producer: ProducerId::of_public_key(&public_key),
        public_key,
    }
}

fn invocation_receipt(
    config: &AgentConfig,
    invocation: &ActorInvocation,
) -> ActorInvocationReceipt {
    let key = authority_signing_key();
    let claim = ActorInvocationClaim {
        authority: config.authority.clone(),
        space: config.identity.space,
        agent: config.identity.agent,
        principal: invocation.auth.principal,
        credential: invocation.auth.principal.map(|_| CredentialId([0x34; 32])),
        authorization: invocation.authorization_message(),
        auth: invocation.auth.clone(),
        valid_from: 10,
        valid_until: 20,
    };
    ActorInvocationReceipt {
        signature: key.sign(&claim.signing_message().0).to_bytes().to_vec(),
        claim,
    }
}

fn invoke(
    driver: &mut AgentDriver<FileAgentStore>,
    invocation: ActorInvocation,
) -> Result<ActorExecutionReply, AgentDriverError> {
    let receipt = invocation_receipt(&driver.image().config, &invocation);
    driver.invoke(invocation, &receipt)
}

fn acknowledge(
    driver: &mut AgentDriver<FileAgentStore>,
    invocation: ActorInvocation,
) -> Result<(), AgentDriverError> {
    let receipt = invocation_receipt(&driver.image().config, &invocation);
    driver.acknowledge_invocation(invocation, &receipt)
}

fn installed_incarnation(
    driver: &mut AgentDriver<FileAgentStore>,
    actor: ActorId,
    deployment: DeploymentId,
) -> Hash {
    let page = driver
        .inspect(None, 1)
        .expect("inspect the fixture's installed actor");
    assert_eq!(page.next, None, "the fixture installs exactly one actor");
    let record = page
        .entries
        .into_iter()
        .next()
        .expect("the installed actor is present in the guest directory");
    assert_eq!(record.entry.actor, actor);
    assert_eq!(record.entry.deployment, deployment);
    record.incarnation
}

fn authority_receipt(
    config: &AgentConfig,
    request: &LifecycleRequest,
    capability: &str,
    sequence: u64,
) -> AgentAuthorityReceipt {
    let key = authority_signing_key();
    let claim = AgentAuthorityClaim {
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
    };
    AgentAuthorityReceipt {
        signature: key.sign(&claim.signing_message().0).to_bytes().to_vec(),
        claim,
    }
}

fn creation_receipt(config: &AgentConfig) -> AgentAuthorityReceipt {
    let request = LifecycleRequest::Create(config.clone());
    authority_receipt(
        config,
        &request,
        vos::agent::authority::CAPABILITY_AGENT_CREATE_LOCAL,
        1,
    )
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
    let space = SpaceId([3; 32]);
    let creation_nonce = Hash([2; 32]);
    let agent = AgentId::derive(space, owner, &creation_nonce.0);
    let runtime = runtime_package();
    let agent_config = AgentConfig {
        identity: AgentIdentity {
            space,
            agent,
            owner,
            profile: AgentProfile::Local,
            runtime_deployment: runtime.deployment_id(),
            runtime_program: runtime.manifest.program,
            runtime_producer: runtime.deployment_signature.producer,
        },
        creation_nonce,
        authority: authority_binding(
            AgentId([7; 32]),
            ActorId([8; 32]),
            DeploymentId([9; 32]),
            vos::service::ProgramId([10; 32]),
        ),
        runtime_package: BlobRef::of_bytes(&runtime.encode()),
        runtime_contract: RuntimePackageContract::canonical(),
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
    let incarnation = installed_incarnation(&mut driver, actor, deployment);

    let first = ActorInvocation {
        invocation: InvocationId([0x20; 32]),
        actor,
        incarnation,
        deployment,
        program: package.manifest.program,
        mode: vos::agent::MethodMode::Linear,
        auth: ActorInvocationAuth {
            origin: Origin::Member(SubjectId([0x11; 32])),
            principal: Some(owner),
            origin_service: None,
            space_role: None,
            actor_role: None,
            capability: None,
        },
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

    let suspend = LifecycleRequest::Suspend {
        actor,
        expected_deployment: deployment,
    };
    let receipt = authority_receipt(
        &agent_config,
        &suspend,
        vos::agent::authority::CAPABILITY_ACTOR_LIFECYCLE,
        3,
    );
    assert!(driver.suspend_actor(&receipt, actor).unwrap().suspended);

    let resume = LifecycleRequest::Resume {
        actor,
        expected_deployment: deployment,
    };
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

    let isolation = Command::new(env!("CARGO_BIN_EXE_vosx"))
        .args([
            "agent",
            "build",
            "../tests/fixtures/actors/lane-isolation",
            "--out-dir",
        ])
        .arg(&out)
        .env("XDG_CONFIG_HOME", temp.0.join("isolation-config"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("reject the cross-lane adversarial fixture");
    assert!(!isolation.status.success());
    let isolation_error = String::from_utf8_lossy(&isolation.stderr);
    assert!(
        isolation_error.contains("no field `linear`")
            && isolation_error.contains("no field `private`"),
        "lane-specific views must reject both Merge→Linear and Query→Local access: {isolation_error}"
    );

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
    let space = SpaceId([0x33; 32]);
    let creation_nonce = Hash([0x32; 32]);
    let agent = AgentId::derive(space, owner, &creation_nonce.0);
    let runtime = runtime_package();
    let agent_config = AgentConfig {
        identity: AgentIdentity {
            space,
            agent,
            owner,
            profile: AgentProfile::Local,
            runtime_deployment: runtime.deployment_id(),
            runtime_program: runtime.manifest.program,
            runtime_producer: runtime.deployment_signature.producer,
        },
        creation_nonce,
        authority: authority_binding(
            AgentId([0x36; 32]),
            ActorId([0x37; 32]),
            DeploymentId([0x38; 32]),
            vos::service::ProgramId([0x39; 32]),
        ),
        runtime_package: BlobRef::of_bytes(&runtime.encode()),
        runtime_contract: RuntimePackageContract::canonical(),
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
    let incarnation = installed_incarnation(&mut driver, actor, deployment);

    let installed = driver.image().runtime_state.clone();

    let invocation = |id: u8, mode, message| ActorInvocation {
        invocation: InvocationId([id; 32]),
        actor,
        incarnation,
        deployment,
        program: package.manifest.program,
        mode,
        auth: ActorInvocationAuth {
            origin: Origin::Member(SubjectId([0x3b; 32])),
            principal: Some(owner),
            origin_service: None,
            space_role: None,
            actor_role: None,
            capability: None,
        },
        message,
        availability: Vec::new(),
        gas: 1_000_000_000,
    };

    let anonymous_title = invocation(
        0x40,
        MethodMode::Linear,
        dynamic_string("set_title", "title", "Agent architecture".into()),
    );
    let revision = driver.image().revision;
    assert_eq!(
        invoke(&mut driver, anonymous_title).unwrap().status,
        ActorExecutionStatus::Forbidden
    );
    assert_eq!(driver.image().revision, revision + 1);
    let after_forbidden = driver.image().runtime_state.clone();
    assert_eq!(after_forbidden.control, installed.control);
    assert_ne!(after_forbidden.linear, installed.linear);
    assert_eq!(after_forbidden.merge, installed.merge);
    assert_eq!(after_forbidden.local, installed.local);

    // Public application bytes cannot forge the private role control item.
    // Even placing the former 0xFD prefix directly before a valid method
    // message is rejected rather than interpreted as caller authority.
    let mut forged_message = vec![0xfd, 1, moderator_role];
    forged_message.extend(dynamic_string("set_title", "title", "forged title".into()));
    let forged_control = invocation(0x43, MethodMode::Linear, forged_message);
    let revision = driver.image().revision;
    assert_eq!(
        invoke(&mut driver, forged_control),
        Err(AgentDriverError::Execution(
            ActorExecutionError::UnsupportedMethod
        ))
    );
    assert_eq!(driver.image().revision, revision);
    assert_eq!(driver.image().runtime_state, after_forbidden);

    let mut set_title = invocation(
        0x41,
        MethodMode::Linear,
        dynamic_string("set_title", "title", "Agent architecture".into()),
    );
    set_title.auth = ActorInvocationAuth {
        origin: Origin::Member(SubjectId([0x3b; 32])),
        principal: Some(vos::service::PrincipalId([0x3c; 32])),
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
    assert_eq!(after_linear.control, after_forbidden.control);
    assert_ne!(after_linear.linear, after_forbidden.linear);
    assert_eq!(after_linear.merge, after_forbidden.merge);
    assert_eq!(after_linear.local, after_forbidden.local);
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

    // Correct method name but incomplete arguments reaches the actor guest.
    // The durable Panicked outcome advances only its owning Merge result
    // component; it cannot commit a candidate in any other component.
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
    assert_eq!(driver.image().revision, revision + 1);
    let after_panicked = driver.image().runtime_state.clone();
    assert_eq!(after_panicked.control, after_linear.control);
    assert_eq!(after_panicked.linear, after_linear.linear);
    assert_ne!(after_panicked.merge, after_linear.merge);
    assert_eq!(after_panicked.local, after_linear.local);

    let task_text = "A task large enough to cross the FETCH probe".repeat(32);
    let add_task = invocation(0x45, MethodMode::Merge, dynamic_task(1, task_text.clone()));
    let add_task_reply = invoke(&mut driver, add_task.clone()).unwrap();
    assert_eq!(add_task_reply.status, ActorExecutionStatus::Done);
    assert_eq!(
        vos::value::Value::decode(&add_task_reply.reply).as_str(),
        Some(task_text.as_str()),
        "Merge execution can return only data available through its Merge view"
    );
    let after_merge = driver.image().runtime_state.clone();
    assert_eq!(after_merge.control, after_panicked.control);
    assert_eq!(after_merge.linear, after_panicked.linear);
    assert_ne!(after_merge.merge, after_panicked.merge);
    assert_eq!(after_merge.local, after_panicked.local);
    acknowledge(&mut driver, add_task.clone()).unwrap();
    let after_merge = driver.image().runtime_state.clone();

    let edit_count = invocation(0x46, MethodMode::Query, dynamic_no_args("edit_count"));
    let edit_count_reply = invoke(&mut driver, edit_count.clone()).unwrap();
    assert_eq!(
        vos::value::Value::decode(&edit_count_reply.reply).as_i64(),
        Some(1)
    );
    assert_eq!(
        invoke(&mut driver, edit_count.clone()).unwrap(),
        edit_count_reply,
        "a coherent query retry returns its guest-owned exact result"
    );
    let after_query = driver.image().runtime_state.clone();
    assert_ne!(after_query.control, after_merge.control);
    assert_eq!(after_query.linear, after_merge.linear);
    assert_eq!(after_query.merge, after_merge.merge);
    assert_eq!(after_query.local, after_merge.local);
    acknowledge(&mut driver, edit_count).unwrap();

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
