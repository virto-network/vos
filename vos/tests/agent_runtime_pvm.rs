use std::sync::Arc;

use vos::Encode as _;
use vos::agent::authority::{AgentAuthorityBinding, AgentAuthorityClaim, AgentAuthorityReceipt};
use vos::agent::driver::{
    AgentDriver, AgentDriverError, AgentImage, AgentImageStore, AgentTrustProvider,
    MemoryAgentStore,
};
use vos::agent::execution::{
    ActorExecutionError, ActorExecutionStatus, ActorInvocation, ActorInvocationAuth,
    ActorInvocationVerificationError, MAX_EXECUTION_GAS,
};
use vos::agent::host::AgentHost;
use vos::agent::package::{Package, PackageManifest, PackageSignatureVerifier};
use vos::agent::wire::{RuntimeCall, RuntimeReturn, RuntimeState, decode_standard_runtime_state};
use vos::agent::{
    ActorEntry, AgentConfig, AgentIdentity, AgentProfile, AgentReplica, InstallActor, LaneSet,
    LifecycleReply, LifecycleRequest, MethodMode, ReplicaRole, RuntimeCapabilities,
    RuntimeRequirements, STANDARD_RUNTIME_PROGRAM_ID,
};
use vos::service::{
    ActorId, AgentId, BlobRef, CapabilityId, CredentialId, DeploymentId, DeploymentSignature, Hash,
    InvocationId, MethodPolicy, NodeId, PackageRolePolicies, PrincipalId, ProducerId, ProgramId,
    ServiceWire, SpaceId, artifact_hash, task_dependencies_hash,
};
use vos_pvm::ExitReason;
use vos_pvm::refine_host::RefineContext;

const AGENT_RUNTIME_PVM: &[u8] = include_bytes!("../../vosx/blobs/agent_runtime.pvm");
const GAS: u64 = 1_000_000_000;

const TEST_INVOCATION_AUTHORITY_KEY: &[u8] = b"vos-agent-test-invocation-authority";
const TEST_PACKAGE_KEY: &[u8] = b"vos-agent-test-package-key";

struct TestTrust;

impl AgentTrustProvider for TestTrust {
    fn current_logical_slot(&self) -> Option<u64> {
        Some(1)
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
        Hash::digest(
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
        package.deployment_signature.public_key == TEST_PACKAGE_KEY
            && package.deployment_signature.producer == ProducerId::of_public_key(TEST_PACKAGE_KEY)
            && package.deployment_signature.signature == package_signature(package)
            && agent.identity.space == SpaceId([2; 32])
    }
}

fn trust() -> Arc<dyn AgentTrustProvider> {
    Arc::new(TestTrust)
}

fn invocation_evidence(config: &AgentConfig, invocation: &ActorInvocation) -> Hash {
    Hash::digest(
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

fn package_signature(package: &Package) -> Vec<u8> {
    Hash::digest(
        b"vos/agent/test-package-signature",
        &[TEST_PACKAGE_KEY, &package.signing_message()],
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
            producer: ProducerId::of_public_key(TEST_PACKAGE_KEY),
            public_key: TEST_PACKAGE_KEY.to_vec(),
            signature: Vec::new(),
        },
    };
    package.deployment_signature.signature = package_signature(&package);
    package
}

fn replacement_runtime_package() -> Package {
    let mut package = runtime_package();
    package.manifest.name = "custom-agent-runtime".into();
    package.deployment_signature.signature = package_signature(&package);
    package
}

fn creation_receipt(config: &AgentConfig) -> AgentAuthorityReceipt {
    let request = LifecycleRequest::Create(config.clone());
    lifecycle_receipt(
        config,
        vos::agent::authority::CAPABILITY_AGENT_CREATE_LOCAL,
        &request,
        1,
    )
}

fn lifecycle_receipt(
    config: &AgentConfig,
    capability: &str,
    request: &LifecycleRequest,
    sequence: u64,
) -> AgentAuthorityReceipt {
    AgentAuthorityReceipt {
        claim: AgentAuthorityClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: config.identity.owner,
            credential: CredentialId([0x71; 32]),
            capability: CapabilityId::named(capability),
            operation: request.commitment(),
            sequence,
            valid_from: 1,
            valid_until: 2,
        },
        signature: vec![1],
    }
}

fn config_for(agent: AgentId) -> AgentConfig {
    let owner = PrincipalId([1; 32]);
    let runtime = runtime_package();
    AgentConfig {
        identity: AgentIdentity {
            space: SpaceId([2; 32]),
            agent,
            owner,
            profile: AgentProfile::Local,
            runtime_deployment: runtime.deployment_id(),
            runtime_program: runtime.manifest.program,
            runtime_producer: runtime.deployment_signature.producer,
        },
        authority: vos::agent::authority::AgentAuthorityBinding {
            agent: AgentId([8; 32]),
            actor: ActorId([9; 32]),
            deployment: DeploymentId([10; 32]),
            program: ProgramId([11; 32]),
            producer: ProducerId::of_public_key(b"authority-key"),
            public_key: b"authority-key".to_vec(),
        },
        runtime_package: BlobRef::of_bytes(&runtime.encode()),
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
    let mut driver = AgentDriver::create(
        runtime_package(),
        config.clone(),
        MemoryAgentStore::default(),
        trust(),
        &creation_receipt(&config),
    )
    .expect("create agent");
    assert_eq!(driver.image().revision, 1);
    assert_eq!(
        driver.inspect(None, 16).expect("inspect agent"),
        vos::agent::ActorDirectoryPage {
            entries: Vec::new(),
            next: None,
        }
    );
    assert_eq!(driver.image().revision, 1, "inspection is not a commit");

    let store = driver.into_store();
    let reopened = AgentDriver::open(store, trust()).expect("reopen agent");
    assert_eq!(reopened.image().revision, 1);
}

#[test]
fn durable_creation_ignores_caller_selected_package_verifiers() {
    struct PermissiveVerifier;
    impl PackageSignatureVerifier for PermissiveVerifier {
        fn verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool {
            true
        }
    }

    let mut package = runtime_package();
    package.deployment_signature.signature = vec![0xff];
    assert!(
        package.verify_signature(&PermissiveVerifier).is_ok(),
        "an offline caller can select a permissive verifier"
    );
    let mut config = config();
    config.runtime_package = BlobRef::of_bytes(&package.encode());
    assert!(matches!(
        AgentDriver::create(
            package,
            config.clone(),
            MemoryAgentStore::default(),
            trust(),
            &creation_receipt(&config),
        ),
        Err(AgentDriverError::Package(
            vos::agent::package::PackageError::InvalidSignature
        ))
    ));
}

#[test]
fn reopen_requires_the_exact_runtime_catalog_closure() {
    let config = config();
    let driver = AgentDriver::create(
        runtime_package(),
        config.clone(),
        MemoryAgentStore::default(),
        trust(),
        &creation_receipt(&config),
    )
    .expect("create agent");
    let store = driver.into_store();

    let mut missing_package = store.clone();
    missing_package
        .remove_package(&config.runtime_package)
        .unwrap();
    assert!(matches!(
        AgentDriver::open(missing_package, trust()),
        Err(AgentDriverError::PackageUnavailable(hash)) if hash == config.runtime_package.hash
    ));

    let mut missing_program = store.clone();
    missing_program
        .remove_program(config.identity.runtime_program)
        .unwrap();
    assert!(matches!(
        AgentDriver::open(missing_program, trust()),
        Err(AgentDriverError::ProgramUnavailable(program))
            if program == config.identity.runtime_program
    ));

    AgentDriver::open(store, trust()).expect("complete closure reopens");
}

#[test]
fn custom_runtime_upgrade_is_catalogued_and_reopens_without_a_host_source() {
    let config = config();
    let mut driver = AgentDriver::create(
        runtime_package(),
        config.clone(),
        MemoryAgentStore::default(),
        trust(),
        &creation_receipt(&config),
    )
    .expect("create agent");
    let replacement = replacement_runtime_package();
    let request = driver
        .runtime_upgrade_request(config.identity.runtime_deployment, &replacement)
        .expect("construct exact runtime upgrade");
    let receipt = lifecycle_receipt(
        &config,
        vos::agent::authority::CAPABILITY_AGENT_RUNTIME_UPGRADE,
        &request,
        2,
    );
    let identity = driver
        .upgrade_runtime(&receipt, config.identity.runtime_deployment, &replacement)
        .expect("upgrade runtime");
    assert_eq!(identity.runtime_deployment, replacement.deployment_id());
    assert_eq!(
        driver.image().config.runtime_package,
        BlobRef::of_bytes(&replacement.encode())
    );

    let store = driver.into_store();
    let reopened = AgentDriver::open(store, trust()).expect("reopen upgraded runtime");
    assert_eq!(reopened.image().config.identity, identity);
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
    let mut host = AgentHost::open(&directory, trust()).expect("open empty agent host");
    let first = AgentId([0x31; 32]);
    let second = AgentId([0x32; 32]);
    let first_config = config_for(first);
    let second_config = config_for(second);
    host.create(
        first_config.clone(),
        runtime_package(),
        &creation_receipt(&first_config),
    )
    .expect("create first agent");
    host.create(
        second_config.clone(),
        runtime_package(),
        &creation_receipt(&second_config),
    )
    .expect("create second agent");
    assert_eq!(host.len(), 2);
    assert_eq!(
        host.identities()
            .map(|identity| identity.agent)
            .collect::<Vec<_>>(),
        vec![first, second]
    );
    drop(host);

    let reopened = AgentHost::open(&directory, trust()).expect("reopen agent host");
    assert_eq!(reopened.len(), 2);
    assert_eq!(reopened.revision(first), Some(1));
    assert_eq!(reopened.revision(second), Some(1));
}

fn static_actor_pvm() -> Vec<u8> {
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    // Actor output: Done, linear/merge/local lengths, one linear-state byte,
    // then one reply byte.
    let output = vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2a, 0x63];
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
    let actor_pvm = static_actor_pvm();
    let program = ProgramId::of_pvm(&actor_pvm);
    let driver = AgentDriver::create(
        runtime_package(),
        config.clone(),
        MemoryAgentStore::default(),
        trust(),
        &creation_receipt(&config),
    )
    .expect("create agent");
    let actor = ActorId::top_level(config.identity.agent, "counter");
    let deployment = DeploymentId([0x44; 32]);
    let (schema, schema_len) = vos::agent::schema::encode::<512>(&vos::agent::schema::SchemaMeta {
        uses_storage: false,
        fields: &[vos::agent::schema::FieldMeta {
            name: "value",
            codec: "u8",
            persistence: vos::agent::FieldPersistence::State(vos::agent::StateLane::Linear),
        }],
        methods: &[vos::agent::schema::MethodMeta {
            name: "increment",
            mode: MethodMode::Linear,
            explicit: false,
        }],
    });
    let schema = schema[..schema_len].to_vec();
    let parsed_schema = vos::agent::schema::decode(&schema).unwrap();
    let schema_reference = BlobRef::of_bytes(&schema);
    let policies = PackageRolePolicies {
        methods: vec![MethodPolicy {
            method: "increment".into(),
            schema: Hash([0x61; 32]),
            policy: vos::service::public_policy_hash(),
            public: true,
            attested: false,
            space_role: None,
            capability: None,
            actor_role: None,
        }],
        task_dependencies: Vec::new(),
    }
    .encode();
    let policy_reference = BlobRef::of_bytes(&policies);
    let package_bytes = b"signed-counter-package";
    let package_reference = BlobRef::of_bytes(package_bytes);
    let installed_entry = ActorEntry {
        actor,
        name: "counter".into(),
        parent: None,
        deployment,
        program,
        package: package_reference.clone(),
        agent_schema: schema_reference.clone(),
        role_policies: policy_reference.clone(),
        state_layout: parsed_schema.state_layout_hash(),
        lanes: LaneSet::of(vos::agent::StateLane::Linear),
        suspended: false,
    };
    let installed = invoke(RuntimeCall {
        state: driver.image().runtime_state.clone(),
        request: LifecycleRequest::Install(InstallActor {
            entry: installed_entry.clone(),
            producer: ProducerId([0x55; 32]),
            package: package_reference.clone(),
            agent_schema: schema_reference.clone(),
            role_policies: policy_reference.clone(),
            state_layout: parsed_schema.state_layout_hash(),
            requirements: RuntimeRequirements {
                lanes: LaneSet::of(vos::agent::StateLane::Linear),
                scheduling: false,
                proofs: false,
            },
        }),
    });
    assert_eq!(
        installed.result,
        Ok(LifecycleReply::Installed(installed_entry))
    );
    let mut store = driver.into_store();
    store
        .put_package(&package_reference, package_bytes)
        .expect("catalog actor package");
    store
        .put_program(program, &actor_pvm)
        .expect("catalog actor program");
    store
        .put_actor_schema(deployment, &schema_reference, &schema)
        .expect("catalog actor schema");
    store
        .put_actor_policies(deployment, &policy_reference, &policies)
        .expect("catalog actor policies");
    store
        .commit(
            Some(1),
            &AgentImage {
                revision: 2,
                runtime_program: STANDARD_RUNTIME_PROGRAM_ID,
                config: config.clone(),
                runtime_state: installed.state,
            },
        )
        .expect("commit installed runtime fixture");
    let mut driver = AgentDriver::open(store, trust()).expect("open installed agent");

    let dynamic_increment = || {
        let mut message = vec![vos::value::TAG_DYNAMIC];
        message.extend_from_slice(&vos::value::Msg::new("increment").encode());
        message
    };
    let original = driver.image().clone();
    let mut anonymous_with_role = ActorInvocationAuth::anonymous();
    anonymous_with_role.actor_role = Some(1);
    let forged_claim = ActorInvocation {
        invocation: InvocationId([0x64; 32]),
        actor,
        deployment,
        program,
        mode: MethodMode::Linear,
        auth: anonymous_with_role,
        message: dynamic_increment(),
        availability: Vec::new(),
        gas: 10_000_000,
    };
    let forged_evidence = forged_claim.authorization_message();
    assert_eq!(
        driver.invoke(forged_claim, &forged_evidence.0),
        Err(AgentDriverError::InvocationVerification(
            ActorInvocationVerificationError::InvalidInvocation(ActorExecutionError::InvalidInput),
        ))
    );
    assert_eq!(driver.image(), &original);
    let excessive_gas = ActorInvocation {
        invocation: InvocationId([0x65; 32]),
        actor,
        deployment,
        program,
        mode: MethodMode::Linear,
        auth: ActorInvocationAuth::anonymous(),
        message: dynamic_increment(),
        availability: Vec::new(),
        gas: MAX_EXECUTION_GAS + 1,
    };
    let excessive_gas_evidence = excessive_gas.authorization_message();
    assert_eq!(
        driver.invoke(excessive_gas, &excessive_gas_evidence.0),
        Err(AgentDriverError::InvocationVerification(
            ActorInvocationVerificationError::InvalidInvocation(ActorExecutionError::InvalidInput),
        ))
    );
    assert_eq!(driver.image(), &original);

    let invocation = ActorInvocation {
        invocation: InvocationId([0x66; 32]),
        actor,
        deployment,
        program,
        mode: MethodMode::Linear,
        auth: ActorInvocationAuth::anonymous(),
        message: dynamic_increment(),
        availability: Vec::new(),
        gas: 10_000_000,
    };
    let evidence = invocation_evidence(&driver.image().config, &invocation);
    let reply = driver
        .invoke(invocation, &evidence.0)
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
