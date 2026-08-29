use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer as _, SigningKey};
use vos::Encode as _;
use vos::agent::authority::{
    ActorInvocationClaim, ActorInvocationReceipt, AgentAuthorityBinding, AgentAuthorityClaim,
    AgentAuthorityReceipt, ed25519_public_key_wire,
};
use vos::agent::contract::{ActorPackageContract, RuntimePackageContract};
use vos::agent::driver::{
    AgentDriver, AgentDriverError, AgentImage, AgentImageStore, AgentTrustProvider, FileAgentStore,
    MemoryAgentStore,
};
use vos::agent::execution::{
    ActorExecutionError, ActorExecutionStatus, ActorInvocation, ActorInvocationAuth,
    MAX_EXECUTION_GAS, RuntimeBlob, RuntimeExecutionCall, RuntimeExecutionReturn,
};
use vos::agent::host::AgentHost;
use vos::agent::package::{Package, PackageManifest, PackageSignatureVerifier};
use vos::agent::standard::{
    StandardActorState, StandardLaneRevisions, StandardLaneState, StandardRuntimeState,
};
use vos::agent::wire::{
    RuntimeCall, RuntimeReturn, RuntimeState, decode_standard_runtime_state,
    encode_standard_runtime_state,
};
use vos::agent::{
    ActorEntry, ActorLifecycleDebt, ActorRecord, AgentConfig, AgentIdentity, AgentProfile,
    AgentReplica, FieldPersistence, InstallActor, LaneSet, LifecycleAuthorityAdmission,
    LifecycleReply, LifecycleRequest, MethodMode, ReplicaRole, RuntimeCapabilities,
    RuntimeRequirements, STANDARD_RUNTIME_PROGRAM_ID, StateLane,
};
use vos::service::{
    ActorId, AgentId, BlobRef, CapabilityId, CredentialId, DeploymentId, DeploymentSignature, Hash,
    InvocationId, MethodPolicy, NodeId, Origin, PackageRolePolicies, PrincipalId, ProducerId,
    ProgramId, ServiceWire, SpaceId, SubjectId, artifact_hash, task_dependencies_hash,
};
use vos_pvm::ExitReason;
use vos_pvm::refine_host::RefineContext;

const AGENT_RUNTIME_PVM: &[u8] = include_bytes!("../../vosx/blobs/agent_runtime.pvm");
const GAS: u64 = 1_000_000_000;

const TEST_PACKAGE_KEY: &[u8] = b"vos-agent-test-package-key";
const TEST_AUTHORITY_SEED: [u8; 32] = [0x42; 32];

struct TestTrust;

impl AgentTrustProvider for TestTrust {
    fn current_logical_slot(&self) -> Option<u64> {
        Some(1)
    }

    fn authority_for_space(&self, space: SpaceId) -> Option<AgentAuthorityBinding> {
        (space == SpaceId([2; 32])).then(authority_binding)
    }

    fn verify_package(&self, agent: &AgentConfig, package: &Package) -> bool {
        package.deployment_signature.public_key == TEST_PACKAGE_KEY
            && package.deployment_signature.producer == ProducerId::of_public_key(TEST_PACKAGE_KEY)
            && package.deployment_signature.signature == package_signature(package)
            && agent.identity.space == SpaceId([2; 32])
    }
}

struct ClockTrust {
    slot: Arc<AtomicU64>,
}

impl AgentTrustProvider for ClockTrust {
    fn current_logical_slot(&self) -> Option<u64> {
        Some(self.slot.load(Ordering::SeqCst))
    }

    fn authority_for_space(&self, space: SpaceId) -> Option<AgentAuthorityBinding> {
        (space == SpaceId([2; 32])).then(authority_binding)
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

fn clock_trust(initial_slot: u64) -> (Arc<AtomicU64>, Arc<dyn AgentTrustProvider>) {
    let slot = Arc::new(AtomicU64::new(initial_slot));
    let trust: Arc<dyn AgentTrustProvider> = Arc::new(ClockTrust { slot: slot.clone() });
    (slot, trust)
}

fn authority_signing_key() -> SigningKey {
    SigningKey::from_bytes(&TEST_AUTHORITY_SEED)
}

fn authority_binding() -> AgentAuthorityBinding {
    let key = authority_signing_key();
    let public_key = ed25519_public_key_wire(key.verifying_key().to_bytes());
    AgentAuthorityBinding {
        agent: AgentId([8; 32]),
        actor: ActorId([9; 32]),
        deployment: DeploymentId([10; 32]),
        program: ProgramId([11; 32]),
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
        credential: invocation.auth.principal.map(|_| CredentialId([0x72; 32])),
        authorization: invocation.authorization_message(),
        auth: invocation.auth.clone(),
        valid_from: 1,
        valid_until: 2,
    };
    ActorInvocationReceipt {
        signature: key.sign(&claim.signing_message().0).to_bytes().to_vec(),
        claim,
    }
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

fn authorized_request(
    config: &AgentConfig,
    request: LifecycleRequest,
    capability: &str,
    sequence: u64,
) -> LifecycleRequest {
    let receipt = lifecycle_receipt(config, capability, &request, sequence);
    LifecycleRequest::Authorized {
        admission: LifecycleAuthorityAdmission {
            receipt,
            observed_slot: 1,
        },
        request: Box::new(request),
    }
}

fn lifecycle_receipt(
    config: &AgentConfig,
    capability: &str,
    request: &LifecycleRequest,
    sequence: u64,
) -> AgentAuthorityReceipt {
    let key = authority_signing_key();
    let claim = AgentAuthorityClaim {
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
    };
    AgentAuthorityReceipt {
        signature: key.sign(&claim.signing_message().0).to_bytes().to_vec(),
        claim,
    }
}

fn config_for(creation_nonce: Hash) -> AgentConfig {
    let owner = PrincipalId([1; 32]);
    let space = SpaceId([2; 32]);
    let agent = AgentId::derive(space, owner, &creation_nonce.0);
    let runtime = runtime_package();
    AgentConfig {
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
        authority: authority_binding(),
        runtime_package: BlobRef::of_bytes(&runtime.encode()),
        runtime_contract: RuntimePackageContract::canonical(),
        capabilities: RuntimeCapabilities::standard(),
        replicas: vec![AgentReplica {
            node: NodeId([7; 32]),
            principal: owner,
            role: ReplicaRole::Voter,
        }],
    }
}

fn config() -> AgentConfig {
    config_for(Hash([3; 32]))
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

fn invoke_execution(call: RuntimeExecutionCall) -> RuntimeExecutionReturn {
    let invocation = RefineContext::load(AGENT_RUNTIME_PVM, &call.encode(), GAS)
        .expect("load bundled agent runtime")
        .run();
    assert_eq!(
        invocation.exit,
        ExitReason::Halt,
        "agent execution runtime exited at instruction counter {} with registers {:?}",
        invocation.pc,
        invocation.registers,
    );
    RuntimeExecutionReturn::decode(&invocation.output().expect("valid output window"))
        .expect("decode runtime execution return")
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
    let create = LifecycleRequest::Create(config.clone());
    let rejected = invoke(RuntimeCall {
        state: RuntimeState::default(),
        request: create.clone(),
    });
    assert_eq!(
        rejected.result,
        Err(vos::agent::LifecycleError::InvalidRequest)
    );
    let created = invoke(RuntimeCall {
        state: RuntimeState::default(),
        request: authorized_request(
            &config,
            create,
            vos::agent::authority::CAPABILITY_AGENT_CREATE_LOCAL,
            1,
        ),
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
    let first_config = config_for(Hash([0x31; 32]));
    let second_config = config_for(Hash([0x32; 32]));
    let first = first_config.identity.agent;
    let second = second_config.identity.agent;
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

static LANE_PROBE_FIELDS: [vos::agent::schema::FieldMeta; 3] = [
    vos::agent::schema::FieldMeta {
        name: "linear",
        codec: "u8",
        persistence: FieldPersistence::State(StateLane::Linear),
    },
    vos::agent::schema::FieldMeta {
        name: "merge",
        codec: "u8",
        persistence: FieldPersistence::State(StateLane::Merge),
    },
    vos::agent::schema::FieldMeta {
        name: "local",
        codec: "u8",
        persistence: FieldPersistence::State(StateLane::Local),
    },
];

static LANE_PROBE_LINEAR: [vos::agent::schema::MethodMeta; 1] = [vos::agent::schema::MethodMeta {
    name: "probe",
    mode: MethodMode::Linear,
    explicit: true,
}];
static LANE_PROBE_MERGE: [vos::agent::schema::MethodMeta; 1] = [vos::agent::schema::MethodMeta {
    name: "probe",
    mode: MethodMode::Merge,
    explicit: true,
}];
static LANE_PROBE_QUERY: [vos::agent::schema::MethodMeta; 1] = [vos::agent::schema::MethodMeta {
    name: "probe",
    mode: MethodMode::Query,
    explicit: true,
}];
static LANE_PROBE_LOCAL: [vos::agent::schema::MethodMeta; 1] = [vos::agent::schema::MethodMeta {
    name: "probe",
    mode: MethodMode::Local,
    explicit: true,
}];

/// Hand-assembled actor which copies one raw FETCH item into its reply. Its
/// output shape is valid both for the restricted method and for the control
/// method which owns the probed lane.
fn lane_probe_actor(target: StateLane, linear: u8, merge: u8) -> Vec<u8> {
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    let (linear_state, target_fetch) = match target {
        StateLane::Linear => (Vec::new(), 0),
        StateLane::Local => (vec![linear], 2),
        StateLane::Merge => panic!("Merge is visible to every mode in this regression"),
    };
    let merge_state = vec![merge];
    let mut output = vec![vos::actors::STATUS_DONE];
    output.extend_from_slice(&(linear_state.len() as u32).to_le_bytes());
    output.extend_from_slice(&(merge_state.len() as u32).to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&linear_state);
    output.extend_from_slice(&merge_state);
    let reply_offset = output.len();
    output.extend_from_slice(&[0xee, 0xee]);
    let output_len = output.len();
    let scratch_offset = output.len();
    output.extend_from_slice(&[0; 2]);

    let rw_base = 2 * u64::from(vos_pvm::PVM_ZONE_SIZE);
    let mut actor = Assembler::new();
    actor.set_rw_data(output);
    for _ in 0..target_fetch {
        actor
            .load_imm_64(Reg::A0, rw_base + scratch_offset as u64)
            .load_imm_64(Reg::A1, 2)
            .ecalli(vos::abi::hostcall::FETCH);
    }
    actor
        .load_imm_64(Reg::A0, rw_base + reply_offset as u64)
        .load_imm_64(Reg::A1, 2)
        .ecalli(vos::abi::hostcall::FETCH)
        .load_imm_64(Reg::A0, rw_base)
        .load_imm_64(Reg::A1, output_len as u64)
        .jump_ind(Reg::RA, 0);
    actor.build_standard()
}

fn lane_probe_call(
    actor_pvm: Vec<u8>,
    mode: MethodMode,
    invocation_byte: u8,
    linear: u8,
    merge: u8,
    local: u8,
) -> RuntimeExecutionCall {
    let config = config();
    let program = ProgramId::of_pvm(&actor_pvm);
    let actor = ActorId::top_level(config.identity.agent, "lane-probe");
    let deployment = DeploymentId([0xa1; 32]);
    let methods = match mode {
        MethodMode::Linear => &LANE_PROBE_LINEAR,
        MethodMode::Merge => &LANE_PROBE_MERGE,
        MethodMode::Query => &LANE_PROBE_QUERY,
        MethodMode::Local => &LANE_PROBE_LOCAL,
        _ => panic!("unexpected lane-probe mode"),
    };
    let (schema, schema_len) =
        vos::agent::schema::encode::<1024>(&vos::agent::schema::SchemaMeta {
            uses_storage: false,
            fields: &LANE_PROBE_FIELDS,
            methods,
        });
    let schema = schema[..schema_len].to_vec();
    let parsed_schema = vos::agent::schema::decode(&schema).unwrap();
    let schema_reference = BlobRef::of_bytes(&schema);
    let policies = PackageRolePolicies {
        methods: vec![MethodPolicy {
            method: "probe".into(),
            schema: Hash([0xa2; 32]),
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
    let package = BlobRef::of_bytes(b"signed-lane-probe-package");
    let requirements = RuntimeRequirements {
        lanes: LaneSet::ALL,
        scheduling: false,
        proofs: false,
    };
    let entry = ActorEntry {
        actor,
        name: "lane-probe".into(),
        parent: None,
        deployment,
        program,
        package: package.clone(),
        agent_schema: schema_reference.clone(),
        role_policies: policy_reference.clone(),
        state_layout: parsed_schema.state_layout_hash(),
        lanes: LaneSet::ALL,
        suspended: false,
    };
    let state = encode_standard_runtime_state(&StandardRuntimeState {
        config: Some(config.clone()),
        actors: vec![StandardActorState {
            record: ActorRecord {
                entry,
                producer: ProducerId([0xa3; 32]),
                package,
                agent_schema: schema_reference.clone(),
                role_policies: policy_reference.clone(),
                state_layout: parsed_schema.state_layout_hash(),
                contract: ActorPackageContract::canonical(),
                requirements,
            },
            debt: ActorLifecycleDebt::default(),
            lane_state: StandardLaneState {
                linear: Some(vec![linear]),
                merge: Some(vec![merge]),
                local: Some(vec![local]),
            },
        }],
        lane_revisions: StandardLaneRevisions {
            linear: 1,
            merge: 1,
            local: 1,
            ..Default::default()
        },
        ..Default::default()
    });
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&vos::value::Msg::new("probe").encode());
    let invocation = ActorInvocation {
        invocation: InvocationId([invocation_byte; 32]),
        actor,
        deployment,
        program,
        mode,
        auth: ActorInvocationAuth::anonymous(),
        message,
        availability: Vec::new(),
        gas: 10_000_000,
    };
    let authority = invocation_receipt(&config, &invocation);
    RuntimeExecutionCall {
        state,
        invocation,
        authority,
        observed_slot: 1,
        recovery_only: false,
        actor_pvm,
        actor_schema: RuntimeBlob {
            reference: schema_reference,
            bytes: schema,
        },
        actor_policies: RuntimeBlob {
            reference: policy_reference,
            bytes: policies,
        },
    }
}

#[test]
fn bundled_runtime_hides_unreadable_lanes_from_hostile_actor_pvms() {
    const LINEAR_SECRET: u8 = 0x71;
    const MERGE_STATE: u8 = 0x72;
    const LOCAL_SECRET: u8 = 0x73;
    const SENTINEL: u8 = 0xee;

    for (target, control_mode, restricted_mode, base, secret) in [
        (
            StateLane::Linear,
            MethodMode::Linear,
            MethodMode::Merge,
            0xb0,
            LINEAR_SECRET,
        ),
        (
            StateLane::Local,
            MethodMode::Local,
            MethodMode::Query,
            0xc0,
            LOCAL_SECRET,
        ),
    ] {
        let actor_pvm = lane_probe_actor(target, LINEAR_SECRET, MERGE_STATE);

        // Control: the program really exfiltrates the selected FETCH item
        // when the method contract permits that lane to reach the actor.
        let control = invoke_execution(lane_probe_call(
            actor_pvm.clone(),
            control_mode,
            base,
            LINEAR_SECRET,
            MERGE_STATE,
            LOCAL_SECRET,
        ));
        let control = control.result.expect("control invocation completes");
        assert_eq!(control.status, ActorExecutionStatus::Done);
        assert_eq!(control.reply, vec![1, secret]);

        // The same hostile PVM cannot recover the byte when the selected
        // method mode hides the lane at the outer-runtime boundary.
        let restricted = invoke_execution(lane_probe_call(
            actor_pvm,
            restricted_mode,
            base + 1,
            LINEAR_SECRET,
            MERGE_STATE,
            LOCAL_SECRET,
        ));
        let restricted = restricted
            .result
            .expect("restricted invocation completes with projected state");
        assert_eq!(restricted.status, ActorExecutionStatus::Done);
        assert_eq!(restricted.reply, vec![0, SENTINEL]);
    }
}

#[test]
fn bundled_runtime_enforces_signed_evidence_and_recovers_exact_queries() {
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
    let directory = std::env::temp_dir().join(format!(
        "vos-agent-runtime-evidence-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let _remove = RemoveOnDrop(directory.clone());
    let image_path = directory.join("agent.image");

    let config = config();
    let (slot, trust) = clock_trust(1);
    let actor_pvm = static_actor_pvm();
    let program = ProgramId::of_pvm(&actor_pvm);
    let driver = AgentDriver::create(
        runtime_package(),
        config.clone(),
        FileAgentStore::new(&image_path),
        trust.clone(),
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
        methods: &[
            vos::agent::schema::MethodMeta {
                name: "increment",
                mode: MethodMode::Linear,
                explicit: false,
            },
            vos::agent::schema::MethodMeta {
                name: "read",
                mode: MethodMode::Query,
                explicit: true,
            },
        ],
    });
    let schema = schema[..schema_len].to_vec();
    let parsed_schema = vos::agent::schema::decode(&schema).unwrap();
    let schema_reference = BlobRef::of_bytes(&schema);
    let policies = PackageRolePolicies {
        methods: vec![
            MethodPolicy {
                method: "increment".into(),
                schema: Hash([0x61; 32]),
                policy: vos::service::public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                capability: None,
                actor_role: None,
            },
            MethodPolicy {
                method: "read".into(),
                schema: Hash([0x62; 32]),
                policy: vos::service::public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                capability: None,
                actor_role: None,
            },
        ],
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
    let install = LifecycleRequest::Install(InstallActor {
        entry: installed_entry.clone(),
        producer: ProducerId([0x55; 32]),
        package: package_reference.clone(),
        agent_schema: schema_reference.clone(),
        role_policies: policy_reference.clone(),
        state_layout: parsed_schema.state_layout_hash(),
        contract: ActorPackageContract::canonical(),
        requirements: RuntimeRequirements {
            lanes: LaneSet::of(vos::agent::StateLane::Linear),
            scheduling: false,
            proofs: false,
        },
    });
    let preinstall_state = driver.image().runtime_state.clone();
    let raw = invoke(RuntimeCall {
        state: preinstall_state.clone(),
        request: install.clone(),
    });
    assert_eq!(
        raw.result,
        Err(vos::agent::LifecycleError::InvalidRequest),
        "raw lifecycle mutations must never reach the bundled runtime"
    );
    assert_eq!(raw.state, preinstall_state);

    let mut forged_lifecycle = lifecycle_receipt(
        &config,
        vos::agent::authority::CAPABILITY_ACTOR_INSTALL,
        &install,
        2,
    );
    forged_lifecycle.signature[0] ^= 1;
    let forged = invoke(RuntimeCall {
        state: preinstall_state.clone(),
        request: LifecycleRequest::Authorized {
            admission: LifecycleAuthorityAdmission {
                receipt: forged_lifecycle,
                observed_slot: 1,
            },
            request: Box::new(install.clone()),
        },
    });
    assert_eq!(
        forged.result,
        Err(vos::agent::LifecycleError::InvalidRequest),
        "the guest must reject a forged lifecycle receipt"
    );
    assert_eq!(forged.state, preinstall_state);

    let installed = invoke(RuntimeCall {
        state: preinstall_state,
        request: authorized_request(
            &config,
            install,
            vos::agent::authority::CAPABILITY_ACTOR_INSTALL,
            2,
        ),
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
    let mut driver = AgentDriver::open(store, trust.clone()).expect("open installed agent");

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
    let forged_receipt = invocation_receipt(&driver.image().config, &forged_claim);
    assert_eq!(
        driver.invoke(forged_claim, &forged_receipt),
        Err(AgentDriverError::Execution(
            ActorExecutionError::InvalidInput
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
    let excessive_gas_receipt = invocation_receipt(&driver.image().config, &excessive_gas);
    assert_eq!(
        driver.invoke(excessive_gas, &excessive_gas_receipt),
        Err(AgentDriverError::Execution(
            ActorExecutionError::InvalidInput
        ))
    );
    assert_eq!(driver.image(), &original);

    let invocation = ActorInvocation {
        invocation: InvocationId([0x66; 32]),
        actor,
        deployment,
        program,
        mode: MethodMode::Linear,
        auth: ActorInvocationAuth {
            origin: Origin::Member(SubjectId([0x67; 32])),
            principal: Some(config.identity.owner),
            origin_service: None,
            space_role: None,
            actor_role: None,
            capability: None,
        },
        message: dynamic_increment(),
        availability: Vec::new(),
        gas: 10_000_000,
    };
    let mut forged_receipt = invocation_receipt(&driver.image().config, &invocation);
    forged_receipt.signature[0] ^= 1;
    let before_forged_execution = driver.image().runtime_state.clone();
    let forged_execution = invoke_execution(RuntimeExecutionCall {
        state: before_forged_execution.clone(),
        invocation: invocation.clone(),
        authority: forged_receipt,
        observed_slot: 1,
        recovery_only: false,
        actor_pvm: actor_pvm.clone(),
        actor_schema: RuntimeBlob {
            reference: schema_reference.clone(),
            bytes: schema.clone(),
        },
        actor_policies: RuntimeBlob {
            reference: policy_reference.clone(),
            bytes: policies.clone(),
        },
    });
    assert_eq!(
        forged_execution.result,
        Err(ActorExecutionError::InvalidAuthorization),
        "the bundled guest must verify invocation evidence independently"
    );
    assert_eq!(forged_execution.state, before_forged_execution);

    let receipt = invocation_receipt(&driver.image().config, &invocation);
    let reply = driver
        .invoke(invocation.clone(), &receipt)
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

    let dynamic_read = || {
        let mut message = vec![vos::value::TAG_DYNAMIC];
        message.extend_from_slice(&vos::value::Msg::new("read").encode());
        message
    };
    let query = ActorInvocation {
        invocation: InvocationId([0x68; 32]),
        actor,
        deployment,
        program,
        mode: MethodMode::Query,
        auth: invocation.auth.clone(),
        message: dynamic_read(),
        availability: Vec::new(),
        gas: 10_000_000,
    };
    let query_receipt = invocation_receipt(&driver.image().config, &query);
    let query_reply = driver
        .invoke(query.clone(), &query_receipt)
        .expect("execute exact query");
    assert_eq!(query_reply.status, ActorExecutionStatus::Done);
    assert_eq!(query_reply.reply, vec![0x63]);
    assert_eq!(query_reply.observation.linear_revision, Some(1));
    assert_eq!(driver.image().revision, 4);

    let mut mutation = invocation.clone();
    mutation.invocation = InvocationId([0x69; 32]);
    let mutation_receipt = invocation_receipt(&driver.image().config, &mutation);
    let mutation_reply = driver
        .invoke(mutation, &mutation_receipt)
        .expect("commit an intervening mutation");
    assert_eq!(mutation_reply.observation.linear_revision, Some(2));
    assert_eq!(driver.image().revision, 5);

    let mut later_query = query.clone();
    later_query.invocation = InvocationId([0x6a; 32]);
    let later_receipt = invocation_receipt(&driver.image().config, &later_query);
    let later_reply = driver
        .invoke(later_query, &later_receipt)
        .expect("query the newer observation");
    assert_eq!(later_reply.observation.linear_revision, Some(2));
    assert_ne!(later_reply.observation, query_reply.observation);

    let store = driver.into_store();
    slot.store(40, Ordering::SeqCst);
    let mut driver = AgentDriver::open(store, trust).expect("reopen after the receipt expires");
    let recovered = driver
        .invoke(query.clone(), &query_receipt)
        .expect("recover exact query after response loss");
    assert_eq!(recovered, query_reply);

    // A reopened driver which can no longer resolve the actor artifacts must
    // select recovery-only execution and return the guest-owned disposition.
    // It may not use that path to execute unseen work.
    let mut artifact_store = FileAgentStore::new(&image_path);
    artifact_store.remove_program(program).unwrap();
    artifact_store.remove_actor_schema(deployment).unwrap();
    artifact_store.remove_actor_policies(deployment).unwrap();
    let recovery_revision = driver.image().revision;
    let recovered_without_artifacts = driver
        .invoke(query.clone(), &query_receipt)
        .expect("recover without historical actor artifacts");
    assert_eq!(recovered_without_artifacts, query_reply);
    assert_eq!(driver.image().revision, recovery_revision);

    let mut unseen = query.clone();
    unseen.invocation = InvocationId([0x6b; 32]);
    let unseen_receipt = invocation_receipt(&driver.image().config, &unseen);
    assert_eq!(
        driver.invoke(unseen, &unseen_receipt),
        Err(AgentDriverError::Execution(
            ActorExecutionError::InvalidAvailability
        ))
    );
    assert_eq!(driver.image().revision, recovery_revision);

    driver
        .acknowledge_invocation(query.clone(), &query_receipt)
        .expect("acknowledge the delivered exact result");
    let acknowledged = decode_standard_runtime_state(&driver.image().runtime_state).unwrap();
    assert!(
        acknowledged
            .invocation_results
            .iter()
            .all(|result| result.invocation != query.invocation)
    );
    assert!(driver.catalog_cleanup_pending());

    artifact_store.put_program(program, &actor_pvm).unwrap();
    artifact_store
        .put_actor_schema(deployment, &schema_reference, &schema)
        .unwrap();
    artifact_store
        .put_actor_policies(deployment, &policy_reference, &policies)
        .unwrap();
    assert_eq!(
        driver.invoke(query, &query_receipt),
        Err(AgentDriverError::Execution(
            ActorExecutionError::AuthorityExpired
        )),
        "acknowledgement retires the exact result; an expired receipt cannot re-execute it"
    );
}
