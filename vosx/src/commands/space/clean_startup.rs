//! Native construction of the one root-authorized Shared system Agent.

use std::num::NonZeroU64;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::identity::{KeyType, Keypair};
use zeroize::Zeroize as _;

use system_authority::{
    AuthorityBindingState, AuthorityBlobRow, AuthorityIssuerState,
    ROOT_BOOTSTRAP_AUTHORIZATION_HIGH_WATER, SystemAuthorityConfiguration,
};
use system_catalog::{CatalogAuthorityState, CatalogIssuerState, SystemCatalogConfiguration};
use vos::agent::Ed25519NodeMergeAuthenticator;
use vos::agent::authority::ed25519_public_key_wire;
use vos::agent::bootstrap::SystemAgentGenesisProvider;
use vos::agent::clean_bootstrap::{
    AuthorizedCleanSystemAgentBootstrap, CleanSystemAgentBootstrapOwner,
};
use vos::agent::driver::AgentTrustProvider;
use vos::agent::genesis::{
    AgentGenesisFinalityError, AgentGenesisFinalityVerifier, AgentReplicaCommittee,
    AgentReplicaMember, derive_replica_raft_slot,
};
use vos::agent::host::LocalMergeAuthenticator;
use vos::agent::package::{Ed25519PackageVerifier, Package};
use vos::agent::package_admission::AdmittedActorPackage;
use vos::agent::sdk::authority::{
    AgentAuthorityBinding, AuthorityActorTarget, AuthorityCredentialCall, AuthorityCredentialKind,
    AuthorityIssuer, ManagedAgentTarget,
};
use vos::agent::sdk::{
    ActorEntry, ActorId, AgentDescriptor, AgentId, AgentIdentity, AgentProfile, AgentReplica,
    BlobRef, CredentialId, Hash, InstallationData, InstallationId, InvocationId, ManagementRequest,
    PrincipalId, ProducerId, ReplicaRole, SpaceId,
};
use vos::agent::supervisor::AgentSupervisorLimits;
use vos::agent::{AgentConfig, AgentProfile as HostAgentProfile, ReplicaRole as HostReplicaRole};
use vos::node::VosNode;
use vos::service::{
    AgentId as HostAgentId, Hash as HostHash, NodeId as HostNodeId, PrincipalId as HostPrincipalId,
    SpaceId as HostSpaceId,
};

use super::authority_projection_authenticator::OperatorAuthorityProjectionAuthenticator;
use super::clean_genesis_archive::CleanSystemAgentGenesisArchive;
use super::clean_identity::{
    CleanOperatorIdentitySigner, OwnedCleanOperatorIdentitySigner, node_id_from_authenticated_peer,
    sign_node_encryption_enrollment,
};
use super::clean_store::{
    CleanAuthorityOperationFiles, CleanManagementLifecycleStoreFactory,
    CleanNativeAuthorityOperationJournal, CleanSystemAgentFileStores,
};

const SYSTEM_AUTHORITY_NAME: &str = "system-authority";
const SYSTEM_CATALOG_NAME: &str = "system-catalog";
const SYSTEM_AGENT_CONTROL_DIRECTORY: &str = "system-agent";
const SHARED_AGENT_HOST_DIRECTORY: &str = "agent-host";
const LOCAL_AGENT_HOST_DIRECTORY: &str = "local-agent-host";
const LOCAL_LIFECYCLE_DIRECTORY: &str = "local-agent-lifecycle";
const OPERATION_IMAGES_DIRECTORY: &str = "authority-operation";
const OPERATION_JOURNAL_DIRECTORY: &str = "authority-operation-journal";
const PROJECTION_ROUTE_QUEUE_CAPACITY: usize = 64;
const LOCAL_LIFECYCLE_RECOVERY_LIMIT: usize = 1_024;
const PROJECTION_RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

/// Shared immutable bootstrap derivation for startup and fresh CLI requests.
/// This derives an expected target, not proof of the daemon's live state.
pub(crate) fn derive_system_authority_target(
    space: SpaceId,
    operator_public: [u8; 32],
    runtime: &vos::agent::package_admission::AdmittedRuntimePackage,
    authority_package: &AdmittedActorPackage,
) -> anyhow::Result<(AuthorityActorTarget, Hash)> {
    let principal = PrincipalId::of_public_key(&operator_public);
    let producer = ProducerId::of_public_key(&operator_public);
    anyhow::ensure!(
        runtime.producer() == producer && authority_package.producer() == producer,
        "system packages must be signed by the configured root"
    );
    authority_package.require_runtime(AgentProfile::Shared, runtime)?;
    let nonce = Hash::digest(
        b"vos/system-agent/creation-nonce/v1",
        &[space.as_bytes(), &operator_public],
    );
    let agent = AgentId::derive(space, principal, nonce.as_bytes());
    let target = AuthorityActorTarget {
        space,
        system_agent: agent,
        system_runtime_deployment: runtime.deployment(),
        binding: AgentAuthorityBinding {
            policy: Hash::digest(
                b"vos/system-authority/policy-binding/v1",
                &[
                    space.as_bytes(),
                    agent.as_bytes(),
                    authority_package.package_ref().hash.as_bytes(),
                ],
            ),
            issuer: AuthorityIssuer {
                principal,
                actor: ActorId::top_level(agent, SYSTEM_AUTHORITY_NAME),
                deployment: authority_package.deployment(),
                program: authority_package.program(),
                producer: authority_package.producer(),
            },
            public_key: operator_public,
            initial_epoch: 1,
        },
    };
    anyhow::ensure!(
        target.is_valid(),
        "derived system-authority target is invalid"
    );
    Ok((target, nonce))
}

/// Start or exactly reopen the native system Agent after the node network has
/// been attached. Every fresh identity is derived from the immutable Space
/// root and authenticated node key; no compatibility runtime is selectable.
pub(crate) fn start_clean_system_agent(
    node: &mut VosNode,
    data_dir: &Path,
    space_bytes: [u8; 32],
    operator: &Keypair,
    daemon: &Keypair,
) -> anyhow::Result<()> {
    require_ed25519(operator, "space root")?;
    require_ed25519(daemon, "node transport")?;

    let space = SpaceId(space_bytes);
    let operator_public = raw_public_key(operator)?;
    let node_public = raw_public_key(daemon)?;
    let operator_principal = PrincipalId::of_public_key(&operator_public);
    let node_principal = PrincipalId::of_public_key(&node_public);
    let operator_producer = ProducerId::of_public_key(&operator_public);
    let transition_producer = ProducerId::of_public_key(&node_public);
    if transition_producer == operator_producer {
        anyhow::bail!("system Agent requires distinct root and node signing identities");
    }

    let peer = daemon.public().to_peer_id();
    let peer_bytes = peer.to_bytes();
    let clean_node = node_id_from_authenticated_peer(&peer);

    let runtime = crate::bundled::root_signed_agent_runtime_package(operator)?;
    let authority_package = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template(),
        SYSTEM_AUTHORITY_NAME,
        operator,
    )?;
    let catalog_package = crate::bundled::root_signed_actor_package(
        crate::bundled::system_catalog_package_template(),
        SYSTEM_CATALOG_NAME,
        operator,
    )?;
    authority_package.require_runtime(AgentProfile::Shared, &runtime)?;
    catalog_package.require_runtime(AgentProfile::Shared, &runtime)?;

    let (authority_target, creation_nonce) =
        derive_system_authority_target(space, operator_public, &runtime, &authority_package)?;
    let system_agent = authority_target.system_agent;
    let authority = authority_target.binding;
    let catalog_actor = ActorId::top_level(system_agent, SYSTEM_CATALOG_NAME);

    let node_encryption_public = derive_node_encryption_public(daemon, space)?;
    let enrollment =
        sign_node_encryption_enrollment(daemon, space, operator_principal, node_encryption_public)?;
    if enrollment.node != clean_node {
        anyhow::bail!("node enrollment does not bind the authenticated transport identity");
    }

    let replica = AgentReplica {
        node: clean_node,
        principal: node_principal,
        role: ReplicaRole::Voter,
    };
    let descriptor = AgentDescriptor {
        identity: AgentIdentity {
            space,
            agent: system_agent,
            owner: operator_principal,
            profile: AgentProfile::Shared,
            runtime_deployment: runtime.deployment(),
            runtime_program: runtime.program(),
            runtime_producer: runtime.producer(),
            transition_producer,
        },
        creation_nonce,
        authority,
        private_recovery: None,
        runtime_package: runtime.package_ref().clone(),
        runtime_contract: runtime.manifest().contract,
        capabilities: runtime.capabilities(),
        replicas: vec![replica],
    };
    descriptor
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid system-Agent descriptor: {error:?}"))?;

    let host_replica = vos::agent::AgentReplica {
        node: HostNodeId(clean_node.0),
        principal: HostPrincipalId(node_principal.0),
        role: HostReplicaRole::Voter,
    };
    let member = AgentReplicaMember::new(
        host_replica,
        peer_bytes.clone(),
        node_public,
        Some(derive_replica_raft_slot(&peer_bytes)),
    )?;
    let replicas = AgentReplicaCommittee::new(
        HostSpaceId(space.0),
        HostAgentId(system_agent.0),
        HostAgentProfile::Shared,
        vec![member],
    )?;

    let authority_state = AuthorityBindingState {
        policy: authority.policy.0,
        issuer: AuthorityIssuerState {
            principal: authority.issuer.principal.0,
            actor: authority.issuer.actor.0,
            deployment: authority.issuer.deployment.0,
            program: authority.issuer.program.0,
            producer: authority.issuer.producer.0,
        },
        public_key: authority.public_key,
        initial_epoch: authority.initial_epoch,
    };
    let authority_configuration = SystemAuthorityConfiguration {
        space: space.0,
        system_agent: system_agent.0,
        system_runtime_deployment: runtime.deployment().0,
        system_runtime_program: runtime.program().0,
        system_runtime_producer: runtime.producer().0,
        system_transition_producer: transition_producer.0,
        system_runtime_package: AuthorityBlobRow {
            hash: runtime.package_ref().hash.0,
            len: runtime.package_ref().len,
        },
        binding: authority_state,
        bootstrap_authorization_high_water: ROOT_BOOTSTRAP_AUTHORIZATION_HIGH_WATER,
        bootstrap_system_agent_creation_nonce: creation_nonce.0,
        bootstrap_principal: operator_principal.0,
        bootstrap_replica_principal: node_principal.0,
        bootstrap_credential_public_key: operator_public,
        bootstrap_credential_kind: AuthorityCredentialKind::Api as u8,
        bootstrap_node: enrollment.node.0,
        bootstrap_node_transport_public_key: enrollment.transport_public_key,
        bootstrap_node_transport_peer_id: enrollment.transport_peer_id,
        bootstrap_node_encryption_public_key: enrollment.encryption_public_key,
        bootstrap_node_transport_signature: enrollment.transport_signature,
    };
    if !authority_configuration.is_valid() {
        anyhow::bail!("derived system-authority configuration is invalid");
    }
    let catalog_configuration = SystemCatalogConfiguration {
        space: space.0,
        system_agent: system_agent.0,
        system_runtime_deployment: runtime.deployment().0,
        actor: catalog_actor.0,
        deployment: catalog_package.deployment().0,
        program: catalog_package.program().0,
        authority: CatalogAuthorityState {
            policy: authority.policy.0,
            issuer: CatalogIssuerState {
                principal: authority.issuer.principal.0,
                actor: authority.issuer.actor.0,
                deployment: authority.issuer.deployment.0,
                program: authority.issuer.program.0,
                producer: authority.issuer.producer.0,
            },
            public_key: authority.public_key,
            initial_epoch: authority.initial_epoch,
        },
    };
    if !catalog_configuration.is_valid() {
        anyhow::bail!("derived system-catalog configuration is invalid");
    }

    let authority_request = install_request(
        system_agent,
        &authority_package,
        authority_configuration.encode(),
        b"authority",
    )?;
    let catalog_request = install_request(
        system_agent,
        &catalog_package,
        catalog_configuration.encode(),
        b"catalog",
    )?;

    let stores =
        CleanSystemAgentFileStores::open_or_create(data_dir.join(SYSTEM_AGENT_CONTROL_DIRECTORY))?;
    let (pins_store, record_store, issuer_store, genesis_store) = stores.into_production_parts();
    let archive = Arc::new(CleanSystemAgentGenesisArchive::new(
        genesis_store,
        HostSpaceId(space.0),
        HostAgentId(system_agent.0),
        HostNodeId(clean_node.0),
        HostHash(authority.commitment().0),
        operator.clone(),
    )?);
    let observed_slot = archive
        .stored_observed_slot()?
        .unwrap_or(system_logical_slot()?);
    let clock = Arc::new(SystemAgentTrust::new(
        observed_slot,
        HostSpaceId(space.0),
        host_authority_binding(system_agent, authority),
    ));
    let trust: Arc<dyn AgentTrustProvider> = clock;
    let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(
        Ed25519NodeMergeAuthenticator::new(daemon.clone())
            .map_err(|error| anyhow::anyhow!("construct node merge signer: {error:?}"))?,
    );
    let finality: Arc<dyn AgentGenesisFinalityVerifier> = Arc::new(UnavailableAgentFinality);
    let genesis: Arc<dyn SystemAgentGenesisProvider> = archive.clone();
    let network = node
        .network()
        .ok_or_else(|| anyhow::anyhow!("clean system Agent requires an attached network"))?;

    let mut owner_signer = CleanOperatorIdentitySigner::new(operator)?;
    let mut planning_signer = CleanOperatorIdentitySigner::new(operator)?;
    let mut catalog_call = AuthorityCredentialCall {
        invocation: InvocationId::ZERO,
        authority: AuthorityActorTarget {
            space,
            system_agent,
            system_runtime_deployment: runtime.deployment(),
            binding: authority,
        },
        managed: ManagedAgentTarget {
            space,
            agent: system_agent,
            owner: operator_principal,
            profile: AgentProfile::Shared,
            runtime_deployment: runtime.deployment(),
            transition_producer,
        },
        principal: operator_principal,
        credential: CredentialId::of_public_key(&operator_public),
        request_sequence: NonZeroU64::new(1).expect("one is nonzero"),
        credential_public_key: operator_public,
        authenticated_node: Some(clean_node),
        requested_valid_from: observed_slot,
        requested_expires_at: u64::MAX,
        plan: catalog_request
            .authorization_plan()
            .ok_or_else(|| anyhow::anyhow!("catalog install has no authorization plan"))?,
        signature: [0; 64],
    };
    catalog_call.invocation = catalog_call.expected_invocation();
    catalog_call.signature = sign_exact(operator, &catalog_call.signing_bytes())?;
    catalog_call
        .validate_shape()
        .map_err(|error| anyhow::anyhow!("invalid catalog authorization call: {error:?}"))?;

    let archive_for_certification = Arc::clone(&archive);
    let mut root_certifier = move |root, proposal: &_, catalog: &_| {
        archive_for_certification.certify_fresh(root, proposal, catalog)
    };
    let plan_trust = Arc::clone(&trust);
    let plan_merge = Arc::clone(&merge);
    let fresh_plan = move || {
        AuthorizedCleanSystemAgentBootstrap::prepare_root_authorized(
            descriptor,
            runtime.exact_bytes().to_vec(),
            replicas,
            observed_slot,
            authority_package.exact_bytes().to_vec(),
            authority_request,
            catalog_package.exact_bytes().to_vec(),
            catalog_request,
            catalog_call,
            vos::agent::execution::MAX_EXECUTION_GAS,
            &mut planning_signer,
            &mut root_certifier,
            plan_trust,
            plan_merge,
        )
        .map(|prepared| prepared.into_parts().0)
    };
    let mut lifecycle_stores = CleanManagementLifecycleStoreFactory::open_or_create(
        data_dir.join(LOCAL_LIFECYCLE_DIRECTORY),
        space,
    )?;
    let lifecycle_recovery = vos::agent::local_lifecycle::discover_local_lifecycle_recovery(
        &mut lifecycle_stores,
        authority_target,
        LOCAL_LIFECYCLE_RECOVERY_LIMIT,
    )
    .map_err(|error| anyhow::anyhow!("verify Local lifecycle stores before startup: {error:?}"))?;
    let lifecycle_admission = lifecycle_recovery.startup_admission()
        .map_err(|error| anyhow::anyhow!("Local lifecycle requires incomplete-phase recovery before startup; preserved all stores: {error:?}"))?;
    let operation_journal = CleanNativeAuthorityOperationJournal::open_or_create(
        data_dir.join(OPERATION_JOURNAL_DIRECTORY),
        authority_target,
    )?;
    let operation_ids = operation_journal.discover(
        2 * vos::agent::authority_operation_coordinator::MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS,
    )?;
    let (operation_coordinator, operation_issuer) =
        CleanAuthorityOperationFiles::open_or_create(data_dir.join(OPERATION_IMAGES_DIRECTORY))?
            .into_parts();
    let mut operations = vos::agent::clean_bootstrap::NativeAuthorityOperationController::new(
        authority_target,
        operation_coordinator,
        operation_issuer,
        operation_journal,
    );
    let operation_admission = operations
        .startup_admission(&operation_ids)
        .map_err(|error| {
            anyhow::anyhow!("verify operation recovery before startup; preserved stores: {error:?}")
        })?;
    let owner = CleanSystemAgentBootstrapOwner::open_or_bootstrap_with_operation_admission(
        pins_store,
        record_store,
        issuer_store,
        &mut owner_signer,
        fresh_plan,
        data_dir.join(SHARED_AGENT_HOST_DIRECTORY),
        crate::paths::agent_host_lock_path(&space_bytes),
        space,
        clean_node,
        Arc::clone(&trust),
        Arc::clone(&merge),
        finality,
        genesis,
        network,
        Some(&lifecycle_admission),
        Some(&operation_admission),
    )?;
    drop(operation_admission);
    let local_root = data_dir.join(LOCAL_AGENT_HOST_DIRECTORY);
    let local = match std::fs::symlink_metadata(&local_root) {
        Ok(_) => vos::agent::local_sdk_host::LocalAgentHost::open(
            &local_root,
            space,
            clean_node,
            Arc::clone(&trust),
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            vos::agent::local_sdk_host::LocalAgentHost::create(
                &local_root,
                space,
                clean_node,
                Arc::clone(&trust),
            )?
        }
        Err(error) => return Err(error.into()),
    };
    let lifecycle = vos::agent::local_lifecycle::LocalLifecycleController::with_recovery(
        owner,
        local,
        lifecycle_stores,
        OwnedCleanOperatorIdentitySigner::new(operator.clone())?,
        lifecycle_recovery,
    )?
    .with_operations(
        operations,
        OwnedCleanOperatorIdentitySigner::new(operator.clone())?,
    )?;
    node.start_clean_local_agent_production(
        clean_node,
        lifecycle,
        Box::new(OperatorAuthorityProjectionAuthenticator::new(
            operator.clone(),
        )?),
        AgentSupervisorLimits::default(),
        PROJECTION_ROUTE_QUEUE_CAPACITY,
        PROJECTION_RECONCILE_INTERVAL,
    )?;
    Ok(())
}

fn install_request(
    agent: AgentId,
    package: &AdmittedActorPackage,
    bytes: Vec<u8>,
    role: &[u8],
) -> anyhow::Result<ManagementRequest> {
    let schema = vos::agent::sdk::schema::decode(package.state_lane_schema_bytes())
        .map_err(|error| anyhow::anyhow!("decode {} schema: {error:?}", package.manifest().name))?;
    let installation_data = InstallationData {
        reference: BlobRef::of_bytes(&bytes),
        bytes,
    };
    let name = package.manifest().name.clone();
    let actor = ActorId::top_level(agent, &name);
    let id = Hash::digest(
        b"vos/system-agent/root-installation/v1",
        &[agent.as_bytes(), actor.as_bytes(), role],
    );
    let reservation = Hash::digest(
        b"vos/system-agent/root-registry-reservation/v1",
        &[agent.as_bytes(), actor.as_bytes(), role],
    );
    let entry = ActorEntry {
        actor,
        name,
        parent: None,
        deployment: package.deployment(),
        program: package.program(),
        package: package.package_ref().clone(),
        agent_schema: package.manifest().state_lane_schema.clone(),
        method_policy: package.manifest().method_policy.clone(),
        constructor_abi: schema
            .constructor_abi()
            .map_err(|error| anyhow::anyhow!("derive actor constructor ABI: {error:?}"))?,
        installation_data: Some(installation_data.reference.clone()),
        state_layout: schema
            .state_layout_hash()
            .map_err(|error| anyhow::anyhow!("derive actor state layout: {error:?}"))?,
        lanes: package.requirements().lanes,
        suspended: false,
    };
    let request = ManagementRequest::Install(Box::new(vos::agent::sdk::InstallActor {
        installation_id: InstallationId(id.0),
        registry_reservation: reservation,
        entry,
        producer: package.producer(),
        package: package.package_ref().clone(),
        agent_schema: package.manifest().state_lane_schema.clone(),
        method_policy: package.manifest().method_policy.clone(),
        constructor_abi: schema
            .constructor_abi()
            .map_err(|error| anyhow::anyhow!("derive actor constructor ABI: {error:?}"))?,
        installation_data: Some(installation_data),
        state_layout: schema
            .state_layout_hash()
            .map_err(|error| anyhow::anyhow!("derive actor state layout: {error:?}"))?,
        contract: package.manifest().contract,
        requirements: package.requirements(),
    }));
    if !request.is_valid() {
        anyhow::bail!(
            "derived {} install request is invalid",
            package.manifest().name
        );
    }
    Ok(request)
}

fn require_ed25519(keypair: &Keypair, label: &str) -> anyhow::Result<()> {
    if keypair.key_type() != KeyType::Ed25519 {
        anyhow::bail!("{label} identity must be Ed25519");
    }
    Ok(())
}

fn raw_public_key(keypair: &Keypair) -> anyhow::Result<[u8; 32]> {
    keypair
        .public()
        .try_into_ed25519()
        .map(|public| public.to_bytes())
        .map_err(|_| anyhow::anyhow!("Ed25519 public key unavailable"))
}

fn sign_exact(keypair: &Keypair, message: &[u8]) -> anyhow::Result<[u8; 64]> {
    keypair
        .sign(message)
        .map_err(|error| anyhow::anyhow!("Ed25519 signing failed: {error}"))?
        .try_into()
        .map_err(|signature: Vec<u8>| {
            anyhow::anyhow!("Ed25519 signer returned {} bytes", signature.len())
        })
}

fn derive_node_encryption_public(daemon: &Keypair, space: SpaceId) -> anyhow::Result<[u8; 32]> {
    let mut secret_encoding = daemon
        .to_protobuf_encoding()
        .map_err(|error| anyhow::anyhow!("encode node key for X25519 derivation: {error}"))?;
    let secret = Hash::digest(
        b"vos/node/x25519-from-transport/v1",
        &[space.as_bytes(), &secret_encoding],
    );
    secret_encoding.zeroize();
    let key = vos::agent::private_crypto::PrivateNodeDecryptionKey::from_bytes(secret.0)
        .map_err(|error| anyhow::anyhow!("derive node X25519 key: {error}"))?;
    Ok(key.public_key())
}

fn system_logical_slot() -> anyhow::Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| anyhow::anyhow!("system clock precedes Unix epoch"))?
            .as_secs(),
    )
    .map_err(|_| anyhow::anyhow!("system logical clock overflow"))
}

fn host_authority_binding(
    system_agent: AgentId,
    authority: AgentAuthorityBinding,
) -> vos::agent::authority::AgentAuthorityBinding {
    let public_key = ed25519_public_key_wire(authority.public_key);
    vos::agent::authority::AgentAuthorityBinding {
        agent: HostAgentId(system_agent.0),
        actor: vos::service::ActorId(authority.issuer.actor.0),
        deployment: vos::service::DeploymentId(authority.issuer.deployment.0),
        program: vos::service::ProgramId(authority.issuer.program.0),
        producer: vos::service::ProducerId::of_public_key(&public_key),
        public_key,
    }
}

struct SystemAgentTrust {
    floor: AtomicU64,
    space: HostSpaceId,
    authority: vos::agent::authority::AgentAuthorityBinding,
}

impl SystemAgentTrust {
    fn new(
        floor: u64,
        space: HostSpaceId,
        authority: vos::agent::authority::AgentAuthorityBinding,
    ) -> Self {
        Self {
            floor: AtomicU64::new(floor),
            space,
            authority,
        }
    }
}

impl AgentTrustProvider for SystemAgentTrust {
    fn current_logical_slot(&self) -> Option<u64> {
        let observed = system_logical_slot().ok()?;
        Some(
            self.floor
                .fetch_max(observed, Ordering::AcqRel)
                .max(observed),
        )
    }

    fn authority_for_space(
        &self,
        space: HostSpaceId,
    ) -> Option<vos::agent::authority::AgentAuthorityBinding> {
        (space == self.space).then(|| self.authority.clone())
    }

    fn verify_package(&self, _agent: &AgentConfig, package: &Package) -> bool {
        package.verify_signature(&Ed25519PackageVerifier).is_ok()
    }
}

/// Root system genesis has its own pinned QC path. Ordinary Agent genesis is
/// refused until an authenticated live-system finality adapter is supplied.
struct UnavailableAgentFinality;

impl AgentGenesisFinalityVerifier for UnavailableAgentFinality {
    fn verify_finalized(
        &self,
        _provision: &vos::agent::genesis::AgentGenesisProvision,
    ) -> Result<(), AgentGenesisFinalityError> {
        Err(AgentGenesisFinalityError::Unavailable)
    }
}
