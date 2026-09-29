//! Production file owners and startup discovery, without a second bootstrap.
use super::*;
use std::path::PathBuf;
use vos::agent::clean_bootstrap::GenesisClaimSigner;
use vos::agent::committee::AuthoritySignerId;
use vos::network::{Network, NetworkConfig, derive_node_prefix};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        for index in 0..10_000 {
            let path = std::env::temp_dir().join(format!(
                "vosx-shared-file-recovery-{}-{index}",
                std::process::id(),
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path.canonicalize().unwrap()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => panic!("create isolated recovery directory: {error}"),
            }
        }
        panic!("recovery directory namespace exhausted");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn journal_files(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    fn visit(
        root: &Path,
        directory: &Path,
        files: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
    ) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                visit(root, &entry.path(), files);
            } else {
                assert!(kind.is_file(), "journal snapshot must not follow symlinks");
                files.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    std::fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut files = std::collections::BTreeMap::new();
    visit(root, root, &mut files);
    files
}

struct GenesisSigner<'a>(&'a Keypair, usize);

impl GenesisClaimSigner for GenesisSigner<'_> {
    type Error = anyhow::Error;
    fn public_key(&self) -> [u8; 32] {
        raw_public_key(self.0).unwrap()
    }
    fn sign_genesis_claim(&mut self, message: &[u8; 32]) -> anyhow::Result<[u8; 64]> {
        self.1 += 1;
        sign_exact(self.0, message)
    }
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_create_file_owner_reopens_preparation_publication_and_terminal() {
    check_shared_file_recovery(false, false, InstallFault::None);
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_create_file_owner_reopens_denial_beside_retired_generation() {
    check_shared_file_recovery(true, false, InstallFault::None);
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_management_handoff_reopens_under_production_lifecycle_owner() {
    check_shared_file_recovery(true, true, InstallFault::None);
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_install_file_owner_recovers_staged_finalization() {
    check_shared_file_recovery(true, true, InstallFault::Intent(2));
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_install_file_owner_recovers_staged_authorization() {
    check_shared_file_recovery(true, true, InstallFault::Intent(1));
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_install_file_owner_recovers_issuer_decision() {
    check_shared_file_recovery(true, true, InstallFault::Issuer(1));
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_install_file_owner_recovers_issuer_receipt() {
    check_shared_file_recovery(true, true, InstallFault::Issuer(2));
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_install_file_owner_recovers_issuer_observation() {
    check_shared_file_recovery(true, true, InstallFault::Issuer(3));
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_install_file_owner_recovers_issuer_terminal() {
    check_shared_file_recovery(true, true, InstallFault::Issuer(4));
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_install_file_owner_recovers_issuer_finality() {
    check_shared_file_recovery(true, true, InstallFault::Issuer(5));
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_install_file_owner_recovers_successive_handoffs() {
    check_shared_file_recovery(true, true, InstallFault::Successive);
}

#[derive(Clone, Copy)]
enum InstallFault {
    None,
    Expiry,
    MixedExpiry { pending_first: bool },
    Denial,
    DenialAuthorization,
    DenialSuccessor,
    DenialRetirement,
    Intent(usize),
    Issuer(usize),
    Successive,
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_install_file_owner_recovers_expiry_and_staged_finality() {
    check_shared_file_recovery(false, true, InstallFault::Expiry);
}

#[test]
#[ignore = "executes bundled outer PVM; exercises both Agent-ID recovery orderings"]
fn shared_install_file_owner_recovers_expiry_beside_retired_generation() {
    for pending_first in [true, false] {
        check_shared_file_recovery(false, true, InstallFault::MixedExpiry { pending_first });
    }
}

#[test]
fn expiry_test_clock_tracks_wall_time_and_preserves_forward_jump() {
    let operator = Keypair::generate_ed25519();
    let inputs = expiry_startup_inputs(&operator);
    let space = SpaceId([0x73; 32]);
    let (target, _) = derive_system_authority_target(
        space,
        raw_public_key(&operator).unwrap(),
        &inputs.runtime,
        &inputs.authority,
    )
    .unwrap();
    inputs.clock.store(1, Ordering::Release);
    let trust = SystemAgentTrust {
        test_clock: Some(inputs.clock.clone()),
        ..SystemAgentTrust::new(
            1,
            HostSpaceId(space.0),
            host_authority_binding(target.system_agent, target.binding),
        )
    };
    let wall = system_logical_slot().unwrap();
    let first = trust.current_logical_slot().unwrap();
    assert!(first >= wall);
    let future = first + 10_000;
    inputs.clock.fetch_max(future, Ordering::AcqRel);
    assert!(trust.current_logical_slot().unwrap() >= future);
    assert!(trust.current_logical_slot().unwrap() > future);
}

fn expiry_startup_inputs(operator: &Keypair) -> StartupTestInputs {
    // Qualify exactly the shipped packages. Only the logical clock is
    // controlled; no candidate environment variable can replace guest bytes.
    let runtime = crate::bundled::root_signed_agent_runtime_package(operator).unwrap();
    let authority = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template(),
        SYSTEM_AUTHORITY_NAME,
        operator,
    )
    .unwrap();
    StartupTestInputs {
        runtime,
        authority,
        catalog: crate::bundled::root_signed_actor_package(
            crate::bundled::system_catalog_package_template(),
            SYSTEM_CATALOG_NAME,
            operator,
        )
        .unwrap(),
        clock: Arc::new(AtomicU64::new(system_logical_slot().unwrap() + 1)),
    }
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_install_file_owner_retires_policy_denial() {
    check_shared_file_recovery(true, true, InstallFault::Denial);
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_install_file_owner_recovers_staged_denial_retirement() {
    check_shared_file_recovery(true, true, InstallFault::DenialRetirement);
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_install_file_owner_recovers_pending_policy_denial() {
    check_shared_file_recovery(true, true, InstallFault::DenialAuthorization);
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_install_file_owner_recovers_successor_after_denial() {
    check_shared_file_recovery(true, true, InstallFault::DenialSuccessor);
}

fn check_shared_file_recovery(
    with_denial: bool,
    with_handoff: bool,
    interrupt_install: InstallFault,
) {
    check_shared_file_recovery_with_candidate(with_denial, with_handoff, interrupt_install, None);
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF; candidate bootstrap and Shared Create use production stores"]
fn candidate_authority_shared_create_reopens_production_stores() {
    let elf = PathBuf::from(std::env::var("AUTHORITY_CANDIDATE_ELF").unwrap());
    check_shared_file_recovery_with_candidate(false, false, InstallFault::None, Some(&elf));
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF; exercises certified genesis import with production file owners"]
fn candidate_certified_genesis_import_is_scoped_immutable_and_restartable() {
    use crate::commands::space::clean_store::ensure_private_directory;
    use vos::agent::bootstrap::{SystemAgentGenesisLocator, SystemAgentGenesisProviderError};
    use vos::agent::execution::RuntimeBlob;

    let scratch = Scratch::new();
    let data = scratch.0.join("source");
    drop(ensure_private_directory(&data).unwrap());
    let operator = Keypair::ed25519_from_bytes([0x71; 32]).unwrap();
    let daemon = Keypair::ed25519_from_bytes([0x72; 32]).unwrap();
    let peer = daemon.public().to_peer_id();
    let network = Arc::new(Network::start(NetworkConfig {
        keypair: daemon.clone(),
        local_prefix: derive_node_prefix(&peer),
        listen: vec![],
        bootstrap: vec![],
        auto_dial_mdns: false,
    }));
    let space = SpaceId([0x73; 32]);
    let inputs = candidate_authority_inputs(
        &operator,
        &PathBuf::from(std::env::var("AUTHORITY_CANDIDATE_ELF").unwrap()),
    );
    let (node, lifecycle) = open_clean_system_lifecycle_with_inputs(
        network.clone(),
        &data,
        space.0,
        &operator,
        &daemon,
        crate::commands::space::local_config::LocalAgentStorage::Image,
        &scratch.0.join("source-host.lock"),
        None,
        Some(&inputs),
    )
    .unwrap();
    drop(lifecycle);
    let (authority, _) = derive_system_authority_target(
        space,
        raw_public_key(&operator).unwrap(),
        &inputs.runtime,
        &inputs.authority,
    )
    .unwrap();
    let agent = HostAgentId(authority.system_agent.0);
    let node = HostNodeId(node.0);
    let space = HostSpaceId(space.0);
    let binding = HostHash(authority.binding.commitment().0);
    use vos::agent::clean_bootstrap::{
        CleanSystemAgentBootstrapRecord, CleanSystemAgentBootstrapStore,
        MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES,
    };
    let plan = {
        let (_, mut record, _, _) =
            CleanSystemAgentFileStores::open_or_create(data.join(SYSTEM_AGENT_CONTROL_DIRECTORY))
                .unwrap()
                .into_production_parts();
        let bytes = record
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .unwrap()
            .unwrap();
        CleanSystemAgentBootstrapRecord::authorized_plan(&bytes).unwrap()
    };
    let make_archive = |path: &Path, space, agent, node, binding, signer| {
        let (_, _, _, store) = CleanSystemAgentFileStores::open_or_create(path)
            .unwrap()
            .into_production_parts();
        CleanSystemAgentGenesisArchive::new(store, space, agent, node, binding, signer).unwrap()
    };
    let source = make_archive(
        &data.join(SYSTEM_AGENT_CONTROL_DIRECTORY),
        space,
        agent,
        node,
        binding,
        operator.clone(),
    );
    let locator = SystemAgentGenesisLocator { space, agent, node };
    let provision = source.reproduce(locator).unwrap();
    let catalog: Vec<_> = provision
        .proposal()
        .catalog()
        .iter()
        .map(|reference| RuntimeBlob {
            reference: reference.clone(),
            bytes: source.load_catalog(locator, reference).unwrap().unwrap(),
        })
        .collect();
    let certified = PreparedCleanSystemAgentBootstrap::from_certified_parts(
        plan.clone(),
        provision.clone(),
        catalog.clone(),
        Arc::new(SystemAgentTrust::new(
            plan.pins().observed_slot(),
            space,
            host_authority_binding(authority.system_agent, authority.binding),
        )),
        Arc::new(Ed25519NodeMergeAuthenticator::new(daemon.clone()).unwrap()),
    )
    .unwrap();
    let imported_data = scratch.0.join("imported-startup");
    drop(ensure_private_directory(&imported_data).unwrap());
    for supplied in [Some(&certified), None, Some(&certified)] {
        let (_, recovered) = open_clean_system_lifecycle_with_inputs(
            network.clone(),
            &imported_data,
            space.0,
            &operator,
            &daemon,
            crate::commands::space::local_config::LocalAgentStorage::Image,
            &scratch.0.join("imported-host.lock"),
            supplied,
            Some(&inputs),
        )
        .unwrap();
        drop(recovered);
        let archived = make_archive(
            &imported_data.join(SYSTEM_AGENT_CONTROL_DIRECTORY),
            space,
            agent,
            node,
            binding,
            operator.clone(),
        );
        assert_eq!(archived.reproduce(locator).unwrap(), provision);
    }
    let archive_path = imported_data
        .join(SYSTEM_AGENT_CONTROL_DIRECTORY)
        .join("system-agent.genesis-archive");
    let saved_archive = scratch.0.join("saved-imported-genesis");
    std::fs::rename(&archive_path, &saved_archive).unwrap();
    let missing_archive_files = journal_files(&imported_data);
    assert!(
        open_clean_system_lifecycle_with_inputs(
            network.clone(),
            &imported_data,
            space.0,
            &operator,
            &daemon,
            crate::commands::space::local_config::LocalAgentStorage::Image,
            &scratch.0.join("imported-host.lock"),
            Some(&certified),
            Some(&inputs),
        )
        .is_err()
    );
    assert_eq!(journal_files(&imported_data), missing_archive_files);
    std::fs::rename(&saved_archive, &archive_path).unwrap();
    for (label, scoped_space, scoped_agent, scoped_node, scoped_binding, key) in [
        (
            "space",
            HostSpaceId([0x91; 32]),
            agent,
            node,
            binding,
            operator.clone(),
        ),
        (
            "agent",
            space,
            HostAgentId([0x91; 32]),
            node,
            binding,
            operator.clone(),
        ),
        (
            "node",
            space,
            agent,
            HostNodeId([0x91; 32]),
            binding,
            operator.clone(),
        ),
        (
            "binding",
            space,
            agent,
            node,
            HostHash([0x91; 32]),
            operator.clone(),
        ),
        (
            "signer",
            space,
            agent,
            node,
            binding,
            Keypair::ed25519_from_bytes([0x91; 32]).unwrap(),
        ),
    ] {
        let path = scratch.0.join(label);
        let archive = make_archive(
            &path,
            scoped_space,
            scoped_agent,
            scoped_node,
            scoped_binding,
            key,
        );
        let before = journal_files(&path);
        assert!(
            matches!(
                archive.import_certified(&provision, &catalog),
                Err(SystemAgentGenesisProviderError::Refused)
            ),
            "{label}"
        );
        assert_eq!(journal_files(&path), before, "{label}");
    }
    let path = scratch.0.join("imported");
    let archive = make_archive(&path, space, agent, node, binding, operator.clone());
    let before = journal_files(&path);
    let mut corrupted = catalog.clone();
    corrupted[0].bytes[0] ^= 1;
    assert!(archive.import_certified(&provision, &corrupted).is_err());
    assert_eq!(journal_files(&path), before);
    assert_eq!(
        archive.import_certified(&provision, &catalog).unwrap(),
        provision
    );
    let published = journal_files(&path);
    assert_eq!(
        archive.import_certified(&provision, &catalog).unwrap(),
        provision
    );
    assert_eq!(journal_files(&path), published);
    assert!(matches!(
        archive.certify_fresh(Hash([0x92; 32]), provision.proposal(), &catalog),
        Err(SystemAgentGenesisProviderError::Conflict)
    ));
    assert_eq!(journal_files(&path), published);
    drop(archive);
    let reopened = make_archive(&path, space, agent, node, binding, operator.clone());
    assert_eq!(reopened.reproduce(locator).unwrap(), provision);
    assert_eq!(
        reopened.import_certified(&provision, &catalog).unwrap(),
        provision
    );
    assert_eq!(journal_files(&path), published);
    for blob in &catalog {
        assert_eq!(
            reopened.load_catalog(locator, &blob.reference).unwrap(),
            Some(blob.bytes.clone())
        );
    }
    // The root committee's node is not the selected data-plane replica.
    // Build independently signed evidence for that topology; importing must
    // retain it exactly, never replace it with a locally certified root.
    use vos::agent::committee::{
        AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole,
        AuthorityQuorumCertificate, AuthoritySignature, RootAnchorPins, RootAnchorRecord,
        SystemAgentGenesisClaim, SystemAgentGenesisEvidence,
    };
    let public = raw_public_key(&operator).unwrap();
    let root_node = HostNodeId([0x93; 32]);
    assert_ne!(root_node, node);
    let committee = AuthorityCommittee::new(
        space,
        binding,
        1,
        None,
        vec![AuthorityCommitteeMember::new(root_node, public, AuthorityMemberRole::Voter).unwrap()],
    )
    .unwrap();
    let root = RootAnchorRecord::new(
        1,
        space,
        agent,
        binding,
        provision.root().record().root_certification(),
        committee,
    )
    .unwrap();
    let claim = SystemAgentGenesisClaim::new(&root, provision.proposal().expectations()).unwrap();
    let committee = root.initial_committee();
    let message = AuthorityQuorumCertificate::signing_message(
        committee.authority_binding(),
        committee.epoch(),
        committee.commitment(),
        claim.authority_claim(),
    );
    let signature = AuthoritySignature::new(
        AuthoritySignerId::of_raw_ed25519(&public),
        operator.sign(&message.0).unwrap().try_into().unwrap(),
    )
    .unwrap();
    let evidence = SystemAgentGenesisEvidence::new(
        claim.clone(),
        AuthorityQuorumCertificate::new(committee, claim.authority_claim(), vec![signature])
            .unwrap(),
    )
    .unwrap();
    let pins = RootAnchorPins::new(
        root.clone(),
        1,
        root.id(),
        root.config_commitment(),
        claim.authority_claim(),
    )
    .unwrap();
    let remote = vos::agent::bootstrap::SystemAgentGenesisProvision::new(
        provision.proposal().clone(),
        pins,
        evidence,
    )
    .unwrap();
    let remote_path = scratch.0.join("remote-root");
    let imported = make_archive(&remote_path, space, agent, node, binding, operator.clone());
    assert_eq!(
        imported.import_certified(&remote, &catalog).unwrap(),
        remote
    );
    drop(imported);
    let imported = make_archive(&remote_path, space, agent, node, binding, operator);
    assert_eq!(imported.reproduce(locator).unwrap(), remote);
}

fn candidate_authority_inputs(operator: &Keypair, path: &Path) -> StartupTestInputs {
    use vos::agent::sdk::package::{
        PackageArtifact, PackageEnvelope, PackageManifest, PackageSigning,
    };
    let mut inputs = expiry_startup_inputs(operator);
    let elf = std::fs::read(path).unwrap();
    let program = vos_pvm_compiler::link_elf_spi(&elf).unwrap();
    let schema = vos::agent::schema::raw_section_from_elf(&elf).unwrap();
    let mut package =
        PackageEnvelope::decode(crate::bundled::system_authority_package_template()).unwrap();
    let PackageManifest::Actor(manifest) = &mut package.manifest else {
        unreachable!()
    };
    let old_program = std::mem::replace(
        &mut manifest.program,
        vos::agent::sdk::BlobRef::of_bytes(&program),
    );
    let old_schema = std::mem::replace(
        &mut manifest.state_lane_schema,
        vos::agent::sdk::BlobRef::of_bytes(&schema),
    );
    package
        .artifacts
        .retain(|artifact| artifact.identity != old_program && artifact.identity != old_schema);
    for bytes in [program, schema] {
        package.artifacts.push(PackageArtifact {
            identity: vos::agent::sdk::BlobRef::of_bytes(&bytes),
            bytes,
        });
    }
    package
        .artifacts
        .sort_unstable_by(|a, b| a.identity.cmp(&b.identity));
    let public_key = raw_public_key(operator).unwrap();
    *package.manifest.signing_mut() = PackageSigning {
        producer: ProducerId::of_public_key(&public_key),
        public_key,
        signature: [0; 64],
    };
    package.manifest.signing_mut().signature =
        sign_exact(operator, &package.signing_bytes().unwrap()).unwrap();
    inputs.authority =
        vos::agent::package_admission::admit_actor_package(&package.encode().unwrap()).unwrap();
    inputs
}

fn check_shared_file_recovery_with_candidate(
    with_denial: bool,
    with_handoff: bool,
    interrupt_install: InstallFault,
    candidate: Option<&Path>,
) {
    use crate::commands::space::clean_store::{
        CleanAgentGenesisSignatureFile, CleanFileStoreError, ensure_private_directory,
    };
    use vos::agent::shared_host::SharedAgentHostError;
    let scratch = Scratch::new();
    let data = scratch.0.join("space");
    drop(ensure_private_directory(&data).unwrap());
    let signatures = scratch.0.join("signatures");
    drop(ensure_private_directory(&signatures).unwrap());
    let lock = scratch.0.join("agent-host.lock");
    let operator = Keypair::ed25519_from_bytes([0x71; 32]).unwrap();
    let daemon = Keypair::ed25519_from_bytes([0x72; 32]).unwrap();
    let peer = daemon.public().to_peer_id();
    let network = Arc::new(Network::start(NetworkConfig {
        keypair: daemon.clone(),
        local_prefix: derive_node_prefix(&peer),
        listen: vec![],
        bootstrap: vec![],
        auto_dial_mdns: false,
    }));
    let space = SpaceId([0x73; 32]);
    let expiry = candidate
        .map(|path| candidate_authority_inputs(&operator, path))
        .or_else(|| {
            matches!(
                interrupt_install,
                InstallFault::Expiry | InstallFault::MixedExpiry { .. }
            )
            .then(|| expiry_startup_inputs(&operator))
        });
    let open = || {
        open_clean_system_lifecycle_with_inputs(
            network.clone(),
            &data,
            space.0,
            &operator,
            &daemon,
            crate::commands::space::local_config::LocalAgentStorage::Image,
            &lock,
            None,
            expiry.as_ref(),
        )
        .unwrap()
    };
    let (node, mut lifecycle) = open();
    let runtime = crate::bundled::root_signed_agent_runtime_package(&operator).unwrap();
    let authority_package = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template_for_storage(
            crate::commands::space::local_config::LocalAgentStorage::Image,
        )
        .unwrap(),
        SYSTEM_AUTHORITY_NAME,
        &operator,
    )
    .unwrap();
    let (runtime, authority_package) = expiry
        .as_ref()
        .map_or((runtime, authority_package), |inputs| {
            (inputs.runtime.clone(), inputs.authority.clone())
        });
    let public = raw_public_key(&operator).unwrap();
    let owner = PrincipalId::of_public_key(&public);
    let (authority, _) =
        derive_system_authority_target(space, public, &runtime, &authority_package).unwrap();
    let nonce = Hash([0x74; 32]);
    let agent = AgentId::derive(space, owner, nonce.as_bytes());
    let descriptor = AgentDescriptor {
        identity: AgentIdentity {
            space,
            agent,
            owner,
            profile: AgentProfile::Shared,
            runtime_deployment: runtime.deployment(),
            runtime_program: runtime.program(),
            runtime_producer: runtime.producer(),
            transition_producer: ProducerId::of_public_key(&raw_public_key(&daemon).unwrap()),
        },
        creation_nonce: nonce,
        authority: authority.binding,
        private_recovery: None,
        runtime_package: runtime.package_ref().clone(),
        runtime_contract: runtime.manifest().contract,
        capabilities: runtime.capabilities(),
        replicas: vec![AgentReplica {
            node,
            principal: owner,
            role: ReplicaRole::Voter,
        }],
    };
    descriptor.validate().unwrap();
    let peer_bytes = peer.to_bytes();
    let replicas = AgentReplicaCommittee::new(
        HostSpaceId(space.0),
        HostAgentId(agent.0),
        HostAgentProfile::Shared,
        vec![
            AgentReplicaMember::new(
                vos::agent::AgentReplica {
                    node: HostNodeId(node.0),
                    principal: HostPrincipalId(owner.0),
                    role: HostReplicaRole::Voter,
                },
                peer_bytes.clone(),
                raw_public_key(&daemon).unwrap(),
                Some(derive_replica_raft_slot(&peer_bytes)),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let mut call = AuthorityCredentialCall {
        invocation: InvocationId::ZERO,
        authority,
        managed: ManagedAgentTarget {
            space,
            agent,
            owner,
            profile: AgentProfile::Shared,
            runtime_deployment: runtime.deployment(),
            transition_producer: descriptor.identity.transition_producer,
        },
        principal: owner,
        credential: CredentialId::of_public_key(&public),
        request_sequence: NonZeroU64::new(2).unwrap(),
        credential_public_key: public,
        authenticated_node: Some(node),
        requested_valid_from: system_logical_slot().unwrap(),
        requested_expires_at: u64::MAX,
        plan: request.authorization_plan().unwrap(),
        signature: [0; 64],
    };
    call.invocation = call.expected_invocation();
    call.signature = sign_exact(&operator, &call.signing_bytes()).unwrap();
    let locator = lifecycle
        .reserve_shared_create(&descriptor, &call, &runtime, &replicas)
        .unwrap();
    let candidate = lifecycle.prepare_shared_create(locator).unwrap();
    let signer_id = AuthoritySignerId::of_raw_ed25519(&public);
    let mut signature_store =
        CleanAgentGenesisSignatureFile::open_or_create(&signatures, locator, signer_id).unwrap();
    let mut signer = GenesisSigner(&operator, 0);
    let signature = candidate
        .endorse(&mut signature_store, &mut signer)
        .unwrap();
    assert_eq!(signer.1, 1);
    assert!(matches!(
        discover_shared_genesis_startup(&data, authority, 4096),
        Err(CleanFileStoreError::Busy)
    ));
    let journal = data
        .join(SHARED_AGENT_HOST_DIRECTORY)
        .join(format!("{}.agent", hex::encode(agent.0)));
    assert!(!journal.exists(), "preparation cannot apply a generation");
    let lifecycle_root = data
        .join(crate::commands::space::clean_store::SHARED_LIFECYCLE_DIRECTORY)
        .join(hex::encode(agent.0));
    if with_handoff {
        assert!(lifecycle.initialize_shared_management(locator).is_err());
        assert!(!lifecycle_root.join("shared-management.handoff").exists());
        assert!(!lifecycle_root.join("shared-management.issuer").exists());
    }
    drop(signature_store);
    drop(lifecycle);

    // Reopen all production leases through the daemon's discovery path after
    // endorsement but before the immutable archive/publication exists.
    let (_, mut lifecycle) = open();
    assert_eq!(
        lifecycle
            .reserve_shared_create(&descriptor, &call, &runtime, &replicas)
            .unwrap(),
        locator
    );
    let recovered_candidate = lifecycle.prepare_shared_create(locator).unwrap();
    assert_eq!(recovered_candidate, candidate);
    let mut signature_store =
        CleanAgentGenesisSignatureFile::open_or_create(&signatures, locator, signer_id).unwrap();
    assert_eq!(
        recovered_candidate
            .endorse(&mut signature_store, &mut signer)
            .unwrap(),
        signature
    );
    assert_eq!(signer.1, 1, "restart must reuse the durable endorsement");
    let published = lifecycle
        .publish_shared_create(locator, vec![signature])
        .unwrap();
    assert_eq!(
        lifecycle.publish_shared_create(locator, vec![]).unwrap(),
        published
    );
    assert!(
        !journal.exists(),
        "publication alone cannot apply a generation"
    );
    drop(signature_store);
    drop(lifecycle);

    // Recovery must finish the archived but unapplied Create before handing
    // the production lifecycle back to its caller.
    let (_, mut lifecycle) = open();
    assert!(journal.exists());
    assert_eq!(
        lifecycle
            .reserve_shared_create(&descriptor, &call, &runtime, &replicas)
            .unwrap(),
        locator
    );
    let acknowledgement = lifecycle.complete_shared_create(locator).unwrap();
    assert_eq!(acknowledgement.credential_call, call.commitment());
    let applied = journal_files(&journal);
    assert!(!applied.is_empty());
    let retired_peer = if let InstallFault::MixedExpiry { pending_first } = interrupt_install {
        let mut other = descriptor.clone();
        other.creation_nonce = (1u8..=255)
            .map(|marker| Hash([marker; 32]))
            .find(|nonce| {
                let id = AgentId::derive(space, owner, nonce.as_bytes());
                id != agent && (agent < id) == pending_first
            })
            .expect("both Agent-ID orderings must be constructible");
        other.identity.agent = AgentId::derive(space, owner, other.creation_nonce.as_bytes());
        other.validate().unwrap();
        let committee = AgentReplicaCommittee::new(
            HostSpaceId(space.0),
            HostAgentId(other.identity.agent.0),
            HostAgentProfile::Shared,
            replicas.members().to_vec(),
        )
        .unwrap();
        let mut other_call = call.clone();
        other_call.managed.agent = other.identity.agent;
        other_call.request_sequence = NonZeroU64::new(3).unwrap();
        other_call.plan = ManagementRequest::Create(Box::new(other.clone()))
            .authorization_plan()
            .unwrap();
        other_call.invocation = other_call.expected_invocation();
        other_call.signature = sign_exact(&operator, &other_call.signing_bytes()).unwrap();
        let other_locator = lifecycle
            .reserve_shared_create(&other, &other_call, &runtime, &committee)
            .unwrap();
        assert_eq!(locator.agent < other_locator.agent, pending_first);
        let candidate = lifecycle.prepare_shared_create(other_locator).unwrap();
        let mut store =
            CleanAgentGenesisSignatureFile::open_or_create(&signatures, other_locator, signer_id)
                .unwrap();
        let signature = candidate.endorse(&mut store, &mut signer).unwrap();
        lifecycle
            .publish_shared_create(other_locator, vec![signature])
            .unwrap();
        let ack = lifecycle.complete_shared_create(other_locator).unwrap();
        assert_eq!(ack.credential_call, other_call.commitment());
        let path = data
            .join(SHARED_AGENT_HOST_DIRECTORY)
            .join(format!("{}.agent", hex::encode(other.identity.agent.0)));
        let files = journal_files(&path);
        Some((other_locator, ack, path, files))
    } else {
        None
    };
    let denied = with_denial.then(|| {
        let mut denied_descriptor = descriptor.clone();
        denied_descriptor.creation_nonce = Hash([0x75; 32]);
        denied_descriptor.identity.agent =
            AgentId::derive(space, owner, denied_descriptor.creation_nonce.as_bytes());
        let denied_replicas = AgentReplicaCommittee::new(
            HostSpaceId(space.0),
            HostAgentId(denied_descriptor.identity.agent.0),
            HostAgentProfile::Shared,
            replicas.members().to_vec(),
        )
        .unwrap();
        let mut denied_call = call.clone();
        denied_call.managed.agent = denied_descriptor.identity.agent;
        denied_call.request_sequence = NonZeroU64::new(99).unwrap();
        denied_call.plan = ManagementRequest::Create(Box::new(denied_descriptor.clone()))
            .authorization_plan()
            .unwrap();
        denied_call.invocation = denied_call.expected_invocation();
        denied_call.signature = sign_exact(&operator, &denied_call.signing_bytes()).unwrap();
        let denied_locator = lifecycle
            .reserve_shared_create(&denied_descriptor, &denied_call, &runtime, &denied_replicas)
            .unwrap();
        assert_eq!(
            lifecycle.prepare_shared_create(denied_locator),
            Err(SharedAgentHostError::ScopeMismatch)
        );
        // Successful completion's fresh Authority read would fail if the
        // rejected Create still held its original management reservation.
        assert_eq!(
            lifecycle.complete_shared_create(locator).unwrap(),
            acknowledgement
        );
        (
            denied_descriptor,
            denied_call,
            denied_replicas,
            denied_locator,
        )
    });
    let handoff_files = with_handoff.then(|| {
        let before = journal_files(&lifecycle_root);
        lifecycle.initialize_shared_management(locator).unwrap();
        let retained = journal_files(&lifecycle_root);
        for (name, bytes) in before {
            assert_eq!(
                retained.get(&name),
                Some(&bytes),
                "handoff must preserve original Create evidence"
            );
        }
        assert!(retained.contains_key(Path::new("shared-management.handoff")));
        assert!(retained.contains_key(Path::new("shared-management.issuer")));
        lifecycle.initialize_shared_management(locator).unwrap();
        assert_eq!(journal_files(&lifecycle_root), retained);
        assert_eq!(journal_files(&journal), applied);
        assert!(matches!(
            discover_shared_genesis_startup(&data, authority, 4),
            Err(CleanFileStoreError::Busy)
        ));
        let package = crate::bundled::root_signed_actor_package(
            crate::bundled::system_catalog_package_template(),
            SYSTEM_CATALOG_NAME,
            &operator,
        )
        .unwrap();
        let configuration = SystemCatalogConfiguration {
            space: space.0,
            system_agent: agent.0,
            system_runtime_deployment: runtime.deployment().0,
            actor: ActorId::top_level(agent, "prepared-catalog").0,
            deployment: package.deployment().0,
            program: package.program().0,
            authority: CatalogAuthorityState {
                policy: authority.binding.policy.0,
                issuer: CatalogIssuerState {
                    principal: authority.binding.issuer.principal.0,
                    actor: authority.binding.issuer.actor.0,
                    deployment: authority.binding.issuer.deployment.0,
                    program: authority.binding.issuer.program.0,
                    producer: authority.binding.issuer.producer.0,
                },
                public_key: authority.binding.public_key,
                initial_epoch: authority.binding.initial_epoch,
            },
        };
        assert!(configuration.is_valid());
        let install = crate::commands::space::local_install::build_install(
            agent,
            vos::agent::sdk::InstallationId([0x81; 32]),
            Hash([0x82; 32]),
            "prepared-catalog".into(),
            None,
            Some(configuration.encode()),
            &package,
        )
        .unwrap();
        let mut install_call = call.clone();
        install_call.request_sequence = NonZeroU64::new(
            if matches!(
                interrupt_install,
                InstallFault::Denial
                    | InstallFault::DenialRetirement
                    | InstallFault::DenialAuthorization
                    | InstallFault::DenialSuccessor
            ) {
                99
            } else if retired_peer.is_some() {
                4
            } else {
                3
            },
        )
        .unwrap();
        install_call.plan = ManagementRequest::Install(Box::new(install.clone()))
            .authorization_plan()
            .unwrap();
        if let Some(inputs) = &expiry {
            install_call.requested_expires_at = inputs.clock.load(Ordering::Acquire) + 10_000;
        }
        install_call.invocation = install_call.expected_invocation();
        install_call.signature = sign_exact(&operator, &install_call.signing_bytes()).unwrap();
        let mut forged = install_call.clone();
        forged.signature[0] ^= 1;
        assert_eq!(
            lifecycle.prepare_shared_install(install.clone(), forged, &package),
            Err(SharedAgentHostError::ScopeMismatch)
        );
        assert_eq!(journal_files(&lifecycle_root), retained);
        lifecycle
            .prepare_shared_install(install.clone(), install_call.clone(), &package)
            .unwrap();
        let prepared = journal_files(&lifecycle_root);
        for (name, bytes) in retained {
            assert_eq!(
                prepared.get(&name),
                Some(&bytes),
                "Install preparation preserves Create and issuer checkpoint"
            );
        }
        assert!(prepared.contains_key(Path::new("shared-management.intent")));
        assert!(prepared.contains_key(Path::new("shared-management.actor")));
        lifecycle
            .prepare_shared_install(install.clone(), install_call.clone(), &package)
            .unwrap();
        let mut changed = install.clone();
        changed.installation_id = vos::agent::sdk::InstallationId([0x83; 32]);
        let mut changed_call = install_call.clone();
        changed_call.plan = ManagementRequest::Install(Box::new(changed.clone()))
            .authorization_plan()
            .unwrap();
        changed_call.invocation = changed_call.expected_invocation();
        changed_call.signature = sign_exact(&operator, &changed_call.signing_bytes()).unwrap();
        assert_eq!(
            lifecycle.prepare_shared_install(changed, changed_call, &package),
            Err(SharedAgentHostError::Conflict)
        );
        assert_eq!(journal_files(&lifecycle_root), prepared);
        assert_eq!(journal_files(&journal), applied);
        (prepared, install, install_call, package)
    });
    drop(lifecycle);
    if with_handoff {
        // A missing activated slot must fail without recreating its seed.
        let continuation = lifecycle_root.join("shared-management.issuer");
        let saved = scratch.0.join("saved-management-issuer");
        std::fs::rename(&continuation, &saved).unwrap();
        assert!(discover_shared_genesis_startup(&data, authority, 4).is_err());
        assert!(!continuation.exists());
        std::fs::rename(saved, continuation).unwrap();
        // An unissued intent may have persisted before its actor package.
        std::fs::rename(
            lifecycle_root.join("shared-management.actor"),
            scratch.0.join("saved-management-actor"),
        )
        .unwrap();
    }
    let (_, mut lifecycle) = open();
    let install_commitment = handoff_files
        .as_ref()
        .map(|(_, _, call, _)| call.commitment());
    let successor_input = handoff_files
        .as_ref()
        .map(|(_, install, call, package)| (install.clone(), call.clone(), package.clone()));
    if let Some((retained, install, install_call, package)) = handoff_files {
        assert!(!lifecycle_root.join("shared-management.actor").exists());
        lifecycle.initialize_shared_management(locator).unwrap();
        assert!(!lifecycle_root.join("shared-management.actor").exists());
        lifecycle
            .prepare_shared_install(install, install_call, &package)
            .unwrap();
        assert_eq!(journal_files(&lifecycle_root), retained);
    }
    assert_eq!(
        lifecycle
            .reserve_shared_create(&descriptor, &call, &runtime, &replicas)
            .unwrap(),
        locator
    );
    assert_eq!(
        lifecycle.complete_shared_create(locator).unwrap(),
        acknowledgement
    );
    assert_eq!(
        journal_files(&journal),
        applied,
        "terminal retry cannot repeat physical Create"
    );
    if let Some((descriptor, call, replicas, denied_locator)) = denied {
        let system_journal = data
            .join(SHARED_AGENT_HOST_DIRECTORY)
            .join(format!("{}.agent", hex::encode(authority.system_agent.0)));
        let before = journal_files(&system_journal);
        for _ in 0..2 {
            if with_handoff {
                assert_eq!(
                    lifecycle.initialize_shared_management(denied_locator),
                    Err(SharedAgentHostError::ScopeMismatch)
                );
            }
            assert_eq!(
                lifecycle
                    .reserve_shared_create(&descriptor, &call, &runtime, &replicas)
                    .unwrap(),
                denied_locator
            );
            assert_eq!(
                lifecycle.prepare_shared_create(denied_locator),
                Err(SharedAgentHostError::ScopeMismatch)
            );
            assert_eq!(
                lifecycle.publish_shared_create(denied_locator, vec![]),
                Err(SharedAgentHostError::ScopeMismatch)
            );
            assert_eq!(
                lifecycle.complete_shared_create(denied_locator),
                Err(SharedAgentHostError::ScopeMismatch)
            );
            assert_eq!(
                journal_files(&system_journal),
                before,
                "denial retry must not repeat Authority execution"
            );
        }
        assert!(
            !data
                .join(SHARED_AGENT_HOST_DIRECTORY)
                .join(format!("{}.agent", hex::encode(denied_locator.agent.0)))
                .exists()
        );
        assert_eq!(journal_files(&journal), applied);
    }
    if with_handoff {
        use super::super::clean_store::SharedManagementStageFault;
        use vos::agent::clean_authority_issuer::SignedManagementTerminal;
        if matches!(
            interrupt_install,
            InstallFault::Denial
                | InstallFault::DenialRetirement
                | InstallFault::DenialAuthorization
                | InstallFault::DenialSuccessor
        ) {
            use std::fs;
            let issuer_path = lifecycle_root.join("shared-management.issuer");
            let issuer_before = fs::read(&issuer_path).unwrap();
            let (denied_install, denied_call, _) = successor_input.as_ref().unwrap();
            assert!(
                lifecycle
                    .shared_install_denial(locator, denied_install, denied_call)
                    .unwrap()
                    .is_none()
            );
            let system_journal = data
                .join(SHARED_AGENT_HOST_DIRECTORY)
                .join(format!("{}.agent", hex::encode(authority.system_agent.0)));
            if matches!(
                interrupt_install,
                InstallFault::DenialRetirement | InstallFault::DenialAuthorization
            ) {
                // Authorization is the first intent write; CND1 follows the
                // positive ACK. Interrupt either durable boundary.
                let write = if matches!(interrupt_install, InstallFault::DenialAuthorization) {
                    1
                } else {
                    2
                };
                let fault = SharedManagementStageFault::intent(&lifecycle_root, write);
                assert_eq!(
                    lifecycle.complete_shared_install(locator),
                    Err(SharedAgentHostError::Unavailable)
                );
                assert!(fault.fired());
                assert!(
                    lifecycle_root
                        .join("shared-management.intent.next")
                        .exists()
                );
                assert_eq!(journal_files(&journal), applied);
                assert_eq!(fs::read(&issuer_path).unwrap(), issuer_before);
                drop(fault);
                drop(lifecycle);
                (_, lifecycle) = open();
                assert!(
                    !lifecycle_root
                        .join("shared-management.intent.next")
                        .exists()
                );
            }
            assert_eq!(
                lifecycle.complete_shared_install(locator),
                Err(SharedAgentHostError::ScopeMismatch)
            );
            assert_eq!(journal_files(&journal), applied);
            assert_eq!(fs::read(&issuer_path).unwrap(), issuer_before);
            let denied_system = journal_files(&system_journal);
            let certificate = lifecycle
                .shared_install_denial(locator, denied_install, denied_call)
                .unwrap()
                .unwrap();
            assert_eq!(
                vos::agent::local_lifecycle::SharedInstallDenial::verify(
                    denied_install,
                    denied_call,
                    certificate.exact_bytes()
                )
                .unwrap(),
                certificate
            );
            let mut forged_certificate = certificate.exact_bytes().to_vec();
            *forged_certificate.last_mut().unwrap() ^= 1;
            assert!(
                vos::agent::local_lifecycle::SharedInstallDenial::verify(
                    denied_install,
                    denied_call,
                    &forged_certificate
                )
                .is_err()
            );
            assert_eq!(
                lifecycle.complete_shared_install(locator),
                Err(SharedAgentHostError::ScopeMismatch)
            );
            assert_eq!(journal_files(&system_journal), denied_system);
            drop(lifecycle);
            let (_, mut lifecycle) = open();
            let recovered_system = journal_files(&system_journal);
            assert_eq!(
                lifecycle
                    .shared_install_denial(locator, denied_install, denied_call)
                    .unwrap(),
                Some(certificate.clone())
            );
            assert_eq!(
                lifecycle.complete_shared_install(locator),
                Err(SharedAgentHostError::ScopeMismatch)
            );
            assert_eq!(journal_files(&system_journal), recovered_system);
            assert_eq!(journal_files(&journal), applied);
            assert_eq!(fs::read(&issuer_path).unwrap(), issuer_before);
            // A fresh Authority read proves the rejected Install released its reservation.
            assert_eq!(
                lifecycle.complete_shared_create(locator).unwrap(),
                acknowledgement
            );
            if matches!(interrupt_install, InstallFault::DenialSuccessor) {
                let (install, mut successor, package) = successor_input.as_ref().unwrap().clone();
                successor.request_sequence = NonZeroU64::new(3).unwrap();
                successor.invocation = successor.expected_invocation();
                successor.signature = sign_exact(&operator, &successor.signing_bytes()).unwrap();
                assert!(
                    vos::agent::local_lifecycle::SharedInstallDenial::verify(
                        &install,
                        &successor,
                        certificate.exact_bytes()
                    )
                    .is_err()
                );
                let fault = SharedManagementStageFault::install_handoff(&lifecycle_root);
                assert_eq!(
                    lifecycle.prepare_shared_install(install.clone(), successor.clone(), &package),
                    Err(SharedAgentHostError::Unavailable)
                );
                assert!(fault.fired());
                assert_eq!(journal_files(&journal), applied);
                drop(fault);
                drop(lifecycle);
                let (_, mut lifecycle) = open();
                assert_eq!(journal_files(&journal), applied);
                lifecycle
                    .prepare_shared_install(install, successor.clone(), &package)
                    .unwrap();
                let terminal = lifecycle.complete_shared_install(locator).unwrap();
                let SignedManagementTerminal::Applied(ack) = &terminal else {
                    panic!("successor must apply");
                };
                assert_eq!(ack.credential_call, successor.commitment());
                let installed = journal_files(&journal);
                assert_ne!(installed, applied);
                drop(lifecycle);
                let (_, mut lifecycle) = open();
                let system = journal_files(&system_journal);
                assert_eq!(
                    lifecycle
                        .shared_install_denial(locator, denied_install, denied_call)
                        .unwrap(),
                    Some(certificate)
                );
                assert!(
                    lifecycle
                        .shared_install_denial(locator, denied_install, &successor)
                        .unwrap()
                        .is_none()
                );
                assert_eq!(
                    lifecycle.complete_shared_install(locator).unwrap(),
                    terminal
                );
                assert_eq!(journal_files(&journal), installed);
                assert_eq!(journal_files(&system_journal), system);
            }
            return;
        }
        if let Some(inputs) = &expiry {
            // Stop after signing the immutable receipt, before first application.
            let fault = SharedManagementStageFault::issuer(&lifecycle_root, 2);
            assert_eq!(
                lifecycle.complete_shared_install(locator),
                Err(SharedAgentHostError::Unavailable)
            );
            assert!(fault.fired());
            assert!(
                lifecycle_root
                    .join("shared-management.issuer.next")
                    .exists()
            );
            assert_eq!(journal_files(&journal), applied);
            drop(fault);
            drop(lifecycle);
            let (_, call, _) = successor_input.as_ref().unwrap();
            inputs
                .clock
                .fetch_max(call.requested_expires_at + 1, Ordering::AcqRel);
            // Reopen the receipt, record non-execution, then interrupt issuer
            // finality after sync but before publication under the real lease.
            let fault = SharedManagementStageFault::issuer(&lifecycle_root, 3);
            assert!(
                open_clean_system_lifecycle_with_inputs(
                    network.clone(),
                    &data,
                    space.0,
                    &operator,
                    &daemon,
                    crate::commands::space::local_config::LocalAgentStorage::Image,
                    &lock,
                    None,
                    expiry.as_ref(),
                )
                .is_err()
            );
            assert!(fault.fired());
            assert!(
                lifecycle_root
                    .join("shared-management.issuer.next")
                    .exists()
            );
            let fenced = journal_files(&journal);
            assert_ne!(fenced, applied);
            drop(fault);
            (_, lifecycle) = open();
            assert!(
                !lifecycle_root
                    .join("shared-management.issuer.next")
                    .exists()
            );
            assert_eq!(journal_files(&journal), fenced);
            let terminal = lifecycle.complete_shared_install(locator).unwrap();
            let SignedManagementTerminal::Rejected(failure) = &terminal else {
                panic!("expiry must not install");
            };
            assert_eq!(
                failure.error,
                vos::agent::sdk::ManagementError::ExpiredBeforeApplication
            );
            assert_eq!(Some(failure.credential_call), install_commitment);
            assert!(failure.failed_at > failure.receipt.selector.expires_at);
            let completed = journal_files(&lifecycle_root);
            drop(lifecycle);
            (_, lifecycle) = open();
            assert_eq!(
                lifecycle.complete_shared_install(locator).unwrap(),
                terminal
            );
            assert_eq!(journal_files(&journal), fenced);
            assert_eq!(journal_files(&lifecycle_root), completed);
            if let Some((other, acknowledgement, path, files)) = &retired_peer {
                assert_eq!(
                    lifecycle.complete_shared_create(*other).unwrap(),
                    *acknowledgement
                );
                assert_eq!(
                    journal_files(path),
                    *files,
                    "recovering expiry must not republish the retired peer"
                );
            }
            return;
        }
        let interruption = match interrupt_install {
            InstallFault::None
            | InstallFault::Expiry
            | InstallFault::MixedExpiry { .. }
            | InstallFault::Successive
            | InstallFault::Denial
            | InstallFault::DenialAuthorization
            | InstallFault::DenialSuccessor
            | InstallFault::DenialRetirement => None,
            InstallFault::Intent(write) => Some((
                SharedManagementStageFault::intent(&lifecycle_root, write),
                "shared-management.intent.next",
                write >= 2,
            )),
            InstallFault::Issuer(write) => Some((
                SharedManagementStageFault::issuer(&lifecycle_root, write),
                "shared-management.issuer.next",
                write >= 3,
            )),
        };
        if let Some((fault, staged_file, already_applied)) = interruption {
            // The first changed intent write retains authorization work; the
            // second retains finalization work after the signed observation.
            // Issuer writes retain the decision pledge, receipt, observation
            // pledge, signed terminal, and finality, in that order.
            // Leave its real staged envelope on disk, without publication.
            assert_eq!(
                lifecycle.complete_shared_install(locator),
                Err(SharedAgentHostError::Unavailable)
            );
            assert!(fault.fired());
            assert!(lifecycle_root.join(staged_file).exists());
            let installed = journal_files(&journal);
            if !already_applied {
                assert_eq!(
                    installed, applied,
                    "pre-application fault must leave the Agent unchanged"
                );
            } else {
                assert_ne!(
                    installed, applied,
                    "post-application fault must retain the applied Agent"
                );
            }
            drop(fault);
            drop(lifecycle);
            // Force a later wall-clock slot so fast machines cannot hide a
            // stale-envelope bug behind same-second recovery reads.
            let interrupted_at = system_logical_slot().unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while system_logical_slot().unwrap() <= interrupted_at
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(system_logical_slot().unwrap() > interrupted_at);
            (_, lifecycle) = open();
            assert!(!lifecycle_root.join(staged_file).exists());
            if !already_applied {
                assert_ne!(
                    journal_files(&journal),
                    installed,
                    "recovery must apply Install"
                );
            } else {
                assert_eq!(
                    journal_files(&journal),
                    installed,
                    "recovery must not reapply Install"
                );
            }
        }
        let terminal = lifecycle.complete_shared_install(locator).unwrap();
        let SignedManagementTerminal::Applied(ack) = &terminal else {
            panic!("valid retained Install must apply: {terminal:?}");
        };
        assert_eq!(Some(ack.credential_call), install_commitment);
        let completed = journal_files(&journal);
        assert_ne!(completed, applied, "Install must execute physically");
        let system_journal = data
            .join(SHARED_AGENT_HOST_DIRECTORY)
            .join(format!("{}.agent", hex::encode(authority.system_agent.0)));
        let system_completed = journal_files(&system_journal);
        let lifecycle_completed = journal_files(&lifecycle_root);
        assert_eq!(
            lifecycle.complete_shared_install(locator).unwrap(),
            terminal
        );
        assert_eq!(journal_files(&system_journal), system_completed);
        drop(lifecycle);
        let (_, mut lifecycle) = open();
        let recovered_system = journal_files(&system_journal);
        assert_eq!(
            lifecycle.complete_shared_install(locator).unwrap(),
            terminal
        );
        assert_eq!(journal_files(&journal), completed);
        assert_eq!(journal_files(&system_journal), recovered_system);
        assert_eq!(journal_files(&lifecycle_root), lifecycle_completed);
        assert!(matches!(
            discover_shared_genesis_startup(&data, authority, 4),
            Err(CleanFileStoreError::Busy)
        ));
        if matches!(interrupt_install, InstallFault::Successive) {
            for index in 0..3u8 {
                let name = format!("successor-catalog-{index}");
                use vos::agent::sdk::package::{PackageEnvelope, PackageManifest, PackageSigning};
                let mut envelope =
                    PackageEnvelope::decode(crate::bundled::system_catalog_package_template())
                        .unwrap();
                let PackageManifest::Actor(manifest) = &mut envelope.manifest else {
                    panic!("actor template");
                };
                manifest.name = name.clone();
                manifest.signing = PackageSigning {
                    producer: ProducerId::of_public_key(&public),
                    public_key: public,
                    signature: [0; 64],
                };
                envelope.manifest.signing_mut().signature =
                    sign_exact(&operator, &envelope.signing_bytes().unwrap()).unwrap();
                let package =
                    vos::agent::package_admission::admit_actor_package(&envelope.encode().unwrap())
                        .unwrap();
                let configuration = SystemCatalogConfiguration {
                    space: space.0,
                    system_agent: agent.0,
                    system_runtime_deployment: runtime.deployment().0,
                    actor: ActorId::top_level(agent, &name).0,
                    deployment: package.deployment().0,
                    program: package.program().0,
                    authority: CatalogAuthorityState {
                        policy: authority.binding.policy.0,
                        issuer: CatalogIssuerState {
                            principal: authority.binding.issuer.principal.0,
                            actor: authority.binding.issuer.actor.0,
                            deployment: authority.binding.issuer.deployment.0,
                            program: authority.binding.issuer.program.0,
                            producer: authority.binding.issuer.producer.0,
                        },
                        public_key: authority.binding.public_key,
                        initial_epoch: authority.binding.initial_epoch,
                    },
                };
                assert!(configuration.is_valid());
                let install = crate::commands::space::local_install::build_install(
                    agent,
                    InstallationId([0x90 + index; 32]),
                    Hash([0xa0 + index; 32]),
                    name,
                    None,
                    Some(configuration.encode()),
                    &package,
                )
                .unwrap();
                let mut next_call = call.clone();
                next_call.request_sequence = NonZeroU64::new(4 + u64::from(index)).unwrap();
                next_call.plan = ManagementRequest::Install(Box::new(install.clone()))
                    .authorization_plan()
                    .unwrap();
                next_call.invocation = next_call.expected_invocation();
                next_call.signature = sign_exact(&operator, &next_call.signing_bytes()).unwrap();
                let before = journal_files(&journal);
                if index == 1 {
                    // Consecutive refusals after an applied Install must keep
                    // that same finalized predecessor across each handoff.
                    for sequence in [99, 100] {
                        let mut denied_call = next_call.clone();
                        denied_call.request_sequence = NonZeroU64::new(sequence).unwrap();
                        denied_call.invocation = denied_call.expected_invocation();
                        denied_call.signature =
                            sign_exact(&operator, &denied_call.signing_bytes()).unwrap();
                        lifecycle
                            .prepare_shared_install(install.clone(), denied_call, &package)
                            .unwrap();
                        assert_eq!(
                            lifecycle.complete_shared_install(locator),
                            Err(SharedAgentHostError::ScopeMismatch)
                        );
                        assert_eq!(journal_files(&journal), before);
                        drop(lifecycle);
                        (_, lifecycle) = open();
                        assert_eq!(
                            lifecycle.complete_shared_install(locator),
                            Err(SharedAgentHostError::ScopeMismatch)
                        );
                        assert_eq!(journal_files(&journal), before);
                    }
                }
                let old_actor =
                    std::fs::read(lifecycle_root.join("shared-management.actor")).unwrap();
                let fault = match index {
                    0 => SharedManagementStageFault::install_handoff(&lifecycle_root),
                    1 => SharedManagementStageFault::intent(&lifecycle_root, 1),
                    _ => SharedManagementStageFault::actor(&lifecycle_root),
                };
                assert_eq!(
                    lifecycle.prepare_shared_install(install.clone(), next_call.clone(), &package),
                    Err(SharedAgentHostError::Unavailable),
                );
                assert!(fault.fired(), "handoff boundary {index}");
                assert_eq!(
                    std::fs::read(lifecycle_root.join("shared-management.actor")).unwrap(),
                    old_actor
                );
                assert_eq!(journal_files(&journal), before);
                drop(fault);
                drop(lifecycle);
                (_, lifecycle) = open();
                assert_eq!(
                    journal_files(&journal),
                    before,
                    "preparation must not execute Install"
                );
                lifecycle
                    .prepare_shared_install(install, next_call.clone(), &package)
                    .unwrap();
                let terminal = lifecycle.complete_shared_install(locator).unwrap();
                let SignedManagementTerminal::Applied(ack) = &terminal else {
                    panic!("successor Install failed: {terminal:?}");
                };
                assert_eq!(ack.credential_call, next_call.commitment());
                let completed = journal_files(&journal);
                assert_ne!(completed, before);
                drop(lifecycle);
                (_, lifecycle) = open();
                let system_completed = journal_files(&system_journal);
                assert_eq!(
                    lifecycle.complete_shared_install(locator).unwrap(),
                    terminal
                );
                assert_eq!(journal_files(&journal), completed);
                assert_eq!(journal_files(&system_journal), system_completed);
            }
        }
        drop(lifecycle);
    } else {
        drop(lifecycle);
    }
    network.shutdown();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while Arc::strong_count(&network) != 1 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    // No listeners or outside peers are used by this fixture.
    Arc::try_unwrap(network)
        .ok()
        .expect("all lifecycle owners released")
        .join();
}
