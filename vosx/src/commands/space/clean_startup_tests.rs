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
    check_shared_file_recovery(false, false);
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_create_file_owner_reopens_denial_beside_retired_generation() {
    check_shared_file_recovery(true, false);
}

#[test]
#[ignore = "executes bundled outer PVM with production file stores; use disk-backed TMPDIR"]
fn shared_management_handoff_reopens_under_production_lifecycle_owner() {
    check_shared_file_recovery(true, true);
}

fn check_shared_file_recovery(with_denial: bool, with_handoff: bool) {
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
    let open = || {
        open_clean_system_lifecycle(
            network.clone(),
            &data,
            space.0,
            &operator,
            &daemon,
            crate::commands::space::local_config::LocalAgentStorage::Image,
            &lock,
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
        retained
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
    }
    let (_, mut lifecycle) = open();
    if let Some(retained) = handoff_files {
        assert_eq!(journal_files(&lifecycle_root), retained);
        lifecycle.initialize_shared_management(locator).unwrap();
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
    drop(lifecycle);
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
