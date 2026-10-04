//! Production file owners and startup discovery, without a second bootstrap.
use super::*;
use std::path::PathBuf;
use vos::agent::clean_bootstrap::GenesisClaimSigner;
use vos::agent::committee::AuthoritySignerId;
use vos::network::{Network, NetworkConfig, derive_node_prefix};

#[cfg(feature = "experimental-state-blocks")]
#[path = "clean_startup/member_handoff_tests.rs"]
mod member_handoff;

#[cfg(feature = "experimental-state-blocks")]
#[path = "clean_startup/member_workflow_tests.rs"]
mod member_workflow;

#[cfg(feature = "experimental-state-blocks")]
#[path = "clean_startup/member_cold_install_tests.rs"]
mod member_cold_install;

struct Scratch(PathBuf);

#[test]
fn production_genesis_endorsement_requires_the_exact_single_root_voter() {
    use vos::agent::committee::{
        AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole,
    };
    use vos::agent::shared_host::SharedAgentHostError;
    let public = raw_public_key(&Keypair::ed25519_from_bytes([0x49; 32]).unwrap()).unwrap();
    let other = raw_public_key(&Keypair::ed25519_from_bytes([0x4a; 32]).unwrap()).unwrap();
    let root =
        AuthorityCommitteeMember::new(HostNodeId([0x4b; 32]), public, AuthorityMemberRole::Voter)
            .unwrap();
    let committee = |mut members: Vec<AuthorityCommitteeMember>| {
        members.sort_by_key(AuthorityCommitteeMember::signer);
        AuthorityCommittee::new(
            HostSpaceId([0x4c; 32]),
            HostHash([0x4d; 32]),
            1,
            None,
            members,
        )
        .unwrap()
    };
    assert_eq!(
        production_genesis_signer(&committee(vec![root.clone()]), &public),
        Ok(root.signer())
    );
    assert_eq!(
        production_genesis_signer(&committee(vec![root.clone()]), &other),
        Err(SharedAgentHostError::ScopeMismatch)
    );
    for role in [AuthorityMemberRole::Voter, AuthorityMemberRole::Observer] {
        let member = AuthorityCommitteeMember::new(HostNodeId([0x4e; 32]), other, role).unwrap();
        assert_eq!(
            production_genesis_signer(&committee(vec![root.clone(), member]), &public),
            Err(SharedAgentHostError::ScopeMismatch)
        );
    }
}

#[test]
fn bootstrap_roster_requires_exact_signed_owner_and_node_inputs() {
    let space = SpaceId([0x61; 32]);
    let agent = AgentId([0x62; 32]);
    let owner = PrincipalId([0x63; 32]);
    let mut nodes = Vec::new();
    for seed in [0x64, 0x65, 0x66] {
        let key = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
        nodes.push(
            sign_node_encryption_enrollment(
                &key,
                space,
                owner,
                derive_node_encryption_public(&key, space).unwrap(),
            )
            .unwrap(),
        );
    }
    let mut sorted = nodes.clone();
    sorted.sort_by_key(|node| node.node);
    for primary in &nodes {
        let roster =
            SystemBootstrapRoster::from_enrollments(space, agent, owner, primary.node, &nodes)
                .unwrap();
        assert_eq!(roster.primary, *primary);
        let expected: Vec<_> = sorted
            .iter()
            .map(|node| AgentReplica {
                node: node.node,
                principal: PrincipalId::of_public_key(&node.transport_public_key),
                role: ReplicaRole::Voter,
            })
            .collect();
        assert_eq!(roster.descriptor_replicas(), expected);
        let extra = roster.additional.unwrap();
        let expected_extra: Vec<_> = sorted
            .iter()
            .filter(|node| node.node != primary.node)
            .collect();
        for (actual, expected) in extra.iter().zip(expected_extra) {
            assert_eq!(actual.transport_public_key, expected.transport_public_key);
            assert_eq!(actual.encryption_public_key, expected.encryption_public_key);
            assert_eq!(actual.transport_signature, expected.transport_signature);
        }
        let mut reversed = nodes.clone();
        reversed.reverse();
        let reversed =
            SystemBootstrapRoster::from_enrollments(space, agent, owner, primary.node, &reversed)
                .unwrap();
        assert_eq!(reversed.replicas, roster.replicas);
        let single =
            SystemBootstrapRoster::from_enrollments(space, agent, owner, primary.node, &[*primary])
                .unwrap();
        assert!(single.additional.is_none());
        assert_eq!(single.descriptor_replicas().len(), 1);
    }
    let check = |nodes: &[vos::agent::sdk::private::NodeEncryptionEnrollment]| {
        SystemBootstrapRoster::from_enrollments(space, agent, owner, sorted[0].node, nodes)
    };
    assert!(check(&[]).is_err());
    assert!(check(&sorted[..2]).is_err());
    assert!(check(&[sorted[0]; 3]).is_err());
    assert!(check(&[sorted[0], sorted[1], sorted[2], sorted[0]]).is_err());
    assert!(
        SystemBootstrapRoster::from_enrollments(
            space,
            agent,
            owner,
            vos::agent::sdk::NodeId([0xff; 32]),
            &sorted
        )
        .is_err()
    );
    for field in 0..5 {
        let mut altered = sorted.clone();
        match field {
            0 => altered[1].space = SpaceId([0x71; 32]),
            1 => altered[1].principal = PrincipalId([0x72; 32]),
            2 => altered[1].transport_signature[0] ^= 1,
            3 => altered[1].transport_peer_id[0] ^= 1,
            _ => altered[1].encryption_public_key[0] ^= 1,
        }
        assert!(check(&altered).is_err(), "field {field}");
    }
    // A cryptographically valid enrollment for a different owner is also
    // refused; node possession alone cannot select the Space's operator.
    let key = Keypair::ed25519_from_bytes([0x65; 32]).unwrap();
    let mut foreign = nodes;
    foreign[1] = sign_node_encryption_enrollment(
        &key,
        space,
        PrincipalId([0x72; 32]),
        derive_node_encryption_public(&key, space).unwrap(),
    )
    .unwrap();
    assert!(check(&foreign).is_err());
}

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

#[test]
fn bootstrap_roster_refuses_old_contracts_and_binds_exact_system_observation_configuration() {
    let operator = Keypair::ed25519_from_bytes([0x61; 32]).unwrap();
    let public = raw_public_key(&operator).unwrap();
    let owner = PrincipalId::of_public_key(&public);
    let space = SpaceId([0x62; 32]);
    let runtime = crate::bundled::root_signed_agent_runtime_package(&operator).unwrap();
    let authority = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template(),
        SYSTEM_AUTHORITY_NAME,
        &operator,
    )
    .unwrap();
    let (target, nonce) =
        derive_system_authority_target(space, public, &runtime, &authority).unwrap();
    let mut nodes = Vec::new();
    for seed in [0x64, 0x65, 0x66] {
        let key = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
        nodes.push(
            sign_node_encryption_enrollment(
                &key,
                space,
                owner,
                derive_node_encryption_public(&key, space).unwrap(),
            )
            .unwrap(),
        );
    }
    for count in [1, 3] {
        let selected = &nodes[..count];
        for primary in selected {
            let roster = SystemBootstrapRoster::from_enrollments(
                space,
                target.system_agent,
                owner,
                primary.node,
                selected,
            )
            .unwrap();
            let descriptor = AgentDescriptor {
                identity: AgentIdentity {
                    space,
                    agent: target.system_agent,
                    owner,
                    profile: AgentProfile::Shared,
                    runtime_deployment: runtime.deployment(),
                    runtime_program: runtime.program(),
                    runtime_producer: runtime.producer(),
                    transition_producer: ProducerId::of_public_key(&primary.transport_public_key),
                },
                creation_nonce: nonce,
                authority: target.binding,
                private_recovery: None,
                runtime_package: runtime.package_ref().clone(),
                runtime_contract: runtime.manifest().contract,
                capabilities: runtime.capabilities(),
                replicas: roster.descriptor_replicas(),
            };
            let configuration = roster.authority_configuration(&descriptor, public).unwrap();
            assert!(configuration.matches_system_descriptor(&descriptor));
            let bytes = configuration.encode();
            assert_eq!(&bytes[..4], if count == 1 { b"SAC5" } else { b"SAC6" });
            assert_eq!(
                SystemAuthorityConfiguration::decode(&bytes),
                Some(configuration)
            );
            assert!(
                validate_system_observation_bootstrap_configuration(&descriptor, &bytes).is_err(),
                "SAC5/SAC6 or the old canonical contract must not become v1 startup inputs"
            );
            #[cfg(feature = "experimental-state-blocks")]
            if count == 3 {
                // Positive matching uses the distinct signed System image,
                // never a canonical Local PVM with relabelled metadata.
                let observation_runtime =
                    crate::bundled::root_signed_system_agent_runtime_package(&operator).unwrap();
                assert_eq!(
                    observation_runtime.manifest().contract.lifecycle_abi,
                    vos::agent::sdk::SYSTEM_OBSERVATION_ABI_ID,
                );
                assert_ne!(observation_runtime.program(), runtime.program());
                let (observation_target, observation_nonce) =
                    derive_system_authority_target(space, public, &observation_runtime, &authority)
                        .unwrap();
                let observation_roster = SystemBootstrapRoster::from_enrollments(
                    space,
                    observation_target.system_agent,
                    owner,
                    primary.node,
                    selected,
                )
                .unwrap();
                let mut observation = descriptor.clone();
                observation.creation_nonce = observation_nonce;
                observation.identity.agent = observation_target.system_agent;
                observation.identity.runtime_deployment = observation_runtime.deployment();
                observation.identity.runtime_program = observation_runtime.program();
                observation.identity.runtime_producer = observation_runtime.producer();
                observation.authority = observation_target.binding;
                observation.runtime_package = observation_runtime.package_ref().clone();
                observation.runtime_contract = observation_runtime.manifest().contract;
                observation.capabilities = observation_runtime.capabilities();
                observation.replicas = observation_roster.descriptor_replicas();
                let observation_configuration = observation_roster
                    .authority_configuration(&observation, public)
                    .unwrap();
                let observation_bytes = observation_configuration.encode();
                assert_eq!(&observation_bytes[..4], b"SAC7");
                validate_system_observation_bootstrap_configuration(
                    &observation,
                    &observation_bytes,
                )
                .unwrap();
                for field in 0..5 {
                    let mut changed = observation.clone();
                    match field {
                        0 => changed.runtime_contract.resources.max_runtime_state_bytes -= 1,
                        1 => changed.replicas.pop().map(|_| ()).unwrap(),
                        2 => changed.replicas[2].role = ReplicaRole::Observer,
                        3 => {
                            changed.identity.runtime_program =
                                vos::agent::sdk::ProgramId([0x98; 32])
                        }
                        4 => changed.identity.owner = PrincipalId([0x97; 32]),
                        _ => unreachable!(),
                    }
                    assert!(
                        validate_system_observation_bootstrap_configuration(
                            &changed,
                            &observation_bytes,
                        )
                        .is_err()
                    );
                }
                let mut legacy_tag = observation_bytes.clone();
                legacy_tag[..4].copy_from_slice(b"SAC6");
                assert!(
                    validate_system_observation_bootstrap_configuration(&observation, &legacy_tag)
                        .is_err()
                );
            }
            assert_eq!(configuration.bootstrap_node, primary.node.0);
            assert_eq!(configuration.bootstrap_principal, owner.0);
            assert_eq!(
                configuration.bootstrap_replica_principal,
                PrincipalId::of_public_key(&primary.transport_public_key).0
            );
            assert!(
                roster
                    .authority_configuration(&descriptor, [0x99; 32])
                    .is_err()
            );
            let mut changed = descriptor.clone();
            changed.replicas[0].principal = owner;
            assert!(roster.authority_configuration(&changed, public).is_err());
            let mut changed = descriptor;
            changed.identity.agent = AgentId([0x99; 32]);
            assert!(roster.authority_configuration(&changed, public).is_err());
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn pending_system_observation_release_gate_leaves_fresh_and_experimental_roots_untouched() {
    use crate::commands::space::clean_store::ensure_private_directory;
    use crate::commands::space::local_config::LocalAgentStorage;
    let scratch = Scratch::new();
    let operator = Keypair::ed25519_from_bytes([0x58; 32]).unwrap();
    let daemon = Keypair::ed25519_from_bytes([0x5b; 32]).unwrap();
    let before = journal_files(&scratch.0);
    for _ in 0..2 {
        let error = preflight_released_system_startup(
            &scratch.0,
            LocalAgentStorage::Image,
            None,
            &operator,
            [0x5a; 32],
            &daemon,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains(
                "requires a supplied root-certified plan or canonical retained CSB5 plan"
            )
        );
        assert_eq!(journal_files(&scratch.0), before);
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    // A malformed/partial old control root is not permission to reconcile its
    // stages, create missing images or silently select another runtime role.
    let control = scratch.0.join(SYSTEM_AGENT_CONTROL_DIRECTORY);
    drop(ensure_private_directory(&control).unwrap());
    std::fs::write(
        control.join("experimental-space-marker"),
        b"preserve old inputs",
    )
    .unwrap();
    let before = journal_files(&scratch.0);
    assert!(
        preflight_released_system_startup(
            &scratch.0,
            LocalAgentStorage::Image,
            None,
            &operator,
            [0x5a; 32],
            &daemon,
        )
        .is_err()
    );
    assert_eq!(journal_files(&scratch.0), before);

    // The retired Local spelling is refused before any System selection or
    // mutation, even in a build that understands external Shared runtimes.
    let error = preflight_released_system_startup(
        &scratch.0,
        LocalAgentStorage::ExternalState,
        None,
        &operator,
        [0x5a; 32],
        &daemon,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("external-state Local deployment is unsupported")
    );
    assert_eq!(journal_files(&scratch.0), before);
}

#[test]
fn system_preflight_refuses_shared_residue_without_retained_plan_before_writes() {
    use crate::commands::space::clean_store::ensure_private_directory;
    use crate::commands::space::local_config::LocalAgentStorage;
    let operator = Keypair::ed25519_from_bytes([0x5f; 32]).unwrap();
    let daemon = Keypair::ed25519_from_bytes([0x5b; 32]).unwrap();
    for directory in [true, false] {
        let scratch = Scratch::new();
        let shared = scratch.0.join(SHARED_AGENT_HOST_DIRECTORY);
        if directory {
            drop(ensure_private_directory(&shared).unwrap());
            std::fs::write(shared.join("retained-marker"), b"preserve Shared residue").unwrap();
        } else {
            std::fs::write(&shared, b"preserve non-directory Shared residue").unwrap();
        }
        let before = journal_files(&scratch.0);
        for _ in 0..2 {
            let error = preflight_released_system_startup(
                &scratch.0,
                LocalAgentStorage::Image,
                None,
                &operator,
                [0x5a; 32],
                &daemon,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("Shared deployment residue lacks its retained System bootstrap plan")
            );
            assert_eq!(journal_files(&scratch.0), before);
            assert!(!scratch.0.join(SYSTEM_AGENT_CONTROL_DIRECTORY).exists());
            assert!(!scratch.0.join(LOCAL_AGENT_HOST_DIRECTORY).exists());
            assert!(!scratch.0.join(LOCAL_LIFECYCLE_DIRECTORY).exists());
        }
    }
}

#[test]
fn system_preflight_refuses_retired_or_incomplete_retained_records_without_writes() {
    use crate::commands::space::local_config::LocalAgentStorage;
    let operator = Keypair::ed25519_from_bytes([0x59; 32]).unwrap();
    let daemon = Keypair::ed25519_from_bytes([0x5b; 32]).unwrap();
    for version in [3, 4, 5] {
        let scratch = Scratch::new();
        let control = scratch.0.join(SYSTEM_AGENT_CONTROL_DIRECTORY);
        let (mut pins, mut bootstrap, issuer, mut genesis) =
            CleanSystemAgentFileStores::open_or_create(&control)
                .unwrap()
                .into_production_parts();
        // Valid file-store envelopes ensure preflight reaches the read-only
        // bootstrap decoder. Retired headers refuse before their body, while
        // the current header still needs a complete certified plan.
        let mut record = b"CSB2".to_vec();
        record.extend_from_slice(vos::agent::sdk::RUNTIME_ABI_ID.as_bytes());
        record.push(version);
        pins.commit(b"uninterpreted pins for record-header rejection")
            .unwrap();
        bootstrap.commit(&record).unwrap();
        genesis
            .commit(b"uninterpreted genesis for record-header rejection")
            .unwrap();
        drop((pins, bootstrap, issuer, genesis));
        let before = journal_files(&scratch.0);
        for _ in 0..2 {
            let error = preflight_released_system_startup(
                &scratch.0,
                LocalAgentStorage::Image,
                None,
                &operator,
                [0x5a; 32],
                &daemon,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("invalid persisted bootstrap plan")
            );
            assert_eq!(journal_files(&scratch.0), before);
            assert!(!scratch.0.join(SHARED_AGENT_HOST_DIRECTORY).exists());
            assert!(!scratch.0.join(LOCAL_AGENT_HOST_DIRECTORY).exists());
        }
    }
}

#[cfg(feature = "experimental-state-blocks")]
fn fixed_three_materials_for_packaged_preflight(
    operator: &Keypair,
    runtime: vos::agent::package_admission::AdmittedRuntimePackage,
    authority: AdmittedActorPackage,
) -> SystemBootstrapMaterials {
    let space = SpaceId([0x5a; 32]);
    let public = raw_public_key(operator).unwrap();
    let owner = PrincipalId::of_public_key(&public);
    let enrollments: Vec<_> = [0x5b, 0x5c, 0x5d]
        .into_iter()
        .map(|seed| {
            let daemon = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
            sign_node_encryption_enrollment(
                &daemon,
                space,
                owner,
                derive_node_encryption_public(&daemon, space).unwrap(),
            )
            .unwrap()
        })
        .collect();
    SystemBootstrapMaterials::new(
        space,
        public,
        enrollments[0].node,
        runtime,
        authority,
        crate::bundled::root_signed_actor_package(
            crate::bundled::system_catalog_package_template(),
            SYSTEM_CATALOG_NAME,
            operator,
        )
        .unwrap(),
        &enrollments,
    )
    .unwrap()
}

#[cfg(feature = "experimental-state-blocks")]
fn prepared_startup_stage_fixture(
    scratch: &Scratch,
    operator: &Keypair,
    daemon: &Keypair,
) -> (PreparedCleanSystemAgentBootstrap, Vec<u8>, PathBuf) {
    let materials = fixed_three_materials_for_packaged_preflight(
        operator,
        crate::bundled::root_signed_system_agent_runtime_package(operator).unwrap(),
        crate::bundled::root_signed_actor_package(
            crate::bundled::system_authority_package_template(),
            SYSTEM_AUTHORITY_NAME,
            operator,
        )
        .unwrap(),
    );
    let output = scratch.0.join("prepared-stages");
    bootstrap_prepare::prepare_materials(materials, operator, daemon, &output).unwrap();
    let bundle = output.join("common.bundle");
    let prepared = read_certified_bootstrap_bundle(&bundle, [0x5a; 32], operator, daemon).unwrap();
    let archive = CleanSystemAgentFileStores::read_startup_bootstrap(&output.join("certification"))
        .unwrap()
        .unwrap()
        .genesis
        .selected_payload()
        .unwrap()
        .to_vec();
    (prepared, archive, bundle)
}

#[cfg(feature = "experimental-state-blocks")]
fn startup_record_fixture(
    prepared: &PreparedCleanSystemAgentBootstrap,
    receipt: Option<&vos::agent::sdk::authority::AuthorityReceipt>,
) -> (Vec<u8>, Vec<u8>) {
    use vos::agent::sdk::wire::CanonicalWire as _;
    // Host CSB5 test bytes embed the immutable public plan/pins transported by
    // the real certified bundle; no signed input or certificate is invented.
    let imported = prepared.encode_import().unwrap();
    let length = usize::try_from(u64::from_le_bytes(imported[36..44].try_into().unwrap())).unwrap();
    let plan = &imported[44..44 + length];
    let pins_length = u32::from_le_bytes(plan[36..40].try_into().unwrap()) as usize;
    let pins = plan[40..40 + pins_length].to_vec();
    assert_eq!(
        Hash::digest(b"vos/clean-system-agent-pins/v2", &[&pins]),
        prepared.plan().pins().commitment()
    );
    let mut record = b"CSB2".to_vec();
    record.extend_from_slice(vos::agent::sdk::RUNTIME_ABI_ID.as_bytes());
    record.extend_from_slice(&[5, u8::from(receipt.is_some())]);
    record.extend_from_slice(prepared.plan().pins().commitment().as_bytes());
    record.extend_from_slice(prepared.plan().commitment().as_bytes());
    record.extend_from_slice(&(plan.len() as u64).to_le_bytes());
    record.extend_from_slice(plan);
    match receipt {
        Some(receipt) => {
            let bytes = receipt.encode().unwrap();
            record.push(1);
            record.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            record.extend_from_slice(&bytes);
        }
        None => record.push(0),
    }
    record.extend_from_slice(&[0; 4]);
    assert_eq!(
        CleanSystemAgentBootstrapRecord::authorized_plan(&record)
            .unwrap()
            .commitment(),
        prepared.plan().commitment()
    );
    (pins, record)
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
fn system_startup_stage_admission_validates_every_candidate_before_locked_recovery() {
    use crate::commands::space::clean_store::{
        ensure_private_directory, tests::stage_startup_images,
    };
    use crate::commands::space::local_config::LocalAgentStorage;
    use vos::agent::clean_authority_issuer::CleanManagementIssuerStore as _;
    let scratch = Scratch::new();
    let operator = Keypair::ed25519_from_bytes([0x66; 32]).unwrap();
    let daemon = Keypair::ed25519_from_bytes([0x5b; 32]).unwrap();
    let (prepared, genesis_bytes, bundle) =
        prepared_startup_stage_fixture(&scratch, &operator, &daemon);
    let vos::agent::journal::ReplayOperation::CleanManage {
        authority: receipt, ..
    } = &prepared.provision().proposal().create().operation
    else {
        unreachable!()
    };
    let (pins_bytes, record_bytes) = startup_record_fixture(&prepared, None);
    let alternate_daemon = Keypair::ed25519_from_bytes([0x5c; 32]).unwrap();
    let alternate =
        read_certified_bootstrap_bundle(&bundle, [0x5a; 32], &operator, &alternate_daemon).unwrap();
    let (_, alternate_record) = startup_record_fixture(&alternate, None);
    let mut forged = receipt.clone();
    forged.signature[0] ^= 1;
    let (_, forged_record) = startup_record_fixture(&prepared, Some(&forged));
    assert!(CleanSystemAgentBootstrapRecord::validated_startup_plan(&forged_record).is_err());

    for corruption in 0..7 {
        let data = scratch.0.join(format!("stage-{corruption}"));
        drop(ensure_private_directory(&data).unwrap());
        let control = data.join(SYSTEM_AGENT_CONTROL_DIRECTORY);
        let (mut pins, mut bootstrap, issuer, mut genesis) =
            CleanSystemAgentFileStores::open_or_create(&control)
                .unwrap()
                .into_production_parts();
        pins.commit(&pins_bytes).unwrap();
        let mut canonical_record = record_bytes.clone();
        if corruption == 1 {
            canonical_record[36] = 4;
        }
        bootstrap.commit(&canonical_record).unwrap();
        genesis.commit(&genesis_bytes).unwrap();
        drop((pins, bootstrap, issuer, genesis));
        let candidates = match corruption {
            0 => [
                Some(pins_bytes.as_slice()),
                Some(record_bytes.as_slice()),
                None,
                Some(genesis_bytes.as_slice()),
            ],
            1 => [None, Some(record_bytes.as_slice()), None, None],
            2 => [None, Some(alternate_record.as_slice()), None, None],
            3 => [None, Some(forged_record.as_slice()), None, None],
            4 => [None, None, Some(b"malformed issuer".as_slice()), None],
            5 => [None, None, None, Some(b"malformed archive".as_slice())],
            6 => [Some(b"different pins".as_slice()), None, None, None],
            _ => unreachable!(),
        };
        stage_startup_images(&control, candidates);
        let before = journal_files(&data);
        let result = inspect_released_system_startup(
            &data,
            LocalAgentStorage::Image,
            Some(&prepared),
            &operator,
            [0x5a; 32],
            &daemon,
        );
        assert_eq!(journal_files(&data), before);
        assert!(!data.join(SHARED_AGENT_HOST_DIRECTORY).exists());
        if corruption != 0 {
            assert!(
                result.is_err(),
                "must refuse candidate {corruption} before stage publication"
            );
            continue;
        }
        let inspection = result.unwrap();
        let retained = inspect_released_system_startup(
            &data,
            LocalAgentStorage::Image,
            None,
            &operator,
            [0x5a; 32],
            &daemon,
        )
        .unwrap();
        assert_eq!(retained, inspection);
        let admitted = preflight_released_system_startup(
            &data,
            LocalAgentStorage::Image,
            Some(&prepared),
            &operator,
            [0x5a; 32],
            &daemon,
        )
        .unwrap();
        assert_eq!(
            admitted, inspection,
            "preflight preserves the exact inspected snapshot"
        );
        assert_eq!(journal_files(&data), before);
        assert!(CleanSystemAgentFileStores::read_client_bootstrap(&control).is_err());
        let stores = CleanSystemAgentFileStores::open_or_create(&control).unwrap();
        assert!(stores.matches_startup_inspection(&inspection).unwrap());
        let (mut pins, mut bootstrap, mut issuer, mut genesis) = stores.into_production_parts();
        assert_eq!(
            pins.load(MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES)
                .unwrap()
                .as_deref(),
            Some(pins_bytes.as_slice())
        );
        assert_eq!(
            bootstrap
                .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
                .unwrap()
                .as_deref(),
            Some(record_bytes.as_slice())
        );
        assert!(issuer.load().unwrap().is_none());
        assert_eq!(
            genesis.load().unwrap().as_deref(),
            Some(genesis_bytes.as_slice())
        );
        assert!(CleanSystemAgentFileStores::read_client_bootstrap(&control).is_ok());
    }
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
fn system_startup_empty_and_exact_pins_only_initialization_require_supplied_certificate() {
    use crate::commands::space::clean_store::ensure_private_directory;
    use crate::commands::space::local_config::LocalAgentStorage;
    let scratch = Scratch::new();
    let operator = Keypair::ed25519_from_bytes([0x68; 32]).unwrap();
    let daemon = Keypair::ed25519_from_bytes([0x5b; 32]).unwrap();
    let (prepared, _, _) = prepared_startup_stage_fixture(&scratch, &operator, &daemon);
    let (pins_bytes, _) = startup_record_fixture(&prepared, None);
    for pins_only in [false, true] {
        let data = scratch.0.join(format!("initialization-{pins_only}"));
        drop(ensure_private_directory(&data).unwrap());
        let control = data.join(SYSTEM_AGENT_CONTROL_DIRECTORY);
        drop(ensure_private_directory(&control).unwrap());
        if pins_only {
            let (mut pins, bootstrap, issuer, genesis) =
                CleanSystemAgentFileStores::open_or_create(&control)
                    .unwrap()
                    .into_production_parts();
            pins.commit(&pins_bytes).unwrap();
            drop((pins, bootstrap, issuer, genesis));
        }
        let before = journal_files(&data);
        assert!(
            inspect_released_system_startup(
                &data,
                LocalAgentStorage::Image,
                None,
                &operator,
                [0x5a; 32],
                &daemon
            )
            .is_err()
        );
        let inspection = inspect_released_system_startup(
            &data,
            LocalAgentStorage::Image,
            Some(&prepared),
            &operator,
            [0x5a; 32],
            &daemon,
        )
        .unwrap();
        assert_eq!(journal_files(&data), before);
        let stores = CleanSystemAgentFileStores::open_or_create(&control).unwrap();
        assert!(stores.matches_startup_inspection(&inspection).unwrap());
        let (mut pins, mut bootstrap, issuer, genesis) = stores.into_production_parts();
        let pins = pins.load(MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES).unwrap();
        let record = bootstrap
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .unwrap();
        assert_eq!(pins.as_deref(), pins_only.then_some(pins_bytes.as_slice()));
        assert!(record.is_none());
        let target = prepared.plan().pins().descriptor();
        let archive = CleanSystemAgentGenesisArchive::new(
            genesis,
            HostSpaceId(target.identity.space.0),
            HostAgentId(target.identity.agent.0),
            HostNodeId(prepared.plan().pins().node().0),
            HostHash(target.authority.commitment().0),
            operator.clone(),
        )
        .unwrap();
        import_certified_system_bootstrap(
            pins.as_deref(),
            None,
            &archive,
            &prepared,
            &data.join(SHARED_AGENT_HOST_DIRECTORY),
        )
        .unwrap();
        let published = journal_files(&data);
        import_certified_system_bootstrap(
            pins.as_deref(),
            None,
            &archive,
            &prepared,
            &data.join(SHARED_AGENT_HOST_DIRECTORY),
        )
        .unwrap();
        assert_eq!(journal_files(&data), published);
        assert!(
            import_certified_system_bootstrap(
                Some(b"substituted pins"),
                None,
                &archive,
                &prepared,
                &data.join(SHARED_AGENT_HOST_DIRECTORY)
            )
            .is_err()
        );
        assert_eq!(journal_files(&data), published);
        drop(ensure_private_directory(&data.join(SHARED_AGENT_HOST_DIRECTORY)).unwrap());
        let residue = journal_files(&data);
        assert!(
            import_certified_system_bootstrap(
                pins.as_deref(),
                None,
                &archive,
                &prepared,
                &data.join(SHARED_AGENT_HOST_DIRECTORY)
            )
            .is_err()
        );
        assert_eq!(journal_files(&data), residue);
        drop((bootstrap, issuer, archive));
    }
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
fn retained_system_startup_target_keeps_the_complete_roster_and_exact_signed_closure() {
    let scratch = Scratch::new();
    let before = journal_files(&scratch.0);
    let operator = Keypair::ed25519_from_bytes([0x60; 32]).unwrap();
    let public = raw_public_key(&operator).unwrap();
    let runtime = crate::bundled::root_signed_system_agent_runtime_package(&operator).unwrap();
    let authority = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template(),
        SYSTEM_AUTHORITY_NAME,
        &operator,
    )
    .unwrap();
    let materials = fixed_three_materials_for_packaged_preflight(&operator, runtime, authority);
    let descriptor = materials.descriptor.clone();
    let check = |descriptor: &AgentDescriptor,
                 runtime: &vos::agent::package_admission::AdmittedRuntimePackage| {
        system_startup_target_from_descriptor(
            descriptor,
            descriptor.identity.space,
            public,
            runtime,
            &materials.authority_package,
            &materials.catalog_package,
        )
    };
    let ManagementRequest::Install(install) = &materials.authority_request else {
        unreachable!()
    };
    let configuration =
        SystemAuthorityConfiguration::decode(&install.installation_data.as_ref().unwrap().bytes)
            .unwrap();
    assert!(configuration.matches_system_descriptor(&descriptor));
    assert_eq!(descriptor.replicas.len(), 3);
    assert_eq!(
        check(&descriptor, &materials.runtime).unwrap(),
        materials.authority_target(),
        "each reopening voter uses the same founding descriptor, not a new singleton"
    );
    assert_eq!(materials.descriptor, descriptor);
    assert_eq!(configuration.bootstrap_additional_nodes.unwrap().len(), 2);

    let local = crate::bundled::root_signed_agent_runtime_package(&operator).unwrap();
    assert!(check(&descriptor, &local).is_err());
    let mut wrong_program = descriptor.clone();
    wrong_program.identity.runtime_program.0[0] ^= 1;
    assert!(check(&wrong_program, &materials.runtime).is_err());
    let mut wrong_package = descriptor.clone();
    wrong_package.runtime_package.hash.0[0] ^= 1;
    assert!(check(&wrong_package, &materials.runtime).is_err());
    let mut wrong_authority = descriptor;
    wrong_authority.authority.policy.0[0] ^= 1;
    assert!(check(&wrong_authority, &materials.runtime).is_err());
    assert_eq!(journal_files(&scratch.0), before);
    assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
fn packaged_system_prewrite_binding_refuses_same_sac7_other_runtime_and_authority_closures() {
    use vos::agent::package_admission::{admit_actor_package, admit_runtime_package};
    use vos::agent::sdk::contract::RuntimePackageContract;
    use vos::agent::sdk::package::{PackageEnvelope, PackageManifest};
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    let scratch = Scratch::new();
    let before = journal_files(&scratch.0);
    let operator = Keypair::ed25519_from_bytes([0x5e; 32]).unwrap();
    let authority = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template(),
        SYSTEM_AUTHORITY_NAME,
        &operator,
    )
    .unwrap();
    let candidate_program = Assembler::new()
        .load_imm_64(Reg::A0, 0x5f)
        .trap()
        .build_standard();
    assert_ne!(candidate_program, crate::bundled::agent_runtime_pvm());
    let candidate_runtime = admit_runtime_package(
        &crate::bundled::root_signed_runtime_package_bytes(
            &operator,
            &candidate_program,
            "system-image-runtime",
            RuntimePackageContract::system_observation_image(),
            vos::agent::sdk::RuntimeCapabilities::standard(),
            None,
        )
        .unwrap(),
    )
    .unwrap();
    let check = |materials: &SystemBootstrapMaterials| {
        let ManagementRequest::Install(install) = &materials.authority_request else {
            unreachable!()
        };
        let bytes = &install.installation_data.as_ref().unwrap().bytes;
        assert!(bytes.starts_with(b"SAC7"));
        validate_system_observation_bootstrap_configuration(&materials.descriptor, bytes).unwrap();
        validate_packaged_system_observation_bootstrap_materials(
            &materials.descriptor,
            materials.runtime.exact_bytes(),
            materials.authority_package.exact_bytes(),
            &materials.authority_request,
            materials.catalog_package.exact_bytes(),
            &materials.catalog_request,
            &operator,
        )
    };
    let candidate = fixed_three_materials_for_packaged_preflight(
        &operator,
        candidate_runtime,
        authority.clone(),
    );
    let runtime = match crate::bundled::root_signed_system_agent_runtime_package(&operator) {
        Ok(runtime) => runtime,
        Err(unavailable) => {
            // Missing packaged bytes must refuse even a signed, admitted
            // same-ABI/SAC7 closure. This is not a fixture promotion fallback.
            let error = check(&candidate).unwrap_err();
            assert_eq!(error.to_string(), unavailable.to_string());
            assert!(
                error
                    .to_string()
                    .contains("release artifact is not yet qualified and pinned")
            );
            assert_eq!(journal_files(&scratch.0), before);
            assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
            return;
        }
    };
    let canonical =
        fixed_three_materials_for_packaged_preflight(&operator, runtime.clone(), authority.clone());
    check(&canonical).unwrap();
    assert_eq!(
        canonical.runtime.manifest().contract,
        candidate.runtime.manifest().contract
    );
    assert_ne!(canonical.runtime.program(), candidate.runtime.program());
    assert!(
        check(&candidate)
            .unwrap_err()
            .to_string()
            .contains("System runtime differs from the exact packaged System observation role")
    );

    // A root-signed actor with the same admitted schema/policy but a different
    // program is still not the packaged Authority. Preserve its full closure
    // and re-sign it normally rather than forging an admitted value.
    let mut envelope = PackageEnvelope::decode(authority.exact_bytes()).unwrap();
    let PackageManifest::Actor(manifest) = &mut envelope.manifest else {
        unreachable!()
    };
    let previous_program = manifest.program.clone();
    let replacement = BlobRef::of_bytes(&candidate_program);
    manifest.program = replacement.clone();
    let artifact = envelope
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.identity == previous_program)
        .unwrap();
    artifact.identity = replacement;
    artifact.bytes = candidate_program;
    envelope
        .artifacts
        .sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
    envelope.manifest.signing_mut().signature = operator
        .sign(&envelope.signing_bytes().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let other_authority = admit_actor_package(&envelope.encode().unwrap()).unwrap();
    let other_authority_materials =
        fixed_three_materials_for_packaged_preflight(&operator, runtime, other_authority);
    assert!(
        check(&other_authority_materials)
            .unwrap_err()
            .to_string()
            .contains("Authority differs from the exact packaged Authority template")
    );

    let mut changed = canonical.descriptor.clone();
    changed.runtime_package.hash.0[0] ^= 1;
    let mut changed_request = canonical.authority_request.clone();
    let ManagementRequest::Install(install) = &mut changed_request else {
        unreachable!()
    };
    let mut configuration =
        SystemAuthorityConfiguration::decode(&install.installation_data.as_ref().unwrap().bytes)
            .unwrap();
    configuration.system_runtime_package.hash = changed.runtime_package.hash.0;
    let bytes = configuration.encode();
    let reference = BlobRef::of_bytes(&bytes);
    install.entry.installation_data = Some(reference.clone());
    install.installation_data = Some(InstallationData { reference, bytes });
    assert!(
        validate_packaged_system_observation_bootstrap_materials(
            &changed,
            canonical.runtime.exact_bytes(),
            canonical.authority_package.exact_bytes(),
            &changed_request,
            canonical.catalog_package.exact_bytes(),
            &canonical.catalog_request,
            &operator,
        )
        .unwrap_err()
        .to_string()
        .contains("descriptor differs from its exact packaged runtime and Authority closure")
    );
    assert_eq!(journal_files(&scratch.0), before);
    assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
fn packaged_system_prewrite_binding_refuses_other_catalog_closure_and_configuration_without_writes()
{
    use vos::agent::package_admission::admit_actor_package;
    use vos::agent::sdk::package::{PackageEnvelope, PackageManifest};
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    let scratch = Scratch::new();
    let before = journal_files(&scratch.0);
    let operator = Keypair::ed25519_from_bytes([0x60; 32]).unwrap();
    let runtime = crate::bundled::root_signed_system_agent_runtime_package(&operator).unwrap();
    let authority = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template(),
        SYSTEM_AUTHORITY_NAME,
        &operator,
    )
    .unwrap();
    let materials = fixed_three_materials_for_packaged_preflight(&operator, runtime, authority);
    let check = |package: &[u8], request: &ManagementRequest| {
        validate_packaged_system_observation_bootstrap_materials(
            &materials.descriptor,
            materials.runtime.exact_bytes(),
            materials.authority_package.exact_bytes(),
            &materials.authority_request,
            package,
            request,
            &operator,
        )
    };
    check(
        materials.catalog_package.exact_bytes(),
        &materials.catalog_request,
    )
    .unwrap();

    // An admitted, correctly root-signed alternate Catalog still cannot be
    // imported as the released closure, even with a coherent SCC1 request.
    let replacement_program = Assembler::new()
        .load_imm_64(Reg::A0, 0x61)
        .trap()
        .build_standard();
    assert_ne!(
        replacement_program,
        materials.catalog_package.program_bytes()
    );
    let mut envelope = PackageEnvelope::decode(materials.catalog_package.exact_bytes()).unwrap();
    let PackageManifest::Actor(manifest) = &mut envelope.manifest else {
        unreachable!()
    };
    let previous = manifest.program.clone();
    let replacement = BlobRef::of_bytes(&replacement_program);
    manifest.program = replacement.clone();
    let artifact = envelope
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.identity == previous)
        .unwrap();
    artifact.identity = replacement;
    artifact.bytes = replacement_program;
    envelope
        .artifacts
        .sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
    envelope.manifest.signing_mut().signature = operator
        .sign(&envelope.signing_bytes().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let other = admit_actor_package(&envelope.encode().unwrap()).unwrap();
    other
        .require_runtime(AgentProfile::Shared, &materials.runtime)
        .unwrap();
    let other_request = install_request(
        materials.descriptor.identity.agent,
        &other,
        system_catalog_configuration(&materials.descriptor, &other)
            .unwrap()
            .encode(),
        b"catalog",
    )
    .unwrap();
    assert!(
        check(other.exact_bytes(), &other_request)
            .unwrap_err()
            .to_string()
            .contains("Catalog differs from the exact packaged Catalog template")
    );

    let mut wrong_configuration = materials.catalog_request.clone();
    let ManagementRequest::Install(install) = &mut wrong_configuration else {
        unreachable!()
    };
    let mut configuration =
        SystemCatalogConfiguration::decode(&install.installation_data.as_ref().unwrap().bytes)
            .unwrap();
    configuration.system_runtime_deployment[0] ^= 1;
    assert!(configuration.is_valid());
    let bytes = configuration.encode();
    let reference = BlobRef::of_bytes(&bytes);
    install.entry.installation_data = Some(reference.clone());
    install.installation_data = Some(InstallationData { reference, bytes });

    let mut wrong_reservation = materials.catalog_request.clone();
    let ManagementRequest::Install(install) = &mut wrong_reservation else {
        unreachable!()
    };
    install.registry_reservation.0[0] ^= 1;
    for request in [&wrong_configuration, &wrong_reservation] {
        assert!(
            check(materials.catalog_package.exact_bytes(), request)
                .unwrap_err()
                .to_string()
                .contains("Catalog installation differs from its exact packaged program, package and descriptor closure")
        );
    }
    assert_eq!(journal_files(&scratch.0), before);
    assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
}

fn assert_released_system_plan_refused(error: &anyhow::Error) {
    let message = error.to_string();
    assert!(
        [
            "requires the exact signed System image observation contract",
            "System observation runtime release artifact is not yet qualified and pinned",
            "System runtime differs from the exact packaged System observation role",
            "Authority differs from the exact packaged Authority template",
            "Catalog differs from the exact packaged Catalog template",
        ]
        .iter()
        .any(|reason| message.contains(reason)),
        "{error:#}"
    );
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
    let at_future = trust.current_logical_slot().unwrap();
    assert_eq!(at_future, future);
    let repeated = trust.current_logical_slot().unwrap();
    assert_eq!(repeated, at_future);
    assert_eq!(inputs.clock.load(Ordering::Acquire), future);
}

fn expiry_startup_inputs(operator: &Keypair) -> StartupTestInputs {
    // Qualify exactly the shipped packages. Only the logical clock is
    // controlled; no candidate environment variable can replace guest bytes.
    let runtime = crate::bundled::root_signed_system_agent_runtime_package(operator).unwrap();
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
#[ignore = "requires AUTHORITY_CANDIDATE_ELF; prepares a common three-node bundle with production materials and root archive"]
fn candidate_fixed_roster_materials_prepare_one_common_bundle() {
    check_fixed_roster_preparation(FixedRosterStage::Bundle);
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback networks; production lifecycle file owners"]
fn candidate_fixed_roster_production_owners_start_from_common_bundle() {
    check_fixed_roster_preparation(FixedRosterStage::Owners);
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and loopback; production participants and leader route publication across reopen"]
fn candidate_fixed_roster_production_retains_pending_participants() {
    check_fixed_roster_preparation(FixedRosterStage::Participants);
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and loopback; physical three-owner startup/restart qualification"]
fn candidate_fixed_roster_production_routes_start_from_common_bundle() {
    check_fixed_roster_preparation(FixedRosterStage::Routes);
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
#[ignore = "requires fresh Authority/System IMAGE/external runtime guests and authenticated loopback; public handoff through production file owners"]
fn candidate_public_shared_member_handoff_retries_and_reopens_production_owners() {
    check_fixed_roster_preparation(FixedRosterStage::WarmMembers);
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
#[ignore = "requires exact pinned System/Authority/Shared runtime roles, CLERK_AGENT_PACKAGE and loopback; real public nonleader Install, lost result and all-owner reopen"]
fn packaged_public_shared_clerk_nonleader_install_lost_result_and_reopen() {
    check_fixed_roster_preparation(FixedRosterStage::PublicWorkflow);
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
#[ignore = "requires exact pinned System/Authority/Shared runtime roles, CLERK_AGENT_PACKAGE and loopback; 257 real public Root-authorized actor Invoke/ACKs, exact archived issuance and locked restart"]
fn packaged_public_shared_clerk_native_authorization_exceeds_256_and_reopens() {
    check_fixed_roster_preparation(FixedRosterStage::OperationCapacity);
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
#[ignore = "requires exact pinned System/Authority/Shared runtime roles, CLERK_AGENT_PACKAGE and loopback; pending Install receipt-stage fault and all-owner locked startup with whole30s recovery"]
fn packaged_pending_shared_install_all_cold_public_startup() {
    check_fixed_roster_preparation(FixedRosterStage::ColdInstallAll);
}

#[cfg(feature = "experimental-state-blocks")]
#[test]
#[ignore = "requires exact pinned System/Authority/Shared runtime roles, CLERK_AGENT_PACKAGE and loopback; pending Install receipt-stage fault and returning-Follower locked startup with whole30s recovery"]
fn packaged_pending_shared_install_returning_follower_public_startup() {
    check_fixed_roster_preparation(FixedRosterStage::ColdInstallReturning);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FixedRosterStage {
    Bundle,
    Owners,
    Participants,
    Routes,
    #[cfg(feature = "experimental-state-blocks")]
    WarmMembers,
    #[cfg(feature = "experimental-state-blocks")]
    PublicWorkflow,
    #[cfg(feature = "experimental-state-blocks")]
    OperationCapacity,
    #[cfg(feature = "experimental-state-blocks")]
    ColdInstallAll,
    #[cfg(feature = "experimental-state-blocks")]
    ColdInstallReturning,
    ProductionGate,
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF; production qualification rejection before writes, no singleton fallback"]
fn candidate_production_roster_gate_preserves_fresh_root_without_singleton_fallback() {
    check_fixed_roster_preparation(FixedRosterStage::ProductionGate);
}

fn check_fixed_roster_preparation(stage: FixedRosterStage) {
    use crate::commands::space::local_config::LocalAgentStorage;
    if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
    }
    use vos::agent::bootstrap::SystemAgentGenesisLocator;
    let scratch = Scratch::new();
    let operator = Keypair::ed25519_from_bytes([0x71; 32]).unwrap();
    let public = raw_public_key(&operator).unwrap();
    let owner = PrincipalId::of_public_key(&public);
    let space = SpaceId([0x73; 32]);
    let daemons: Vec<_> = [0x72, 0x74, 0x75]
        .into_iter()
        .map(|seed| Keypair::ed25519_from_bytes([seed; 32]).unwrap())
        .collect();
    let enrollments: Vec<_> = daemons
        .iter()
        .map(|key| {
            sign_node_encryption_enrollment(
                key,
                space,
                owner,
                derive_node_encryption_public(key, space).unwrap(),
            )
            .unwrap()
        })
        .collect();
    #[cfg(feature = "experimental-state-blocks")]
    let packaged = matches!(
        stage,
        FixedRosterStage::PublicWorkflow
            | FixedRosterStage::OperationCapacity
            | FixedRosterStage::ColdInstallAll
            | FixedRosterStage::ColdInstallReturning
    );
    #[cfg(not(feature = "experimental-state-blocks"))]
    let packaged = false;
    #[cfg(feature = "experimental-state-blocks")]
    let inputs = if packaged {
        // Mandatory integration selectors use the released roles unchanged;
        // candidate overrides remain confined to the separate candidate selectors.
        expiry_startup_inputs(&operator)
    } else {
        StartupTestInputs {
            runtime: member_handoff::fresh_system_runtime(&operator),
            ..candidate_authority_inputs(
                &operator,
                &PathBuf::from(std::env::var("AUTHORITY_CANDIDATE_ELF").unwrap()),
            )
        }
    };
    #[cfg(not(feature = "experimental-state-blocks"))]
    let inputs = candidate_authority_inputs(
        &operator,
        &PathBuf::from(std::env::var("AUTHORITY_CANDIDATE_ELF").unwrap()),
    );
    let make_materials = || {
        SystemBootstrapMaterials::new(
            space,
            public,
            enrollments[0].node,
            inputs.runtime.clone(),
            inputs.authority.clone(),
            inputs.catalog.clone(),
            &enrollments,
        )
        .unwrap()
    };
    let materials = make_materials();
    let target = materials.authority_target();
    assert_eq!(materials.descriptor.replicas.len(), 3);
    let certificate_path = scratch.0.join("certification");
    let open_archive = |path: &Path, node| {
        let (_, _, _, file) = CleanSystemAgentFileStores::open_or_create(path)
            .unwrap()
            .into_production_parts();
        CleanSystemAgentGenesisArchive::new(
            file,
            HostSpaceId(space.0),
            HostAgentId(target.system_agent.0),
            HostNodeId(node),
            HostHash(target.binding.commitment().0),
            operator.clone(),
        )
        .unwrap()
    };
    let archive = open_archive(&certificate_path, enrollments[0].node.0);
    let slot = system_logical_slot().unwrap();
    let trust = Arc::new(SystemAgentTrust::new(
        slot,
        HostSpaceId(space.0),
        host_authority_binding(target.system_agent, target.binding),
    ));
    let merge = Arc::new(Ed25519NodeMergeAuthenticator::new(daemons[0].clone()).unwrap());
    let mut certifications = 0;
    let untouched = journal_files(&certificate_path);
    let foreign = Keypair::ed25519_from_bytes([0x76; 32]).unwrap();
    assert!(matches!(
        make_materials().prepare(
            &foreign,
            slot,
            &mut |root, proposal: &_, catalog: &_| {
                certifications += 1;
                archive.certify_fresh(root, proposal, catalog)
            },
            trust.clone(),
            merge.clone()
        ),
        Err(CleanSystemAgentBootstrapError::Signer)
    ));
    assert_eq!(certifications, 0);
    assert_eq!(journal_files(&certificate_path), untouched);
    let prepared = materials
        .prepare(
            &operator,
            slot,
            &mut |root, proposal: &_, catalog: &_| {
                certifications += 1;
                archive.certify_fresh(root, proposal, catalog)
            },
            trust,
            merge,
        )
        .unwrap();
    assert_eq!(certifications, 1);
    let published = journal_files(&certificate_path);
    let bundle = scratch.0.join("common.bundle");
    std::fs::write(&bundle, prepared.encode_import().unwrap()).unwrap();
    #[cfg(feature = "experimental-state-blocks")]
    if packaged {
        // Even a valid exact packaged certificate cannot import over an
        // orphaned Shared host and initialize a new System/control root.
        let data = scratch.0.join("shared-residue-refusal");
        drop(crate::commands::space::clean_store::ensure_private_directory(&data).unwrap());
        let untouched = journal_files(&data);
        for (configured_space, daemon, reason) in [
            (
                [0xff; 32],
                &daemons[0],
                "bootstrap plan belongs to another Space or node",
            ),
            (
                space.0,
                &daemons[1],
                "retained bootstrap plan belongs to another local node",
            ),
        ] {
            let error = preflight_released_system_startup(
                &data,
                crate::commands::space::local_config::LocalAgentStorage::Image,
                Some(&prepared),
                &operator,
                configured_space,
                daemon,
            )
            .unwrap_err();
            assert!(error.to_string().contains(reason), "{error:#}");
            assert_eq!(journal_files(&data), untouched);
            assert!(!data.join(SYSTEM_AGENT_CONTROL_DIRECTORY).exists());
            assert!(!data.join(SHARED_AGENT_HOST_DIRECTORY).exists());
            assert!(!data.join(LOCAL_AGENT_HOST_DIRECTORY).exists());
            assert!(!data.join(LOCAL_LIFECYCLE_DIRECTORY).exists());
        }
        let shared = data.join(SHARED_AGENT_HOST_DIRECTORY);
        drop(crate::commands::space::clean_store::ensure_private_directory(&shared).unwrap());
        std::fs::write(shared.join("retained-marker"), b"preserve Shared residue").unwrap();
        let before = journal_files(&data);
        let error = preflight_released_system_startup(
            &data,
            crate::commands::space::local_config::LocalAgentStorage::Image,
            Some(&prepared),
            &operator,
            space.0,
            &daemons[0],
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Shared deployment residue lacks its retained System bootstrap plan")
        );
        assert_eq!(journal_files(&data), before);
        assert!(!data.join(SYSTEM_AGENT_CONTROL_DIRECTORY).exists());
        assert!(!data.join(LOCAL_AGENT_HOST_DIRECTORY).exists());
        assert!(!data.join(LOCAL_LIFECYCLE_DIRECTORY).exists());
    }
    if stage == FixedRosterStage::ProductionGate {
        let data = scratch.0.join("rejected-import");
        drop(crate::commands::space::clean_store::ensure_private_directory(&data).unwrap());
        let daemon = &daemons[0];
        let peer = daemon.public().to_peer_id();
        let network = Arc::new(Network::start(NetworkConfig {
            keypair: daemon.clone(),
            local_prefix: derive_node_prefix(&peer),
            listen: vec![],
            bootstrap: vec![],
            auto_dial_mdns: false,
        }));
        let local = read_certified_bootstrap_bundle(&bundle, space.0, &operator, daemon).unwrap();
        let before = journal_files(&data);
        let error = open_clean_system_lifecycle_with_roster_policy(
            network.clone(),
            &data,
            space.0,
            &operator,
            daemon,
            crate::commands::space::local_config::LocalAgentStorage::Image,
            &data.join("host.lock"),
            Some(&local),
            false,
            Some(&inputs),
        )
        .err()
        .expect("production must reject a three-node import");
        assert_released_system_plan_refused(&error);
        assert_eq!(journal_files(&data), before);
        assert_eq!(std::fs::read_dir(&data).unwrap().count(), 0);
        // Removing the bundle must not select the old singleton image. The
        // unqualified v1 path stays closed without creating any roots.
        let error = open_clean_system_lifecycle_with_roster_policy(
            network,
            &data,
            space.0,
            &operator,
            daemon,
            crate::commands::space::local_config::LocalAgentStorage::Image,
            &data.join("host.lock"),
            None,
            false,
            Some(&inputs),
        )
        .err()
        .expect("public startup must not fall back to a singleton");
        assert!(
            error.to_string().contains(
                "requires a supplied root-certified plan or canonical retained CSB5 plan"
            )
        );
        assert_eq!(journal_files(&data), before);
        assert_eq!(std::fs::read_dir(&data).unwrap().count(), 0);
        return;
    }
    for (index, daemon) in daemons.iter().enumerate() {
        let local = read_certified_bootstrap_bundle(&bundle, space.0, &operator, daemon).unwrap();
        assert_eq!(local.plan().pins().node(), enrollments[index].node);
        assert_eq!(local.provision().root(), prepared.provision().root());
        assert_eq!(
            local.provision().evidence(),
            prepared.provision().evidence()
        );
        assert_eq!(
            local.provision().proposal().create(),
            prepared.provision().proposal().create()
        );
        assert_eq!(local.plan().catalog_call(), prepared.plan().catalog_call());
        let path = scratch.0.join(format!("member-{index}"));
        let imported = open_archive(&path, enrollments[index].node.0);
        assert_eq!(
            imported
                .import_certified(local.provision(), local.catalog())
                .unwrap(),
            *local.provision()
        );
        drop(imported);
        let reopened = open_archive(&path, enrollments[index].node.0);
        let locator = SystemAgentGenesisLocator {
            space: HostSpaceId(space.0),
            agent: HostAgentId(target.system_agent.0),
            node: HostNodeId(enrollments[index].node.0),
        };
        assert_eq!(reopened.reproduce(locator).unwrap(), *local.provision());
        assert_eq!(journal_files(&certificate_path), published);
    }
    assert_eq!(certifications, 1);
    if stage != FixedRosterStage::Bundle {
        let networks: Vec<_> = daemons
            .iter()
            .map(|key| {
                let peer = key.public().to_peer_id();
                Arc::new(Network::start(NetworkConfig {
                    keypair: key.clone(),
                    local_prefix: derive_node_prefix(&peer),
                    listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                    bootstrap: vec![],
                    auto_dial_mdns: false,
                }))
            })
            .collect();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while networks
            .iter()
            .any(|network| network.listen_addrs().is_empty())
        {
            assert!(
                std::time::Instant::now() < deadline,
                "listeners did not start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        while networks
            .iter()
            .any(|network| network.connected_peers().len() != 2)
        {
            assert!(
                std::time::Instant::now() < deadline,
                "authenticated mesh did not connect"
            );
            for (index, network) in networks.iter().enumerate() {
                for other in networks.iter().skip(index + 1) {
                    network.connect(other.listen_addrs()[0].clone());
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let data: Vec<_> = (0..3)
            .map(|index| {
                let path = scratch.0.join(format!("startup-{index}"));
                drop(crate::commands::space::clean_store::ensure_private_directory(&path).unwrap());
                path
            })
            .collect();
        #[cfg(feature = "experimental-state-blocks")]
        let interrupted_inputs: Vec<_> = if stage == FixedRosterStage::PublicWorkflow {
            daemons
                .iter()
                .map(|daemon| {
                    read_certified_bootstrap_bundle(&bundle, space.0, &operator, daemon).unwrap()
                })
                .collect()
        } else {
            Vec::new()
        };
        #[cfg(feature = "experimental-state-blocks")]
        for (index, local) in interrupted_inputs.iter().take(2).enumerate() {
            // Real initialization publishes genesis and pins before the first
            // CSB5 Intent. Lose this process at each side of that record write:
            // voter0 has no record; voter1 retains its first pre-rename stage.
            let control = data[index].join(SYSTEM_AGENT_CONTROL_DIRECTORY);
            let (pins_bytes, intent_bytes) = startup_record_fixture(local, None);
            let archive = open_archive(&control, enrollments[index].node.0);
            archive
                .import_certified(local.provision(), local.catalog())
                .unwrap();
            drop(archive);
            let (mut pins, bootstrap, issuer, genesis) =
                CleanSystemAgentFileStores::open_or_create(&control)
                    .unwrap()
                    .into_production_parts();
            pins.commit(&pins_bytes).unwrap();
            drop((pins, bootstrap, issuer, genesis));
            if index == 1 {
                crate::commands::space::clean_store::tests::stage_startup_images(
                    &control,
                    [None, Some(intent_bytes.as_slice()), None, None],
                );
            }
            let before = journal_files(&data[index]);
            let inspected = inspect_released_system_startup(
                &data[index],
                LocalAgentStorage::Image,
                Some(local),
                &operator,
                space.0,
                &daemons[index],
            )
            .unwrap()
            .unwrap();
            assert_eq!(inspected.bootstrap.selected_payload().is_some(), index == 1);
            assert!(CleanSystemAgentFileStores::read_client_bootstrap(&control).is_err());
            assert_eq!(journal_files(&data[index]), before);
            assert!(!data[index].join(SHARED_AGENT_HOST_DIRECTORY).exists());
        }
        #[cfg(feature = "experimental-state-blocks")]
        if !interrupted_inputs.is_empty() {
            assert!(!data[2].join(SYSTEM_AGENT_CONTROL_DIRECTORY).exists());
        }
        // Drop every lifecycle/file owner, then recover solely from persisted
        // plans. The networking processes stay alive; this is not a daemon
        // crash or public-route qualification.
        #[cfg(feature = "experimental-state-blocks")]
        let mut handoff = None;
        #[cfg(feature = "experimental-state-blocks")]
        let mut workflow = None;
        #[cfg(feature = "experimental-state-blocks")]
        let mut operation_capacity = None;
        #[cfg(feature = "experimental-state-blocks")]
        let mut cold_install = None;
        #[cfg(feature = "experimental-state-blocks")]
        let restarts: &[bool] = if stage == FixedRosterStage::OperationCapacity {
            &[false, true, true]
        } else {
            &[false, true]
        };
        #[cfg(not(feature = "experimental-state-blocks"))]
        let restarts: &[bool] = &[false, true];
        for &restart in restarts {
            // Include every locked constructor and production attachment in
            // the pending-recovery measurement, not just the later HTTP retry.
            #[cfg(feature = "experimental-state-blocks")]
            let recovery_started = std::time::Instant::now();
            let owners = std::thread::scope(|scope| {
                let handles: Vec<_> = (0..3)
                    .map(|index| {
                        let network = networks[index].clone();
                        let data = &data[index];
                        let daemon = &daemons[index];
                        let operator = &operator;
                        let bundle = &bundle;
                        let inputs = &inputs;
                        scope.spawn(move || {
                            let certified = (!restart).then(|| {
                                read_certified_bootstrap_bundle(bundle, space.0, operator, daemon)
                                    .unwrap()
                            });
                            open_clean_system_lifecycle_with_roster_policy(
                                network,
                                data,
                                space.0,
                                operator,
                                daemon,
                                LocalAgentStorage::Image,
                                &data.join("host.lock"),
                                certified.as_ref(),
                                !packaged,
                                match stage {
                                    #[cfg(feature = "experimental-state-blocks")]
                                    FixedRosterStage::WarmMembers
                                    | FixedRosterStage::PublicWorkflow
                                    | FixedRosterStage::OperationCapacity
                                    | FixedRosterStage::ColdInstallAll
                                    | FixedRosterStage::ColdInstallReturning => Some(inputs),
                                    _ => None,
                                },
                            )
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .enumerate()
                    .map(|(index, handle)| {
                        handle.join().unwrap().unwrap_or_else(|error| {
                            panic!("replica {index} startup (restart={restart}) failed: {error:#}")
                        })
                    })
                    .collect::<Vec<_>>()
            });
            for (index, (node, _)) in owners.iter().enumerate() {
                assert_eq!(*node, enrollments[index].node);
            }
            #[cfg(feature = "experimental-state-blocks")]
            for (index, local) in interrupted_inputs.iter().enumerate() {
                let control = data[index].join(SYSTEM_AGENT_CONTROL_DIRECTORY);
                let published = CleanSystemAgentFileStores::read_client_bootstrap(&control)
                    .unwrap()
                    .unwrap();
                let plan =
                    CleanSystemAgentBootstrapRecord::validated_startup_plan(&published.bootstrap)
                        .unwrap();
                assert_eq!(plan.commitment(), local.plan().commitment());
                assert_eq!(
                    Hash::digest(b"vos/clean-system-agent-pins/v2", &[&published.pins]),
                    local.plan().pins().commitment()
                );
                assert_eq!(
                    published.bootstrap[37],
                    vos::agent::clean_bootstrap::CleanSystemAgentBootstrapPhase::Complete as u8
                );
                let (provision, catalog) =
                    super::super::clean_genesis_archive::client_archive_parts(&published.genesis)
                        .unwrap();
                assert_eq!(&provision, local.provision());
                assert_eq!(catalog.as_slice(), local.catalog());
                let images = CleanSystemAgentFileStores::read_startup_bootstrap(&control)
                    .unwrap()
                    .unwrap();
                let issuer =
                    vos::agent::clean_authority_issuer::DurableCleanManagementIssuer::open(
                        ReadonlyStartupIssuer(images.issuer.selected_payload().unwrap()),
                        target.binding,
                        space,
                        target.system_agent,
                    )
                    .unwrap();
                assert_eq!(
                    (issuer.sequence_high_water(), issuer.acknowledged_through()),
                    (3, 3)
                );
            }
            #[cfg(feature = "experimental-state-blocks")]
            let warm = matches!(
                stage,
                FixedRosterStage::WarmMembers
                    | FixedRosterStage::PublicWorkflow
                    | FixedRosterStage::OperationCapacity
                    | FixedRosterStage::ColdInstallAll
                    | FixedRosterStage::ColdInstallReturning
            );
            #[cfg(not(feature = "experimental-state-blocks"))]
            let warm = false;
            if warm
                || matches!(
                    stage,
                    FixedRosterStage::Participants | FixedRosterStage::Routes
                )
            {
                let nodes = std::thread::scope(|scope| {
                    let handles: Vec<_> = owners
                        .into_iter()
                        .map(|(id, lifecycle)| {
                            let operator = &operator;
                            scope.spawn(move || {
                                let mut node = VosNode::new();
                                let result = node.start_clean_local_agent_production(
                                    id,
                                    lifecycle,
                                    Box::new(
                                        OperatorAuthorityProjectionAuthenticator::new(
                                            operator.clone(),
                                        )
                                        .unwrap(),
                                    ),
                                    AgentSupervisorLimits::default(),
                                    PROJECTION_ROUTE_QUEUE_CAPACITY,
                                    PROJECTION_RECONCILE_INTERVAL,
                                );
                                (node, result)
                            })
                        })
                        .collect();
                    handles
                        .into_iter()
                        .map(|handle| handle.join().unwrap())
                        .collect::<Vec<_>>()
                });
                for (index, (node, result)) in nodes.iter().enumerate() {
                    eprintln!("replica {index} route attachment (restart={restart}): {result:?}");
                    if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                        eprintln!(
                            "shared_create_initial_readiness replica={index} restart={restart} recovering={} supervisor_exposed={}",
                            node.ingress_handle().clean_agent_recovering(),
                            node.clean_agent_supervisor().is_some(),
                        );
                    }
                }
                for (index, (node, result)) in nodes.iter().enumerate() {
                    assert!(
                        result.is_ok(),
                        "replica {index} route attachment (restart={restart}): {result:?}"
                    );
                    assert!(
                        !node
                            .shutdown_handle()
                            .load(std::sync::atomic::Ordering::Acquire),
                        "replica {index} stopped during initial reconciliation"
                    );
                }
                // Initial construction may retain all owners unpublished while
                // their workers complete the exact read custody. Observe actual
                // fresh publication; never drive recovery or set readiness here.
                // This bounded phase wait is not whole-startup latency evidence.
                let readiness_deadline = std::time::Instant::now() + Duration::from_secs(30);
                loop {
                    assert!(
                        nodes.iter().all(|(node, _)| !node
                            .shutdown_handle()
                            .load(std::sync::atomic::Ordering::Acquire)),
                        "replica stopped before initial verified route publication"
                    );
                    assert!(
                        std::time::Instant::now() < readiness_deadline,
                        "required initial verified routes not published within 30s"
                    );
                    let published = if stage == FixedRosterStage::Routes {
                        nodes
                            .iter()
                            .all(|(node, _)| node.clean_agent_supervisor().is_some())
                    } else {
                        nodes
                            .iter()
                            .any(|(node, _)| node.clean_agent_supervisor().is_some())
                    };
                    if published {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                #[cfg(feature = "experimental-state-blocks")]
                if warm {
                    let mut nodes: Vec<_> = nodes
                        .into_iter()
                        .map(|(node, result)| {
                            result.unwrap();
                            node
                        })
                        .collect();
                    let handoff_result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let cold = matches!(
                                stage,
                                FixedRosterStage::ColdInstallAll
                                    | FixedRosterStage::ColdInstallReturning
                            );
                            // Pending recovery must not first rerun public Create
                            // or handoff operations just to establish test readiness.
                            if !(cold && restart) {
                                member_handoff::public_handoff(
                                    &mut nodes,
                                    &data,
                                    &operator,
                                    &daemons,
                                    &enrollments,
                                    space,
                                    target,
                                    &inputs,
                                    packaged,
                                    restart,
                                    &mut handoff,
                                );
                            }
                            if stage == FixedRosterStage::PublicWorkflow
                                || (stage == FixedRosterStage::OperationCapacity
                                    && operation_capacity.is_none())
                            {
                                member_workflow::exercise(
                                    &mut nodes,
                                    &networks,
                                    &data,
                                    &operator,
                                    &daemons,
                                    &enrollments,
                                    space,
                                    target,
                                    &inputs,
                                    &handoff.as_ref().unwrap().1,
                                    restart,
                                    &mut workflow,
                                );
                            }
                            if stage == FixedRosterStage::OperationCapacity && restart {
                                member_workflow::exercise_capacity(
                                    &mut nodes,
                                    &data[0],
                                    &operator,
                                    space,
                                    raw_public_key(&daemons[0]).unwrap(),
                                    workflow.as_ref().unwrap(),
                                    &mut operation_capacity,
                                );
                            }
                            if cold {
                                member_cold_install::exercise(
                                    member_cold_install::Inputs {
                                        nodes: &mut nodes,
                                        networks: &networks,
                                        data: &data,
                                        operator: &operator,
                                        daemons: &daemons,
                                        enrollments: &enrollments,
                                        space,
                                        authority: target,
                                        startup: &inputs,
                                        archive: &handoff.as_ref().unwrap().1,
                                    },
                                    restart,
                                    stage == FixedRosterStage::ColdInstallReturning,
                                    recovery_started,
                                    &mut cold_install,
                                );
                            }
                        }));
                    if let Err(original_panic) = handoff_result {
                        // Stop every participant before joining any of them.
                        // Checked collection logs the retained production-owner
                        // error instead of losing it during ordinary Drop.
                        for node in &nodes {
                            node.shutdown();
                        }
                        for (index, node) in nodes.into_iter().enumerate() {
                            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                node.collect_checked()
                            })) {
                                Ok(Ok(_)) => {}
                                Ok(Err(error)) => eprintln!(
                                    "replica {index} checked handoff cleanup (restart={restart}): {error:?}"
                                ),
                                Err(_) => eprintln!(
                                    "replica {index} handoff cleanup panicked (restart={restart}); preserving original failure"
                                ),
                            }
                        }
                        std::panic::resume_unwind(original_panic);
                    }
                    drop(nodes);
                } else {
                    drop(nodes);
                }
                #[cfg(not(feature = "experimental-state-blocks"))]
                drop(nodes);
            } else {
                drop(owners);
            }
            // At the restart boundary, supported packaged plans receive
            // readonly normal admission; unsupported candidates still refuse.
            for (index, data) in data.iter().enumerate() {
                let before = journal_files(data);
                #[cfg(feature = "experimental-state-blocks")]
                if packaged {
                    // The exact retained certificate must stay bound to this
                    // configured Space and this voter before a writer opens.
                    for (configured_space, daemon, reason) in [
                        (
                            [0xff; 32],
                            &daemons[index],
                            "bootstrap plan belongs to another Space or node",
                        ),
                        (
                            space.0,
                            &daemons[(index + 1) % daemons.len()],
                            "retained bootstrap plan belongs to another local node",
                        ),
                    ] {
                        let error = preflight_released_system_startup(
                            data,
                            crate::commands::space::local_config::LocalAgentStorage::Image,
                            None,
                            &operator,
                            configured_space,
                            daemon,
                        )
                        .unwrap_err();
                        assert!(error.to_string().contains(reason), "{error:#}");
                        assert_eq!(journal_files(data), before);
                    }
                    let retained = preflight_released_system_startup(
                        data,
                        LocalAgentStorage::Image,
                        None,
                        &operator,
                        space.0,
                        &daemons[index],
                    )
                    .unwrap()
                    .unwrap();
                    let plan = CleanSystemAgentBootstrapRecord::validated_startup_plan(
                        retained.bootstrap.selected_payload().unwrap(),
                    )
                    .unwrap();
                    let expected = prepared.plan().for_node(enrollments[index].node).unwrap();
                    assert_eq!(plan.commitment(), expected.commitment());
                    let (provision, catalog) =
                        super::super::clean_genesis_archive::client_archive_parts(
                            retained.genesis.selected_payload().unwrap(),
                        )
                        .unwrap();
                    assert_eq!(provision.root(), prepared.provision().root());
                    assert_eq!(provision.evidence(), prepared.provision().evidence());
                    assert_eq!(catalog.as_slice(), prepared.catalog());
                    assert_eq!(journal_files(data), before);
                    continue;
                }
                let error = open_clean_system_lifecycle_with_roster_policy(
                    networks[index].clone(),
                    data,
                    space.0,
                    &operator,
                    &daemons[index],
                    crate::commands::space::local_config::LocalAgentStorage::Image,
                    &data.join("host.lock"),
                    None,
                    false,
                    Some(&inputs),
                )
                .err()
                .expect("production must reject the persisted roster");
                assert_released_system_plan_refused(&error);
                assert_eq!(journal_files(data), before);
            }
        }
    }
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
    let bundle_path = scratch.0.join("bootstrap.bundle");
    std::fs::write(&bundle_path, certified.encode_import().unwrap()).unwrap();
    let certified =
        read_certified_bootstrap_bundle(&bundle_path, space.0, &operator, &daemon).unwrap();
    // A deployed nondefault plan selects the client's expected target even
    // without a bootstrap-bundle option. Reading beside the live archive's
    // lease must not acquire another writer, repair a stage or reserve a call.
    crate::secure_file::write_owner_only_atomic(
        &data.join("node.key"),
        &daemon.to_protobuf_encoding().unwrap(),
    )
    .unwrap();
    let sdk_space = SpaceId(space.0);
    let daemon_public = raw_public_key(&daemon).unwrap();
    let bundled_target = derive_system_authority_target(
        sdk_space,
        raw_public_key(&operator).unwrap(),
        &crate::bundled::root_signed_system_agent_runtime_package(&operator).unwrap(),
        &crate::bundled::root_signed_actor_package(
            crate::bundled::system_authority_package_template(),
            SYSTEM_AUTHORITY_NAME,
            &operator,
        )
        .unwrap(),
    )
    .unwrap()
    .0;
    assert_ne!(authority, bundled_target);
    let mut client_config = super::super::local_config::LocalConfig::default();
    super::super::local_config::save(&data, &client_config).unwrap();
    let client_files = journal_files(&data);
    assert_eq!(
        client_system_authority_target(&data, sdk_space, &operator, daemon_public).unwrap(),
        authority
    );
    assert_eq!(journal_files(&data), client_files);
    let client_foreign = Keypair::ed25519_from_bytes([0x96; 32]).unwrap();
    for (selected_space, selected_root, selected_node) in [
        (SpaceId([0x97; 32]), &operator, daemon_public),
        (sdk_space, &client_foreign, daemon_public),
        (
            sdk_space,
            &operator,
            raw_public_key(&client_foreign).unwrap(),
        ),
    ] {
        assert!(
            client_system_authority_target(&data, selected_space, selected_root, selected_node,)
                .is_err()
        );
        assert_eq!(journal_files(&data), client_files);
        assert!(!data.join("agent-client").exists());
    }
    let bootstrap_path = data
        .join(SYSTEM_AGENT_CONTROL_DIRECTORY)
        .join("system-agent.bootstrap");
    let saved_bootstrap = scratch.0.join("saved-client-bootstrap");
    std::fs::rename(&bootstrap_path, &saved_bootstrap).unwrap();
    let partial_files = journal_files(&data);
    assert!(
        super::super::local_create::create_local(
            &data,
            "127.0.0.1:1".parse().unwrap(),
            &operator,
            sdk_space,
            daemon_public,
            false,
        )
        .is_err()
    );
    assert_eq!(journal_files(&data), partial_files);
    assert!(!data.join("agent-client").exists());
    std::fs::rename(&saved_bootstrap, &bootstrap_path).unwrap();
    client_config.system_bootstrap_bundle = Some(bundle_path.clone());
    super::super::local_config::save(&data, &client_config).unwrap();
    assert_eq!(
        client_system_authority_target(&data, sdk_space, &operator, daemon_public).unwrap(),
        authority
    );

    let alternate_materials = SystemBootstrapMaterials::new(
        sdk_space,
        raw_public_key(&operator).unwrap(),
        node_id_from_authenticated_peer(&daemon.public().to_peer_id()),
        crate::bundled::root_signed_system_agent_runtime_package(&operator).unwrap(),
        crate::bundled::root_signed_actor_package(
            crate::bundled::system_authority_package_template(),
            SYSTEM_AUTHORITY_NAME,
            &operator,
        )
        .unwrap(),
        crate::bundled::root_signed_actor_package(
            crate::bundled::system_catalog_package_template(),
            SYSTEM_CATALOG_NAME,
            &operator,
        )
        .unwrap(),
        &[sign_node_encryption_enrollment(
            &daemon,
            sdk_space,
            PrincipalId::of_public_key(&raw_public_key(&operator).unwrap()),
            derive_node_encryption_public(&daemon, sdk_space).unwrap(),
        )
        .unwrap()],
    )
    .unwrap();
    let alternate_output = scratch.0.join("alternate-client-certificate");
    bootstrap_prepare::prepare_materials(
        alternate_materials,
        &operator,
        &daemon,
        &alternate_output,
    )
    .unwrap();
    let alternate_path = alternate_output.join("common.bundle");
    let alternate =
        read_certified_bootstrap_bundle(&alternate_path, sdk_space.0, &operator, &daemon).unwrap();
    assert_ne!(alternate.plan().commitment(), certified.plan().commitment());
    client_config.system_bootstrap_bundle = Some(alternate_path);
    super::super::local_config::save(&data, &client_config).unwrap();
    let client_files = journal_files(&data);
    assert!(client_system_authority_target(&data, sdk_space, &operator, daemon_public).is_err());
    assert!(
        super::super::local_create::create_local(
            &data,
            "127.0.0.1:1".parse().unwrap(),
            &operator,
            sdk_space,
            daemon_public,
            false,
        )
        .is_err()
    );
    assert_eq!(journal_files(&data), client_files);
    assert!(!data.join("agent-client").exists());
    // Removing the optional import input does not remove the deployed plan.
    client_config.system_bootstrap_bundle = None;
    super::super::local_config::save(&data, &client_config).unwrap();
    assert_eq!(
        client_system_authority_target(&data, sdk_space, &operator, daemon_public).unwrap(),
        authority
    );
    assert!(read_certified_bootstrap_bundle(&bundle_path, [0x94; 32], &operator, &daemon).is_err());
    let foreign = Keypair::ed25519_from_bytes([0x95; 32]).unwrap();
    assert!(read_certified_bootstrap_bundle(&bundle_path, space.0, &foreign, &daemon).is_err());
    assert!(read_certified_bootstrap_bundle(&bundle_path, space.0, &operator, &foreign).is_err());
    let link = scratch.0.join("bundle-link");
    std::os::unix::fs::symlink(&bundle_path, &link).unwrap();
    assert!(read_certified_bootstrap_bundle(&link, space.0, &operator, &daemon).is_err());
    assert!(read_certified_bootstrap_bundle(&scratch.0, space.0, &operator, &daemon).is_err());
    let oversized_path = scratch.0.join("oversized-bundle");
    std::fs::File::create(&oversized_path)
        .unwrap()
        .set_len(vos::agent::clean_bootstrap::MAX_CLEAN_SYSTEM_AGENT_IMPORT_BYTES as u64 + 1)
        .unwrap();
    assert!(read_certified_bootstrap_bundle(&oversized_path, space.0, &operator, &daemon).is_err());
    drop(ensure_private_directory(&imported_data).unwrap());
    for supplied in [
        Some(bundle_path.as_path()),
        None,
        Some(bundle_path.as_path()),
    ] {
        let (_, recovered) = open_clean_system_lifecycle(
            network.clone(),
            &imported_data,
            space.0,
            &operator,
            &daemon,
            crate::commands::space::local_config::LocalAgentStorage::Image,
            &scratch.0.join("imported-host.lock"),
            supplied,
        )
        .unwrap();
        drop(recovered);
        // Certified import and stored-plan reopen retain the same exact
        // packages; fresh bundled defaults must never replace their inputs.
        let retained = CleanSystemAgentFileStores::read_client_bootstrap(
            &imported_data.join(SYSTEM_AGENT_CONTROL_DIRECTORY),
        )
        .unwrap()
        .unwrap();
        let reopened_plan =
            CleanSystemAgentBootstrapRecord::authorized_plan(&retained.bootstrap).unwrap();
        assert_eq!(
            reopened_plan.runtime_package_bytes(),
            plan.runtime_package_bytes()
        );
        assert_eq!(
            reopened_plan.authority_package_bytes(),
            plan.authority_package_bytes()
        );
        assert_eq!(
            reopened_plan.catalog_package_bytes(),
            plan.catalog_package_bytes()
        );
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
    use vos::agent::sdk::introspection::{
        ActorIntrospectionArtifact, ActorMethodIntrospection, CliExposure, MethodDispatch,
    };
    use vos::agent::sdk::method_policy::{
        ActorMethodPolicy, ActorMethodPolicyArtifact, AttestationRequirement,
        AuthorizationPolicySelector, IdempotencyRequirement, MethodArgument,
    };
    use vos::agent::sdk::package::{
        PackageArtifact, PackageEnvelope, PackageManifest, PackageSigning,
    };
    use vos::agent::sdk::wire::CanonicalWire as _;
    let mut inputs = expiry_startup_inputs(operator);
    let elf = std::fs::read(path).unwrap();
    let program = vos_pvm_compiler::link_elf_spi(&elf).unwrap();
    let schema = vos::agent::schema::raw_section_from_elf(&elf).unwrap();
    let parsed_schema = vos::agent::sdk::schema::decode(&schema).unwrap();
    let metadata =
        vos::metadata::decode(&vos::metadata::raw_section_from_elf(&elf).unwrap()).unwrap();
    let authorizations = vos::metadata::decode_agent_authorizations(
        &vos::metadata::raw_agent_authorizations_from_elf(&elf).unwrap(),
    )
    .unwrap();
    assert_eq!(metadata.messages.len(), parsed_schema.methods.len());
    assert_eq!(metadata.messages.len(), authorizations.len());
    let mut methods = Vec::new();
    let mut introspection_methods = Vec::new();
    for ((message, method), authorization) in metadata
        .messages
        .iter()
        .zip(&parsed_schema.methods)
        .zip(&authorizations)
    {
        assert_eq!(message.name, method.name);
        assert_eq!(message.name, authorization.name);
        assert_eq!(message.is_query, method.mode.write_lane().is_none());
        // Authority checks its signed requests in the guest. Require the
        // freshly emitted Public selector rather than inventing a policy.
        assert!(!message.attested);
        assert_eq!(message.space_role, None);
        assert_eq!(message.actor_role, None);
        assert_eq!(message.capability, None);
        assert_eq!(
            authorization.selector,
            vos::metadata::ParsedAgentAuthorizationSelector::Public
        );
        methods.push(ActorMethodPolicy {
            name: message.name.clone(),
            mode: method.mode,
            arguments: message
                .fields
                .iter()
                .map(|field| MethodArgument {
                    name: field.name.clone(),
                    type_identity: field.ty.clone(),
                })
                .collect(),
            return_type_identity: message.returns.clone(),
            authorization_policy: AuthorizationPolicySelector::Public,
            idempotency: IdempotencyRequirement::for_mode(method.mode),
            attestation: AttestationRequirement::None,
        });
        introspection_methods.push(ActorMethodIntrospection {
            name: message.name.clone(),
            doc: message.doc.clone(),
            cli_exposure: if message.exposed_to_cli {
                CliExposure::Exposed
            } else {
                CliExposure::Hidden
            },
            timeout_ms: message.timeout_ms,
            dispatch: match message.mode {
                0 => MethodDispatch::Sync,
                1 => MethodDispatch::Job,
                other => panic!("unknown Authority method dispatch mode {other}"),
            },
        });
    }
    methods.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    introspection_methods.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    let policy = ActorMethodPolicyArtifact {
        actor_schema: vos::agent::sdk::BlobRef::of_bytes(&schema),
        methods,
    };
    policy.validate_against_schema_bytes(&schema).unwrap();
    let policies = policy.encode().unwrap();
    let introspection = ActorIntrospectionArtifact {
        actor_schema: vos::agent::sdk::BlobRef::of_bytes(&schema),
        method_policy: vos::agent::sdk::BlobRef::of_bytes(&policies),
        actor_doc: metadata.doc,
        methods: introspection_methods,
    };
    introspection
        .validate_against_artifact_bytes(&schema, &policies)
        .unwrap();
    let introspection = introspection.encode().unwrap();
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
    let old_policies = std::mem::replace(
        &mut manifest.method_policy,
        vos::agent::sdk::BlobRef::of_bytes(&policies),
    );
    let old_introspection = std::mem::replace(
        &mut manifest.introspection,
        vos::agent::sdk::BlobRef::of_bytes(&introspection),
    );
    package.artifacts.retain(|artifact| {
        artifact.identity != old_program
            && artifact.identity != old_schema
            && artifact.identity != old_policies
            && artifact.identity != old_introspection
    });
    for bytes in [program, schema, policies, introspection] {
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

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF; validates the complete freshly emitted candidate closure"]
fn candidate_authority_metadata_binds_fresh_guest_method_surface() {
    use vos::agent::sdk::introspection::ActorIntrospectionArtifact;
    use vos::agent::sdk::method_policy::{ActorMethodPolicyArtifact, AuthorizationPolicySelector};
    use vos::agent::sdk::wire::CanonicalWire as _;

    let operator = Keypair::ed25519_from_bytes([0x71; 32]).unwrap();
    let inputs = candidate_authority_inputs(
        &operator,
        &PathBuf::from(std::env::var("AUTHORITY_CANDIDATE_ELF").unwrap()),
    );
    let package = &inputs.authority;
    let schema = vos::agent::sdk::schema::decode(package.state_lane_schema_bytes()).unwrap();
    let policy = ActorMethodPolicyArtifact::decode(package.method_policy_bytes()).unwrap();
    let introspection = ActorIntrospectionArtifact::decode(package.introspection_bytes()).unwrap();
    assert_eq!(policy.methods.len(), schema.methods.len());
    assert_eq!(introspection.methods.len(), schema.methods.len());
    assert_eq!(policy.actor_schema, package.manifest().state_lane_schema);
    assert_eq!(
        introspection.actor_schema,
        package.manifest().state_lane_schema
    );
    assert_eq!(
        introspection.method_policy,
        package.manifest().method_policy
    );
    let signed_read = policy.method("genesis_decision_projection").unwrap();
    assert_eq!(signed_read.mode, vos::agent::sdk::MethodMode::Query);
    assert_eq!(
        signed_read.authorization_policy,
        AuthorizationPolicySelector::Public
    );
    assert_eq!(signed_read.arguments.len(), 1);
    assert_eq!(signed_read.arguments[0].name, "query");
    assert_eq!(signed_read.arguments[0].type_identity, "Vec<u8>");
    assert_eq!(signed_read.return_type_identity, "Vec<u8>");
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
    let system_runtime =
        crate::bundled::root_signed_system_agent_runtime_package(&operator).unwrap();
    let authority_package = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template_for_storage(
            crate::commands::space::local_config::LocalAgentStorage::Image,
        )
        .unwrap(),
        SYSTEM_AUTHORITY_NAME,
        &operator,
    )
    .unwrap();
    let (system_runtime, authority_package) = expiry
        .as_ref()
        .map_or((system_runtime, authority_package), |inputs| {
            (inputs.runtime.clone(), inputs.authority.clone())
        });
    let public = raw_public_key(&operator).unwrap();
    let owner = PrincipalId::of_public_key(&public);
    let (authority, _) =
        derive_system_authority_target(space, public, &system_runtime, &authority_package).unwrap();
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
    // Exercise the configured production endorser, not a replacement test
    // signer. It uses the same sealed native claim and independently leased
    // pledge/result store; exact retries return the original signature.
    assert_eq!(
        lifecycle.endorse_shared_create(locator).unwrap(),
        vec![signature.clone()]
    );
    assert_eq!(
        lifecycle.endorse_shared_create(locator).unwrap(),
        vec![signature.clone()]
    );
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
