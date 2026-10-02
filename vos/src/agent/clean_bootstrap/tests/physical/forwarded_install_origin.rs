//! Receiver-level immutable-origin qualification, using the existing three
//! physical System owners. Ordinary EXTERNAL and System IMAGE share each host.
//! Valid shadow custody permits bounded upload, never mutation admission.
//! This is not public CLI, packaged, workload or whole-recovery qualification.

use super::*;
use crate::agent::clean_authority_issuer::{
    CleanSharedManagementIntentStore, SignedManagementTerminal,
};
use crate::agent::clean_bootstrap::SharedGenesisRuntimePackage;
use crate::agent::clean_management_intent::CleanManagementIntentSlot;
use crate::agent::genesis::{AgentGenesisArchiveRecord, AgentGenesisLocator};
use crate::agent::local_lifecycle::SharedInstallSubmission;
use crate::agent::package_admission::{
    AdmittedStateRuntimePackage, admit_state_runtime_package, tests::admitted_state_fixture_limits,
};
use crate::agent::shared_recovery::SharedRecoveryManifest;
use crate::network::agent_protocol::{
    ForwardedSharedInstallOperation, ForwardedSharedInstallOwner, ForwardedSharedInstallRequest,
};
use crate::service::wire::ServiceWire as _;
use std::time::Duration;

type Controller = NativeSharedGenesisController<
    IssuerMemoryStore,
    IssuerMemoryStore,
    IssuerMemoryStore,
    IssuerMemoryStore,
    IssuerMemoryStore,
    IssuerMemoryStore,
    MixedSharedArchive,
>;

// The existing actual Root credential signs the actual committee's claim.
// No synthetic receipt, approval, quorum or copied remote node key is used.
struct GenesisSigner(SigningKey);
impl crate::agent::clean_bootstrap::GenesisClaimSigner for GenesisSigner {
    type Error = ();
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign_genesis_claim(&mut self, message: &[u8; 32]) -> Result<[u8; 64], ()> {
        Ok(self.0.sign(message).to_bytes())
    }
}

fn external_inputs() -> (AdmittedStateRuntimePackage, AdmittedActorPackage) {
    // The same signed candidate/limits as external_shared.rs. This test does
    // not promote a pin, change limits or synthesize an actor implementation.
    let target = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    let runtime = admitted_state_fixture_limits(
        vos_pvm_compiler::link_elf_spi(
            &std::fs::read(
                target.join("agent-state-standard/riscv64em-vos/release/agent_runtime.elf"),
            )
            .unwrap(),
        )
        .unwrap(),
        LaneSet::of(StateLane::Linear),
        crate::agent_sdk::state_execution::MAX_ADMITTED_EXTERNAL_RUNTIME_STATE_BYTES as u32,
    );
    let mut envelope = PackageEnvelope::decode(runtime.exact_bytes()).unwrap();
    let PackageManifest::AgentRuntime(manifest) = &mut envelope.manifest else {
        unreachable!()
    };
    manifest.capabilities.scheduling = false;
    manifest.capabilities.proof_systems = ProofSystemSet::EMPTY;
    let key = SigningKey::from_bytes(&[0x67; 32]);
    let public_key = key.verifying_key().to_bytes();
    *envelope.manifest.signing_mut() = PackageSigning {
        producer: ProducerId::of_public_key(&public_key),
        public_key,
        signature: [0; 64],
    };
    envelope.manifest.signing_mut().signature =
        key.sign(&envelope.signing_bytes().unwrap()).to_bytes();
    let runtime = admit_state_runtime_package(&envelope.encode().unwrap()).unwrap();
    let clerk = admit_actor_package(
        &std::fs::read(std::env::var_os("CLERK_AGENT_PACKAGE").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(clerk.manifest().name.as_str(), "clerk-ledger");
    assert_eq!(clerk.requirements().lanes, LaneSet::of(StateLane::Linear));
    (runtime, clerk)
}

fn descriptor_and_roster(
    owner: &MemoryBootstrapOwner,
    runtime: &AdmittedStateRuntimePackage,
) -> (AgentDescriptor, AgentReplicaCommittee) {
    let mut descriptor = owner.pins.descriptor.clone();
    descriptor.creation_nonce = Hash([0xc7; 32]);
    descriptor.identity.agent = AgentId::derive(
        descriptor.identity.space,
        descriptor.identity.owner,
        descriptor.creation_nonce.as_bytes(),
    );
    descriptor.identity.runtime_deployment = runtime.deployment();
    descriptor.identity.runtime_program = runtime.program();
    descriptor.identity.runtime_producer = runtime.manifest().signing.producer;
    descriptor.runtime_package = runtime.package_ref().clone();
    descriptor.runtime_contract = runtime.manifest().contract;
    descriptor.capabilities = runtime.manifest().capabilities;
    // All nodes were actually enrolled by this System's signed configuration.
    // Preserve their real principals, peers, keys and Raft slots.
    let roster = AgentReplicaCommittee::new(
        crate::service::SpaceId(descriptor.identity.space.0),
        HostAgentId(descriptor.identity.agent.0),
        crate::agent::AgentProfile::Shared,
        owner.pins.replicas.members().to_vec(),
    )
    .unwrap();
    descriptor.replicas = roster
        .members()
        .iter()
        .map(|member| {
            let replica = member.replica();
            AgentReplica {
                node: NodeId(replica.node.0),
                principal: PrincipalId(replica.principal.0),
                role: ReplicaRole::Voter,
            }
        })
        .collect();
    descriptor.validate().unwrap();
    roster.validate_for_clean_descriptor(&descriptor).unwrap();
    assert!(crate::agent::replay::external_shared_descriptor_supported(
        &descriptor
    ));
    (descriptor, roster)
}

fn signed_call(
    owner: &MemoryBootstrapOwner,
    descriptor: &AgentDescriptor,
    request: &ManagementRequest,
    sequence: u64,
) -> AuthorityCredentialCall {
    let key = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
    let (mut call, _) = credential_call_and_approval(descriptor, request, &key);
    call.authority = owner.authority_target();
    call.authenticated_node = None;
    call.request_sequence = NonZeroU64::new(sequence).unwrap();
    call.invocation = call.expected_invocation();
    call.signature = key.sign(&call.signing_bytes()).to_bytes();
    call.verify_with(&RawCredentialVerifier).unwrap();
    call
}

fn create_and_admit(
    origin: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    runtime: &AdmittedStateRuntimePackage,
    descriptor: &AgentDescriptor,
    roster: &AgentReplicaCommittee,
    signer: &mut CountingSigner,
) -> (Controller, AgentGenesisArchiveRecord) {
    let owner = owners[origin].as_mut().unwrap();
    let target = owner.authority_target();
    let mut controller = Controller::new(target, vec![]).unwrap();
    controller.recover(owner, signer).unwrap();
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    // Root Catalog consumed one, Create uses two, Install later uses three.
    let call = signed_call(owner, descriptor, &request, 2);
    let locator = AgentGenesisLocator {
        space: crate::service::SpaceId(descriptor.identity.space.0),
        agent: HostAgentId(descriptor.identity.agent.0),
    };
    let selected = SharedGenesisRuntimePackage::External(runtime.clone());
    let archive = MixedSharedArchive::default();
    controller
        .reserve_create_with_runtime(descriptor, &call, &selected, roster, || {
            Ok((
                NativeSharedGenesisRecovery::reserve_create_with_replicas_runtime(
                    target,
                    locator,
                    descriptor.clone(),
                    call.clone(),
                    selected.clone(),
                    roster.clone(),
                    (
                        IssuerMemoryStore::default(),
                        IssuerMemoryStore::default(),
                        IssuerMemoryStore::default(),
                        IssuerMemoryStore::default(),
                        IssuerMemoryStore::default(),
                        IssuerMemoryStore::default(),
                    ),
                )?,
                Some(archive.clone()),
            ))
        })
        .unwrap();
    let mut claim_signer = GenesisSigner(SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]));
    let mut signature_store = IssuerMemoryStore::default();
    let (_, _, signature) = super::management_retention::exact_management_retry(
        "receiver fixture Create endorsement",
        || {
            controller.endorse_pending_create(
                owner,
                locator,
                signer,
                &mut signature_store,
                &mut claim_signer,
            )
        },
    );
    let record = super::management_retention::exact_management_retry(
        "receiver fixture Create publication",
        || controller.publish_pending_create(owner, locator, vec![signature.clone()], signer),
    );
    super::management_retention::exact_management_retry("receiver fixture Create terminal", || {
        controller.complete_pending_create(owner, locator, signer)
    });
    assert!(!owner.management_admission_held().unwrap());
    assert_eq!(
        controller.create_archive(locator).unwrap(),
        Some(record.clone())
    );

    for (index, owner) in owners.iter_mut().enumerate() {
        if index == origin {
            continue;
        }
        let owner = owner.as_mut().unwrap();
        let mut member = Controller::new(target, vec![])
            .unwrap()
            .with_member_archive_factory(|_| Ok(MixedSharedArchive::default()))
            .unwrap();
        member.recover(owner, signer).unwrap();
        super::management_retention::exact_management_retry(
            "receiver fixture member admission",
            || member.admit_member_archive(owner, &record, signer),
        );
        // The controller owns the member lease during genuine fresh proof and
        // publication. The opened host keeps actual finality afterwards.
        assert_eq!(
            owner
                .host
                .lock()
                .unwrap()
                .clean_runtime_descriptor(locator.agent)
                .unwrap(),
            *descriptor
        );
        owner._network_host.refresh().unwrap();
    }
    owners[origin]
        .as_mut()
        .unwrap()
        ._network_host
        .refresh()
        .unwrap();
    (controller, record)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PublishedState {
    system_position: crate::agent::shared_host::SharedAgentJournalPosition,
    system_state: Hash,
    manifest: SharedRecoveryManifest,
    ordinary_position: crate::agent::shared_host::SharedAgentJournalPosition,
    ordinary_state: Hash,
    actors: RuntimeOutcome,
    canonical_artifacts: Vec<(PathBuf, BlobRef)>,
    catalog: Vec<(PathBuf, BlobRef)>,
}

// Inspect only this existing fixture's physical artifact/catalog namespaces,
// not Raft database bytes (heartbeats/election metadata are not publication).
// These are observations under the live host owner, never another file owner.
fn artifact_root(owner: &MemoryBootstrapOwner, ordinary: HostAgentId) -> PathBuf {
    let path = owner
        .host
        .lock()
        .unwrap()
        .physical_route(ordinary)
        .unwrap()
        .raft_database;
    let name = path.file_name().unwrap().to_str().unwrap();
    let stem = name.strip_suffix(".shared-raft.redb").unwrap();
    path.parent()
        .unwrap()
        .join(format!("{stem}.shared-artifacts"))
}

fn files(root: &std::path::Path, exclude_upload: bool) -> Vec<(PathBuf, BlobRef)> {
    fn walk(
        root: &std::path::Path,
        path: &std::path::Path,
        skip_upload: bool,
        output: &mut Vec<(PathBuf, BlobRef)>,
    ) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if skip_upload && entry.file_name() == "forwarded-install" {
                continue;
            }
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                walk(root, &path, false, output);
            } else {
                assert!(metadata.is_file());
                output.push((
                    path.strip_prefix(root).unwrap().to_owned(),
                    BlobRef::of_bytes(&std::fs::read(&path).unwrap()),
                ));
            }
        }
    }
    if !root.try_exists().unwrap() {
        return Vec::new();
    }
    let mut output = Vec::new();
    walk(root, root, exclude_upload, &mut output);
    output.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    output
}

fn published(
    owner: &MemoryBootstrapOwner,
    ordinary: HostAgentId,
    journal_root: &std::path::Path,
) -> PublishedState {
    let system = HostAgentId(owner.pins.agent.0);
    let artifacts = artifact_root(owner, ordinary);
    let stem = artifacts
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .strip_suffix(".shared-artifacts")
        .unwrap();
    // Authority artifacts and replaceable journals deliberately have separate
    // pinned parents. Use the actual fixture journal root, not the Raft parent.
    let catalog = journal_root.join(format!("{stem}.agent/catalog/blobs"));
    assert!(artifacts.is_dir());
    assert!(catalog.is_dir());
    let mut host = owner.host.lock().unwrap();
    PublishedState {
        system_position: host.journal_position(system).unwrap(),
        system_state: host.clean_state_commitment(system).unwrap(),
        manifest: host.recovery_manifest(system).unwrap(),
        ordinary_position: host.journal_position(ordinary).unwrap(),
        ordinary_state: host.clean_state_commitment(ordinary).unwrap(),
        actors: host
            .inspect_clean_management(
                ordinary,
                &ManagementRequest::InspectActors {
                    after: None,
                    limit: crate::agent_sdk::MAX_DIRECTORY_PAGE_ENTRIES as u16,
                },
            )
            .unwrap(),
        canonical_artifacts: files(&artifacts, true),
        catalog: files(&catalog, false),
    }
}

fn send(
    network: &Network,
    target: NodeId,
    route: AgentGenerationRoute,
    request: ForwardedSharedInstallRequest,
) -> Option<u64> {
    // The transport's existing timeout is unchanged. Only an authenticated,
    // target/peer/route/request-correlated reply counts as receiver evidence.
    network
        .send_agent_forwarded_shared_install(target, route, request)
        .recv_timeout(Duration::from_secs(10))
        .expect("receiver must explicitly reply, not time out")
        .expect("a transport/correlation error is not receiver refusal")
}

fn chunk(
    route: crate::agent::shared_raft::AgentRouteKey,
    package: &AdmittedActorPackage,
    offset: u64,
) -> crate::agent::shared_raft::ArtifactChunk {
    let manifest = crate::agent::shared_raft::ArtifactBatchManifest::new(
        route,
        vec![crate::service::BlobRef {
            hash: crate::service::Hash(package.package_ref().hash.0),
            len: package.package_ref().len,
        }],
    )
    .unwrap();
    let start = usize::try_from(offset).unwrap();
    let end = start
        .checked_add(crate::agent::shared_raft::ARTIFACT_CHUNK_DATA_BYTES)
        .unwrap()
        .min(package.exact_bytes().len());
    crate::agent::shared_raft::ArtifactChunk::new(
        manifest,
        0,
        offset,
        package.exact_bytes()[start..end].to_vec(),
    )
    .unwrap()
}

pub(super) fn exercise(
    origin: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    directories: &[TestDirectory],
    networks: &[Arc<Network>],
    signer: &mut CountingSigner,
) {
    let (runtime, clerk) = external_inputs();
    let (descriptor, roster) = descriptor_and_roster(owners[origin].as_ref().unwrap(), &runtime);
    let (mut controller, archive) =
        create_and_admit(origin, owners, &runtime, &descriptor, &roster, signer);
    let locator = archive.provision().proposal().locator();
    let ordinary = locator.agent;
    let system = HostAgentId(owners[origin].as_ref().unwrap().pins.agent.0);

    // Select an actual ordinary leader different from origin. The existing
    // per-generation attachment fixture controls election only; real votes,
    // committed current-term no-op and full roster are still mandatory.
    let receiver = (origin + 1) % 3;
    super::management_retention::elect_origin(owners, receiver, ordinary);
    let shadow = (origin + 2) % 3;
    assert!(wait_until(Duration::from_secs(30), || owners[origin]
        .as_ref()
        .unwrap()
        ._network_host
        .bootstrap_raft_role_for_test(ordinary)
        .is_ok_and(|role| role == vos_raft::Role::Follower)));
    let target = fixtures[receiver].plan.pins.node;
    let status = owners[receiver]
        .as_ref()
        .unwrap()
        .host
        .lock()
        .unwrap()
        .supervisor_attachment_status(ordinary)
        .unwrap()
        .unwrap();
    let route = AgentGenerationRoute {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        generation: Hash(status.replication_id),
    };
    assert_eq!(status.replicas.len(), 3);

    let request = install_request(descriptor.identity.agent, &clerk, 0xc8, None);
    let ManagementRequest::Install(install) = &request else {
        unreachable!()
    };
    let owner = owners[origin].as_mut().unwrap();
    let call = signed_call(owner, &descriptor, &request, 3);
    assert_eq!(call.authenticated_node, None);
    let submission =
        SharedInstallSubmission::new((**install).clone(), call.clone(), clerk.clone()).unwrap();
    assert_eq!(
        SharedInstallSubmission::decode(&submission.encode())
            .unwrap()
            .call(),
        &call
    );
    controller
        .prepare_install(owner, (**install).clone(), call.clone(), &clerk, signer)
        .unwrap();
    // Consume the owner before reopening its SAME genuine continuation
    // sidecars. This is neither a cloned signing key/issuer nor a second lease.
    let mut entries = controller.into_entries_for_test();
    assert_eq!(entries.len(), 1);
    let (recovery, leased_archive) = entries.pop().unwrap();
    assert_eq!(recovery.locator(), locator);
    assert_eq!(recovery.retired, true);
    let (mut create_intent, create_issuer, query, reply, publication, publication_reply) =
        recovery.into_stores();
    let install_store = create_intent.management_intent_continuation().unwrap();
    let mut create_issuer = DurableCleanManagementIssuer::open(
        create_issuer,
        descriptor.authority,
        descriptor.identity.space,
        descriptor.identity.agent,
    )
    .unwrap();
    let mut issuer = create_issuer.open_creation_continuation().unwrap();
    let issuer_store = issuer.into_store();
    let mut issuer = DurableCleanManagementIssuer::open(
        issuer_store.clone(),
        descriptor.authority,
        descriptor.identity.space,
        descriptor.identity.agent,
    )
    .unwrap();
    let mut intent = CleanManagementIntentSlot::open(install_store.clone()).unwrap();
    assert_eq!(intent.intent().unwrap().call(), &call);
    assert_eq!(
        intent.load_actor().unwrap().unwrap().exact_bytes(),
        clerk.exact_bytes()
    );
    assert!(
        issuer
            .can_resume_install(
                owner.authority_target(),
                call.managed,
                &request,
                &call,
                &RawCredentialVerifier
            )
            .unwrap()
    );

    // Existing stage5: capture + pledge + ensure exact management member and
    // physical reserved authorization all run; first Invoke has not run yet.
    owner.finalization_failure_once = Some(5);
    let before_capture = owner.ordered_index_for_test().unwrap();
    assert_eq!(
        owner.issue_management_intent_with_admission(
            &mut intent,
            call.managed,
            &mut issuer,
            signer,
            true,
        ),
        Err(SharedAgentHostError::Unavailable)
    );
    assert_eq!(owner.finalization_failure_once, None);
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_capture);
    let envelope = intent.authorization_work().unwrap().unwrap().clone();
    let anchor = intent.authorization_anchor().unwrap().unwrap().clone();
    let first = owner
        ._network_host
        .management_recovery_manifest(system)
        .unwrap();
    let original_node = crate::service::NodeId(owner.pins.node.0);
    let first_slot = first.management_slot(original_node).unwrap();
    assert_eq!(first_slot.origin_owner(), original_node);
    assert!(first_slot.members_evidence()[0].invoke().is_none());
    assert_eq!(first_slot.members()[0].envelope(), &envelope);

    // New cross-owner historical-root admission is deliberately forbidden.
    // Acquire the legitimate signed shadow NOW, before A's first Invoke.
    let peer = owners[shadow].as_mut().unwrap();
    let shadow_node = crate::service::NodeId(peer.pins.node.0);
    let mut shadow_pending = None;
    super::management_retention::exact_management_retry(
        "receiver fixture shadow registration",
        || {
            peer._network_host
                .capture_management_pending(system, &envelope, |pending| {
                    assert_eq!(pending.0, anchor);
                    assert_eq!(pending.1, envelope);
                    shadow_pending = Some(pending.clone());
                    Ok(())
                })
        },
    );
    assert!(shadow_pending.is_some());
    let owner = owners[origin].as_mut().unwrap();
    let receipt = super::management_retention::exact_management_retry(
        "receiver fixture first genuine approval",
        || {
            owner.issue_management_intent_with_admission(
                &mut intent,
                call.managed,
                &mut issuer,
                signer,
                true,
            )
        },
    );
    assert_eq!(intent.authorization_work().unwrap(), Some(&envelope));
    assert_eq!(intent.intent().unwrap().call(), &call);
    assert!(wait_until(Duration::from_secs(30), || {
        owners.iter().all(|owner| {
            let owner = owner.as_ref().unwrap();
            let manifest = owner
                ._network_host
                .management_recovery_manifest(system)
                .unwrap();
            let Some(original) = manifest.management_slot(original_node) else {
                return false;
            };
            let Some(shadow) = manifest.management_slot(shadow_node) else {
                return false;
            };
            assert_eq!(shadow.origin_owner(), original_node);
            assert_eq!(shadow.members()[0], original.members()[0]);
            let Some(first) = original.members_evidence()[0].invoke() else {
                return false;
            };
            let Some(copied) = shadow.members_evidence()[0].invoke() else {
                return false;
            };
            assert_eq!(first, copied);
            matches!(first.outcome(), RuntimeOutcome::Completed(Ok(_)))
        })
    }));

    let receiver_owner = owners[receiver].as_ref().unwrap();
    assert!(
        receiver_owner
            ._network_host
            .bootstrap_is_local_leader(ordinary)
            .unwrap()
    );
    let manifest = receiver_owner
        ._network_host
        .management_recovery_manifest(system)
        .unwrap();
    let shadow_slot = manifest.management_slot(shadow_node).unwrap();
    let system_route = AgentGenerationRoute {
        space: descriptor.identity.space,
        agent: AgentId(system.0),
        generation: Hash(manifest.generation().replication_id()),
    };
    let shadow_owner = ForwardedSharedInstallOwner {
        system: system_route,
        registration: Hash(shadow_slot.registration().commitment().0),
        member: Hash(shadow_slot.members()[0].commitment().0),
    };
    let mut transfer = ForwardedSharedInstallRequest {
        owner: shadow_owner,
        request: request.clone(),
        authority: receipt.clone(),
        operation: ForwardedSharedInstallOperation::Progress,
    };
    assert!(transfer.is_valid(route));
    let before: Vec<_> = owners
        .iter()
        .enumerate()
        .map(|(index, owner)| {
            published(
                owner.as_ref().unwrap(),
                ordinary,
                &directories[index].host(),
            )
        })
        .collect();
    let intent_before = install_store.image.lock().unwrap().clone();
    let issuer_before = issuer_store.image.lock().unwrap().clone();
    assert!(
        receiver_owner
            .host
            .lock()
            .unwrap()
            .retained_forwarded_shared_install(ordinary, &request, &receipt)
            .unwrap()
            .is_none()
    );
    // Directly assert the actual settled same-host authorization boundary too:
    // the valid shadow's only changed fact is its immutable original owner.
    let original_slot = manifest.management_slot(original_node).unwrap();
    assert_eq!(
        receiver_owner
            .host
            .lock()
            .unwrap()
            .validate_forwarded_shared_install_owner(
                system_route,
                NodeId(original_node.0),
                Hash(original_slot.registration().commitment().0),
                Hash(original_slot.members()[0].commitment().0),
                &request,
                &receipt,
            ),
        Ok(())
    );
    assert_eq!(
        receiver_owner
            .host
            .lock()
            .unwrap()
            .validate_forwarded_shared_install_owner(
                system_route,
                NodeId(shadow_node.0),
                shadow_owner.registration,
                shadow_owner.member,
                &request,
                &receipt,
            ),
        Err(SharedAgentHostError::InvalidProvision)
    );

    let mut offset = send(networks[shadow].as_ref(), target, route, transfer.clone())
        .expect("valid shadow custody permits bounded upload progress");
    while offset < clerk.package_ref().len {
        transfer.operation =
            ForwardedSharedInstallOperation::Chunk(chunk(status.route, &clerk, offset));
        let next = send(networks[shadow].as_ref(), target, route, transfer.clone())
            .expect("valid shadow custody permits this bounded package chunk");
        assert!(next > offset && transfer.admits_progress(next));
        offset = next;
    }
    assert_eq!(offset, clerk.package_ref().len);
    let uploads_before = files(
        &artifact_root(receiver_owner, ordinary).join("forwarded-install"),
        false,
    );
    transfer.operation = ForwardedSharedInstallOperation::Finish;
    assert_eq!(
        send(networks[shadow].as_ref(), target, route, transfer.clone()),
        None,
        "an authenticated shadow cannot Finish the original owner's None call"
    );
    assert_eq!(
        owners
            .iter()
            .enumerate()
            .map(|(index, owner)| published(
                owner.as_ref().unwrap(),
                ordinary,
                &directories[index].host()
            ))
            .collect::<Vec<_>>(),
        before
    );
    assert_eq!(*install_store.image.lock().unwrap(), intent_before);
    assert_eq!(*issuer_store.image.lock().unwrap(), issuer_before);
    assert_eq!(
        files(
            &artifact_root(receiver_owner, ordinary).join("forwarded-install"),
            false
        ),
        uploads_before
    );
    assert!(
        receiver_owner
            .host
            .lock()
            .unwrap()
            .retained_forwarded_shared_install(ordinary, &request, &receipt)
            .unwrap()
            .is_none()
    );

    // A structurally valid request selecting no actual root must explicitly
    // refuse before even upload creation; neither a timeout nor wire rejection
    // establishes this receiver-level absence boundary.
    transfer.owner.registration = Hash([0xf7; 32]);
    transfer.owner.member = Hash([0xf8; 32]);
    for operation in [
        ForwardedSharedInstallOperation::Progress,
        ForwardedSharedInstallOperation::Chunk(chunk(status.route, &clerk, 0)),
        ForwardedSharedInstallOperation::Finish,
    ] {
        transfer.operation = operation;
        assert!(transfer.is_valid(route));
        assert_eq!(
            send(networks[shadow].as_ref(), target, route, transfer.clone()),
            None
        );
    }
    assert_eq!(
        owners
            .iter()
            .enumerate()
            .map(|(index, owner)| published(
                owner.as_ref().unwrap(),
                ordinary,
                &directories[index].host()
            ))
            .collect::<Vec<_>>(),
        before
    );
    assert_eq!(*install_store.image.lock().unwrap(), intent_before);
    assert_eq!(*issuer_store.image.lock().unwrap(), issuer_before);
    assert_eq!(
        files(
            &artifact_root(receiver_owner, ordinary).join("forwarded-install"),
            false
        ),
        uploads_before
    );

    // The online original owner uses the SAME genuine continuing intent,
    // issued receipt and first policy capsule through the normal Native path.
    let owner = owners[origin].as_mut().unwrap();
    assert_eq!(
        owner
            ._network_host
            .bootstrap_raft_role_for_test(ordinary)
            .unwrap(),
        vos_raft::Role::Follower
    );
    let terminal = super::management_retention::exact_management_retry(
        "receiver fixture original Install",
        || {
            owner.complete_shared_install_from_management_intent(
                &mut intent,
                &clerk,
                &mut issuer,
                signer,
            )
        },
    );
    assert!(matches!(terminal, SignedManagementTerminal::Applied(_)));
    assert!(intent.retirement_complete().unwrap());
    let committed = owner
        .host
        .lock()
        .unwrap()
        .journal_position(ordinary)
        .unwrap();
    let retained_intent = install_store.image.lock().unwrap().clone();
    let retained_issuer = issuer_store.image.lock().unwrap().clone();
    let signatures = signer.calls;
    assert_eq!(
        owner
            .complete_shared_install_from_management_intent(
                &mut intent,
                &clerk,
                &mut issuer,
                signer
            )
            .unwrap(),
        terminal
    );
    assert_eq!(
        owner
            .host
            .lock()
            .unwrap()
            .journal_position(ordinary)
            .unwrap(),
        committed
    );
    assert_eq!(*install_store.image.lock().unwrap(), retained_intent);
    assert_eq!(*issuer_store.image.lock().unwrap(), retained_issuer);
    assert_eq!(signer.calls, signatures);
    let expected = owner
        .host
        .lock()
        .unwrap()
        .clean_state_commitment(ordinary)
        .unwrap();
    assert!(wait_until(Duration::from_secs(30), || owners.iter().all(
        |owner| {
            let host = owner.as_ref().unwrap().host.lock().unwrap();
            host.journal_position(ordinary).unwrap() == committed
                && host.clean_state_commitment(ordinary).unwrap() == expected
        }
    )));

    // Keep the original immutable publication owners alive through all calls.
    // Transfer-only residue is intentionally not confused with canonical actor
    // catalog publication; normal host teardown owns its discard/retry scope.
    drop((
        leased_archive,
        query,
        reply,
        publication,
        publication_reply,
        create_intent,
        create_issuer,
    ));
}
