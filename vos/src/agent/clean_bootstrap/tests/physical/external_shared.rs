//! Real Authority publication followed by three independently locked external
//! Shared journals. The file fixture isolates application/recovery; the network
//! fixture uses the candidate host, authenticated Raft and applied availability.
use super::*;
use crate::agent::clean_management_intent::{CleanManagementIntent, CleanManagementIntentSlot};
use crate::agent::genesis::VerifiedAgentGenesisProvision;
use crate::agent::journal::{CanonicalJournalRecord, ReplayOperation};
use crate::agent::journal_store::{
    AgentJournalStore, CatalogBlobResolverFactory, FileAgentJournalStore,
    FileLocalAgentJournalSlot, JournalBlobClass, MemoryAgentJournalStore,
};
use crate::agent::local_journal_driver::{LocalJournalAgentDriver, StandardLocalReplayExecutor};
use crate::agent::replay::{
    NoPrunedOrderedBases, ReplaySealedExternalGenesis, ReplaySealedOrdinaryGenesis,
};
use crate::agent::shared_journal_driver::{
    CleanInvocationReplayRequest, FileSharedArtifactStager, PreparedCleanOrdered,
    SharedJournalAgentDriver, SharedPhysicalApplyOutcome,
};
use crate::agent::shared_raft::{AgentGenerationRouteKey, AgentRaftApplicationLedgerV2};
use crate::agent_sdk::state_blocks::ReadBudget;

type Driver = SharedJournalAgentDriver<FileAgentJournalStore, FileSharedArtifactStager>;

fn budget() -> ReadBudget {
    ReadBudget::new(100_000, 128_000_000)
}

struct ReplicaFiles {
    directory: TestDirectory,
    seal: Arc<ReplaySealedExternalGenesis>,
    committee: AgentReplicaCommittee,
    authority: CommitteeChangeAuthorityBinding,
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    intent: HostHash,
}

impl ReplicaFiles {
    fn journal_root(&self) -> PathBuf {
        let agent = self.seal.genesis().runtime().agent;
        let leaf: String = agent.0.iter().map(|byte| format!("{byte:02x}")).collect();
        self.directory.0.join(format!("{leaf}.agent"))
    }

    fn acquire(&self) -> FileLocalAgentJournalSlot {
        let parent = std::fs::File::open(&self.directory.0).unwrap();
        FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            self.journal_root(),
            self.journal_root().with_extension("agent-lock"),
            self.merge.node(),
            self.intent,
            &parent,
            &parent,
        )
        .unwrap()
    }

    fn open(&self, fresh: bool, catalog: &[crate::agent::execution::RuntimeBlob]) -> Driver {
        let slot = self.acquire();
        let mut store = if fresh {
            let mut store = slot
                .open_external_genesis(&self.seal, false, &mut budget())
                .unwrap();
            for blob in catalog {
                store
                    .put_blob(
                        JournalBlobClass::CatalogArtifact,
                        &blob.reference,
                        &blob.bytes,
                    )
                    .unwrap();
            }
            store
                .initialize_external_local(&self.seal, &mut budget())
                .unwrap();
            store
        } else {
            slot.open_external_journal_with_executor(
                &self.seal,
                |store| {
                    Ok(StandardLocalReplayExecutor::new_shared(
                        store.catalog_blob_resolver()?,
                        self.trust.clone(),
                        self.merge.clone(),
                        vec![self.committee.clone()],
                    ))
                },
                &NoPrunedOrderedBases,
                &mut budget(),
            )
            .unwrap()
            .0
        };
        let generation = AgentGenerationRouteKey::new(
            self.committee.space(),
            self.committee.agent(),
            self.seal.genesis().id(),
            self.seal.admission_record().unwrap().id(),
        )
        .unwrap();
        let ledger = AgentRaftApplicationLedgerV2::open(
            Arc::new(redb::Database::create(self.directory.0.join("raft.redb")).unwrap()),
            generation,
            store.instance_id(),
            self.merge.node(),
            self.committee.clone(),
            self.authority,
        )
        .unwrap();
        let artifacts_path = self.directory.0.join("artifacts");
        if fresh {
            std::fs::create_dir(&artifacts_path).unwrap();
        }
        let artifacts = FileSharedArtifactStager::open(artifacts_path, generation).unwrap();
        if fresh {
            store
                .commit_external_genesis_exposure(&self.seal, self.intent, &mut budget())
                .unwrap();
        }
        SharedJournalAgentDriver::open_external(
            store,
            artifacts,
            ledger,
            self.trust.clone(),
            self.merge.clone(),
            self.seal.clone(),
        )
        .unwrap()
    }
}

fn apply(drivers: &mut [Driver], payloads: Vec<Vec<u8>>) {
    for payload in payloads {
        let mut expected = None;
        for (replica, driver) in drivers.iter_mut().enumerate() {
            let index = driver.append_command_for_test(1, payload.clone()).unwrap();
            assert_eq!(index, *expected.get_or_insert(index));
            assert_eq!(
                driver.apply_next().unwrap_or_else(|error| panic!(
                    "replica {replica} committed slot {index}: {error:?}"
                )),
                SharedPhysicalApplyOutcome::Applied { index }
            );
        }
    }
}

fn ordered(drivers: &mut [Driver], request: CleanInvocationReplayRequest) -> RuntimeOutcome {
    let mut selected = None;
    for driver in drivers.iter() {
        let PreparedCleanOrdered::Proposal { input, payload } = driver
            .prepare_clean_ordered_operation(request.clone())
            .unwrap()
        else {
            panic!("new operation unexpectedly retained");
        };
        assert_eq!(
            &(input, payload.clone()),
            selected.get_or_insert((input, payload))
        );
    }
    let (input, payload) = selected.unwrap();
    apply(drivers, vec![payload]);
    let mut result = None;
    for driver in drivers {
        let outcome = driver.take_clean_ordered_result(input).unwrap();
        assert_eq!(&outcome, result.get_or_insert(outcome.clone()));
    }
    result.unwrap()
}

struct GenesisSigner(SigningKey);
impl super::super::super::genesis_issuance::GenesisClaimSigner for GenesisSigner {
    type Error = ();
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign_genesis_claim(&mut self, message: &[u8; 32]) -> Result<[u8; 64], ()> {
        Ok(self.0.sign(message).to_bytes())
    }
}

fn enroll_replica(owner: &mut MemoryBootstrapOwner, node_key: &SigningKey, nonce: u8) {
    use crate::actors::value::Value;
    use crate::agent_sdk::InvocationAuthorization;
    use crate::agent_sdk::authority::{
        AuthorityAdminCall, AuthorityAdminOperation, AuthorityAdminResult,
    };
    let key = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
    let public = key.verifying_key().to_bytes();
    let credential = CredentialId::of_public_key(&public);
    let (attestor, _, _, node) = node_material();
    let mut query = AuthorityProjectionQuery {
        recovery: None,
        authority: owner.authority_target(),
        credential,
        nonce: Hash([nonce; 32]),
        selector: AuthorityProjectionSelector::Credential,
        authentication: AuthorityIngressAuthentication::SshNodeAttestation {
            credential_public_key: public,
            node: NodeId(node.0),
            request_binding: Hash([nonce; 32]),
            signature: [1; 64],
        },
    };
    let signature = attestor.sign(&query.signing_bytes()).to_bytes();
    query.authentication = AuthorityIngressAuthentication::SshNodeAttestation {
        credential_public_key: public,
        node: NodeId(node.0),
        request_binding: Hash([nonce; 32]),
        signature,
    };
    let current =
        AuthorityCredentialProjection::decode(&owner.invoke_authority_projection(query).unwrap())
            .unwrap();
    let target = owner.authority_target();
    let mut material = owner
        .supervisor_invocation_material(owner.pins.agent, target.binding.issuer.actor)
        .unwrap();
    material.root_provenance = false;
    let identity =
        crate::agent::supervisor_adapters::physical_material_identity(&material).unwrap();
    let mut enrollment = crate::agent_sdk::private::NodeEncryptionEnrollment::from_keys(
        target.space,
        current.principal,
        node_key.verifying_key().to_bytes(),
        [nonce; 32],
        [1; 64],
    );
    enrollment.transport_signature = node_key.sign(&enrollment.signing_bytes()).to_bytes();
    let mut call = AuthorityAdminCall {
        invocation: InvocationId::ZERO,
        authority: target,
        administrator: current.principal,
        credential,
        request_sequence: NonZeroU64::new(current.admin_request_high_water + 1).unwrap(),
        credential_public_key: public,
        authenticated_node: owner.pins.node,
        observed_slot: material.observed_slot,
        expected_generation: current.head.administration_generation,
        operation: AuthorityAdminOperation::EnrollNode { enrollment },
        signature: [1; 64],
    };
    call.invocation = call.expected_invocation();
    call.signature = key.sign(&call.signing_bytes()).to_bytes();
    call.verify_with(&RawCredentialVerifier).unwrap();
    let mut availability = vec![material.program, material.schema, material.policies];
    availability.extend(material.installation_data);
    availability.sort_unstable_by(|a, b| a.reference.cmp(&b.reference));
    let work = InvocationWork {
        space: target.space,
        agent: target.system_agent,
        runtime_deployment: target.system_runtime_deployment,
        invocation: call.invocation,
        actor: target.binding.issuer.actor,
        incarnation: material.actor.incarnation,
        deployment: target.binding.issuer.deployment,
        program: target.binding.issuer.program,
        mode: MethodMode::Linear,
        origin: InvocationOrigin {
            principal: Some(current.principal),
            credential: Some(credential),
            transport_node: Some(owner.pins.node),
            actor: None,
            capability: None,
        },
        roles: InvocationRoleClaims::none(),
        message: dynamic_message("administer", "call", Value::Bytes(call.encode().unwrap())),
        installation_data: material.actor.entry.installation_data,
        availability,
        gas: owner.invocation_gas,
        recovery_only: false,
    };
    let auth = InvocationAuthorization::PublicPreflight(
        crate::agent_sdk::PublicPreflight::for_work(&work, call.observed_slot),
    );
    let result = owner
        .supervisor_invoke_terminal(identity, work.clone(), auth.clone())
        .unwrap();
    let RuntimeOutcome::Completed(Ok(reply)) = result else {
        panic!("node enrollment: {result:?}")
    };
    let Some(Value::Bytes(bytes)) = Value::try_decode(&reply.reply) else {
        panic!("invalid enrollment response")
    };
    let result = AuthorityAdminResult::decode(&bytes).unwrap();
    result.verify_with(&RawCredentialVerifier).unwrap();
    assert_eq!(result.call, call);
    assert!(matches!(
        owner.supervisor_acknowledge(identity, work, auth).unwrap(),
        RuntimeOutcome::Acknowledged(Ok(_))
    ));
}

#[test]
#[ignore = "requires compiled external runtime/Authority, CLERK_AGENT_PACKAGE and physical outer PVM"]
fn three_file_replicas_external_clerk_install_invoke_ack_reopen() {
    external_clerk_lifecycle(false);
}

#[test]
#[ignore = "requires compiled external runtime/Authority, CLERK_AGENT_PACKAGE and authenticated loopback"]
fn three_network_replicas_external_clerk_install_invoke_ack_reopen() {
    external_clerk_lifecycle(true);
}

fn external_clerk_lifecycle(with_network: bool) {
    use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
    use crate::agent::driver::SdkManagementArtifacts;
    use crate::agent::package_admission::{
        admit_actor_package, tests::admitted_state_fixture_limits,
    };
    use crate::agent_sdk::{InvocationAuthorization, RuntimeExecutionContext};

    assert!(std::env::var_os("VOS_AGENT_PROFILE_REFINE_MACHINES").is_some());
    let target = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    let mut fixture = native_candidate_state_authority_fixture(&target);
    struct RejectArchive;
    impl AgentGenesisFinalityVerifier for RejectArchive {
        fn verify_finalized(
            &self,
            _: &crate::agent::genesis::AgentGenesisProvision,
        ) -> Result<(), AgentGenesisFinalityError> {
            Err(AgentGenesisFinalityError::NotFinalized)
        }
    }
    fixture.finality = Arc::new(RejectArchive);
    let mut harness =
        NativeProjectionOwnerHarness::with_real_bootstrap("external-shared-clerk", fixture);
    let owner = harness.owner.as_mut().unwrap();
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
    // Sign the narrowed capabilities into the package, not just the descriptor.
    // Scheduling=false alone does not exclude yield: the host's physical
    // pre-proposal validation separately requires a completed Direct result.
    let mut package = PackageEnvelope::decode(runtime.exact_bytes()).unwrap();
    let PackageManifest::AgentRuntime(manifest) = &mut package.manifest else {
        unreachable!()
    };
    manifest.capabilities.scheduling = false;
    manifest.capabilities.proof_systems = ProofSystemSet::EMPTY;
    let runtime_signer = SigningKey::from_bytes(&[0x67; 32]);
    let public_key = runtime_signer.verifying_key().to_bytes();
    *package.manifest.signing_mut() = PackageSigning {
        producer: ProducerId::of_public_key(&public_key),
        public_key,
        signature: [0; 64],
    };
    package.manifest.signing_mut().signature = runtime_signer
        .sign(&package.signing_bytes().unwrap())
        .to_bytes();
    let runtime =
        crate::agent::package_admission::admit_state_runtime_package(&package.encode().unwrap())
            .unwrap();
    let clerk = admit_actor_package(
        &std::fs::read(std::env::var_os("CLERK_AGENT_PACKAGE").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(clerk.manifest().name.as_str(), "clerk-ledger");
    assert_eq!(clerk.requirements().lanes, LaneSet::of(StateLane::Linear));
    let mut descriptor = owner.pins.descriptor.clone();
    descriptor.creation_nonce = Hash([0xd9; 32]);
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
    let keys: Vec<_> = [NODE_SEED, 0x61, 0x62]
        .into_iter()
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .collect();
    for (index, key) in keys.iter().skip(1).enumerate() {
        enroll_replica(owner, key, 0x63 + index as u8);
    }
    let mut members: Vec<_> = keys
        .iter()
        .map(|key| {
            let keypair = libp2p::identity::Keypair::ed25519_from_bytes(key.to_bytes()).unwrap();
            let peer = keypair.public().to_peer_id().to_bytes();
            let node = HostNodeId::of_authenticated_peer(&peer);
            AgentReplicaMember::new(
                HostAgentReplica {
                    node,
                    principal: HostPrincipalId(descriptor.identity.owner.0),
                    role: HostReplicaRole::Voter,
                },
                peer.clone(),
                key.verifying_key().to_bytes(),
                Some(crate::agent::genesis::derive_replica_raft_slot(&peer)),
            )
            .unwrap()
        })
        .collect();
    members.sort_by_key(|member| member.replica().node);
    let committee = AgentReplicaCommittee::new(
        HostSpaceId(descriptor.identity.space.0),
        HostAgentId(descriptor.identity.agent.0),
        HostAgentProfile::Shared,
        members,
    )
    .unwrap();
    descriptor.replicas = committee
        .members()
        .iter()
        .map(|member| AgentReplica {
            node: crate::agent_sdk::NodeId(member.replica().node.0),
            principal: PrincipalId(member.replica().principal.0),
            role: ReplicaRole::Voter,
        })
        .collect();
    descriptor.validate().unwrap();
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let key = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
    let (mut call, _) = credential_call_and_approval(&descriptor, &request, &key);
    call.request_sequence = NonZeroU64::new(2).unwrap();
    call.authority = owner.authority_target();
    call.invocation = call.expected_invocation();
    call.signature = key.sign(&call.signing_bytes()).to_bytes();
    let mut slot = CleanManagementIntentSlot::open(IssuerMemoryStore::default()).unwrap();
    slot.pledge(
        CleanManagementIntent::new(
            owner.authority_target(),
            call.managed,
            request,
            call.clone(),
            &RawCredentialVerifier,
        )
        .unwrap(),
    )
    .unwrap();
    let mut issuer = DurableCleanManagementIssuer::open(
        IssuerMemoryStore::default(),
        descriptor.authority,
        descriptor.identity.space,
        descriptor.identity.agent,
    )
    .unwrap();
    assert!(crate::agent::replay::external_shared_descriptor_supported(
        &descriptor
    ));
    committee
        .validate_for_clean_descriptor(&descriptor)
        .unwrap();
    assert!(
        committee
            .member_by_node(HostNodeId(owner.pins.node.0))
            .is_some()
    );
    let mut receipt_signer = CountingSigner::new();
    let prepared = owner
        .prepare_external_shared_from_management_intent(
            &mut slot,
            call.managed,
            &runtime,
            &committee,
            &mut issuer,
            &mut receipt_signer,
        )
        .expect("enrolled signed Shared Create must receive exact Authority admission");
    assert_eq!(prepared.replicas().members().len(), 3);
    let applied = owner.ordered_index_for_test().unwrap();
    assert_eq!(
        owner
            .prepare_external_shared_from_management_intent(
                &mut slot,
                call.managed,
                &runtime,
                &committee,
                &mut issuer,
                &mut receipt_signer,
            )
            .unwrap(),
        prepared
    );
    assert_eq!(receipt_signer.calls, 1);
    assert_eq!(owner.ordered_index_for_test().unwrap(), applied);
    let mut query = IssuerMemoryStore::default();
    let authority_committee = owner
        .query_genesis_committee(
            &prepared,
            &slot,
            &mut query,
            &mut IssuerMemoryStore::default(),
        )
        .unwrap();
    let signature = super::super::super::genesis_issuance::issue(
        &prepared,
        &authority_committee,
        &mut IssuerMemoryStore::default(),
        &mut GenesisSigner(key),
    )
    .unwrap();
    let record = super::super::super::genesis_issuance::assemble(
        &prepared,
        &authority_committee,
        vec![signature],
    )
    .unwrap();
    let mut publication = IssuerMemoryStore::default();
    let mut publication_reply = IssuerMemoryStore::default();
    assert!(
        owner
            .verify_authorized_shared_genesis_publication(
                &prepared,
                &authority_committee,
                &record,
                &mut query,
                &mut publication,
                &mut publication_reply,
            )
            .is_err(),
        "unpublished certificate must not authorize a generation"
    );
    owner
        .execute_genesis_publication(
            &prepared,
            &authority_committee,
            &record,
            &mut query,
            &mut publication,
            &mut publication_reply,
        )
        .unwrap();
    let finality = owner
        .verify_authorized_shared_genesis_publication(
            &prepared,
            &authority_committee,
            &record,
            &mut query,
            &mut publication,
            &mut publication_reply,
        )
        .unwrap();
    if with_network {
        external_network_lifecycle(
            &harness.fixture,
            &descriptor,
            &runtime,
            &clerk,
            &keys,
            record.provision(),
            prepared.catalog(),
            &finality,
            harness.network.clone(),
        );
        harness.stop();
        return;
    }
    let verified =
        VerifiedAgentGenesisProvision::verify(record.provision().clone(), &finality).unwrap();
    let authority = CommitteeChangeAuthorityBinding::new(
        descriptor.authority.policy,
        descriptor.authority.issuer,
        descriptor.identity.runtime_deployment,
        descriptor.authority.public_key,
        descriptor.authority.initial_epoch,
    )
    .unwrap();
    let files: Vec<_> = keys.into_iter().map(|key| {
        let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(crate::agent::local_journal_driver::Ed25519NodeMergeAuthenticator::new(
            libp2p::identity::Keypair::ed25519_from_bytes(key.to_bytes()).unwrap(),
        ).unwrap());
        let replica = committee.member_by_node(merge.node()).unwrap().replica();
        let seal = LocalJournalAgentDriver::<MemoryAgentJournalStore>::prepare_external_shared_genesis(
            &verified, replica, prepared.catalog(), &harness.fixture.trust, merge.node(),
        ).unwrap();
        let directory = TestDirectory::new("external-shared-file-replica");
        // Preserve the full authenticated provision before acquiring a stable
        // generation slot. This fixture does not substitute a bare hash for it.
        write_operation_test_image(&directory.0.join("genesis.provision"), &record.encode()).unwrap();
        ReplicaFiles { directory, seal: Arc::new(seal), committee: committee.clone(), authority,
            trust: harness.fixture.trust.clone(), merge,
            intent: HostHash::digest(b"vos/test/external-shared/provision/v1", &[&record.encode()]) }
    }).collect();
    let mut drivers: Vec<_> = files
        .iter()
        .map(|files| files.open(true, prepared.catalog()))
        .collect();
    let install = install_request(descriptor.identity.agent, &clerk, 0x71, None);
    let ManagementRequest::Install(install_actor) = &install else {
        unreachable!()
    };
    let actor = install_actor.entry.actor;
    let mut receipt = prepared.proposal().create().operation.clone();
    let ReplayOperation::CleanManage {
        authority: ref mut install_receipt,
        ..
    } = receipt
    else {
        unreachable!()
    };
    install_receipt.selector.operation = install.authority_operation().unwrap();
    (
        install_receipt.selector.actor,
        install_receipt.selector.actor_deployment,
    ) = install.authority_actor_selector();
    install_receipt.selector.request = install.commitment();
    install_receipt.selector.decision_sequence += 1;
    install_receipt.selector.expires_at += 100;
    install_receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
        .sign(&install_receipt.signing_bytes())
        .to_bytes();
    let install_receipt = install_receipt.clone();
    let same_slot = drivers[0]
        .prepare_clean_management(
            install.clone(),
            install_receipt.clone(),
            SdkManagementArtifacts::Actor(&clerk),
        )
        .unwrap();
    assert!(
        matches!(
            &same_slot,
            crate::agent::shared_journal_driver::PreparedCleanManagement::Denied {
                outcome: RuntimeOutcome::Management(Err(
                    crate::agent_sdk::ManagementError::AuthoritySequenceConflict
                )),
                ..
            }
        ),
        "same-slot Install: {same_slot:?}"
    );
    // Distinct management mutations require an advancing trusted logical slot.
    harness
        .fixture
        .logical_slot
        .as_ref()
        .unwrap()
        .fetch_add(1, Ordering::AcqRel);
    let mut install_plan = None;
    for driver in &mut drivers {
        let plan = driver
            .prepare_clean_management(
                install.clone(),
                install_receipt.clone(),
                SdkManagementArtifacts::Actor(&clerk),
            )
            .unwrap();
        let input = plan
            .input()
            .unwrap_or_else(|| panic!("Clerk Install admission: {plan:?}"));
        let commands = plan.into_commands();
        assert!(!commands.is_empty());
        assert_eq!(
            &(input, commands.clone()),
            install_plan.get_or_insert((input, commands))
        );
    }
    let (install_input, commands) = install_plan.unwrap();
    apply(&mut drivers, commands);
    let install_claim = drivers[0].available_ordered_claim(install_input).unwrap();
    for driver in &mut drivers {
        assert_eq!(
            driver.available_ordered_claim(install_input).unwrap(),
            install_claim
        );
        driver
            .verify_ordered_availability(
                install_claim.raft_index(),
                install_claim.raft_term(),
                install_claim.commitment(),
            )
            .unwrap();
        assert!(matches!(
            driver.take_clean_ordered_result(install_input).unwrap(),
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(_)))
        ));
    }
    let material = drivers[0].physical_invocation_material(actor).unwrap();
    let mut availability = vec![material.program, material.schema, material.policies];
    availability.extend(material.installation_data);
    availability.sort_by(|a, b| a.reference.cmp(&b.reference));
    let mut message = vec![TAG_DYNAMIC];
    message.extend(Msg::new("journal_id").encode());
    let work = InvocationWork {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        runtime_deployment: runtime.deployment(),
        invocation: InvocationId([0xe1; 32]),
        actor,
        incarnation: material.actor.incarnation,
        deployment: clerk.deployment(),
        program: clerk.program(),
        mode: MethodMode::LinearizableQuery,
        origin: InvocationOrigin::anonymous(),
        roles: InvocationRoleClaims::none(),
        message,
        installation_data: material.actor.entry.installation_data,
        availability,
        gas: 100_000_000,
        recovery_only: false,
    };
    let mut receipt = install_receipt;
    receipt.selector.operation = crate::agent_sdk::authority::AuthorityOperationKind::InvokeActor;
    receipt.selector.request = work.commitment();
    receipt.selector.decision_sequence = 0;
    receipt.selector.acknowledged_through = 0;
    receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
        .sign(&receipt.signing_bytes())
        .to_bytes();
    let authorization = InvocationAuthorization::AuthorityReceipt(receipt);
    // Validly re-signed excessive gas must fail at admission, not poison a
    // committed Raft slot. Rejection cannot invalidate earlier availability.
    for driver in &drivers {
        let before = (driver.journal_position(), driver.capacity().unwrap());
        let claim = driver.available_ordered_claim(install_input).unwrap();
        let mut oversized = work.clone();
        oversized.invocation = InvocationId([0xe2; 32]);
        oversized.gas = crate::agent::execution::MAX_EXECUTION_GAS + 1;
        let InvocationAuthorization::AuthorityReceipt(mut receipt) = authorization.clone() else {
            unreachable!()
        };
        receipt.selector.request = oversized.commitment();
        receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
            .sign(&receipt.signing_bytes())
            .to_bytes();
        assert!(
            driver
                .prepare_clean_ordered(
                    oversized.clone(),
                    InvocationAuthorization::AuthorityReceipt(receipt.clone())
                )
                .is_err()
        );
        assert_eq!(
            (driver.journal_position(), driver.capacity().unwrap()),
            before
        );
        driver
            .verify_ordered_availability(claim.raft_index(), claim.raft_term(), claim.commitment())
            .unwrap();
        oversized.gas -= 1;
        receipt.selector.request = oversized.commitment();
        receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
            .sign(&receipt.signing_bytes())
            .to_bytes();
        assert!(matches!(
            driver
                .prepare_clean_ordered(
                    oversized,
                    InvocationAuthorization::AuthorityReceipt(receipt)
                )
                .unwrap(),
            PreparedCleanOrdered::Proposal { .. }
        ));
        let yielded = crate::agent_sdk::YieldedInvocation {
            invocation: work.invocation,
            actor: work.actor,
            incarnation: work.incarnation,
            deployment: work.deployment,
            program: work.program,
            mode: work.mode,
            continuation: BlobRef::of_bytes(b"unadmitted-continuation"),
            ready_sequence: 1,
            installation_data: work.installation_data.clone(),
            required: work
                .availability
                .iter()
                .map(|blob| blob.reference.clone())
                .collect(),
            reason: crate::agent_sdk::YieldReason::Cooperative,
        };
        assert!(yielded.validate());
        for unsupported in [
            CleanInvocationReplayRequest::Resume {
                context: RuntimeExecutionContext::Direct,
                work: work.clone(),
                authorization: authorization.clone(),
                yielded,
            },
            CleanInvocationReplayRequest::Invoke {
                context: RuntimeExecutionContext::Attested {
                    proof_system: Hash([0x7f; 32]),
                },
                work: work.clone(),
                authorization: authorization.clone(),
            },
        ] {
            assert!(driver.prepare_clean_ordered_operation(unsupported).is_err());
            assert_eq!(
                (driver.journal_position(), driver.capacity().unwrap()),
                before
            );
            driver
                .verify_ordered_availability(
                    claim.raft_index(),
                    claim.raft_term(),
                    claim.commitment(),
                )
                .unwrap();
        }
    }
    let invoke = CleanInvocationReplayRequest::Invoke {
        context: RuntimeExecutionContext::Direct,
        work: work.clone(),
        authorization: authorization.clone(),
    };
    let result = ordered(&mut drivers, invoke.clone());
    let RuntimeOutcome::Completed(Ok(reply)) = &result else {
        panic!("Clerk query: {result:?}");
    };
    assert_eq!(Value::decode(&reply.reply), Value::Bytes(Vec::new()));
    let states: Vec<_> = drivers
        .iter()
        .map(|driver| driver.materialization().state().clone())
        .collect();
    assert!(states.windows(2).all(|pair| pair[0] == pair[1]));
    drop(drivers);
    let mut drivers: Vec<_> = files.iter().map(|files| files.open(false, &[])).collect();
    for (driver, state) in drivers.iter_mut().zip(states) {
        assert_eq!(driver.materialization().state(), &state);
        assert_eq!(
            driver.available_ordered_claim(install_input).unwrap(),
            install_claim
        );
        driver
            .verify_ordered_availability(
                install_claim.raft_index(),
                install_claim.raft_term(),
                install_claim.commitment(),
            )
            .unwrap();
        assert_eq!(
            driver
                .replay_durable_clean_terminal(invoke.clone())
                .unwrap(),
            result
        );
    }
    let acknowledgement = ordered(
        &mut drivers,
        CleanInvocationReplayRequest::Acknowledge {
            work: work.clone(),
            authorization: authorization.clone(),
        },
    );
    assert!(matches!(
        acknowledgement,
        RuntimeOutcome::Acknowledged(Ok(_))
    ));
    drop(drivers);
    let drivers: Vec<_> = files.iter().map(|files| files.open(false, &[])).collect();
    for driver in &drivers {
        assert!(
            driver
                .retained_positive_clean_acknowledgement(&work, &authorization)
                .unwrap()
        );
    }
    // A lost block revokes this open's availability proof; read-only reopen
    // must fail instead of silently recovering/repairing it from history.
    let claim = drivers[0].available_ordered_claim(install_input).unwrap();
    let root = drivers[0]
        .materialization()
        .external_inspection_lanes()
        .unwrap()[0]
        .base;
    let block = root
        .bind(root.context(), root.commitment())
        .unwrap()
        .root()
        .unwrap();
    let name: String = block
        .hash()
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let path = files[0].journal_root().join("lane-state/blocks").join(name);
    let parked = files[0].directory.0.join("parked-state-block");
    std::fs::rename(&path, &parked).unwrap();
    let mut fresh = work.clone();
    fresh.invocation = InvocationId([0xe3; 32]);
    let InvocationAuthorization::AuthorityReceipt(mut receipt) = authorization else {
        unreachable!()
    };
    receipt.selector.request = fresh.commitment();
    receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
        .sign(&receipt.signing_bytes())
        .to_bytes();
    assert!(
        drivers[0]
            .prepare_clean_ordered(fresh, InvocationAuthorization::AuthorityReceipt(receipt))
            .is_err()
    );
    assert!(
        drivers[0]
            .verify_ordered_availability(claim.raft_index(), claim.raft_term(), claim.commitment())
            .is_err()
    );
    drop(drivers);
    let files = &files[0];
    assert!(
        files
            .acquire()
            .open_external_journal_with_executor(
                &files.seal,
                |store| Ok(StandardLocalReplayExecutor::new_shared(
                    store.catalog_blob_resolver()?,
                    files.trust.clone(),
                    files.merge.clone(),
                    vec![files.committee.clone()]
                )),
                &NoPrunedOrderedBases,
                &mut budget(),
            )
            .is_err()
    );
    assert!(
        !path.exists(),
        "failed open must not repair the missing block"
    );
    std::fs::rename(&parked, &path).unwrap();
    // A fresh full audit can re-establish availability after exact restoration.
    files
        .open(false, &[])
        .verify_ordered_availability(claim.raft_index(), claim.raft_term(), claim.commitment())
        .unwrap();
    harness.stop();
}

fn external_network_lifecycle(
    fixture: &PhysicalFixture,
    descriptor: &AgentDescriptor,
    runtime: &crate::agent::package_admission::AdmittedStateRuntimePackage,
    clerk: &crate::agent::package_admission::AdmittedActorPackage,
    keys: &[SigningKey],
    provision: &crate::agent::genesis::AgentGenesisProvision,
    catalog: &[crate::agent::execution::RuntimeBlob],
    finality: &ReplayVerifiedAgentGenesisFinality,
    authority_network: Arc<Network>,
) {
    use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
    use crate::agent::driver::SdkManagementArtifacts;
    use crate::network::SharedAgentNetworkHost;
    use crate::network::shared_agent::CleanManagementSubmission;

    let agent = HostAgentId(descriptor.identity.agent.0);
    let authority = CommitteeChangeAuthorityBinding::new(
        descriptor.authority.policy,
        descriptor.authority.issuer,
        descriptor.identity.runtime_deployment,
        descriptor.authority.public_key,
        descriptor.authority.initial_epoch,
    )
    .unwrap();
    let directories: Vec<_> = keys
        .iter()
        .map(|_| TestDirectory::new("external-shared-network-owner"))
        .collect();
    let merges: Vec<Arc<dyn LocalMergeAuthenticator>> = keys
        .iter()
        .map(|key| {
            Arc::new(
                crate::agent::local_journal_driver::Ed25519NodeMergeAuthenticator::new(
                    libp2p::identity::Keypair::ed25519_from_bytes(key.to_bytes()).unwrap(),
                )
                .unwrap(),
            ) as Arc<dyn LocalMergeAuthenticator>
        })
        .collect();
    let open = |index: usize, candidate: bool| {
        let scope = crate::agent::host::AgentHostScope {
            space: HostSpaceId(descriptor.identity.space.0),
            node: merges[index].node(),
        };
        let proof: Arc<dyn AgentGenesisFinalityVerifier> = Arc::new(finality.clone());
        if candidate {
            SharedAgentHost::open_external_candidates(
                directories[index].host(),
                directories[index].lock(),
                scope,
                fixture.trust.clone(),
                merges[index].clone(),
                proof,
                None,
            )
        } else {
            SharedAgentHost::open(
                directories[index].host(),
                directories[index].lock(),
                scope,
                fixture.trust.clone(),
                merges[index].clone(),
                proof,
            )
        }
    };
    let mut hosts: Vec<_> = (0..keys.len())
        .map(|index| {
            let mut host = open(index, true).unwrap();
            let status = host
                .provision_replay_verified(provision.clone(), catalog.to_vec(), authority, finality)
                .unwrap();
            assert!(host.uses_external_state(agent).unwrap());
            assert_eq!(status.replicas.len(), 3);
            assert!(status.engines.control_raft && status.engines.linear_raft);
            assert!(!status.engines.merge && !status.engines.local);
            let route = host.physical_route(agent).unwrap();
            assert_eq!(route.generation, status.generation);
            assert_eq!(route.replication_id, status.replication_id);
            assert!(route.raft_database.is_file());
            Arc::new(std::sync::Mutex::new(host))
        })
        .collect();
    let networks: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            if index == 0 {
                // The actual Authority owner is on this voter. Attach the new
                // generation to its existing authenticated transport, not a
                // second simultaneous transport impersonating the same PeerId.
                return authority_network.clone();
            }
            let keypair = libp2p::identity::Keypair::ed25519_from_bytes(key.to_bytes()).unwrap();
            let peer = keypair.public().to_peer_id();
            Arc::new(Network::start(NetworkConfig {
                keypair,
                local_prefix: crate::network::derive_node_prefix(&peer),
                listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                bootstrap: Vec::new(),
                auto_dial_mdns: false,
            }))
        })
        .collect();
    assert!(wait_until(std::time::Duration::from_secs(5), || networks
        .iter()
        .skip(1)
        .all(|network| !network.listen_addrs().is_empty())));
    let mut last_dial = None;
    assert!(
        wait_until(std::time::Duration::from_secs(15), || {
            if networks
                .iter()
                .all(|network| network.connected_peers().len() == 2)
            {
                return true;
            }
            if last_dial.is_none_or(|last: std::time::Instant| {
                last.elapsed() >= std::time::Duration::from_millis(250)
            }) {
                for (index, network) in networks.iter().enumerate() {
                    for target in networks.iter().skip(index + 1) {
                        network.connect(target.listen_addrs()[0].clone());
                    }
                }
                last_dial = Some(std::time::Instant::now());
            }
            false
        }),
        "external candidate authenticated mesh did not connect"
    );
    let attach = |hosts: &[Arc<std::sync::Mutex<SharedAgentHost>>]| -> Vec<_> {
        hosts
            .iter()
            .zip(&networks)
            .map(|(host, network)| {
                SharedAgentNetworkHost::attach(host.clone(), network.clone()).unwrap()
            })
            .collect()
    };
    let mut attached = attach(&hosts);
    let install = install_request(descriptor.identity.agent, clerk, 0x71, None);
    let ManagementRequest::Install(install_actor) = &install else {
        unreachable!()
    };
    let actor = install_actor.entry.actor;
    let ReplayOperation::CleanManage {
        authority: create_receipt,
        ..
    } = &provision.proposal().create().operation
    else {
        unreachable!()
    };
    let mut receipt = create_receipt.clone();
    receipt.selector.operation = install.authority_operation().unwrap();
    (receipt.selector.actor, receipt.selector.actor_deployment) =
        install.authority_actor_selector();
    receipt.selector.request = install.commitment();
    receipt.selector.decision_sequence += 1;
    receipt.selector.expires_at += 100;
    receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
        .sign(&receipt.signing_bytes())
        .to_bytes();
    fixture
        .logical_slot
        .as_ref()
        .unwrap()
        .fetch_add(1, Ordering::AcqRel);
    let installed = external_network_on_leader(&attached, agent, |owner| {
        owner
            .manage_clean(
                agent,
                install.clone(),
                receipt.clone(),
                SdkManagementArtifacts::Actor(clerk),
            )
            .map(|result| match result {
                CleanManagementSubmission::Applied { outcome, .. } => outcome,
                CleanManagementSubmission::Denied { outcome, .. } => {
                    panic!("external network Install denied: {outcome:?}")
                }
            })
    });
    assert!(matches!(
        installed,
        RuntimeOutcome::Management(Ok(ManagementReply::Installed(_)))
    ));
    assert!(wait_until(std::time::Duration::from_secs(15), || hosts
        .iter()
        .all(|host| {
            host.lock()
                .unwrap()
                .journal_position(agent)
                .unwrap()
                .ordered_index
                == 1
        })));
    let material = hosts[0]
        .lock()
        .unwrap()
        .supervisor_invocation_material(agent, actor)
        .unwrap();
    let identity =
        crate::agent::supervisor_adapters::physical_material_identity(&material).unwrap();
    let mut availability = vec![material.program, material.schema, material.policies];
    availability.extend(material.installation_data);
    availability.sort_by(|left, right| left.reference.cmp(&right.reference));
    let mut message = vec![TAG_DYNAMIC];
    message.extend(Msg::new("journal_id").encode());
    let work = InvocationWork {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        runtime_deployment: runtime.deployment(),
        invocation: InvocationId([0xe1; 32]),
        actor,
        incarnation: material.actor.incarnation,
        deployment: clerk.deployment(),
        program: clerk.program(),
        mode: MethodMode::LinearizableQuery,
        origin: InvocationOrigin::anonymous(),
        roles: InvocationRoleClaims::none(),
        message,
        installation_data: material.actor.entry.installation_data,
        availability,
        gas: 100_000_000,
        recovery_only: false,
    };
    receipt.selector.operation = crate::agent_sdk::authority::AuthorityOperationKind::InvokeActor;
    receipt.selector.request = work.commitment();
    receipt.selector.decision_sequence = 0;
    receipt.selector.acknowledged_through = 0;
    receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
        .sign(&receipt.signing_bytes())
        .to_bytes();
    let authorization = InvocationAuthorization::AuthorityReceipt(receipt);
    // Use the signed package's roles for the Clerk kernel workflow. The
    // Authority receipt binds each exact call independently of the embedded
    // registrar/debit signatures, which the physical Clerk guest must verify.
    let policy = ActorMethodPolicyArtifact::decode(clerk.method_policy_bytes()).unwrap();
    let clerk_role = |method: &str| {
        let AuthorizationPolicySelector::ActorRole(role) = policy
            .methods
            .iter()
            .find(|entry| entry.name == method)
            .unwrap_or_else(|| panic!("missing signed Clerk {method} policy"))
            .authorization_policy
        else {
            panic!("Clerk {method} must require its signed actor role");
        };
        role
    };
    let operator = clerk_role("bootstrap");
    assert_eq!(clerk_role("create_account"), operator);
    assert_eq!(clerk_role("apply_transfer"), operator);
    let member = clerk_role("state_root");
    let clerk_call = |method: &str,
                      args: Vec<(&str, Value)>,
                      mode: MethodMode,
                      role: crate::agent_sdk::RoleId,
                      invocation: u8| {
        let mut call = work.clone();
        call.invocation = InvocationId([invocation; 32]);
        call.mode = mode;
        call.gas = crate::agent::execution::MAX_EXECUTION_GAS;
        call.origin.principal = Some(PrincipalId([0xe3; 32]));
        call.roles.actor = Some(role);
        let mut message = Msg::new(method);
        for (name, value) in args {
            message = message.with(name, value);
        }
        call.message = vec![TAG_DYNAMIC];
        call.message.extend(message.encode());
        let InvocationAuthorization::AuthorityReceipt(mut signed_receipt) = authorization.clone()
        else {
            unreachable!()
        };
        signed_receipt.selector.request = call.commitment();
        signed_receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
            .sign(&signed_receipt.signing_bytes())
            .to_bytes();
        (
            call,
            InvocationAuthorization::AuthorityReceipt(signed_receipt),
        )
    };
    use cipher_clerk::helpers::{MemLedger, MemOracle};
    use cipher_clerk::prelude::{
        Account, CreateAccount, EventStatus, Keypair, Layer, LedgerState, Transfer,
    };
    let mut reference = MemLedger::new();
    let mut reference_oracle = MemOracle::new();
    let registrar = Keypair::generate();
    let journal_id = reference.bootstrap_journal(registrar.public, 1);
    let alice_key = Keypair::generate();
    let bob_key = Keypair::generate();
    let alice = Account::asset(journal_id, alice_key.public, 840, 100);
    let bob = Account::liability(journal_id, bob_key.public, 840, 200);
    let creates = [
        CreateAccount::signed(alice.clone(), &registrar.secret),
        CreateAccount::signed(bob.clone(), &registrar.secret),
    ];
    let mut setup = vec![(
        "bootstrap",
        vec![
            ("journal_id", Value::Bytes(journal_id.0.to_vec())),
            (
                "registrar_pubkey",
                Value::Bytes(registrar.public.0.to_vec()),
            ),
            ("code", Value::U32(1)),
        ],
        0xe6,
    )];
    for (index, create) in creates.iter().enumerate() {
        let timestamp = 500_000 + index as u64;
        let expected = cipher_clerk::apply_account_creations(
            &mut reference,
            core::slice::from_ref(create),
            &mut reference_oracle,
            timestamp,
        );
        assert_eq!(expected[0].status, EventStatus::Created);
        setup.push((
            "create_account",
            vec![
                (
                    "create_account_bytes",
                    Value::Bytes(
                        crate::rkyv::to_bytes::<crate::rkyv::rancor::Error>(create)
                            .unwrap()
                            .to_vec(),
                    ),
                ),
                ("batch_seed_timestamp", Value::U64(timestamp)),
            ],
            0xe7 + index as u8,
        ));
    }
    for (method, args, invocation) in setup {
        let (call, authorization) =
            clerk_call(method, args, MethodMode::Linear, operator, invocation);
        let started = std::time::Instant::now();
        let outcome = external_network_on_leader(&attached, agent, |owner| {
            owner.supervisor_invoke(identity, call.clone(), authorization.clone())
        });
        let RuntimeOutcome::Completed(Ok(reply)) = &outcome else {
            panic!("external network Clerk {method}: {outcome:?}")
        };
        assert_eq!(
            Value::decode(&reply.reply),
            Value::Bytes(vec![0]),
            "Clerk {method} must return Status::Ok"
        );
        assert!(matches!(
            external_network_on_leader(&attached, agent, |owner| {
                owner.supervisor_acknowledge(identity, call.clone(), authorization.clone())
            }),
            RuntimeOutcome::Acknowledged(Ok(_))
        ));
        eprintln!(
            "clerk_shared_network_call method={method} invoke_ack_elapsed_us={}",
            started.elapsed().as_micros()
        );
    }
    let amount = reference_oracle.commit(17);
    let transfer = Transfer::builder(journal_id)
        .debit(&alice, Layer::Settled, amount)
        .credit(&bob, Layer::Settled, amount)
        .signed_with(&[(&alice, &alice_key.secret)]);
    let (value, blinding) = reference_oracle.openings.get(&amount.0).copied().unwrap();
    let openings = vec![cipher_clerk::state::Opening {
        amount,
        value,
        blinding,
    }];
    let expected_transfer = cipher_clerk::apply_batch(
        &mut reference,
        core::slice::from_ref(&transfer),
        &mut reference_oracle,
        1_000_000,
    );
    assert_eq!(expected_transfer[0].status, EventStatus::Created);
    // The existing lost-response/reopen lifecycle now protects a mutation:
    // retrying this exact signed debit must recover its one committed result.
    let (work, authorization) = clerk_call(
        "apply_transfer",
        vec![
            (
                "transfer_bytes",
                Value::Bytes(
                    crate::rkyv::to_bytes::<crate::rkyv::rancor::Error>(&transfer)
                        .unwrap()
                        .to_vec(),
                ),
            ),
            (
                "openings_bytes",
                Value::Bytes(
                    crate::rkyv::to_bytes::<crate::rkyv::rancor::Error>(&openings)
                        .unwrap()
                        .to_vec(),
                ),
            ),
            ("batch_seed_timestamp", Value::U64(1_000_000)),
        ],
        MethodMode::Linear,
        operator,
        0xe9,
    );
    let input = crate::agent::journal::ReplayInput {
        runtime: provision.proposal().create().runtime.clone(),
        operation: ReplayOperation::CleanInvoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work: work.clone(),
            authorization: authorization.clone(),
            observed_slot: material.observed_slot,
        },
    }
    .id();
    let ack_input = crate::agent::journal::ReplayInput {
        runtime: provision.proposal().create().runtime.clone(),
        operation: ReplayOperation::CleanAcknowledge {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            expected_live: None,
            work: crate::agent_sdk::InvocationRetirement::from_work(&work),
            authorization: authorization.clone(),
        },
    }
    .id();
    let before = hosts[0].lock().unwrap().journal_position(agent).unwrap();
    let invoke_started = std::time::Instant::now();
    let result = external_network_on_leader(&attached, agent, |owner| {
        owner.supervisor_invoke(identity, work.clone(), authorization.clone())
    });
    eprintln!(
        "clerk_shared_network_call method=apply_transfer invoke_elapsed_us={}",
        invoke_started.elapsed().as_micros()
    );
    let RuntimeOutcome::Completed(Ok(reply)) = &result else {
        panic!("external network Invoke: {result:?}")
    };
    assert_eq!(
        Value::decode(&reply.reply),
        Value::Bytes(vec![0]),
        "the debit-signed settled transfer must return Clerk Status::Ok"
    );
    let mut expected = None;
    assert!(
        wait_until(std::time::Duration::from_secs(15), || {
            let Some(states) = hosts
                .iter()
                .map(|host| {
                    let mut host = host.lock().unwrap();
                    let claim = host.available_ordered_claim(agent, input).ok()?;
                    Some((host.journal_position(agent).unwrap(), claim))
                })
                .collect::<Option<Vec<_>>>()
            else {
                return false;
            };
            if states.iter().all(|state| state == &states[0])
                && states[0].0.ordered_index > before.ordered_index
            {
                expected = Some(states[0].clone());
                true
            } else {
                false
            }
        }),
        "external Invoke did not converge on all three independently published roots"
    );
    let expected = expected.unwrap();
    drop(attached);
    drop(hosts);
    for index in 0..keys.len() {
        assert!(
            matches!(
                open(index, false),
                Err(SharedAgentHostError::InvalidProvision)
            ),
            "public image owner must not infer an external executor from persisted files"
        );
    }
    hosts = (0..keys.len())
        .map(|index| {
            let mut host = open(index, true).unwrap();
            assert!(host.uses_external_state(agent).unwrap());
            assert_eq!(
                (
                    host.journal_position(agent).unwrap(),
                    host.available_ordered_claim(agent, input).unwrap()
                ),
                expected
            );
            Arc::new(std::sync::Mutex::new(host))
        })
        .collect();
    attached = attach(&hosts);
    assert_eq!(
        external_network_on_leader(&attached, agent, |owner| {
            owner.supervisor_invoke(identity, work.clone(), authorization.clone())
        }),
        result,
        "lost response retry must recover the exact physical result"
    );
    for host in &hosts {
        assert_eq!(
            host.lock().unwrap().journal_position(agent).unwrap(),
            expected.0,
            "retained retry must not append another Ordered invocation"
        );
    }
    assert!(matches!(
        external_network_on_leader(&attached, agent, |owner| {
            owner.supervisor_acknowledge(identity, work.clone(), authorization.clone())
        }),
        RuntimeOutcome::Acknowledged(Ok(_))
    ));
    assert!(wait_until(std::time::Duration::from_secs(15), || hosts
        .iter()
        .all(|host| {
            host.lock()
                .unwrap()
                .retained_positive_clean_acknowledgement(agent, &work, &authorization)
                .unwrap()
        })));
    let (root_work, root_authorization) = clerk_call(
        "state_root",
        Vec::new(),
        MethodMode::LinearizableQuery,
        member,
        0xea,
    );
    let root_started = std::time::Instant::now();
    let root_outcome = external_network_on_leader(&attached, agent, |owner| {
        owner.supervisor_invoke(identity, root_work.clone(), root_authorization.clone())
    });
    eprintln!(
        "clerk_shared_network_call method=state_root phase=post_reopen invoke_elapsed_us={}",
        root_started.elapsed().as_micros()
    );
    let RuntimeOutcome::Completed(Ok(root_reply)) = &root_outcome else {
        panic!("external network Clerk state_root: {root_outcome:?}")
    };
    assert_eq!(
        Value::decode(&root_reply.reply),
        Value::Bytes(reference.root().to_vec()),
        "Shared Clerk must preserve the signed transfer's reference kernel root"
    );
    let root_input = crate::agent::journal::ReplayInput {
        runtime: provision.proposal().create().runtime.clone(),
        operation: ReplayOperation::CleanInvoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work: root_work.clone(),
            authorization: root_authorization.clone(),
            observed_slot: material.observed_slot,
        },
    }
    .id();
    let root_ack_input = crate::agent::journal::ReplayInput {
        runtime: provision.proposal().create().runtime.clone(),
        operation: ReplayOperation::CleanAcknowledge {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            expected_live: None,
            work: crate::agent_sdk::InvocationRetirement::from_work(&root_work),
            authorization: root_authorization.clone(),
        },
    }
    .id();
    assert!(matches!(
        external_network_on_leader(&attached, agent, |owner| {
            owner.supervisor_acknowledge(identity, root_work.clone(), root_authorization.clone())
        }),
        RuntimeOutcome::Acknowledged(Ok(_))
    ));
    let mut completed = None;
    assert!(
        wait_until(std::time::Duration::from_secs(15), || {
            let Some(states) = hosts
                .iter()
                .map(|host| {
                    let mut host = host.lock().unwrap();
                    if !host
                        .retained_positive_clean_acknowledgement(
                            agent,
                            &root_work,
                            &root_authorization,
                        )
                        .ok()?
                    {
                        return None;
                    }
                    Some((
                        host.journal_position(agent).ok()?,
                        host.available_ordered_claim(agent, ack_input).ok()?,
                        host.available_ordered_claim(agent, root_input).ok()?,
                        host.available_ordered_claim(agent, root_ack_input).ok()?,
                    ))
                })
                .collect::<Option<Vec<_>>>()
            else {
                return false;
            };
            if states.iter().all(|state| state == &states[0]) {
                completed = Some(states[0].clone());
                true
            } else {
                false
            }
        }),
        "transfer/root Invoke and ACK claims must converge on all three replicas"
    );
    let completed = completed.unwrap();
    drop(attached);
    drop(hosts);
    for index in 0..keys.len() {
        let mut host = open(index, true).unwrap();
        assert!(host.uses_external_state(agent).unwrap());
        assert!(
            host.retained_positive_clean_acknowledgement(agent, &work, &authorization)
                .unwrap()
        );
        assert!(
            host.retained_positive_clean_acknowledgement(agent, &root_work, &root_authorization,)
                .unwrap()
        );
        let acknowledged = host.available_ordered_claim(agent, ack_input).unwrap();
        assert_eq!(
            (
                host.journal_position(agent).unwrap(),
                acknowledged.clone(),
                host.available_ordered_claim(agent, root_input).unwrap(),
                host.available_ordered_claim(agent, root_ack_input).unwrap(),
            ),
            completed,
            "reopen must preserve the complete claims binding the public Clerk root"
        );
        assert!(acknowledged.ordered().index > expected.1.ordered().index);
        assert_ne!(
            acknowledged.linear().manifest(),
            expected.1.linear().manifest()
        );
    }
    for network in networks.into_iter().skip(1) {
        stop_network(network);
    }
}

fn external_network_on_leader(
    attached: &[crate::network::SharedAgentNetworkHost],
    agent: HostAgentId,
    mut operation: impl FnMut(
        &crate::network::SharedAgentNetworkHost,
    ) -> Result<RuntimeOutcome, SharedAgentHostError>,
) -> RuntimeOutcome {
    let mut result = None;
    assert!(
        wait_until(std::time::Duration::from_secs(30), || {
            let Some(owner) = attached
                .iter()
                .find(|owner| owner.bootstrap_is_local_leader(agent).unwrap_or(false))
            else {
                return false;
            };
            match operation(owner) {
                Ok(outcome) => {
                    result = Some(outcome);
                    true
                }
                Err(SharedAgentHostError::Unavailable) => false,
                Err(error) => panic!("external network lifecycle admission: {error:?}"),
            }
        }),
        "external network lifecycle did not complete through its current leader"
    );
    result.unwrap()
}
