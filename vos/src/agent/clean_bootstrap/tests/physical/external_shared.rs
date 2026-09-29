//! Real Authority publication followed by three independently locked external
//! Shared journals. Raft commands enter through the existing committed-slot
//! harness: this qualifies application/recovery, not transport or election.
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
    for driver in &mut drivers {
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
