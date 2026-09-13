use super::tests::{Fixture, stage, write_private};
use super::*;
use vos::Encode as _;
use vos::agent::sdk::{authority::*, authority_operation::*, wire::CanonicalWire as _, *};

// Signed protocol fixture with a synthetic, structurally valid journal anchor.
// This tests file binding, not native execution or admission of that anchor.
fn record(sequence: u64, native_gas: u64) -> (AuthorityActorTarget, InvocationId, Vec<u8>) {
    let (operator, authority, descriptor, _) = super::super::local_create::tests::fixture();
    let public = operator.public().try_into_ed25519().unwrap().to_bytes();
    let origin = InvocationOrigin {
        principal: Some(descriptor.identity.owner),
        credential: Some(CredentialId::of_public_key(&public)),
        transport_node: None,
        actor: None,
        capability: None,
    };
    let mut work = InvocationWork {
        space: authority.space,
        agent: descriptor.identity.agent,
        runtime_deployment: descriptor.identity.runtime_deployment,
        invocation: InvocationId([0x61; 32]),
        actor: ActorId([0x62; 32]),
        incarnation: Hash([0x63; 32]),
        deployment: DeploymentId([0x64; 32]),
        program: ProgramId([0x65; 32]),
        mode: MethodMode::Linear,
        origin,
        roles: InvocationRoleClaims::none(),
        message: vec![1],
        installation_data: None,
        availability: Vec::new(),
        gas: 100,
        recovery_only: false,
    };
    let managed = ManagedAgentTarget {
        space: work.space,
        agent: work.agent,
        owner: descriptor.identity.owner,
        profile: descriptor.identity.profile,
        runtime_deployment: work.runtime_deployment,
        transition_producer: descriptor.identity.transition_producer,
    };
    let mut call = AuthorityOperationCall {
        invocation: InvocationId::ZERO,
        authority,
        principal: descriptor.identity.owner,
        credential: origin.credential.unwrap(),
        request_sequence: core::num::NonZeroU64::new(sequence).unwrap(),
        authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key: public,
            signature: [1; 64],
        },
        requested_valid_from: 10,
        requested_expires_at: 100,
        intent: AuthorityOperationIntent::invoke(managed, &work).unwrap(),
    };
    call.invocation = call.expected_invocation();
    let signature = operator
        .sign(&call.signing_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    call.authentication = AuthorityIngressAuthentication::ApiCredentialSignature {
        credential_public_key: public,
        signature,
    };
    let call_bytes = call.encode().unwrap();
    work.agent = authority.system_agent;
    work.runtime_deployment = authority.system_runtime_deployment;
    work.invocation = call.invocation;
    work.actor = authority.binding.issuer.actor;
    work.deployment = authority.binding.issuer.deployment;
    work.program = authority.binding.issuer.program;
    work.gas = native_gas;
    work.message = vec![vos::value::TAG_DYNAMIC];
    work.message.extend(
        vos::value::Msg::new("authorize_operation")
            .with("call", call_bytes.clone())
            .encode(),
    );
    let authorization =
        InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 20));
    let envelope = RuntimeWork::Invoke {
        context: RuntimeExecutionContext::Direct,
        state: RuntimeState::default(),
        invocation: Box::new(work),
        authorization: Box::new(authorization),
        observed_slot: 20,
    };
    let mut anchor = b"MJA1".to_vec();
    anchor.extend_from_slice(&vos::service::PLATFORM_ID.0);
    for byte in [1, 2, 3] {
        anchor.extend_from_slice(&[byte; 32]);
    }
    anchor.extend_from_slice(&0u64.to_le_bytes());
    anchor.push(0); // empty ordered prefix
    let mut bytes = b"NOD1".to_vec();
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    bytes.push(0);
    for field in [call_bytes, envelope.encode().unwrap(), anchor] {
        bytes.extend_from_slice(&(field.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&field);
    }
    assert!(native_operation_record_matches(
        authority,
        call.invocation,
        &bytes
    ));
    (authority, call.invocation, bytes)
}

#[test]
fn operation_journal_is_immutable_scoped_and_exclusively_leased() {
    let fixture = Fixture::new("operation-journal");
    let (authority, invocation, bytes) = record(1, 100);
    let mut journal =
        CleanNativeAuthorityOperationJournal::open_or_create(&fixture.root, authority).unwrap();
    assert_eq!(journal.load(invocation).unwrap(), None);
    assert!(journal.discover(0).unwrap().is_empty());
    assert!(!fixture.root.join(hex::encode(invocation.0)).exists());
    journal.retain(invocation, &bytes).unwrap();
    let saved = fs::read(fixture.root.join(hex::encode(invocation.0))).unwrap();
    journal.retain(invocation, &bytes).unwrap();
    let (_, same_invocation, different) = record(1, 101);
    assert_eq!(same_invocation, invocation);
    assert!(matches!(
        journal.retain(invocation, &different),
        Err(CleanFileStoreError::RequestConflict)
    ));
    assert!(matches!(
        CleanNativeAuthorityOperationJournal::open_existing(&fixture.root, authority),
        Err(CleanFileStoreError::Busy)
    ));
    assert_eq!(
        fs::read(fixture.root.join(hex::encode(invocation.0))).unwrap(),
        saved
    );
    drop(journal);
    let mut journal =
        CleanNativeAuthorityOperationJournal::open_existing(&fixture.root, authority).unwrap();
    assert_eq!(journal.discover(1).unwrap(), vec![invocation]);
    assert!(matches!(
        journal.discover(0),
        Err(CleanFileStoreError::Oversized)
    ));
    assert_eq!(journal.load(invocation).unwrap(), Some(bytes));
    assert!(journal.load(InvocationId::ZERO).is_err());
    drop(journal);
    assert!(CleanSystemAgentFileStores::open_or_create(&fixture.root).is_err());
    let missing = fixture.parent.join("missing-journal");
    assert!(CleanNativeAuthorityOperationJournal::open_existing(&missing, authority).is_err());
    assert!(!missing.exists());
}

#[test]
fn operation_journal_discovers_and_recovers_initial_staging() {
    let fixture = Fixture::new("operation-journal-stage");
    let (authority, invocation, bytes) = record(1, 100);
    let journal =
        CleanNativeAuthorityOperationJournal::open_or_create(&fixture.root, authority).unwrap();
    let file = ExactFileStore::operation_record(Arc::clone(&journal.root), invocation).unwrap();
    stage(&file, None, &bytes);
    assert_eq!(journal.discover(1).unwrap(), vec![invocation]);
    drop((file, journal));
    let mut journal =
        CleanNativeAuthorityOperationJournal::open_existing(&fixture.root, authority).unwrap();
    assert_eq!(journal.load(invocation).unwrap(), Some(bytes));
    assert!(
        !fixture
            .root
            .join(format!("{}.next", hex::encode(invocation.0)))
            .exists()
    );
}

#[test]
fn operation_journal_rejects_key_and_authority_substitution_before_publication() {
    let fixture = Fixture::new("operation-journal-substitution");
    let (authority, invocation, bytes) = record(1, 100);
    let other = InvocationId([0x91; 32]);
    let mut journal =
        CleanNativeAuthorityOperationJournal::open_or_create(&fixture.root, authority).unwrap();
    assert!(journal.retain(other, &bytes).is_err());
    let file = ExactFileStore::operation_record(Arc::clone(&journal.root), other).unwrap();
    stage(&file, None, &bytes);
    let staged = fs::read(fixture.root.join(file.stage_file())).unwrap();
    assert!(journal.load(other).is_err());
    assert!(!fixture.root.join(file.file()).exists());
    assert_eq!(
        fs::read(fixture.root.join(file.stage_file())).unwrap(),
        staged
    );
    drop(file);
    journal.retain(invocation, &bytes).unwrap();
    drop(journal);
    let fixture = Fixture::new("operation-journal-authority");
    let mut journal =
        CleanNativeAuthorityOperationJournal::open_or_create(&fixture.root, authority).unwrap();
    journal.retain(invocation, &bytes).unwrap();
    drop(journal);
    let mut wrong_authority = authority;
    wrong_authority.binding.policy = Hash([0x92; 32]);
    assert!(
        CleanNativeAuthorityOperationJournal::open_existing(&fixture.root, wrong_authority)
            .is_err()
    );
    assert!(fixture.root.join(hex::encode(invocation.0)).exists());
}

#[test]
fn operation_journal_preserves_staged_replacement_and_cross_role_evidence() {
    let (authority, invocation, bytes) = record(1, 100);
    for cross_role in [false, true] {
        let fixture = Fixture::new("operation-journal-evidence");
        let mut journal =
            CleanNativeAuthorityOperationJournal::open_or_create(&fixture.root, authority).unwrap();
        journal.retain(invocation, &bytes).unwrap();
        let file = ExactFileStore::operation_record(Arc::clone(&journal.root), invocation).unwrap();
        let canonical = fs::read(fixture.root.join(file.file())).unwrap();
        let encoded = encode_envelope(
            if cross_role {
                StoreRole::OperationIssuer
            } else {
                StoreRole::OperationDispatch
            },
            if cross_role { None } else { Some([7; 32]) },
            &bytes,
        )
        .unwrap();
        write_private(&fixture.root.join(file.stage_file()), &encoded);
        assert!(journal.load(invocation).is_err());
        assert_eq!(fs::read(fixture.root.join(file.file())).unwrap(), canonical);
        assert_eq!(
            fs::read(fixture.root.join(file.stage_file())).unwrap(),
            encoded
        );
    }
}

#[test]
fn operation_journal_refuses_unknown_names_aliases_and_lost_locks() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let (authority, invocation, _) = record(1, 100);
    for name in [
        "unexpected",
        &"A".repeat(64),
        &"0".repeat(64),
        &format!("{}.next.next", "1".repeat(64)),
    ] {
        let fixture = Fixture::new("operation-journal-name");
        drop(
            CleanNativeAuthorityOperationJournal::open_or_create(&fixture.root, authority).unwrap(),
        );
        write_private(&fixture.root.join(name), b"preserve");
        assert!(
            CleanNativeAuthorityOperationJournal::open_existing(&fixture.root, authority).is_err()
        );
        assert_eq!(fs::read(fixture.root.join(name)).unwrap(), b"preserve");
    }
    let fixture = Fixture::new("operation-journal-alias");
    let mut journal =
        CleanNativeAuthorityOperationJournal::open_or_create(&fixture.root, authority).unwrap();
    let target = fixture.parent.join("outside");
    write_private(&target, b"preserve");
    symlink(&target, fixture.root.join(hex::encode(invocation.0))).unwrap();
    assert!(journal.load(invocation).is_err());
    assert_eq!(fs::read(target).unwrap(), b"preserve");
    drop(journal);
    let fixture = Fixture::new("operation-journal-lock");
    let mut journal =
        CleanNativeAuthorityOperationJournal::open_or_create(&fixture.root, authority).unwrap();
    fs::rename(
        fixture.root.join(LOCK_FILE),
        fixture.parent.join("old-lock"),
    )
    .unwrap();
    write_private(&fixture.root.join(LOCK_FILE), b"");
    assert!(journal.load(invocation).is_err());
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(journal.discover(1).is_err());
}

#[test]
fn operation_journal_enforces_record_and_directory_limits_without_eviction() {
    use std::os::unix::fs::OpenOptionsExt as _;
    let (authority, invocation, bytes) = record(1, 100);
    let fixture = Fixture::new("operation-journal-byte-bound");
    let mut journal =
        CleanNativeAuthorityOperationJournal::open_or_create(&fixture.root, authority).unwrap();
    let path = fixture.root.join(hex::encode(invocation.0));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    let oversized = (MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES + STORE_HEADER_BYTES + 1) as u64;
    file.set_len(oversized).unwrap(); // sparse: exercise the pre-allocation bound
    file.sync_all().unwrap();
    assert!(matches!(
        journal.load(invocation),
        Err(CleanFileStoreError::Oversized)
    ));
    assert_eq!(fs::metadata(path).unwrap().len(), oversized);
    drop((file, journal));
    assert!(CleanNativeAuthorityOperationJournal::open_existing(&fixture.root, authority).is_err());

    let fixture = Fixture::new("operation-journal-count-bound");
    let mut journal =
        CleanNativeAuthorityOperationJournal::open_or_create(&fixture.root, authority).unwrap();
    // Discovery is bounded independently of semantic decoding. These empty
    // files must count against admission, never become trusted NOD1 evidence.
    for index in 0..MAX_OPERATION_JOURNAL_RECORDS {
        let mut id = [0x33; 32];
        id[24..].copy_from_slice(&(index as u64).to_le_bytes());
        assert_ne!(id, invocation.0);
        write_private(&fixture.root.join(hex::encode(id)), b"");
    }
    assert_eq!(
        journal
            .discover(MAX_OPERATION_JOURNAL_RECORDS)
            .unwrap()
            .len(),
        MAX_OPERATION_JOURNAL_RECORDS
    );
    assert!(matches!(
        journal.retain(invocation, &bytes),
        Err(CleanFileStoreError::Oversized)
    ));
    assert!(!fixture.root.join(hex::encode(invocation.0)).exists());
    assert_eq!(
        journal
            .discover(MAX_OPERATION_JOURNAL_RECORDS)
            .unwrap()
            .len(),
        MAX_OPERATION_JOURNAL_RECORDS
    );
}

#[test]
fn operation_journal_rejects_hardlink_aliases_and_directory_replacement() {
    use std::os::unix::fs::DirBuilderExt as _;
    let (authority, invocation, bytes) = record(1, 100);
    let fixture = Fixture::new("operation-journal-hardlink");
    let mut journal =
        CleanNativeAuthorityOperationJournal::open_or_create(&fixture.root, authority).unwrap();
    journal.retain(invocation, &bytes).unwrap();
    fs::hard_link(
        fixture.root.join(hex::encode(invocation.0)),
        fixture.parent.join("alias"),
    )
    .unwrap();
    assert!(journal.load(invocation).is_err());
    drop(journal);
    assert!(CleanNativeAuthorityOperationJournal::open_existing(&fixture.root, authority).is_err());
    let fixture = Fixture::new("operation-journal-root-replacement");
    let mut journal =
        CleanNativeAuthorityOperationJournal::open_or_create(&fixture.root, authority).unwrap();
    journal.retain(invocation, &bytes).unwrap();
    let retained = fixture.parent.join("retained-root");
    fs::rename(&fixture.root, &retained).unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&fixture.root)
        .unwrap();
    assert!(journal.load(invocation).is_err());
    assert!(journal.retain(invocation, &bytes).is_err());
    assert!(retained.join(hex::encode(invocation.0)).is_file());
    assert!(fs::read_dir(&fixture.root).unwrap().next().is_none());
}
