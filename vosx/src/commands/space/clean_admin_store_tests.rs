use super::super::tests::{Fixture, stage, write_private};
use super::*;
use vos::Encode as _;
use vos::agent::sdk::{authority::*, wire::CanonicalWire, *};

// Synthetic signed storage evidence; native finality is covered in vos tests.
fn evidence(
    gas: u64,
    denied: bool,
) -> (
    AuthorityActorTarget,
    InvocationId,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
) {
    let (key, authority, descriptor, _) = crate::commands::space::local_create::tests::fixture();
    let public = key.public().try_into_ed25519().unwrap().to_bytes();
    let mut call = AuthorityAdminCall {
        invocation: InvocationId::ZERO,
        authority,
        administrator: descriptor.identity.owner,
        credential: CredentialId::of_public_key(&public),
        request_sequence: core::num::NonZeroU64::new(1).unwrap(),
        credential_public_key: public,
        authenticated_node: NodeId([9; 32]),
        observed_slot: 20,
        expected_generation: core::num::NonZeroU64::new(1).unwrap(),
        operation: AuthorityAdminOperation::SetSpaceRole {
            principal: descriptor.identity.owner,
            role: RoleId([0x51; 32]),
            granted: true,
        },
        signature: [1; 64],
    };
    call.invocation = call.expected_invocation();
    call.signature = key.sign(&call.signing_bytes()).unwrap().try_into().unwrap();
    let (_, _, operation) = super::super::operation_journal_tests::record(1, gas);
    let mut cursor = 4 + RUNTIME_ABI_ID.as_bytes().len() + 1;
    fn field(bytes: &[u8], cursor: &mut usize) -> Vec<u8> {
        let len = u32::from_le_bytes(bytes[*cursor..*cursor + 4].try_into().unwrap()) as usize;
        *cursor += 4;
        let value = bytes[*cursor..*cursor + len].to_vec();
        *cursor += len;
        value
    }
    let _ = field(&operation, &mut cursor);
    let mut envelope = RuntimeWork::decode(&field(&operation, &mut cursor)).unwrap();
    let anchor = field(&operation, &mut cursor);
    let RuntimeWork::Invoke {
        invocation: work,
        authorization,
        observed_slot,
        ..
    } = &mut envelope
    else {
        unreachable!()
    };
    work.invocation = call.invocation;
    work.origin.transport_node = Some(call.authenticated_node);
    work.message = vec![vos::value::TAG_DYNAMIC];
    work.message.extend(
        vos::value::Msg::new("administer")
            .with("call", call.encode().unwrap())
            .encode(),
    );
    **authorization =
        InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(work, *observed_slot));
    let mut draft = call.clone();
    draft.observed_slot = 0;
    let intent = draft.invocation_payload_commitment();
    let mut signed_preparation = b"vos/agent/native-admin-preparation/v1".to_vec();
    signed_preparation.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    signed_preparation.extend_from_slice(&intent.0);
    signed_preparation.extend_from_slice(&call.observed_slot.to_le_bytes());
    signed_preparation.extend_from_slice(&work.incarnation.0);
    let mut preparation = b"NAP1".to_vec();
    preparation.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    preparation.extend_from_slice(&intent.0);
    preparation.extend_from_slice(&call.observed_slot.to_le_bytes());
    preparation.extend_from_slice(&work.incarnation.0);
    preparation.extend_from_slice(&64u32.to_le_bytes());
    preparation.extend(key.sign(&signed_preparation).unwrap());
    assert!(
        vos::agent::clean_bootstrap::NativeAuthorityAdminPreparation::decode(&preparation)
            .unwrap()
            .matches_call(&call)
    );
    let mut dispatch = b"NAD2".to_vec();
    dispatch.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    for bytes in [
        call.encode().unwrap(),
        envelope.encode().unwrap(),
        anchor,
        preparation,
    ] {
        dispatch.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        dispatch.extend(bytes);
    }
    assert!(native_admin_record_matches(
        authority,
        call.invocation,
        &dispatch
    ));
    let result = if denied {
        vec![]
    } else {
        AuthorityAdminResult::from_call(call.clone())
            .unwrap()
            .encode()
            .unwrap()
    };
    let record = Hash::digest(b"vos/agent/native-admin-dispatch/v1", &[&dispatch]);
    let certificate = |retired: bool| {
        let mut signed = b"vos/agent/native-admin-terminal/v1".to_vec();
        signed.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        signed.extend_from_slice(&call.invocation.0);
        signed.extend_from_slice(&record.0);
        signed.push(u8::from(retired));
        signed.extend_from_slice(&Hash::digest(b"vos/agent/native-admin-result/v1", &[&result]).0);
        let mut bytes = b"NAT1".to_vec();
        bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        bytes.extend_from_slice(&call.invocation.0);
        bytes.extend_from_slice(&record.0);
        bytes.push(u8::from(retired));
        bytes.extend_from_slice(&(result.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&result);
        bytes.extend_from_slice(&64u32.to_le_bytes());
        bytes.extend(key.sign(&signed).unwrap());
        assert!(native_admin_terminal_matches(
            authority,
            call.invocation,
            &dispatch,
            retired,
            &bytes
        ));
        bytes
    };
    let observed = certificate(false);
    let retired = certificate(true);
    (authority, call.invocation, dispatch, observed, retired)
}

#[test]
fn admin_stores_retain_bound_phases_and_all_controller_leases() {
    use vos::agent::clean_bootstrap::NativeAuthorityAdminController;
    for denied in [false, true] {
        let fixture = Fixture::new("admin-stores");
        let paths = [
            fixture.parent.join("admin-dispatch"),
            fixture.parent.join("admin-observed"),
            fixture.parent.join("admin-retired"),
        ];
        let (authority, id, dispatch, observed, retired) = evidence(100, denied);
        let open = |create| {
            CleanNativeAuthorityAdminStores::open(
                &paths[0], &paths[1], &paths[2], authority, create,
            )
        };
        let mut stores = open(true).unwrap();
        assert!(stores.terminals.retain(id, false, &observed).is_err());
        stores.journal.retain(id, &dispatch).unwrap();
        for _ in 0..2 {
            stores.terminals.retain(id, false, &observed).unwrap();
            stores.terminals.retain(id, true, &retired).unwrap();
        }
        assert!(stores.terminals.retain(id, true, &observed).is_err());
        assert!(
            stores
                .terminals
                .retain(InvocationId([0xf1; 32]), false, &observed)
                .is_err()
        );
        assert_eq!(stores.journal.discover().unwrap(), vec![id]);
        let mut controller =
            NativeAuthorityAdminController::new(authority, stores.journal, stores.terminals);
        let mut operations =
            CleanNativeAuthorityOperationJournal::open_or_create(&fixture.root, authority).unwrap();
        assert!(
            controller
                .startup_admission(
                    operations.startup_admission().unwrap(),
                    &[InvocationId([0xf1; 32])]
                )
                .is_err()
        );
        assert!(matches!(open(false), Err(CleanFileStoreError::Busy)));
        for (path, role) in [
            (&paths[1], StoreRole::AdminResult),
            (&paths[2], StoreRole::AdminRetirement),
        ] {
            assert!(matches!(
                Records::open(path, authority, role, None, false),
                Err(CleanFileStoreError::Busy)
            ));
        }
        drop(
            controller
                .startup_admission(operations.startup_admission().unwrap(), &[id])
                .unwrap(),
        );
        drop(controller);
        let mut reopened = open(false).unwrap();
        assert_eq!(reopened.journal.load(id).unwrap(), Some(dispatch));
        assert_eq!(reopened.terminals.load(id, false).unwrap(), Some(observed));
        assert_eq!(reopened.terminals.load(id, true).unwrap(), Some(retired));
    }
}

#[test]
fn admin_stores_recover_stages_and_reject_changed_sources_and_roles() {
    let fixture = Fixture::new("admin-stages");
    let paths = [
        fixture.parent.join("dispatch"),
        fixture.parent.join("observed"),
        fixture.parent.join("retired"),
    ];
    let (authority, id, dispatch, observed, _) = evidence(100, false);
    let mut stores =
        CleanNativeAuthorityAdminStores::open(&paths[0], &paths[1], &paths[2], authority, true)
            .unwrap();
    stage(&stores.journal.0.file(id).unwrap(), None, &dispatch);
    assert_eq!(stores.journal.discover().unwrap(), vec![id]);
    assert_eq!(stores.journal.load(id).unwrap(), Some(dispatch.clone()));
    stage(
        &stores.terminals.observed.file(id).unwrap(),
        None,
        &observed,
    );
    assert_eq!(
        stores.terminals.load(id, false).unwrap(),
        Some(observed.clone())
    );
    let (_, same_id, changed, changed_result, _) = evidence(99, false);
    assert_eq!(id, same_id);
    assert!(matches!(
        stores.journal.retain(id, &changed),
        Err(CleanFileStoreError::RequestConflict)
    ));
    assert!(stores.terminals.retain(id, false, &changed_result).is_err());
    // A well-framed stage with a different native source must not be published.
    let file = stores.terminals.observed.file(id).unwrap();
    let old = file
        .read_optional(file.file(), file.role.maximum_bytes())
        .unwrap()
        .unwrap();
    stage(&file, Some(old.commitment()), &changed_result);
    let canonical = fs::read(paths[1].join(hex::encode(id.0))).unwrap();
    assert!(stores.terminals.load(id, false).is_err());
    assert_eq!(
        fs::read(paths[1].join(hex::encode(id.0))).unwrap(),
        canonical
    );
    // The result and retirement namespaces cannot exchange CSF1 envelopes.
    write_private(&paths[2].join(hex::encode(id.0)), &canonical);
    assert!(stores.terminals.load(id, true).is_err());
    // Even another fully valid dispatch for the same signed call cannot
    // replace an immutable record through a predecessor-bearing stage.
    let file = stores.journal.0.file(id).unwrap();
    let old = file
        .read_optional(file.file(), file.role.maximum_bytes())
        .unwrap()
        .unwrap();
    stage(&file, Some(old.commitment()), &changed);
    let canonical = fs::read(paths[0].join(hex::encode(id.0))).unwrap();
    assert!(matches!(
        stores.journal.load(id),
        Err(CleanFileStoreError::RequestConflict)
    ));
    assert_eq!(
        fs::read(paths[0].join(hex::encode(id.0))).unwrap(),
        canonical
    );
}

#[test]
fn admin_stores_reject_symlinks_wrong_scope_and_missing_existing_roots() {
    let fixture = Fixture::new("admin-paths");
    let paths = [
        fixture.parent.join("dispatch"),
        fixture.parent.join("observed"),
        fixture.parent.join("retired"),
    ];
    let (authority, id, dispatch, _, _) = evidence(100, false);
    assert!(
        CleanNativeAuthorityAdminStores::open(&paths[0], &paths[1], &paths[2], authority, false)
            .is_err()
    );
    assert!(!paths[0].exists());
    let mut stores =
        CleanNativeAuthorityAdminStores::open(&paths[0], &paths[1], &paths[2], authority, true)
            .unwrap();
    stores.journal.retain(id, &dispatch).unwrap();
    drop(stores);
    let mut wrong = authority;
    wrong.space.0[0] ^= 1;
    assert!(
        CleanNativeAuthorityAdminStores::open(&paths[0], &paths[1], &paths[2], wrong, false)
            .is_err()
    );
    let mut stores =
        CleanNativeAuthorityAdminStores::open(&paths[0], &paths[1], &paths[2], authority, false)
            .unwrap();
    let other = InvocationId([0xf2; 32]);
    std::os::unix::fs::symlink(
        paths[0].join(hex::encode(id.0)),
        paths[0].join(hex::encode(other.0)),
    )
    .unwrap();
    assert!(stores.journal.load(id).is_err());
    assert!(stores.journal.discover().is_err());
}
