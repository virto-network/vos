use super::super::tests::{Fixture, stage, write_private};
use super::*;
use vos::Encode as _;
use vos::agent::sdk::{authority::*, wire::CanonicalWire, *};

// Synthetic signed storage evidence; native finality is covered in vos tests.
fn client_evidence(denied: bool) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    use vos::agent::clean_bootstrap::{
        NativeAuthorityAdminPreparation, NativeAuthorityAdminSubmission,
    };
    let (_, _, dispatch, observed, terminal) = evidence(100, denied);
    fn field<'a>(bytes: &mut &'a [u8]) -> &'a [u8] {
        let length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        let (value, rest) = bytes[4..].split_at(length);
        *bytes = rest;
        value
    }
    let mut fields = &dispatch[4 + RUNTIME_ABI_ID.as_bytes().len()..];
    let call = AuthorityAdminCall::decode(field(&mut fields)).unwrap();
    field(&mut fields);
    field(&mut fields);
    let prepared = field(&mut fields).to_vec();
    assert!(fields.is_empty());
    let preparation = NativeAuthorityAdminPreparation::decode(&prepared).unwrap();
    let submission = NativeAuthorityAdminSubmission::new(call.clone(), preparation)
        .unwrap()
        .encode()
        .unwrap();
    let (key, _, _, _) = crate::commands::space::local_create::tests::fixture();
    let mut draft = call;
    draft.observed_slot = 0;
    draft.invocation = draft.expected_invocation();
    draft.signature = key
        .sign(&draft.signing_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    (
        draft.encode().unwrap(),
        prepared,
        submission,
        observed,
        terminal,
    )
}

#[test]
fn admin_client_pairs_are_bound_immutable_and_recoverable() {
    let (draft, preparation, submission, observed, terminal) = client_evidence(false);
    for (prepare, request, response, request_role, response_role) in [
        (
            true,
            draft,
            preparation,
            StoreRole::AdminPreparationRequest,
            StoreRole::AdminPreparationResponse,
        ),
        (
            false,
            submission,
            terminal,
            StoreRole::AdminClientRequest,
            StoreRole::AdminClientResponse,
        ),
    ] {
        let fixture = Fixture::new("admin-client-pair");
        let open = |path: &Path| {
            if prepare {
                CleanOperationClientFile::open_admin_preparation(path)
            } else {
                CleanOperationClientFile::open_admin_submission(path)
            }
        };
        let mut store = open(&fixture.root).unwrap();
        assert!(open(&fixture.root).is_err());
        assert!(store.publish_response(&response).is_err());
        drop(store);
        write_private(
            &fixture.root.join(request_role.stage_file()),
            &encode_envelope(request_role, None, &request).unwrap(),
        );
        let mut store = open(&fixture.root).unwrap();
        assert_eq!(store.load_request().unwrap(), Some(request.clone()));
        if !prepare {
            assert!(store.publish_response(&observed).is_err());
        }
        let mut corrupt = response.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(store.publish_response(&corrupt).is_err());
        store.publish_response(&response).unwrap();
        store.publish_request(&request).unwrap();
        drop(store);
        let mut store = open(&fixture.root).unwrap();
        assert_eq!(store.load_response().unwrap(), Some(response.clone()));
        drop(store);
        // A validly enveloped replacement stage is still forbidden.
        let current = fs::read(fixture.root.join(response_role.file())).unwrap();
        let image =
            decode_envelope(response_role, &current, response_role.maximum_bytes()).unwrap();
        write_private(
            &fixture.root.join(response_role.stage_file()),
            &encode_envelope(response_role, Some(image.commitment()), &response).unwrap(),
        );
        let mut store = open(&fixture.root).unwrap();
        assert!(store.load_response().is_err());
        assert_eq!(
            fs::read(fixture.root.join(response_role.file())).unwrap(),
            current
        );
        drop(store);
        let orphan = Fixture::new("admin-client-orphan");
        drop(open(&orphan.root).unwrap());
        write_private(
            &orphan.root.join(response_role.stage_file()),
            &encode_envelope(response_role, None, &response).unwrap(),
        );
        let mut store = open(&orphan.root).unwrap();
        assert!(store.load_response().is_err());
        assert!(store.publish_request(&request).is_err());
        assert!(!orphan.root.join(request_role.file()).exists());
    }
}

#[test]
fn admin_client_http_retains_exact_requests_and_verified_responses() {
    use crate::commands::space::admin_client::deliver;
    use std::io::{Read as _, Write as _};
    let (draft, preparation, submission, _, terminal) = client_evidence(true);
    let (_, _, successful_submission, _, successful_terminal) = client_evidence(false);
    for (prepare, request, response, status) in [
        (true, draft, preparation, 200),
        (false, submission, terminal, 403),
        (false, successful_submission, successful_terminal, 200),
    ] {
        let fixture = Fixture::new("admin-client-http");
        let input = fixture.parent.join("input");
        write_private(&input, &request);
        for attempt in 0..4 {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let expected = request.clone();
            let mut body = response.clone();
            if attempt == 1 {
                *body.last_mut().unwrap() ^= 1;
            }
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    headers.push(byte[0]);
                    assert!(headers.len() < 8192);
                }
                let path = if prepare {
                    "/__agents/admin/prepare"
                } else {
                    "/__agents/admin"
                };
                assert!(
                    String::from_utf8(headers)
                        .unwrap()
                        .starts_with(&format!("POST {path} HTTP/1.1"))
                );
                let mut received = vec![0; expected.len()];
                stream.read_exact(&mut received).unwrap();
                assert_eq!(received, expected);
                let status = if attempt == 0 {
                    503
                } else if attempt == 2 {
                    if status == 200 { 403 } else { 200 }
                } else {
                    status
                };
                write!(stream, "HTTP/1.1 {status} Result\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(&body).unwrap();
            });
            let result = deliver(&fixture.root, Some(&input), address, prepare);
            server.join().unwrap();
            if attempt < 3 {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), response);
            }
        }
        // Reopen from durable evidence without a listener or usable input.
        assert_eq!(
            deliver(
                &fixture.root,
                Some(&fixture.parent.join("absent")),
                "127.0.0.1:1".parse().unwrap(),
                prepare
            )
            .unwrap(),
            response
        );
        assert!(
            deliver(
                &fixture.root,
                None,
                "192.0.2.1:80".parse().unwrap(),
                prepare
            )
            .is_err()
        );
    }
}

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
    let preparation_commitment = Hash::digest(
        b"vos/agent/native-admin-preparation-commitment/v1",
        &[&preparation],
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
        let mut signed = b"vos/agent/native-admin-terminal/v2".to_vec();
        signed.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        signed.extend_from_slice(&call.invocation.0);
        signed.extend_from_slice(&record.0);
        signed.extend_from_slice(&preparation_commitment.0);
        signed.push(u8::from(retired));
        signed.extend_from_slice(&Hash::digest(b"vos/agent/native-admin-result/v1", &[&result]).0);
        let mut bytes = b"NAT2".to_vec();
        bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        bytes.extend_from_slice(&call.invocation.0);
        bytes.extend_from_slice(&record.0);
        bytes.extend_from_slice(&preparation_commitment.0);
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
