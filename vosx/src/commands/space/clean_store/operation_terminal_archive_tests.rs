use super::super::operation_journal_tests::record;
use super::super::tests::{Fixture, stage, write_private};
use super::*;
use vos::Encode as _;
use vos::agent::clean_bootstrap::NativeAuthorityOperationJournalStore as _;
use vos::agent::sdk::{authority::*, authority_operation::*, wire::CanonicalWire as _, *};

// Signed framing/filesystem fixture only: the original NOD fixture's synthetic
// anchor does NOT establish native execution, ACK finality or a released gate.
pub(in crate::commands::space) fn pair(
    sequence: u64,
) -> (AuthorityActorTarget, [InvocationId; 2], [Vec<u8>; 3]) {
    let (key, authority, _, _) = crate::commands::space::local_create::tests::fixture();
    let (_, invocation, authorization) = record(sequence, 100);
    let mut cursor = 4 + RUNTIME_ABI_ID.as_bytes().len() + 1;
    let mut fields = Vec::new();
    for _ in 0..3 {
        let size =
            u32::from_le_bytes(authorization[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        fields.push(authorization[cursor..cursor + size].to_vec());
        cursor += size;
    }
    assert_eq!(cursor, authorization.len());
    let call = AuthorityOperationCall::decode(&fields[0]).unwrap();
    let approval = AuthorityOperationApproval::from_call(
        &call,
        core::num::NonZeroU64::new(sequence).unwrap(),
        AuthorityEvidence {
            package: None,
            proof: None,
            commitment: Hash([0x71; 32]),
        },
        AuthorityLaneRoots {
            control: Some(Hash([0x72; 32])),
            linear: Some(Hash([0x73; 32])),
            merge: None,
            local: None,
        },
        authority.binding.initial_epoch,
        10,
        100,
    )
    .unwrap();
    let mut receipt = AuthorityReceipt {
        selector: approval.selector.clone(),
        public_key: authority.binding.public_key,
        signature: [0; 64],
    };
    receipt.signature = key
        .sign(&receipt.signing_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    let mut ack = AuthorityOperationIssuanceAck {
        authorization_invocation: invocation,
        acknowledgement_invocation: approval.acknowledgement_invocation,
        authority,
        operation_call: call.commitment(),
        approval: approval.commitment(),
        authorization_sequence: approval.authorization_sequence,
        receipt,
        issued_at: 20,
        signature: [0; 64],
    };
    ack.signature = key.sign(&ack.signing_bytes()).unwrap().try_into().unwrap();
    let mut envelope = RuntimeWork::decode(&fields[1]).unwrap();
    let RuntimeWork::Invoke {
        invocation: work,
        authorization: preflight,
        ..
    } = &mut envelope
    else {
        panic!("original fixture is Invoke");
    };
    work.invocation = ack.acknowledgement_invocation;
    work.message = vec![vos::value::TAG_DYNAMIC];
    work.message.extend(
        vos::value::Msg::new("acknowledge_issuance")
            .with("ack", ack.encode().unwrap())
            .encode(),
    );
    *preflight = Box::new(InvocationAuthorization::PublicPreflight(
        PublicPreflight::for_work(work, 20),
    ));
    let mut acknowledgement = b"NOD1".to_vec();
    acknowledgement.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    acknowledgement.push(1);
    for field in [
        ack.encode().unwrap(),
        envelope.encode().unwrap(),
        fields[2].clone(),
    ] {
        acknowledgement.extend_from_slice(&(field.len() as u32).to_le_bytes());
        acknowledgement.extend_from_slice(&field);
    }
    let ids = [invocation, ack.acknowledgement_invocation];
    let mut signed_fields = ids[0].0.to_vec();
    signed_fields.extend_from_slice(&ids[1].0);
    for bytes in [&authorization, &acknowledgement] {
        signed_fields.extend_from_slice(
            &Hash::digest(b"vos/agent/native-operation-dispatch/v1", &[bytes]).0,
        );
    }
    let mut message = b"vos/agent/native-operation-completion/v1".to_vec();
    message.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    message.extend_from_slice(&signed_fields);
    let mut completion = b"NOC1".to_vec();
    completion.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    completion.extend_from_slice(&signed_fields);
    completion.extend_from_slice(&64u32.to_le_bytes());
    completion.extend_from_slice(&key.sign(&message).unwrap());
    let mut message = b"vos/agent/native-operation-retirement/v1".to_vec();
    message.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    message.extend_from_slice(
        &Hash::digest(
            b"vos/agent/native-operation-retired-completion/v1",
            &[&completion],
        )
        .0,
    );
    let mut terminal = b"NRT1".to_vec();
    terminal.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    terminal.extend_from_slice(&(completion.len() as u32).to_le_bytes());
    terminal.extend_from_slice(&completion);
    terminal.extend_from_slice(&64u32.to_le_bytes());
    terminal.extend_from_slice(&key.sign(&message).unwrap());
    assert!(native_operation_retired_pair_matches(
        authority,
        ids[0],
        &authorization,
        &acknowledgement,
        &terminal
    ));
    (authority, ids, [authorization, acknowledgement, terminal])
}

fn journal(
    fixture: &Fixture,
    authority: AuthorityActorTarget,
) -> CleanNativeAuthorityOperationJournal {
    CleanNativeAuthorityOperationJournal::open_or_create(&fixture.root, authority)
        .unwrap()
        .with_terminal_archive(&fixture.parent.join("terminal-archive"))
        .unwrap()
}

#[test]
fn operation_terminal_archive_exceeds_old_cumulative_ceiling_with_bounded_hot_discovery() {
    let fixture = Fixture::new("operation-terminal-capacity");
    let (authority, first_ids, first) = pair(1);
    let mut journal = journal(&fixture, authority);
    for sequence in 1..=257 {
        let (_, ids, bytes) = if sequence == 1 {
            (authority, first_ids, first.clone())
        } else {
            pair(sequence)
        };
        journal.retain(ids[0], &bytes[0]).unwrap();
        journal.retain(ids[1], &bytes[1]).unwrap();
        assert_eq!(journal.discover(2).unwrap().len(), 2);
        assert!(
            journal
                .retain_retired([&bytes[0], &bytes[1]], &bytes[2])
                .unwrap()
        );
        journal
            .remove_retired([&bytes[0], &bytes[1]], &bytes[2])
            .unwrap();
        assert!(journal.discover(0).unwrap().is_empty());
    }
    // An unrelated archive directory is deliberately not a namespace scan on
    // keyed old retry; only touched fixed-entry directories grant evidence.
    let unrelated = fixture.parent.join("terminal-archive").join("unrelated");
    ensure_private_directory(&unrelated).unwrap();
    write_private(&unrelated.join("not-a-record"), b"untrusted");
    assert_eq!(journal.load(first_ids[0]).unwrap(), Some(first[0].clone()));
    assert_eq!(journal.load(first_ids[1]).unwrap(), Some(first[1].clone()));
    journal.retain(first_ids[0], &first[0]).unwrap();
    assert!(journal.discover(0).unwrap().is_empty());
    let (_, _, changed) = record(1, 101);
    assert!(matches!(
        journal.retain(first_ids[0], &changed),
        Err(CleanFileStoreError::RequestConflict)
    ));
    assert!(journal.discover(0).unwrap().is_empty());
    drop(journal);
    let mut journal = CleanNativeAuthorityOperationJournal::open_existing(&fixture.root, authority)
        .unwrap()
        .with_terminal_archive(&fixture.parent.join("terminal-archive"))
        .unwrap();
    assert_eq!(journal.load(first_ids[0]).unwrap(), Some(first[0].clone()));
    assert!(journal.discover(0).unwrap().is_empty());
}

#[test]
fn operation_terminal_archive_partial_publication_never_authorizes_hot_removal() {
    for published in 0..=5 {
        let fixture = Fixture::new("operation-terminal-partial");
        let (authority, ids, bytes) = pair(1);
        let mut journal = journal(&fixture, authority);
        journal.retain(ids[0], &bytes[0]).unwrap();
        journal.retain(ids[1], &bytes[1]).unwrap();
        let archive = journal.terminal_archive().unwrap();
        for (alias, id) in ids.into_iter().enumerate() {
            if published <= alias * 3 {
                continue;
            }
            let root = archive.slot(id, true).unwrap().unwrap();
            for (index, (mut file, bytes)) in NativeOperationTerminalArchive::files(&root)
                .into_iter()
                .zip(bytes.iter())
                .enumerate()
            {
                if alias * 3 + index < published {
                    file.commit_with_replacement(bytes, false).unwrap();
                }
            }
        }
        assert!(
            journal
                .remove_retired([&bytes[0], &bytes[1]], &bytes[2])
                .is_err()
        );
        assert_eq!(journal.discover(2).unwrap().len(), 2);
        assert!(
            journal
                .retain_retired([&bytes[0], &bytes[1]], &bytes[2])
                .unwrap()
        );
        journal
            .remove_retired([&bytes[0], &bytes[1]], &bytes[2])
            .unwrap();
        journal
            .remove_retired([&bytes[0], &bytes[1]], &bytes[2])
            .unwrap();
        assert!(journal.discover(0).unwrap().is_empty());
        assert_eq!(archive.load(ids[0]).unwrap(), Some(bytes));
    }
}

#[test]
fn operation_terminal_archive_half_removed_hot_pair_reopens_exactly_and_preserves_pending() {
    let fixture = Fixture::new("operation-terminal-hot-cut");
    let (authority, ids, bytes) = pair(1);
    let (_, pending_id, pending) = record(2, 100);
    let mut journal = journal(&fixture, authority);
    journal.retain(ids[0], &bytes[0]).unwrap();
    journal.retain(ids[1], &bytes[1]).unwrap();
    journal.retain(pending_id, &pending).unwrap();
    assert!(
        journal
            .retain_retired([&bytes[0], &bytes[1]], &bytes[2])
            .unwrap()
    );
    // The first exact unlink has reached disk, but the second has not.
    fs::remove_file(fixture.root.join(hex::encode(ids[0].0))).unwrap();
    journal.root.sync().unwrap();
    drop(journal);
    let mut journal = CleanNativeAuthorityOperationJournal::open_existing(&fixture.root, authority)
        .unwrap()
        .with_terminal_archive(&fixture.parent.join("terminal-archive"))
        .unwrap();
    assert_eq!(journal.load(ids[0]).unwrap(), Some(bytes[0].clone()));
    journal
        .remove_retired([&bytes[0], &bytes[1]], &bytes[2])
        .unwrap();
    assert_eq!(journal.discover(1).unwrap(), vec![pending_id]);
    assert_eq!(journal.load(pending_id).unwrap(), Some(pending));
    assert_eq!(journal.load(ids[1]).unwrap(), Some(bytes[1].clone()));
}

#[test]
fn operation_terminal_archive_validates_stages_before_publication_or_removal() {
    for corrupt in [false, true] {
        let fixture = Fixture::new("operation-terminal-stage");
        let (authority, ids, bytes) = pair(1);
        let mut journal = journal(&fixture, authority);
        journal.retain(ids[0], &bytes[0]).unwrap();
        journal.retain(ids[1], &bytes[1]).unwrap();
        let archive = journal.terminal_archive().unwrap();
        for id in ids {
            let root = archive.slot(id, true).unwrap().unwrap();
            for (index, (file, value)) in NativeOperationTerminalArchive::files(&root)
                .into_iter()
                .zip(bytes.iter())
                .enumerate()
            {
                let mut value = value.clone();
                if corrupt && index == 2 {
                    *value.last_mut().unwrap() ^= 1;
                }
                stage(&file, None, &value);
            }
        }
        if corrupt {
            assert!(archive.load(ids[0]).is_err());
            assert!(
                journal
                    .remove_retired([&bytes[0], &bytes[1]], &bytes[2])
                    .is_err()
            );
            assert_eq!(journal.discover(2).unwrap().len(), 2);
            assert!(
                !archive
                    .path
                    .join(hex::encode(ids[0].0))
                    .join("authorization")
                    .exists()
            );
            assert!(
                archive
                    .path
                    .join(hex::encode(ids[0].0))
                    .join("authorization.next")
                    .exists()
            );
        } else {
            assert_eq!(archive.load(ids[0]).unwrap(), Some(bytes.clone()));
            journal
                .remove_retired([&bytes[0], &bytes[1]], &bytes[2])
                .unwrap();
            assert!(journal.discover(0).unwrap().is_empty());
        }
    }
}

#[test]
fn operation_terminal_archive_refuses_touched_replacement_and_missing_serving_preimages() {
    let fixture = Fixture::new("operation-terminal-replaced");
    let (authority, ids, bytes) = pair(1);
    let mut journal = journal(&fixture, authority);
    journal.retain(ids[0], &bytes[0]).unwrap();
    journal.retain(ids[1], &bytes[1]).unwrap();
    assert!(
        journal
            .retain_retired([&bytes[0], &bytes[1]], &bytes[2])
            .unwrap()
    );
    let archive = journal.terminal_archive().unwrap();
    let path = archive
        .path
        .join(hex::encode(ids[1].0))
        .join("acknowledgement");
    let original = fs::read(&path).unwrap();
    fs::rename(&path, archive.path.join("retained-test-backup")).unwrap();
    write_private(&path, b"malformed");
    assert!(archive.load(ids[0]).is_err());
    assert!(
        journal
            .remove_retired([&bytes[0], &bytes[1]], &bytes[2])
            .is_err()
    );
    assert_eq!(journal.discover(2).unwrap().len(), 2);
    assert_eq!(
        fs::read(archive.path.join("retained-test-backup")).unwrap(),
        original
    );
}

#[test]
fn operation_terminal_archive_existing_root_loss_is_not_recreated() {
    let fixture = Fixture::new("operation-terminal-root-loss");
    let (authority, ids, bytes) = pair(1);
    let mut journal = journal(&fixture, authority);
    journal.retain(ids[0], &bytes[0]).unwrap();
    journal.retain(ids[1], &bytes[1]).unwrap();
    assert!(
        journal
            .retain_retired([&bytes[0], &bytes[1]], &bytes[2])
            .unwrap()
    );
    journal
        .remove_retired([&bytes[0], &bytes[1]], &bytes[2])
        .unwrap();
    let archive_path = fixture.parent.join("terminal-archive");
    // Live inode/path validation also refuses the disappeared root.
    fs::rename(&archive_path, fixture.parent.join("lost-archive-backup")).unwrap();
    assert!(journal.load(ids[0]).is_err());
    drop(journal);
    let journal =
        CleanNativeAuthorityOperationJournal::open_existing(&fixture.root, authority).unwrap();
    assert!(
        journal
            .with_terminal_archive_mode(&archive_path, false)
            .is_err()
    );
    assert!(!archive_path.exists());
    assert!(
        fixture
            .parent
            .join("lost-archive-backup")
            .join(hex::encode(ids[0].0))
            .join("retirement")
            .exists()
    );
}
