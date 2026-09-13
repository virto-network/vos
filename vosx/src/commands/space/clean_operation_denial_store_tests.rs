use super::super::tests::{Fixture, stage};
use super::tests::{certificate, terminal};
use super::*;

// Synthetic signed storage evidence, not native policy execution proof.
fn denial(key: &libp2p::identity::Keypair, number: u16, hash: u8) -> Vec<u8> {
    let mut invocation = [0x43; 32];
    invocation[30..].copy_from_slice(&number.to_be_bytes());
    let fields = [invocation, [hash; 32], [0x67; 32], [0x68; 32]].concat();
    let abi = vos::agent::sdk::RUNTIME_ABI_ID.as_bytes();
    let mut message = b"vos/agent/native-operation-denial-retirement/v1".to_vec();
    message.extend_from_slice(abi);
    message.extend_from_slice(&fields);
    let mut bytes = b"NDR1".to_vec();
    bytes.extend_from_slice(abi);
    bytes.extend_from_slice(&fields);
    bytes.extend_from_slice(&64u32.to_le_bytes());
    bytes.extend_from_slice(&key.sign(&message).unwrap());
    bytes
}

#[test]
fn denial_index_retains_exact_signed_evidence_and_exclusive_scope() {
    let fixture = Fixture::new("denial-index");
    let (key, authority, _, _) = crate::commands::space::local_create::tests::fixture();
    let mut store =
        CleanNativeAuthorityOperationDenials::open_or_create(&fixture.root, authority).unwrap();
    assert!(store.load().unwrap().is_empty());
    let first = denial(&key, 1, 0x65);
    assert!(store.retain(&certificate(&key, 1, 0x65)).is_err());
    assert!(store.retain(&terminal(&key, 1, 0x65)).is_err());
    for end in [0, 3, first.len() - 1] {
        assert!(store.retain(&first[..end]).is_err());
    }
    store.retain(&first).unwrap();
    let path = fixture.root.join(StoreRole::OperationDenials.file());
    let saved = fs::read(&path).unwrap();
    store.retain(&first).unwrap();
    assert_eq!(fs::read(&path).unwrap(), saved);
    assert!(matches!(
        store.retain(&denial(&key, 1, 0x67)),
        Err(CleanFileStoreError::RequestConflict)
    ));
    assert!(matches!(
        CleanNativeAuthorityOperationDenials::open_existing(&fixture.root, authority),
        Err(CleanFileStoreError::Busy)
    ));
    drop(store);
    let store =
        CleanNativeAuthorityOperationDenials::open_existing(&fixture.root, authority).unwrap();
    assert_eq!(store.load().unwrap(), vec![first]);
    drop(store);
    assert!(
        CleanNativeAuthorityOperationCompletions::open_existing(&fixture.root, authority).is_err()
    );
    assert!(
        CleanNativeAuthorityOperationRetirements::open_existing(&fixture.root, authority).is_err()
    );
    let mut wrong = authority;
    wrong.system_agent.0[0] ^= 1;
    assert!(CleanNativeAuthorityOperationDenials::open_existing(&fixture.root, wrong).is_err());
    assert_eq!(fs::read(&path).unwrap(), saved);
    let absent = fixture.parent.join("absent-denial");
    assert!(CleanNativeAuthorityOperationDenials::open_existing(&absent, authority).is_err());
    assert!(!absent.exists());
}

#[test]
fn denial_index_recovers_append_but_preserves_conflicting_and_malformed_stages() {
    let (key, authority, _, _) = crate::commands::space::local_create::tests::fixture();
    let first = denial(&key, 1, 0x65);
    let second = denial(&key, 2, 0x65);
    for mode in 0..8 {
        let fixture = Fixture::new("denial-stage");
        let mut store =
            CleanNativeAuthorityOperationDenials::open_or_create(&fixture.root, authority).unwrap();
        store.retain(&first).unwrap();
        let predecessor = store
            .0
            .file
            .read_optional(store.0.file.file(), store.0.maximum_image())
            .unwrap()
            .unwrap();
        let records = match mode {
            0 => vec![first.clone(), second.clone()],
            1 => vec![],
            2 => vec![denial(&key, 1, 0x69)],
            3 => vec![first.clone(), first.clone()],
            4 => vec![certificate(&key, 1, 0x65)],
            7 => vec![second.clone(), first.clone()],
            _ => vec![first.clone()],
        };
        let mut payload = store.0.encode(&records).unwrap();
        if mode == 5 {
            payload.push(0);
        }
        if mode == 6 {
            *payload.last_mut().unwrap() ^= 1;
        }
        stage(&store.0.file, Some(predecessor.commitment()), &payload);
        let path = fixture.root.join(store.0.file.file());
        let staged = fixture.root.join(store.0.file.stage_file());
        let saved = fs::read(&path).unwrap();
        let saved_stage = fs::read(&staged).unwrap();
        drop(store);
        let reopened =
            CleanNativeAuthorityOperationDenials::open_existing(&fixture.root, authority);
        if mode == 0 {
            assert_eq!(reopened.unwrap().load().unwrap(), records);
            assert!(!staged.exists());
        } else {
            assert!(reopened.is_err());
            assert_eq!(fs::read(&path).unwrap(), saved);
            assert_eq!(fs::read(&staged).unwrap(), saved_stage);
        }
    }
}

#[test]
fn denial_index_enforces_capacity_without_eviction() {
    let fixture = Fixture::new("denial-capacity");
    let (key, authority, _, _) = crate::commands::space::local_create::tests::fixture();
    let mut store =
        CleanNativeAuthorityOperationDenials::open_or_create(&fixture.root, authority).unwrap();
    assert_eq!(
        store.0.maximum_image(),
        StoreRole::OperationDenials.maximum_bytes()
    );
    let records: Vec<_> = (0..MAX_RECORDS)
        .map(|i| denial(&key, i as u16, 0x65))
        .collect();
    stage(&store.0.file, None, &store.0.encode(&records).unwrap());
    assert_eq!(store.load().unwrap(), records);
    let path = fixture.root.join(store.0.file.file());
    let saved = fs::read(&path).unwrap();
    assert!(matches!(
        store.retain(&denial(&key, MAX_RECORDS as u16, 0x65)),
        Err(CleanFileStoreError::Oversized)
    ));
    assert_eq!(fs::read(&path).unwrap(), saved);
    assert_eq!(store.load().unwrap(), records);
}
