//! Host-side smoke test for the dev-project store.
//!
//! Drives `store::*` directly against a `ProjectState` — bypasses
//! the actor dispatch layer to exercise the storage logic without
//! running a VosNode. The PVM-side integration path (where calls
//! go through the runtime + an installed agent + a `Ref`) is the
//! dev-extension e2e test's job, landing in a later commit.

use dev_project::*;

#[test]
fn blob_storage_is_content_addressed_and_idempotent() {
    let mut s = ProjectState::default();

    let h1 = store::put_blob(&mut s, b"hello".to_vec());
    let h2 = store::put_blob(&mut s, b"hello".to_vec());
    assert_eq!(h1, h2, "same bytes → same hash");
    assert_eq!(h1.len(), HASH_BYTES);

    let h3 = store::put_blob(&mut s, b"world".to_vec());
    assert_ne!(h1, h3);

    // Dedup: two distinct contents → two stored rows.
    assert_eq!(s.blobs.len(), 2);
}

#[test]
fn root_commit_and_fast_forward() {
    let mut s = ProjectState::default();

    let lib_hash = store::put_blob(&mut s, b"// lib.rs v1\n".to_vec());

    let result = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &[],
            paths: &["src/lib.rs".to_string()],
            blob_hashes: &lib_hash,
            branch: "main",
            intent_tag: INTENT_INIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 1,
            change_id: &[],
        },
    );
    assert_eq!(result.status, STATUS_OK);
    let root_commit = result.hash.clone();
    assert_eq!(root_commit.len(), HASH_BYTES);

    assert_eq!(store::head(&s, "main"), root_commit);

    let log = store::log(&s, "main", 10);
    assert_eq!(log.len(), HASH_BYTES);
    assert_eq!(log, root_commit);

    let row = store::get_commit(&s, &root_commit).expect("commit fetchable");
    assert_eq!(row.parent, [0u8; HASH_BYTES], "root has zero parent");
    assert_eq!(row.files.len(), 1);
    assert_eq!(row.files[0].path, "src/lib.rs");

    // Fast-forward — same file, new content.
    let lib_hash_v2 = store::put_blob(&mut s, b"// lib.rs v2\n".to_vec());
    let result2 = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &root_commit,
            paths: &["src/lib.rs".to_string()],
            blob_hashes: &lib_hash_v2,
            branch: "main",
            intent_tag: INTENT_EDIT,
            intent_data: b"bump version".to_vec(),
            author: &[],
            ts_ms: 2,
            change_id: &[],
        },
    );
    assert_eq!(result2.status, STATUS_OK);
    assert_eq!(store::head(&s, "main"), result2.hash);

    // Log emits two hashes, newest first.
    let log2 = store::log(&s, "main", 10);
    assert_eq!(log2.len(), 2 * HASH_BYTES);
    assert_eq!(&log2[..HASH_BYTES], result2.hash.as_slice());
    assert_eq!(&log2[HASH_BYTES..], root_commit.as_slice());
}

#[test]
fn non_fast_forward_is_rejected() {
    let mut s = ProjectState::default();

    let h_a = store::put_blob(&mut s, b"a".to_vec());
    let h_b = store::put_blob(&mut s, b"b".to_vec());

    let r1 = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &[],
            paths: &["a.rs".to_string()],
            blob_hashes: &h_a,
            branch: "main",
            intent_tag: INTENT_INIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 1,
            change_id: &[],
        },
    );
    assert_eq!(r1.status, STATUS_OK);
    let c1 = r1.hash.clone();

    // Advance main to c2.
    let r2 = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &c1,
            paths: &["b.rs".to_string()],
            blob_hashes: &h_b,
            branch: "main",
            intent_tag: INTENT_EDIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 2,
            change_id: &[],
        },
    );
    assert_eq!(r2.status, STATUS_OK);

    // Try to commit on top of c1 again — main is past c1, so this
    // is non-fast-forward.
    let r3 = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &c1,
            paths: &["c.rs".to_string()],
            blob_hashes: &h_a,
            branch: "main",
            intent_tag: INTENT_EDIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 3,
            change_id: &[],
        },
    );
    assert_eq!(r3.status, STATUS_BRANCH_NOT_FAST_FORWARD);
    assert!(r3.hash.is_empty());
}

#[test]
fn invalid_inputs_rejected() {
    let mut s = ProjectState::default();
    let h = store::put_blob(&mut s, b"x".to_vec());

    // Mismatched paths.len() vs blob_hashes.len()/32.
    let bad_shape = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &[],
            paths: &["a.rs".to_string(), "b.rs".to_string()],
            blob_hashes: &h, // only one hash but two paths
            branch: "main",
            intent_tag: INTENT_INIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 1,
            change_id: &[],
        },
    );
    assert_eq!(bad_shape.status, STATUS_INVALID_INPUT);

    // Path forms we reject.
    for bad in &["/abs.rs", "../escape.rs", "./local.rs", "a\\b.rs", "a/./b.rs"] {
        let r = store::commit(
            &mut s,
            store::CommitInputs {
                parent: &[],
                paths: &[bad.to_string()],
                blob_hashes: &h,
                branch: "main",
                intent_tag: INTENT_INIT,
                intent_data: Vec::new(),
                author: &[],
                ts_ms: 1,
                change_id: &[],
            },
        );
        assert_eq!(
            r.status, STATUS_INVALID_INPUT,
            "expected reject for path {bad:?}",
        );
    }

    // Reference an unstored blob hash.
    let missing_blob = vec![0xAAu8; HASH_BYTES];
    let bad_blob = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &[],
            paths: &["ok.rs".to_string()],
            blob_hashes: &missing_blob,
            branch: "main",
            intent_tag: INTENT_INIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 1,
            change_id: &[],
        },
    );
    assert_eq!(bad_blob.status, STATUS_BLOB_NOT_FOUND);

    // Unknown parent commit.
    let missing_parent = vec![0xBBu8; HASH_BYTES];
    let bad_parent = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &missing_parent,
            paths: &["ok.rs".to_string()],
            blob_hashes: &h,
            branch: "main",
            intent_tag: INTENT_EDIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 1,
            change_id: &[],
        },
    );
    assert_eq!(bad_parent.status, STATUS_PARENT_NOT_FOUND);

    // Bad hash length.
    let bad_len = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &[0u8; 5],
            paths: &["ok.rs".to_string()],
            blob_hashes: &h,
            branch: "main",
            intent_tag: INTENT_EDIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 1,
            change_id: &[],
        },
    );
    assert_eq!(bad_len.status, STATUS_BAD_HASH);
}

#[test]
fn duplicate_paths_in_one_commit_rejected() {
    let mut s = ProjectState::default();
    let h = store::put_blob(&mut s, b"x".to_vec());
    let mut blob_hashes = Vec::new();
    blob_hashes.extend_from_slice(&h);
    blob_hashes.extend_from_slice(&h);
    let r = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &[],
            paths: &["dup.rs".to_string(), "dup.rs".to_string()],
            blob_hashes: &blob_hashes,
            branch: "main",
            intent_tag: INTENT_INIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 1,
            change_id: &[],
        },
    );
    assert_eq!(r.status, STATUS_INVALID_INPUT);
}

#[test]
fn fork_off_existing_commit_creates_new_branch() {
    let mut s = ProjectState::default();
    let h = store::put_blob(&mut s, b"x".to_vec());

    let root = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &[],
            paths: &["a.rs".to_string()],
            blob_hashes: &h,
            branch: "main",
            intent_tag: INTENT_INIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 1,
            change_id: &[],
        },
    );
    assert_eq!(root.status, STATUS_OK);

    // Fork: "feature" branch off the root.
    let h_b = store::put_blob(&mut s, b"y".to_vec());
    let feat = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &root.hash,
            paths: &["b.rs".to_string()],
            blob_hashes: &h_b,
            branch: "feature",
            intent_tag: INTENT_EDIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 2,
            change_id: &[],
        },
    );
    assert_eq!(feat.status, STATUS_OK);

    let branches = store::list_branches(&s);
    assert_eq!(branches, vec!["feature".to_string(), "main".to_string()]);
    assert_eq!(store::head(&s, "main"), root.hash);
    assert_eq!(store::head(&s, "feature"), feat.hash);
}

#[test]
fn get_blob_roundtrip() {
    let mut s = ProjectState::default();
    let content = b"// some file\n".to_vec();
    let h = store::put_blob(&mut s, content.clone());
    let row = store::get_blob(&s, &h).expect("stored blob");
    assert_eq!(row.bytes, content);
    assert_eq!(row.hash.to_vec(), h);

    assert!(store::get_blob(&s, &[0xCCu8; HASH_BYTES]).is_none());
    assert!(store::get_blob(&s, &[0u8; 5]).is_none(), "wrong length → None");
}

#[test]
fn unknown_branch_head_is_empty() {
    let s = ProjectState::default();
    assert!(store::head(&s, "ghost").is_empty());
    assert!(store::log(&s, "ghost", 10).is_empty());
}
