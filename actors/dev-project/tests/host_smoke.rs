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

#[test]
fn working_change_open_put_commit_amend_dedups_log() {
    let mut s = ProjectState::default();

    // 1. Stash a few blobs so put_file_working has something
    //    valid to point at.
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    for i in 0..5 {
        let h = store::put_blob(&mut s, format!("// file v1 ({i})\n").into_bytes());
        blobs.push(h.to_vec());
    }

    // 2. open_change against an empty branch (no parent yet).
    let opened = store::open_change(&mut s, &[]);
    assert_eq!(opened.status, STATUS_OK);
    let change_id = opened.hash.clone();
    assert_eq!(change_id.len(), HASH_BYTES);

    // 3. Five put_file_working calls.
    for i in 0..5 {
        let status = store::put_file_working(
            &mut s,
            &change_id,
            &format!("src/file_{i}.rs"),
            &blobs[i],
        );
        assert_eq!(status, STATUS_OK, "put_file_working[{i}]");
    }

    // 4. Materialised tree should carry all 5 files.
    let tree = store::working_tree(&s, &change_id).expect("working tree");
    assert_eq!(tree.len(), 5);

    // 5. commit_change → first snapshot.
    let snap1 = store::commit_change(
        &mut s,
        &change_id,
        "main",
        INTENT_EDIT,
        Vec::new(),
        &[],
        100,
    );
    assert_eq!(snap1.status, STATUS_OK);
    let snap1_hash = snap1.hash.clone();

    // 6. Three amends — same change_id, new ts_ms each time.
    let mut latest_hash = snap1_hash.clone();
    for i in 0..3 {
        let amend = store::amend(
            &mut s,
            &change_id,
            INTENT_AMEND,
            Vec::new(),
            &[],
            200 + i as u64,
        );
        assert_eq!(
            amend.status, STATUS_OK,
            "amend[{i}] failed: status={}",
            amend.status
        );
        assert_ne!(amend.hash, latest_hash, "amend should mint a new hash");
        latest_hash = amend.hash.clone();
    }

    // 7. log dedupes by change_id — should be exactly one entry,
    //    and that entry is the latest amend.
    let log = store::log(&s, "main", 10);
    assert_eq!(
        log.len(),
        HASH_BYTES,
        "log should surface exactly one commit per change_id, got {} bytes",
        log.len()
    );
    assert_eq!(&log[..], &latest_hash[..], "log should surface the latest amend");

    // 8. The DAG still has all 4 commits (1 snapshot + 3 amends);
    //    they're just hidden from `log`'s view.
    assert_eq!(s.commits.len(), 4);
}

#[test]
fn working_change_delete_masks_base_entry() {
    let mut s = ProjectState::default();

    let blob_a = store::put_blob(&mut s, b"// a\n".to_vec());
    let blob_b = store::put_blob(&mut s, b"// b\n".to_vec());

    // Land an initial commit with two files.
    let snap = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &[],
            paths: &["src/a.rs".to_string(), "src/b.rs".to_string()],
            blob_hashes: &[&blob_a[..], &blob_b[..]].concat(),
            branch: "main",
            intent_tag: INTENT_INIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 1,
            change_id: &[],
        },
    );
    assert_eq!(snap.status, STATUS_OK);

    // Open a change off the snapshot, delete one file in the
    // working overlay.
    let opened = store::open_change(&mut s, &snap.hash);
    assert_eq!(opened.status, STATUS_OK);
    assert_eq!(
        store::delete_file_working(&mut s, &opened.hash, "src/a.rs"),
        STATUS_OK
    );

    let tree = store::working_tree(&s, &opened.hash).expect("tree");
    assert_eq!(tree.len(), 1, "deleted file should be masked");
    assert_eq!(tree[0].path, "src/b.rs");
}

/// Helper: land a fresh commit on `branch` with one file.
fn commit_one_file(
    s: &mut ProjectState,
    branch: &str,
    parent: &[u8],
    path: &str,
    content: &[u8],
    ts_ms: u64,
) -> Vec<u8> {
    let blob = store::put_blob(s, content.to_vec());
    let r = store::commit(
        s,
        store::CommitInputs {
            parent,
            paths: &[path.to_string()],
            blob_hashes: &blob,
            branch,
            intent_tag: INTENT_EDIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms,
            change_id: &[],
        },
    );
    assert_eq!(r.status, STATUS_OK, "commit failed: status={}", r.status);
    r.hash
}

#[test]
fn merge_fast_forwards_when_theirs_is_descendant() {
    let mut s = ProjectState::default();

    // main: A → B (linear)
    let a = commit_one_file(&mut s, "main", &[], "src/lib.rs", b"// A\n", 1);
    let b = commit_one_file(&mut s, "main", &a, "src/lib.rs", b"// B\n", 2);

    // Reset branch to A so theirs (B) is a strict descendant.
    let main_idx = s.branches.iter().position(|x| x.name == "main").unwrap();
    s.branches[main_idx].commit = bytes_to_arr(&a);

    let merge = store::merge(&mut s, "main", &b, &[], 3);
    assert_eq!(merge.status, STATUS_OK);
    assert_eq!(&merge.hash[..], &b[..], "FF: branch should advance to theirs");
    // No new commit row, just branch pointer moved.
    assert_eq!(s.commits.len(), 2);
}

#[test]
fn merge_clean_independent_edits() {
    let mut s = ProjectState::default();

    // Common ancestor: holds lib.rs + a.rs.
    let lib_blob = store::put_blob(&mut s, b"// lib\n".to_vec());
    let a_blob = store::put_blob(&mut s, b"// a v1\n".to_vec());
    let base = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &[],
            paths: &["src/a.rs".to_string(), "src/lib.rs".to_string()],
            blob_hashes: &[&a_blob[..], &lib_blob[..]].concat(),
            branch: "main",
            intent_tag: INTENT_EDIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 1,
            change_id: &[],
        },
    );
    assert_eq!(base.status, STATUS_OK);

    // ours: edits a.rs.
    let ours = commit_one_file(&mut s, "main", &base.hash, "src/a.rs", b"// a v2\n", 2);

    // theirs: a separate branch off base that adds b.rs while
    // keeping the existing files (commits carry the full tree —
    // dropping a path from `paths` means "this commit deletes
    // it", which would conflict with ours's continued presence).
    let b_blob = store::put_blob(&mut s, b"// b v1\n".to_vec());
    let theirs_r = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &base.hash,
            paths: &[
                "src/a.rs".to_string(),
                "src/b.rs".to_string(),
                "src/lib.rs".to_string(),
            ],
            blob_hashes: &[&a_blob[..], &b_blob[..], &lib_blob[..]].concat(),
            branch: "feature",
            intent_tag: INTENT_EDIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 3,
            change_id: &[],
        },
    );
    assert_eq!(theirs_r.status, STATUS_OK);

    let merge = store::merge(&mut s, "main", &theirs_r.hash, &[], 4);
    assert_eq!(merge.status, STATUS_OK);

    let merge_commit = store::get_commit(&s, &merge.hash).expect("merge commit exists");
    assert!(
        merge_commit.conflicts.is_empty(),
        "clean merge should record no conflicts: {:?}",
        merge_commit.conflicts
    );
    assert_eq!(merge_commit.parent, bytes_to_arr(&ours));
    assert_eq!(merge_commit.extras.len(), 1);
    assert_eq!(merge_commit.extras[0], bytes_to_arr(&theirs_r.hash));
    assert_eq!(merge_commit.intent_tag, INTENT_MERGE);
}

#[test]
fn merge_records_conflict_then_subsequent_commit_resolves() {
    let mut s = ProjectState::default();

    // base: lib.rs v0.
    let v0 = store::put_blob(&mut s, b"// v0\n".to_vec());
    let base = store::commit(
        &mut s,
        store::CommitInputs {
            parent: &[],
            paths: &["src/lib.rs".to_string()],
            blob_hashes: &v0,
            branch: "main",
            intent_tag: INTENT_EDIT,
            intent_data: Vec::new(),
            author: &[],
            ts_ms: 1,
            change_id: &[],
        },
    );
    assert_eq!(base.status, STATUS_OK);

    // ours: lib.rs v1.
    let ours = commit_one_file(&mut s, "main", &base.hash, "src/lib.rs", b"// ours v1\n", 2);

    // theirs (off base): lib.rs v2 — same path, different content.
    let theirs = commit_one_file(&mut s, "feature", &base.hash, "src/lib.rs", b"// theirs v1\n", 3);

    let merge = store::merge(&mut s, "main", &theirs, &[], 4);
    assert_eq!(merge.status, STATUS_OK);

    let merge_commit = store::get_commit(&s, &merge.hash).expect("merge commit");
    assert_eq!(
        merge_commit.conflicts.len(),
        1,
        "lib.rs should conflict (both sides changed differently)"
    );
    let cf = &merge_commit.conflicts[0];
    assert_eq!(cf.path, "src/lib.rs");
    let v0_arr = bytes_to_arr(&v0.to_vec());
    let ours_blob = merge_commit
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .map(|f| f.blob)
        .unwrap();
    assert_eq!(cf.base, v0_arr);
    assert_eq!(cf.ours, ours_blob, "merge keeps ours as tentative pick");

    // Resolve by committing a fresh content on top of the merge.
    let resolved = commit_one_file(
        &mut s,
        "main",
        &merge.hash,
        "src/lib.rs",
        b"// resolved\n",
        5,
    );
    let res_commit = store::get_commit(&s, &resolved).expect("resolved commit");
    assert!(
        res_commit.conflicts.is_empty(),
        "resolution commit clears conflicts"
    );

    // Branch advanced through merge → resolved.
    assert_eq!(store::head(&s, "main"), resolved);
}

fn bytes_to_arr(b: &[u8]) -> [u8; HASH_BYTES] {
    let mut out = [0u8; HASH_BYTES];
    out[..b.len().min(HASH_BYTES)].copy_from_slice(&b[..b.len().min(HASH_BYTES)]);
    out
}

#[test]
fn working_changes_arent_in_commit_log() {
    // Regression for Phase 3.2: working entries shouldn't leak
    // into commits / branch refs even though they live on the
    // same `ProjectState`. The actor uses
    // commits/branches/blobs as the replication source-of-truth;
    // confirming working stays out keeps the deferred per-field
    // consistency story coherent.
    let mut s = ProjectState::default();

    let blob = store::put_blob(&mut s, b"// only in working\n".to_vec());
    let opened = store::open_change(&mut s, &[]);
    assert_eq!(opened.status, STATUS_OK);
    assert_eq!(
        store::put_file_working(&mut s, &opened.hash, "src/lib.rs", &blob),
        STATUS_OK
    );

    // Working state has the edit...
    assert_eq!(s.working.len(), 1);
    assert_eq!(s.working[0].edits.len(), 1);
    // ...but commits + branches are untouched.
    assert!(s.commits.is_empty());
    assert!(s.branches.is_empty());
    assert!(store::log(&s, "main", 10).is_empty());
}
