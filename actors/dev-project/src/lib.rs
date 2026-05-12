//! Dev-project actor — the PVM side of the dev-extension toolchain.
//!
//! Holds a content-addressed object store + commit DAG for **one
//! VOS program's source code**. The agent edits source as data
//! (file blobs, indexed by blake2b-256) and snapshots immutable
//! commits that string together into a history. Pairs with the
//! native dev extension (separate crate, future commit) which
//! reads `(commit, tree)` and produces a PVM ELF.
//!
//! v1 scope — deliberately tight so the storage shape and CRDT
//! replication can be pressure-tested before piling on:
//!
//! - Whole-blob file replacement (no AST patches yet).
//! - Single working state per agent, mirrored into immutable
//!   commits on `commit()`. No mutable working-change layer.
//! - Single-parent commits; merge is a follow-up.
//! - Fast-forward refs only.
//!
//! Borrowed from existing VCS:
//!
//! - **git** — content-addressed blob/commit objects, named refs,
//!   blake2b instead of sha1 since vos already exposes the
//!   precompile.
//! - **jujutsu** — `change_id` separates "the change I'm working
//!   on" from "the snapshots I've taken of it". An amend keeps the
//!   change_id, mints a new commit hash, advances the ref. Latest
//!   commit per change_id is what `log` surfaces. Working-state
//!   semantics will be layered on top in v2.
//!
//! Real-time collaborative editing (multiple agents editing the
//! same project simultaneously) lands later via CRDT-mergeable
//! patch types on top of this primitive store. The current shape
//! is already CRDT-friendly: every `Vec<Row>` sorted by hash maps
//! to an OR-Map of content-addressed inserts, so two replicas
//! pushing commits to different branches never conflict at the
//! object layer. The only contentious slot is `branches`, and v1
//! picks "fast-forward only under each agent's identity" — fine
//! until two agents race the same branch, which we'll address
//! with explicit branch ownership or quorum advance later.
//!
//! ## Layering
//!
//! The pure store logic lives in [`store`] as plain functions
//! over [`ProjectState`]. The `#[actor]` shell wraps that with
//! the message-dispatch glue. Host-side tests exercise the
//! `store::` API directly; integration tests through the runtime
//! exercise the actor.

#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "wasm32", no_std)]

use vos::prelude::*;

// ── Constants ─────────────────────────────────────────────────────

/// 32-byte content hash. blake2b-256 of the canonical encoding of
/// whichever object kind the hash refers to. Crosses message
/// boundaries as `Vec<u8>`; the store validates length and stores
/// `[u8; 32]` in archived rows.
pub const HASH_BYTES: usize = 32;

// ── Status codes ──────────────────────────────────────────────────

pub const STATUS_OK: u8 = 0;
pub const STATUS_NOT_FOUND: u8 = 1;
pub const STATUS_BAD_HASH: u8 = 2;
pub const STATUS_PARENT_NOT_FOUND: u8 = 3;
pub const STATUS_BLOB_NOT_FOUND: u8 = 4;
pub const STATUS_BRANCH_NOT_FAST_FORWARD: u8 = 5;
pub const STATUS_INVALID_INPUT: u8 = 6;
pub const STATUS_CHANGE_NOT_FOUND: u8 = 7;

// ── Intent tag values ─────────────────────────────────────────────

pub const INTENT_INIT: u8 = 0;
pub const INTENT_EDIT: u8 = 1;
pub const INTENT_BUILD: u8 = 2;
pub const INTENT_PUBLISH: u8 = 3;
pub const INTENT_MERGE: u8 = 4;
pub const INTENT_AMEND: u8 = 5;
pub const INTENT_REVERT: u8 = 6;

/// Decoded payload for `INTENT_PUBLISH` commits. The actor stores
/// the rkyv-encoded form in [`CommitNode::intent_data`]; agents
/// (and any host tooling) decode on read.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct PublishIntent {
    pub program_name: String,
    pub program_version: String,
    pub program_hash: [u8; HASH_BYTES],
}

/// Decoded payload for `INTENT_BUILD` commits. The dev extension
/// records one of these whenever it tries to compile a source
/// commit, regardless of success — failure carries a blob hash
/// pointing at the captured stderr so the operator can inspect
/// the failure mode from the commit DAG alone.
///
/// `source_commit` links the build commit back to the tree that
/// produced it; the commit's `parent` is the previous build on the
/// `builds` branch (chained linearly so the FF-only commit handler
/// works), and the source linkage lives here. `artifact` is the
/// PVM blob hash on success, or the stderr blob hash on failure.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct BuildIntent {
    /// `1` on successful compile, `0` on failure.
    pub ok: u8,
    /// The source-tree commit the extension was asked to build.
    pub source_commit: [u8; HASH_BYTES],
    /// PVM blob hash (when `ok = 1`) or stderr blob hash
    /// (when `ok = 0`).
    pub artifact: [u8; HASH_BYTES],
}

// ── Wire rows ─────────────────────────────────────────────────────

/// One entry in a commit's flat file table.
///
/// v1 carries the file list inline on each commit rather than via
/// a tree object. Path-level dedup across commits is sacrificed
/// (every commit pays for naming every file even when most are
/// unchanged); blob-level dedup is still there (`ProjectState.blobs`).
/// When project size makes path-level dedup matter we'll introduce
/// real tree nodes; doing it now would only pay overhead for
/// trivial projects.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct FileEntry {
    /// Forward-slash-separated path relative to project root.
    /// Validated to reject leading slash, `..`, and `\`.
    pub path: String,
    /// blake2b-256 of the blob's content.
    pub blob: [u8; HASH_BYTES],
}

/// Discriminator for the encoding inside [`BlobObject::bytes`].
///
/// - `Raw` — bytes are file content verbatim. The compile path
///   writes them to disk unchanged.
/// - `RustAst` — bytes are an rkyv-encoded `syn::File`, hashed
///   under a separate domain tag so a content-equivalent text and
///   AST blob still hash to different values. The compile path
///   rehydrates the AST to source via `dev_ast::ast_to_text`
///   before invoking the compiler. Agents and AI tooling that
///   manipulate code as structured values store under this kind.
///
/// The byte encoding matches the variant order so on-disk values
/// stay stable; only append at the end if more kinds are added.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum BlobKind {
    Raw = 0,
    RustAst = 1,
}

impl Default for BlobKind {
    fn default() -> Self {
        Self::Raw
    }
}

/// One blob — bytes addressed by their hash, with a [`BlobKind`]
/// discriminator that tells the consumer how to interpret the
/// bytes. v1 stored only `Raw`; Phase 2 added `RustAst` so the
/// compile path can decode AST blobs back to text before
/// invoking the compiler.
///
/// Schema-evolution note: appending `kind` to an existing rkyv-
/// archived struct breaks decoding of pre-Phase-2 persisted
/// state. Acceptable while pre-release — the actor falls back to
/// `create()` per the dev-project-level note above.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct BlobObject {
    pub hash: [u8; HASH_BYTES],
    pub bytes: Vec<u8>,
    pub kind: BlobKind,
}

/// Immutable commit, content-addressed by blake2b of its canonical
/// encoding.
///
/// `parent` is `[0; 32]` for the root commit; `extras` carries
/// additional parents (merges, future). `change_id` is jj-style:
/// an amend mints a fresh `CommitNode` hash but keeps the same
/// `change_id` so the change's authoritative snapshot is "the
/// latest commit sharing this change_id". v1 always mints fresh
/// change_ids (one commit per change); amend semantics come with
/// the working-state layer.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct CommitNode {
    /// `[0; 32]` iff this is the root commit.
    pub parent: [u8; HASH_BYTES],
    /// Extra parents (merges). Empty for normal commits. Sorted.
    pub extras: Vec<[u8; HASH_BYTES]>,
    /// Sorted by path. Reject duplicate paths.
    pub files: Vec<FileEntry>,
    /// Identity of the calling agent. `[0; 32]` when the caller
    /// didn't pass one. v1 trusts the caller; identity verification
    /// is a separate concern threaded through the registry's
    /// Members table.
    pub author: [u8; HASH_BYTES],
    /// Unix millis on the calling agent's clock when it committed.
    /// Not authoritative — replicas don't agree on time — but
    /// useful as a sort hint.
    pub ts_ms: u64,
    pub intent_tag: u8,
    pub intent_data: Vec<u8>,
    pub change_id: [u8; HASH_BYTES],
}

/// One branch pointer.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct BranchRef {
    pub name: String,
    pub commit: [u8; HASH_BYTES],
}

// ── Result wrappers ───────────────────────────────────────────────

/// Returned by mutating store ops. `status == STATUS_OK` ⇔
/// `hash.len() == 32`; on failure the hash field is empty so
/// the caller doesn't try to use it.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct HashResult {
    pub status: u8,
    pub hash: Vec<u8>,
}

impl HashResult {
    fn ok(hash: [u8; HASH_BYTES]) -> Self {
        Self {
            status: STATUS_OK,
            hash: hash.to_vec(),
        }
    }
    fn err(status: u8) -> Self {
        Self {
            status,
            hash: Vec::new(),
        }
    }
}

// ── ProjectState — the pure data, separable from the actor ─────

/// Owned state of one dev-project. Lives inside the `DevProject`
/// actor on the PVM side; the same struct is what host-side tests
/// instantiate directly via [`store`] to exercise the storage
/// logic without round-tripping through the runtime.
#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ProjectState {
    pub name: String,
    /// Sorted by hash. Binary-searchable.
    pub blobs: Vec<BlobObject>,
    /// Sorted by canonical commit hash.
    pub commits: Vec<CommitNode>,
    /// Sorted by branch name.
    pub branches: Vec<BranchRef>,
    /// Open working changes (jj-style) — `(change_id, edits)`
    /// pairs the agent is iterating on between snapshot commits.
    /// Sorted by `change_id`.
    ///
    /// **NOT REPLICATED — runtime support pending.** Working
    /// state is per-replica scratchpad and shouldn't appear in
    /// the CRDT export to peers; the runtime doesn't yet expose
    /// a per-field consistency knob, so for now the field still
    /// participates in archive/replication. Once that knob
    /// lands, this field becomes the canonical example of
    /// "local-only" state. Until then, the regression test in
    /// `tests/host_smoke.rs::working_changes_arent_in_commit_log`
    /// asserts the next-best invariant: working entries don't
    /// leak into the commit log or branch refs (the parts of
    /// state any consumer of the CRDT replication stream
    /// observes).
    pub working: Vec<WorkingChange>,
}

/// Per-file edit on top of a working change's `base` commit.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub enum EditOp {
    /// Replace (or add) the file at `path` with the blob at
    /// `hash`. Blob must already exist via `put_blob` /
    /// `put_blob_ast` — the working change references blobs by
    /// content hash, never by inline bytes.
    PutBlob([u8; HASH_BYTES]),
    /// Drop the file at `path` from the working tree. The base
    /// commit's entry for the same path is masked.
    Delete,
}

/// One open working change. The combination `(base, edits)` is
/// the agent's current edit-in-progress; `commit_change` snapshots
/// it as an immutable [`CommitNode`].
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct WorkingChange {
    /// jj-style stable identifier. Survives `amend` so the
    /// authoritative snapshot is "the latest commit sharing
    /// this change_id"; `log` dedupes by it.
    pub change_id: [u8; HASH_BYTES],
    /// Commit the working tree builds on. `[0; 32]` for a fresh
    /// change off a branch that doesn't exist yet.
    pub base: [u8; HASH_BYTES],
    /// Per-file overlays, sorted by path. An entry's presence at
    /// a path always wins over the same path in `base`'s tree.
    pub edits: Vec<WorkingEdit>,
}

/// One overlay entry in a working change.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct WorkingEdit {
    pub path: String,
    pub op: EditOp,
}

/// One unresolved-merge entry recorded on a `CommitNode`. The
/// merge commit carries a tentative pick in `files` (Phase 4.1
/// defaults to "ours") *plus* this row for the operator / agent
/// to act on. A subsequent plain commit that puts an explicit
/// blob at `path` clears the conflict — no extra ceremony.
///
/// All three hashes are `[0; 32]` when the file was absent on
/// that side (e.g. added on `ours` but not at `base` and not on
/// `theirs`).
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ConflictEntry {
    pub path: String,
    pub base: [u8; HASH_BYTES],
    pub ours: [u8; HASH_BYTES],
    pub theirs: [u8; HASH_BYTES],
}

/// Result of a three-way merge — the resolved file tree plus any
/// per-path conflicts the algorithm couldn't decide. `files` is
/// always populated (a conflicting file gets `ours`'s blob as a
/// tentative pick); `conflicts` is empty on a clean merge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeResult {
    pub files: Vec<FileEntry>,
    pub conflicts: Vec<ConflictEntry>,
}

// ── store — pure functions over ProjectState ──────────────────

pub mod store {
    //! Plain functions over [`ProjectState`]. No `#[msg]`, no
    //! macro magic — directly callable from host-side tests.
    //! The actor's `#[messages]` impl is a thin wrapper that
    //! marshals `Vec<u8>` arguments to/from these.

    use super::*;
    // `to_string()` etc. live on `alloc::string::ToString`, which
    // is in `std::prelude` on the host but not in the riscv64em-
    // javm `no_std` build. Explicitly importing keeps the same
    // source path compiling for both flavors.
    #[allow(unused_imports)]
    use alloc::string::ToString;

    /// Store a `BlobKind::Raw` blob, returning its hash. Idempotent —
    /// calling with the same bytes twice is a no-op except for the
    /// return value. Same domain tag the original v1 used so existing
    /// raw blobs keep hashing identically.
    pub fn put_blob(state: &mut ProjectState, bytes: Vec<u8>) -> [u8; HASH_BYTES] {
        put_blob_with_kind(state, bytes, BlobKind::Raw)
    }

    /// Store a blob with an explicit kind. AST blobs hash under a
    /// distinct domain tag so a content-equivalent text and AST blob
    /// don't collide (and so the rendered text isn't accidentally
    /// returned when the AST archive is what was asked for).
    pub fn put_blob_with_kind(
        state: &mut ProjectState,
        bytes: Vec<u8>,
        kind: BlobKind,
    ) -> [u8; HASH_BYTES] {
        let domain = match kind {
            BlobKind::Raw => b"vos-dev-project/blob/v1".as_slice(),
            BlobKind::RustAst => b"vos-dev-project/ast/v1".as_slice(),
        };
        let hash: [u8; HASH_BYTES] = vos::crypto::blake2b_hash(domain, &[&bytes]);
        if find_blob(state, &hash).is_none() {
            let row = BlobObject { hash, bytes, kind };
            let pos = state
                .blobs
                .binary_search_by(|b| b.hash.cmp(&hash))
                .unwrap_or_else(|p| p);
            state.blobs.insert(pos, row);
        }
        hash
    }

    /// Fetch a blob row by hash. Returns `None` for unknown hashes
    /// or wrong-length input.
    pub fn get_blob(state: &ProjectState, hash: &[u8]) -> Option<BlobObject> {
        let h = bytes_to_32(hash)?;
        find_blob(state, &h).map(|i| state.blobs[i].clone())
    }

    /// Fetch a commit row by hash. Returns `None` for unknown hashes
    /// or wrong-length input.
    pub fn get_commit(state: &ProjectState, hash: &[u8]) -> Option<CommitNode> {
        let h = bytes_to_32(hash)?;
        find_commit(state, &h).map(|i| state.commits[i].clone())
    }

    /// Resolve a branch name to its commit hash. Returns an empty
    /// vector when the branch doesn't exist (preserving the wire
    /// convention that empty = absent).
    pub fn head(state: &ProjectState, branch: &str) -> Vec<u8> {
        match find_branch(state, branch) {
            Some(i) => state.branches[i].commit.to_vec(),
            None => Vec::new(),
        }
    }

    /// Walk back from a branch's head emitting up to `limit` commit
    /// hashes, newest first. Follows only `parent`, not `extras`.
    ///
    /// jj-style change_id deduplication: when `amend` produces a
    /// chain of commits sharing the same change_id, only the most
    /// recent (newest, encountered first while walking back) is
    /// surfaced. The older commits are still in the DAG — they're
    /// just hidden from this view so the agent sees one entry per
    /// change.
    pub fn log(state: &ProjectState, branch: &str, limit: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut seen_changes: Vec<[u8; HASH_BYTES]> = Vec::new();
        let Some(idx) = find_branch(state, branch) else {
            return out;
        };
        let mut cur = state.branches[idx].commit;
        let zero = [0u8; HASH_BYTES];
        while out.len() / HASH_BYTES < limit && cur != zero {
            let Some(ci) = find_commit(state, &cur) else {
                break;
            };
            let cid = state.commits[ci].change_id;
            if !seen_changes.contains(&cid) {
                out.extend_from_slice(&cur);
                seen_changes.push(cid);
            }
            cur = state.commits[ci].parent;
        }
        out
    }

    /// List branch names.
    pub fn list_branches(state: &ProjectState) -> Vec<String> {
        state.branches.iter().map(|b| b.name.clone()).collect()
    }

    /// Inputs for [`commit`]. Mirrors the actor's wire shape so the
    /// pure-function tests cover the same parameter validation.
    pub struct CommitInputs<'a> {
        pub parent: &'a [u8],
        pub paths: &'a [String],
        pub blob_hashes: &'a [u8],
        pub branch: &'a str,
        pub intent_tag: u8,
        pub intent_data: Vec<u8>,
        pub author: &'a [u8],
        pub ts_ms: u64,
        pub change_id: &'a [u8],
    }

    /// Snapshot the given file list as a new commit, advance the
    /// named branch (fast-forward only — non-FF advances are
    /// rejected pending merge support). See the actor wrapper
    /// for wire-level documentation.
    pub fn commit(state: &mut ProjectState, args: CommitInputs<'_>) -> HashResult {
        // ── Validate parent
        let parent_arr = if args.parent.is_empty() {
            [0u8; HASH_BYTES]
        } else {
            let Some(h) = bytes_to_32(args.parent) else {
                return HashResult::err(STATUS_BAD_HASH);
            };
            if find_commit(state, &h).is_none() {
                return HashResult::err(STATUS_PARENT_NOT_FOUND);
            }
            h
        };

        // ── Validate file table shape
        if args.blob_hashes.len() != args.paths.len() * HASH_BYTES {
            return HashResult::err(STATUS_INVALID_INPUT);
        }

        // ── Build + validate file entries
        let mut files: Vec<FileEntry> = Vec::with_capacity(args.paths.len());
        for (i, path) in args.paths.iter().enumerate() {
            if !is_valid_path(path) {
                return HashResult::err(STATUS_INVALID_INPUT);
            }
            let off = i * HASH_BYTES;
            let mut blob = [0u8; HASH_BYTES];
            blob.copy_from_slice(&args.blob_hashes[off..off + HASH_BYTES]);
            if find_blob(state, &blob).is_none() {
                return HashResult::err(STATUS_BLOB_NOT_FOUND);
            }
            files.push(FileEntry {
                path: path.clone(),
                blob,
            });
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        for w in files.windows(2) {
            if w[0].path == w[1].path {
                return HashResult::err(STATUS_INVALID_INPUT);
            }
        }

        // ── Validate fixed-width inputs
        let author_arr = if args.author.is_empty() {
            [0u8; HASH_BYTES]
        } else {
            match bytes_to_32(args.author) {
                Some(h) => h,
                None => return HashResult::err(STATUS_BAD_HASH),
            }
        };
        let change_id_arr = if args.change_id.is_empty() {
            [0u8; HASH_BYTES]
        } else {
            match bytes_to_32(args.change_id) {
                Some(h) => h,
                None => return HashResult::err(STATUS_BAD_HASH),
            }
        };

        // ── Hash + mint change_id when caller passed empty
        let mut row = CommitNode {
            parent: parent_arr,
            extras: Vec::new(),
            files,
            author: author_arr,
            ts_ms: args.ts_ms,
            intent_tag: args.intent_tag,
            intent_data: args.intent_data,
            change_id: change_id_arr,
        };
        let hash = commit_hash(&row, change_id_arr);
        if change_id_arr == [0u8; HASH_BYTES] {
            row.change_id = hash;
        }

        // ── Fast-forward gate
        match find_branch(state, args.branch) {
            Some(bi) => {
                if parent_arr == [0u8; HASH_BYTES] || state.branches[bi].commit != parent_arr {
                    return HashResult::err(STATUS_BRANCH_NOT_FAST_FORWARD);
                }
                state.branches[bi].commit = hash;
            }
            None => {
                let new_branch = BranchRef {
                    name: args.branch.to_string(),
                    commit: hash,
                };
                let pos = state
                    .branches
                    .binary_search_by(|b| b.name.as_str().cmp(args.branch))
                    .unwrap_or_else(|p| p);
                state.branches.insert(pos, new_branch);
            }
        }

        // ── Persist commit
        let pos = state
            .commits
            .binary_search_by(|c| commit_row_hash(c).cmp(&hash))
            .unwrap_or_else(|p| p);
        state.commits.insert(pos, row);

        HashResult::ok(hash)
    }

    // ── Three-way merge ─────────────────────────────────────────

    /// Three-way merge over file trees. Per-path rules:
    ///
    /// - `base == ours == theirs` → take any (no change).
    /// - `ours == theirs` (parallel identical edits or deletes) →
    ///   take either side, no conflict.
    /// - `base == ours`, `theirs` differs → take `theirs`
    ///   (only the other side changed).
    /// - `base == theirs`, `ours` differs → take `ours`
    ///   (mirror of the above).
    /// - Everything else (both sides changed differently, including
    ///   add/add with different content or modify/delete) →
    ///   conflict. `files` keeps `ours`'s blob as a tentative
    ///   pick so the merged commit still has *something* there;
    ///   the `ConflictEntry` row tells the caller to resolve.
    pub fn merge_trees(
        base: &[FileEntry],
        ours: &[FileEntry],
        theirs: &[FileEntry],
    ) -> MergeResult {
        let lookup = |tree: &[FileEntry], p: &str| -> Option<[u8; HASH_BYTES]> {
            tree.iter().find(|f| f.path == p).map(|f| f.blob)
        };

        // Collect every path mentioned across the three trees,
        // sorted, deduped.
        let mut paths: Vec<String> = Vec::new();
        for tree in [base, ours, theirs] {
            for f in tree {
                if !paths.iter().any(|p| p == &f.path) {
                    paths.push(f.path.clone());
                }
            }
        }
        paths.sort();

        let mut merged: Vec<FileEntry> = Vec::new();
        let mut conflicts: Vec<ConflictEntry> = Vec::new();

        for path in &paths {
            let b = lookup(base, path);
            let o = lookup(ours, path);
            let t = lookup(theirs, path);

            // Both sides agree (modulo deletes).
            if o == t {
                if let Some(blob) = o {
                    merged.push(FileEntry {
                        path: path.clone(),
                        blob,
                    });
                }
                continue;
            }
            // ours unchanged from base → take theirs.
            if b == o {
                if let Some(blob) = t {
                    merged.push(FileEntry {
                        path: path.clone(),
                        blob,
                    });
                }
                continue;
            }
            // theirs unchanged from base → take ours.
            if b == t {
                if let Some(blob) = o {
                    merged.push(FileEntry {
                        path: path.clone(),
                        blob,
                    });
                }
                continue;
            }
            // Both sides changed differently — record a conflict.
            // Pick `ours` for the tentative merged file so the
            // commit's tree still resolves to *some* content; the
            // ConflictEntry below tells callers it's tentative.
            if let Some(blob) = o {
                merged.push(FileEntry {
                    path: path.clone(),
                    blob,
                });
            }
            conflicts.push(ConflictEntry {
                path: path.clone(),
                base: b.unwrap_or([0u8; HASH_BYTES]),
                ours: o.unwrap_or([0u8; HASH_BYTES]),
                theirs: t.unwrap_or([0u8; HASH_BYTES]),
            });
        }

        MergeResult {
            files: merged,
            conflicts,
        }
    }

    // ── Working changes (jj-style) ──────────────────────────────

    /// Open a new working change off `base`. `base` is 32 bytes
    /// pointing at an existing commit, or empty to open against
    /// "no parent yet" (the change's eventual commit will become
    /// the root commit of its branch).
    ///
    /// The minted `change_id` is derived deterministically from
    /// the base + the current count of open changes so two
    /// `open_change` calls on the same state don't collide and a
    /// snapshot-then-restore round-trip reproduces the same id.
    /// Stable across replays.
    pub fn open_change(state: &mut ProjectState, base: &[u8]) -> HashResult {
        let base_arr = if base.is_empty() {
            [0u8; HASH_BYTES]
        } else {
            let Some(h) = bytes_to_32(base) else {
                return HashResult::err(STATUS_BAD_HASH);
            };
            if find_commit(state, &h).is_none() {
                return HashResult::err(STATUS_PARENT_NOT_FOUND);
            }
            h
        };
        let count = state.working.len() as u64;
        let change_id: [u8; HASH_BYTES] = vos::crypto::blake2b_hash(
            b"vos-dev-project/change-id/v1",
            &[&base_arr, &count.to_le_bytes()],
        );
        let change = WorkingChange {
            change_id,
            base: base_arr,
            edits: Vec::new(),
        };
        let pos = state
            .working
            .binary_search_by(|w| w.change_id.cmp(&change_id))
            .unwrap_or_else(|p| p);
        state.working.insert(pos, change);
        HashResult::ok(change_id)
    }

    /// Drop `path` from the working change. The base commit's
    /// entry for the same path will be masked when
    /// `working_tree` materialises.
    pub fn delete_file_working(state: &mut ProjectState, change_id: &[u8], path: &str) -> u8 {
        if !is_valid_path(path) {
            return STATUS_INVALID_INPUT;
        }
        let Some(cid) = bytes_to_32(change_id) else {
            return STATUS_BAD_HASH;
        };
        let Some(idx) = find_working(state, &cid) else {
            return STATUS_CHANGE_NOT_FOUND;
        };
        upsert_edit(&mut state.working[idx], path, EditOp::Delete);
        STATUS_OK
    }

    /// Stage a file overlay on the working change: the file at
    /// `path` now resolves to the blob at `blob_hash`. Blob must
    /// already be in the project's blob store (call `put_blob`
    /// first to get its hash). Replaces any prior edit for the
    /// same path.
    pub fn put_file_working(
        state: &mut ProjectState,
        change_id: &[u8],
        path: &str,
        blob_hash: &[u8],
    ) -> u8 {
        if !is_valid_path(path) {
            return STATUS_INVALID_INPUT;
        }
        let Some(cid) = bytes_to_32(change_id) else {
            return STATUS_BAD_HASH;
        };
        let Some(bh) = bytes_to_32(blob_hash) else {
            return STATUS_BAD_HASH;
        };
        if find_blob(state, &bh).is_none() {
            return STATUS_BLOB_NOT_FOUND;
        }
        let Some(idx) = find_working(state, &cid) else {
            return STATUS_CHANGE_NOT_FOUND;
        };
        upsert_edit(&mut state.working[idx], path, EditOp::PutBlob(bh));
        STATUS_OK
    }

    /// Snapshot the working change as an immutable commit and
    /// advance `branch`. The working change stays open jj-style:
    /// its `base` becomes the new commit hash, edits clear, and
    /// the agent can keep iterating from here. Returns the new
    /// commit's hash.
    ///
    /// Branch advance is the same fast-forward gate `commit`
    /// enforces: the branch's current head must equal the
    /// working change's base, or the branch must not exist yet.
    pub fn commit_change(
        state: &mut ProjectState,
        change_id: &[u8],
        branch: &str,
        intent_tag: u8,
        intent_data: Vec<u8>,
        author: &[u8],
        ts_ms: u64,
    ) -> HashResult {
        let Some(cid) = bytes_to_32(change_id) else {
            return HashResult::err(STATUS_BAD_HASH);
        };
        let Some(idx) = find_working(state, &cid) else {
            return HashResult::err(STATUS_CHANGE_NOT_FOUND);
        };
        let parent_arr = state.working[idx].base;

        // Materialise the working tree the same way `working_tree`
        // would, then hand it to the regular commit path.
        let files = match working_tree(state, change_id) {
            Some(f) => f,
            None => return HashResult::err(STATUS_CHANGE_NOT_FOUND),
        };
        let mut paths: Vec<String> = Vec::with_capacity(files.len());
        let mut blob_hashes: Vec<u8> = Vec::with_capacity(files.len() * HASH_BYTES);
        for f in &files {
            paths.push(f.path.clone());
            blob_hashes.extend_from_slice(&f.blob);
        }

        let parent_bytes: Vec<u8> = if parent_arr == [0u8; HASH_BYTES] {
            Vec::new()
        } else {
            parent_arr.to_vec()
        };

        let result = commit(
            state,
            CommitInputs {
                parent: &parent_bytes,
                paths: &paths,
                blob_hashes: &blob_hashes,
                branch,
                intent_tag,
                intent_data,
                author,
                ts_ms,
                change_id: &cid,
            },
        );
        if result.status != STATUS_OK {
            return result;
        }
        // Carry the change forward: clear edits, advance its base
        // to the new commit. Same change_id stays — that's what
        // `amend` later looks up.
        let new_base = bytes_to_32(&result.hash).unwrap_or([0u8; HASH_BYTES]);
        let work = &mut state.working[idx];
        work.base = new_base;
        work.edits.clear();
        result
    }

    /// Re-snapshot the working change under the same change_id
    /// with a new ts_ms / intent, advancing whichever branch was
    /// tracking the change's base. Functionally a thin wrapper
    /// over `commit_change` — the named entry point signals
    /// "you're fixing up the last commit, not landing a new
    /// change". `log`'s change_id dedupe hides the superseded
    /// commits so the operator only sees the latest.
    pub fn amend(
        state: &mut ProjectState,
        change_id: &[u8],
        intent_tag: u8,
        intent_data: Vec<u8>,
        author: &[u8],
        ts_ms: u64,
    ) -> HashResult {
        let Some(cid) = bytes_to_32(change_id) else {
            return HashResult::err(STATUS_BAD_HASH);
        };
        let Some(idx) = find_working(state, &cid) else {
            return HashResult::err(STATUS_CHANGE_NOT_FOUND);
        };
        let base = state.working[idx].base;
        // Find the branch whose head equals the change's base —
        // i.e. the branch we last committed onto. amend advances
        // that one.
        let branch_name = state
            .branches
            .iter()
            .find(|b| b.commit == base)
            .map(|b| b.name.clone());
        let Some(branch_name) = branch_name else {
            return HashResult::err(STATUS_NOT_FOUND);
        };
        commit_change(
            state,
            change_id,
            &branch_name,
            intent_tag,
            intent_data,
            author,
            ts_ms,
        )
    }

    /// Materialise the working change's tree: take the base
    /// commit's `files`, then apply each overlay (replace or
    /// drop). The result is the file list the next snapshot
    /// commit would carry.
    pub fn working_tree(state: &ProjectState, change_id: &[u8]) -> Option<Vec<FileEntry>> {
        let cid = bytes_to_32(change_id)?;
        let idx = find_working(state, &cid)?;
        let change = &state.working[idx];

        // Start from the base commit's tree (empty if root).
        let mut tree: Vec<FileEntry> = if change.base == [0u8; HASH_BYTES] {
            Vec::new()
        } else {
            state
                .commits
                .iter()
                .find(|c| commit_row_hash(c) == change.base)
                .map(|c| c.files.clone())
                .unwrap_or_default()
        };

        for edit in &change.edits {
            match edit.op {
                EditOp::PutBlob(blob) => match tree.binary_search_by(|f| f.path.cmp(&edit.path)) {
                    Ok(i) => tree[i].blob = blob,
                    Err(i) => tree.insert(
                        i,
                        FileEntry {
                            path: edit.path.clone(),
                            blob,
                        },
                    ),
                },
                EditOp::Delete => {
                    if let Ok(i) = tree.binary_search_by(|f| f.path.cmp(&edit.path)) {
                        tree.remove(i);
                    }
                }
            }
        }
        Some(tree)
    }

    // ── Lookups (linear or binary depending on table) ─────────

    fn find_blob(state: &ProjectState, hash: &[u8; HASH_BYTES]) -> Option<usize> {
        state.blobs.binary_search_by(|b| b.hash.cmp(hash)).ok()
    }

    fn find_commit(state: &ProjectState, hash: &[u8; HASH_BYTES]) -> Option<usize> {
        for (i, c) in state.commits.iter().enumerate() {
            if commit_row_hash(c) == *hash {
                return Some(i);
            }
        }
        None
    }

    fn find_branch(state: &ProjectState, name: &str) -> Option<usize> {
        state
            .branches
            .binary_search_by(|b| b.name.as_str().cmp(name))
            .ok()
    }

    fn find_working(state: &ProjectState, change_id: &[u8; HASH_BYTES]) -> Option<usize> {
        state
            .working
            .binary_search_by(|w| w.change_id.cmp(change_id))
            .ok()
    }

    fn upsert_edit(change: &mut WorkingChange, path: &str, op: EditOp) {
        match change.edits.binary_search_by(|e| e.path.as_str().cmp(path)) {
            Ok(i) => change.edits[i].op = op,
            Err(i) => change.edits.insert(
                i,
                WorkingEdit {
                    path: path.to_string(),
                    op,
                },
            ),
        }
    }
}

// ── Pure helpers ─────────────────────────────────────────────────

fn bytes_to_32(b: &[u8]) -> Option<[u8; HASH_BYTES]> {
    if b.len() != HASH_BYTES {
        return None;
    }
    let mut out = [0u8; HASH_BYTES];
    out.copy_from_slice(b);
    Some(out)
}

/// Path validation — forward-slashes only, no leading slash, no
/// `..` segments, no embedded NULs. Cheap and stable; tighter
/// rules can land later.
fn is_valid_path(p: &str) -> bool {
    if p.is_empty() || p.starts_with('/') || p.contains('\\') || p.contains('\0') {
        return false;
    }
    for seg in p.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return false;
        }
    }
    true
}

/// Hash a commit row's canonical encoding. `change_id_used` is
/// the value we hash with even if the row's stored `change_id`
/// will be patched to equal the hash later (chicken-and-egg
/// otherwise). The protocol is: when the caller passes
/// `change_id == [0; 32]`, we hash with `[0; 32]` and then
/// store the resulting hash as the change_id; recomputing the
/// hash with the real `change_id` later would produce a
/// different value, so we deliberately don't.
fn commit_hash(row: &CommitNode, change_id_used: [u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    // Hand-roll a stable encoding: domain tag (via blake2b_hash's
    // own domain arg) + fixed fields + length-prefixed variable
    // fields. rkyv's serialised representation isn't promised to
    // be stable across versions, which would silently change
    // hashes on a rkyv upgrade.
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    buf.extend_from_slice(&row.parent);
    buf.extend_from_slice(&(row.extras.len() as u32).to_le_bytes());
    for e in &row.extras {
        buf.extend_from_slice(e);
    }
    buf.extend_from_slice(&(row.files.len() as u32).to_le_bytes());
    for f in &row.files {
        let pb = f.path.as_bytes();
        buf.extend_from_slice(&(pb.len() as u32).to_le_bytes());
        buf.extend_from_slice(pb);
        buf.extend_from_slice(&f.blob);
    }
    buf.extend_from_slice(&row.author);
    buf.extend_from_slice(&row.ts_ms.to_le_bytes());
    buf.push(row.intent_tag);
    buf.extend_from_slice(&(row.intent_data.len() as u32).to_le_bytes());
    buf.extend_from_slice(&row.intent_data);
    buf.extend_from_slice(&change_id_used);
    vos::crypto::blake2b_hash(b"vos-dev-project/commit/v1", &[&buf])
}

/// Re-hash a stored commit row, using its on-disk `change_id`.
/// Used to locate rows in `state.commits` by their canonical hash.
fn commit_row_hash(row: &CommitNode) -> [u8; HASH_BYTES] {
    // Two cases:
    // - Caller passed an explicit change_id: that's what was used
    //   when we hashed at commit-time, so use it here too.
    // - Caller passed empty: we patched change_id to the hash
    //   itself, but the hash was computed with change_id_used =
    //   [0; 32]. Re-hashing with [0; 32] reproduces it.
    //
    // Distinguishing the two cases without an extra flag: if the
    // stored change_id equals the hash you'd get by feeding
    // [0; 32], we're in the empty-caller case. Compute both and
    // pick. Cheap — two blake2b calls per lookup at this scale.
    let h_with_zero = commit_hash(row, [0u8; HASH_BYTES]);
    if row.change_id == h_with_zero {
        return h_with_zero;
    }
    commit_hash(row, row.change_id)
}

// ── Actor ─────────────────────────────────────────────────────────

#[actor]
pub struct DevProject {
    pub state: ProjectState,
}

#[messages]
impl DevProject {
    fn new(name: String) -> Self {
        Self {
            state: ProjectState {
                name,
                blobs: Vec::new(),
                commits: Vec::new(),
                branches: Vec::new(),
                working: Vec::new(),
            },
        }
    }

    // ── Reads ───────────────────────────────────────────────────

    #[msg]
    async fn head(&self, branch: String) -> Vec<u8> {
        store::head(&self.state, &branch)
    }

    #[msg]
    async fn get_commit(&self, hash: Vec<u8>) -> Option<CommitNode> {
        store::get_commit(&self.state, &hash)
    }

    #[msg]
    async fn get_blob(&self, hash: Vec<u8>) -> Option<BlobObject> {
        store::get_blob(&self.state, &hash)
    }

    #[msg]
    async fn log(&self, branch: String, limit: u32) -> Vec<u8> {
        store::log(&self.state, &branch, limit as usize)
    }

    #[msg]
    async fn list_branches(&self) -> Vec<String> {
        store::list_branches(&self.state)
    }

    // ── Writes ──────────────────────────────────────────────────

    #[msg]
    async fn put_blob(&mut self, bytes: Vec<u8>) -> Vec<u8> {
        store::put_blob(&mut self.state, bytes).to_vec()
    }

    /// Store a `BlobKind::RustAst` blob. Bytes are an rkyv-encoded
    /// `syn::File` produced host-side by `dev_ast::text_to_ast`;
    /// the compile path detects `kind == RustAst` on read and
    /// renders back to text via `ast_to_text` before invoking
    /// the compiler. Hash uses a distinct domain tag so the
    /// catalog distinguishes ASTs from raw bytes.
    #[msg]
    async fn put_blob_ast(&mut self, bytes: Vec<u8>) -> Vec<u8> {
        store::put_blob_with_kind(&mut self.state, bytes, BlobKind::RustAst).to_vec()
    }

    // ── Working changes (jj-style) ──────────────────────────────

    /// Open a new working change off `base` (32 bytes pointing
    /// at an existing commit, or empty for "no parent yet").
    /// Returns the minted `change_id`, which the agent then
    /// passes to subsequent `put_file_working` /
    /// `delete_file_working` / `commit_change` / `amend` calls.
    #[msg]
    async fn open_change(&mut self, base: Vec<u8>) -> HashResult {
        store::open_change(&mut self.state, &base)
    }

    /// Stage `path => blob_hash` on the working change.
    #[msg]
    async fn put_file_working(
        &mut self,
        change_id: Vec<u8>,
        path: String,
        blob_hash: Vec<u8>,
    ) -> u8 {
        store::put_file_working(&mut self.state, &change_id, &path, &blob_hash)
    }

    /// Mark `path` as deleted in the working change.
    #[msg]
    async fn delete_file_working(&mut self, change_id: Vec<u8>, path: String) -> u8 {
        store::delete_file_working(&mut self.state, &change_id, &path)
    }

    /// Materialise the working change's current tree (base
    /// commit's files overlaid with the change's edits).
    #[msg]
    async fn working_tree(&self, change_id: Vec<u8>) -> Option<Vec<FileEntry>> {
        store::working_tree(&self.state, &change_id)
    }

    /// Snapshot the working change as an immutable commit and
    /// advance `branch`. Returns the new commit's hash. The
    /// working change stays open jj-style — its `base` advances
    /// to the new commit, edits clear, so the agent can keep
    /// iterating without re-opening.
    #[msg]
    async fn commit_change(
        &mut self,
        change_id: Vec<u8>,
        branch: String,
        intent_tag: u8,
        intent_data: Vec<u8>,
        author: Vec<u8>,
        ts_ms: u64,
    ) -> HashResult {
        store::commit_change(
            &mut self.state,
            &change_id,
            &branch,
            intent_tag,
            intent_data,
            &author,
            ts_ms,
        )
    }

    /// Re-snapshot the working change under the same change_id
    /// with new ts_ms / intent. Advances the branch whose head
    /// equals the change's current base. `log` dedupes by
    /// change_id so only the latest snapshot surfaces.
    #[msg]
    async fn amend(
        &mut self,
        change_id: Vec<u8>,
        intent_tag: u8,
        intent_data: Vec<u8>,
        author: Vec<u8>,
        ts_ms: u64,
    ) -> HashResult {
        store::amend(
            &mut self.state,
            &change_id,
            intent_tag,
            intent_data,
            &author,
            ts_ms,
        )
    }

    /// Wire form of [`store::commit`]. Wire encoding for the file
    /// table: `paths` is one utf-8 path per file; `blob_hashes` is
    /// `32 * paths.len()` bytes (each blob hash concatenated).
    ///
    /// `parent` is 32 bytes (the current branch HEAD) or empty
    /// (root commit; branch must not yet exist). `change_id` is
    /// 32 bytes when the caller wants to associate this commit
    /// with an existing change, or empty to mint a fresh one
    /// (= the new commit's hash).
    #[allow(clippy::too_many_arguments)]
    #[msg]
    async fn commit(
        &mut self,
        parent: Vec<u8>,
        paths: Vec<String>,
        blob_hashes: Vec<u8>,
        branch: String,
        intent_tag: u8,
        intent_data: Vec<u8>,
        author: Vec<u8>,
        ts_ms: u64,
        change_id: Vec<u8>,
    ) -> HashResult {
        store::commit(
            &mut self.state,
            store::CommitInputs {
                parent: &parent,
                paths: &paths,
                blob_hashes: &blob_hashes,
                branch: &branch,
                intent_tag,
                intent_data,
                author: &author,
                ts_ms,
                change_id: &change_id,
            },
        )
    }
}
