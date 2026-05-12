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
    /// Returned bytes are `limit * 32`-bounded (might be shorter
    /// when history is finite).
    pub fn log(state: &ProjectState, branch: &str, limit: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let Some(idx) = find_branch(state, branch) else {
            return out;
        };
        let mut cur = state.branches[idx].commit;
        let zero = [0u8; HASH_BYTES];
        while out.len() / HASH_BYTES < limit && cur != zero {
            out.extend_from_slice(&cur);
            let Some(ci) = find_commit(state, &cur) else {
                break;
            };
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
