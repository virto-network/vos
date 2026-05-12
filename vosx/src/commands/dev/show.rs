//! `vosx dev show` — inspect a project's tree at a given commit.
//!
//! Two shapes:
//!
//! - **Tree listing** (`vosx dev show --project P`): print one row
//!   per file at `head(main)` showing the path, blob hash prefix,
//!   and byte length. `--format json` emits a structured tree
//!   suitable for tooling and AI agents.
//! - **File content** (`vosx dev show --project P PATH`): print
//!   that one file's bytes to stdout. Pair with shell redirection
//!   to capture a file locally.
//!
//! Defaults to the project's `main` branch; `--branch` and
//! `--commit` override.
//!
//! Layered on the dev-project actor's `head` / `get_commit` /
//! `get_blob` handlers — no new wire surface required.

use std::io::Write as _;

use serde::Serialize;
use vos::Decode;
use vos::abi::service::ServiceId;
use vos::value::{Msg, Value};

use crate::commands::space::client::DaemonClient;
use crate::output;

#[derive(Serialize)]
struct TreeView<'a> {
    project: &'a str,
    branch: &'a str,
    commit: String,
    files: Vec<FileEntryView>,
}

#[derive(Serialize)]
struct FileEntryView {
    path: String,
    blob: String,
    size: usize,
}

pub struct Args {
    pub space: String,
    pub project: String,
    /// When set, dump just that file's content to stdout. When
    /// `None`, print the whole tree listing.
    pub path: Option<String>,
    pub branch: String,
    pub commit: Option<String>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    DaemonClient::with_connect(&args.space, |client| {
        let project_id = client.resolve_target(&args.project)?;

        // ── Resolve the commit hash. Priority: --commit > --branch head.
        let commit_bytes = match args.commit.as_deref() {
            Some(hex) => parse_hex32(hex)?,
            None => fetch_branch_head(client, project_id, &args.project, &args.branch)?,
        };

        // ── Fetch the commit + its file list.
        let commit = fetch_commit(client, project_id, &commit_bytes)?;

        match &args.path {
            Some(path) => show_file(client, project_id, &commit, path),
            None => show_tree(client, project_id, &args, &commit_bytes, &commit),
        }
    })
}

fn parse_hex32(hex_str: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = hex::decode(hex_str).map_err(|e| anyhow::anyhow!("--commit hex parse: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "--commit must be 64 hex chars (32 bytes), got {} bytes",
            bytes.len()
        );
    }
    Ok(bytes)
}

fn fetch_branch_head(
    client: &DaemonClient,
    project_id: ServiceId,
    project_name: &str,
    branch: &str,
) -> anyhow::Result<Vec<u8>> {
    let reply = client.invoke_dyn(
        project_id,
        &Msg::new("head").with("branch", branch.to_string()),
    )?;
    let bytes = match reply {
        Value::Bytes(b) => b,
        other => anyhow::bail!("project '{project_name}' head returned non-bytes: {other:?}"),
    };
    if bytes.is_empty() {
        anyhow::bail!(
            "project '{project_name}' has no '{branch}' branch yet — \
             either pass --commit, or commit something on that branch first"
        );
    }
    Ok(bytes)
}

fn fetch_commit(
    client: &DaemonClient,
    project_id: ServiceId,
    commit_hash: &[u8],
) -> anyhow::Result<dev_project::CommitNode> {
    let reply = client.invoke_dyn(
        project_id,
        &Msg::new("get_commit").with("hash", commit_hash.to_vec()),
    )?;
    let bytes = match reply {
        Value::Bytes(b) => b,
        Value::Unit => anyhow::bail!("get_commit returned Unit — commit not stored"),
        other => anyhow::bail!("get_commit returned {other:?}, expected Bytes"),
    };
    if bytes.is_empty() {
        anyhow::bail!("get_commit returned empty bytes — commit not stored");
    }
    <dev_project::CommitNode as Decode>::try_decode(&bytes)
        .ok_or_else(|| anyhow::anyhow!("get_commit reply isn't a valid CommitNode"))
}

/// Print the file's content. `path` must match a `FileEntry.path`
/// on the commit; otherwise error out so the operator notices.
fn show_file(
    client: &DaemonClient,
    project_id: ServiceId,
    commit: &dev_project::CommitNode,
    path: &str,
) -> anyhow::Result<()> {
    let entry = commit
        .files
        .iter()
        .find(|f| f.path == path)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "path '{path}' not in commit's tree. Run without a path \
                 to see the file list."
            )
        })?;

    let reply = client.invoke_dyn(
        project_id,
        &Msg::new("get_blob").with("hash", entry.blob.to_vec()),
    )?;
    let bytes = match reply {
        Value::Bytes(b) => b,
        Value::Unit => anyhow::bail!("get_blob returned Unit for {path} — blob not stored"),
        other => anyhow::bail!("get_blob returned {other:?}, expected Bytes"),
    };
    if bytes.is_empty() {
        anyhow::bail!("get_blob returned empty bytes for {path}");
    }
    let blob = <dev_project::BlobObject as Decode>::try_decode(&bytes)
        .ok_or_else(|| anyhow::anyhow!("get_blob reply for {path} isn't a valid BlobObject"))?;

    // RustAst blobs need rendering through dev-ast to be human-
    // readable. Until vosx grows a dependency on that crate, fail
    // loudly rather than dump rkyv-archived bytes to stdout.
    if !matches!(blob.kind, dev_project::BlobKind::Raw) {
        anyhow::bail!(
            "{path} is stored as a {:?} blob; only Raw blobs render through \
             `vosx dev show`. Use --commit on a raw-text commit, or wait for \
             vosx to grow AST rendering.",
            blob.kind,
        );
    }

    // Stream the bytes verbatim. Don't decode-and-println — the
    // caller may be capturing into a file (`> path.rs`) and any
    // utf-8 lossy conversion would silently corrupt non-text.
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&blob.bytes)?;
    Ok(())
}

/// Print the commit's file list. Text mode shows columns; JSON
/// mode emits a structured tree the agent / tooling layer can
/// consume. We fetch each blob to populate the size field — N+1
/// round trips, but on a local daemon over libp2p that's
/// sub-second for any realistic project. If projects grow large
/// enough to feel the round-trip cost, the actor can grow a
/// `tree(commit)` handler that returns sizes inline.
fn show_tree(
    client: &DaemonClient,
    project_id: ServiceId,
    args: &Args,
    commit_bytes: &[u8],
    commit: &dev_project::CommitNode,
) -> anyhow::Result<()> {
    let mut rows: Vec<FileEntryView> = Vec::with_capacity(commit.files.len());
    for f in &commit.files {
        let size = blob_size(client, project_id, &f.blob).unwrap_or(0);
        rows.push(FileEntryView {
            path: f.path.clone(),
            blob: hex::encode(f.blob),
            size,
        });
    }

    if output::is_json() {
        output::print_json(&TreeView {
            project: &args.project,
            branch: &args.branch,
            commit: hex::encode(commit_bytes),
            files: rows,
        });
    } else if rows.is_empty() {
        println!(
            "(no files in {} on '{}' @ {})",
            args.project,
            args.branch,
            &hex::encode(commit_bytes)[..16],
        );
    } else {
        println!(
            "tree @ {} (branch: {})",
            &hex::encode(commit_bytes)[..16],
            args.branch
        );
        for r in &rows {
            println!("  {:<40} {:>8}  {}", r.path, r.size, &r.blob[..16]);
        }
    }
    Ok(())
}

/// Fetch a blob and return its content length. Returns `None`
/// when the blob is missing or malformed — the tree listing
/// continues with size=0 in that case rather than aborting.
fn blob_size(client: &DaemonClient, project_id: ServiceId, hash: &[u8]) -> Option<usize> {
    let reply = client
        .invoke_dyn(
            project_id,
            &Msg::new("get_blob").with("hash", hash.to_vec()),
        )
        .ok()?;
    let bytes = match reply {
        Value::Bytes(b) if !b.is_empty() => b,
        _ => return None,
    };
    let blob = <dev_project::BlobObject as Decode>::try_decode(&bytes)?;
    Some(blob.bytes.len())
}
