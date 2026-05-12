//! `vosx dev compile` — drive the dev extension's `compile`
//! message against a project's commit.
//!
//! Resolves the project's instance ServiceId on the daemon's
//! node, fetches the current head of the source branch (or uses
//! `--commit`), invokes the dev extension's `compile` handler,
//! and surfaces the build commit hash (or a status code for
//! transport/recording errors). Cargo stderr from a failed build
//! is logged daemon-side and persisted to the build commit's
//! `intent.artifact` blob; this CLI doesn't try to re-render it.

use dev_project::{BuildIntent, CommitNode};
use serde::Serialize;
use vos::value::{Msg, Value};

use crate::commands::space::client::DaemonClient;
use crate::output;

/// Source branch the dev-project actor exposes for the project's
/// editable tree. `main` mirrors the convention agents use when
/// publishing source edits.
const SOURCE_BRANCH: &str = "main";

/// Default name the manifest reconciler installs the dev
/// extension under. Stays a const so the CLI can find the
/// dispatch target deterministically; an operator who renamed
/// the extension instance has to pass `--extension`, which we
/// don't surface yet (Phase 1.5 leaves it for a follow-up).
const DEV_EXTENSION_NAME: &str = "dev";

#[derive(Serialize)]
struct CompiledView<'a> {
    project: &'a str,
    source_commit: String,
    build_commit: String,
    artifact_hash: String,
    status: u8,
}

pub struct Args {
    pub space: String,
    pub name: String,
    pub commit: Option<String>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    DaemonClient::with_connect(&args.space, |client| {
        let project_id = client.resolve_target(&args.name)?;
        let extension_id = client.resolve_target(DEV_EXTENSION_NAME).map_err(|_| {
            anyhow::anyhow!(
                "no '{DEV_EXTENSION_NAME}' extension loaded in this space — \
                 add `[[extension]] name = \"{DEV_EXTENSION_NAME}\"` to the \
                 space's manifest and restart `vosx space up`"
            )
        })?;

        // ── Resolve the source commit to build. If the operator
        //    passed --commit, parse + validate; otherwise fetch
        //    the project's `main` branch head.
        let source_commit_bytes = match args.commit.as_deref() {
            Some(hex) => parse_hex32(hex)?,
            None => {
                let head = client
                    .invoke_dyn(project_id, &Msg::new("head").with("branch", SOURCE_BRANCH))?;
                let head_bytes = match head {
                    Value::Bytes(b) => b,
                    other => {
                        anyhow::bail!("project '{}' head returned non-bytes: {other:?}", args.name)
                    }
                };
                if head_bytes.is_empty() {
                    anyhow::bail!(
                        "project '{}' has no '{SOURCE_BRANCH}' branch yet — commit source \
                         first or pass --commit",
                        args.name,
                    );
                }
                head_bytes
            }
        };

        // ── Invoke the extension's compile handler.
        let reply = client.invoke_dyn(
            extension_id,
            &Msg::new("compile")
                .with("project_id", project_id.0)
                .with("commit", source_commit_bytes.clone()),
        )?;
        let (status, build_commit) = decode_hash_result(reply)?;

        // First check the outer HashResult: COMPILE_STATUS_RECORD_FAILED
        // / transport errors land here, distinct from "compile ran but
        // cargo failed".
        if status != 0 {
            anyhow::bail!(
                "dev compile failed (status={status}); the dev extension recorded the attempt \
                 daemon-side — check `vosx dev log --branch builds {}` for details",
                args.name,
            );
        }
        if build_commit.len() != 32 {
            anyhow::bail!(
                "dev compile returned status=0 but build commit isn't 32 bytes ({} bytes); \
                 inspect the daemon log",
                build_commit.len(),
            );
        }

        // Second check: fetch the build commit and inspect the
        // BuildIntent.ok flag. status=0 + intent.ok=0 means the
        // compile pipeline recorded a failure attempt cleanly —
        // the cargo run itself produced a non-zero exit. Surface
        // as an error to the CLI caller; the stderr blob lives on
        // the commit (`vosx dev log --branch builds <name>` walks
        // it) and is already in the daemon's stderr too.
        let intent = fetch_build_intent(client, project_id, &build_commit).map_err(|e| {
            anyhow::anyhow!(
                "dev compile recorded build commit {} but couldn't read it back: {e}",
                hex::encode(&build_commit),
            )
        })?;
        if intent.ok != 1 {
            // intent.ok=0 covers everything compile_and_record
            // recorded as a failure: cargo's own non-zero exit,
            // dep-resolution failures (cycle, pin conflict, dep
            // not found), transpile rejections, missing source
            // commits. The stderr blob on the commit carries the
            // specific reason — surface its hash so the operator
            // can fetch it via `vosx dev log` once that surfaces
            // blob content (today they grep the daemon stderr).
            anyhow::bail!(
                "compile failed for '{}'; see daemon stderr or `vosx dev log --branch builds {}` \
                 (failure detail blob = {})",
                args.name,
                args.name,
                hex::encode(intent.artifact),
            );
        }

        let source_commit_hex = hex::encode(&source_commit_bytes);
        let build_commit_hex = hex::encode(&build_commit);
        let artifact_hex = hex::encode(intent.artifact);

        if output::is_json() {
            output::print_json(&CompiledView {
                project: &args.name,
                source_commit: source_commit_hex,
                build_commit: build_commit_hex,
                artifact_hash: artifact_hex,
                status,
            });
        } else {
            println!("compiled {} @ {}", args.name, &source_commit_hex[..16]);
            println!("  build_commit = {build_commit_hex}");
        }
        Ok(())
    })
}

/// Fetch a build commit and decode its BuildIntent. Used after a
/// successful outer HashResult to distinguish "compile recorded
/// cargo failure" from "compile succeeded".
fn fetch_build_intent(
    client: &DaemonClient,
    project_id: vos::abi::service::ServiceId,
    build_commit: &[u8],
) -> anyhow::Result<BuildIntent> {
    let reply = client.invoke_dyn(
        project_id,
        &Msg::new("get_commit").with("hash", build_commit.to_vec()),
    )?;
    let bytes = match reply {
        Value::Bytes(b) => b,
        Value::Unit => anyhow::bail!("get_commit returned Unit — build commit not stored"),
        other => anyhow::bail!("get_commit returned {other:?}"),
    };
    if bytes.is_empty() {
        anyhow::bail!("get_commit returned empty bytes — build commit not stored");
    }
    let commit = <CommitNode as vos::Decode>::try_decode(&bytes)
        .ok_or_else(|| anyhow::anyhow!("get_commit reply isn't a valid CommitNode"))?;
    <BuildIntent as vos::Decode>::try_decode(&commit.intent_data)
        .ok_or_else(|| anyhow::anyhow!("build commit's intent_data isn't a valid BuildIntent"))
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

/// Decode the `Value::Bytes(rkyv(HashResult))` shape every dev-
/// extension reply uses. Returns `(status, hash_bytes)`.
fn decode_hash_result(value: Value) -> anyhow::Result<(u8, Vec<u8>)> {
    let inner = match value {
        Value::Bytes(b) => b,
        other => anyhow::bail!("expected Value::Bytes, got {other:?}"),
    };
    let result = <dev_project::HashResult as vos::Decode>::try_decode(&inner)
        .ok_or_else(|| anyhow::anyhow!("dev extension reply not a valid HashResult"))?;
    Ok((result.status, result.hash))
}
