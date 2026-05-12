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

        if status != 0 {
            anyhow::bail!(
                "dev compile failed (status={status}); the dev extension recorded the attempt \
                 daemon-side — check `vosx dev log --branch builds {}` for details",
                args.name,
            );
        }

        let source_commit_hex = hex::encode(&source_commit_bytes);
        let build_commit_hex = hex::encode(&build_commit);

        if output::is_json() {
            output::print_json(&CompiledView {
                project: &args.name,
                source_commit: source_commit_hex,
                build_commit: build_commit_hex,
                status,
            });
        } else {
            println!("compiled {} @ {}", args.name, &source_commit_hex[..16]);
            println!("  build_commit = {build_commit_hex}");
        }
        Ok(())
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
