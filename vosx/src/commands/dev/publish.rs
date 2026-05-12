//! `vosx dev publish` — drive the dev extension's `publish`
//! message to land a built actor in the space-registry catalog.

use serde::Serialize;
use vos::value::{Msg, Value};

use crate::commands::space::client::DaemonClient;
use crate::output;

const DEV_EXTENSION_NAME: &str = "dev";
/// Branch the dev extension records build commits on. Stays in
/// sync with the constant the extension's `compile_and_record`
/// uses.
const BUILDS_BRANCH: &str = "builds";

#[derive(Serialize)]
struct PublishedView<'a> {
    project: &'a str,
    program_name: &'a str,
    program_version: &'a str,
    publish_commit: String,
    status: u8,
}

pub struct Args {
    pub space: String,
    pub name: String,
    pub program_name: String,
    pub version: String,
    pub build_commit: Option<String>,
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

        // ── Resolve the build commit. Default: the project's
        //    `builds` branch head — i.e. the latest build attempt.
        let build_commit_bytes = match args.build_commit.as_deref() {
            Some(hex) => parse_hex32(hex)?,
            None => {
                let head = client
                    .invoke_dyn(project_id, &Msg::new("head").with("branch", BUILDS_BRANCH))?;
                let head_bytes = match head {
                    Value::Bytes(b) => b,
                    other => {
                        anyhow::bail!("project '{}' head returned non-bytes: {other:?}", args.name)
                    }
                };
                if head_bytes.is_empty() {
                    anyhow::bail!(
                        "project '{}' has no '{BUILDS_BRANCH}' branch — \
                         run `vosx dev compile` first or pass --build-commit",
                        args.name,
                    );
                }
                head_bytes
            }
        };

        let reply = client.invoke_dyn(
            extension_id,
            &Msg::new("publish")
                .with("project_id", project_id.0)
                .with("build_commit", build_commit_bytes)
                .with("name", args.program_name.clone())
                .with("version", args.version.clone()),
        )?;
        let (status, publish_commit) = decode_hash_result(reply)?;

        if status != 0 {
            anyhow::bail!(
                "dev publish failed (status={status}); see `vosx dev log --branch publishes {}` \
                 for the recording side, and the daemon logs for the registry-side error",
                args.name,
            );
        }

        let publish_commit_hex = hex::encode(&publish_commit);

        if output::is_json() {
            output::print_json(&PublishedView {
                project: &args.name,
                program_name: &args.program_name,
                program_version: &args.version,
                publish_commit: publish_commit_hex,
                status,
            });
        } else {
            println!("published {}:{}", args.program_name, args.version);
            println!("  publish_commit = {publish_commit_hex}");
            println!();
            println!(
                "next: `vosx space install {} {}:{}`",
                args.space, args.program_name, args.version,
            );
        }
        Ok(())
    })
}

fn parse_hex32(hex_str: &str) -> anyhow::Result<Vec<u8>> {
    let bytes =
        hex::decode(hex_str).map_err(|e| anyhow::anyhow!("--build-commit hex parse: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "--build-commit must be 64 hex chars (32 bytes), got {} bytes",
            bytes.len()
        );
    }
    Ok(bytes)
}

fn decode_hash_result(value: Value) -> anyhow::Result<(u8, Vec<u8>)> {
    let inner = match value {
        Value::Bytes(b) => b,
        other => anyhow::bail!("expected Value::Bytes, got {other:?}"),
    };
    let result = <dev_project::HashResult as vos::Decode>::try_decode(&inner)
        .ok_or_else(|| anyhow::anyhow!("dev extension reply not a valid HashResult"))?;
    Ok((result.status, result.hash))
}
