//! `vosx dev log` — surface a project's commit graph along a
//! chosen branch. The dev-project actor exposes a `log(branch,
//! limit)` handler that walks `parent` pointers newest-first;
//! this command just decorates the output.

use serde::Serialize;
use vos::value::{Msg, Value};

use crate::commands::space::client::DaemonClient;
use crate::output;

/// Per-row hash size from the dev-project actor's `log()` reply.
const HASH_BYTES: usize = 32;

#[derive(Serialize)]
struct LogView<'a> {
    project: &'a str,
    branch: &'a str,
    commits: Vec<String>,
}

pub struct Args {
    pub space: String,
    pub name: String,
    pub branch: String,
    pub limit: u32,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    DaemonClient::with_connect(&args.space, |client| {
        let project_id = client.resolve_target(&args.name)?;

        let reply = client.invoke_dyn(
            project_id,
            &Msg::new("log")
                .with("branch", args.branch.clone())
                .with("limit", args.limit),
        )?;
        let bytes = match reply {
            Value::Bytes(b) => b,
            other => anyhow::bail!("project '{}' log returned non-bytes: {other:?}", args.name),
        };

        let mut hashes: Vec<String> = Vec::with_capacity(bytes.len() / HASH_BYTES);
        let mut off = 0;
        while off + HASH_BYTES <= bytes.len() {
            hashes.push(hex::encode(&bytes[off..off + HASH_BYTES]));
            off += HASH_BYTES;
        }

        if output::is_json() {
            output::print_json(&LogView {
                project: &args.name,
                branch: &args.branch,
                commits: hashes,
            });
        } else if hashes.is_empty() {
            println!("(branch '{}' is empty or doesn't exist)", args.branch);
        } else {
            for h in &hashes {
                println!("{}", &h[..16]);
            }
        }
        Ok(())
    })
}
