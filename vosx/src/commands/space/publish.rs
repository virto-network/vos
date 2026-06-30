//! `space publish` — add a program to the catalog.

use serde::Serialize;
use space_registry::{Status};

use crate::blob_store::{self, BlobSource};
use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::parse_program_ref;
use crate::output;

#[derive(Serialize)]
struct PublishedView {
    name: String,
    version: String,
    hash: String,
}

pub struct Args {
    pub space: String,
    pub program_ref: String, // "name" or "name:version"
    pub source: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let (name, version) = parse_program_ref(&args.program_ref)?;

    // Resolve and cache the blob bytes locally.
    let source = BlobSource::parse(&args.source);
    let (hash, _bytes) = blob_store::resolve(&source).map_err(|e| anyhow::anyhow!("blob: {e}"))?;

    DaemonClient::with_connect(&args.space, |client| {
        let status = client.publish(name.clone(), version.clone(), hash.0.to_vec())?;
        match status {
            Status::Ok => {
                if output::is_json() {
                    output::print_json(&PublishedView {
                        name: name.clone(),
                        version: version.clone(),
                        hash: hash.to_hex(),
                    });
                } else {
                    println!("published {name}:{version}");
                    println!("  hash = {hash}");
                }
                Ok(())
            }
            Status::TagConflict => anyhow::bail!(
                "{name}:{version} already exists in the catalog with a different hash; \
                 tags are immutable",
            ),
            other => anyhow::bail!("publish returned status {other}"),
        }
    })
}
