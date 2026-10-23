//! `vos-jam-dev`'s commands: an agent as a JAM service, built and driven by
//! its builder, and the JAM statements service deployed and driven.

mod reference;
mod statements;
mod testnet;

use std::path::{Path, PathBuf};

use clap::Subcommand;
use vos_pvm_compiler::{ServiceMetadata, service_blob};
use vos_wire::result::digest;

use crate::{at, link};

#[derive(Subcommand)]
pub enum JamCommand {
    /// Link a program as a JAM service's code blob, its metadata first.
    Service {
        #[arg(long)]
        elf: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "vos-agent")]
        name: String,
    },
    /// Run the agent as a service on a running PolkaJam testnet: every
    /// package checked against the chain and a VOS node, and recorded.
    Testnet(testnet::TestnetArgs),
    /// Deploy the JAM statements service on a running PolkaJam testnet and
    /// drive it: a 256 KiB extrinsic, a space registered and anchored, the
    /// golden fixtures' masked statements, a migration and an
    /// equivocation, each outcome read back and recorded.
    Statements(statements::StatementsArgs),
}

/// The service's metadata, as PolkaJam names services by it.
const METADATA: ServiceMetadata<'static> = ServiceMetadata {
    name: "vos-agent",
    version: env!("CARGO_PKG_VERSION"),
    license: "AGPL-3.0-or-later",
    authors: &["VOS"],
};

impl JamCommand {
    pub fn run(self) -> Result<(), String> {
        match self {
            JamCommand::Service { elf, out, name } => {
                let metadata = ServiceMetadata {
                    name: &name,
                    ..METADATA
                };
                let blob = write_service(&link(&elf)?, &metadata, &out)?;
                println!(
                    "{}: {} bytes, code hash {}",
                    out.display(),
                    blob.len(),
                    hex::encode(digest(&blob))
                );
                Ok(())
            }
            JamCommand::Testnet(args) => testnet::run(args),
            JamCommand::Statements(args) => statements::run(args),
        }
    }
}

/// `code` linked as a JAM service's code blob, its metadata first,
/// written to `out`: the blob.
fn write_service(code: &[u8], metadata: &ServiceMetadata, out: &Path) -> Result<Vec<u8>, String> {
    let blob = service_blob(code, metadata);
    std::fs::write(out, &blob).map_err(at(out))?;
    Ok(blob)
}
