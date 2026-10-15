//! `vos jam`: an agent as a JAM service, built and driven by its builder.

mod reference;
mod testnet;

use std::path::PathBuf;

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
                let blob = service_blob(&link(&elf)?, &metadata);
                std::fs::write(&out, &blob).map_err(at(&out))?;
                println!(
                    "{}: {} bytes, code hash {}",
                    out.display(),
                    blob.len(),
                    hex::encode(digest(&blob))
                );
                Ok(())
            }
            JamCommand::Testnet(args) => testnet::run(args),
        }
    }
}
