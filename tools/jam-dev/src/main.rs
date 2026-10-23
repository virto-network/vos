//! `vos-jam-dev`: JAM as VOS's development and test recipes drive it
//! (`testnet.sh`): a program linked as a JAM service's blob, the default
//! agent run as a service on a PolkaJam testnet, and the JAM statements
//! service deployed and driven there. No VOS node runs it.

mod command;

use std::fmt::Display;
use std::path::Path;
use std::process::ExitCode;

use clap::Parser;

use command::JamCommand;

#[derive(Parser)]
#[command(name = "vos-jam-dev", version)]
struct Cli {
    #[command(subcommand)]
    command: JamCommand,
}

fn main() -> ExitCode {
    match Cli::parse().command.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vos-jam-dev: {error}");
            ExitCode::FAILURE
        }
    }
}

/// A standard program from an ELF built with the guest toolchain.
fn link(path: &Path) -> Result<Vec<u8>, String> {
    let elf = std::fs::read(path).map_err(at(path))?;
    vos_pvm_compiler::link_elf_spi(&elf).map_err(|error| format!("{}: {error:?}", path.display()))
}

/// An error with the file at `path`, as `map_err` takes it.
fn at<E: Display>(path: &Path) -> impl FnOnce(E) -> String {
    move |error| format!("{}: {error}", path.display())
}
