//! `space programs` — list the program catalog.

use serde::Serialize;

use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::truncate;
use crate::output;

#[derive(Serialize)]
struct ProgramView<'a> {
    name: &'a str,
    hash: String,
    crdt: bool,
}

pub fn run(space: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        let programs = client.programs()?;
        if output::is_json() {
            let view: Vec<ProgramView> = programs
                .iter()
                .map(|p| ProgramView {
                    name: &p.name,
                    hash: hex::encode(p.hash),
                    crdt: p.crdt,
                })
                .collect();
            output::print_json(&view);
            return Ok(());
        }
        if programs.is_empty() {
            println!("no programs in catalog. publish one with `vosx space publish`.");
            return Ok(());
        }
        println!("{:<20}  {:<5}  HASH", "NAME", "CRDT");
        for p in &programs {
            let short_hash: String = hex::encode(p.hash).chars().take(12).collect();
            println!(
                "{:<20}  {:<5}  {short_hash}…",
                truncate(&p.name, 20),
                if p.crdt { "yes" } else { "no" },
            );
        }
        Ok(())
    })
}
