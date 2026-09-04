//! `space programs` — list the program catalog.

use serde::Serialize;
use vos::registry::{ProgramKind, ProgramRow};

use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::truncate;
use crate::output;

#[derive(Serialize)]
struct ProgramView<'a> {
    name: &'a str,
    hash: String,
    publication_id: String,
    kind: &'static str,
    crdt: Option<bool>,
}

fn program_kind(row: &ProgramRow) -> (&'static str, Option<bool>) {
    match &row.kind {
        ProgramKind::Service { crdt } => ("service", Some(*crdt)),
        ProgramKind::AgentActor => ("agent-actor", None),
    }
}

pub fn run(space: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        let programs = client.programs()?;
        if output::is_json() {
            let view: Vec<ProgramView> = programs
                .iter()
                .map(|row| {
                    let (kind, crdt) = program_kind(row);
                    ProgramView {
                        name: &row.name,
                        hash: hex::encode(row.hash),
                        publication_id: hex::encode(row.publication_id.as_bytes()),
                        kind,
                        crdt,
                    }
                })
                .collect();
            output::print_json(&view);
            return Ok(());
        }
        if programs.is_empty() {
            println!("no programs in catalog. publish one with `vosx space publish`.");
            return Ok(());
        }
        println!("{:<20}  {:<11}  {:<5}  HASH", "NAME", "KIND", "CRDT");
        for row in &programs {
            let short_hash: String = hex::encode(row.hash).chars().take(12).collect();
            let (kind, crdt) = program_kind(row);
            println!(
                "{:<20}  {:<11}  {:<5}  {short_hash}…",
                truncate(&row.name, 20),
                kind,
                match crdt {
                    Some(true) => "yes",
                    Some(false) => "no",
                    None => "—",
                },
            );
        }
        Ok(())
    })
}
