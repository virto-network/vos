//! `space agents` — list installed agents.

use serde::Serialize;
use space_registry::consistency_name;

use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::truncate;
use crate::output;

#[derive(Serialize)]
struct AgentView<'a> {
    instance_name: &'a str,
    program_name: &'a str,
    program_version: &'a str,
    program_hash: String,
    replication_id: String,
    consistency: &'static str,
}

pub fn run(space: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        let agents = client.agents()?;
        if output::is_json() {
            let view: Vec<AgentView> = agents
                .iter()
                .map(|a| AgentView {
                    instance_name: &a.instance_name,
                    program_name: &a.program_name,
                    program_version: &a.program_version,
                    program_hash: hex::encode(a.program_hash),
                    replication_id: hex::encode(a.replication_id),
                    consistency: consistency_name(a.consistency),
                })
                .collect();
            output::print_json(&view);
            return Ok(());
        }
        if agents.is_empty() {
            println!("no agents installed. install one with `vosx space install <program>`.");
            return Ok(());
        }
        println!(
            "{:<20}  {:<20}  {:<10}  REPLICATION",
            "NAME", "PROGRAM", "MODE",
        );
        for a in &agents {
            let prog = format!("{}:{}", a.program_name, a.program_version);
            let short_rep: String = hex::encode(a.replication_id).chars().take(12).collect();
            println!(
                "{:<20}  {:<20}  {:<10}  {short_rep}…",
                truncate(&a.instance_name, 20),
                truncate(&prog, 20),
                consistency_name(a.consistency),
            );
        }
        Ok(())
    })
}
