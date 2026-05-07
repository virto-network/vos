//! `space agents` — list installed agents.

use space_registry::consistency_name;

use crate::commands::space::client::DaemonClient;

pub fn run(space: &str) -> anyhow::Result<()> {
    let client = DaemonClient::connect(space)?;
    let reg = client.registry();
    let agents = vos::block_on(reg.agents(&mut &*client.node()))
        .map_err(|e| anyhow::anyhow!("agents() failed: {e}"))?;

    if agents.is_empty() {
        println!("no agents installed. install one with `vosx space install <program>`.");
    } else {
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
    }

    client.shutdown()
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
