//! `space programs` — list the program catalog.

use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::truncate;

pub fn run(space: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        let programs = client.programs()?;
        if programs.is_empty() {
            println!("no programs in catalog. publish one with `vosx space publish`.");
            return Ok(());
        }
        println!("{:<20}  {:<12}  HASH", "NAME", "VERSION");
        for p in &programs {
            let short_hash: String = hex::encode(p.hash).chars().take(12).collect();
            println!(
                "{:<20}  {:<12}  {short_hash}…",
                truncate(&p.name, 20),
                truncate(&p.version, 12),
            );
        }
        Ok(())
    })
}
