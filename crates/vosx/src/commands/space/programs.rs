//! `space programs` — list the program catalog.

use vos::abi::service::ServiceId;
use space_registry::SpaceRegistryRef;

use crate::commands::space::transient::TransientRegistry;

pub fn run(space: &str) -> anyhow::Result<()> {
    let reg_handle = TransientRegistry::boot(space)?;
    let reg = SpaceRegistryRef::at(ServiceId::REGISTRY);
    let programs = vos::block_on(reg.programs(&mut &*reg_handle.node()))
        .map_err(|e| anyhow::anyhow!("programs() failed: {e}"))?;

    if programs.is_empty() {
        println!("no programs in catalog. publish one with `vosx space publish`.");
    } else {
        println!("{:<20}  {:<12}  HASH", "NAME", "VERSION");
        for p in &programs {
            let short_hash: String = hex::encode(p.hash).chars().take(12).collect();
            println!("{:<20}  {:<12}  {short_hash}…", truncate(&p.name, 20), truncate(&p.version, 12));
        }
    }

    reg_handle.shutdown()
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
