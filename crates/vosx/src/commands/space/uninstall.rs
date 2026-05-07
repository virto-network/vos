//! `space uninstall` — tombstone an agent.

use vos::abi::service::ServiceId;
use space_registry::{SpaceRegistryRef, STATUS_NOT_FOUND, STATUS_OK};

use crate::commands::space::transient::TransientRegistry;

pub fn run(space: &str, instance: &str) -> anyhow::Result<()> {
    let reg_handle = TransientRegistry::boot(space)?;
    let reg = SpaceRegistryRef::at(ServiceId::REGISTRY);

    let status = vos::block_on(reg.uninstall(
        &mut &*reg_handle.node(),
        instance.to_string(),
    ))
    .map_err(|e| anyhow::anyhow!("uninstall() failed: {e}"))?;

    match status {
        STATUS_OK => println!("uninstalled {instance}"),
        STATUS_NOT_FOUND => anyhow::bail!("no agent named '{instance}' installed"),
        other => anyhow::bail!("uninstall returned status {other}"),
    }

    // TODO(phase 4): move per-agent redb to space_dir/trash/{instance}
    //   so the data is recoverable instead of left dangling.

    reg_handle.shutdown()
}
