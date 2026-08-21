//! Cross-process ownership for one space's mutable data.
//!
//! The lock lives under the config root, keyed by the immutable space id,
//! rather than inside the data directory. A restore can therefore rename the
//! complete data directory while retaining the same lock inode, and a daemon
//! cannot enter between verification and activation.

use std::fs::{File, OpenOptions};
use std::path::PathBuf;

use fs2::FileExt;

pub(super) struct SpaceDataLock {
    _file: File,
}

impl SpaceDataLock {
    pub(super) fn exclusive(space_id: &[u8; 32]) -> anyhow::Result<Self> {
        Self::open(space_id, true)
    }

    pub(super) fn shared(space_id: &[u8; 32]) -> anyhow::Result<Self> {
        Self::open(space_id, false)
    }

    fn open(space_id: &[u8; 32], exclusive: bool) -> anyhow::Result<Self> {
        let path = lock_path(space_id);
        Self::open_path(&path, exclusive)
    }

    fn open_path(path: &std::path::Path, exclusive: bool) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| anyhow::anyhow!("create {}: {error}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|error| anyhow::anyhow!("open space data lock {}: {error}", path.display()))?;
        let acquired = if exclusive {
            FileExt::try_lock_exclusive(&file)
        } else {
            FileExt::try_lock_shared(&file)
        };
        acquired.map_err(|error| {
            anyhow::anyhow!(
                "space data is in use (lock {}): {error}; stop `space up` before backup or restore",
                path.display(),
            )
        })?;
        Ok(Self { _file: file })
    }
}

fn lock_path(space_id: &[u8; 32]) -> PathBuf {
    crate::paths::config_root()
        .join("locks")
        .join(format!("{}.lock", hex::encode(space_id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_owner_blocks_shared_and_second_exclusive_owner() {
        let path = std::env::temp_dir().join(format!(
            "vosx-space-lock-{}-{}.lock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let owner = SpaceDataLock::open_path(&path, true).unwrap();
        assert!(SpaceDataLock::open_path(&path, false).is_err());
        assert!(SpaceDataLock::open_path(&path, true).is_err());
        drop(owner);
        assert!(SpaceDataLock::open_path(&path, false).is_ok());
        let _ = std::fs::remove_file(path);
    }
}
