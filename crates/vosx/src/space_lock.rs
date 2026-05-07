//! Per-space exclusive file lock.
//!
//! A `space *` command that's about to mutate a space's redb
//! (publish, install, upgrade, uninstall, members, up, export,
//! …) acquires this lock first. Two concurrent invocations on
//! the same space will see the second fail loudly rather than
//! silently corrupting the registry's database.
//!
//! Implementation: `fs2::FileExt::try_lock_exclusive` on a
//! `<data_dir>/.vosx.lock` file. The OS releases the lock when
//! the process exits, so a crashed `vosx space up` doesn't
//! leave the space wedged.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use fs2::FileExt;

/// RAII guard. Drops the file → kernel releases the flock.
pub struct SpaceLock {
    /// Holding the file open keeps the flock alive.
    _file: File,
    /// Cached for diagnostics.
    #[allow(dead_code)]
    path: PathBuf,
}

impl SpaceLock {
    /// Acquire an exclusive lock on `<data_dir>/.vosx.lock`.
    /// Errors if another process already holds it.
    pub fn acquire(data_dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(data_dir).map_err(|e| {
            anyhow::anyhow!("create {} for lock: {e}", data_dir.display())
        })?;
        let path = data_dir.join(".vosx.lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| anyhow::anyhow!("open {}: {e}", path.display()))?;

        if let Err(e) = file.try_lock_exclusive() {
            anyhow::bail!(
                "another vosx process is using this space (lock at {} held). \
                 Stop it (Ctrl-C the running `space up`) or wait for it to \
                 finish, then try again. ({e})",
                path.display(),
            );
        }

        // Stamp the lock with PID for human diagnostics. Best-
        // effort — a write failure doesn't void the flock.
        let _ = std::io::Write::write_all(
            &mut (&file).try_clone().unwrap_or_else(|_| {
                File::open(&path).expect("re-open lock for stamp")
            }),
            format!("pid={}\n", std::process::id()).as_bytes(),
        );

        Ok(Self { _file: file, path })
    }
}
