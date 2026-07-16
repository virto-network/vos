//! Small helpers for node-local secret files.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Atomically replace `path` with an owner-readable/writable file.
pub fn write_owner_only_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("secret path '{}' has no parent", path.display()))?;
    fs::create_dir_all(parent)?;

    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| anyhow::anyhow!("OS entropy for secret-file temporary name: {e}"))?;
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("secret path '{}' has no file name", path.display()))?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        hex::encode(nonce),
    ));

    let result = (|| -> anyhow::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn read_optional(path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn remove_if_exists(path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_only_file_round_trips_and_replaces() {
        let dir = std::env::temp_dir().join(format!(
            "vosx-secure-file-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test"),
        ));
        let path = dir.join("token");
        write_owner_only_atomic(&path, b"first").unwrap();
        write_owner_only_atomic(&path, b"second").unwrap();
        assert_eq!(read_optional(&path).unwrap(), Some(b"second".to_vec()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        remove_if_exists(&path).unwrap();
        assert_eq!(read_optional(&path).unwrap(), None);
        let _ = fs::remove_dir(&dir);
    }
}
