//! Small helpers for node-local secret files.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

/// Read a bounded node-local secret without following aliases.
///
/// Existing secret files are accepted only when the named entry and opened
/// inode are the same owner-only regular file.  Returning `None` is reserved
/// for an absent path so create-on-first-use callers can distinguish absence
/// from an unsafe or malformed existing identity.
pub fn read_owner_only_optional(path: &Path, max_bytes: u64) -> anyhow::Result<Option<Vec<u8>>> {
    if max_bytes == 0 {
        anyhow::bail!("secret read bound must be nonzero");
    }
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("secret read bound is too large"))?;
    let named = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(anyhow::anyhow!(
                "inspect secret {}: {error}",
                path.display()
            ));
        }
    };
    validate_secret_metadata(path, &named, max_bytes)?;

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|error| anyhow::anyhow!("open secret {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| anyhow::anyhow!("inspect opened secret {}: {error}", path.display()))?;
    validate_secret_metadata(path, &opened, max_bytes)?;
    if !same_file(&named, &opened) {
        anyhow::bail!("secret changed while opening: {}", path.display());
    }

    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("read secret {}: {error}", path.display()))?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > max_bytes {
        anyhow::bail!("secret changed while reading: {}", path.display());
    }
    Ok(Some(bytes))
}

fn validate_secret_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    max_bytes: u64,
) -> anyhow::Result<()> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > max_bytes
    {
        anyhow::bail!(
            "secret must be a bounded real regular file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("secret permissions must be owner-only: {}", path.display());
        }
        if metadata.nlink() != 1 {
            anyhow::bail!("secret must not have hard-link aliases: {}", path.display());
        }
        // SAFETY: geteuid has no preconditions and reads process credentials.
        if metadata.uid() != unsafe { libc::geteuid() } {
            anyhow::bail!(
                "secret must be owned by the current user: {}",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino() && left.len() == right.len()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
}

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
        assert_eq!(
            read_owner_only_optional(&path, 16).unwrap(),
            Some(b"second".to_vec())
        );
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

    #[cfg(unix)]
    #[test]
    fn owner_only_reader_rejects_permission_and_link_aliases() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let dir = std::env::temp_dir().join(format!(
            "vosx-secure-file-hostile-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test"),
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity");
        write_owner_only_atomic(&path, b"secret").unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_owner_only_optional(&path, 16).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let hard = dir.join("hard-alias");
        fs::hard_link(&path, &hard).unwrap();
        assert!(read_owner_only_optional(&path, 16).is_err());
        fs::remove_file(&hard).unwrap();

        let symbolic = dir.join("symbolic-alias");
        symlink(&path, &symbolic).unwrap();
        assert!(read_owner_only_optional(&symbolic, 16).is_err());
        assert_eq!(
            read_owner_only_optional(&dir.join("absent"), 16).unwrap(),
            None
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
