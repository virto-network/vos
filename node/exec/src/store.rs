//! A fjall store opened after a crash: what the crash left unsynced or
//! unfinished mended first.

use std::path::Path;

/// Mend the store at `dir`, if it exists, before fjall opens it: a
/// creation cut short cleared, and everything it will recover synced, so
/// rows a crashed process left in the page cache cannot still be lost to a
/// power cut after the host relied on them. (This rests on fjall 3.1's
/// files: it syncs its tables and a journal before rotating it, so only
/// journals can hold unsynced rows. Re-check it on an upgrade.)
pub fn recover(dir: &Path) -> std::io::Result<()> {
    if dir.exists() {
        clear_unfinished(dir)?;
        sync_journals(dir)?;
    }
    Ok(())
}

/// Sync every journal file under `dir`, and the directories holding them.
fn sync_journals(dir: &Path) -> std::io::Result<()> {
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let mut journals = false;
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "jnl") {
                std::fs::File::open(&path)?.sync_all()?;
                journals = true;
            }
        }
        if journals {
            std::fs::File::open(&dir)?.sync_all()?;
        }
    }
    Ok(())
}

/// Clear a store fjall began creating and never finished: one whose
/// `version` marker, which fjall writes last, is missing or empty. Such a
/// store holds no data, but fjall takes it for a new one and its creation
/// fails on the journal or lock the interrupted creation left
/// (`AlreadyExists`), so a host killed during its store's creation could
/// never open it again. fjall's own entries (its journals, its lock, its
/// keyspaces' folder and the empty marker) are removed, and the directory
/// synced, so the creation starts over.
fn clear_unfinished(dir: &Path) -> std::io::Result<()> {
    let finished = std::fs::metadata(dir.join("version")).is_ok_and(|marker| marker.len() > 0);
    if finished {
        return Ok(());
    }
    let mut cleared = false;
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if name == "keyspaces" && path.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else if name == "lock"
            || name == "version"
            || path.extension().is_some_and(|extension| extension == "jnl")
        {
            std::fs::remove_file(&path)?;
        } else {
            continue;
        }
        cleared = true;
    }
    if cleared {
        tracing::warn!(?dir, "cleared a store whose creation was cut short");
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}
