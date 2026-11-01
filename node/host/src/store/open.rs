//! Opening the store: what a crash left unsynced or unfinished mended
//! first, and its keyspace layout checked.

use super::*;

/// Sync every journal file under `dir`, and the directories holding them.
fn sync_journals(dir: &Path) -> Result<()> {
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
/// (`AlreadyExists`), so a node killed during its store's creation could
/// never open it again. fjall's own entries (its journals, its lock, its
/// keyspaces' folder and the empty marker) are removed, and the directory
/// synced, so the creation starts over.
fn clear_unfinished(dir: &Path) -> Result<()> {
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

impl Fjall {
    /// Open the store at `path`. Everything it will recover is synced
    /// first: rows a crashed process left in the page cache could otherwise
    /// still be lost to a power cut after the node relied on them. (This
    /// rests on fjall 3.1's files: it syncs its tables and a journal before
    /// rotating it, so only journals can hold unsynced rows. Re-check it on
    /// an upgrade.)
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_tuned(path, Tuning::default())
    }

    /// Open the store at `path` with `tuning`, as [`Fjall::open`] does.
    #[doc(hidden)]
    pub fn open_tuned(path: impl AsRef<Path>, tuning: Tuning) -> Result<Self> {
        if path.as_ref().exists() {
            clear_unfinished(path.as_ref())?;
            sync_journals(path.as_ref())?;
        }
        let db = Database::builder(path.as_ref())
            .cache_size(tuning.cache_bytes)
            .open()?;
        let store = Self(Arc::new(Partitions {
            state: db.keyspace("state", || tuning.rows())?,
            // System keys are looked up for session indexes and replies
            // that are often absent: keep the filters that answer misses
            // cheaply.
            system: db.keyspace("system", KeyspaceCreateOptions::default)?,
            log: db.keyspace("log", KeyspaceCreateOptions::default)?,
            blobs: db.keyspace("blobs", KeyspaceCreateOptions::default)?,
            db,
        }));
        store.check_layout()?;
        Ok(store)
    }

    /// Check the store's layout row against [`LAYOUT`], writing it, synced,
    /// to a store that holds no rows yet. A store whose rows were written
    /// under another layout, or that holds rows and names no layout (it
    /// was written before layouts were numbered), is refused with a
    /// [`LayoutMismatch`] rather than read as if its rows were where this
    /// build looks for them.
    fn check_layout(&self) -> Result<()> {
        let key = node_record(NodeRow::Layout, &[]);
        let found = match self.system().get(&key)? {
            Some(value) => Some(
                <[u8; 4]>::try_from(&value[..])
                    .map(u32::from_be_bytes)
                    .map_err(|_| LayoutMismatch::refuse(Layout::Unreadable))?,
            ),
            None => None,
        };
        match found {
            Some(LAYOUT) => Ok(()),
            Some(layout) => Err(LayoutMismatch::refuse(Layout::Other(layout))),
            None if self.holds_nothing()? => {
                self.system().insert(key, LAYOUT.to_be_bytes())?;
                self.database().persist(PersistMode::SyncAll)
            }
            None => Err(LayoutMismatch::refuse(Layout::Unnamed)),
        }
    }

    fn holds_nothing(&self) -> Result<bool> {
        for partition in [self.state(), self.system(), self.log(), self.blobs()] {
            if !partition.is_empty()? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// What a refused store's layout row says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// A layout other than [`LAYOUT`].
    Other(u32),
    /// No layout row, in a store that holds rows.
    Unnamed,
    /// A layout row that is not a number.
    Unreadable,
}

/// A store refused at open: its rows are laid out other than this build
/// reads them. It reaches the caller as an [`Error::Io`] of kind
/// `InvalidData` carrying this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayoutMismatch {
    pub found: Layout,
}

impl LayoutMismatch {
    fn refuse(found: Layout) -> Error {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            Self { found },
        ))
    }

    /// The mismatch an open refused with, if that is why it failed.
    pub fn of(error: &Error) -> Option<Self> {
        match error {
            Error::Io(inner) => inner.get_ref()?.downcast_ref::<Self>().copied(),
            _ => None,
        }
    }

    /// `error` as an operator reads it: the mismatch's account when an
    /// open refused the store's layout, its `Debug` otherwise.
    pub fn shown(error: &Error) -> String {
        Self::of(error).map_or_else(|| format!("{error:?}"), |mismatch| mismatch.to_string())
    }
}

impl std::fmt::Display for LayoutMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.found {
            Layout::Other(layout) => write!(
                f,
                "the store is laid out as layout {layout} and this build reads layout {LAYOUT}"
            ),
            Layout::Unnamed => write!(
                f,
                "the store holds rows and names no layout: it was written before \
                 layouts were numbered, and this build reads layout {LAYOUT}"
            ),
            Layout::Unreadable => write!(f, "the store's layout row is unreadable"),
        }?;
        f.write_str(
            "; move the store aside to start a new one, which discards the node's secret, \
             the key its venue lists",
        )
    }
}

impl std::error::Error for LayoutMismatch {}
