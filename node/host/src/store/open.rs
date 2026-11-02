//! Opening the store: what a crash left unsynced or unfinished mended
//! first, and its keyspace layout checked.

use super::*;

impl Fjall {
    /// Open the store at `path`, mended first ([`vos_exec::store::recover`]):
    /// everything it will recover synced.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_tuned(path, Tuning::default())
    }

    /// Open the store at `path` with `tuning`, as [`Fjall::open`] does.
    #[doc(hidden)]
    pub fn open_tuned(path: impl AsRef<Path>, tuning: Tuning) -> Result<Self> {
        vos_exec::store::recover(path.as_ref())?;
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
    /// under another layout, or that holds rows and names no layout, is
    /// refused with a [`LayoutMismatch`] rather than read as if its rows
    /// were where this build looks for them.
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
                "the store holds rows and names no layout, and this build reads layout {LAYOUT}"
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
