//! The node's blob store: content-addressed blobs (BLAKE2b-256) too large
//! for the log, and every program.
//!
//! Blobs are appended to segment files by the blob writer, its own thread,
//! a group at a time with one data sync, then indexed. A segment closes at
//! [`SEGMENT_BYTES`]; a new one is created with a directory sync, once per
//! segment. A record is a header (magic, length, hash) and the bytes.
//!
//! The index (hash to segment, offset, length and when it was last put) is
//! the `blobs` partition of the node's keyspace, written without a sync
//! after the segment's. So a blob is durable once indexed, and on open the
//! store reads each segment past its last indexed record: it syncs the
//! segment, rehashes the records there, indexes the whole ones and cuts the
//! segment at the first that is not. The journal recovers a prefix and the
//! writer indexes in order, so only a segment's tail can be unindexed.
//!
//! A blob lives while a log row names it, a pin or a hold keeps it, or it
//! was put or touched within its horizon; [`Blobs::collect`] removes the
//! rest. Its horizon is the one for how it is kept ([`Keep`]).

mod collect;
mod index;
mod segment;
#[cfg(test)]
mod tests;
mod writer;

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread::JoinHandle;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use fjall::{Keyspace, PersistMode};

use crate::lock;
use crate::store::{BlobRef, Fjall, Result};

pub use collect::{Collected, Horizons};
pub(crate) use index::{IndexRow, pin_key};
use index::{Location, location_key};
use segment::{Current, create_segment, forget_missing_segments, recover, segment_path, sync_dir};
use writer::{Answer, Put, Request, Writer};

/// A segment closes once a record would take it past this many bytes.
pub const SEGMENT_BYTES: u64 = 256 << 20;
/// What a put waits behind at most: a guard, as the log writer's cap is.
const GROUP_BYTES: usize = 64 << 20;
const MAGIC: [u8; 4] = *b"VOSB";
/// Segments kept open for reads at once.
const OPEN_SEGMENTS: usize = 64;
const HEADER: u64 = 4 + 8 + 32;

/// The blob's reference: its hash and length.
pub fn blob_ref(bytes: &[u8]) -> BlobRef {
    BlobRef {
        hash: vos_pvm::precompile::blake2b_256(bytes),
        len: bytes.len() as u64,
    }
}

/// Milliseconds since the epoch: the wall clock as the process started,
/// moved on by the monotonic clock since, so a clock jumping during a run
/// ages no blob past the horizon. A put's time, for the horizon only.
fn now() -> u64 {
    static START: OnceLock<(u64, Instant)> = OnceLock::new();
    let (wall, at) = START.get_or_init(|| {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis() as u64);
        (wall, Instant::now())
    });
    wall + at.elapsed().as_millis() as u64
}

/// Which horizon a blob's age keeps it for once no log row names it and no
/// pin or hold keeps it: blobs differ in how soon a row comes to name them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Keep {
    /// A row names it from its first moments: a large work result, held
    /// from its put until its entry is written, or a blob a replica fetches
    /// for an entry it wrote first. Its brief horizon lets it go soon after
    /// the log is compacted past the entry.
    Named = 0,
    /// A row comes to name it only later: a program stored for an install
    /// still queued, or fetched for a snapshot this replica stages.
    Aged = 1,
}

impl Keep {
    /// The keep `byte` names; one this build does not know, the longer.
    fn from_u8(byte: u8) -> Self {
        match byte {
            0 => Self::Named,
            _ => Self::Aged,
        }
    }
}

/// The blobs held, each with how many holds it has.
#[derive(Clone, Default)]
struct Holds(Arc<Mutex<HashMap<[u8; 32], usize>>>);

impl Holds {
    fn contains(&self, hash: &[u8; 32]) -> bool {
        lock(&self.0).contains_key(hash)
    }
}

/// A hold on a blob: no collection removes it while this lives, whatever
/// its age.
pub struct Held {
    holds: Holds,
    hash: [u8; 32],
}

impl Drop for Held {
    fn drop(&mut self) {
        let mut holds = lock(&self.holds.0);
        if let Some(count) = holds.get_mut(&self.hash) {
            *count -= 1;
            if *count == 0 {
                holds.remove(&self.hash);
            }
        }
    }
}

struct Inner {
    dir: PathBuf,
    store: Fjall,
    index: Keyspace,
    sender: Mutex<Option<mpsc::Sender<Request>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    /// One collection at a time.
    collecting: smol::lock::Mutex<()>,
    /// Open segments, for reads.
    files: Mutex<HashMap<u64, Arc<File>>>,
    holds: Holds,
}

impl Drop for Inner {
    fn drop(&mut self) {
        lock(&self.sender).take();
        if let Some(thread) = lock(&self.thread).take() {
            let _ = thread.join();
        }
    }
}

/// The node's blob store. Clones share it.
#[derive(Clone)]
pub struct Blobs {
    inner: Arc<Inner>,
}

impl Blobs {
    /// Open the blob store in `dir`, indexing into `store`.
    pub fn open(dir: impl AsRef<Path>, store: &Fjall) -> Result<Self> {
        Self::open_with(dir, store, SEGMENT_BYTES)
    }

    /// As [`Self::open`], closing segments at `segment_bytes`.
    pub fn open_with(dir: impl AsRef<Path>, store: &Fjall, segment_bytes: u64) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        sync_dir(&dir)?;
        let index = store.blobs().clone();
        let mut segments: Vec<u64> = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let name = entry?.file_name();
            if let Some(segment) = name.to_str().and_then(|name| name.parse().ok()) {
                segments.push(segment);
            }
        }
        segments.sort_unstable();
        let mut batch = store.database().batch();
        let mut recovered = (0, None);
        for &segment in &segments {
            recovered = recover(&dir, &index, &mut batch, segment)?;
        }
        forget_missing_segments(&index, &mut batch, &segments)?;
        batch.durability(Some(PersistMode::SyncAll)).commit()?;
        let current = match segments.last() {
            Some(&segment) => {
                let file = OpenOptions::new()
                    .append(true)
                    .open(segment_path(&dir, segment))?;
                let (len, last) = recovered;
                Current {
                    segment,
                    file,
                    len,
                    last,
                }
            }
            None => create_segment(&dir, 0)?,
        };
        let (sender, receiver) = mpsc::channel();
        let inner = Arc::new(Inner {
            dir,
            store: store.clone(),
            index,
            sender: Mutex::new(Some(sender)),
            thread: Mutex::new(None),
            files: Mutex::new(HashMap::new()),
            collecting: smol::lock::Mutex::new(()),
            holds: Holds::default(),
        });
        let thread = {
            let writer = Writer {
                dir: inner.dir.clone(),
                store: store.clone(),
                index: inner.index.clone(),
                holds: inner.holds.clone(),
                segment_bytes,
                current,
            };
            std::thread::Builder::new()
                .name("vos-blobs".into())
                .spawn(move || writer.run(receiver))
                .expect("the blob writer starts")
        };
        *lock(&inner.thread) = Some(thread);
        Ok(Self { inner })
    }

    /// Store `bytes`, whose reference the caller computed (on an executor,
    /// off the writer), kept by its age: answered once the blob is durable
    /// and indexed.
    pub async fn put(&self, blob: BlobRef, bytes: Arc<Vec<u8>>) -> std::result::Result<(), String> {
        self.put_kept(blob, bytes, Keep::Aged).await
    }

    /// As [`Self::put`], kept as `keep` says. A blob stored already keeps
    /// the longer of its keep and this.
    pub async fn put_kept(
        &self,
        blob: BlobRef,
        bytes: Arc<Vec<u8>>,
        keep: Keep,
    ) -> std::result::Result<(), String> {
        self.send(blob, bytes, keep, false).await
    }

    async fn send(
        &self,
        blob: BlobRef,
        bytes: Arc<Vec<u8>>,
        keep: Keep,
        relocate: bool,
    ) -> std::result::Result<(), String> {
        self.request(|done| {
            Request::Put(Put {
                blob,
                bytes,
                keep,
                relocate,
                done,
            })
        })
        .await
    }

    /// Hold `hash`, stored or about to be: no collection removes it while
    /// the hold lives.
    pub fn hold(&self, hash: [u8; 32]) -> Held {
        *lock(&self.inner.holds.0).entry(hash).or_default() += 1;
        Held {
            holds: self.inner.holds.clone(),
            hash,
        }
    }

    async fn request<T>(
        &self,
        make: impl FnOnce(Answer<T>) -> Request,
    ) -> std::result::Result<T, String> {
        let (done, wait) = smol::channel::bounded(1);
        lock(&self.inner.sender)
            .as_ref()
            .ok_or("the blob writer stopped")?
            .send(make(done))
            .map_err(|_| "the blob writer stopped".to_string())?;
        wait.recv()
            .await
            .map_err(|_| "the blob writer stopped".to_string())?
    }

    /// Of `hashes`, the blobs stored, each now counted as just put: a host
    /// touches every blob it comes to rely on (an entry naming it) before
    /// counting on it, so a collection running meanwhile keeps it.
    pub async fn touch(&self, hashes: Vec<[u8; 32]>) -> std::result::Result<Vec<[u8; 32]>, String> {
        self.request(|done| Request::Touch { hashes, done }).await
    }

    fn location(&self, hash: &[u8; 32]) -> Result<Option<Location>> {
        Ok(self
            .inner
            .index
            .get(location_key(hash))?
            .and_then(|bytes| Location::decode(&bytes)))
    }

    /// Whether the blob is stored, durably.
    pub fn contains(&self, hash: &[u8; 32]) -> Result<bool> {
        Ok(self.location(hash)?.is_some())
    }

    /// The blob's bytes, if stored.
    pub fn get(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let Some(location) = self.location(hash)? else {
            return Ok(None);
        };
        match self.read(&location) {
            Ok(bytes) => Ok(Some(bytes)),
            // A collection moved it, and deleted the segment read from.
            Err(error) => match self.location(hash)? {
                Some(moved) if moved != location => Ok(Some(self.read(&moved)?)),
                Some(_) => Err(error),
                None => Ok(None),
            },
        }
    }

    fn read(&self, location: &Location) -> Result<Vec<u8>> {
        let file = {
            let mut files = lock(&self.inner.files);
            match files.get(&location.segment) {
                Some(file) => Arc::clone(file),
                None => {
                    let path = segment_path(&self.inner.dir, location.segment);
                    let file = Arc::new(File::open(path)?);
                    if files.len() >= OPEN_SEGMENTS {
                        files.clear();
                    }
                    files.insert(location.segment, Arc::clone(&file));
                    file
                }
            }
        };
        let mut bytes = vec![0; location.len as usize];
        file.read_exact_at(&mut bytes, location.offset + HEADER)?;
        Ok(bytes)
    }

    /// Whether `agent` pins the blob: a program it runs.
    pub fn pinned_by(&self, hash: &[u8; 32], agent: u32) -> Result<bool> {
        Ok(self.inner.index.get(pin_key(hash, agent))?.is_some())
    }

    /// Whether any agent pins the blob.
    pub fn pinned_by_any(&self, hash: &[u8; 32]) -> Result<bool> {
        let prefix = [&[IndexRow::Pin as u8][..], hash].concat();
        match self.inner.index.prefix(prefix).next() {
            Some(row) => row.key().map(|_| true),
            None => Ok(false),
        }
    }

    /// The pinned blobs, each once.
    pub fn pinned(&self) -> Result<Vec<[u8; 32]>> {
        let mut out: Vec<[u8; 32]> = Vec::new();
        for row in self.inner.index.prefix([IndexRow::Pin as u8]) {
            let key = row.key()?;
            let hash: [u8; 32] = key[1..33].try_into().expect("a pin names a hash");
            if out.last() != Some(&hash) {
                out.push(hash);
            }
        }
        Ok(out)
    }
}
