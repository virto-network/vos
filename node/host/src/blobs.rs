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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fjall::{Keyspace, PersistMode, Readable};

use crate::lock;
use crate::storage::{Change, StorageThread};
use crate::store::{BlobRef, Error, Fjall, Result};

/// A segment closes once a record would take it past this many bytes.
pub const SEGMENT_BYTES: u64 = 256 << 20;
/// What a put waits behind at most: a guard, as the log writer's cap is.
const GROUP_BYTES: usize = 64 << 20;
const MAGIC: [u8; 4] = *b"VOSB";
/// Segments kept open for reads at once.
const OPEN_SEGMENTS: usize = 64;
const HEADER: u64 = 4 + 8 + 32;

/// The index's rows, by their first byte.
#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum IndexRow {
    /// Hash → segment, offset, length, when last put.
    Location = 0,
    /// Segment → the end of its indexed records, and where the last
    /// starts.
    Segment = 1,
    /// Hash ∥ agent → (): the agent keeps the blob, a program it runs.
    Pin = 2,
}

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

fn location_key(hash: &[u8; 32]) -> Vec<u8> {
    [&[IndexRow::Location as u8][..], hash].concat()
}

fn segment_key(segment: u64) -> Vec<u8> {
    [&[IndexRow::Segment as u8][..], &segment.to_be_bytes()].concat()
}

/// A segment row: the end of its indexed records, and where the last one
/// starts.
fn segment_row(end: u64, last: Option<u64>) -> Vec<u8> {
    [end.to_be_bytes(), last.unwrap_or(u64::MAX).to_be_bytes()].concat()
}

fn decode_segment_row(bytes: &[u8]) -> (u64, Option<u64>) {
    let field = |at: usize| {
        bytes
            .get(at..at + 8)
            .map(|field| u64::from_be_bytes(field.try_into().expect("8 bytes")))
    };
    (
        field(0).unwrap_or(0),
        field(8).filter(|&last| last != u64::MAX),
    )
}

pub(crate) fn pin_key(hash: &[u8; 32], agent: u32) -> Vec<u8> {
    [&[IndexRow::Pin as u8][..], hash, &agent.to_be_bytes()].concat()
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

/// How long a blob that only its age keeps stays after its last put or
/// touch, by how it is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Horizons {
    pub named: Duration,
    pub aged: Duration,
}

impl Horizons {
    /// The times at or before which a blob put or touched has aged out,
    /// as of `now`.
    fn cutoffs(self, now: u64) -> Cutoffs {
        let before = |horizon: Duration| now.saturating_sub(horizon.as_millis() as u64);
        Cutoffs {
            named: before(self.named),
            aged: before(self.aged),
        }
    }
}

#[derive(Clone, Copy)]
struct Cutoffs {
    named: u64,
    aged: u64,
}

impl Cutoffs {
    fn aged_out(self, location: &Location) -> bool {
        let cutoff = match location.keep {
            Keep::Named => self.named,
            Keep::Aged => self.aged,
        };
        location.time <= cutoff
    }
}

/// Where a blob is, when it was last put or touched, and how it is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Location {
    segment: u64,
    offset: u64,
    len: u64,
    time: u64,
    keep: Keep,
}

impl Location {
    fn encode(&self) -> Vec<u8> {
        let mut out: Vec<u8> = [self.segment, self.offset, self.len, self.time]
            .iter()
            .flat_map(|field| field.to_be_bytes())
            .collect();
        out.push(self.keep as u8);
        out
    }

    /// A row of 32 bytes, without its keep, reads as aged: the longer.
    fn decode(bytes: &[u8]) -> Option<Self> {
        let field = |at: usize| Some(u64::from_be_bytes(bytes.get(at..at + 8)?.try_into().ok()?));
        let keep = bytes
            .get(32)
            .map_or(Keep::Aged, |&byte| Keep::from_u8(byte));
        Some(Self {
            segment: field(0)?,
            offset: field(8)?,
            len: field(16)?,
            time: field(24)?,
            keep,
        })
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

fn segment_path(dir: &Path, segment: u64) -> PathBuf {
    dir.join(format!("{segment:016}"))
}

fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

struct Put {
    blob: BlobRef,
    bytes: Arc<Vec<u8>>,
    keep: Keep,
    /// Write it again even if it is stored: collection moving it.
    relocate: bool,
    done: smol::channel::Sender<std::result::Result<(), String>>,
}

type Answer<T> = smol::channel::Sender<std::result::Result<T, String>>;

/// What the blob writer does, in order: so a collection's removal and a
/// put or touch of the same blob never cross.
enum Request {
    Put(Put),
    /// Refresh each stored blob's time: the ones stored.
    Touch {
        hashes: Vec<[u8; 32]>,
        done: Answer<Vec<[u8; 32]>>,
    },
    /// Remove each candidate still aged out by `cutoffs` and not held,
    /// synced: how many.
    Remove {
        candidates: Vec<[u8; 32]>,
        cutoffs: Cutoffs,
        done: Answer<usize>,
    },
}

/// The segment being appended to.
struct Current {
    segment: u64,
    file: File,
    len: u64,
    /// Where its last record starts.
    last: Option<u64>,
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

/// What a collection did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Collected {
    pub removed: usize,
    pub moved: usize,
    pub segments_deleted: usize,
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

    /// Remove what no durable log row names, no pin or hold keeps and
    /// nobody put or touched within its horizon; delete segments left
    /// empty, and move the live blobs out of segments under half live,
    /// then delete those. `stop` ends it early, between its steps, when the
    /// node stops: what it did by then stands, and the next collection goes
    /// on from there.
    pub async fn collect(
        &self,
        writer: &StorageThread,
        horizons: Horizons,
        stop: &dyn Fn() -> bool,
    ) -> std::result::Result<Collected, String> {
        let _one = self.inner.collecting.lock().await;
        let mut collected = Collected::default();
        let store = &self.inner.store;
        let failed = |error: Error| error.to_string();
        let barrier = || writer.commit(vec![Change::Barrier]);
        // A blob put or touched at or before its cutoff has aged out.
        let cutoffs = horizons.cutoffs(now());
        let first = store.database().snapshot();
        // Only a blob aged, unpinned and unheld can go: with none, no log
        // row is read.
        let mut pinned = HashSet::new();
        for row in first.prefix(&self.inner.index, [IndexRow::Pin as u8]) {
            let key = row.key().map_err(failed)?;
            pinned.insert(<[u8; 32]>::try_from(&key[1..33]).expect("a pin names a hash"));
        }
        let mut candidates = Vec::new();
        for row in first.prefix(&self.inner.index, [IndexRow::Location as u8]) {
            let (key, value) = row.into_inner().map_err(failed)?;
            let hash: [u8; 32] = key[1..].try_into().expect("a location names a hash");
            let location = Location::decode(&value).expect("a location this store wrote");
            if cutoffs.aged_out(&location)
                && !pinned.contains(&hash)
                && !self.inner.holds.contains(&hash)
            {
                candidates.push(hash);
            }
        }
        if !candidates.is_empty() && !stop() {
            // What the snapshot shows becomes durable with the barrier after
            // it, so the references read are ones a crash cannot bring back.
            barrier().await?;
            let referenced = store.referenced_blobs(&first).map_err(failed)?;
            candidates.retain(|hash| !referenced.contains(hash));
        } else {
            candidates.clear();
        }
        drop(first);
        if !candidates.is_empty() && !stop() {
            // A fence: anything that came to need a candidate since is seen.
            let second = store.database().snapshot();
            barrier().await?;
            let referenced = store.referenced_blobs(&second).map_err(failed)?;
            drop(second);
            candidates.retain(|hash| !referenced.contains(hash));
            // The blob writer removes them, synced, in order with puts and
            // touches: one that refreshed a candidate since, or a hold
            // taken since, keeps it. Dead blobs leave the index before any
            // segment goes.
            collected.removed = self
                .request(|done| Request::Remove {
                    candidates,
                    cutoffs,
                    done,
                })
                .await?;
        }
        let (live, current) = self.live_bytes().map_err(failed)?;
        let mut to_delete = Vec::new();
        'segments: for (segment, live) in live {
            if segment == current {
                continue;
            }
            let size = std::fs::metadata(segment_path(&self.inner.dir, segment))
                .map_or(0, |metadata| metadata.len());
            if live.bytes == 0 {
                to_delete.push(segment);
            } else if live.bytes * 2 < size {
                for (hash, location) in live.blobs {
                    // A segment only partly moved stays, for the next one.
                    if stop() {
                        break 'segments;
                    }
                    let Some(bytes) = self.get(&hash).map_err(failed)? else {
                        continue;
                    };
                    let blob = BlobRef {
                        hash,
                        len: location.len,
                    };
                    self.send(blob, Arc::new(bytes), location.keep, true)
                        .await?;
                    collected.moved += 1;
                }
                to_delete.push(segment);
            }
        }
        if to_delete.is_empty() {
            return Ok(collected);
        }
        // The moved blobs' new index rows are durable before their old
        // segment goes.
        store
            .database()
            .persist(PersistMode::SyncAll)
            .map_err(failed)?;
        let mut batch = store.database().batch();
        for &segment in &to_delete {
            batch.remove(&self.inner.index, segment_key(segment));
        }
        batch
            .durability(Some(PersistMode::SyncAll))
            .commit()
            .map_err(failed)?;
        for segment in to_delete {
            lock(&self.inner.files).remove(&segment);
            // Gone already: a crash took back the rows' removal, not this.
            match std::fs::remove_file(segment_path(&self.inner.dir, segment)) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(error.to_string());
                }
                _ => {}
            }
            collected.segments_deleted += 1;
        }
        sync_dir(&self.inner.dir).map_err(failed)?;
        Ok(collected)
    }

    /// Each segment's live bytes and blobs, and the current segment.
    fn live_bytes(&self) -> Result<(BTreeMap<u64, Live>, u64)> {
        let mut live: BTreeMap<u64, Live> = BTreeMap::new();
        for row in self.inner.index.prefix([IndexRow::Segment as u8]) {
            let key = row.key()?;
            let segment = u64::from_be_bytes(key[1..9].try_into().expect("a segment number"));
            live.entry(segment).or_default();
        }
        for row in self.inner.index.prefix([IndexRow::Location as u8]) {
            let (key, value) = row.into_inner()?;
            let hash: [u8; 32] = key[1..].try_into().expect("a location names a hash");
            let location = Location::decode(&value).expect("a location this store wrote");
            let entry = live.entry(location.segment).or_default();
            entry.bytes += HEADER + location.len;
            entry.blobs.push((hash, location));
        }
        let current = live.keys().next_back().copied().unwrap_or(0);
        Ok((live, current))
    }
}

#[derive(Default)]
struct Live {
    bytes: u64,
    blobs: Vec<([u8; 32], Location)>,
}

fn create_segment(dir: &Path, segment: u64) -> Result<Current> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(segment_path(dir, segment))?;
    sync_dir(dir)?;
    Ok(Current {
        segment,
        file,
        len: 0,
        last: None,
    })
}

/// The whole record at `at` in `file`, if it is one: its hash and length.
fn record_at(file: &File, at: u64, len: u64) -> Result<Option<([u8; 32], u64)>> {
    if at + HEADER > len {
        return Ok(None);
    }
    let mut header = [0u8; HEADER as usize];
    file.read_exact_at(&mut header, at)?;
    if header[..4] != MAGIC {
        return Ok(None);
    }
    let blob_len = u64::from_be_bytes(header[4..12].try_into().expect("8 bytes"));
    let hash: [u8; 32] = header[12..44].try_into().expect("32 bytes");
    if blob_len > len || at + HEADER + blob_len > len {
        return Ok(None);
    }
    let mut bytes = vec![0; blob_len as usize];
    file.read_exact_at(&mut bytes, at + HEADER)?;
    if vos_pvm::precompile::blake2b_256(&bytes) != hash {
        return Ok(None);
    }
    Ok(Some((hash, blob_len)))
}

/// Index what `segment` holds past its last indexed record, and cut it at
/// the first record that is not whole: the end of its records, and where
/// the last starts.
///
/// Indexed records were synced, but a tail torn anyway (a disk that lost
/// what it said it wrote) is checked too: the last indexed record is
/// rehashed, and if it, or the file, falls short, the segment is walked
/// from its start and the index rows past the damage go, so the log's
/// entries naming those blobs are cut on open.
fn recover(
    dir: &Path,
    index: &Keyspace,
    batch: &mut fjall::OwnedWriteBatch,
    segment: u64,
) -> Result<(u64, Option<u64>)> {
    let path = segment_path(dir, segment);
    let file = OpenOptions::new().read(true).write(true).open(&path)?;
    // What a crashed process wrote but never synced.
    file.sync_data()?;
    let len = file.metadata()?.len();
    let (indexed, indexed_last) = index
        .get(segment_key(segment))?
        .map_or((0, None), |bytes| decode_segment_row(&bytes));
    let intact = indexed <= len
        && match indexed_last {
            Some(offset) => record_at(&file, offset, len)?.is_some(),
            None => true,
        };
    let (mut at, mut last) = (indexed, indexed_last);
    if !intact {
        (at, last) = (0, None);
        while let Some((_, blob_len)) = record_at(&file, at, len)? {
            last = Some(at);
            at += HEADER + blob_len;
        }
        for row in index.prefix([IndexRow::Location as u8]) {
            let (key, value) = row.into_inner()?;
            let location = Location::decode(&value).expect("a location this store wrote");
            if location.segment == segment && location.offset >= at {
                batch.remove(index, key);
            }
        }
    }
    let time = now();
    while let Some((hash, blob_len)) = record_at(&file, at, len)? {
        if !intact || index.get(location_key(&hash))?.is_none() {
            // Which keep it had is lost with its row: the longer one.
            let location = Location {
                segment,
                offset: at,
                len: blob_len,
                time,
                keep: Keep::Aged,
            };
            batch.insert(index, location_key(&hash), location.encode());
        }
        last = Some(at);
        at += HEADER + blob_len;
    }
    if at < len {
        file.set_len(at)?;
        file.sync_all()?;
    }
    batch.insert(index, segment_key(segment), segment_row(at, last));
    Ok((at, last))
}

/// Drop the rows of segments whose files are gone: a collection deleted
/// the file, and a crash took back the synced batch that removed its rows
/// (a disk that lost what it said it wrote). Blobs indexed there are lost,
/// and the log's entries naming them are cut on open.
fn forget_missing_segments(
    index: &Keyspace,
    batch: &mut fjall::OwnedWriteBatch,
    present: &[u64],
) -> Result<()> {
    let mut missing = Vec::new();
    for row in index.prefix([IndexRow::Segment as u8]) {
        let key = row.key()?;
        let segment = u64::from_be_bytes(key[1..9].try_into().expect("a segment number"));
        if present.binary_search(&segment).is_err() {
            missing.push(segment);
            batch.remove(index, key);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    for row in index.prefix([IndexRow::Location as u8]) {
        let (key, value) = row.into_inner()?;
        let location = Location::decode(&value).expect("a location this store wrote");
        if missing.contains(&location.segment) {
            batch.remove(index, key);
        }
    }
    Ok(())
}

/// The blob writer's loop.
struct Writer {
    dir: PathBuf,
    store: Fjall,
    index: Keyspace,
    holds: Holds,
    segment_bytes: u64,
    current: Current,
}

impl Writer {
    /// Requests in order; consecutive puts share a group and a sync. Any
    /// write or sync error stops the writer: a partial record or a failed
    /// sync leaves the segment in a state only recovery may judge, so
    /// every later request answers that the writer stopped.
    fn run(mut self, receiver: mpsc::Receiver<Request>) {
        let mut queued: Option<Request> = None;
        loop {
            let first = match queued.take() {
                Some(request) => request,
                None => match receiver.recv() {
                    Ok(request) => request,
                    Err(_) => return,
                },
            };
            let put = match first {
                Request::Put(put) => put,
                Request::Touch { hashes, done } => {
                    let result = self.touch(&hashes);
                    let failed = result.is_err();
                    let _ = done.try_send(result.map_err(|error| error.to_string()));
                    if failed {
                        return;
                    }
                    continue;
                }
                Request::Remove {
                    candidates,
                    cutoffs,
                    done,
                } => {
                    let result = self.remove(&candidates, cutoffs);
                    let failed = result.is_err();
                    let _ = done.try_send(result.map_err(|error| error.to_string()));
                    if failed {
                        return;
                    }
                    continue;
                }
            };
            let mut bytes = put.bytes.len();
            let mut group = vec![put];
            while let Ok(request) = receiver.try_recv() {
                match request {
                    Request::Put(put) if bytes + put.bytes.len() <= GROUP_BYTES => {
                        bytes += put.bytes.len();
                        group.push(put);
                    }
                    other => {
                        queued = Some(other);
                        break;
                    }
                }
            }
            let result = self.write(&group).map_err(|error| error.to_string());
            let failed = result.is_err();
            for put in group {
                let _ = put.done.try_send(result.clone());
            }
            if failed {
                return;
            }
        }
    }

    fn touch(&mut self, hashes: &[[u8; 32]]) -> Result<Vec<[u8; 32]>> {
        let mut batch = self.store.database().batch();
        let time = now();
        let mut stored = Vec::new();
        for hash in hashes {
            if let Some(location) = self
                .index
                .get(location_key(hash))?
                .and_then(|bytes| Location::decode(&bytes))
            {
                let refreshed = Location { time, ..location };
                batch.insert(&self.index, location_key(hash), refreshed.encode());
                stored.push(*hash);
            }
        }
        batch.durability(Some(PersistMode::Buffer)).commit()?;
        Ok(stored)
    }

    fn remove(&mut self, candidates: &[[u8; 32]], cutoffs: Cutoffs) -> Result<usize> {
        let mut batch = self.store.database().batch();
        let mut removed = 0;
        for hash in candidates {
            let still = self
                .index
                .get(location_key(hash))?
                .and_then(|bytes| Location::decode(&bytes));
            if still.is_some_and(|location| cutoffs.aged_out(&location))
                && !self.holds.contains(hash)
            {
                batch.remove(&self.index, location_key(hash));
                removed += 1;
            }
        }
        batch.durability(Some(PersistMode::SyncAll)).commit()?;
        self.store.database().persist(PersistMode::SyncAll)?;
        Ok(removed)
    }

    fn write(&mut self, group: &[Put]) -> Result<()> {
        let mut batch = self.store.database().batch();
        let time = now();
        let mut wrote = false;
        for put in group {
            let stored = self
                .index
                .get(location_key(&put.blob.hash))?
                .and_then(|bytes| Location::decode(&bytes));
            let keep = stored.map_or(put.keep, |stored| stored.keep.max(put.keep));
            if let Some(stored) = stored
                && !put.relocate
            {
                // Stored already: a new put refreshes its age, so a
                // collection running now keeps it.
                let refreshed = Location {
                    time,
                    keep,
                    ..stored
                };
                batch.insert(
                    &self.index,
                    location_key(&put.blob.hash),
                    refreshed.encode(),
                );
                continue;
            }
            let record = HEADER + put.bytes.len() as u64;
            if self.current.len > 0 && self.current.len + record > self.segment_bytes {
                self.current.file.sync_data()?;
                batch.insert(
                    &self.index,
                    segment_key(self.current.segment),
                    segment_row(self.current.len, self.current.last),
                );
                self.current = create_segment(&self.dir, self.current.segment + 1)?;
            }
            let offset = self.current.len;
            self.current.file.write_all(&MAGIC)?;
            self.current
                .file
                .write_all(&(put.bytes.len() as u64).to_be_bytes())?;
            self.current.file.write_all(&put.blob.hash)?;
            self.current.file.write_all(&put.bytes)?;
            self.current.last = Some(offset);
            self.current.len += record;
            let location = Location {
                segment: self.current.segment,
                offset,
                len: put.bytes.len() as u64,
                time,
                keep,
            };
            batch.insert(&self.index, location_key(&put.blob.hash), location.encode());
            wrote = true;
        }
        if wrote {
            self.current.file.sync_data()?;
            batch.insert(
                &self.index,
                segment_key(self.current.segment),
                segment_row(self.current.len, self.current.last),
            );
        }
        // Indexed after the data's sync, without one of its own: a crash
        // loses only index rows the next open recovers from the segment.
        batch.durability(Some(PersistMode::Buffer)).commit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoHooks;
    use crate::store::{LogEntry, PersistMode};
    use vos_wire::ids::AgentId;

    fn bytes(seed: u8, len: usize) -> Arc<Vec<u8>> {
        Arc::new(
            (0..len)
                .map(|at| (at as u8).wrapping_mul(31) ^ seed)
                .collect(),
        )
    }

    fn put(blobs: &Blobs, bytes: &Arc<Vec<u8>>) -> BlobRef {
        put_kept(blobs, bytes, Keep::Aged)
    }

    fn put_kept(blobs: &Blobs, bytes: &Arc<Vec<u8>>, keep: Keep) -> BlobRef {
        let blob = blob_ref(bytes);
        smol::block_on(blobs.put_kept(blob, Arc::clone(bytes), keep)).unwrap();
        blob
    }

    /// One horizon for every blob.
    fn horizons(horizon: Duration) -> Horizons {
        Horizons {
            named: horizon,
            aged: horizon,
        }
    }

    /// Set `blob`'s last put `ago` before now.
    fn age(blobs: &Blobs, store: &Fjall, blob: &BlobRef, ago: Duration) {
        let aged = Location {
            time: now() - ago.as_millis() as u64,
            ..blobs.location(&blob.hash).unwrap().unwrap()
        };
        store
            .blobs()
            .insert(location_key(&blob.hash), aged.encode())
            .unwrap();
    }

    #[test]
    fn blobs_round_trip_and_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path().join("store")).unwrap();
        let blobs = Blobs::open_with(dir.path().join("blobs"), &store, 4096).unwrap();
        let written: Vec<_> = (0..6).map(|seed| bytes(seed, 1500)).collect();
        let refs: Vec<_> = written.iter().map(|bytes| put(&blobs, bytes)).collect();
        for (blob, bytes) in refs.iter().zip(&written) {
            assert_eq!(
                blobs.get(&blob.hash).unwrap().as_ref(),
                Some(bytes.as_ref())
            );
        }
        assert!(!blobs.contains(&[7; 32]).unwrap());
        assert_eq!(blobs.get(&[7; 32]).unwrap(), None);
        // 4 KiB segments hold two records each.
        let segments = std::fs::read_dir(dir.path().join("blobs")).unwrap().count();
        assert_eq!(segments, 3);
        drop(blobs);
        drop(store);

        let store = Fjall::open(dir.path().join("store")).unwrap();
        let blobs = Blobs::open_with(dir.path().join("blobs"), &store, 4096).unwrap();
        for (blob, bytes) in refs.iter().zip(&written) {
            assert_eq!(
                blobs.get(&blob.hash).unwrap().as_ref(),
                Some(bytes.as_ref())
            );
        }
    }

    #[test]
    fn open_indexes_a_segment_tail_and_cuts_a_torn_record() {
        let dir = tempfile::tempdir().unwrap();
        let blob_dir = dir.path().join("blobs");
        let (first, second) = {
            let store = Fjall::open(dir.path().join("store")).unwrap();
            let blobs = Blobs::open(&blob_dir, &store).unwrap();
            let first = put(&blobs, &bytes(1, 100));
            let second = put(&blobs, &bytes(2, 100));
            // The index rows are lost, as a crash may lose them.
            let mut batch = store.database().batch();
            batch.remove(store.blobs(), location_key(&second.hash));
            batch.remove(store.blobs(), segment_key(0));
            batch.commit().unwrap();
            (first, second)
        };
        // A torn record after the second.
        let segment = segment_path(&blob_dir, 0);
        let mut file = OpenOptions::new().append(true).open(&segment).unwrap();
        file.write_all(&MAGIC).unwrap();
        file.write_all(&100u64.to_be_bytes()).unwrap();
        file.write_all(&[3; 20]).unwrap();
        drop(file);
        let torn_len = std::fs::metadata(&segment).unwrap().len();

        let store = Fjall::open(dir.path().join("store")).unwrap();
        let blobs = Blobs::open(&blob_dir, &store).unwrap();
        assert!(blobs.contains(&first.hash).unwrap());
        assert!(
            blobs.contains(&second.hash).unwrap(),
            "re-indexed from the segment"
        );
        assert_eq!(blobs.get(&second.hash).unwrap().unwrap(), *bytes(2, 100));
        assert_eq!(
            std::fs::metadata(&segment).unwrap().len(),
            torn_len - 4 - 8 - 20,
            "the torn record is cut"
        );
        // The next put follows the cut.
        let third = put(&blobs, &bytes(3, 100));
        assert_eq!(blobs.get(&third.hash).unwrap().unwrap(), *bytes(3, 100));
    }

    #[test]
    fn open_drops_an_indexed_record_torn_anyway() {
        let dir = tempfile::tempdir().unwrap();
        let blob_dir = dir.path().join("blobs");
        let (first, second) = {
            let store = Fjall::open(dir.path().join("store")).unwrap();
            let blobs = Blobs::open(&blob_dir, &store).unwrap();
            (put(&blobs, &bytes(1, 500)), put(&blobs, &bytes(2, 500)))
        };
        // Both are indexed; the disk loses the second's last bytes anyway.
        let segment = segment_path(&blob_dir, 0);
        let len = std::fs::metadata(&segment).unwrap().len();
        let file = OpenOptions::new().write(true).open(&segment).unwrap();
        file.set_len(len - 10).unwrap();
        drop(file);

        let store = Fjall::open(dir.path().join("store")).unwrap();
        let blobs = Blobs::open(&blob_dir, &store).unwrap();
        assert_eq!(blobs.get(&first.hash).unwrap().unwrap(), *bytes(1, 500));
        assert!(
            !blobs.contains(&second.hash).unwrap(),
            "the torn record is gone"
        );
        // It can be stored again.
        put(&blobs, &bytes(2, 500));
        assert_eq!(blobs.get(&second.hash).unwrap().unwrap(), *bytes(2, 500));
    }

    #[test]
    fn collection_keeps_referenced_pinned_and_young_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path().join("store")).unwrap();
        let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
        let blobs = Blobs::open_with(dir.path().join("blobs"), &store, 4096).unwrap();
        let named = put(&blobs, &bytes(1, 1500));
        let pinned = put(&blobs, &bytes(2, 1500));
        let dead: Vec<_> = (3..7).map(|seed| put(&blobs, &bytes(seed, 1500))).collect();
        let entry = LogEntry {
            blobs: vec![named],
            ..LogEntry::result(1, Vec::new())
        };
        let mut batch = store.batch();
        batch.append(AgentId(1), 1, &entry);
        batch.pin(&pinned.hash, AgentId(1));
        batch.commit(PersistMode::SyncAll).unwrap();

        // Everything is younger than a day: nothing goes.
        let kept =
            smol::block_on(
                blobs.collect(&writer, horizons(Duration::from_secs(86_400)), &|| false),
            )
            .unwrap();
        assert_eq!(kept.removed, 0);
        // With no horizon, the unnamed and unpinned blobs go, and segments
        // left empty or sparse are deleted, their live blobs moved.
        let collected =
            smol::block_on(blobs.collect(&writer, horizons(Duration::ZERO), &|| false)).unwrap();
        assert_eq!(collected.removed, dead.len());
        assert!(collected.segments_deleted >= 1, "{collected:?}");
        for blob in &dead {
            assert!(!blobs.contains(&blob.hash).unwrap());
        }
        assert_eq!(blobs.get(&named.hash).unwrap().unwrap(), *bytes(1, 1500));
        assert_eq!(blobs.get(&pinned.hash).unwrap().unwrap(), *bytes(2, 1500));
        assert_eq!(blobs.pinned().unwrap(), vec![pinned.hash]);
        drop(blobs);
        drop(writer);
        drop(store);
        // And all of it holds after a reopen.
        let store = Fjall::open(dir.path().join("store")).unwrap();
        let blobs = Blobs::open_with(dir.path().join("blobs"), &store, 4096).unwrap();
        assert_eq!(blobs.get(&named.hash).unwrap().unwrap(), *bytes(1, 1500));
        assert_eq!(blobs.get(&pinned.hash).unwrap().unwrap(), *bytes(2, 1500));
        for blob in &dead {
            assert!(!blobs.contains(&blob.hash).unwrap());
        }
    }

    #[test]
    fn a_touch_keeps_a_candidate_from_a_removal_after_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path().join("store")).unwrap();
        let blobs = Blobs::open(dir.path().join("blobs"), &store).unwrap();
        let kept = put(&blobs, &bytes(1, 300));
        let dropped = put(&blobs, &bytes(2, 300));
        // Both aged out: candidates of a collection deciding now.
        for blob in [kept, dropped] {
            let old = Location {
                time: 0,
                ..blobs.location(&blob.hash).unwrap().unwrap()
            };
            store
                .blobs()
                .insert(location_key(&blob.hash), old.encode())
                .unwrap();
        }
        let cutoff = now() - 1;
        // An entry comes to rely on one: its host touches it first.
        let touched = smol::block_on(blobs.touch(vec![kept.hash, [9; 32]])).unwrap();
        assert_eq!(touched, vec![kept.hash], "only stored blobs answer");
        let removed = smol::block_on(blobs.request(|done| Request::Remove {
            candidates: vec![kept.hash, dropped.hash],
            cutoffs: Cutoffs {
                named: cutoff,
                aged: cutoff,
            },
            done,
        }))
        .unwrap();
        assert_eq!(removed, 1);
        assert!(blobs.contains(&kept.hash).unwrap());
        assert!(!blobs.contains(&dropped.hash).unwrap());
    }

    #[test]
    fn a_put_of_a_stored_blob_refreshes_its_age() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path().join("store")).unwrap();
        let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
        let blobs = Blobs::open(dir.path().join("blobs"), &store).unwrap();
        let data = bytes(9, 300);
        let blob = put(&blobs, &data);
        // Age it, as if put long ago, then put it again.
        let old = Location {
            time: 0,
            ..blobs.location(&blob.hash).unwrap().unwrap()
        };
        store
            .blobs()
            .insert(location_key(&blob.hash), old.encode())
            .unwrap();
        put(&blobs, &data);
        let kept =
            smol::block_on(blobs.collect(&writer, horizons(Duration::from_secs(3_600)), &|| false))
                .unwrap();
        assert_eq!(kept.removed, 0);
        assert!(blobs.contains(&blob.hash).unwrap());
        let segment_records = std::fs::metadata(segment_path(&dir.path().join("blobs"), 0))
            .unwrap()
            .len();
        assert_eq!(segment_records, HEADER + 300, "stored once");
    }

    /// A blob kept as named goes by its own, brief horizon, an aged one by
    /// the store's; a hold keeps either, whatever its age.
    #[test]
    fn each_keep_ages_by_its_horizon_and_a_hold_outlasts_both() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path().join("store")).unwrap();
        let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
        let blobs = Blobs::open(dir.path().join("blobs"), &store).unwrap();
        let named = put_kept(&blobs, &bytes(1, 300), Keep::Named);
        let aged = put_kept(&blobs, &bytes(2, 300), Keep::Aged);
        let held = put_kept(&blobs, &bytes(3, 300), Keep::Named);
        let hold = blobs.hold(held.hash);
        for blob in [named, aged, held] {
            age(&blobs, &store, &blob, Duration::from_secs(60));
        }
        let horizons = Horizons {
            named: Duration::from_secs(10),
            aged: Duration::from_secs(3_600),
        };
        let collect = || smol::block_on(blobs.collect(&writer, horizons, &|| false)).unwrap();
        assert_eq!(collect().removed, 1);
        assert!(!blobs.contains(&named.hash).unwrap());
        assert!(blobs.contains(&aged.hash).unwrap(), "within its horizon");
        assert!(blobs.contains(&held.hash).unwrap(), "held");
        // A second hold outlives the first.
        let again = blobs.hold(held.hash);
        drop(hold);
        assert_eq!(collect().removed, 0);
        drop(again);
        assert_eq!(collect().removed, 1);
        assert!(!blobs.contains(&held.hash).unwrap());
    }

    /// A hold taken once a collection chose its candidates still keeps the
    /// blob: the writer checks again as it removes.
    #[test]
    fn a_hold_keeps_a_candidate_from_a_removal_after_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path().join("store")).unwrap();
        let blobs = Blobs::open(dir.path().join("blobs"), &store).unwrap();
        let blob = put_kept(&blobs, &bytes(1, 300), Keep::Named);
        age(&blobs, &store, &blob, Duration::from_secs(60));
        let cutoff = now() - 1;
        let remove = || {
            smol::block_on(blobs.request(|done| Request::Remove {
                candidates: vec![blob.hash],
                cutoffs: Cutoffs {
                    named: cutoff,
                    aged: cutoff,
                },
                done,
            }))
            .unwrap()
        };
        let hold = blobs.hold(blob.hash);
        assert_eq!(remove(), 0);
        drop(hold);
        assert_eq!(remove(), 1);
    }

    /// A blob put both ways keeps the longer, and moving it keeps that; a
    /// row without its keep, or with one this build does not know, reads as
    /// aged.
    #[test]
    fn a_blob_keeps_the_longer_of_its_keeps() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path().join("store")).unwrap();
        let blobs = Blobs::open(dir.path().join("blobs"), &store).unwrap();
        let keep = |blob: &BlobRef| blobs.location(&blob.hash).unwrap().unwrap().keep;
        let data = bytes(1, 300);
        let blob = put_kept(&blobs, &data, Keep::Named);
        assert_eq!(keep(&blob), Keep::Named);
        put_kept(&blobs, &data, Keep::Aged);
        assert_eq!(keep(&blob), Keep::Aged);
        put_kept(&blobs, &data, Keep::Named);
        assert_eq!(keep(&blob), Keep::Aged);
        smol::block_on(blobs.send(blob, Arc::clone(&data), Keep::Named, true)).unwrap();
        assert_eq!(keep(&blob), Keep::Aged, "moved");
        let location = blobs.location(&blob.hash).unwrap().unwrap();
        let named = Location {
            keep: Keep::Named,
            ..location
        };
        let mut unknown = named.encode();
        unknown[32] = 7;
        for row in [&named.encode()[..32], &unknown[..]] {
            assert_eq!(Location::decode(row), Some(location));
        }
    }
}
