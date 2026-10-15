//! The blob store's collection: what no row, pin, hold or recent put keeps
//! goes, and sparse segments are compacted.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use fjall::{PersistMode, Readable};

use super::index::{IndexRow, Location, segment_key};
use super::segment::{segment_path, sync_dir};
use super::writer::Request;
use super::{Blobs, HEADER, Keep, now};
use crate::lock;
use crate::storage::{Change, StorageThread};
use crate::store::{BlobRef, Error, Result};

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
    pub(super) fn cutoffs(self, now: u64) -> Cutoffs {
        let before = |horizon: Duration| now.saturating_sub(horizon.as_millis() as u64);
        Cutoffs {
            named: before(self.named),
            aged: before(self.aged),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Cutoffs {
    pub(super) named: u64,
    pub(super) aged: u64,
}

impl Cutoffs {
    pub(super) fn aged_out(self, location: &Location) -> bool {
        let cutoff = match location.keep {
            Keep::Named => self.named,
            Keep::Aged => self.aged,
        };
        location.time <= cutoff
    }
}

/// What a collection did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Collected {
    pub removed: usize,
    pub moved: usize,
    pub segments_deleted: usize,
}

impl Blobs {
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
