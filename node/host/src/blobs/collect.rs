//! The blob store's collection: what no row, pin, hold or recent put keeps
//! goes, and sparse segments are compacted.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use fjall::{PersistMode, Readable};

use super::index::{IndexRow, Location, location_row, pinned_hash, segment_key, segment_of};
use super::segment::{segment_path, sync_dir};
use super::writer::Request;
use super::{Blobs, HEADER, Keep, now};
use crate::lock;
use crate::storage::{Change, StorageThread};
use crate::store::{self, BlobRef, Error};

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
    ) -> Result<Collected, String> {
        let _one = self.inner.collecting.lock().await;
        // A blob put or touched at or before its cutoff has aged out.
        let cutoffs = horizons.cutoffs(now());
        let removed = self.remove_dead(writer, cutoffs, stop).await?;
        let (moved, emptied) = self.move_live(stop).await?;
        let segments_deleted = self.delete_segments(&emptied)?;
        Ok(Collected {
            removed,
            moved,
            segments_deleted,
        })
    }

    /// Remove the blobs aged out by `cutoffs` that nothing keeps, unless
    /// `stop` says otherwise first: how many.
    async fn remove_dead(
        &self,
        writer: &StorageThread,
        cutoffs: Cutoffs,
        stop: &dyn Fn() -> bool,
    ) -> Result<usize, String> {
        let store = &self.inner.store;
        let barrier = || writer.commit(vec![Change::Barrier]);
        let first = store.database().snapshot();
        let mut candidates = self.candidates(&first, cutoffs).map_err(failed)?;
        if candidates.is_empty() || stop() {
            return Ok(0);
        }
        // What the snapshot shows becomes durable with the barrier after it,
        // so the references read are ones a crash cannot bring back.
        barrier().await?;
        let referenced = store.referenced_blobs(&first).map_err(failed)?;
        candidates.retain(|hash| !referenced.contains(hash));
        drop(first);
        if candidates.is_empty() || stop() {
            return Ok(0);
        }
        // A fence: anything that came to need a candidate since is seen.
        let second = store.database().snapshot();
        barrier().await?;
        let referenced = store.referenced_blobs(&second).map_err(failed)?;
        drop(second);
        candidates.retain(|hash| !referenced.contains(hash));
        // The blob writer removes them, synced, in order with puts and
        // touches: one that refreshed a candidate since, or a hold taken
        // since, keeps it. Dead blobs leave the index before any segment
        // goes.
        self.request(|done| Request::Remove {
            candidates,
            cutoffs,
            done,
        })
        .await
    }

    /// The blobs `snapshot` shows aged out by `cutoffs`, unpinned and
    /// unheld: only these can go, and with none, no log row is read.
    fn candidates(
        &self,
        snapshot: &fjall::Snapshot,
        cutoffs: Cutoffs,
    ) -> store::Result<Vec<[u8; 32]>> {
        let mut pinned = HashSet::new();
        for row in snapshot.prefix(self.index(), [IndexRow::Pin as u8]) {
            pinned.insert(pinned_hash(&row.key()?));
        }
        let mut candidates = Vec::new();
        for row in snapshot.prefix(self.index(), [IndexRow::Location as u8]) {
            let (hash, location) = location_row(row)?;
            if cutoffs.aged_out(&location)
                && !pinned.contains(&hash)
                && !self.inner.holds.contains(&hash)
            {
                candidates.push(hash);
            }
        }
        Ok(candidates)
    }

    /// Move the live blobs out of the segments under half live, until
    /// `stop`: how many moved, and the segments to delete, those left empty
    /// and those moved out of whole.
    async fn move_live(&self, stop: &dyn Fn() -> bool) -> Result<(usize, Vec<u64>), String> {
        let (live, current) = self.live_bytes().map_err(failed)?;
        let mut moved = 0;
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
                    self.relocate(blob, Arc::new(bytes), location.keep).await?;
                    moved += 1;
                }
                to_delete.push(segment);
            }
        }
        Ok((moved, to_delete))
    }

    /// Delete `segments`, their rows first: how many.
    fn delete_segments(&self, segments: &[u64]) -> Result<usize, String> {
        if segments.is_empty() {
            return Ok(0);
        }
        let database = self.inner.store.database();
        // The moved blobs' new index rows are durable before their old
        // segment goes.
        database.persist(PersistMode::SyncAll).map_err(failed)?;
        let mut batch = database.batch();
        for &segment in segments {
            batch.remove(self.index(), segment_key(segment));
        }
        batch
            .durability(Some(PersistMode::SyncAll))
            .commit()
            .map_err(failed)?;
        for &segment in segments {
            lock(&self.inner.files).remove(&segment);
            // Gone already: a crash took back the rows' removal, not this.
            match std::fs::remove_file(segment_path(&self.inner.dir, segment)) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(error.to_string());
                }
                _ => {}
            }
        }
        sync_dir(&self.inner.dir).map_err(failed)?;
        Ok(segments.len())
    }

    /// Each segment's live bytes and blobs, and the current segment.
    fn live_bytes(&self) -> store::Result<(BTreeMap<u64, Live>, u64)> {
        let mut live: BTreeMap<u64, Live> = BTreeMap::new();
        for row in self.index().prefix([IndexRow::Segment as u8]) {
            live.entry(segment_of(&row.key()?)).or_default();
        }
        for row in self.index().prefix([IndexRow::Location as u8]) {
            let (hash, location) = location_row(row)?;
            let entry = live.entry(location.segment).or_default();
            entry.bytes += HEADER + location.len;
            entry.blobs.push((hash, location));
        }
        let current = live.keys().next_back().copied().unwrap_or(0);
        Ok((live, current))
    }
}

/// A store's failure, as a collection reports it.
fn failed(error: Error) -> String {
    error.to_string()
}

#[derive(Default)]
struct Live {
    bytes: u64,
    blobs: Vec<([u8; 32], Location)>,
}
