//! The blob writer: its thread appends, touches and removes blobs, in the
//! order they are asked for.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, mpsc};

use fjall::{Keyspace, PersistMode};

use super::collect::Cutoffs;
use super::index::{Location, location_key, segment_key, segment_row};
use super::segment::{Current, create_segment};
use super::{GROUP_BYTES, HEADER, Holds, Keep, MAGIC, now};
use crate::store::{BlobRef, Fjall, Result};

pub(super) struct Put {
    pub(super) blob: BlobRef,
    pub(super) bytes: Arc<Vec<u8>>,
    pub(super) keep: Keep,
    /// Write it again even if it is stored: collection moving it.
    pub(super) relocate: bool,
    pub(super) done: smol::channel::Sender<std::result::Result<(), String>>,
}

pub(super) type Answer<T> = smol::channel::Sender<std::result::Result<T, String>>;

/// What the blob writer does, in order: so a collection's removal and a
/// put or touch of the same blob never cross.
pub(super) enum Request {
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

/// The blob writer's loop.
pub(super) struct Writer {
    pub(super) dir: PathBuf,
    pub(super) store: Fjall,
    pub(super) index: Keyspace,
    pub(super) holds: Holds,
    pub(super) segment_bytes: u64,
    pub(super) current: Current,
}

impl Writer {
    /// Requests in order; consecutive puts share a group and a sync. Any
    /// write or sync error stops the writer: a partial record or a failed
    /// sync leaves the segment in a state only recovery may judge, so
    /// every later request answers that the writer stopped.
    pub(super) fn run(mut self, receiver: mpsc::Receiver<Request>) {
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
