//! The blob store's segment files: their records, and their recovery on
//! open.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use fjall::Keyspace;

use super::index::{
    IndexRow, Location, decode_segment_row, location_key, location_row, segment_key, segment_of,
    segment_row,
};
use super::{HEADER, Keep, MAGIC, now};
use crate::store::Result;

pub(super) fn segment_path(dir: &Path, segment: u64) -> PathBuf {
    dir.join(format!("{segment:016}"))
}

pub(super) fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// The segment being appended to.
pub(super) struct Current {
    pub(super) segment: u64,
    pub(super) file: File,
    pub(super) len: u64,
    /// Where its last record starts.
    pub(super) last: Option<u64>,
}

pub(super) fn create_segment(dir: &Path, segment: u64) -> Result<Current> {
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
pub(super) fn recover(
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
            let (hash, location) = location_row(row)?;
            if location.segment == segment && location.offset >= at {
                batch.remove(index, location_key(&hash));
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
pub(super) fn forget_missing_segments(
    index: &Keyspace,
    batch: &mut fjall::OwnedWriteBatch,
    present: &[u64],
) -> Result<()> {
    let mut missing = Vec::new();
    for row in index.prefix([IndexRow::Segment as u8]) {
        let key = row.key()?;
        let segment = segment_of(&key);
        if present.binary_search(&segment).is_err() {
            missing.push(segment);
            batch.remove(index, key);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    for row in index.prefix([IndexRow::Location as u8]) {
        let (hash, location) = location_row(row)?;
        if missing.contains(&location.segment) {
            batch.remove(index, location_key(&hash));
        }
    }
    Ok(())
}
