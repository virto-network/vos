// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the facility keeps apart from the light node: its enrollments, each
//! space's routes, the bridges, the background job's runs; rows of one fjall
//! database under [`DIRECTORY`], beside the light node's store and apart
//! from it, so sign-in and payments run whatever the personal space is.
//! Each value is SCALE of a facility-owned type (never s4's contract
//! types, whose wire is not this disk), read strictly: the database's
//! [`LAYOUT`] is checked at open, a database of another is refused and left
//! as it is, and a row that does not decode is an error, never a default.
//! A change to a row is a new layout. The database is opened once per
//! directory in a process; every holder of it shares that handle.

use std::collections::BTreeMap;
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use vos_abi::{Decode, Encode};

/// The database's directory, under the facility's.
pub const DIRECTORY: &str = "facility";

/// The number of the database's layout: its rows and how they encode.
pub const LAYOUT: u32 = 2;

const LAYOUT_ROW: &[u8] = b"layout";

/// A row: its key and its value.
pub type Row = (Vec<u8>, Vec<u8>);

/// The facility's database, shared.
#[derive(Clone)]
pub struct Kept(Arc<Inner>);

struct Inner {
    db: Database,
    rows: Keyspace,
}

/// The databases open in this process, by directory.
static OPEN: Mutex<BTreeMap<PathBuf, Weak<Inner>>> = Mutex::new(BTreeMap::new());

fn failed(error: impl std::fmt::Display) -> String {
    format!("the facility's database: {error}")
}

impl Kept {
    /// The database under `directory` (the facility's): made with its
    /// layout if there is none, the one already open in this process if it
    /// is; refused if it is of another layout.
    pub fn open(directory: &Path) -> Result<Self, String> {
        let path = directory.join(DIRECTORY);
        let mut open = crate::lock(&OPEN);
        if let Some(inner) = open.get(&path).and_then(Weak::upgrade) {
            return Ok(Self(inner));
        }
        crate::enrollment::create_private(&path)?;
        let db = Database::builder(&path).open().map_err(failed)?;
        let rows = db
            .keyspace("rows", KeyspaceCreateOptions::default)
            .map_err(failed)?;
        match rows.get(LAYOUT_ROW).map_err(failed)? {
            Some(value) if value[..] == LAYOUT.to_be_bytes() => {}
            Some(value) => {
                return Err(format!(
                    "the facility's database needs repair: its layout is {}, and this build reads {LAYOUT}",
                    hex::encode(&value[..])
                ));
            }
            None if rows.is_empty().map_err(failed)? => {
                rows.insert(LAYOUT_ROW, LAYOUT.to_be_bytes())
                    .map_err(failed)?;
                db.persist(PersistMode::SyncAll).map_err(failed)?;
            }
            None => return Err("the facility's database needs repair: it has no layout".into()),
        }
        let inner = Arc::new(Inner { db, rows });
        open.retain(|_, held| held.strong_count() > 0);
        open.insert(path, Arc::downgrade(&inner));
        Ok(Self(inner))
    }

    /// The row `key`, decoded.
    pub fn get<T: Decode>(&self, key: &[u8]) -> Result<Option<T>, String> {
        match self.0.rows.get(key).map_err(failed)? {
            None => Ok(None),
            Some(value) => T::decode_exact(&value)
                .map(Some)
                .ok_or_else(|| undecoded(key)),
        }
    }

    /// The rows under `prefix`, in order, decoded.
    pub fn under<T: Decode>(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, T)>, String> {
        self.raw(prefix)?
            .into_iter()
            .map(|(key, value)| {
                let decoded = T::decode_exact(&value).ok_or_else(|| undecoded(&key))?;
                Ok((key, decoded))
            })
            .collect()
    }

    /// The rows under `prefix`, in order, as they are written.
    pub fn raw(&self, prefix: &[u8]) -> Result<Vec<Row>, String> {
        let mut rows = Vec::new();
        let start = Bound::Included(prefix.to_vec());
        for row in self.0.rows.range::<Vec<u8>, _>((start, Bound::Unbounded)) {
            let (key, value) = row.into_inner().map_err(failed)?;
            if !key.starts_with(prefix) {
                break;
            }
            rows.push((key.to_vec(), value.to_vec()));
        }
        Ok(rows)
    }

    /// The row `key` set to `value`, synced.
    pub fn put(&self, key: &[u8], value: &impl Encode) -> Result<(), String> {
        self.write(key, Some(value.encode()))
    }

    /// The row `key` deleted, synced.
    pub fn remove(&self, key: &[u8]) -> Result<(), String> {
        self.write(key, None)
    }

    /// The row `key` written as `value` is, or deleted, synced.
    pub fn write(&self, key: &[u8], value: Option<Vec<u8>>) -> Result<(), String> {
        let mut batch = self.0.db.batch();
        match value {
            Some(value) => batch.insert(&self.0.rows, key, value),
            None => batch.remove(&self.0.rows, key),
        }
        batch
            .durability(Some(PersistMode::SyncAll))
            .commit()
            .map_err(failed)
    }
}

fn undecoded(key: &[u8]) -> String {
    format!(
        "the facility's database needs repair: its row {} does not decode",
        key.escape_ascii()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_database_of_another_layout_or_a_row_that_does_not_decode_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        {
            let kept = Kept::open(directory.path()).unwrap();
            kept.put(b"a", &(7u32, String::from("seven"))).unwrap();
            assert_eq!(
                Kept::open(directory.path())
                    .unwrap()
                    .get::<(u32, String)>(b"a"),
                Ok(Some((7, "seven".into()))),
                "one handle a process"
            );
            kept.put(b"b", &1u8).unwrap();
            assert!(kept.get::<u64>(b"b").unwrap_err().contains("needs repair"));
            assert_eq!(kept.under::<(u32, String)>(b"a").unwrap().len(), 1);
            kept.write(LAYOUT_ROW, Some((LAYOUT + 1).to_be_bytes().to_vec()))
                .unwrap();
        }
        let refused = Kept::open(directory.path()).err().unwrap();
        assert!(refused.contains("needs repair"), "{refused}");
    }
}
