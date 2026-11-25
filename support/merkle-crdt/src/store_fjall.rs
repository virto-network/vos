//! A [`Store`] over fjall: one scope in five keyspaces of a database the
//! caller opens and may share.
//!
//! A commit's batch is whole or absent after a crash. Two things are the
//! caller's, before it opens the database after one: a database whose
//! creation was cut short (fjall writes its `version` file last) does not
//! open, and is cleared; and a batch the killed process wrote to the page
//! cache, not yet synced, is read back as committed, so the journals are
//! synced before the replica relies on what it reads (a power cut would
//! otherwise lose a node already pushed, and the next one signed at its
//! number would equivocate).

use crate::apply::row_fits;
use crate::store::{Changes, Loaded};
use crate::{Author, Cid, Decode, Hasher, Store};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::vec::Vec;
use fjall::{Database, Keyspace, KeyspaceCreateOptions, OwnedWriteBatch, PersistMode};

const HEAD: u8 = b'h';
const CURSOR: &[u8] = b"c";
const LATEST: u8 = b'l';
const EQUIVOCATION: u8 = b'e';
const OUTBOX: u8 = b'o';

/// Why a fjall store failed.
#[derive(Debug)]
pub enum FjallError {
    /// fjall failed.
    Fjall(fjall::Error),
    /// A stored row does not read as the store wrote it.
    Corrupt,
    /// The scope's name does not make fjall keyspace names: at most 240
    /// bytes of ASCII letters, digits, `_`, `-`, `.`, `#` or `$`.
    Name,
    /// A row's key is empty or past [`MAX_ROW_KEY`](crate::MAX_ROW_KEY)
    /// bytes, or its value past [`MAX_ROW_VALUE`](crate::MAX_ROW_VALUE).
    Row,
}

impl From<fjall::Error> for FjallError {
    fn from(error: fjall::Error) -> Self {
        FjallError::Fjall(error)
    }
}

impl core::fmt::Display for FjallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FjallError::Fjall(error) => write!(f, "the store: {error}"),
            FjallError::Corrupt => f.write_str("a stored row does not read as written"),
            FjallError::Name => f.write_str("the scope's name is not a keyspace name"),
            FjallError::Row => f.write_str("a row's key or value is past fjall's limits"),
        }
    }
}

impl std::error::Error for FjallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FjallError::Fjall(error) => Some(error),
            _ => None,
        }
    }
}

/// One scope's store in a fjall database, in keyspaces named after it:
///
/// - `<name>.nodes`: applied nodes' bytes by CID;
/// - `<name>.held`: held nodes' bytes by CID;
/// - `<name>.authored`: `author ‖ seq (BE) ‖ cid`, empty values;
/// - `<name>.meta`: the heads (a row a head), the cursor, each author's
///   latest node, the equivocations and the outbox;
/// - the rows: `<name>.rows`, or a keyspace the caller names, so that a
///   light node's agent reads the CRDT's rows with its own.
///
/// Every [`commit`](Store::commit) is one batch, synced before it returns;
/// [`commit_with`](FjallStore::commit_with) adds the caller's writes to it.
/// One store a scope name.
pub struct FjallStore {
    db: Database,
    nodes: Keyspace,
    held: Keyspace,
    authored: Keyspace,
    meta: Keyspace,
    rows: Keyspace,
}

impl FjallStore {
    /// The scope `name` in `db`, its rows in `<name>.rows`.
    pub fn open(db: &Database, name: &str) -> Result<Self, FjallError> {
        check_name(name)?;
        let rows = db.keyspace(&format!("{name}.rows"), KeyspaceCreateOptions::default)?;
        Self::with_rows(db, name, rows)
    }

    /// The scope `name` in `db`, its rows in `rows`.
    pub fn with_rows(db: &Database, name: &str, rows: Keyspace) -> Result<Self, FjallError> {
        check_name(name)?;
        let keyspace =
            |kind: &str| db.keyspace(&format!("{name}.{kind}"), KeyspaceCreateOptions::default);
        Ok(Self {
            nodes: keyspace("nodes")?,
            held: keyspace("held")?,
            authored: keyspace("authored")?,
            meta: keyspace("meta")?,
            rows,
            db: db.clone(),
        })
    }

    /// The keyspace the rows are in.
    pub fn rows(&self) -> &Keyspace {
        &self.rows
    }
}

/// A scope's name makes fjall keyspace names `<name>.<kind>`.
fn check_name(name: &str) -> Result<(), FjallError> {
    let allowed = |c: u8| c.is_ascii_alphanumeric() || b"_-.#$".contains(&c);
    if name.is_empty() || name.len() > 240 || !name.bytes().all(allowed) {
        return Err(FjallError::Name);
    }
    Ok(())
}

fn cid<H: Hasher>(bytes: &[u8]) -> Result<Cid<H>, FjallError> {
    H::Output::decode(bytes).map(Cid).ok_or(FjallError::Corrupt)
}

fn authored_key<H: Hasher>(author: &Author, seq: u64, cid: Option<&Cid<H>>) -> Vec<u8> {
    let mut key = Vec::with_capacity(72);
    key.extend_from_slice(&author.0);
    key.extend_from_slice(&seq.to_be_bytes());
    if let Some(cid) = cid {
        key.extend_from_slice(cid.as_ref());
    }
    key
}

fn tagged(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut key = alloc::vec![tag];
    for part in parts {
        key.extend_from_slice(part);
    }
    key
}

fn seq(bytes: &[u8]) -> Result<u64, FjallError> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| FjallError::Corrupt)?,
    ))
}

fn author(bytes: &[u8]) -> Result<Author, FjallError> {
    <[u8; 32]>::try_from(bytes)
        .map(Author)
        .map_err(|_| FjallError::Corrupt)
}

/// `author ‖ seq (BE)`, read back.
fn author_seq(bytes: &[u8]) -> Result<(Author, u64), FjallError> {
    let (key, at) = bytes.split_at_checked(32).ok_or(FjallError::Corrupt)?;
    Ok((author(key)?, seq(at)?))
}

impl<H: Hasher> Store<H> for FjallStore {
    type Error = FjallError;

    fn node(&self, cid: &Cid<H>) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.nodes.get(cid)?.map(|bytes| bytes.to_vec()))
    }

    fn contains(&self, cid: &Cid<H>) -> Result<bool, Self::Error> {
        Ok(self.nodes.contains_key(cid)?)
    }

    fn held(&self, cid: &Cid<H>) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.held.get(cid)?.map(|bytes| bytes.to_vec()))
    }

    fn authored(&self, author: &Author, seq: u64) -> Result<Option<Cid<H>>, Self::Error> {
        let prefix = authored_key::<H>(author, seq, None);
        self.authored
            .prefix(&prefix)
            .next()
            .map(|row| cid(&row.key()?[prefix.len()..]))
            .transpose()
    }

    fn is_authored(&self, author: &Author, seq: u64, cid: &Cid<H>) -> Result<bool, Self::Error> {
        Ok(self
            .authored
            .contains_key(authored_key(author, seq, Some(cid)))?)
    }

    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.rows.get(key)?.map(|value| value.to_vec()))
    }

    fn load(&self) -> Result<Loaded<H>, Self::Error> {
        let mut heads = BTreeMap::new();
        for row in self.meta.prefix([HEAD]) {
            let (key, value) = row.into_inner()?;
            heads.insert(cid(&key[1..])?, author_seq(&value)?);
        }
        let cursor = self
            .meta
            .get(CURSOR)?
            .map(|bytes| seq(&bytes))
            .transpose()?;
        let mut latest = BTreeMap::new();
        for row in self.meta.prefix([LATEST]) {
            let (key, value) = row.into_inner()?;
            let (at, node) = value.split_at_checked(8).ok_or(FjallError::Corrupt)?;
            latest.insert(author(&key[1..])?, (seq(at)?, cid(node)?));
        }
        let mut equivocations = BTreeSet::new();
        for row in self.meta.prefix([EQUIVOCATION]) {
            equivocations.insert(author_seq(&row.key()?[1..])?);
        }
        let mut outbox = BTreeMap::new();
        for row in self.meta.prefix([OUTBOX]) {
            let (key, value) = row.into_inner()?;
            outbox.insert(author_seq(&key[1..])?, cid(&value)?);
        }
        let mut held = Vec::new();
        for row in self.held.iter() {
            held.push(cid(&row.key()?)?);
        }
        Ok(Loaded {
            heads,
            latest,
            equivocations,
            cursor,
            outbox,
            held,
        })
    }

    fn commit(&mut self, changes: Changes<H>) -> Result<(), Self::Error> {
        self.commit_with(changes, |_| {})
    }
}

impl FjallStore {
    /// Write `changes` and the caller's own writes, which `extra` adds to
    /// the batch, in one synced batch: a store that keeps rows of its own
    /// beside the scope's commits them with the scope's, or not at all. A
    /// row fjall does not take fails the batch with [`FjallError::Row`];
    /// the caller's own writes are its to keep within fjall's limits.
    pub fn commit_with<H: Hasher>(
        &mut self,
        changes: Changes<H>,
        extra: impl FnOnce(&mut OwnedWriteBatch),
    ) -> Result<(), FjallError> {
        if !changes
            .rows
            .iter()
            .all(|(key, value)| row_fits(key, value.as_deref()))
        {
            return Err(FjallError::Row);
        }
        let mut batch = self.db.batch();
        extra(&mut batch);
        for node in changes.applied {
            batch.insert(
                &self.authored,
                authored_key(&node.author, node.seq, Some(&node.cid)),
                [],
            );
            batch.insert(&self.nodes, node.cid.as_ref(), node.bytes);
        }
        for cid in changes.released {
            batch.remove(&self.held, cid.as_ref());
        }
        for (cid, bytes) in changes.held {
            batch.insert(&self.held, cid.as_ref(), bytes);
        }
        for cid in changes.heads_removed {
            batch.remove(&self.meta, tagged(HEAD, &[cid.as_ref()]));
        }
        for (cid, (author, at)) in changes.heads_added {
            let value = [&author.0[..], &at.to_be_bytes()].concat();
            batch.insert(&self.meta, tagged(HEAD, &[cid.as_ref()]), value);
        }
        for (author, (at, cid)) in changes.latest {
            let value = [&at.to_be_bytes()[..], cid.as_ref()].concat();
            batch.insert(&self.meta, tagged(LATEST, &[&author.0]), value);
        }
        for (author, at) in changes.equivocations {
            let key = tagged(EQUIVOCATION, &[&author.0, &at.to_be_bytes()]);
            batch.insert(&self.meta, key, []);
        }
        if let Some(cursor) = changes.cursor {
            batch.insert(&self.meta, CURSOR, cursor.to_be_bytes());
        }
        for ((author, at), cid) in changes.outbox {
            let key = tagged(OUTBOX, &[&author.0, &at.to_be_bytes()]);
            batch.insert(&self.meta, key, cid.as_ref());
        }
        for (author, at) in changes.pushed {
            batch.remove(&self.meta, tagged(OUTBOX, &[&author.0, &at.to_be_bytes()]));
        }
        for (key, value) in changes.rows {
            match value {
                Some(value) => batch.insert(&self.rows, key, value),
                None => batch.remove(&self.rows, key),
            }
        }
        Ok(batch.durability(Some(PersistMode::SyncAll)).commit()?)
    }
}
