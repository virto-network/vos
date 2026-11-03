//! A [`Store`] over fjall: one scope in five keyspaces of a database the
//! caller opens (and mends after a crash) and may share, each commit one
//! synced batch.

use crate::store::{Changes, Loaded};
use crate::{Author, Cid, Decode, Hasher, Store};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::vec::Vec;
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};

const HEADS: &[u8] = b"h";
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
        }
    }
}

impl std::error::Error for FjallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FjallError::Fjall(error) => Some(error),
            FjallError::Corrupt | FjallError::Name => None,
        }
    }
}

/// One scope's store in a fjall database, in keyspaces named after it:
///
/// - `<name>.nodes`: applied nodes' bytes by CID;
/// - `<name>.held`: held nodes' bytes by CID;
/// - `<name>.authored`: `author ‖ seq (BE) ‖ cid`, empty values;
/// - `<name>.meta`: the heads, the cursor, each author's latest node, the
///   equivocations and the outbox;
/// - the rows: `<name>.rows`, or a keyspace the caller names, so that a
///   light node's agent reads the CRDT's rows with its own.
///
/// Every [`commit`](Store::commit) is one batch, synced before it returns.
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
        if name.len() > 240 {
            return Err(FjallError::Name);
        }
        let rows = db.keyspace(&format!("{name}.rows"), KeyspaceCreateOptions::default)?;
        Self::with_rows(db, name, rows)
    }

    /// The scope `name` in `db`, its rows in `rows`.
    pub fn with_rows(db: &Database, name: &str, rows: Keyspace) -> Result<Self, FjallError> {
        let allowed = |c: u8| c.is_ascii_alphanumeric() || b"_-.#$".contains(&c);
        if name.is_empty() || name.len() > 240 || !name.bytes().all(allowed) {
            return Err(FjallError::Name);
        }
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

impl<H: Hasher> Store<H> for FjallStore {
    type Error = FjallError;

    fn node(&self, cid: &Cid<H>) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.nodes.get(cid)?.map(|bytes| bytes.to_vec()))
    }

    fn contains(&self, cid: &Cid<H>) -> Result<bool, Self::Error> {
        Ok(self.nodes.contains_key(cid)?)
    }

    fn nodes(&self) -> Result<Vec<Cid<H>>, Self::Error> {
        self.nodes.iter().map(|row| cid(&row.key()?)).collect()
    }

    fn held(&self, cid: &Cid<H>) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.held.get(cid)?.map(|bytes| bytes.to_vec()))
    }

    fn authored(&self, author: &Author, seq: u64) -> Result<Vec<Cid<H>>, Self::Error> {
        let prefix = authored_key::<H>(author, seq, None);
        self.authored
            .prefix(&prefix)
            .map(|row| cid(&row.key()?[prefix.len()..]))
            .collect()
    }

    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.rows.get(key)?.map(|value| value.to_vec()))
    }

    fn load(&self) -> Result<Loaded<H>, Self::Error> {
        let width = core::mem::size_of::<H::Output>();
        let heads = match self.meta.get(HEADS)? {
            None => BTreeSet::new(),
            Some(bytes) if bytes.len().is_multiple_of(width) => bytes
                .chunks_exact(width)
                .map(cid)
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(FjallError::Corrupt),
        };
        let cursor = self
            .meta
            .get(CURSOR)?
            .map(|bytes| seq(&bytes))
            .transpose()?;
        let mut latest = BTreeMap::new();
        for row in self.meta.prefix([LATEST]) {
            let (key, value) = row.into_inner()?;
            let author = <[u8; 32]>::try_from(&key[1..]).map_err(|_| FjallError::Corrupt)?;
            let (at, node) = value.split_at_checked(8).ok_or(FjallError::Corrupt)?;
            latest.insert(Author(author), (seq(at)?, cid(node)?));
        }
        let mut equivocations = BTreeSet::new();
        for row in self.meta.prefix([EQUIVOCATION]) {
            let key = row.key()?;
            let (author, at) = key[1..].split_at_checked(32).ok_or(FjallError::Corrupt)?;
            let author = <[u8; 32]>::try_from(author).map_err(|_| FjallError::Corrupt)?;
            equivocations.insert((Author(author), seq(at)?));
        }
        let mut outbox = BTreeMap::new();
        for row in self.meta.prefix([OUTBOX]) {
            let (key, value) = row.into_inner()?;
            let (author, at) = key[1..].split_at_checked(32).ok_or(FjallError::Corrupt)?;
            let author = <[u8; 32]>::try_from(author).map_err(|_| FjallError::Corrupt)?;
            outbox.insert((Author(author), seq(at)?), cid(&value)?);
        }
        let mut held = Vec::new();
        for row in self.held.iter() {
            let (key, value) = row.into_inner()?;
            held.push((cid(&key)?, value.to_vec()));
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
        let mut batch = self.db.batch();
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
        if let Some(heads) = changes.heads {
            let bytes: Vec<u8> = heads.iter().flat_map(|cid| cid.as_ref().to_vec()).collect();
            batch.insert(&self.meta, HEADS, bytes);
        }
        for (author, at, cid) in changes.latest {
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
        for (author, at, cid) in changes.outbox {
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
