//! Reads of applied state: a store snapshot's view, and an agent's
//! export for a snapshot stream.

use std::collections::{BTreeMap, HashMap};
use std::iter::Peekable;
use std::ops::Bound;
use std::sync::{Arc, Mutex};

use fjall::Readable;
use vos_wire::ids::AgentId;
use vos_wire::result::Write;

use super::keys::{
    AGENT_KEY_PREFIX, NodeRow, agent_key, applied, decode_entry, decode_last_result,
    decode_position, epoch, log_key, node_row,
};
use super::{Error, Fjall, Result, Row};
use crate::lock;

impl Fjall {
    /// A consistent view of every agent's applied state, for refines and
    /// queries.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            snapshot: self.database().snapshot(),
            store: self.clone(),
            epochs: Mutex::new(HashMap::new()),
            unapplied: None,
        }
    }

    /// An export of the agent's applied state, from one store snapshot.
    pub fn export(&self, agent: AgentId) -> Result<Export> {
        let snapshot = self.database().snapshot();
        let row = |kind| snapshot.get(self.system(), node_row(agent, kind));
        let epoch = epoch(row(NodeRow::Epoch)?);
        let applied = applied(row(NodeRow::Applied)?).unwrap_or(0);
        let log_start = row(NodeRow::LogStart)?
            .and_then(|bytes| decode_position(&bytes))
            .unwrap_or((0, 0));
        let last_result = row(NodeRow::LastResult)?.and_then(|bytes| decode_last_result(&bytes));
        let term = if applied <= log_start.0 {
            log_start.1
        } else {
            snapshot
                .get(self.log(), log_key(agent, applied))?
                .and_then(|bytes| decode_entry(&bytes))
                .map(|entry| entry.term)
                .ok_or_else(|| {
                    Error::Io(std::io::Error::other(format!(
                        "agent {}'s log lacks its applied entry {applied}",
                        agent.0
                    )))
                })?
        };
        Ok(Export {
            snapshot,
            store: self.clone(),
            agent,
            epoch,
            applied,
            term,
            last_result,
            cursor: Cursor::System(None),
        })
    }
}

/// An agent's applied state, exported from one store snapshot: labelled
/// with its own applied index and the term there, and read in chunks of
/// rows (agent-relative keys, in key order, the system keys first).
pub struct Export {
    snapshot: fjall::Snapshot,
    store: Fjall,
    agent: AgentId,
    epoch: u8,
    pub applied: u64,
    pub term: u64,
    /// The time and seed of the last work result applied, as of the same
    /// store snapshot.
    pub last_result: Option<(u64, [u8; 32])>,
    cursor: Cursor,
}

/// Where an export reads next: the system partition, then the state
/// partition, each after the last key read there, or from its start.
enum Cursor {
    System(Option<Vec<u8>>),
    State(Option<Vec<u8>>),
    Done,
}

impl Export {
    /// The next chunk of about `bytes` (at least one row), if any rows are
    /// left.
    pub fn next_chunk(&mut self, bytes: usize) -> Result<Option<Vec<Row>>> {
        let mut chunk = Vec::new();
        let mut size = 0;
        let prefix = agent_key(self.agent, self.epoch, &[]);
        loop {
            let (partition, after) = match &self.cursor {
                Cursor::System(after) => (self.store.system(), after),
                Cursor::State(after) => (self.store.state(), after),
                Cursor::Done => break,
            };
            let start = match after {
                Some(after) => Bound::Excluded(after.clone()),
                None => Bound::Included(prefix.clone()),
            };
            let mut last = None;
            let mut done = true;
            for row in self.snapshot.range(partition, (start, prefix_end(&prefix))) {
                let (key, value) = row.into_inner()?;
                if !key.starts_with(&prefix) {
                    break;
                }
                if !chunk.is_empty() && size + key.len() + value.len() > bytes {
                    done = false;
                    break;
                }
                size += key.len() + value.len();
                chunk.push((key[AGENT_KEY_PREFIX..].to_vec(), value.to_vec()));
                last = Some(key.to_vec());
            }
            if done {
                self.cursor = match self.cursor {
                    Cursor::System(_) => Cursor::State(None),
                    _ => Cursor::Done,
                };
            } else {
                if let (Cursor::System(after) | Cursor::State(after), Some(last)) =
                    (&mut self.cursor, last)
                {
                    *after = Some(last);
                }
                break;
            }
        }
        Ok((!chunk.is_empty()).then_some(chunk))
    }
}

/// Writes to one agent's rows not yet applied, in order: a leader's
/// batches in flight, which its next batch refines over.
#[derive(Debug)]
pub struct Unapplied {
    agent: AgentId,
    /// Each row's last write: a value, or (`None`) a deletion.
    rows: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl Unapplied {
    /// `agent`'s rows as `writes` leave them, later writes to a key over
    /// earlier ones.
    pub fn new<'a>(agent: AgentId, writes: impl IntoIterator<Item = &'a Write>) -> Self {
        let rows = writes
            .into_iter()
            .map(|write| (write.key.clone(), write.value.clone()))
            .collect();
        Self { agent, rows }
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// A read-only view of applied state, as of one store snapshot, and of one
/// agent's writes not yet applied over it, if any. Keys are relative to
/// the agent.
pub struct Snapshot {
    snapshot: fjall::Snapshot,
    store: Fjall,
    /// Each agent's epoch, read once from this snapshot: a reader never
    /// mixes epochs, nor sees a half-installed snapshot.
    epochs: Mutex<HashMap<AgentId, u8>>,
    unapplied: Option<Arc<Unapplied>>,
}

impl Snapshot {
    /// This view with `unapplied` over its agent's rows: each written row
    /// reads as written, each deleted one as absent. They must follow what
    /// this view holds applied, as the batches in flight follow it.
    pub fn over(self, unapplied: Arc<Unapplied>) -> Self {
        Self {
            unapplied: (!unapplied.is_empty()).then_some(unapplied),
            ..self
        }
    }

    /// The unapplied rows over `agent`'s, if any.
    fn unapplied(&self, agent: AgentId) -> Option<&Unapplied> {
        self.unapplied
            .as_deref()
            .filter(|unapplied| unapplied.agent == agent)
    }

    /// The epoch the agent's rows are under.
    pub fn epoch(&self, agent: AgentId) -> Result<u8> {
        if let Some(&epoch) = lock(&self.epochs).get(&agent) {
            return Ok(epoch);
        }
        let epoch = epoch(self.row(agent, NodeRow::Epoch)?);
        lock(&self.epochs).insert(agent, epoch);
        Ok(epoch)
    }

    pub fn get(&self, agent: AgentId, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(written) = self
            .unapplied(agent)
            .and_then(|unapplied| unapplied.rows.get(key))
        {
            return Ok(written.clone());
        }
        let epoch = self.epoch(agent)?;
        Ok(self
            .snapshot
            .get(self.store.partition(key), agent_key(agent, epoch, key))?
            .map(|value| value.to_vec()))
    }

    /// Rows whose key starts with `prefix`, in key order, starting after
    /// `after` when given. `prefix` must not be empty: it selects the
    /// partition.
    pub fn scan<'a>(
        &'a self,
        agent: AgentId,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> impl Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + 'a {
        let start = match after {
            Some(after) if after >= prefix => Bound::Excluded(after),
            _ => Bound::Included(prefix),
        };
        self.scan_from(agent, prefix, start)
    }

    /// Rows whose key starts with `prefix`, in key order, from `start`, or
    /// from the prefix when `start` is below it.
    pub fn scan_from<'a>(
        &'a self,
        agent: AgentId,
        prefix: &'a [u8],
        start: Bound<&'a [u8]>,
    ) -> impl Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + 'a {
        let start = match start {
            Bound::Included(key) | Bound::Excluded(key) if key < prefix => Bound::Included(prefix),
            Bound::Unbounded => Bound::Included(prefix),
            start => start,
        };
        let applied = self.applied_scan(agent, prefix, start);
        let unapplied = self.unapplied(agent).map(|unapplied| {
            unapplied
                .rows
                .range::<[u8], _>((start, Bound::Unbounded))
                .take_while(move |(key, _)| key.starts_with(prefix))
                .peekable()
        });
        Merged {
            applied: applied.peekable(),
            unapplied,
        }
    }

    /// [`Self::scan`] of the applied rows alone.
    fn applied_scan(
        &self,
        agent: AgentId,
        prefix: &[u8],
        start: Bound<&[u8]>,
    ) -> impl Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> {
        assert!(!prefix.is_empty(), "a scan names its partition");
        // An unreadable epoch row is the scan's first, and only, item: never
        // another epoch's rows.
        let (epoch, failed) = match self.epoch(agent) {
            Ok(epoch) => (epoch, None),
            Err(error) => (0, Some(error)),
        };
        let broken = failed.is_some();
        let start = match start {
            Bound::Excluded(after) => Bound::Excluded(agent_key(agent, epoch, after)),
            Bound::Included(from) => Bound::Included(agent_key(agent, epoch, from)),
            Bound::Unbounded => Bound::Included(agent_key(agent, epoch, prefix)),
        };
        let prefix = agent_key(agent, epoch, prefix);
        let rows = self
            .snapshot
            .range(
                self.store.partition(&prefix[AGENT_KEY_PREFIX..]),
                (start, prefix_end(&prefix)),
            )
            .map(|row| row.into_inner())
            .take_while(move |row| {
                !broken
                    && match row {
                        Ok((key, _)) => key.starts_with(&prefix),
                        Err(_) => true,
                    }
            })
            .map(|row| {
                let (key, value) = row?;
                Ok((key[AGENT_KEY_PREFIX..].to_vec(), value.to_vec()))
            });
        failed.map(Err).into_iter().chain(rows)
    }

    /// The last log index applied to the agent's state.
    pub fn applied(&self, agent: AgentId) -> Result<Option<u64>> {
        Ok(applied(self.row(agent, NodeRow::Applied)?))
    }

    /// The time and seed of the last work result applied to the agent.
    pub fn last_result(&self, agent: AgentId) -> Result<Option<(u64, [u8; 32])>> {
        Ok(self
            .row(agent, NodeRow::LastResult)?
            .and_then(|bytes| decode_last_result(&bytes)))
    }

    /// The node's `row` for the agent.
    fn row(&self, agent: AgentId, row: NodeRow) -> Result<Option<fjall::Slice>> {
        self.snapshot.get(self.store.system(), node_row(agent, row))
    }
}

/// Where the keys starting with `prefix` end: the first key past them all,
/// none when every byte of it is the highest. A range bounded there stops
/// at the prefix's last row; one bounded only by a filter on the prefix
/// goes on to the next row the store holds past it, through every row
/// deleted on the way, which a compaction has yet to drop.
pub(super) fn prefix_end(prefix: &[u8]) -> Bound<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < u8::MAX {
            end.push(last + 1);
            return Bound::Excluded(end);
        }
    }
    Bound::Unbounded
}

/// Applied rows, with unapplied writes over them, in key order.
struct Merged<A: Iterator, U: Iterator> {
    applied: Peekable<A>,
    unapplied: Option<Peekable<U>>,
}

impl<'a, A, U> Iterator for Merged<A, U>
where
    A: Iterator<Item = Result<(Vec<u8>, Vec<u8>)>>,
    U: Iterator<Item = (&'a Vec<u8>, &'a Option<Vec<u8>>)>,
{
    type Item = Result<(Vec<u8>, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        let Some(unapplied) = self.unapplied.as_mut() else {
            return self.applied.next();
        };
        loop {
            let written = unapplied.peek().map(|(key, _)| key.as_slice());
            let stored = match self.applied.peek() {
                Some(Ok((key, _))) => Some(key.as_slice()),
                // A failed read is the scan's next item.
                Some(Err(_)) => return self.applied.next(),
                None => None,
            };
            match (stored, written) {
                (None, None) => return None,
                (Some(_), None) => return self.applied.next(),
                (Some(stored), Some(written)) if stored < written => return self.applied.next(),
                (stored, Some(written)) => {
                    // The write takes the row's place.
                    if stored == Some(written) {
                        self.applied.next();
                    }
                    let (key, value) = unapplied.next().expect("peeked");
                    if let Some(value) = value {
                        return Some(Ok((key.clone(), value.clone())));
                    }
                }
            }
        }
    }
}
