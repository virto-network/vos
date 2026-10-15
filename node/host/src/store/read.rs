//! Reads of applied state: a store snapshot's view, and an agent's
//! export for a snapshot stream.

use std::collections::HashMap;
use std::ops::Bound;
use std::sync::Mutex;

use fjall::Readable;
use vos_wire::ids::AgentId;

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
            cursor: Some((true, None)),
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
    /// The partition read next (system, then state), and the last key read.
    cursor: Option<(bool, Option<Vec<u8>>)>,
}

impl Export {
    /// The next chunk of about `bytes` (at least one row), if any rows are
    /// left.
    pub fn next_chunk(&mut self, bytes: usize) -> Result<Option<Vec<Row>>> {
        let mut chunk = Vec::new();
        let mut size = 0;
        let prefix = agent_key(self.agent, self.epoch, &[]);
        while let Some((system, after)) = self.cursor.clone() {
            let partition = if system {
                self.store.system()
            } else {
                self.store.state()
            };
            let start = match &after {
                Some(after) => Bound::Excluded(after.clone()),
                None => Bound::Included(prefix.clone()),
            };
            let mut last = None;
            let mut done = true;
            for row in self.snapshot.range(partition, (start, Bound::Unbounded)) {
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
                self.cursor = system.then_some((false, None));
            } else {
                self.cursor = Some((system, last.or(after)));
                break;
            }
        }
        Ok((!chunk.is_empty()).then_some(chunk))
    }
}

/// A read-only view of applied state, as of one store snapshot. Keys are
/// relative to the agent.
pub struct Snapshot {
    snapshot: fjall::Snapshot,
    store: Fjall,
    /// Each agent's epoch, read once from this snapshot: a reader never
    /// mixes epochs, nor sees a half-installed snapshot.
    epochs: Mutex<HashMap<AgentId, u8>>,
}

impl Snapshot {
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
        let epoch = self.epoch(agent)?;
        Ok(self
            .snapshot
            .get(self.store.partition(key), agent_key(agent, epoch, key))?
            .map(|value| value.to_vec()))
    }

    /// Rows whose key starts with `prefix`, in key order, starting after
    /// `after` when given. `prefix` must not be empty: it selects the
    /// partition.
    pub fn scan(
        &self,
        agent: AgentId,
        prefix: &[u8],
        after: Option<&[u8]>,
    ) -> impl Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> {
        assert!(!prefix.is_empty(), "a scan names its partition");
        // An unreadable epoch row is the scan's first, and only, item: never
        // another epoch's rows.
        let (epoch, failed) = match self.epoch(agent) {
            Ok(epoch) => (epoch, None),
            Err(error) => (0, Some(error)),
        };
        let broken = failed.is_some();
        let start = match after {
            Some(after) if after >= prefix => Bound::Excluded(agent_key(agent, epoch, after)),
            _ => Bound::Included(agent_key(agent, epoch, prefix)),
        };
        let prefix = agent_key(agent, epoch, prefix);
        let rows = self
            .snapshot
            .range(
                self.store.partition(&prefix[AGENT_KEY_PREFIX..]),
                (start, Bound::Unbounded),
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
