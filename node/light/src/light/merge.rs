//! The merge entry's runs: a scope's nodes applied, each operation over
//! the store as the batch began and the batch's writes since; and an
//! install's programs read before they are stored.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::Arc;

use merkle_crdt::{Apply, Event, Rows};
use vos_abi::abi::Failure;
use vos_abi::ids::{AgentId, InstanceId};
use vos_abi::merge::Origin;
use vos_abi::records::stored;
use vos_abi::result::Outcome;
use vos_exec::{ProgramStore, StateReader, value_window};

use super::{Error, Halt, Light, MAX_ARGUMENTS, Written, keep, release};
use crate::store::{Applying, Snapshot, Store};
use crate::sync::{self, Blake2b256, Held, Hold, Mirrored, Op, Ops, Quarantine, Quarantined};

/// A replay's rows: the store as of a snapshot under the batch's writes.
impl Rows for Applying<'_> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        vos_wire::apply::State::read(self, key)
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        vos_wire::apply::State::write(self, key, value);
    }
}

/// A scope's nodes applied through the merge entry: each operation run
/// over the store as the batch began and the batch's writes since, its
/// rows written through the scope's.
pub(super) struct Merging<'a> {
    light: &'a Light,
    instance: InstanceId,
    pub(super) snapshot: Arc<Snapshot>,
    /// The batch's writes so far, which later runs read above the store.
    written: Arc<Written>,
    /// The release of the instance's actor installed here.
    release: u32,
    /// A local operation: its handler's failure declines it.
    local: bool,
    /// A local operation's outcome.
    pub(super) outcome: Option<Outcome>,
    /// The peers' operations held, and quarantined.
    pub(super) held: Vec<Held>,
    pub(super) quarantined: Vec<Quarantined>,
}

impl<'a> Merging<'a> {
    pub(super) fn new(
        light: &'a Light,
        instance: InstanceId,
        snapshot: Snapshot,
        local: bool,
    ) -> Result<Self, Error> {
        Ok(Self {
            light,
            instance,
            release: release(&snapshot, instance)?.unwrap_or(0),
            snapshot: Arc::new(snapshot),
            written: Arc::new(BTreeMap::new()),
            local,
            outcome: None,
            held: Vec::new(),
            quarantined: Vec::new(),
        })
    }

    fn hold(&mut self, kept: Held, rows: &mut dyn Rows) {
        sync::hold(self.instance, &kept, rows);
        self.held.push(kept);
    }

    fn quarantine(&mut self, kept: Quarantined, rows: &mut dyn Rows) {
        sync::quarantine(self.instance, &kept, rows);
        self.quarantined.push(kept);
    }

    /// Run `op` as `origin`, of the node `cid`, its writes through `rows`.
    /// A local operation runs, or declines with nothing recorded. A
    /// peer's is checked first: one whose author was removed at its number,
    /// or whose frame no device records, is quarantined; one of a kind this
    /// build does not know, or of a later release than the one installed,
    /// is held. It then runs: done, its rows are written; its run faulting
    /// here, it is held for a replay; failing otherwise, which no issuing
    /// device records, it is quarantined. So no peer's node stops the
    /// scope's sync, and none writes what its author's device did not.
    pub(super) fn run(
        &mut self,
        cid: &sync::Cid,
        origin: &Origin,
        op: &Op,
        rows: &mut dyn Rows,
    ) -> Result<(), Halt> {
        if !self.local {
            let cutoff = sync::removed(rows, self.instance, &origin.author)?;
            if cutoff.is_some_and(|cutoff| !cutoff.admits(origin.seq)) {
                self.quarantine(keep(cid, origin, op, Quarantine::CutOff), rows);
                return Ok(());
            }
        }
        let call = match op {
            Op::Call(call) => call,
            Op::Unknown { .. } => {
                self.hold(keep(cid, origin, op, Hold::Kind), rows);
                return Ok(());
            }
        };
        if !self.local {
            if call.arguments.len() > MAX_ARGUMENTS {
                self.quarantine(keep(cid, origin, op, Quarantine::Invalid), rows);
                return Ok(());
            }
            if call.release > self.release {
                self.hold(keep(cid, origin, op, Hold::Release), rows);
                return Ok(());
            }
        }
        let state = Arc::new(Layered {
            snapshot: Arc::clone(&self.snapshot),
            written: Arc::clone(&self.written),
        });
        let run = match self.light.merge(self.instance, origin, call, state) {
            Ok(run) => run,
            Err(error) if self.local => return Err(Halt::Error(error)),
            Err(_) => {
                self.hold(keep(cid, origin, op, Hold::Fault), rows);
                return Ok(());
            }
        };
        match run.outcome {
            Outcome::Done(_) => {
                let mut mirrored = Mirrored {
                    rows,
                    written: Arc::make_mut(&mut self.written),
                };
                for write in &run.writes {
                    let value = write.value.as_deref().map(stored);
                    mirrored.write(&write.key, value.as_deref());
                }
            }
            outcome if self.local => return Err(Halt::Declined(outcome)),
            // The device lacks a program its state names: its fault.
            Outcome::Failed {
                code: Failure::Unloadable | Failure::InRefine,
                ..
            } => self.hold(keep(cid, origin, op, Hold::Fault), rows),
            Outcome::Failed { code, .. } => {
                self.quarantine(keep(cid, origin, op, Quarantine::Failed(code)), rows)
            }
            Outcome::Started(_) => {
                self.quarantine(keep(cid, origin, op, Quarantine::Invalid), rows)
            }
        }
        if self.local {
            self.outcome = Some(run.outcome);
        }
        Ok(())
    }
}

impl Apply<Blake2b256, Ops> for Merging<'_> {
    type Error = Halt;

    fn apply(
        &mut self,
        event: Event<'_, Blake2b256, Ops>,
        rows: &mut dyn Rows,
    ) -> Result<(), Halt> {
        sync::apply_node(self.instance, &event, rows, |cid, origin, op, rows| {
            self.run(cid, origin, op, rows)
        })
    }
}

/// The store as a batch began, under the batch's writes since: what an
/// operation's run reads.
pub(super) struct Layered {
    snapshot: Arc<Snapshot>,
    written: Arc<Written>,
}

impl StateReader for Layered {
    fn read(&self, key: &[u8], offset: usize, max: usize) -> Option<(usize, Vec<u8>)> {
        match self.written.get(key) {
            Some(value) => value
                .as_deref()
                .map(|value| value_window(value, offset, max)),
            None => self.snapshot.read(key, offset, max),
        }
    }

    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, usize)> + 'a> {
        let start = match after {
            Some(after) if after >= prefix => Bound::Excluded(after),
            _ => Bound::Included(prefix),
        };
        let mut written = self
            .written
            .range::<[u8], _>((start, Bound::Unbounded))
            .take_while(move |(key, _)| key.starts_with(prefix))
            .peekable();
        let mut stored = self.snapshot.rows(prefix, after).peekable();
        Box::new(std::iter::from_fn(move || {
            loop {
                let order = match (stored.peek(), written.peek()) {
                    (None, None) => return None,
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (Some((key, _)), Some((over, _))) => key.as_slice().cmp(over.as_slice()),
                };
                match order {
                    Ordering::Less => return stored.next(),
                    Ordering::Equal => {
                        stored.next();
                    }
                    Ordering::Greater => {}
                }
                let (key, value) = written.next().expect("peeked");
                if let Some(value) = value {
                    return Some((key.clone(), value.len()));
                }
            }
        }))
    }
}

/// The store's programs, and those an install brings, which its run reads
/// before they are stored with its rows.
pub(super) struct Installing {
    pub(super) store: Store,
    pub(super) programs: BTreeMap<[u8; 32], Vec<u8>>,
}

impl ProgramStore for Installing {
    fn get(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        match self.programs.get(hash) {
            Some(program) => Some(program.clone()),
            None => self.store.get(hash),
        }
    }

    fn pinned_by(&self, hash: &[u8; 32], agent: AgentId) -> bool {
        self.store.pinned_by(hash, agent)
    }
}
