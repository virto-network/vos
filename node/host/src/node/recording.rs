//! The placements a node keeps: its own leaders' and those other nodes
//! send, each checked against the directory and stored by one task, many
//! in one write.
//!
//! A placement that supersedes none held is acknowledged as it arrives:
//! the directory takes a placement only once it is stored, so what it
//! holds is durable. The rest wait here, one entry an agent and sender
//! and order however often it is sent again, until the task stores them
//! together and acknowledges each sender. So a node that learns many
//! placements at once (every group electing after a restart, each new
//! leader's placement sent to every node and again every second until
//! held) spends one write on many, and holds no more than one entry for
//! each placement it has yet to store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vos_wire::ids::AgentId;
use vos_wire::peer::{CreationRecord, NodeNumber, PeerMessage, Placement};

use super::Inner;
use crate::lock;
use crate::storage::Change;

/// The most agents' placements one write stores.
const WRITE: usize = 4_096;

/// The placements waiting to be stored, and what wakes the task that
/// stores them.
pub(crate) struct Recording {
    pending: Mutex<Pending>,
    wake: smol::channel::Sender<()>,
    woken: smol::channel::Receiver<()>,
}

impl Default for Recording {
    fn default() -> Self {
        let (wake, woken) = smol::channel::bounded(1);
        Self {
            pending: Mutex::default(),
            wake,
            woken,
        }
    }
}

/// An agent's placements waiting: its leader's here, and those sent.
#[derive(Default)]
struct Waiting {
    own: Option<Placement>,
    sent: Vec<Sent>,
}

/// A placement another node sent, with the record it came with.
struct Sent {
    from: NodeNumber,
    record: CreationRecord,
    placement: Placement,
}

#[derive(Default)]
struct Pending(HashMap<AgentId, Waiting>);

impl Pending {
    fn own(&mut self, agent: AgentId, placement: Placement) {
        let own = &mut self.0.entry(agent).or_default().own;
        if own
            .as_ref()
            .is_none_or(|held| placement.order() > held.order())
        {
            *own = Some(placement);
        }
    }

    fn sent(&mut self, from: NodeNumber, record: CreationRecord, placement: Placement) {
        let sent = &mut self.0.entry(record.agent).or_default().sent;
        let order = placement.order();
        if !sent
            .iter()
            .any(|sent| sent.from == from && sent.placement.order() == order)
        {
            sent.push(Sent {
                from,
                record,
                placement,
            });
        }
    }

    /// At most [`WRITE`] agents' placements, taken out.
    fn take(&mut self) -> Vec<(AgentId, Waiting)> {
        if self.0.len() <= WRITE {
            return self.0.drain().collect();
        }
        let agents: Vec<AgentId> = self.0.keys().take(WRITE).copied().collect();
        agents
            .into_iter()
            .filter_map(|agent| self.0.remove_entry(&agent))
            .collect()
    }
}

impl Recording {
    fn wake(&self) {
        let _ = self.wake.try_send(());
    }
}

/// What one write stores, and what follows it.
#[derive(Default)]
struct Write {
    changes: Vec<Change>,
    /// The placements it takes, each with its record and whether this
    /// node's leader gave it, and so announces it: one sent that supersedes
    /// it is its sender's to announce.
    learned: HashMap<AgentId, (CreationRecord, Placement, bool)>,
    /// The acknowledgements it owes: to whom, for what.
    acks: Vec<(NodeNumber, CreationRecord, Placement)>,
}

impl Write {
    /// Take `placement` for `record`'s agent when it supersedes what the
    /// directory or this write already holds: false when it does not.
    fn take(
        &mut self,
        known: Option<&Placement>,
        record: &CreationRecord,
        placement: &Placement,
        own: bool,
    ) -> bool {
        let agent = record.agent;
        let held = self
            .learned
            .get(&agent)
            .map(|(_, placement, _)| placement)
            .or(known);
        if held.is_some_and(|held| !placement.supersedes(held)) {
            return false;
        }
        if known.is_none() && !self.learned.contains_key(&agent) {
            self.changes.push(Change::Agent(record.clone()));
        }
        self.changes.push(Change::Placement {
            agent,
            placement: placement.clone(),
        });
        self.learned
            .insert(agent, (record.clone(), placement.clone(), own));
        true
    }
}

impl Inner {
    /// Take `placement`, which this node's leadership of the agent gives,
    /// when it supersedes the one held: kept, acted on, and announced to
    /// every other node until each holds it. One not kept is not taken
    /// again: storage failed, and the node halts.
    pub(crate) fn place(&self, agent: AgentId, placement: Placement) {
        lock(&self.recording.pending).own(agent, placement);
        self.recording.wake();
    }

    /// Keep a placement another node sent, newer than the one held, with
    /// its record, durably, act on it, then acknowledge it, saying whether
    /// this node could run the agent's program. One no newer is
    /// acknowledged at once.
    pub(crate) fn on_directory(
        &self,
        from: NodeNumber,
        record: CreationRecord,
        placement: Placement,
    ) {
        // A store that failed takes nothing more, and its node does not
        // acknowledge: the sender's resends are dropped quietly.
        if self.storage.failed() {
            return;
        }
        match self.directory.get(record.agent) {
            Some(known) if known.record != record => refused(from, &record),
            Some(known) if !placement.supersedes(&known.placement) => {
                self.acknowledge_placement(from, &record, &placement)
            }
            _ => {
                lock(&self.recording.pending).sent(from, record, placement);
                self.recording.wake();
            }
        }
    }

    fn acknowledge_placement(
        &self,
        to: NodeNumber,
        record: &CreationRecord,
        placement: &Placement,
    ) {
        self.send(
            to,
            &PeerMessage::DirectoryAck {
                agent: record.agent,
                order: placement.order(),
                runs: self.could_run_here(record),
            },
        );
    }

    /// Store the placements waiting, many in a write, until the node
    /// stops.
    async fn record_placements(self: Arc<Self>) {
        while self.recording.woken.recv().await.is_ok() {
            loop {
                let taken = lock(&self.recording.pending).take();
                if taken.is_empty() {
                    break;
                }
                self.store_placements(taken).await;
            }
        }
    }

    async fn store_placements(self: &Arc<Self>, taken: Vec<(AgentId, Waiting)>) {
        if self.storage.failed() {
            return;
        }
        let mut write = Write::default();
        for (agent, waiting) in taken {
            let known = self.directory.get(agent);
            if let Some(own) = waiting.own
                && let Some(known) = &known
            {
                write.take(Some(&known.placement), &known.record, &own, true);
            }
            for sent in waiting.sent {
                let held = write
                    .learned
                    .get(&agent)
                    .map(|(record, _, _)| record)
                    .or(known.as_ref().map(|known| &known.record));
                if held.is_some_and(|held| *held != sent.record) {
                    refused(sent.from, &sent.record);
                    continue;
                }
                write.take(
                    known.as_ref().map(|known| &known.placement),
                    &sent.record,
                    &sent.placement,
                    false,
                );
                write.acks.push((sent.from, sent.record, sent.placement));
            }
        }
        if !write.changes.is_empty()
            && let Err(error) = self.storage.commit(write.changes).await
        {
            tracing::error!(
                placements = write.learned.len(),
                "placements were not stored: {error}"
            );
            return;
        }
        for (_, (record, placement, announce)) in write.learned {
            let agent = record.agent;
            self.learn(record, placement);
            if announce {
                self.announce(agent);
            }
        }
        for (to, record, placement) in write.acks {
            self.acknowledge_placement(to, &record, &placement);
        }
    }
}

fn refused(from: NodeNumber, record: &CreationRecord) {
    tracing::error!(
        from,
        agent = record.agent.0,
        "a record differs from the one held for its agent; refused"
    );
}

/// Start the task that stores the node's placements.
pub(super) fn start(inner: &Arc<Inner>) {
    inner.spawn(Arc::clone(inner).record_placements());
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos_wire::ids::ProgramHash;

    fn record(agent: u32) -> CreationRecord {
        CreationRecord {
            agent: AgentId(1 << 24 | agent),
            replicas: vec![1, 2, 3],
            creator: 1,
            time: 0,
            program: ProgramHash([0; 32]),
            accumulate_gas: 0,
            space: vos_wire::SpaceId::NONE,
        }
    }

    fn placement(term: u64) -> Placement {
        Placement {
            replicas: vec![1, 2, 3],
            before: Vec::new(),
            term,
            index: 1,
            joint: false,
            committed: true,
        }
    }

    /// A placement sent again and again while it waits is held once a
    /// sender and order; another order, or another sender, is another.
    #[test]
    fn a_placement_sent_again_waits_once() {
        let mut pending = Pending::default();
        for _ in 0..1_000 {
            pending.sent(2, record(1), placement(3));
        }
        pending.sent(3, record(1), placement(3));
        pending.sent(2, record(1), placement(4));
        pending.own(record(1).agent, placement(5));
        pending.own(record(1).agent, placement(4));
        let taken = pending.take();
        assert_eq!(taken.len(), 1);
        let waiting = &taken[0].1;
        assert_eq!(waiting.sent.len(), 3);
        assert_eq!(waiting.own.as_ref().map(|own| own.term), Some(5));
    }

    /// One write takes at most [`WRITE`] agents' placements; the rest wait
    /// for the next.
    #[test]
    fn a_write_takes_a_bounded_number() {
        let mut pending = Pending::default();
        for agent in 0..(WRITE as u32 + 10) {
            pending.sent(2, record(agent), placement(1));
        }
        assert_eq!(pending.take().len(), WRITE);
        assert_eq!(pending.take().len(), 10);
        assert!(pending.take().is_empty());
    }

    /// A write takes each placement that supersedes what is held, the
    /// directory's or an earlier one of the same write, the agent's record
    /// once when the directory has none; and announces only its own
    /// leader's.
    #[test]
    fn a_write_takes_what_supersedes() {
        let mut write = Write::default();
        let held = placement(2);
        assert!(!write.take(Some(&held), &record(1), &placement(2), false));
        assert!(write.take(Some(&held), &record(1), &placement(3), true));
        assert!(!write.take(Some(&held), &record(1), &placement(3), false));
        assert!(write.take(Some(&held), &record(1), &placement(4), false));
        assert_eq!(write.changes.len(), 2, "two placements, no record");
        let (_, kept, announce) = &write.learned[&record(1).agent];
        assert_eq!((kept.term, *announce), (4, false));
        assert!(write.take(None, &record(2), &placement(1), false));
        assert!(write.take(None, &record(2), &placement(2), true));
        assert!(matches!(write.changes[2], Change::Agent(_)));
        assert_eq!(write.changes.len(), 5, "the new agent's record once");
    }
}
