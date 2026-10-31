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

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use vos_wire::ids::AgentId;
use vos_wire::peer::{CreationRecord, NodeNumber, PeerMessage, Placement};

use super::Inner;
use crate::lock;
use crate::storage::Change;

/// The most agents' placements one write stores.
const WRITE: usize = 4_096;
/// The most placements other nodes sent that wait to be stored: past it a
/// placement sent is dropped, and comes again with its sender's resend.
const SENT: usize = 1 << 18;

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

/// An agent's placements waiting: its leader's here, and those sent, each
/// in the order it came.
#[derive(Default)]
struct Waiting {
    own: Vec<Placement>,
    sent: Vec<Sent>,
}

/// A placement another node sent, with the record it came with.
struct Sent {
    from: NodeNumber,
    record: CreationRecord,
    placement: Placement,
}

/// The placements waiting, by agent, the agents in the order they came.
#[derive(Default)]
struct Pending {
    agents: HashMap<AgentId, Waiting>,
    order: VecDeque<AgentId>,
    /// The placements other nodes sent that wait, at most [`SENT`].
    sent: usize,
}

impl Pending {
    fn waiting(&mut self, agent: AgentId) -> &mut Waiting {
        let order = &mut self.order;
        self.agents.entry(agent).or_insert_with(|| {
            order.push_back(agent);
            Waiting::default()
        })
    }

    fn own(&mut self, agent: AgentId, placement: Placement) {
        let own = &mut self.waiting(agent).own;
        if !own.iter().any(|held| held.order() == placement.order()) {
            own.push(placement);
        }
    }

    /// False when it is not kept: past [`SENT`] waiting, a sender's resend
    /// brings it again.
    fn sent(&mut self, from: NodeNumber, record: CreationRecord, placement: Placement) -> bool {
        if self.sent >= SENT {
            return false;
        }
        let order = placement.order();
        let sent = &mut self.waiting(record.agent).sent;
        if sent
            .iter()
            .any(|sent| sent.from == from && sent.placement.order() == order)
        {
            return true;
        }
        sent.push(Sent {
            from,
            record,
            placement,
        });
        self.sent += 1;
        true
    }

    /// The first [`WRITE`] agents' placements, at most, taken out.
    fn take(&mut self) -> Vec<(AgentId, Waiting)> {
        let count = self.order.len().min(WRITE);
        let taken: Vec<(AgentId, Waiting)> = self
            .order
            .drain(..count)
            .filter_map(|agent| self.agents.remove_entry(&agent))
            .collect();
        self.sent -= taken
            .iter()
            .map(|(_, waiting)| waiting.sent.len())
            .sum::<usize>();
        if self.agents.is_empty() {
            // Many after a restart: what they took goes once they are stored.
            self.agents.shrink_to(WRITE);
            self.order.shrink_to(WRITE);
        }
        taken
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
    /// The newest placement it takes for each agent, with its record,
    /// whether the directory holds the agent already, and whether this
    /// node's leader gave it, and so announces it: one sent that
    /// supersedes it is its sender's to announce.
    learned: HashMap<AgentId, Learned>,
    /// The acknowledgements it owes: to whom, for what.
    acks: Vec<(NodeNumber, CreationRecord, Placement)>,
}

struct Learned {
    record: CreationRecord,
    placement: Placement,
    known: bool,
    own: bool,
}

impl Write {
    /// Take `placement` for `record`'s agent when it supersedes what the
    /// directory or this write already holds, each in the order it came, as
    /// one write after another would: false when it does not.
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
            .map(|learned| &learned.placement)
            .or(known);
        if held.is_some_and(|held| !placement.supersedes(held)) {
            return false;
        }
        self.learned.insert(
            agent,
            Learned {
                record: record.clone(),
                placement: placement.clone(),
                known: known.is_some(),
                own,
            },
        );
        true
    }

    /// The rows it writes: each agent's record where the directory has
    /// none, and its newest placement.
    fn changes(&self) -> Vec<Change> {
        let mut changes = Vec::with_capacity(self.learned.len());
        for (agent, learned) in &self.learned {
            if !learned.known {
                changes.push(Change::Agent(learned.record.clone()));
            }
            changes.push(Change::Placement {
                agent: *agent,
                placement: learned.placement.clone(),
            });
        }
        changes
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
                if lock(&self.recording.pending).sent(from, record, placement) {
                    self.recording.wake();
                }
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
            if let Some(known) = &known {
                for own in &waiting.own {
                    write.take(Some(&known.placement), &known.record, own, true);
                }
            }
            for sent in waiting.sent {
                let held = write
                    .learned
                    .get(&agent)
                    .map(|learned| &learned.record)
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
        let changes = write.changes();
        if !changes.is_empty()
            && let Err(error) = self.storage.commit(changes).await
        {
            tracing::error!(
                placements = write.learned.len(),
                "placements were not stored: {error}"
            );
            return;
        }
        for (agent, learned) in write.learned {
            self.learn(learned.record, learned.placement);
            if learned.own {
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
    /// sender and order; another order, or another sender, is another. Its
    /// own leader's are kept in the order they came.
    #[test]
    fn a_placement_sent_again_waits_once() {
        let mut pending = Pending::default();
        for _ in 0..1_000 {
            assert!(pending.sent(2, record(1), placement(3)));
        }
        pending.sent(3, record(1), placement(3));
        pending.sent(2, record(1), placement(4));
        pending.own(record(1).agent, placement(5));
        pending.own(record(1).agent, placement(4));
        pending.own(record(1).agent, placement(5));
        assert_eq!(pending.sent, 3);
        let taken = pending.take();
        assert_eq!(taken.len(), 1);
        let waiting = &taken[0].1;
        assert_eq!(waiting.sent.len(), 3);
        let own: Vec<u64> = waiting.own.iter().map(|own| own.term).collect();
        assert_eq!(own, [5, 4]);
        assert_eq!(pending.sent, 0);
    }

    /// One write takes at most [`WRITE`] agents' placements, the first to
    /// come; the rest wait for the next. Past [`SENT`] waiting, a placement
    /// sent is not kept.
    #[test]
    fn a_write_takes_a_bounded_number_in_turn() {
        let mut pending = Pending::default();
        for agent in 0..(WRITE as u32 + 10) {
            pending.sent(2, record(agent), placement(1));
        }
        let first = pending.take();
        assert_eq!(first.len(), WRITE);
        assert_eq!(first[0].0, record(0).agent);
        let rest = pending.take();
        assert_eq!(rest.len(), 10);
        assert_eq!(rest[0].0, record(WRITE as u32).agent);
        assert!(pending.take().is_empty());
        pending.sent = SENT;
        assert!(!pending.sent(2, record(1), placement(1)), "full");
        assert!(pending.agents.is_empty());
    }

    /// A write takes each placement that supersedes what is held, the
    /// directory's or an earlier one of the same write, in the order they
    /// came, and writes each agent's newest once, with its record when the
    /// directory has none; it announces only its own leader's.
    #[test]
    fn a_write_takes_what_supersedes() {
        let mut write = Write::default();
        let held = placement(2);
        assert!(!write.take(Some(&held), &record(1), &placement(2), false));
        assert!(write.take(Some(&held), &record(1), &placement(3), true));
        assert!(!write.take(Some(&held), &record(1), &placement(3), false));
        assert!(write.take(Some(&held), &record(1), &placement(4), false));
        let learned = &write.learned[&record(1).agent];
        assert_eq!((learned.placement.term, learned.own), (4, false));
        assert_eq!(write.changes().len(), 1, "the newest placement, no record");
        assert!(write.take(None, &record(2), &placement(1), false));
        assert!(write.take(None, &record(2), &placement(2), true));
        let changes = write.changes();
        assert_eq!(changes.len(), 3, "and the new agent's record once");
        assert_eq!(
            changes
                .iter()
                .filter(|change| matches!(change, Change::Agent(_)))
                .count(),
            1
        );
    }

    /// A committed placement is never replaced by a later uncommitted one
    /// of its configuration, however they come together: taken in turn,
    /// the second does not supersede the first.
    #[test]
    fn an_uncommitted_placement_does_not_replace_a_committed_one() {
        let mut write = Write::default();
        let held = Placement {
            index: 9,
            ..placement(4)
        };
        let committed = Placement {
            index: 10,
            ..placement(5)
        };
        let uncommitted = Placement {
            index: 10,
            committed: false,
            ..placement(6)
        };
        assert!(write.take(Some(&held), &record(1), &committed, true));
        assert!(!write.take(Some(&held), &record(1), &uncommitted, true));
        assert!(write.learned[&record(1).agent].placement.committed);
    }
}
