//! What arrives from the space's other nodes: each frame checked, then
//! routed to its agent's group, or handled by the node itself (the
//! directory, and blobs).
//!
//! The directory: where each agent runs. The node that creates an agent
//! sends its record and first placement to every node of the space, and
//! the agent's leader sends each new placement as its replicas change,
//! again every second until each node acknowledges holding it durably. A
//! node keeps the newest placement by its order (the announcing leader's
//! term, then the configuration's index), and a record that differs from
//! the one held for its agent is refused, never written over.
//!
//! An announcer can stop before every member holds its placement, and
//! then no one sends it. So a node sent Raft traffic for an agent it runs
//! no group for asks the sender, which answers with the record and the
//! placement it holds if that names the asker: a member that missed its
//! placement learns it once its group needs it, a vote or entries.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_net::{Arrivals, Class, Incoming};
use vos_wire::Encode;
use vos_wire::ids::AgentId;
use vos_wire::peer::{CreationRecord, NodeNumber, PeerMessage, Placement};

use crate::group::Input;
use crate::node::{Inner, Order};
use crate::peer;
use crate::storage::Change;
use crate::store::BlobRef;

/// How often unacknowledged records are sent again.
const RESEND: Duration = Duration::from_secs(1);
/// How long the operator's creation waits for a majority of the replicas.
const MAJORITY: Duration = Duration::from_secs(30);
/// How long a blob being served waits for room in its peer's queue.
const BLOB_ROOM: Duration = Duration::from_secs(5);
/// How often a node asks one peer for one agent's record.
const ASK_EVERY: Duration = Duration::from_secs(1);
/// The asks kept before those past [`ASK_EVERY`] are forgotten.
const ASKS_KEPT: usize = 1024;

/// Whether a node sent Raft traffic for an agent asks the sender for its
/// record: when it runs no group for the agent, and the placement it
/// holds, if any, leaves it out (a newer one may name it); at most once
/// every [`ASK_EVERY`] per agent and peer. A group's full inbox does not
/// ask, and nor does a replica whose placement names it but which runs no
/// group (one refused for another agent program).
pub(crate) fn should_ask(
    held: Option<&Placement>,
    has_group: bool,
    me: NodeNumber,
    last: Option<Instant>,
    now: Instant,
) -> bool {
    !has_group
        && !held.is_some_and(|placement| placement.admits(me))
        && last.is_none_or(|last| now.saturating_duration_since(last) >= ASK_EVERY)
}

/// Whether node `me`, holding `placement`, answers `asker`'s request for
/// the agent's record: when it names the asker (a creation's placement is
/// its record's replicas, committed), and `me` is one the asker takes a
/// placement from, a node of it or of the configuration before.
pub(crate) fn should_answer(placement: &Placement, asker: NodeNumber, me: NodeNumber) -> bool {
    placement.admits(asker) && (placement.replicas.contains(&me) || placement.before.contains(&me))
}

/// Forget the asks older than [`ASK_EVERY`], once more than [`ASKS_KEPT`]
/// are kept.
pub(crate) fn trim_asks(asked: &mut HashMap<(AgentId, NodeNumber), Instant>, now: Instant) {
    if asked.len() > ASKS_KEPT {
        asked.retain(|_, at| now.saturating_duration_since(*at) < ASK_EVERY);
    }
}

/// Take arrivals until the network closes. Work that waits on a group or
/// a quorum runs in a task of its own, so the frames behind it are not
/// held.
pub(crate) async fn dispatch(inner: Arc<Inner>, arrivals: Arrivals) {
    while let Some((class, incoming)) = take(&arrivals).await {
        inner.arrive(class, incoming).await;
    }
}

/// The next arrival: consensus before anything else. Liveness frames go
/// to the pair heartbeat's own thread.
async fn take(arrivals: &Arrivals) -> Option<(Class, Incoming)> {
    if let Ok(incoming) = arrivals.consensus.try_recv() {
        return Some((Class::Consensus, incoming));
    }
    let on = |class: Class, queue: &smol::channel::Receiver<Incoming>| {
        let queue = queue.clone();
        async move { queue.recv().await.ok().map(|incoming| (class, incoming)) }
    };
    on(Class::Consensus, &arrivals.consensus)
        .or(on(Class::Requests, &arrivals.requests))
        .or(on(Class::Bulk, &arrivals.bulk))
        .await
}

/// Send unacknowledged placements again until each node holds them.
pub(crate) async fn resend_records(inner: Arc<Inner>) {
    loop {
        smol::Timer::after(RESEND).await;
        // Every node runs this, a space of one too.
        inner.halt_if_store_failed();
        let pending: Vec<(AgentId, Order, Vec<NodeNumber>)> = inner
            .unacknowledged
            .lock()
            .expect("the unacknowledged records")
            .iter()
            .map(|(agent, (order, nodes))| (*agent, *order, nodes.iter().copied().collect()))
            .collect();
        for (agent, announced, nodes) in pending {
            let known = inner
                .directory
                .lock()
                .expect("the directory")
                .get(&agent)
                .cloned();
            // A placement held since from elsewhere is its sender's to
            // announce: this node may not even be one that may send it.
            if known
                .as_ref()
                .is_some_and(|known| known.placement.order() != announced)
            {
                let mut unacknowledged = inner
                    .unacknowledged
                    .lock()
                    .expect("the unacknowledged records");
                if unacknowledged
                    .get(&agent)
                    .is_some_and(|(order, _)| *order == announced)
                {
                    unacknowledged.remove(&agent);
                }
                continue;
            }
            if let Some(known) = known {
                let message = PeerMessage::Directory {
                    record: known.record,
                    placement: known.placement,
                };
                for node in nodes {
                    inner.send(node, Class::Requests, &message);
                }
            }
        }
    }
}

impl Inner {
    pub(crate) fn send(&self, to: NodeNumber, class: Class, message: &PeerMessage) {
        if let Some(network) = &self.network {
            let _ = network.send(to, class, peer::stream(message), message.encode());
        }
    }

    /// Give `agent`'s group `input`: dropped, and counted, when no group
    /// here runs it or its inbox is full; the sender sends again.
    fn to_group(&self, agent: AgentId, input: Input) {
        let routed = self
            .run(agent)
            .is_some_and(|run| run.inbox.try_send(input).is_ok());
        if !routed {
            self.drops.count(peer::Refusal::Unrouted);
        }
    }

    /// The leader `agent`'s replica here follows, and its term.
    fn followed(&self, agent: AgentId) -> Option<(NodeNumber, u64)> {
        let state = self.run(agent)?.shared.state();
        Some((state.leader?, state.term))
    }

    /// Check an arrival and route it. Only Raft routing runs inline: a
    /// blob (hashed) and a creation record (committed) run in tasks of
    /// their own, so no group's consensus waits behind them.
    async fn arrive(self: &Arc<Self>, class: Class, incoming: Incoming) {
        let Incoming {
            from,
            stream,
            frame,
        } = incoming;
        let message = match peer::decode(&frame) {
            Ok(message) => message,
            Err(refusal) => {
                self.drops.count(refusal);
                return;
            }
        };
        let space = self
            .space
            .as_ref()
            .map(|space| space.numbers())
            .unwrap_or_default();
        if matches!(
            message,
            PeerMessage::Blob { .. } | PeerMessage::Directory { .. }
        ) {
            let inner = Arc::clone(self);
            self.spawn(async move {
                let checked = inner
                    .offload(move || {
                        let checked =
                            peer::check(&space, from, (class, stream), &message, |_| None);
                        (checked, message)
                    })
                    .await;
                let Some((checked, message)) = checked else {
                    return;
                };
                if let Err(refusal) = checked {
                    inner.drops.count(refusal);
                    return;
                }
                match message {
                    PeerMessage::Blob { hash, bytes } => inner.take_blob(hash, bytes).await,
                    PeerMessage::Directory { record, placement } => {
                        inner.on_directory(from, record, placement).await
                    }
                    _ => unreachable!("only blobs and records are handled here"),
                }
            });
            return;
        }
        let checked = peer::check(&space, from, (class, stream), &message, |agent| {
            self.followed(agent)
        });
        if let Err(refusal) = checked {
            self.drops.count(refusal);
            tracing::debug!(from, ?refusal, "a peer's message was dropped");
            return;
        }
        match message {
            PeerMessage::Raft { agent, message } => {
                let run = self.run(agent);
                let routed = run.as_ref().is_some_and(|run| {
                    run.inbox
                        .try_send(Input::Raft {
                            from,
                            message: peer::from_wire(message),
                        })
                        .is_ok()
                });
                if !routed {
                    // No group here, or its inbox is full: Raft sends again.
                    self.drops.count(peer::Refusal::Unrouted);
                    self.ask_for_record(from, agent, run.is_some());
                }
            }
            PeerMessage::BlobRequest { agent, hashes } => self.serve_blobs(from, agent, hashes),
            PeerMessage::DirectoryAck { agent, order, runs } => {
                self.on_ack(from, agent, order, runs)
            }
            PeerMessage::DirectoryRequest { agent } => self.on_request(from, agent),
            PeerMessage::Forward {
                agent,
                token,
                term,
                call,
            } => self.on_forward(from, agent, token, term, call),
            PeerMessage::Forwarded {
                agent,
                token,
                term,
                answer,
            } => self.on_forwarded(from, agent, token, term, answer),
            PeerMessage::ReadIndex { agent, token } => self.on_read_index(from, agent, token),
            PeerMessage::ReadIndexAnswer {
                agent,
                token,
                index,
            } => self.on_read_index_answer(from, agent, token, index),
            PeerMessage::Deliver {
                to,
                message,
                relayed,
            } => self.on_deliver(from, to, message, relayed),
            PeerMessage::Acknowledge {
                sender,
                receiver,
                sequence,
                relayed,
            } => self.on_acknowledge(from, sender, receiver, sequence, relayed),
            PeerMessage::Blob { .. } | PeerMessage::Directory { .. } => {
                unreachable!("blobs and records are handled in tasks")
            }
            PeerMessage::SnapshotChunk(chunk) => {
                let agent = chunk.agent;
                self.to_group(agent, Input::Chunk { from, chunk });
            }
            PeerMessage::SnapshotAck(ack) => {
                let agent = ack.agent;
                self.to_group(agent, Input::ChunkAck { from, ack });
            }
            // Taken on the pair heartbeat's own thread; none arrives here.
            PeerMessage::Liveness { .. } => {}
        }
    }

    /// Send `from` the blobs it asked for that this node holds, if it
    /// replicates `agent`.
    fn serve_blobs(self: &Arc<Self>, from: NodeNumber, agent: AgentId, hashes: Vec<[u8; 32]>) {
        let replica = self
            .placement(agent)
            .is_some_and(|placement| placement.admits(from));
        if !replica {
            tracing::debug!(
                from,
                agent = agent.0,
                "a blob request from a node not replicating its agent"
            );
            return;
        }
        if !self.hooks.serve_blob() {
            return;
        }
        let inner = Arc::clone(self);
        self.spawn(async move {
            // One at a time, each once the peer's queue has room for it:
            // a blob is read only to be sent.
            for hash in hashes {
                if let Some(network) = &inner.network {
                    let room = async {
                        network.ready(from, Class::Bulk).await;
                        true
                    };
                    let late = async {
                        smol::Timer::after(BLOB_ROOM).await;
                        false
                    };
                    if !room.or(late).await {
                        return;
                    }
                }
                let blobs = inner.blobs.clone();
                let read = inner.offload(move || blobs.get(&hash)).await;
                if let Some(Ok(Some(bytes))) = read {
                    // Refused, it is dropped: the replica asks again.
                    inner.send(from, Class::Bulk, &PeerMessage::Blob { hash, bytes });
                }
            }
        });
    }

    /// Store a blob a group asked for, and tell the groups waiting on it.
    /// One nobody asked for is dropped.
    async fn take_blob(&self, hash: [u8; 32], bytes: Vec<u8>) {
        // A store that failed takes nothing more.
        if !self.is_wanted(&hash) || self.storage.failed() {
            return;
        }
        let blob = BlobRef {
            hash,
            len: bytes.len() as u64,
        };
        match self.blobs.put(blob, Arc::new(bytes)).await {
            Ok(()) => self.arrived(&hash),
            Err(error) => tracing::warn!("a blob from a peer was not stored: {error}"),
        }
    }

    /// Keep a placement newer than the one held, with its record, durably,
    /// act on it, then acknowledge it, saying whether this node could run
    /// the agent's program.
    async fn on_directory(
        self: &Arc<Self>,
        from: NodeNumber,
        record: CreationRecord,
        placement: Placement,
    ) {
        // A store that failed takes nothing more, and its node does not
        // acknowledge: the sender's resends are dropped quietly.
        if self.storage.failed() {
            return;
        }
        let agent = record.agent;
        let order = placement.order();
        let recording = self.recording.lock().await;
        let known = self
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .cloned();
        if known.as_ref().is_some_and(|known| known.record != record) {
            tracing::error!(
                from,
                agent = agent.0,
                "a record differs from the one held for its agent; refused"
            );
            return;
        }
        if known
            .as_ref()
            .is_none_or(|known| placement.supersedes(&known.placement))
        {
            let mut changes = vec![Change::Placement {
                agent,
                placement: placement.clone(),
            }];
            if known.is_none() {
                changes.insert(0, Change::Agent(record.clone()));
            }
            if let Err(error) = self.commit(changes).await {
                tracing::error!(agent = agent.0, "a placement was not stored: {error}");
                return;
            }
            self.learn(record.clone(), placement);
        }
        drop(recording);
        self.send(
            from,
            Class::Requests,
            &PeerMessage::DirectoryAck {
                agent,
                order,
                runs: record.program == self.program_hash,
            },
        );
    }

    /// Ask `from`, whose group sent Raft traffic for `agent` that found no
    /// room here, for the agent's record and placement, as [`should_ask`]
    /// says.
    fn ask_for_record(&self, from: NodeNumber, agent: AgentId, has_group: bool) {
        let held = self
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .map(|known| known.placement.clone());
        let now = Instant::now();
        {
            let mut asked = self.asked.lock().expect("the asks");
            let last = asked.get(&(agent, from)).copied();
            if !should_ask(held.as_ref(), has_group, self.number, last, now) {
                return;
            }
            asked.insert((agent, from), now);
            trim_asks(&mut asked, now);
        }
        self.send(
            from,
            Class::Requests,
            &PeerMessage::DirectoryRequest { agent },
        );
    }

    /// Answer `from`'s request for `agent`'s record with the record and
    /// placement held here, if the placement names it: an ordinary record,
    /// acknowledged as any. It is sent once; the asker asks again.
    fn on_request(&self, from: NodeNumber, agent: AgentId) {
        let Some(known) = self
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .cloned()
        else {
            return;
        };
        if !should_answer(&known.placement, from, self.number) {
            return;
        }
        self.send(
            from,
            Class::Requests,
            &PeerMessage::Directory {
                record: known.record,
                placement: known.placement,
            },
        );
    }

    fn on_ack(&self, from: NodeNumber, agent: AgentId, order: Order, runs: bool) {
        let mut unacknowledged = self
            .unacknowledged
            .lock()
            .expect("the unacknowledged records");
        if let Some((announced, nodes)) = unacknowledged.get_mut(&agent)
            && order >= *announced
        {
            nodes.remove(&from);
            if nodes.is_empty() {
                unacknowledged.remove(&agent);
            }
        }
        drop(unacknowledged);
        {
            let mut refusing = self.refusing.lock().expect("the refusing nodes");
            let nodes = refusing.entry(agent).or_default();
            if runs {
                nodes.remove(&from);
            } else {
                nodes.insert(from);
            }
        }
        if let Some(waiting) = self
            .capable
            .lock()
            .expect("the capability waits")
            .remove(&(agent, from))
        {
            let _ = waiting.try_send(runs);
        }
        self.acknowledged.notify(usize::MAX);
    }

    /// Send where `agent` runs, with its record, to every other node, and
    /// keep sending it until each acknowledges it.
    pub(crate) fn announce(&self, agent: AgentId) {
        let Some(known) = self
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .cloned()
        else {
            return;
        };
        let others: std::collections::BTreeSet<NodeNumber> = self
            .space
            .as_ref()
            .map(|space| space.numbers())
            .unwrap_or_default()
            .into_iter()
            .filter(|node| *node != self.number)
            .collect();
        if others.is_empty() {
            return;
        }
        let order = known.placement.order();
        let message = PeerMessage::Directory {
            record: known.record,
            placement: known.placement,
        };
        for node in &others {
            self.send(*node, Class::Requests, &message);
        }
        self.unacknowledged
            .lock()
            .expect("the unacknowledged records")
            .insert(agent, (order, others));
    }

    /// Whether `node` could run `agent`'s program, as it answers when sent
    /// where the agent runs: false when it does not answer in `within`.
    pub(crate) async fn could_run(
        &self,
        agent: AgentId,
        node: NodeNumber,
        within: Duration,
    ) -> bool {
        let Some(known) = self
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .cloned()
        else {
            return false;
        };
        let (answer, answered) = smol::channel::bounded(1);
        self.capable
            .lock()
            .expect("the capability waits")
            .insert((agent, node), answer);
        let message = PeerMessage::Directory {
            record: known.record,
            placement: known.placement,
        };
        let until = Instant::now() + within;
        let runs = loop {
            self.send(node, Class::Requests, &message);
            let heard = async { answered.recv().await.ok() };
            let quiet = async {
                smol::Timer::after(RESEND.min(until.saturating_duration_since(Instant::now())))
                    .await;
                None
            };
            if let Some(runs) = heard.or(quiet).await {
                break runs;
            }
            if Instant::now() >= until {
                break false;
            }
        };
        self.capable
            .lock()
            .expect("the capability waits")
            .remove(&(agent, node));
        runs
    }

    /// Wait until a majority of `record`'s replicas hold it durably: false
    /// when they do not within [`MAJORITY`].
    pub(crate) async fn held_by_majority(&self, record: &CreationRecord) -> bool {
        let needed = record.replicas.len() / 2 + 1;
        let until = Instant::now() + MAJORITY;
        loop {
            let acknowledged = self.acknowledged.listen();
            let holding = {
                let unacknowledged = self
                    .unacknowledged
                    .lock()
                    .expect("the unacknowledged records");
                let waiting = unacknowledged.get(&record.agent).map(|(_, nodes)| nodes);
                let refusing = self.refusing.lock().expect("the refusing nodes");
                let refusing = refusing.get(&record.agent);
                // A replica counts once it holds the record and could run
                // the agent's program.
                record
                    .replicas
                    .iter()
                    .filter(|replica| {
                        **replica == self.number
                            || (!waiting.is_some_and(|nodes| nodes.contains(replica))
                                && !refusing.is_some_and(|nodes| nodes.contains(replica)))
                    })
                    .count()
            };
            if holding >= needed {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            acknowledged
                .or(async {
                    smol::Timer::at(until).await;
                })
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placement(replicas: Vec<NodeNumber>) -> Placement {
        Placement {
            replicas,
            before: Vec::new(),
            term: 2,
            index: 1,
            joint: false,
            committed: true,
        }
    }

    /// A node asks only when it runs no group and its placement leaves it
    /// out, at most once a second per agent and peer.
    #[test]
    fn a_node_asks_for_a_record_only_when_it_may_need_one() {
        let now = Instant::now();
        let names_me = placement(vec![1, 2, 3]);
        let leaves_me_out = placement(vec![1, 2, 4]);
        assert!(should_ask(None, false, 3, None, now), "no placement");
        assert!(should_ask(Some(&leaves_me_out), false, 3, None, now));
        assert!(!should_ask(None, true, 3, None, now), "a group runs here");
        assert!(
            !should_ask(Some(&names_me), false, 3, None, now),
            "named, yet no group: refused for another program"
        );
        let asked = now - Duration::from_millis(400);
        assert!(
            !should_ask(None, false, 3, Some(asked), now),
            "asked lately"
        );
        assert!(should_ask(None, false, 3, Some(asked), asked + ASK_EVERY));
    }

    /// A node answers the members its placement names, and no one else,
    /// and only with a placement the asker takes from it.
    #[test]
    fn a_node_answers_only_the_members_its_placement_names() {
        let held = placement(vec![1, 2, 3]);
        assert!(should_answer(&held, 3, 2));
        assert!(!should_answer(&held, 4, 2));
        assert!(
            !should_answer(&held, 3, 4),
            "a placement leaving the answerer out, which the asker would refuse"
        );
        let joint = Placement {
            before: vec![1, 2, 4],
            committed: false,
            ..held.clone()
        };
        assert!(
            should_answer(&joint, 4, 2),
            "a member of the configuration before"
        );
        let removing = Placement {
            replicas: vec![1, 2, 5],
            before: vec![1, 2, 3],
            ..held.clone()
        };
        assert!(
            should_answer(&removing, 5, 3),
            "a leader that removed itself"
        );
        let created = Placement::created(&CreationRecord {
            agent: AgentId(1 << 24 | 1),
            replicas: vec![1, 2, 3],
            creator: 1,
            time: 0,
            program: vos_wire::ids::ProgramHash([0; 32]),
            accumulate_gas: 0,
        });
        assert!(should_answer(&created, 3, 2));
    }

    /// The asks kept are bounded: past the bound, those older than the
    /// limit go, and the recent stay.
    #[test]
    fn the_asks_kept_stay_bounded() {
        let now = Instant::now();
        let old = now - ASK_EVERY;
        let mut asked: HashMap<(AgentId, NodeNumber), Instant> = (0..ASKS_KEPT as u32)
            .map(|agent| ((AgentId(agent), 2), old))
            .collect();
        trim_asks(&mut asked, now);
        assert_eq!(asked.len(), ASKS_KEPT, "within the bound, all kept");
        asked.insert((AgentId(u32::MAX), 2), now);
        trim_asks(&mut asked, now);
        assert_eq!(asked.len(), 1);
        assert!(asked.contains_key(&(AgentId(u32::MAX), 2)));
    }
}
