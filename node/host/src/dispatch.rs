//! What arrives from the space's other nodes: each frame checked, then
//! routed to its agent's group, or handled by the node itself (the
//! directory, and blobs).
//!
//! The directory: the node that creates an agent sends its record to
//! every node of the space, and again every second (and after every
//! restart) until each acknowledges holding it durably. A record comes only
//! from its creator, and one that differs from the record held for its
//! agent is refused, never written over.

use std::sync::Arc;
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_net::{Arrivals, Class, Incoming};
use vos_wire::Encode;
use vos_wire::ids::AgentId;
use vos_wire::peer::{CreationRecord, NodeNumber, PeerMessage};

use crate::group::Input;
use crate::node::Inner;
use crate::peer;
use crate::storage::Change;
use crate::store::BlobRef;

/// How often unacknowledged records are sent again.
const RESEND: Duration = Duration::from_secs(1);
/// How long the operator's creation waits for a majority of the replicas.
const MAJORITY: Duration = Duration::from_secs(30);
/// How long a blob being served waits for room in its peer's queue.
const BLOB_ROOM: Duration = Duration::from_secs(5);

/// Take arrivals until the network closes.
pub(crate) async fn dispatch(inner: Arc<Inner>, arrivals: Arrivals) {
    while let Some((class, incoming)) = take(&arrivals).await {
        inner.arrive(class, incoming).await;
    }
}

/// The next arrival: liveness and consensus before anything else.
async fn take(arrivals: &Arrivals) -> Option<(Class, Incoming)> {
    if let Ok(incoming) = arrivals.liveness.try_recv() {
        return Some((Class::Liveness, incoming));
    }
    if let Ok(incoming) = arrivals.consensus.try_recv() {
        return Some((Class::Consensus, incoming));
    }
    let on = |class: Class, queue: &smol::channel::Receiver<Incoming>| {
        let queue = queue.clone();
        async move { queue.recv().await.ok().map(|incoming| (class, incoming)) }
    };
    on(Class::Liveness, &arrivals.liveness)
        .or(on(Class::Consensus, &arrivals.consensus))
        .or(on(Class::Requests, &arrivals.requests))
        .or(on(Class::Bulk, &arrivals.bulk))
        .await
}

/// Send unacknowledged creation records again until each node holds them.
pub(crate) async fn resend_records(inner: Arc<Inner>) {
    loop {
        smol::Timer::after(RESEND).await;
        let pending: Vec<(AgentId, Vec<NodeNumber>)> = inner
            .unacknowledged
            .lock()
            .expect("the unacknowledged records")
            .iter()
            .map(|(agent, nodes)| (*agent, nodes.iter().copied().collect()))
            .collect();
        for (agent, nodes) in pending {
            let record = inner
                .directory
                .lock()
                .expect("the directory")
                .get(&agent)
                .cloned();
            if let Some(record) = record {
                for node in nodes {
                    inner.send(
                        node,
                        Class::Requests,
                        &PeerMessage::Directory(record.clone()),
                    );
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
            PeerMessage::Blob { .. } | PeerMessage::Directory(_)
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
                    PeerMessage::Directory(record) => inner.on_record(from, record).await,
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
                let routed = self.run(agent).is_some_and(|run| {
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
                }
            }
            PeerMessage::BlobRequest { agent, hashes } => self.serve_blobs(from, agent, hashes),
            PeerMessage::DirectoryAck { agent } => self.on_ack(from, agent),
            // A task of its own runs the call: the dispatcher never waits.
            PeerMessage::Forward { agent, token, call } => {
                self.on_forward(from, agent, token, call)
            }
            PeerMessage::Forwarded {
                agent,
                token,
                answer,
            } => self.on_forwarded(from, agent, token, answer),
            PeerMessage::Blob { .. } | PeerMessage::Directory(_) => {
                unreachable!("blobs and records are handled in tasks")
            }
            // Snapshots stream in step 3.7, and pair liveness comes in 3.8.
            PeerMessage::SnapshotChunk(_)
            | PeerMessage::SnapshotAck(_)
            | PeerMessage::Liveness { .. }
            | PeerMessage::LivenessAnswer { .. } => {}
        }
    }

    /// Send `from` the blobs it asked for that this node holds, if it
    /// replicates `agent`.
    fn serve_blobs(self: &Arc<Self>, from: NodeNumber, agent: AgentId, hashes: Vec<[u8; 32]>) {
        let replica = self
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .is_some_and(|record| record.replicas.contains(&from));
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
        if !self.is_wanted(&hash) {
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

    /// Keep a record from its creator, durably, then acknowledge it.
    async fn on_record(self: &Arc<Self>, from: NodeNumber, record: CreationRecord) {
        let _recording = self.recording.lock().await;
        let known = self
            .directory
            .lock()
            .expect("the directory")
            .get(&record.agent)
            .cloned();
        match known {
            Some(known) if known == record => {}
            Some(_) => {
                tracing::error!(
                    from,
                    agent = record.agent.0,
                    "a record differs from the one held for its agent; refused"
                );
                return;
            }
            None => {
                if let Err(error) = self.commit(vec![Change::Agent(record.clone())]).await {
                    tracing::error!(agent = record.agent.0, "a record was not stored: {error}");
                    return;
                }
                self.learn(record.clone());
            }
        }
        self.send(
            from,
            Class::Requests,
            &PeerMessage::DirectoryAck {
                agent: record.agent,
            },
        );
    }

    fn on_ack(&self, from: NodeNumber, agent: AgentId) {
        let mut unacknowledged = self
            .unacknowledged
            .lock()
            .expect("the unacknowledged records");
        if let Some(nodes) = unacknowledged.get_mut(&agent) {
            nodes.remove(&from);
            if nodes.is_empty() {
                unacknowledged.remove(&agent);
            }
        }
        drop(unacknowledged);
        self.acknowledged.notify(usize::MAX);
    }

    /// Send a record this node created to every other node, and keep
    /// sending it until each acknowledges it.
    pub(crate) fn announce(&self, record: &CreationRecord) {
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
        for node in &others {
            self.send(
                *node,
                Class::Requests,
                &PeerMessage::Directory(record.clone()),
            );
        }
        self.unacknowledged
            .lock()
            .expect("the unacknowledged records")
            .insert(record.agent, others);
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
                let waiting = unacknowledged.get(&record.agent);
                record
                    .replicas
                    .iter()
                    .filter(|replica| {
                        **replica == self.number
                            || !waiting.is_some_and(|nodes| nodes.contains(replica))
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
