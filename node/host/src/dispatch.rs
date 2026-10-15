//! What arrives from the space's other nodes: each frame checked, then
//! routed to its agent's group, or handled by the node itself (the
//! directory, and blobs).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use smol::future::FutureExt;
use vos_net::{Arrivals, Class, Incoming};
use vos_wire::Encode;
use vos_wire::ids::AgentId;
use vos_wire::peer::{NodeNumber, PeerMessage};

use crate::group::Input;
use crate::node::Inner;
use crate::peer;
use crate::store::BlobRef;
use crate::timeout;

/// How long a blob being served waits for room in its peer's queue.
const BLOB_ROOM: Duration = Duration::from_secs(5);

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
    next(Class::Consensus, &arrivals.consensus)
        .or(next(Class::Requests, &arrivals.requests))
        .or(next(Class::Bulk, &arrivals.bulk))
        .await
}

/// The next arrival on `queue`, of `class`.
async fn next(
    class: Class,
    queue: &smol::channel::Receiver<Incoming>,
) -> Option<(Class, Incoming)> {
    queue.recv().await.ok().map(|incoming| (class, incoming))
}

impl Inner {
    /// Send `message` to node `to`, on the class and the stream it travels
    /// on. Refused, it is dropped, as the network may drop it.
    pub(crate) fn send(&self, to: NodeNumber, message: &PeerMessage) {
        if let Some(network) = &self.network {
            let _ = network.send(
                to,
                peer::class(message),
                peer::stream(message),
                message.encode(),
            );
        }
    }

    /// Whether `from` replicates `agent`, as a node relaying, forwarding or
    /// asking for the agent must: an arrival from any other node is
    /// dropped, and counted.
    pub(crate) fn admit(&self, agent: AgentId, from: NodeNumber) -> bool {
        let known = self.directory.get(agent);
        match peer::check_replica(known.as_ref().map(|known| &known.placement), from) {
            Ok(()) => true,
            Err(refusal) => {
                self.drops.count(refusal);
                false
            }
        }
    }

    /// Give `agent`'s group `input`: false, and counted, when no group here
    /// runs it or its inbox is full; the sender sends again.
    fn to_group(&self, agent: AgentId, input: Input) -> bool {
        let routed = self
            .run(agent)
            .is_some_and(|run| run.inbox.try_send(input).is_ok());
        if !routed {
            self.drops.count(peer::Refusal::Unrouted);
        }
        routed
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
        self.counters.arrived[class as usize].fetch_add(1, Ordering::Relaxed);
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
        if matches!(
            message,
            PeerMessage::Blob { .. } | PeerMessage::Directory { .. }
        ) {
            let inner = Arc::clone(self);
            let space = Arc::clone(&self.numbers);
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
        let checked = peer::check(&self.numbers, from, (class, stream), &message, |agent| {
            self.followed(agent)
        });
        if let Err(refusal) = checked {
            self.drops.count(refusal);
            tracing::debug!(from, ?refusal, "a peer's message was dropped");
            return;
        }
        match message {
            PeerMessage::Raft { agent, message } => {
                let input = Input::Raft {
                    from,
                    message: peer::from_wire(message),
                };
                // No group here, or its inbox is full: Raft sends again.
                if !self.to_group(agent, input) {
                    self.ask_for_record(from, agent, self.run(agent).is_some());
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
            } => self.on_answer(&self.calls.forwards, from, agent, token, (term, answer)),
            PeerMessage::ReadIndex { agent, token } => self.on_read_index(from, agent, token),
            PeerMessage::ReadIndexAnswer {
                agent,
                token,
                index,
            } => self.on_answer(&self.reads, from, agent, token, index),
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
            PeerMessage::Behind {
                sender,
                receiver,
                relayed,
            } => self.on_behind(from, sender, receiver, relayed),
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
        let hashes: Vec<[u8; 32]> = hashes
            .into_iter()
            .filter(|hash| self.hooks.serve_blob(from, hash))
            .collect();
        let inner = Arc::clone(self);
        self.spawn(async move {
            // One at a time, each once the peer's queue has room for it:
            // a blob is read only to be sent.
            for hash in hashes {
                if let Some(network) = &inner.network
                    && timeout(BLOB_ROOM, network.ready(from, Class::Bulk))
                        .await
                        .is_none()
                {
                    return;
                }
                let blobs = inner.blobs.clone();
                let read = inner.offload(move || blobs.get(&hash)).await;
                if let Some(Ok(Some(bytes))) = read {
                    // Refused, it is dropped: the replica asks again.
                    inner.send(from, &PeerMessage::Blob { hash, bytes });
                }
            }
        });
    }

    /// Store a blob a group asked for, kept as it asked, and tell the
    /// groups waiting on it. One nobody asked for is dropped.
    async fn take_blob(&self, hash: [u8; 32], bytes: Vec<u8>) {
        // A store that failed takes nothing more.
        let Some(keep) = self.wanted(&hash).filter(|_| !self.storage.failed()) else {
            return;
        };
        let blob = BlobRef {
            hash,
            len: bytes.len() as u64,
        };
        match self.blobs.put_kept(blob, Arc::new(bytes), keep).await {
            Ok(()) => self.arrived(&hash),
            Err(error) => tracing::warn!("a blob from a peer was not stored: {error}"),
        }
    }
}
