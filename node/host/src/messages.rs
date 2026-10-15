//! Agents' messages between nodes, their acknowledgements, and their
//! receivers' calls to send again (`Behind`).
//!
//! One reaches its agent's queue when this node leads that agent, goes to
//! the agent's leader when this node replicates it, and otherwise to one of
//! its replicas, which relays it to its leader once. Anything a node cannot
//! place is dropped: the sender's leader sends again, and messages are
//! idempotent by their pair's sequence, acknowledgements monotone, and a
//! `Behind` only makes the sender send again what it sent.

use std::sync::atomic::Ordering;

use vos_wire::batch::Message;
use vos_wire::ids::AgentId;
use vos_wire::peer::{NodeNumber, PeerMessage};

use crate::node::{CallError, Inner, Pending};
use crate::peer::Refusal;

/// Where an agent's input goes from this node.
enum Route {
    /// Into its queue: this node leads it.
    Here,
    /// To this node: its leader, or one of its replicas.
    To(NodeNumber),
    /// Nowhere now: its group here knows no leader to send to.
    Nowhere,
}

/// Where an arrival from another node goes.
enum Hop {
    /// Into its agent's queue: this node leads it.
    Here,
    /// To the agent's leader, from this replica of it.
    Relay(NodeNumber),
}

impl Inner {
    /// Where `agent`'s input goes. Through a replica, `turn` picks which:
    /// the same turn, the same replica, so one sender's messages keep their
    /// order on one stream.
    fn route(&self, agent: AgentId, turn: u64) -> Route {
        if let Some(run) = self.run(agent) {
            if run.agent.leading() {
                return Route::Here;
            }
            // Never to itself: a group naming this node leader before its
            // loop takes inputs has nowhere to put it yet.
            return match run.shared.state().leader {
                Some(leader) if leader != self.number => Route::To(leader),
                _ => Route::Nowhere,
            };
        }
        let Some(known) = self.directory.get(agent) else {
            return Route::Nowhere;
        };
        let others = || {
            known
                .placement
                .replicas
                .iter()
                .filter(|replica| **replica != self.number)
        };
        match others().count() as u64 {
            0 => Route::Nowhere,
            count => Route::To(*others().nth((turn % count) as usize).expect("a replica")),
        }
    }

    /// Where an arrival for `agent` from node `from` goes: into the queue
    /// here, or to the agent's leader, which a direct hop is relayed to
    /// once. A direct hop must come from a replica of `origin`, the agent
    /// at its other end, and a relayed one from a replica of `agent`;
    /// anything else, or anything a node cannot place, is dropped and
    /// counted.
    fn hop(&self, from: NodeNumber, agent: AgentId, origin: AgentId, relayed: bool) -> Option<Hop> {
        if !self.admit(if relayed { agent } else { origin }, from) {
            return None;
        }
        match self.route(agent, 0) {
            Route::Here => Some(Hop::Here),
            Route::To(leader) if !relayed && self.run(agent).is_some() => Some(Hop::Relay(leader)),
            _ => {
                self.drops.count(Refusal::Unplaced);
                None
            }
        }
    }

    /// Send `message` toward agent `to`, through the replica `turn` picks
    /// when it goes through one: false when it went nowhere, or the agent's
    /// queue here is full.
    pub(crate) fn deliver_message(&self, to: AgentId, message: Message, turn: u64) -> bool {
        match self.route(to, turn) {
            Route::Here => self.push(to, Pending::Message(message)).is_ok(),
            Route::To(node) => {
                self.counters.sent_across.fetch_add(1, Ordering::Relaxed);
                self.send(
                    node,
                    &PeerMessage::Deliver {
                        to,
                        message,
                        relayed: false,
                    },
                );
                true
            }
            Route::Nowhere => false,
        }
    }

    /// Tell agent `sender` that `receiver` holds its messages through
    /// `sequence`.
    pub(crate) fn acknowledge(&self, sender: AgentId, receiver: AgentId, sequence: u64) {
        // Acknowledgements are monotone: any replica will do, a different
        // one each time.
        let turn = self.turn.fetch_add(1, Ordering::Relaxed);
        match self.route(sender, turn) {
            Route::Here => {
                let ack = Pending::Ack {
                    to: receiver,
                    sequence,
                };
                if let Err(error) = self.push(sender, ack) {
                    tracing::debug!(
                        sender = sender.0,
                        "an acknowledgement is not queued: {error:?}"
                    );
                }
            }
            Route::To(node) => self.send(
                node,
                &PeerMessage::Acknowledge {
                    sender,
                    receiver,
                    sequence,
                    relayed: false,
                },
            ),
            Route::Nowhere => {}
        }
    }

    /// Tell agent `sender` that `receiver` refused one of its messages past
    /// a gap, or dropped one at a full queue that has drained since: its
    /// leader sends again at once. Routed as an acknowledgement is. While
    /// the queue stays full, the sender's rounds and their backoff send
    /// again, as a congested receiver needs.
    pub(crate) fn behind(&self, sender: AgentId, receiver: AgentId) {
        let turn = self.turn.fetch_add(1, Ordering::Relaxed);
        match self.route(sender, turn) {
            Route::Here => {
                self.note_behind(sender, receiver);
            }
            Route::To(node) => self.send(
                node,
                &PeerMessage::Behind {
                    sender,
                    receiver,
                    relayed: false,
                },
            ),
            Route::Nowhere => {}
        }
    }

    /// A message for agent `to` from node `from`. Dropped, the sender's
    /// leader sends it again.
    pub(crate) fn on_deliver(
        &self,
        from: NodeNumber,
        to: AgentId,
        message: Message,
        relayed: bool,
    ) {
        match self.hop(from, to, message.from, relayed) {
            Some(Hop::Here) => match self.push(to, Pending::Message(message)) {
                Ok(()) => {}
                Err(CallError::Busy) => self.drops.count(Refusal::Full),
                Err(_) => self.drops.count(Refusal::Unplaced),
            },
            Some(Hop::Relay(leader)) => {
                self.counters.relayed.fetch_add(1, Ordering::Relaxed);
                self.send(
                    leader,
                    &PeerMessage::Deliver {
                        to,
                        message,
                        relayed: true,
                    },
                );
            }
            None => {}
        }
    }

    /// An acknowledgement for agent `sender` from node `from`. Dropped, the
    /// receiver acknowledges again, with the next delivery.
    pub(crate) fn on_acknowledge(
        &self,
        from: NodeNumber,
        sender: AgentId,
        receiver: AgentId,
        sequence: u64,
        relayed: bool,
    ) {
        match self.hop(from, sender, receiver, relayed) {
            Some(Hop::Here) => {
                let ack = Pending::Ack {
                    to: receiver,
                    sequence,
                };
                if self.push(sender, ack).is_err() {
                    self.drops.count(Refusal::Unplaced);
                }
            }
            Some(Hop::Relay(leader)) => self.send(
                leader,
                &PeerMessage::Acknowledge {
                    sender,
                    receiver,
                    sequence,
                    relayed: true,
                },
            ),
            None => {}
        }
    }

    /// A `Behind` for agent `sender` from node `from`. Dropped, the receiver
    /// says so again at its next refusal, and the sender's rounds send
    /// again meanwhile.
    pub(crate) fn on_behind(
        &self,
        from: NodeNumber,
        sender: AgentId,
        receiver: AgentId,
        relayed: bool,
    ) {
        match self.hop(from, sender, receiver, relayed) {
            Some(Hop::Here) => {
                if !self.note_behind(sender, receiver) {
                    self.drops.count(Refusal::Unplaced);
                }
            }
            Some(Hop::Relay(leader)) => self.send(
                leader,
                &PeerMessage::Behind {
                    sender,
                    receiver,
                    relayed: true,
                },
            ),
            None => {}
        }
    }
}
