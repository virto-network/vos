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

use vos_net::Class;
use vos_wire::batch::Message;
use vos_wire::ids::AgentId;
use vos_wire::peer::{NodeNumber, PeerMessage};

use crate::lock;
use crate::node::{Inner, Pending};
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

impl Inner {
    /// Where `agent`'s input goes. Through a replica, `turn` picks which:
    /// the same turn, the same replica, so one sender's messages keep their
    /// order on one stream.
    fn route(&self, agent: AgentId, turn: u64) -> Route {
        if let Some(run) = self.run(agent) {
            if lock(&run.agent.queue).leading {
                return Route::Here;
            }
            // Never to itself: a group naming this node leader before its
            // loop takes inputs has nowhere to put it yet.
            return match run.shared.state().leader {
                Some(leader) if leader != self.number => Route::To(leader),
                _ => Route::Nowhere,
            };
        }
        let replicas: Vec<NodeNumber> = self
            .placement(agent)
            .map(|placement| placement.replicas)
            .unwrap_or_default()
            .into_iter()
            .filter(|replica| *replica != self.number)
            .collect();
        if replicas.is_empty() {
            return Route::Nowhere;
        }
        Route::To(replicas[(turn % replicas.len() as u64) as usize])
    }

    /// Send `message` toward agent `to`, through the replica `turn` picks
    /// when it goes through one: false when it went nowhere, or the agent's
    /// queue here is full.
    pub(crate) fn deliver_message(&self, to: AgentId, message: Message, turn: u64) -> bool {
        match self.route(to, turn) {
            Route::Here => self.push(to, Pending::Message(message)).is_ok(),
            Route::To(node) => {
                self.sent_across.fetch_add(1, Ordering::Relaxed);
                self.send(
                    node,
                    Class::Requests,
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
                Class::Requests,
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
    /// a gap: its leader sends again at once. Routed as an acknowledgement
    /// is. A message dropped at a full queue waits for the sender's
    /// rounds, whose backoff a congested receiver needs.
    pub(crate) fn behind(&self, sender: AgentId, receiver: AgentId) {
        let turn = self.turn.fetch_add(1, Ordering::Relaxed);
        match self.route(sender, turn) {
            Route::Here => {
                self.note_behind(sender, receiver);
            }
            Route::To(node) => self.send(
                node,
                Class::Requests,
                &PeerMessage::Behind {
                    sender,
                    receiver,
                    relayed: false,
                },
            ),
            Route::Nowhere => {}
        }
    }

    /// A message for agent `to` from node `from`: a direct hop must come
    /// from a replica of its sender, a relayed one from a replica of `to`.
    pub(crate) fn on_deliver(
        &self,
        from: NodeNumber,
        to: AgentId,
        message: Message,
        relayed: bool,
    ) {
        let origin = if relayed { to } else { message.from };
        if let Err(refusal) = self.check_replica(origin, from) {
            self.drops.count(refusal);
            return;
        }
        match self.route(to, 0) {
            Route::Here => {
                if self.push(to, Pending::Message(message)).is_err() {
                    self.drops.count(Refusal::Unplaced);
                }
            }
            Route::To(leader) if !relayed && self.run(to).is_some() => {
                self.relayed.fetch_add(1, Ordering::Relaxed);
                self.send(
                    leader,
                    Class::Requests,
                    &PeerMessage::Deliver {
                        to,
                        message,
                        relayed: true,
                    },
                );
            }
            // The sender's leader sends it again.
            _ => self.drops.count(Refusal::Unplaced),
        }
    }

    /// An acknowledgement for agent `sender` from node `from`: a direct hop
    /// must come from a replica of its receiver, a relayed one from a
    /// replica of `sender`.
    pub(crate) fn on_acknowledge(
        &self,
        from: NodeNumber,
        sender: AgentId,
        receiver: AgentId,
        sequence: u64,
        relayed: bool,
    ) {
        let origin = if relayed { sender } else { receiver };
        if let Err(refusal) = self.check_replica(origin, from) {
            self.drops.count(refusal);
            return;
        }
        match self.route(sender, 0) {
            Route::Here => {
                let ack = Pending::Ack {
                    to: receiver,
                    sequence,
                };
                if self.push(sender, ack).is_err() {
                    self.drops.count(Refusal::Unplaced);
                }
            }
            Route::To(leader) if !relayed && self.run(sender).is_some() => self.send(
                leader,
                Class::Requests,
                &PeerMessage::Acknowledge {
                    sender,
                    receiver,
                    sequence,
                    relayed: true,
                },
            ),
            // The receiver acknowledges again, with the next delivery.
            _ => self.drops.count(Refusal::Unplaced),
        }
    }

    /// A `Behind` for agent `sender` from node `from`: a direct hop must
    /// come from a replica of its receiver, a relayed one from a replica of
    /// `sender`.
    pub(crate) fn on_behind(
        &self,
        from: NodeNumber,
        sender: AgentId,
        receiver: AgentId,
        relayed: bool,
    ) {
        let origin = if relayed { sender } else { receiver };
        if let Err(refusal) = self.check_replica(origin, from) {
            self.drops.count(refusal);
            return;
        }
        match self.route(sender, 0) {
            Route::Here => {
                if !self.note_behind(sender, receiver) {
                    self.drops.count(Refusal::Unplaced);
                }
            }
            Route::To(leader) if !relayed && self.run(sender).is_some() => self.send(
                leader,
                Class::Requests,
                &PeerMessage::Behind {
                    sender,
                    receiver,
                    relayed: true,
                },
            ),
            // The receiver says so again at its next refusal, and the
            // sender's rounds send again meanwhile.
            _ => self.drops.count(Refusal::Unplaced),
        }
    }
}
