//! Leader-aware routing across the nodes behind the gateway: a call to
//! the agent's leader as last learned, a read to any ready node in turn, an
//! operator's request to the one node it is signed for; `NotLeader` and
//! `Elsewhere` followed, resending the same frame, up to four times.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use vos_api::client::Answer;
use vos_api::{FRAME_ERROR, FrameError, Kind};
use vos_wire::ingress::{Contact, OperatorRefusal, Rejection, Response};
use vos_wire::{Decode, Encode};

use crate::upstream::Upstream;

/// Redirects a request follows before it answers what the last node said.
const REDIRECTS: usize = 4;

/// The nodes behind the gateway, and what it learned of their agents.
pub struct Gateway {
    upstreams: Vec<Arc<Upstream>>,
    /// Each agent's leader as last learned, by its index among the
    /// upstreams.
    leaders: Mutex<HashMap<u32, usize>>,
    turn: AtomicUsize,
    /// Requests sent to nodes, redirects included.
    sent: AtomicU64,
}

/// The frame error a relay answers when no node did.
pub fn unavailable() -> Answer {
    (FRAME_ERROR, FrameError::Unavailable.encode())
}

impl Gateway {
    pub fn new(upstreams: Vec<Arc<Upstream>>) -> Self {
        Self {
            upstreams,
            leaders: Mutex::new(HashMap::new()),
            turn: AtomicUsize::new(0),
            sent: AtomicU64::new(0),
        }
    }

    /// Requests the gateway sent to nodes.
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    /// Whether the node keyed `key` is behind the gateway.
    pub fn serves(&self, key: &[u8; 32]) -> bool {
        self.by_key(key).is_some()
    }

    fn by_key(&self, key: &[u8; 32]) -> Option<usize> {
        self.upstreams
            .iter()
            .position(|upstream| upstream.key == *key)
    }

    /// A request of `kind` holding `body`, relayed to the node it goes to:
    /// the answer frame's kind and body.
    pub async fn relay(&self, kind: Kind, body: &[u8]) -> Answer {
        if self.upstreams.is_empty() {
            return unavailable();
        }
        if kind.operator() {
            // The one node it is signed for, never another: the envelope
            // names it first.
            let node = body
                .get(..32)
                .and_then(|node| <[u8; 32]>::try_from(node).ok());
            return match node.and_then(|node| self.by_key(&node)) {
                Some(at) => self.send(at, kind, body).await,
                None => (
                    kind as u16,
                    Response::Rejected(Rejection::Operator(OperatorRefusal::OtherNode)).encode(),
                ),
            };
        }
        let agent = body
            .get(..4)
            .map(|agent| u32::from_le_bytes(agent.try_into().expect("four bytes")));
        // A leader not ready may have died: another node names the next.
        let learned = match (kind, agent) {
            (Kind::Call, Some(agent)) => self.leaders.lock().expect("leaders").get(&agent).copied(),
            _ => None,
        }
        .filter(|at| self.upstreams[*at].ready());
        let mut at = learned.unwrap_or_else(|| self.next());
        let mut redirects = 0;
        loop {
            let answer = self.send(at, kind, body).await;
            if !matches!(kind, Kind::Call | Kind::Query | Kind::Workflow) || answer.0 != kind as u16
            {
                return answer;
            }
            let next = match Response::decode_exact(&answer.1) {
                Some(Response::NotLeader {
                    leader: Some(leader),
                }) => self.at(&leader),
                Some(Response::Elsewhere { replicas }) => {
                    replicas.iter().find_map(|replica| self.at(replica))
                }
                _ => None,
            };
            match next {
                Some(next) if redirects < REDIRECTS => {
                    redirects += 1;
                    if let (Kind::Call, Some(agent)) = (kind, agent) {
                        self.leaders.lock().expect("leaders").insert(agent, next);
                    }
                    at = next;
                }
                _ => return answer,
            }
        }
    }

    /// The upstream a contact names, by its key.
    fn at(&self, contact: &Contact) -> Option<usize> {
        self.by_key(&contact.node.0)
    }

    /// The next upstream in turn that is ready ([`Upstream::ready`]), or
    /// the next in turn when none is.
    fn next(&self) -> usize {
        let count = self.upstreams.len();
        let first = self.turn.fetch_add(1, Ordering::Relaxed);
        (0..count)
            .map(|step| (first + step) % count)
            .find(|at| self.upstreams[*at].ready())
            .unwrap_or(first % count)
    }

    async fn send(&self, at: usize, kind: Kind, body: &[u8]) -> Answer {
        self.sent.fetch_add(1, Ordering::Relaxed);
        match self.upstreams[at].request(kind as u16, body).await {
            Ok(answer) => answer,
            Err(error) => {
                tracing::debug!(%error, "a node gave no answer");
                unavailable()
            }
        }
    }
}
