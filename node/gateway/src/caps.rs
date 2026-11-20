//! Caps on the calls a port relays, beside the limits per address
//! (`light-node.md` §6.6): an onion's clients have no address, and a
//! proven call costs a node a verification, so each port bounds
//! - its proven calls in flight, from every connection: the node's
//!   verification budget behind it, which a flood through one port cannot
//!   take whole from the others;
//! - the proven calls in flight from one connection, and from one address
//!   or circuit;
//! - an agent's calls and proven calls from one address or circuit, a
//!   second with a burst, so one circuit cannot fill a personal agent's
//!   log.
//!
//! A proven call holds its places from its header on, before its body is
//! read: its connection's and circuit's first, at once (past either, the
//! SSH relay closes its channel), then the port's, for which it waits, one
//! waiter a circuit (past it, closed too), so no circuit queues ahead of
//! the others by sending headers; a request whose body is already read is
//! answered `Busy` past any cap, by the gateway, with no node asked. The clearnet's ports
//! cap nothing ([`Caps::none`]): their clients' addresses are the bound
//! ([`crate::limits`]); a large proven body waits for a place among the
//! port's [`PROVEN_BODIES`] alone.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use vos_abi::Encode;
use vos_api::Kind;
use vos_api::client::Answer;
use vos_wire::ingress::Response;

use crate::limits::{Rate, counted};

/// Proven calls' bodies past a call's limit one uncapped SSH port holds at
/// once, from every channel: as many as the gateway's HTTP holds.
pub const PROVEN_BODIES: usize = vos_http::CREDENTIALED_LARGE;

/// What one port's calls may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerPort {
    /// Proven calls in flight from every connection.
    pub proven: usize,
    /// Proven calls in flight from one connection.
    pub proven_per_connection: usize,
    /// Proven calls in flight from one address or circuit.
    pub proven_per_circuit: usize,
    /// Proven calls from one address or circuit waiting for a place among
    /// the port's.
    pub waiting_per_circuit: usize,
    /// An agent's calls and proven calls a second from one address or
    /// circuit, on average.
    pub agent_rate: u32,
    /// The same at once past the average.
    pub agent_burst: u32,
}

impl Default for PerPort {
    fn default() -> Self {
        Self {
            proven: 16,
            proven_per_connection: 2,
            proven_per_circuit: 4,
            waiting_per_circuit: 1,
            agent_rate: 4,
            agent_burst: 16,
        }
    }
}

/// Requests a port's caps refused, by the cap.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Refused {
    pub proven: u64,
    pub connection: u64,
    pub circuit: u64,
    pub agent: u64,
    pub waiting: u64,
}

/// The caps, each counting what it refused ([`Refused`]).
#[derive(Clone, Copy)]
#[repr(usize)]
enum Cap {
    Proven,
    Connection,
    Circuit,
    Agent,
    Waiting,
}

/// Counts by key, each at most a limit.
struct Counted<K>(Mutex<HashMap<K, usize>>);

impl<K: Hash + Eq + Copy> Counted<K> {
    fn take(&self, key: K, most: usize) -> bool {
        let mut open = self.0.lock().expect("the counts");
        let count = open.entry(key).or_insert(0);
        if *count >= most {
            if *count == 0 {
                open.remove(&key);
            }
            return false;
        }
        *count += 1;
        true
    }

    fn give(&self, key: K) {
        let mut open = self.0.lock().expect("the counts");
        if let Some(count) = open.get_mut(&key) {
            *count -= 1;
            if *count == 0 {
                open.remove(&key);
            }
        }
    }
}

/// One port's caps on calls.
pub struct Caps {
    per: Option<PerPort>,
    proven: Arc<Semaphore>,
    connections: Counted<SocketAddr>,
    circuits: Counted<IpAddr>,
    waiting: Counted<IpAddr>,
    agents: Rate<(IpAddr, u32)>,
    refused: [AtomicU64; Cap::Waiting as usize + 1],
}

/// A proven call's places among its port's, its connection's and its
/// circuit's, given back when it is answered.
pub struct Held {
    _own: Own,
    _place: OwnedSemaphorePermit,
}

/// A proven call's places among its connection's and its circuit's.
struct Own {
    caps: Arc<Caps>,
    peer: Option<SocketAddr>,
}

impl Drop for Own {
    fn drop(&mut self) {
        if let Some(peer) = self.peer {
            self.caps.connections.give(peer);
            self.caps.circuits.give(counted(peer.ip()));
        }
    }
}

/// A circuit's place among those waiting for the port's.
struct Waiting<'a> {
    caps: &'a Caps,
    circuit: IpAddr,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.caps.waiting.give(self.circuit);
    }
}

/// A request past a cap: answered `Busy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capped;

/// The answer a cap gives: the kind's `Busy`.
pub fn busy(kind: Kind) -> Answer {
    (kind as u16, Response::Busy.encode())
}

impl Caps {
    pub fn new(per: PerPort) -> Arc<Self> {
        Self::with(Some(per))
    }

    /// Caps on nothing: a clearnet port's.
    pub fn none() -> Arc<Self> {
        Self::with(None)
    }

    fn with(per: Option<PerPort>) -> Arc<Self> {
        let rates = per.unwrap_or_default();
        let proven = per.map_or(PROVEN_BODIES, |per| per.proven);
        Arc::new(Self {
            per,
            proven: Arc::new(Semaphore::new(proven)),
            connections: Counted(Mutex::new(HashMap::new())),
            circuits: Counted(Mutex::new(HashMap::new())),
            waiting: Counted(Mutex::new(HashMap::new())),
            agents: Rate::new(rates.agent_rate, rates.agent_burst),
            refused: Default::default(),
        })
    }

    /// Whether the port caps proven calls.
    pub fn caps(&self) -> bool {
        self.per.is_some()
    }

    fn refuse(&self, cap: Cap) {
        self.refused[cap as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// The connection's and circuit's places for a proven call from
    /// `peer`; `None` past either.
    fn own(self: &Arc<Self>, per: PerPort, peer: Option<SocketAddr>) -> Option<Own> {
        if let Some(peer) = peer {
            if !self.connections.take(peer, per.proven_per_connection) {
                self.refuse(Cap::Connection);
                return None;
            }
            if !self
                .circuits
                .take(counted(peer.ip()), per.proven_per_circuit)
            {
                self.connections.give(peer);
                self.refuse(Cap::Circuit);
                return None;
            }
        }
        Some(Own {
            caps: Arc::clone(self),
            peer,
        })
    }

    /// A proven call's places from `peer` now, if the port, its connection
    /// and its circuit have one: `Ok(None)` on a port that caps nothing.
    pub fn proven_now(self: &Arc<Self>, peer: Option<SocketAddr>) -> Result<Option<Held>, Capped> {
        let Some(per) = self.per else {
            return Ok(None);
        };
        let own = self.own(per, peer).ok_or(Capped)?;
        let Ok(place) = Arc::clone(&self.proven).try_acquire_owned() else {
            self.refuse(Cap::Proven);
            return Err(Capped);
        };
        Ok(Some(Held {
            _own: own,
            _place: place,
        }))
    }

    /// A proven call's places from `peer`, once the port has one: `Err` at
    /// once past its connection's or circuit's, or when its circuit has
    /// as many waiting already. Its connection's and circuit's are taken
    /// first, so what it waits for is the port's alone. On a port that caps
    /// nothing, a place among its [`PROVEN_BODIES`].
    pub async fn proven_wait(self: &Arc<Self>, peer: Option<SocketAddr>) -> Result<Held, Capped> {
        let Some(per) = self.per else {
            let place = Arc::clone(&self.proven)
                .acquire_owned()
                .await
                .expect("the port's places are never closed");
            return Ok(Held {
                _own: Own {
                    caps: Arc::clone(self),
                    peer: None,
                },
                _place: place,
            });
        };
        let own = self.own(per, peer).ok_or(Capped)?;
        let place = match Arc::clone(&self.proven).try_acquire_owned() {
            Ok(place) => place,
            Err(_) => {
                let _waiting = match peer {
                    Some(peer) => {
                        let circuit = counted(peer.ip());
                        if !self.waiting.take(circuit, per.waiting_per_circuit) {
                            self.refuse(Cap::Waiting);
                            return Err(Capped);
                        }
                        Some(Waiting {
                            caps: self,
                            circuit,
                        })
                    }
                    None => None,
                };
                Arc::clone(&self.proven)
                    .acquire_owned()
                    .await
                    .expect("the port's places are never closed")
            }
        };
        Ok(Held {
            _own: own,
            _place: place,
        })
    }

    /// Whether a call or proven call holding `body` from `peer` passes its
    /// agent's rate; other kinds always do.
    pub fn agent(&self, kind: Kind, body: &[u8], peer: Option<SocketAddr>) -> bool {
        if self.per.is_none() || !matches!(kind, Kind::Call | Kind::Credentialed) {
            return true;
        }
        let (Some(peer), Some(agent)) = (peer, body.get(..4)) else {
            return true;
        };
        let agent = u32::from_le_bytes(agent.try_into().expect("four bytes"));
        let passes = self.agents.take((counted(peer.ip()), agent));
        if !passes {
            self.refuse(Cap::Agent);
        }
        passes
    }

    /// Whether a whole request of `kind` holding `body` from `peer` may go
    /// on: the places it holds while in flight, if it is a proven call;
    /// `Err` when a cap answers it `Busy`.
    pub fn admit(
        self: &Arc<Self>,
        kind: Kind,
        body: &[u8],
        peer: Option<SocketAddr>,
    ) -> Result<Option<Held>, Capped> {
        let held = match kind {
            Kind::Credentialed => self.proven_now(peer)?,
            _ => None,
        };
        if !self.agent(kind, body, peer) {
            return Err(Capped);
        }
        Ok(held)
    }

    /// [`Caps::admit`] for a request that may hold `held`, the places its
    /// header took: then its agent's rate alone is left.
    pub fn admit_held(
        self: &Arc<Self>,
        kind: Kind,
        body: &[u8],
        peer: Option<SocketAddr>,
        held: Option<Held>,
    ) -> Result<Option<Held>, Capped> {
        match held {
            Some(held) => self
                .agent(kind, body, peer)
                .then_some(Some(held))
                .ok_or(Capped),
            None => self.admit(kind, body, peer),
        }
    }

    /// The requests refused so far, by the cap.
    pub fn refused(&self) -> Refused {
        let count = |cap: Cap| self.refused[cap as usize].load(Ordering::Relaxed);
        Refused {
            proven: count(Cap::Proven),
            connection: count(Cap::Connection),
            circuit: count(Cap::Circuit),
            agent: count(Cap::Agent),
            waiting: count(Cap::Waiting),
        }
    }

    /// The proven calls in flight now.
    pub fn proven(&self) -> usize {
        self.per
            .map_or(0, |per| per.proven - self.proven.available_permits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(agent: u32) -> Vec<u8> {
        agent.to_le_bytes().to_vec()
    }

    #[tokio::test]
    async fn a_ports_proven_calls_are_capped_whole_by_connection_circuit_and_agent() {
        let caps = Caps::new(PerPort {
            proven: 4,
            proven_per_connection: 2,
            proven_per_circuit: 3,
            waiting_per_circuit: 1,
            agent_rate: 1,
            agent_burst: 4,
        });
        let at = |text: &str| Some(text.parse::<SocketAddr>().unwrap());
        // Reads pass untouched.
        for _ in 0..100 {
            assert!(
                caps.admit(Kind::Query, &body(1), at("10.0.0.1:1"))
                    .unwrap()
                    .is_none()
            );
        }
        let first = caps
            .admit(Kind::Credentialed, &body(1), at("10.0.0.1:1"))
            .unwrap();
        let second = caps
            .admit(Kind::Credentialed, &body(2), at("10.0.0.1:1"))
            .unwrap();
        assert!(first.is_some() && second.is_some());
        assert!(
            caps.admit(Kind::Credentialed, &body(3), at("10.0.0.1:1"))
                .is_err(),
            "the connection's"
        );
        let third = caps.proven_wait(at("10.0.0.1:2")).await.unwrap();
        assert!(caps.proven_now(at("10.0.0.1:3")).is_err(), "the circuit's");
        let fourth = caps.proven_now(at("10.0.0.2:1")).unwrap();
        assert!(caps.proven_now(at("10.0.0.3:1")).is_err(), "the port's");
        assert_eq!(caps.proven(), 4);
        // A wait for the port's place ends as one is given back.
        let waiting = {
            let caps = Arc::clone(&caps);
            tokio::spawn(async move { caps.proven_wait(at("10.0.0.3:1")).await.is_ok() })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        // One waiter a circuit: another from it is refused at once, its
        // own places given back.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                caps.proven_wait(at("10.0.0.3:2"))
            )
            .await
            .expect("at once")
            .is_err(),
            "the circuit's waiter"
        );
        drop(first);
        assert!(waiting.await.unwrap());
        drop((second, third, fourth));
        // An agent's calls from one address: its burst, then `Busy`.
        let agent = |text: &str| caps.admit(Kind::Call, &body(9), at(text));
        assert!((0..4).all(|_| agent("10.0.0.4:1").is_ok()));
        assert!(
            agent("10.0.0.4:2").is_err(),
            "another connection, one address"
        );
        assert!(agent("10.0.0.5:1").is_ok(), "another address");
        assert_eq!(
            caps.refused(),
            Refused {
                proven: 1,
                connection: 1,
                circuit: 1,
                agent: 1,
                waiting: 1,
            }
        );
        assert_eq!(caps.proven(), 0);
        assert_eq!(
            busy(Kind::Call),
            (Kind::Call as u16, Response::Busy.encode())
        );
        let none = Caps::none();
        assert!(!none.caps());
        assert!((0..100).all(|_| {
            none.admit(Kind::Credentialed, &body(1), at("10.0.0.1:1"))
                .unwrap()
                .is_none()
        }));
    }
}
