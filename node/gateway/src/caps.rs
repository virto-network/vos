//! Caps on the calls a port relays, beside the limits per address
//! (`light-node.md` §6.6): an onion's clients have no address, and a
//! proven call costs a node a verification, so each port bounds
//! - its proven calls in flight, from every connection (past them,
//!   `Busy`): the node's verification budget behind it, which a flood
//!   through one port cannot take whole from the others;
//! - a connection's proven calls in flight (past them, `Busy`);
//! - an agent's calls and proven calls from one address or circuit, a
//!   second with a burst (past them, `Busy`), so one circuit cannot fill a
//!   personal agent's log.
//!
//! The gateway answers `Busy` itself, never asking a node, and the client
//! backs off as it does on a node's. The clearnet's ports cap nothing
//! ([`Caps::none`]): their clients' addresses are the bound
//! ([`crate::limits`]).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use vos_api::Kind;
use vos_api::client::Answer;
use vos_wire::Encode;
use vos_wire::ingress::Response;

use crate::limits::{Rate, counted};

/// Proven calls' bodies past a call's limit the gateway's SSH ports hold
/// at once, from every channel: as many as its HTTP holds.
pub const PROVEN_BODIES: usize = vos_http::CREDENTIALED_LARGE;

/// The proven bodies' places a gateway's SSH ports share.
pub fn bodies() -> Arc<tokio::sync::Semaphore> {
    Arc::new(tokio::sync::Semaphore::new(PROVEN_BODIES))
}

/// What one port's calls may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerPort {
    /// Proven calls in flight from every connection.
    pub proven: usize,
    /// Proven calls in flight from one connection.
    pub proven_per_connection: usize,
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
            agent_rate: 4,
            agent_burst: 16,
        }
    }
}

/// Requests a port's caps answered `Busy`, by the cap.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Refused {
    pub proven: u64,
    pub connection: u64,
    pub agent: u64,
}

/// One port's caps on calls.
pub struct Caps {
    per: Option<PerPort>,
    proven: Mutex<usize>,
    connections: Mutex<HashMap<SocketAddr, usize>>,
    agents: Rate<(IpAddr, u32)>,
    refused: [AtomicU64; 3],
}

/// A proven call's places among its port's and its connection's, given
/// back when it is answered.
pub struct Held {
    caps: Arc<Caps>,
    connection: Option<SocketAddr>,
}

impl Drop for Held {
    fn drop(&mut self) {
        *self.caps.proven.lock().expect("the proven calls") -= 1;
        if let Some(connection) = self.connection {
            let mut open = self.caps.connections.lock().expect("the connections");
            if let Some(count) = open.get_mut(&connection) {
                *count -= 1;
                if *count == 0 {
                    open.remove(&connection);
                }
            }
        }
    }
}

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
        Arc::new(Self {
            per,
            proven: Mutex::new(0),
            connections: Mutex::new(HashMap::new()),
            agents: Rate::new(rates.agent_rate, rates.agent_burst),
            refused: Default::default(),
        })
    }

    /// Whether a request of `kind` holding `body` from the connection
    /// `peer` (its address, or its circuit's) may go on: `Ok` with the
    /// places it holds while in flight, if it is a proven call; `Err` when
    /// a cap answers it `Busy`. Only calls and proven calls are capped.
    pub fn admit(
        self: &Arc<Self>,
        kind: Kind,
        body: &[u8],
        peer: Option<SocketAddr>,
    ) -> Result<Option<Held>, ()> {
        let Some(per) = self
            .per
            .filter(|_| matches!(kind, Kind::Call | Kind::Credentialed))
        else {
            return Ok(None);
        };
        if let (Some(peer), Some(agent)) = (peer, body.get(..4)) {
            let agent = u32::from_le_bytes(agent.try_into().expect("four bytes"));
            if !self.agents.take((counted(peer.ip()), agent)) {
                return self.refuse(2);
            }
        }
        if kind != Kind::Credentialed {
            return Ok(None);
        }
        {
            let mut proven = self.proven.lock().expect("the proven calls");
            if *proven >= per.proven {
                drop(proven);
                return self.refuse(0);
            }
            *proven += 1;
        }
        let held = Held {
            caps: Arc::clone(self),
            connection: None,
        };
        let Some(peer) = peer else {
            return Ok(Some(held));
        };
        let mut open = self.connections.lock().expect("the connections");
        let count = open.entry(peer).or_insert(0);
        if *count >= per.proven_per_connection {
            drop(open);
            drop(held);
            return self.refuse(1);
        }
        *count += 1;
        let mut held = held;
        held.connection = Some(peer);
        Ok(Some(held))
    }

    fn refuse(&self, cap: usize) -> Result<Option<Held>, ()> {
        self.refused[cap].fetch_add(1, Ordering::Relaxed);
        Err(())
    }

    /// The requests answered `Busy` so far, by the cap.
    pub fn refused(&self) -> Refused {
        let count = |cap: usize| self.refused[cap].load(Ordering::Relaxed);
        Refused {
            proven: count(0),
            connection: count(1),
            agent: count(2),
        }
    }

    /// The proven calls in flight now.
    pub fn proven(&self) -> usize {
        *self.proven.lock().expect("the proven calls")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(agent: u32) -> Vec<u8> {
        agent.to_le_bytes().to_vec()
    }

    #[test]
    fn a_ports_proven_calls_are_capped_whole_by_connection_and_by_agent() {
        let caps = Caps::new(PerPort {
            proven: 3,
            proven_per_connection: 2,
            agent_rate: 1,
            agent_burst: 4,
        });
        let one: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let two: SocketAddr = "10.0.0.2:1000".parse().unwrap();
        let three: SocketAddr = "10.0.0.3:1000".parse().unwrap();
        // Reads pass untouched.
        for _ in 0..100 {
            assert!(
                caps.admit(Kind::Query, &body(1), Some(one))
                    .unwrap()
                    .is_none()
            );
        }
        let first = caps.admit(Kind::Credentialed, &body(1), Some(one)).unwrap();
        let second = caps.admit(Kind::Credentialed, &body(2), Some(one)).unwrap();
        assert!(first.is_some() && second.is_some());
        assert!(
            caps.admit(Kind::Credentialed, &body(3), Some(one)).is_err(),
            "the connection's"
        );
        let third = caps.admit(Kind::Credentialed, &body(1), Some(two)).unwrap();
        assert!(
            caps.admit(Kind::Credentialed, &body(1), Some(three))
                .is_err(),
            "the port's"
        );
        assert_eq!(caps.proven(), 3);
        drop(first);
        assert!(
            caps.admit(Kind::Credentialed, &body(4), Some(three))
                .is_ok()
        );
        drop((second, third));
        // An agent's calls from one address: its burst, then `Busy`.
        let agent = |at: &str| caps.admit(Kind::Call, &body(9), Some(at.parse().unwrap()));
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
                agent: 1
            }
        );
        assert_eq!(caps.proven(), 0);
        assert_eq!(
            busy(Kind::Call),
            (Kind::Call as u16, Response::Busy.encode())
        );
        let none = Caps::none();
        let one = Some(one);
        assert!((0..100).all(|_| {
            none.admit(Kind::Credentialed, &body(1), one)
                .unwrap()
                .is_none()
        }));
    }
}
