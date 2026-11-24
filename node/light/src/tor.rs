//! The client over arti (`light-node.md` §6.2–§6.5, E22, E23): how the
//! light node reaches a space's gateways.
//!
//! - **One `TorClient` a process** ([`Tor`]): its state and cache in the
//!   app's private directory, checked by arti whatever the environment
//!   says; plain bridges pasted in the chrome ([`bridge`]); a bootstrap
//!   bounded, and its failure named: a wrong clock, a bridge that does not
//!   answer, a network that blocks Tor ([`BootstrapError`]).
//! - **`vos-api` over SSH over the onion** ([`Client`]): each request goes
//!   under its [`Purpose`](crate::route::Purpose), on that purpose's
//!   connection to the space, an SSH connection whose `vos-api` subsystem
//!   carries the node API's frames, multiplexed. Each connection is its own
//!   circuit (an arti isolation token drawn for it alone) under its own SSH
//!   key (an ed25519 key drawn for it alone), so the gateway cannot join two
//!   purposes by circuit or by key (§8, H10). A kept-open purpose's connection stays while it is
//!   used, closed after [`Config::idle`] without a request; a proven call
//!   and a fetch each take one of their own, closed once answered.
//! - **A spare a one-shot purpose** ([`Client::keep_spares`]): for a proven
//!   call and for a fetch, one connection built ahead to the space, its SSH
//!   handshake and subsystem done, which the purpose's next request takes,
//!   used once. Spares are built one at a time, each after a delay drawn
//!   below [`Config::spare_gap`], only while the app is in the foreground
//!   ([`Client::set_foreground`]); one left unused past a time drawn around
//!   [`Config::spare_idle`] is closed and built anew.
//! - **A fresh connection that fails is retried on a new circuit**, up to
//!   [`Config::attempts`], through the next onion of the pinned set (§6.4).
//!   When every attempt found the onion service unpublished or unreachable
//!   ([`Unpublished`], a service just relaunched), one more is made after
//!   [`Config::again`]. Every step has
//!   its deadline ([`Config`]), as nothing in arti or SSH ends on its own;
//!   a request that misses one loses its connection.
//! - **Dormant** ([`Client::set_dormant`]): no connection, no spare, no
//!   timer, arti told so; nothing is sent until the client is woken.
//! - **The Tor policy** ([`crate::route`]): decided before a byte leaves;
//!   an anonymous request with no onion to take is refused.
//! - **s4's screens over the same Tor** ([`Client::screens`]): s4's own SSH
//!   session carried as bytes between a stream it hands over (a socketpair's
//!   descriptor, [`Client::screens_fd`]) and the space's onion, on a circuit
//!   of its own.
//! - **The pinned onion set** ([`Client::refresh_onions`]): the registrar's
//!   current set, read through any onion of the pinned one, replaces it.
//!   The answer is the gateway's word, as any answer it relays (§8, H5).
//! - **What it opened** ([`Client::opened`]): each hour's rendezvous by
//!   purpose, in the foreground and in the background, for the bound on
//!   rendezvous an hour.
//! - **The credential tree's feed** ([`Client::read_tree`]): each page on
//!   the space's one feed connection, which carries reads alone and names
//!   nothing of the member's; the tree kept by a [`crate::TreeKeeper`].

mod arti;
mod client;
mod connection;
mod dial;
mod tally;

pub use arti::{BootstrapError, BridgeError, Tor, TorConfig, bridge, onion_address, onion_key};
pub use client::{Client, Error, FEED_PAGES, Registrar, Screens, SpaceId};
pub use dial::{Circuit, Dial, Dialing, Io, Stream, Target, Unpublished};
pub use tally::{HOURS, Hour, Opened};

use std::time::Duration;

/// The SSH port of a gateway's onion (E23).
pub const SSH_PORT: u16 = 22;

/// The client's deadlines and limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// An onion stream's (a clearnet connection's), from the request to
    /// the stream: a descriptor, an introduction and a rendezvous.
    pub connect: Duration,
    /// The SSH handshake's, the key exchange, the authentication and the
    /// subsystem together.
    pub handshake: Duration,
    /// Each request's on an open connection, to its answer.
    pub request: Duration,
    /// A proven call's, its upload of up to a device proof's 1.5 MiB
    /// included.
    pub proven: Duration,
    /// A fresh connection's attempts, each on a new circuit.
    pub attempts: usize,
    /// The pause before one more attempt when every attempt found the
    /// onion service unpublished or unreachable ([`Unpublished`]): the
    /// `n`th of [`Config::agains`] after `n` such pauses.
    pub again: Duration,
    /// The attempts made after those pauses, while every attempt still
    /// finds the service so: a service whose circuits fail for a while (a
    /// host stalled, a descriptor republished) is waited for, within
    /// `again` × (1 + 2 + … + `agains`).
    pub agains: usize,
    /// How long a kept-open connection stays without a request.
    pub idle: Duration,
    /// The most a spare waits before it is built: each draws its delay
    /// below it, so no two are built at once or on a schedule.
    pub spare_gap: Duration,
    /// How long a spare stays unused, about: each draws its life between
    /// half and one and a half of it.
    pub spare_idle: Duration,
}

impl Default for Config {
    /// The onion connection's measured tail (p95 7.6–13.6 s, a run's worst
    /// at 43–84 s, `light-node.md` §6.3–§6.4) cut at 45 s, as a retry on a
    /// new circuit beats the tail; the SSH handshake's 3–5 s at p95 given
    /// 30 s; a 1 MiB upload's slowest 26 s given 90 s. A spare is built
    /// within 4 s of being wanted, and lives 5 to 15 minutes unused
    /// (`light-node.md` §6.2: the bound on rendezvous an hour).
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(45),
            handshake: Duration::from_secs(30),
            request: Duration::from_secs(30),
            proven: Duration::from_secs(90),
            attempts: 3,
            again: Duration::from_secs(5),
            agains: 3,
            idle: Duration::from_secs(300),
            spare_gap: Duration::from_secs(4),
            spare_idle: Duration::from_secs(600),
        }
    }
}
