//! A node seen from its tests: its counters, its storage and the blobs and
//! programs it holds, which no embedder reads ([`Node::probes`]). Built for
//! the tests alone (feature `dump`).

use std::sync::atomic::Ordering;

use vos_abi::ids::AgentId;
use vos_pvm::pool::CodeHash;

use super::Node;
use crate::store::Fjall;

/// What a test reads of a node: see [`Node::probes`].
#[derive(Clone, Copy)]
pub struct Probes<'a>(&'a Node);

impl Node {
    /// The node's counters and storage, as its tests read them.
    pub fn probes(&self) -> Probes<'_> {
        Probes(self)
    }
}

impl<'a> Probes<'a> {
    /// Requests the node API's socket and QUIC endpoint brought.
    pub fn api_frames(&self) -> u64 {
        self.0.api.frames.load(Ordering::Relaxed)
    }

    /// The node API's places for credentialed calls' large bodies free
    /// now, from the socket and QUIC together.
    pub fn credentialed_places_free(&self) -> usize {
        self.0.api.credentialed_free()
    }

    /// The calls this node queued in their lanes as their agent's leader
    /// and has not answered yet, with the duplicates waiting on them.
    pub fn calls_in_flight(&self) -> usize {
        self.0.inner.calls.in_flight()
    }

    /// Snapshots this node's groups switched to.
    pub fn snapshots_installed(&self) -> u64 {
        self.0.inner.counters.installed.load(Ordering::Relaxed)
    }

    /// Messages this node sent toward agents on other nodes, again on
    /// rounds included.
    pub fn messages_sent_across(&self) -> u64 {
        self.0.inner.counters.sent_across.load(Ordering::Relaxed)
    }

    /// Messages this node relayed to their agent's leader.
    pub fn messages_relayed(&self) -> u64 {
        self.0.inner.counters.relayed.load(Ordering::Relaxed)
    }

    /// Frames of `class` that arrived here from other nodes; none of
    /// liveness, which are not counted.
    pub fn frames_arrived(&self, class: vos_net::Class) -> u64 {
        self.0.inner.counters.arrived[class as usize].load(Ordering::Relaxed)
    }

    /// Arrivals this node dropped for `refusal`.
    pub fn dropped(&self, refusal: crate::peer::Refusal) -> u64 {
        self.0.inner.drops.get(refusal)
    }

    /// The node's storage, to read applied state and the log.
    pub fn store(&self) -> &'a Fjall {
        &self.0.inner.store
    }

    /// The latest root of `agent`'s committed map `map`, the node of the
    /// agent's tree at the map's prefix, the state version it holds, and a
    /// proof of `keys` against it, from one storage snapshot. Refused as
    /// building while a build is part-way through the tree and a write to
    /// the map waits.
    pub fn prove<K: AsRef<[u8]>>(
        &self,
        agent: AgentId,
        map: vos_abi::ids::MapId,
        keys: &[K],
    ) -> Result<crate::roots::Proven, crate::roots::Error> {
        crate::roots::prove(&self.0.inner.store.snapshot(), agent, map, keys)
    }

    /// The blobs some agent keeps here: the programs its instances run.
    pub fn pinned(&self) -> Vec<[u8; 32]> {
        self.0.inner.blobs.pinned().unwrap_or_default()
    }

    /// Whether the blob store holds `hash`.
    pub fn stores_blob(&self, hash: &[u8; 32]) -> bool {
        self.0.inner.blobs.contains(hash).unwrap_or(false)
    }

    /// Whether the machine pool holds `program`: instances of it run
    /// without loading it first.
    pub fn pooled(&self, program: &[u8; 32]) -> bool {
        self.0
            .inner
            .machines
            .pool
            .program(&CodeHash(*program))
            .is_some()
    }
}
