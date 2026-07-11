//! Host-side chronos feeder — drives the per-space `chronos` clock + v1
//! bias-resistance protocol from a daemon's periodic hook.
//!
//! Split out of the vosx daemon so it lives next to the protocol it speaks
//! ([`crate::chronos`]) and the registry it reads ([`crate::registry`]).
//! Network-gated: it needs the node, the libp2p transport, the raft-role
//! probe, VRF proving, and OS entropy. The daemon owns the construction and
//! the 1 s cadence; this module owns the per-pass logic.

use std::collections::HashSet;

use crate::abi::service::ServiceId;
use crate::chronos::{self, ChronosRef};
use crate::node::VosNode;
use crate::registry::{MEMBER_KIND_NODE, NODE_ROLE_VOTER, RegistryRef};

/// Slot granularity for the chronos clock: the wall-clock is bucketed into
/// 250 ms slots (the design's fast clock). Slots are integers counted from
/// [`VOS_COMMON_ERA_MS`].
const CHRONOS_SLOT_MS: u64 = 250;

/// Global VOS Common Era anchor — 2024-01-01T00:00:00Z in Unix milliseconds.
/// Slots are counted from here so they are comparable across spaces and nodes.
/// This is part of the wire contract: every feeder MUST use the same anchor,
/// since the slot value committed to the chain is `(wall_ms - era) / slot_ms`.
const VOS_COMMON_ERA_MS: u64 = 1_704_067_200_000;

/// How many feed passes a cached registry voter set is reused before refreshing.
/// Keeps the feeder from reading the registry every pass; membership changes
/// take effect within this many seconds.
const VOTERS_REFRESH_PASSES: u32 = 8;

/// Drives the per-space `chronos` clock + v1 bias-resistance protocol from a
/// daemon's periodic hook. Holds the node's static VRF keypair (derived once
/// from `node.key`) and the cross-pass feed state.
///
/// Each pass does up to three things:
///
/// 1. **Leader only** — drive the clock (`init`/`advance` via `Caller::System`,
///    which bypasses the `Advancer` gate) and mirror the registry's
///    `NODE_ROLE_VOTER` set into chronos (`set_committee`), so the committee is
///    exactly the raft voters. Gated on the locally-observed raft role: a
///    `System` write on a follower would run the handler then fail NotLeader at
///    commit, churning the replica every pass.
/// 2. **Every voter node** — enrol its own VRF public key (`enrol_voter`) and
///    post a reveal for each open round (`reveal`, a VRF proof over the round's
///    `α`). The committed reveal log on the leader is what gets each reveal
///    sequenced — the property that stops a reveal being dropped after the
///    leader has seen its value. How the write reaches the leader depends on the
///    role, because the daemon's periodic hook runs on the main loop and must
///    never block on the network:
///    - **Leader**: a *local* `block_on` write to its own replica
///      (`Caller::System`, `voter_id` honoured) — no network, no block.
///    - **Follower**: the call is encoded with a [`CaptureInvoker`] and sent to
///      the leader with `net.send_invoke`, **fire-and-forget** (the reply
///      receiver is dropped). It arrives at the leader as `Caller::Peer`, which
///      is how chronos binds the reveal to the authenticated voter, and the
///      main loop never waits on the wire. The protocol is self-correcting:
///      enrolment re-fires until the follower observes its own key in the
///      replicated `committee()`, and reveals re-fire each pass while a round is
///      open (chronos dedups idempotently, short-circuiting duplicates before
///      any commit).
/// 3. Reads (`now`, `committee`, `open_rounds`) come from the **local** replica
///    (cheap, no network hop); only the writes target the leader.
///
/// The feeder keeps its per-pass footprint close to v0's single `advance`
/// (cached voter set, enrol/reveal tracking) because a raft actor that commits
/// continuously is sensitive to extra per-commit work: the agent only reloads
/// (soft-restarts) when committed entries are ahead of what it has applied, so
/// the leader no longer replays its whole log on every one of its own commits —
/// the change that lets the chronos clock stay live indefinitely instead of
/// stalling. Reveals/enrols authenticate by the VRF proof + the leader-pushed
/// authorized set, NOT by the caller (a chronos handler runs on the raft apply
/// path, where the originating caller is not preserved), so the follower's
/// fire-and-forget cross-node write is bound to its voter by the proof it
/// carries, not by its connection identity.
pub struct ChronosFeeder {
    /// Per-space domain label passed to `chronos.init`.
    domain: Vec<u8>,
    /// This node's `peer_id` multihash bytes — its committee identity (matches
    /// the registry `MemberRow.key` and the `Caller::Peer` bytes a follower's
    /// cross-node invoke carries).
    local_peer: Vec<u8>,
    /// Static VRF keypair, derived from `node.key` (domain-separated). The
    /// secret never leaves this process; only `vrf_pk_bytes` is published.
    vrf_sk: vrf::SecretKey,
    vrf_pk: vrf::PublicKey,
    vrf_pk_bytes: Vec<u8>,
    /// Leader's authoritative slot, cached across passes (see `drive_clock`);
    /// `None` whenever this node is not the chronos leader.
    clock: Option<u64>,
    /// chronos replication id, resolved once from the catalog, for the raft role
    /// + leader probe.
    chronos_rep: Option<[u8; 32]>,
    /// Last committee set pushed (sorted), so an unchanged set skips the commit.
    last_committee: Option<Vec<Vec<u8>>>,
    /// Cached registry voter set + a refresh countdown, so the feeder doesn't
    /// re-read the registry every pass — keeping its per-pass footprint close to
    /// v0's single `advance`, which a raft actor (it soft-restarts after every
    /// commit) tolerates without the feeder's calls piling up behind a restart.
    voters_cache: Vec<Vec<u8>>,
    voters_ttl: u32,
    /// Whether this node's key is enrolled (leader: committed locally; follower:
    /// observed in the replicated committee), so enrolment stops re-firing.
    enrolled: bool,
    /// Rounds already revealed, pruned to the open set — so the leader writes a
    /// reveal at most once per round instead of every pass.
    revealed: HashSet<u64>,
}

impl ChronosFeeder {
    /// Load `node.key` and derive the node's static VRF keypair + committee id.
    /// `domain` is the per-space label (the space id) passed to `chronos.init`.
    pub fn new(data_dir: &std::path::Path, domain: Vec<u8>) -> Result<Self, String> {
        let key_bytes = std::fs::read(data_dir.join("node.key"))
            .map_err(|e| format!("chronos feeder: read node.key: {e}"))?;
        let keypair = libp2p::identity::Keypair::from_protobuf_encoding(&key_bytes)
            .map_err(|e| format!("chronos feeder: decode node.key: {e}"))?;
        let local_peer = libp2p::PeerId::from(keypair.public()).to_bytes();
        // The VRF seed is a one-way, domain-separated hash of the node secret,
        // so the VRF key is independent of every other use of the node key and
        // never derivable from public material. `keypair_from_seed` reduces it
        // into the scalar field, so any 32-byte seed yields a valid key.
        let seed = crate::crypto::blake2b_hash(b"vos-chronos-vrf/v1", &[&key_bytes]);
        let (vrf_sk, vrf_pk) = vrf::keypair_from_seed(&seed);
        let vrf_pk_bytes = vrf_pk.to_bytes().to_vec();
        Ok(Self {
            domain,
            local_peer,
            vrf_sk,
            vrf_pk,
            vrf_pk_bytes,
            clock: None,
            chronos_rep: None,
            last_committee: None,
            voters_cache: Vec::new(),
            voters_ttl: 0,
            enrolled: false,
            revealed: HashSet::new(),
        })
    }

    /// One feed pass. Cheap when chronos isn't installed or this node isn't a
    /// voter; drives the clock + committee on the leader and posts this node's
    /// enrol/reveals when it's a voter.
    pub fn feed(&mut self, node: &mut VosNode, local_prefix: u16) {
        let chronos_id = ServiceId(crate::registry::instance_service_id("chronos", local_prefix));
        if !node.has_agent(chronos_id) {
            return; // chronos not installed in this space — nothing to feed
        }

        // Resolve the chronos raft group id once (stable from name+program).
        if self.chronos_rep.is_none() {
            let reg = RegistryRef::at(ServiceId::REGISTRY);
            let Ok(rows) = crate::block_on(reg.agents(&mut &*node)) else {
                return; // catalog unavailable — retry next pass
            };
            self.chronos_rep = rows
                .iter()
                .find(|r| r.instance_name == "chronos")
                .map(|r| r.replication_id);
        }
        let Some(rep) = self.chronos_rep else {
            return; // chronos row not in the catalog yet
        };

        // Our role in the chronos raft group + who the leader is.
        let status = node.network().and_then(|net| net.local_raft_status(&rep));
        let is_leader = status
            .as_ref()
            .is_some_and(|s| s.role == crate::network::RaftRole::Leader);
        let leader_prefix = if is_leader {
            Some(local_prefix)
        } else {
            status.and_then(|s| s.leader_hint)
        };

        // The registry voter set (peer_id bytes) drives both the committee push
        // (leader) and the local "am I a voter?" gate. Cached with a TTL so the
        // feeder isn't reading the registry every pass.
        if self.voters_ttl == 0 {
            let reg = RegistryRef::at(ServiceId::REGISTRY);
            let Ok(members) = crate::block_on(reg.members_all(&mut &*node)) else {
                return; // registry unavailable — retry next pass
            };
            self.voters_cache = members
                .into_iter()
                .filter(|m| m.kind == MEMBER_KIND_NODE && m.role == NODE_ROLE_VOTER)
                .map(|m| m.key)
                .collect();
            self.voters_ttl = VOTERS_REFRESH_PASSES;
        }
        self.voters_ttl -= 1;
        let voters = self.voters_cache.clone();
        let am_voter = voters.iter().any(|v| v == &self.local_peer);

        // (1) Leader: drive the clock + mirror the committee.
        if is_leader {
            self.drive_clock(node, chronos_id);
            self.push_committee(node, chronos_id, &voters);
        } else {
            self.clock = None; // follower / mid-election — re-establish if we win
        }

        // (2) Every voter node enrols + reveals. The leader writes locally; a
        // follower fires at the leader's replica over libp2p (fire-and-forget).
        let Some(lp) = leader_prefix else {
            return; // leader unknown yet — nothing to reveal to
        };
        if !am_voter {
            return; // a non-voter contributes nothing to the committee
        }
        // A follower needs the leader's PeerId to send; the leader writes locally.
        let leader_peer = if is_leader {
            None
        } else {
            match node.network().and_then(|net| net.peer_for_prefix(lp)) {
                Some(p) => Some(p),
                None => return, // leader not connected yet — retry next pass
            }
        };
        let leader_chronos = ServiceId(crate::registry::instance_service_id("chronos", lp));
        self.enrol_self(node, is_leader, chronos_id, leader_chronos, leader_peer);
        self.post_reveals(node, is_leader, chronos_id, leader_chronos, leader_peer);
    }

    /// Leader-only: (re)establish the clock and propose an `advance` to the
    /// current wall-slot with fresh OS entropy. `clock` caches the authoritative
    /// slot so a long downtime catches up over a few passes (pre-clamped to the
    /// actor's future-drift cap) and an unmoved wall-slot skips the commit.
    fn drive_clock(&mut self, node: &mut VosNode, chronos_id: ServiceId) {
        let chronos = ChronosRef::at(chronos_id);
        if self.clock.is_none() {
            if crate::block_on(chronos.init(&mut &*node, self.domain.clone())).is_err() {
                return;
            }
            match crate::block_on(chronos.now(&mut &*node)) {
                Ok(s) => self.clock = Some(s),
                Err(_) => return,
            }
        }
        let cur = self.clock.expect("seeded just above");
        let wall_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let wall_slot = wall_ms.saturating_sub(VOS_COMMON_ERA_MS) / CHRONOS_SLOT_MS;
        if wall_slot <= cur {
            return; // already current — no commit needed this pass
        }
        let proposed = if cur == 0 {
            wall_slot
        } else {
            wall_slot.min(cur + chronos::MAX_SLOT_JUMP)
        };
        let mut entropy = [0u8; 32];
        if getrandom::getrandom(&mut entropy).is_err() {
            return; // never feed zero entropy — skip the pass on a draw failure
        }
        match crate::block_on(chronos.advance(&mut &*node, proposed, entropy.to_vec())) {
            Ok(out) => self.clock = Some(out.slot),
            Err(_) => self.clock = None, // lost leadership / unreachable
        }
    }

    /// Leader-only: mirror the registry voter set into the chronos committee.
    /// Only commits when the set changed, so a steady membership costs no raft
    /// traffic.
    fn push_committee(&mut self, node: &mut VosNode, chronos_id: ServiceId, voters: &[Vec<u8>]) {
        let mut sorted = voters.to_vec();
        sorted.sort();
        sorted.dedup();
        if self.last_committee.as_ref() == Some(&sorted) {
            return; // unchanged — skip the commit
        }
        let n = sorted.len();
        let encoded = chronos::encode_committee(&sorted);
        let chronos = ChronosRef::at(chronos_id);
        if let Ok(chronos::Status::Ok) = crate::block_on(chronos.set_committee(&mut &*node, encoded)) {
            self.last_committee = Some(sorted);
            tracing::info!(voters = n, "chronos: committee updated from registry");
        }
    }

    /// Enrol this node's VRF public key. The leader writes locally (`System`); a
    /// follower fires the enrolment at the leader and re-fires each pass until it
    /// observes its own key in the replicated `committee()` — self-correcting
    /// against packet loss and the race where the enrol arrives before the
    /// leader's `set_committee` (then `NOT_A_VOTER`, retried).
    fn enrol_self(
        &mut self,
        node: &mut VosNode,
        is_leader: bool,
        chronos_id: ServiceId,
        leader_chronos: ServiceId,
        leader_peer: Option<libp2p::PeerId>,
    ) {
        if self.enrolled {
            return;
        }
        if is_leader {
            let chronos = ChronosRef::at(chronos_id);
            // One local write; mark done so it doesn't re-fire every pass.
            if let Ok(chronos::Status::Ok) = crate::block_on(chronos.enrol_voter(
                &mut &*node,
                self.local_peer.clone(),
                self.vrf_pk_bytes.clone(),
            )) {
                self.enrolled = true;
                tracing::info!("chronos: enrolled this node's VRF key (leader-local)");
            }
            return;
        }
        // Follower: stop once our key has replicated back into the committee.
        let local = ChronosRef::at(chronos_id);
        if let Ok(committee) = crate::block_on(local.committee(&mut &*node))
            && committee.iter().any(|vk| vk.voter == self.local_peer)
        {
            self.enrolled = true;
            tracing::info!("chronos: VRF key enrolled (observed in the committee)");
            return;
        }
        let Some(peer) = leader_peer else { return };
        let payload = {
            let mut cap = CaptureInvoker::default();
            let chronos = ChronosRef::at(leader_chronos);
            let _ = crate::block_on(chronos.enrol_voter(
                &mut cap,
                self.local_peer.clone(),
                self.vrf_pk_bytes.clone(),
            ));
            cap.payload
        };
        self.fire_to_leader(node, peer, leader_chronos, payload);
        tracing::debug!("chronos: sent VRF-key enrolment to the leader");
    }

    /// Post a reveal for each open round. The leader proves + writes locally; a
    /// follower fires its reveal at the leader. Re-fired each pass while a round
    /// is open — chronos dedups idempotently (a duplicate short-circuits before
    /// the VRF verify and before any commit), so re-firing is cheap and covers
    /// packet loss without per-round bookkeeping.
    fn post_reveals(
        &mut self,
        node: &mut VosNode,
        is_leader: bool,
        chronos_id: ServiceId,
        leader_chronos: ServiceId,
        leader_peer: Option<libp2p::PeerId>,
    ) {
        let local = ChronosRef::at(chronos_id);
        let Ok(open) = crate::block_on(local.open_rounds(&mut &*node)) else {
            return;
        };
        // Forget rounds that have folded (left the open set), so the set stays
        // small and a re-opened index can't be wrongly skipped.
        let open_set: HashSet<u64> = open.iter().map(|o| o.round).collect();
        self.revealed.retain(|r| open_set.contains(r));

        for o in &open {
            // The leader commits once per round (re-revealing every pass would
            // pile writes behind the per-commit soft-restart). A follower
            // re-fires until the round folds, since its fire-and-forget send is
            // unconfirmed; those are cheap (no local commit, idempotent on the
            // leader).
            if is_leader && self.revealed.contains(&o.round) {
                continue;
            }
            let proof = vrf::prove(&self.vrf_sk, &self.vrf_pk, &o.alpha);
            if is_leader {
                let chronos = ChronosRef::at(chronos_id);
                if crate::block_on(chronos.reveal(
                    &mut &*node,
                    self.local_peer.clone(),
                    o.round,
                    proof.to_bytes().to_vec(),
                ))
                .is_ok()
                {
                    self.revealed.insert(o.round);
                }
            } else {
                let Some(peer) = leader_peer else { return };
                let payload = {
                    let mut cap = CaptureInvoker::default();
                    let chronos = ChronosRef::at(leader_chronos);
                    let _ = crate::block_on(chronos.reveal(
                        &mut cap,
                        self.local_peer.clone(),
                        o.round,
                        proof.to_bytes().to_vec(),
                    ));
                    cap.payload
                };
                self.fire_to_leader(node, peer, leader_chronos, payload);
            }
            tracing::debug!(round = o.round, leader = is_leader, "chronos: posted committee reveal");
        }
    }

    /// Send an already-encoded chronos call to the leader's replica over libp2p,
    /// fire-and-forget: the reply receiver is dropped so the daemon main loop
    /// never blocks on the wire. The leader sees it as `Caller::Peer(self)` (the
    /// same authority a forwarded raft write carries), so chronos binds it to
    /// this voter; an unconfirmed write is re-fired next pass.
    fn fire_to_leader(
        &self,
        node: &VosNode,
        leader_peer: libp2p::PeerId,
        leader_chronos: ServiceId,
        payload: Vec<u8>,
    ) {
        if payload.is_empty() {
            return;
        }
        if let Some(net) = node.network() {
            // `from = 0` (host-side, no source agent). Dropping the receiver
            // makes this fire-and-forget; the invoke is still delivered + run.
            let _ = net.send_invoke(
                leader_peer,
                ServiceId::REGISTRY.0,
                leader_chronos.0,
                Vec::new(),
                payload,
            );
        }
    }
}

/// An [`Invoker`](crate::actors::client::Invoker) that *captures* the encoded
/// call instead of dispatching it, so the feeder can hand a follower's
/// enrol/reveal to `net.send_invoke` as a fire-and-forget cross-node write. The
/// returned reply is a placeholder (the caller ignores it and reads `payload`).
#[derive(Default)]
struct CaptureInvoker {
    payload: Vec<u8>,
}

impl crate::actors::client::Invoker for CaptureInvoker {
    fn invoke(
        &mut self,
        _target: ServiceId,
        payload: Vec<u8>,
    ) -> impl std::future::Future<
        Output = Result<crate::actors::value::Value, crate::actors::client::ClientError>,
    > + '_ {
        self.payload = payload;
        std::future::ready(Ok(crate::actors::value::Value::Unit))
    }
}
