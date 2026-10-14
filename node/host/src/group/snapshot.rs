//! Snapshots: a leader's streams to followers its log no longer reaches,
//! a follower's install of one beside its state and its switch to it, the
//! old epochs dropped after, and the log's compaction, which a stream
//! holds back.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_net::Class;
use vos_raft::{ActiveConfigRecord, Role};
use vos_wire::Encode;
use vos_wire::ids::AgentId;
use vos_wire::peer::{
    Configuration, Manifest, NodeNumber, PeerMessage, SnapshotAck, SnapshotChunk,
};

use super::{Driver, Local, Shared, pinned, programs, unpinned};
use crate::blobs::Keep;
use crate::node::Inner;
use crate::raft;
use crate::storage::Change;
use crate::store::{Export, next_epoch};
use crate::timeout;

/// Snapshot chunks a stream sends past its follower's acknowledgement.
const CHUNKS_AHEAD: u64 = 4;
/// How long a stream waits for an acknowledgement that moves before it
/// sends its chunks again, and before it gives up.
const CHUNK_RESEND: Duration = Duration::from_secs(2);
const STREAM_SILENCE: Duration = Duration::from_secs(10);
/// How long a stream whose chunks are all staged holds compaction, and
/// keeps the core from starting another, waiting for its follower to
/// switch.
pub(super) const STREAM_HOLD: Duration = Duration::from_secs(60);
/// How long a follower keeps a snapshot it stages without a new chunk.
pub(super) const INSTALL_IDLE: Duration = Duration::from_secs(30);
/// Rows of an old epoch one write removes.
const DROP_ROWS: usize = 4096;

/// A snapshot stream this replica runs to a follower, as leader.
pub(super) struct Shipment {
    pub(super) term: u64,
    pub(super) index: u64,
    /// Where the follower's acknowledgements go: the next chunk it wants.
    pub(super) acks: smol::channel::Sender<u64>,
    /// When the follower had staged every chunk: the stream is held until
    /// it switches (its match reaches the index) or [`STREAM_HOLD`] passes.
    pub(super) staged: Option<Instant>,
}

/// A snapshot this replica stages from its leader, named by the leader's
/// term and the snapshot's index.
pub(super) struct Install {
    pub(super) term: u64,
    pub(super) index: u64,
    pub(super) snapshot_term: u64,
    /// The epoch its rows are staged under.
    pub(super) epoch: u8,
    /// The next chunk it wants.
    pub(super) next: u64,
    pub(super) manifest: Manifest,
    /// The programs its installed instances name.
    pub(super) programs: BTreeSet<[u8; 32]>,
    /// Every chunk is staged.
    pub(super) staged: bool,
    /// When the last chunk was staged.
    pub(super) since: Instant,
}

impl Driver {
    /// Release each stream whose follower switched to its snapshot, or
    /// that waited for it too long: the core then sends again as soon as
    /// it would, not once its own deadline passes.
    pub(super) fn settle_streams(&mut self) {
        let core = &self.core;
        let mut unswitched = Vec::new();
        let before = self.shipments.len();
        self.shipments.retain(|to, shipment| match shipment.staged {
            Some(staged) => {
                let switched = core.match_index(*to).unwrap_or(0) >= shipment.index;
                let held = !switched && staged.elapsed() < STREAM_HOLD;
                if !switched && !held {
                    unswitched.push(*to);
                }
                held
            }
            None => true,
        });
        for to in unswitched {
            self.core.snapshot_failed(to);
        }
        if self.shipments.len() < before {
            self.compact_due = true;
        }
    }

    /// Compact the log as far as the core's bound allows, less a tail a
    /// follower a little behind still gets entries from, and never past a
    /// snapshot being streamed: its follower needs the entries after it.
    /// The configuration recorded is the one in effect where it stops.
    pub(super) async fn compact(&mut self) -> bool {
        if !std::mem::take(&mut self.compact_due) {
            return true;
        }
        let mut point = self.core.compaction_point(
            self.compact_bound,
            self.inner.settings.compact_tail,
            self.inner.settings.compact_tail_bytes,
        );
        if let Some(lowest) = self.shipments.values().map(|shipment| shipment.index).min() {
            point = point.min(lowest);
        }
        if point <= self.core.status().snap_last_index {
            return true;
        }
        let configuration = self.core.config_at(point);
        let change = match raft::compaction(
            &self.inner.store,
            self.shared.agent,
            point,
            configuration.as_ref(),
        ) {
            Ok(Some(change)) => change,
            Ok(None) => return true,
            Err(error) => {
                tracing::warn!(
                    agent = self.shared.agent.0,
                    "a compaction read failed: {error}"
                );
                return true;
            }
        };
        // A compaction is never needed: refused, the log stays longer.
        if let Err(error) = self.inner.storage.commit(vec![change]).await {
            tracing::warn!(
                agent = self.shared.agent.0,
                "a compaction was refused: {error}"
            );
            return true;
        }
        self.core.compacted(point);
        true
    }

    /// Stream this replica's state to `to`, which needs entries the log no
    /// longer holds: exported at its applied index, with the configuration
    /// in effect there. One stream per follower: the core asks again while
    /// one runs, and is not heard.
    pub(super) fn send_snapshot(&mut self, to: NodeNumber) {
        if self.shipments.contains_key(&to) {
            return;
        }
        let export = match self.inner.store.export(self.shared.agent) {
            Ok(export) => export,
            Err(error) => {
                tracing::warn!(
                    agent = self.shared.agent.0,
                    "a snapshot export failed: {error}"
                );
                self.core.snapshot_failed(to);
                return;
            }
        };
        let configuration = self
            .core
            .config_at(export.applied)
            .map(|record| Configuration {
                members: record.current,
                joint_old: record.joint_old,
                index: record.log_index.unwrap_or(0),
            });
        let manifest = Manifest {
            configuration,
            last_result: export.last_result,
        };
        let term = self.core.status().current_term;
        let index = export.applied;
        let (acks, acked) = smol::channel::unbounded();
        self.shipments.insert(
            to,
            Shipment {
                term,
                index,
                acks,
                staged: None,
            },
        );
        self.inner.streamed.fetch_add(1, Ordering::Relaxed);
        let inner = Arc::clone(&self.inner);
        let shared = Arc::clone(&self.shared);
        let agent = self.shared.agent;
        self.inner.spawn(async move {
            let done = stream(&inner, &shared, (to, term), export, manifest, acked).await;
            inner.propose(
                agent,
                Local::StreamEnded {
                    to,
                    term,
                    index,
                    done,
                },
            );
        });
    }

    /// Stage the snapshot chunks taken this round, and switch to the
    /// snapshot once it is whole and its programs are here. False when the
    /// node must halt.
    pub(super) async fn stage(&mut self) -> bool {
        if self.core.role() == Role::Leader {
            self.chunks.clear();
            self.abandon().await;
            return true;
        }
        while let Some((from, chunk)) = self.chunks.pop_front() {
            self.stage_chunk(from, chunk).await;
        }
        if self
            .install
            .as_ref()
            .is_some_and(|install| install.since.elapsed() >= INSTALL_IDLE)
        {
            tracing::warn!(
                agent = self.shared.agent.0,
                "a snapshot stopped arriving; dropped"
            );
            self.abandon().await;
        }
        if self.install.as_ref().is_some_and(|install| install.staged) {
            return self.switch().await;
        }
        true
    }

    async fn stage_chunk(&mut self, from: NodeNumber, chunk: SnapshotChunk) {
        let name = (chunk.term, chunk.index);
        // Not acknowledged: the leader's appends correct its view of this
        // replica, and the stream falls silent.
        if chunk.agent != self.shared.agent || chunk.index <= self.shared.state().applied {
            return;
        }
        let current = self
            .install
            .as_ref()
            .map(|install| (install.term, install.index));
        // A late chunk of a stream a newer one replaced.
        if current.is_some_and(|current| name < current) {
            return;
        }
        if current != Some(name) {
            // A snapshot staged whole switches, or is dropped once idle,
            // before a newer stream takes its place.
            if self.install.as_ref().is_some_and(|install| install.staged) {
                return;
            }
            // A newer stream, from its first chunk: the follower wants that.
            if chunk.sequence != 0 {
                self.ack(from, name, 0);
                return;
            }
            self.abandon().await;
            let Some(epoch) = self.empty_epoch() else {
                return;
            };
            self.install = Some(Install {
                term: chunk.term,
                index: chunk.index,
                snapshot_term: chunk.snapshot_term,
                epoch,
                next: 0,
                manifest: chunk.manifest.clone().unwrap_or(Manifest {
                    configuration: None,
                    last_result: None,
                }),
                programs: BTreeSet::new(),
                staged: false,
                since: Instant::now(),
            });
        }
        let install = self.install.as_mut().expect("an install");
        if install.staged || chunk.sequence != install.next {
            let next = install.next;
            self.ack(from, name, next);
            return;
        }
        install
            .programs
            .extend(programs(chunk.rows.iter().map(|(key, value)| (key, value))));
        let stage = Change::Stage {
            agent: self.shared.agent,
            epoch: install.epoch,
            first: chunk.sequence == 0,
            rows: chunk.rows,
        };
        if let Err(error) = self.inner.storage.commit(vec![stage]).await {
            tracing::warn!(
                agent = self.shared.agent.0,
                "a snapshot chunk was not staged: {error}"
            );
            self.abandon().await;
            return;
        }
        let install = self.install.as_mut().expect("an install");
        install.next += 1;
        install.since = Instant::now();
        install.staged = chunk.last;
        let next = install.next;
        self.ack(from, name, next);
    }

    /// Switch to the staged snapshot, in one synced batch with the core's
    /// rows, its last result and its programs' pins, once those programs
    /// are here.
    async fn switch(&mut self) -> bool {
        let Some(install) = self.install.as_ref() else {
            return true;
        };
        let named: Vec<[u8; 32]> = install.programs.iter().copied().collect();
        let blobs = &self.inner.blobs;
        self.install_missing = named
            .iter()
            .filter(|hash| !blobs.contains(hash).unwrap_or(false))
            .copied()
            .collect();
        // Once every program is here, each is touched: it stays while the
        // switch comes to pin it, as the blob writer orders the touch with
        // a collection's removals. One removed meanwhile is wanted again.
        if self.install_missing.is_empty() && !named.is_empty() {
            match blobs.touch(named.clone()).await {
                Ok(stored) => {
                    self.install_missing = named
                        .into_iter()
                        .filter(|hash| !stored.contains(hash))
                        .collect();
                }
                Err(error) => {
                    tracing::warn!(agent = self.shared.agent.0, "a blob touch failed: {error}");
                    return true;
                }
            }
        }
        if !self.install_missing.is_empty() {
            self.inner
                .want(self.shared.agent, &self.install_missing, Keep::Aged);
            return true;
        }
        let install = self.install.take().expect("an install");
        let configuration =
            install
                .manifest
                .configuration
                .clone()
                .map(|configuration| ActiveConfigRecord {
                    log_index: Some(configuration.index),
                    current: configuration.members,
                    joint_old: configuration.joint_old,
                });
        let switch =
            self.core
                .snapshot_switch(install.index, install.snapshot_term, configuration.as_ref());
        let keeps_suffix = switch.truncate_after.is_none();
        let snapshot = self.inner.store.snapshot();
        let (old_epoch, before) = match snapshot
            .epoch(self.shared.agent)
            .and_then(|epoch| Ok((epoch, pinned(&snapshot, self.shared.agent)?)))
        {
            Ok(read) => read,
            Err(error) => {
                tracing::warn!(
                    agent = self.shared.agent.0,
                    "the state before a switch is unreadable: {error}"
                );
                self.install = Some(install);
                return true;
            }
        };
        let mut changes = vec![raft::switch_change(
            self.shared.agent,
            install.epoch,
            install.index,
            install.snapshot_term,
            &switch,
        )];
        if let Some((time, seed)) = install.manifest.last_result {
            changes.push(Change::LastResult {
                agent: self.shared.agent,
                time,
                seed,
            });
        }
        let agent = self.shared.agent;
        changes.extend(
            install
                .programs
                .difference(&before)
                .map(|hash| Change::Pin { hash: *hash, agent }),
        );
        changes.extend(
            before
                .difference(&install.programs)
                .map(|hash| Change::Unpin { hash: *hash, agent }),
        );
        let applying = self.shared.applying.lock().await;
        let unpinned = unpinned(&changes);
        if let Err(error) = self.inner.storage.commit(changes).await {
            drop(applying);
            // A failed flush may have written the switch: the staged epoch
            // may be the store's now, and is not to be dropped.
            if self.inner.storage.failed() {
                tracing::error!(
                    agent = self.shared.agent.0,
                    "a snapshot switch failed ({error}); the node stops and needs a restart"
                );
                self.inner.halt();
                return false;
            }
            tracing::warn!(
                agent = self.shared.agent.0,
                "a snapshot switch was refused: {error}"
            );
            self.install = Some(install);
            self.abandon().await;
            return true;
        }
        self.inner.evict(&unpinned);
        let index = install.index;
        self.core
            .snapshot_installed(index, install.snapshot_term, configuration);
        self.reports.switched(index, keeps_suffix);
        if keeps_suffix {
            self.last_index = self.last_index.max(index);
        } else {
            self.last_index = index;
            for (_, last) in &mut self.writes {
                *last = (*last).min(index);
            }
        }
        self.shared.update(|state| {
            state.applied = state.applied.max(index);
            state.commit = state.commit.max(index);
            state.written = if keeps_suffix {
                state.written.max(index)
            } else {
                index
            };
        });
        drop(applying);
        self.inner.installed.fetch_add(1, Ordering::Relaxed);
        self.drop_epoch(old_epoch);
        true
    }

    /// Drop the snapshot being staged, if any, in the background.
    async fn abandon(&mut self) {
        let Some(install) = self.install.take() else {
            return;
        };
        self.install_missing.clear();
        self.drop_epoch(install.epoch);
    }

    /// An epoch past the current one that holds no rows, for a snapshot to
    /// be staged under: one an earlier install left is being dropped in the
    /// background, and a stream never waits for it.
    fn empty_epoch(&self) -> Option<u8> {
        empty_epoch(&self.inner, self.shared.agent)
    }

    /// Remove an epoch a switch, or an abandoned install, left behind, in
    /// the background: marked as dropped before the drop can run.
    fn drop_epoch(&self, epoch: u8) {
        let inner = Arc::clone(&self.inner);
        let agent = self.shared.agent;
        self.inner.dropping(agent, epoch);
        self.inner.spawn(async move {
            drop_epoch(&inner, agent, epoch).await;
            inner.dropped(agent, epoch);
        });
    }

    /// Tell the leader `to` which chunk of the stream `name` this replica
    /// wants next.
    fn ack(&self, to: NodeNumber, (term, index): (u64, u64), next: u64) {
        self.inner.send(
            to,
            Class::Consensus,
            &PeerMessage::SnapshotAck(SnapshotAck {
                agent: self.shared.agent,
                term,
                index,
                next,
            }),
        );
    }
}

/// Remove `agent`'s rows under the old `epoch`, a few thousand a write,
/// until it holds none. Its caller marks the epoch as dropped first
/// (`Inner::dropping`): an epoch emptied by one pass, and chosen for a new
/// install before the next, would lose the install's rows.
async fn drop_epoch(inner: &Inner, agent: AgentId, epoch: u8) {
    loop {
        let drop = Change::DropEpoch {
            agent,
            epoch,
            limit: DROP_ROWS,
        };
        if inner.storage.commit(vec![drop]).await.is_err() {
            return;
        }
        match inner.store.stale_epochs(agent) {
            Ok(stale) if stale.contains(&epoch) => {}
            _ => return,
        }
    }
}

/// An epoch of `agent`'s past its current one that holds no rows, and that
/// no drop runs on.
pub(crate) fn empty_epoch(inner: &Inner, agent: AgentId) -> Option<u8> {
    let read = inner
        .store
        .snapshot()
        .epoch(agent)
        .and_then(|current| Ok((current, inner.store.stale_epochs(agent)?)));
    let (current, stale) = match read {
        Ok(read) => read,
        Err(error) => {
            tracing::warn!(agent = agent.0, "the epochs are unreadable: {error}");
            return None;
        }
    };
    let mut epoch = next_epoch(current);
    while stale.contains(&epoch) || inner.is_dropping(agent, epoch) {
        epoch = next_epoch(epoch);
        if epoch == current {
            return None;
        }
    }
    Some(epoch)
}

/// Remove every stale epoch of `agent`'s, as [`drop_epoch`] does.
pub(crate) async fn drop_stale_epochs(inner: &Inner, agent: AgentId) {
    let Ok(stale) = inner.store.stale_epochs(agent) else {
        return;
    };
    for &epoch in &stale {
        inner.dropping(agent, epoch);
    }
    for epoch in stale {
        drop_epoch(inner, agent, epoch).await;
        inner.dropped(agent, epoch);
    }
}

/// Stream `export` to `to` as leader in `term`, a few chunks past what
/// it acknowledged: true once it staged every chunk, false when it fell
/// silent or the leadership ended. A stream ends with a chunk of no rows.
async fn stream(
    inner: &Inner,
    shared: &Shared,
    (to, term): (NodeNumber, u64),
    mut export: Export,
    manifest: Manifest,
    acked: smol::channel::Receiver<u64>,
) -> bool {
    let agent = shared.agent;
    let (index, snapshot_term) = (export.applied, export.term);
    // Chunks sent and not yet acknowledged, by sequence.
    let mut window: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut read = 0;
    let mut last = None;
    let mut wanted = 0;
    let mut moved = Instant::now();
    // When the chunk the follower still wants was last sent again.
    let mut resent: Option<Instant> = None;
    let mut manifest = Some(manifest);
    let send = |frame: Vec<u8>| async move {
        let Some(network) = &inner.network else {
            return;
        };
        if timeout(CHUNK_RESEND, network.ready(to, Class::Bulk))
            .await
            .is_some()
        {
            // Refused, it is sent again when no acknowledgement moves.
            let _ = network.send(to, Class::Bulk, u64::from(agent.0), frame);
        }
    };
    loop {
        while last.is_none() && read < wanted + CHUNKS_AHEAD {
            let bytes = inner.settings.snapshot_chunk;
            let Some((back, rows)) = inner
                .offload(move || {
                    let rows = export.next_chunk(bytes);
                    (export, rows)
                })
                .await
            else {
                return false;
            };
            export = back;
            let (rows, end) = match rows {
                Ok(Some(rows)) => (rows, false),
                Ok(None) => (Vec::new(), true),
                Err(error) => {
                    tracing::warn!(agent = agent.0, "a snapshot read failed: {error}");
                    return false;
                }
            };
            let frame = PeerMessage::SnapshotChunk(SnapshotChunk {
                agent,
                term,
                index,
                snapshot_term,
                sequence: read,
                manifest: if read == 0 { manifest.take() } else { None },
                rows,
                last: end,
            })
            .encode();
            window.insert(read, frame.clone());
            let delay = inner.hooks.delay_chunk();
            if !delay.is_zero() {
                smol::Timer::after(delay).await;
            }
            send(frame).await;
            if end {
                last = Some(read);
            }
            read += 1;
        }
        if last.is_some_and(|last| wanted > last) {
            return true;
        }
        let ack = async { acked.recv().await.ok() };
        let lost = async {
            shared
                .wait(|state| state.stopped || state.term != term || state.role != Role::Leader)
                .await;
            None
        };
        match timeout(CHUNK_RESEND, ack.or(lost)).await {
            Some(Some(next)) if next > wanted => {
                wanted = next;
                moved = Instant::now();
                resent = None;
                window.retain(|sequence, _| *sequence >= next);
            }
            // The follower still wants `next`, having had a later chunk
            // first: that one goes again, at most once a while, so
            // reordered duplicates do not multiply.
            Some(Some(next)) if next == wanted => {
                if resent.is_none_or(|at| at.elapsed() >= CHUNK_RESEND)
                    && let Some(frame) = window.get(&next)
                {
                    send(frame.clone()).await;
                    resent = Some(Instant::now());
                }
            }
            // An acknowledgement overtaken by a later one.
            Some(Some(_)) => {}
            Some(None) => return false,
            None => {
                if moved.elapsed() >= STREAM_SILENCE {
                    return false;
                }
                for frame in window.values() {
                    send(frame.clone()).await;
                }
            }
        }
    }
}
