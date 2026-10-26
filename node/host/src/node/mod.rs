//! The node: every agent's replica group, applier and leader loop on one
//! async thread, the executor threads for PVM work, the storage thread,
//! the machine pool, and the network to the space's other nodes.
//!
//! Per agent, a leader's batch runs strictly in order: refine, a dry run
//! of accumulate, the result proposed and replicated, and once this
//! replica has applied it, the replies, the outbox's deliveries and the
//! acknowledgements. Every replica applies the committed log the same way.

mod admin;
mod api;
mod config;
mod directory;
mod error;
mod open;
mod queue;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use vos_net::Network;
use vos_pvm::pool::CodeHash;
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, ProgramHash};
use vos_wire::ingress::{Contact, NodeId};
use vos_wire::peer::{NodeNumber, Placement};

use crate::Hooks;
use crate::blobs::{Blobs, Keep};
use crate::executor::Executors;
use crate::group::{self, DryRun, Input as GroupInput, Local, Shared};
use crate::pvm::Machines;
use crate::space::Space;
use crate::storage::StorageThread;
use crate::store::Fjall;
use crate::tls::IngressTls;
use crate::{lock, timeout};

pub(crate) use config::Settings;
pub use config::{Config, Peers};
pub(crate) use directory::Directory;
pub use error::{CallError, Error, ReplaceError, Reply};
pub(crate) use open::write_private;
pub use open::{ADMIN_TOKEN, NODE_KEY, STORE, wall_clock};
pub(crate) use queue::{Agent, Answered, Pending};

/// An agent this node replicates: its queue, its group's shared state, the
/// group's inbox, and their tasks.
pub(crate) struct Run {
    pub(crate) agent: Arc<Agent>,
    pub(crate) shared: Arc<Shared>,
    pub(crate) inbox: smol::channel::Sender<GroupInput>,
    /// The leader loop's proposals and its retirement, never dropped.
    local: smol::channel::Sender<Local>,
    tasks: Mutex<Vec<smol::Task<()>>>,
}

impl Run {
    /// Stop the agent's leader after its batch in flight, and its group.
    pub(crate) fn stop(&self) {
        self.agent.stop();
        self.shared.stop();
    }

    /// Stop it, and close its group's inboxes.
    pub(crate) fn close(&self) {
        self.stop();
        self.inbox.close();
        self.local.close();
    }

    /// Wait for its tasks to end.
    pub(crate) async fn join(&self) {
        let tasks = std::mem::take(&mut *lock(&self.tasks));
        for task in tasks {
            task.await;
        }
    }
}

/// How long a call waits for a new leader to apply what it took over.
pub(crate) const CATCH_UP: Duration = Duration::from_secs(10);

/// A blob groups here asked for: which, and how it is kept once it
/// arrives.
struct Wanted {
    groups: BTreeSet<AgentId>,
    keep: Keep,
}

pub(crate) struct Inner {
    pub(crate) store: Fjall,
    pub(crate) blobs: Blobs,
    pub(crate) storage: StorageThread,
    pub(crate) executors: Executors,
    pub(crate) machines: Machines,
    pub(crate) program_hash: ProgramHash,
    pub(crate) settings: Settings,
    pub(crate) hooks: Arc<dyn Hooks>,
    pub(crate) clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub(crate) node_id: NodeId,
    /// The node key, whose public half is its id: the only key the
    /// anchors of the space's representative, led here, are signed with.
    pub(crate) node_key: ed25519_dalek::SigningKey,
    /// Where the representative's leader here anchors its roots.
    pub(crate) venue: Option<Arc<dyn vos_venue::VenueClient>>,
    /// This node's number in its space.
    pub(crate) number: NodeNumber,
    pub(crate) space: Option<Space>,
    /// The numbers of its space's nodes: none in a space of one.
    pub(crate) numbers: Arc<[NodeNumber]>,
    pub(crate) network: Option<Arc<dyn Network>>,
    /// Where each agent runs, and the placements this node sends.
    pub(crate) directory: Directory,
    /// The agents' epochs a drop may still remove rows from, with how many
    /// drops run on each: no install is staged into one (`empty_epoch`),
    /// or a drop would take its rows.
    pub(crate) dropping: Mutex<HashMap<(AgentId, u8), usize>>,
    /// The agents this node replicates.
    pub(crate) runs: Mutex<HashMap<AgentId, Arc<Run>>>,
    pub(crate) dry_runs: Mutex<HashMap<AgentId, DryRun>>,
    /// The blobs groups here asked for.
    wanted: Mutex<HashMap<[u8; 32], Wanted>>,
    pub(crate) drops: crate::peer::Drops,
    /// The low 24 bits of the next agent id this node makes.
    next_agent: smol::lock::Mutex<u32>,
    pub(crate) runtime: Arc<smol::Executor<'static>>,
    /// Node-wide tasks: the dispatcher, the directory's resends, and the
    /// work groups hand off.
    tasks: Mutex<Tasks>,
    /// Held while a record or a placement is checked against the directory
    /// and stored. It orders `place` against `on_directory`: each reads,
    /// compares and writes, and neither may store over a newer placement.
    pub(crate) recording: smol::lock::Mutex<()>,
    /// Turns through an agent's replicas, for what goes to one of them.
    pub(crate) turn: AtomicU64,
    pub(crate) counters: Counters,
    /// How long its leaders' batches spend in each stage.
    pub(crate) stats: Arc<crate::stats::Stats>,
    /// The node is shutting down: no group starts or retires.
    pub(crate) closing: AtomicBool,
    /// Agents whose retirement is not yet written: no group starts for
    /// them until it is.
    pub(crate) retiring: Mutex<HashSet<AgentId>>,
    /// Storage failed: every group stopped, and the node sends no pair
    /// heartbeat.
    pub(crate) halted: AtomicBool,
    /// The pair heartbeat this node sends, and what it hears.
    pub(crate) liveness: crate::liveness::Liveness,
    /// Clients' calls: their lanes, and the calls forwarded both ways.
    pub(crate) calls: crate::calls::Calls,
    /// The read indexes this replica asked its leaders for.
    pub(crate) reads: crate::asking::Waits<Option<u64>>,
    /// The anchor rows the representative's leader here asked its
    /// replicas for: each answer's node and root.
    pub(crate) anchor_rows: crate::asking::Waits<(NodeNumber, Option<[u8; 32]>)>,
    /// The representative's leaders' alerts here, the latest few.
    pub(crate) anchor_alerts: Mutex<std::collections::VecDeque<crate::AnchorAlert>>,
    /// The window of the space's clock in which a representative's leader
    /// here last handed its leadership on, unlisted: once a window, across
    /// leaderships.
    pub(crate) anchor_handed: Mutex<Option<u64>>,
    /// The statements proved here that their agents have still to record.
    pub(crate) unrecorded: crate::prover::Unrecorded,
    /// The prover worker's latest backlog.
    pub(crate) backlog: Mutex<Option<vos_node_prover::Backlog>>,
}

/// What the node counts, as [`Node`]'s getters report it.
#[derive(Default)]
pub(crate) struct Counters {
    pub(crate) sent_across: AtomicU64,
    pub(crate) installed: AtomicU64,
    pub(crate) streamed: AtomicU64,
    pub(crate) relayed: AtomicU64,
    /// By class; none of liveness, which the pair heartbeat takes.
    pub(crate) arrived: [AtomicU64; vos_net::Class::ALL.len()],
}

impl Inner {
    /// The space the node's agents belong to, and the clock that numbers
    /// its windows: its genesis's, or no space and the default clock.
    pub(crate) fn space_and_clock(&self) -> (vos_wire::SpaceId, vos_wire::WindowClock) {
        self.space.as_ref().map_or(
            (vos_wire::SpaceId::NONE, vos_wire::WindowClock::DEFAULT),
            |space| (space.id(), space.clock()),
        )
    }

    /// The space's genesis, when the node has one.
    pub(crate) fn genesis(&self) -> Option<&vos_wire::vos_anchor::SpaceGenesis> {
        self.space.as_ref().and_then(|space| space.genesis())
    }

    /// The space's representative ([`vos_wire::served::representative`]):
    /// none without a genesis.
    pub(crate) fn representative(&self) -> Option<AgentId> {
        self.genesis().and_then(vos_wire::served::representative)
    }

    /// The anchor keys the space has registered: the venue's listing, or,
    /// without a venue, the founding keys its genesis names, those a venue
    /// registers with it.
    pub(crate) fn registered_anchor_keys(&self) -> Vec<[u8; 32]> {
        let (space, _) = self.space_and_clock();
        match &self.venue {
            Some(venue) => venue.anchor_keys(&space),
            None => self
                .genesis()
                .map(|genesis| genesis.nodes.iter().map(|(_, key)| *key).collect())
                .unwrap_or_default(),
        }
    }

    /// Whether this node may replicate the space's representative: the
    /// space registered its node key as an anchor key, as the venue's
    /// client last read it. Before the client's first read of the space it
    /// lists none, so the representative is refused here (`CannotRun`)
    /// until then (`docs/operations.md`).
    pub(crate) fn may_represent(&self) -> bool {
        self.registered_anchor_keys().contains(&self.node_id.0)
    }

    pub(crate) fn run(&self, id: AgentId) -> Option<Arc<Run>> {
        lock(&self.runs).get(&id).cloned()
    }

    /// Agent `id`'s replica here, or why a call to it cannot be served
    /// here.
    pub(crate) fn present(&self, id: AgentId) -> Result<Arc<Run>, CallError> {
        self.run(id).ok_or_else(|| self.absent(id))
    }

    /// Why a call to `id` cannot be served here: a replica with no group
    /// running is stopping (or refused the group), and any other node
    /// names the replicas.
    pub(crate) fn absent(&self, id: AgentId) -> CallError {
        match self.directory.get(id) {
            Some(known) if known.placement.replicas.contains(&self.number) => CallError::Stopped,
            Some(known) => CallError::Elsewhere(
                known
                    .placement
                    .replicas
                    .iter()
                    .filter_map(|replica| self.contact(*replica))
                    .collect(),
            ),
            None => CallError::NoAgent,
        }
    }

    /// Where agent `id` runs, as this node last heard.
    pub(crate) fn placement(&self, id: AgentId) -> Option<Placement> {
        self.directory.get(id).map(|known| known.placement.clone())
    }

    /// How clients reach node `number`, from the space.
    pub(crate) fn contact(&self, number: NodeNumber) -> Option<Contact> {
        let node = self.space.as_ref()?.node(number)?;
        Some(Contact {
            address: node.ingress.clone(),
            node: NodeId(node.key),
        })
    }

    /// The node `contact` names, by its key.
    pub(crate) fn number_of(&self, contact: &Contact) -> Option<NodeNumber> {
        self.space
            .as_ref()?
            .nodes()
            .iter()
            .find(|node| node.key == contact.node.0)
            .map(|node| node.number)
    }

    /// That this node does not lead `shared`'s group, with its leader's
    /// address when known; or that the group stopped.
    pub(crate) fn not_leader(&self, shared: &Shared) -> CallError {
        let state = shared.state();
        if state.stopped {
            return CallError::Stopped;
        }
        CallError::NotLeader(
            state
                .leader
                .filter(|leader| *leader != self.number)
                .and_then(|leader| self.contact(leader)),
        )
    }

    /// Agent `id`'s replica here, when its leader loop takes inputs and
    /// it has applied what its predecessors committed: else where calls go
    /// instead. While the group elects, it waits as a call does.
    ///
    /// Applied that far, the replica's marks hold every request an earlier
    /// leader answered, so ingress reads no gap after one.
    pub(crate) async fn leading(&self, id: AgentId) -> Result<Arc<Run>, CallError> {
        let run = self.present(id)?;
        let state = run.shared.state();
        if !state.stopped && !self.knows_leader(&run, &state) {
            self.settled(id).await?;
        }
        let caught_up = run.shared.wait(|state| {
            state.stopped
                || state
                    .leading_from
                    .is_none_or(|first| state.applied >= first)
        });
        if timeout(CATCH_UP, caught_up).await.is_none() {
            return Err(CallError::Failed(
                "the leader has not applied what it took over".into(),
            ));
        }
        let (stopped, leading) = {
            let queue = lock(&run.agent.queue);
            (queue.stopped, queue.leading)
        };
        if run.shared.state().stopped || stopped {
            return Err(CallError::Stopped);
        }
        if !leading {
            return Err(self.not_leader(&run.shared));
        }
        Ok(run)
    }

    /// Wait until agent `id`'s group here knows a leader, for a few
    /// election timeouts at most: a call to a group just created, or one
    /// electing, then goes where it should.
    pub(crate) async fn settled(&self, id: AgentId) -> Result<(), CallError> {
        let run = self.present(id)?;
        let electing = run
            .shared
            .wait(|state| state.stopped || self.knows_leader(&run, state));
        timeout(
            Duration::from_millis(4 * self.settings.election_timeout_ms.1),
            electing,
        )
        .await;
        Ok(())
    }

    /// Whether `run`'s group knows where calls go: a leader elsewhere, or
    /// this replica's leader loop taking inputs.
    pub(crate) fn knows_leader(&self, run: &Run, state: &group::State) -> bool {
        match state.leader {
            Some(leader) if leader == self.number => run.agent.leading(),
            Some(_) => true,
            None => false,
        }
    }

    /// Take out of the pool each program in `unpinned` that no agent here
    /// pins any more, as a restart would leave it. A program pinned again
    /// meanwhile is only loaded again on its next use, at the same gas.
    pub(crate) fn evict(&self, unpinned: &[[u8; 32]]) {
        for hash in unpinned {
            match self.blobs.pinned_by_any(hash) {
                Ok(false) => self.machines.pool.uninstall(&CodeHash(*hash)),
                Ok(true) => {}
                Err(error) => tracing::warn!("a pin read failed: {error}"),
            }
        }
    }

    /// Halt once the store failed a flush, whichever path met the
    /// failure: the pair heartbeat and the records' resends look, so a
    /// node halts within one of their rounds.
    pub(crate) fn halt_if_store_failed(&self) {
        if self.storage.failed() && !self.halted.load(Ordering::SeqCst) {
            tracing::error!("a flush failed; the node stops and needs a restart");
            self.halt();
        }
    }

    /// Stop every agent: a commit failed, and storage takes no more.
    /// Queued and later calls answer `Stopped`.
    pub(crate) fn halt(&self) {
        self.halted.store(true, Ordering::SeqCst);
        let runs: Vec<Arc<Run>> = lock(&self.runs).values().cloned().collect();
        for run in runs {
            run.stop();
        }
    }

    /// How long its stages took since it started, its leaders' batches'
    /// and its writer's; and its replica groups now.
    pub(crate) fn stats(&self) -> vos_wire::ingress::Stats {
        let mut stats = self.stats.wire(self.storage.stages());
        let runs: Vec<Arc<Run>> = lock(&self.runs).values().cloned().collect();
        for run in runs {
            let state = run.shared.state();
            stats.groups.replicas += 1;
            stats.groups.leading += u64::from(state.role == vos_raft::Role::Leader);
            stats.groups.terms += state.term;
        }
        stats
    }

    /// Hand `local` to agent `id`'s group, never dropped. False when it has
    /// none here, or it stopped.
    pub(crate) fn to_group(&self, id: AgentId, local: Local) -> bool {
        self.run(id)
            .is_some_and(|run| run.local.try_send(local).is_ok())
    }

    /// Agent `id`'s group waits for `hashes`, to be kept as `keep` says
    /// (the longer, if another group waits too): tell it when they arrive.
    pub(crate) fn want(&self, id: AgentId, hashes: &[[u8; 32]], keep: Keep) {
        let mut wanted = lock(&self.wanted);
        for hash in hashes {
            let wanted = wanted.entry(*hash).or_insert(Wanted {
                groups: BTreeSet::new(),
                keep,
            });
            wanted.groups.insert(id);
            wanted.keep = wanted.keep.max(keep);
        }
    }

    /// How a blob some group here asked for is kept, if one did.
    pub(crate) fn wanted(&self, hash: &[u8; 32]) -> Option<Keep> {
        lock(&self.wanted).get(hash).map(|wanted| wanted.keep)
    }

    /// The groups that wanted `hash`, which arrived.
    pub(crate) fn arrived(&self, hash: &[u8; 32]) {
        let waiting = lock(&self.wanted)
            .remove(hash)
            .map(|wanted| wanted.groups)
            .unwrap_or_default();
        for id in waiting {
            if let Some(run) = self.run(id) {
                let _ = run.inbox.try_send(GroupInput::Blobs);
            }
        }
    }

    /// Run `work` on an executor, off the thread every leader shares.
    pub(crate) async fn offload<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        self.executors.run(work).await.ok()
    }

    /// A call: queued at once when the group knows where calls go, so
    /// calls made together share a batch; else once it does.
    pub(crate) fn call(
        self: &Arc<Self>,
        agent: AgentId,
        request: Request,
    ) -> impl Future<Output = Result<Answered, CallError>> + use<> {
        let (answer, reply) = smol::channel::bounded(1);
        let pending = Pending::Request { request, answer };
        let known = self.run(agent).is_some_and(|run| {
            let state = run.shared.state();
            state.stopped || self.knows_leader(&run, &state)
        });
        let queued = if known {
            Ok(self.push(agent, pending))
        } else {
            Err(pending)
        };
        let inner = Arc::clone(self);
        async move {
            match queued {
                Ok(queued) => queued?,
                Err(pending) => {
                    inner.settled(agent).await?;
                    inner.push(agent, pending)?;
                }
            }
            reply.recv().await.map_err(|_| CallError::Stopped)?
        }
    }

    /// Run `task` on the node's thread until it ends or the node stops.
    pub(crate) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        // A node shutting down runs nothing new: what such a task would do
        // (an old epoch dropped, say) is done again at the next start.
        if self.closing.load(Ordering::SeqCst) {
            return;
        }
        let task = self.runtime.spawn(task);
        lock(&self.tasks).push(task);
    }
}

/// The node's tasks, finished ones dropped whenever the list has doubled
/// since: a spawn costs the same however many tasks run.
#[derive(Default)]
struct Tasks {
    list: Vec<smol::Task<()>>,
    prune_at: usize,
}

impl Tasks {
    /// The fewest tasks the list holds before it is pruned.
    const PRUNE_AT: usize = 64;

    fn push(&mut self, task: smol::Task<()>) {
        if self.list.len() >= self.prune_at {
            self.list.retain(|task| !task.is_finished());
            self.prune_at = (2 * self.list.len()).max(Self::PRUNE_AT);
        }
        self.list.push(task);
    }
}

/// A VOS node on one process.
pub struct Node {
    inner: Arc<Inner>,
    data: PathBuf,
    /// The seed of the node's key.
    secret: [u8; 32],
    ingress_tls: Option<IngressTls>,
    /// The node API's one handler, whichever transport brings a request.
    api: Arc<crate::api::Api>,
    /// The servers on the node's thread (the HTTP ingress, the API's
    /// socket), and what stops each.
    fronts: Mutex<Vec<(smol::Task<()>, smol::channel::Sender<()>)>>,
    /// The API's QUIC endpoint, on its own thread.
    quic_api: Mutex<Option<crate::api::quic::Served>>,
    stop: Option<smol::channel::Sender<()>>,
    runtime: Option<JoinHandle<()>>,
    /// The pair heartbeat's thread, and what stops it.
    liveness: Option<(smol::channel::Sender<()>, JoinHandle<()>)>,
    /// The blob collector's thread, and what stops it.
    collector: Option<(mpsc::Sender<()>, JoinHandle<()>)>,
    /// The prover worker's thread, and what stops it.
    prover: Option<(mpsc::Sender<()>, JoinHandle<()>)>,
}

#[cfg(test)]
mod tests {
    use super::{Config, Node, Tasks};
    use std::sync::Arc;

    /// The default agent program, linked.
    fn agent_program() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../agent/default/target/riscv64em-vos/release/vos-agent.elf"
        );
        let elf = std::fs::read(path).expect("run `just build-agent`");
        vos_pvm_compiler::link_elf_spi(&elf).expect("links")
    }

    /// A node stopped while an executor runs a job holding its state (a
    /// signature check, or any job) is gone once its stop returns, its
    /// store and the store's lock with it: it opens again on the same
    /// directory at once.
    #[test]
    fn a_node_stopped_while_a_job_holds_it_opens_again_at_once() {
        let agent = agent_program();
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(dir.path(), Config::new(agent.clone())).unwrap();
        let (started, start) = std::sync::mpsc::channel();
        let held = Arc::clone(&node.inner);
        let job = node.inner.executors.run(move || {
            started.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(600));
            drop(held);
        });
        start.recv().unwrap();
        node.shutdown();
        drop(job);
        let opened = Node::open(dir.path(), Config::new(agent));
        assert!(opened.is_ok(), "{:?}", opened.err());
    }

    /// An epoch a drop runs on is chosen for no install, though a pass of
    /// the drop has emptied it: the drop's next pass would take the
    /// install's rows.
    #[test]
    fn an_epoch_being_dropped_takes_no_install() {
        use crate::group::empty_epoch;
        use crate::storage::Change;
        use vos_wire::ids::AgentId;
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(dir.path(), Config::new(agent_program())).unwrap();
        let inner = &node.inner;
        let agent = AgentId(9);
        let commit = |change: Change| smol::block_on(inner.storage.commit(vec![change])).unwrap();
        // An abandoned install's rows in epoch 1: not empty, so not chosen.
        commit(Change::Stage {
            agent,
            epoch: 1,
            first: true,
            rows: vec![(b"\x01row".to_vec(), b"value".to_vec())],
        });
        assert_eq!(empty_epoch(inner, agent), Some(2));
        // Its drop runs, and one pass empties it.
        inner.dropping(agent, 1);
        commit(Change::DropEpoch {
            agent,
            epoch: 1,
            limit: usize::MAX,
        });
        assert_eq!(empty_epoch(inner, agent), Some(2), "chosen mid-drop");
        inner.dropped(agent, 1);
        assert_eq!(empty_epoch(inner, agent), Some(1));
        // A retirement's drops mark every epoch before their first pass,
        // and unmark each once it is gone.
        commit(Change::Stage {
            agent,
            epoch: 3,
            first: true,
            rows: vec![(b"\x01row".to_vec(), b"value".to_vec())],
        });
        let mut drops = Box::pin(crate::group::drop_stale_epochs(inner, agent));
        if smol::block_on(smol::future::poll_once(&mut drops)).is_none() {
            assert!(inner.is_dropping(agent, 3), "dropped unmarked");
            smol::block_on(drops);
        }
        assert!(!inner.is_dropping(agent, 3));
        assert_eq!(empty_epoch(inner, agent), Some(1));
    }

    #[test]
    fn finished_tasks_do_not_pile_up() {
        let executor = smol::Executor::new();
        let mut tasks = Tasks::default();
        for _ in 0..10_000 {
            tasks.push(executor.spawn(async {}));
            while executor.try_tick() {}
        }
        assert!(
            tasks.list.len() <= Tasks::PRUNE_AT + 1,
            "{}",
            tasks.list.len()
        );
        // Tasks still running are kept.
        let (_hold, held) = smol::channel::bounded::<()>(1);
        for _ in 0..200 {
            let held = held.clone();
            tasks.push(executor.spawn(async move {
                let _ = held.recv().await;
            }));
        }
        while executor.try_tick() {}
        assert!(tasks.list.len() >= 200);
    }
}
