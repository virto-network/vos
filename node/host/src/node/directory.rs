//! The directory: where each agent runs, and this node's groups started
//! and retired as their placements name it or no longer do.
//!
//! The node that creates an agent sends its record and first placement to
//! every node of the space, and the agent's leader sends each new
//! placement as its replicas change, again every second until each node
//! acknowledges holding it durably. A node keeps the newest placement by
//! its order (the announcing leader's term, then the configuration's
//! index), and a record that differs from the one held for its agent is
//! refused, never written over.
//!
//! An announcer can stop before every member holds its placement, and
//! then no one sends it. So a node sent Raft traffic for an agent it runs
//! no group for asks the sender, which answers with the record and the
//! placement it holds if that names the asker: a member that missed its
//! placement learns it once its group needs it, a vote or entries.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_wire::ids::AgentId;
use vos_wire::peer::{CreationRecord, NodeNumber, Order, PeerMessage, Placement};

use super::{Agent, Inner, Run};
use crate::group::{self, Shared, pin_changes};
use crate::lock;
use crate::storage::Change;
use crate::store::HardState;

/// How often unacknowledged records are sent again.
const RESEND: Duration = Duration::from_secs(1);
/// How long the operator's creation waits for a majority of the replicas.
const MAJORITY: Duration = Duration::from_secs(30);
/// How often a node asks one peer for one agent's record.
const ASK_EVERY: Duration = Duration::from_secs(1);
/// The asks kept before those past [`ASK_EVERY`] are forgotten.
const ASKS_KEPT: usize = 1024;
/// A group's inbox: Raft messages beyond it are dropped, and resent.
const GROUP_INBOX: usize = 1024;

/// What an agent's retirement reads of it.
struct Retiring {
    /// The programs it pins.
    programs: BTreeSet<[u8; 32]>,
    hard: HardState,
    /// The last log position it held: the log's end, else where it starts,
    /// and no lower than a floor an earlier retirement left.
    floor: (u64, u64),
}

/// What a node knows of an agent: its record, and where it runs.
#[derive(Clone, Debug)]
pub(crate) struct Known {
    pub(crate) record: CreationRecord,
    pub(crate) placement: Placement,
}

impl Known {
    /// It, as the directory sends it.
    fn message(&self) -> PeerMessage {
        PeerMessage::Directory {
            record: self.record.clone(),
            placement: self.placement.clone(),
        }
    }
}

/// What this node knows of where agents run, and the placements it sends
/// until they are held.
#[derive(Default)]
pub(crate) struct Directory {
    /// Every agent this node knows of, and where it runs.
    pub(crate) known: Mutex<HashMap<AgentId, Arc<Known>>>,
    /// For each agent whose placement this node sends until it is held:
    /// its order, and the nodes yet to hold one at least as new.
    unacknowledged: Mutex<HashMap<AgentId, (Order, BTreeSet<NodeNumber>)>>,
    /// Notified as nodes acknowledge placements.
    acknowledged: event_listener::Event,
    /// For each agent, the nodes that said they could not run its program.
    refusing: Mutex<HashMap<AgentId, BTreeSet<NodeNumber>>>,
    /// When this node last asked each peer for each agent's record.
    asked: Mutex<HashMap<(AgentId, NodeNumber), Instant>>,
}

impl Directory {
    /// What this node knows of `agent`.
    pub(crate) fn get(&self, agent: AgentId) -> Option<Arc<Known>> {
        lock(&self.known).get(&agent).cloned()
    }
}

/// Whether a node sent Raft traffic for an agent asks the sender for its
/// record: when it runs no group for the agent, and the placement it
/// holds, if any, leaves it out (a newer one may name it); at most once
/// every [`ASK_EVERY`] per agent and peer. A group's full inbox does not
/// ask, and nor does a replica whose placement names it but which runs no
/// group (one refused for another agent program).
fn should_ask(
    held: Option<&Placement>,
    has_group: bool,
    me: NodeNumber,
    last: Option<Instant>,
    now: Instant,
) -> bool {
    !has_group
        && !held.is_some_and(|placement| placement.admits(me))
        && last.is_none_or(|last| now.saturating_duration_since(last) >= ASK_EVERY)
}

/// Whether node `me`, holding `placement`, answers `asker`'s request for
/// the agent's record: when it names the asker (a creation's placement is
/// its record's replicas, committed), and `me` is one the asker takes a
/// placement from, a node of it or of the configuration before.
fn should_answer(placement: &Placement, asker: NodeNumber, me: NodeNumber) -> bool {
    placement.admits(asker) && (placement.replicas.contains(&me) || placement.before.contains(&me))
}

/// Forget the asks older than [`ASK_EVERY`], once more than [`ASKS_KEPT`]
/// are kept.
fn trim_asks(asked: &mut HashMap<(AgentId, NodeNumber), Instant>, now: Instant) {
    if asked.len() > ASKS_KEPT {
        asked.retain(|_, at| now.saturating_duration_since(*at) < ASK_EVERY);
    }
}

/// Send unacknowledged placements again until each node holds them.
pub(crate) async fn resend_records(inner: Arc<Inner>) {
    let directory = &inner.directory;
    loop {
        smol::Timer::after(RESEND).await;
        // Every node runs this, a space of one too.
        inner.halt_if_store_failed();
        let pending: Vec<(AgentId, Order, Vec<NodeNumber>)> = lock(&directory.unacknowledged)
            .iter()
            .map(|(agent, (order, nodes))| (*agent, *order, nodes.iter().copied().collect()))
            .collect();
        for (agent, announced, nodes) in pending {
            let known = directory.get(agent);
            // A placement held since from elsewhere is its sender's to
            // announce: this node may not even be one that may send it.
            if known
                .as_ref()
                .is_some_and(|known| known.placement.order() != announced)
            {
                let mut unacknowledged = lock(&directory.unacknowledged);
                if unacknowledged
                    .get(&agent)
                    .is_some_and(|(order, _)| *order == announced)
                {
                    unacknowledged.remove(&agent);
                    // A node asked whether it could run the agent is
                    // asked again with the newer placement.
                    directory.acknowledged.notify(usize::MAX);
                }
                continue;
            }
            if let Some(known) = known {
                let message = known.message();
                for node in nodes {
                    inner.send(node, &message);
                }
            }
        }
    }
}

impl Inner {
    /// Learn where an agent runs, and act on it.
    pub(crate) fn learn(self: &Arc<Self>, record: CreationRecord, placement: Placement) {
        let agent = record.agent;
        lock(&self.directory.known).insert(agent, Arc::new(Known { record, placement }));
        self.reconsider(agent);
    }

    /// Start the agent's group where its placement names this node, and
    /// retire it where it no longer does: at once while this replica never
    /// held a committed configuration naming it (a configuration that never
    /// committed named it), else once a final configuration without it has
    /// committed and this replica does not lead.
    pub(crate) fn reconsider(self: &Arc<Self>, agent: AgentId) {
        // A group stopping with the node is not started again.
        if self.closing.load(Ordering::SeqCst) {
            return;
        }
        let Some(known) = self.directory.get(agent) else {
            return;
        };
        // A member of the configuration before, while the new one has not
        // committed, may still be needed to vote.
        let named = known.placement.admits(self.number);
        match self.run(agent) {
            None if named => {
                if known.record.program != self.program_hash {
                    tracing::error!(
                        agent = agent.0,
                        "the agent runs another agent program than this node's; its group does not start here"
                    );
                    return;
                }
                self.start(known.record.clone());
            }
            Some(run) if !named => {
                let state = run.shared.state();
                // A replica a committed final placement leaves out is stale
                // whatever it believes, its leadership included.
                let committed_final = known.placement.committed && !known.placement.joint;
                if !state.established || committed_final {
                    self.retire_agent(agent);
                }
            }
            _ => {}
        }
    }

    /// Stop the agent's group here for good: its log, state and pins go,
    /// in a task of their own once the group has stopped; the record, the
    /// placement and the term and vote stay.
    fn retire_agent(self: &Arc<Self>, agent: AgentId) {
        let run = {
            let mut runs = lock(&self.runs);
            let Some(run) = runs.remove(&agent) else {
                return;
            };
            lock(&self.retiring).insert(agent);
            run
        };
        tracing::info!(agent = agent.0, "this node no longer replicates the agent");
        run.close();
        let inner = Arc::clone(self);
        self.spawn(async move {
            run.join().await;
            inner.finish_retirement(agent).await;
        });
    }

    /// Write the agent's retirement, its group stopped, then reconsider
    /// the agent: a placement naming this node again may have come
    /// meanwhile.
    pub(super) async fn finish_retirement(self: &Arc<Self>, agent: AgentId) {
        self.write_retirement(agent).await;
        lock(&self.retiring).remove(&agent);
        self.reconsider(agent);
    }

    /// The agent's state moves to an epoch that holds no rows (not one a
    /// snapshot was staged in), the programs it named are unpinned, and
    /// every stale epoch is dropped.
    async fn write_retirement(&self, agent: AgentId) {
        let Retiring {
            programs,
            hard,
            floor,
        } = match self.retirement(agent) {
            Ok(read) => read,
            Err(error) => {
                tracing::error!(agent = agent.0, "a retiring agent is unreadable: {error}");
                return;
            }
        };
        let Some(epoch) = group::empty_epoch(self, agent) else {
            tracing::error!(agent = agent.0, "a retiring agent has no empty epoch");
            return;
        };
        let mut changes = vec![Change::Retire {
            agent,
            epoch,
            hard: HardState { commit: 0, ..hard },
            floor,
        }];
        changes.extend(pin_changes(agent, &programs, &BTreeSet::new()));
        if let Err(error) = self.commit_unpinning(changes).await {
            tracing::error!(agent = agent.0, "an agent did not retire: {error}");
            return;
        }
        group::drop_stale_epochs(self, agent).await;
    }

    /// What `agent`'s retirement reads of it.
    fn retirement(&self, agent: AgentId) -> Result<Retiring, fjall::Error> {
        let programs = group::pinned(&self.store.snapshot(), agent)?;
        let rows = self.store.raft(agent)?;
        let mut floor = rows
            .log
            .last()
            .map_or(rows.log_start, |(index, entry)| (*index, entry.term));
        if let Some(earlier) = rows.vote_floor
            && (earlier.1, earlier.0) > (floor.1, floor.0)
        {
            floor = earlier;
        }
        Ok(Retiring {
            programs,
            hard: rows.hard,
            floor,
        })
    }

    /// Whether this node's store holds anything of `agent`'s replica: a
    /// log, an applied index, a membership, or rows in any epoch.
    pub(super) fn holds_replica(&self, agent: AgentId) -> Result<bool, fjall::Error> {
        let rows = self.store.raft(agent)?;
        if !rows.log.is_empty()
            || rows.applied > 0
            || rows.log_start.0 > 0
            || rows.membership.is_some()
        {
            return Ok(true);
        }
        let current = self.store.snapshot().epoch(agent)?;
        Ok(self.store.epoch_holds_rows(agent, current)?
            || !self.store.stale_epochs(agent)?.is_empty())
    }

    /// Take `placement`, which this node's leadership of the agent gives,
    /// when it supersedes the one held: kept, acted on, and announced to
    /// every other node until each holds it. One not kept is not taken
    /// again: storage failed, and the node halts.
    pub(crate) async fn place(self: &Arc<Self>, agent: AgentId, placement: Placement) {
        let _recording = self.recording.lock().await;
        let Some(known) = self.directory.get(agent) else {
            return;
        };
        if !placement.supersedes(&known.placement) {
            return;
        }
        let change = Change::Placement {
            agent,
            placement: placement.clone(),
        };
        if let Err(error) = self.storage.commit(vec![change]).await {
            tracing::warn!(agent = agent.0, "a placement was not kept: {error}");
            return;
        }
        self.learn(known.record.clone(), placement);
        self.announce(agent);
    }

    fn start(self: &Arc<Self>, record: CreationRecord) {
        // Under the runs' lock, which the node's shutdown takes to set
        // `closing`: a group starts before the shutdown takes the runs, or
        // not at all.
        let mut runs = lock(&self.runs);
        let id = record.agent;
        if self.closing.load(Ordering::SeqCst) || lock(&self.retiring).contains(&id) {
            return;
        }
        let shared = Arc::new(Shared::new(record));
        let agent = Arc::new(Agent::new());
        let (inbox, inputs) = smol::channel::bounded(GROUP_INBOX);
        let (local, locals) = smol::channel::unbounded();
        let (inner, run) = (Arc::clone(self), (&agent, &shared));
        let tasks = vec![
            self.guarded(
                run,
                "group",
                group::drive(Arc::clone(&inner), Arc::clone(&shared), inputs, locals),
            ),
            self.guarded(
                run,
                "applier",
                group::apply(Arc::clone(&inner), Arc::clone(&shared)),
            ),
            // A builder that panics stops the agent, as its other tasks do:
            // a root built by a bug is worse than none.
            self.guarded(
                run,
                "root builder",
                crate::roots::build(Arc::clone(&inner), Arc::clone(&shared)),
            ),
            self.guarded(
                run,
                "leader",
                crate::leader::lead(inner, Arc::clone(&agent), Arc::clone(&shared)),
            ),
        ];
        runs.insert(
            id,
            Arc::new(Run {
                agent,
                shared,
                inbox,
                local,
                tasks: Mutex::new(tasks),
            }),
        );
    }

    /// Spawn `work`, the `name` task of the agent whose queue and group
    /// are `run`: a panic in it stops the agent.
    fn guarded(
        &self,
        (agent, shared): (&Arc<Agent>, &Arc<Shared>),
        name: &'static str,
        work: impl Future<Output = ()> + Send + 'static,
    ) -> smol::Task<()> {
        let (agent, shared) = (Arc::clone(agent), Arc::clone(shared));
        self.runtime.spawn(async move {
            if AssertUnwindSafe(work).catch_unwind().await.is_err() {
                tracing::error!(
                    agent = shared.agent.0,
                    "the agent's {name} panicked; the agent stops"
                );
                agent.stop();
                shared.stop();
            }
        })
    }

    /// Keep a placement newer than the one held, with its record, durably,
    /// act on it, then acknowledge it, saying whether this node could run
    /// the agent's program.
    pub(crate) async fn on_directory(
        self: &Arc<Self>,
        from: NodeNumber,
        record: CreationRecord,
        placement: Placement,
    ) {
        // A store that failed takes nothing more, and its node does not
        // acknowledge: the sender's resends are dropped quietly.
        if self.storage.failed() {
            return;
        }
        let agent = record.agent;
        let order = placement.order();
        let recording = self.recording.lock().await;
        let known = self.directory.get(agent);
        if known.as_ref().is_some_and(|known| known.record != record) {
            tracing::error!(
                from,
                agent = agent.0,
                "a record differs from the one held for its agent; refused"
            );
            return;
        }
        if known
            .as_ref()
            .is_none_or(|known| placement.supersedes(&known.placement))
        {
            let mut changes = vec![Change::Placement {
                agent,
                placement: placement.clone(),
            }];
            if known.is_none() {
                changes.insert(0, Change::Agent(record.clone()));
            }
            if let Err(error) = self.storage.commit(changes).await {
                tracing::error!(agent = agent.0, "a placement was not stored: {error}");
                return;
            }
            self.learn(record.clone(), placement);
        }
        drop(recording);
        self.send(
            from,
            &PeerMessage::DirectoryAck {
                agent,
                order,
                runs: record.program == self.program_hash,
            },
        );
    }

    /// Ask `from`, whose group sent Raft traffic for `agent` that found no
    /// room here, for the agent's record and placement, as [`should_ask`]
    /// says.
    pub(crate) fn ask_for_record(&self, from: NodeNumber, agent: AgentId, has_group: bool) {
        let held = self
            .directory
            .get(agent)
            .map(|known| known.placement.clone());
        let now = Instant::now();
        {
            let mut asked = lock(&self.directory.asked);
            let last = asked.get(&(agent, from)).copied();
            if !should_ask(held.as_ref(), has_group, self.number, last, now) {
                return;
            }
            asked.insert((agent, from), now);
            trim_asks(&mut asked, now);
        }
        self.send(from, &PeerMessage::DirectoryRequest { agent });
    }

    /// Answer `from`'s request for `agent`'s record with the record and
    /// placement held here, if the placement names it: an ordinary record,
    /// acknowledged as any. It is sent once; the asker asks again.
    pub(crate) fn on_request(&self, from: NodeNumber, agent: AgentId) {
        let Some(known) = self.directory.get(agent) else {
            return;
        };
        if should_answer(&known.placement, from, self.number) {
            self.send(from, &known.message());
        }
    }

    pub(crate) fn on_ack(&self, from: NodeNumber, agent: AgentId, order: Order, runs: bool) {
        let mut unacknowledged = lock(&self.directory.unacknowledged);
        if let Some((announced, nodes)) = unacknowledged.get_mut(&agent)
            && order >= *announced
        {
            nodes.remove(&from);
            if nodes.is_empty() {
                unacknowledged.remove(&agent);
            }
        }
        drop(unacknowledged);
        {
            let mut refusing = lock(&self.directory.refusing);
            let nodes = refusing.entry(agent).or_default();
            if runs {
                nodes.remove(&from);
            } else {
                nodes.insert(from);
            }
        }
        self.directory.acknowledged.notify(usize::MAX);
    }

    /// Send where `agent` runs, with its record, to every other node, and
    /// keep sending it until each acknowledges it.
    pub(crate) fn announce(&self, agent: AgentId) {
        let Some(known) = self.directory.get(agent) else {
            return;
        };
        let others: BTreeSet<NodeNumber> = self
            .numbers
            .iter()
            .copied()
            .filter(|node| *node != self.number)
            .collect();
        if !others.is_empty() {
            self.send_until_held(agent, &known, others);
        }
    }

    /// Send `known`, where `agent` runs, to `nodes`, and again every
    /// [`RESEND`] until each holds it, or one newer: they join those yet to
    /// hold it, and those of an older placement are no longer sent theirs.
    fn send_until_held(&self, agent: AgentId, known: &Known, nodes: BTreeSet<NodeNumber>) {
        let message = known.message();
        for node in &nodes {
            self.send(*node, &message);
        }
        let order = known.placement.order();
        let mut unacknowledged = lock(&self.directory.unacknowledged);
        match unacknowledged.get_mut(&agent) {
            Some((held, waiting)) if *held == order => waiting.extend(nodes),
            Some((held, _)) if *held > order => {}
            _ => {
                unacknowledged.insert(agent, (order, nodes));
            }
        }
    }

    /// Whether `node` could run `agent`'s program, as it answers when sent
    /// where the agent runs: false when it does not answer in `within`. It
    /// is asked again should a newer placement come meanwhile, which ends
    /// the resends of the older one, answered or not.
    pub(crate) async fn could_run(
        &self,
        agent: AgentId,
        node: NodeNumber,
        within: Duration,
    ) -> bool {
        let until = Instant::now() + within;
        loop {
            let Some(known) = self.directory.get(agent) else {
                return false;
            };
            let order = known.placement.order();
            self.send_until_held(agent, &known, BTreeSet::from([node]));
            let answered = || {
                !lock(&self.directory.unacknowledged)
                    .get(&agent)
                    .is_some_and(|(_, nodes)| nodes.contains(&node))
            };
            if !self.acknowledged_by(until, answered).await {
                return false;
            }
            let held = self
                .directory
                .get(agent)
                .is_some_and(|known| known.placement.order() == order);
            if held {
                return !lock(&self.directory.refusing)
                    .get(&agent)
                    .is_some_and(|nodes| nodes.contains(&node));
            }
        }
    }

    /// Wait until a majority of `record`'s replicas hold it durably: false
    /// when they do not within [`MAJORITY`].
    pub(crate) async fn held_by_majority(&self, record: &CreationRecord) -> bool {
        let needed = record.replicas.len() / 2 + 1;
        let holding = || {
            let unacknowledged = lock(&self.directory.unacknowledged);
            let waiting = unacknowledged.get(&record.agent).map(|(_, nodes)| nodes);
            let refusing = lock(&self.directory.refusing);
            let refusing = refusing.get(&record.agent);
            // A replica counts once it holds the record and could run the
            // agent's program.
            record
                .replicas
                .iter()
                .filter(|replica| {
                    **replica == self.number
                        || (!waiting.is_some_and(|nodes| nodes.contains(replica))
                            && !refusing.is_some_and(|nodes| nodes.contains(replica)))
                })
                .count()
        };
        self.acknowledged_by(Instant::now() + MAJORITY, || holding() >= needed)
            .await
    }

    /// Wait until `done` holds, looked at again whenever a node
    /// acknowledges a placement: false when it does not by `until`.
    async fn acknowledged_by(&self, until: Instant, done: impl Fn() -> bool) -> bool {
        loop {
            let acknowledged = self.directory.acknowledged.listen();
            if done() {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            acknowledged
                .or(async {
                    smol::Timer::at(until).await;
                })
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placement(replicas: Vec<NodeNumber>) -> Placement {
        Placement {
            replicas,
            before: Vec::new(),
            term: 2,
            index: 1,
            joint: false,
            committed: true,
        }
    }

    /// A node asks only when it runs no group and its placement leaves it
    /// out, at most once a second per agent and peer.
    #[test]
    fn a_node_asks_for_a_record_only_when_it_may_need_one() {
        let now = Instant::now();
        let names_me = placement(vec![1, 2, 3]);
        let leaves_me_out = placement(vec![1, 2, 4]);
        assert!(should_ask(None, false, 3, None, now), "no placement");
        assert!(should_ask(Some(&leaves_me_out), false, 3, None, now));
        assert!(!should_ask(None, true, 3, None, now), "a group runs here");
        assert!(
            !should_ask(Some(&names_me), false, 3, None, now),
            "named, yet no group: refused for another program"
        );
        let asked = now - Duration::from_millis(400);
        assert!(
            !should_ask(None, false, 3, Some(asked), now),
            "asked lately"
        );
        assert!(should_ask(None, false, 3, Some(asked), asked + ASK_EVERY));
    }

    /// A node answers the members its placement names, and no one else,
    /// and only with a placement the asker takes from it.
    #[test]
    fn a_node_answers_only_the_members_its_placement_names() {
        let held = placement(vec![1, 2, 3]);
        assert!(should_answer(&held, 3, 2));
        assert!(!should_answer(&held, 4, 2));
        assert!(
            !should_answer(&held, 3, 4),
            "a placement leaving the answerer out, which the asker would refuse"
        );
        let joint = Placement {
            before: vec![1, 2, 4],
            committed: false,
            ..held.clone()
        };
        assert!(
            should_answer(&joint, 4, 2),
            "a member of the configuration before"
        );
        let removing = Placement {
            replicas: vec![1, 2, 5],
            before: vec![1, 2, 3],
            ..held.clone()
        };
        assert!(
            should_answer(&removing, 5, 3),
            "a leader that removed itself"
        );
        let created = Placement::created(&CreationRecord {
            agent: AgentId(1 << 24 | 1),
            replicas: vec![1, 2, 3],
            creator: 1,
            time: 0,
            program: vos_wire::ids::ProgramHash([0; 32]),
            accumulate_gas: 0,
        });
        assert!(should_answer(&created, 3, 2));
    }

    /// The asks kept are bounded: past the bound, those older than the
    /// limit go, and the recent stay.
    #[test]
    fn the_asks_kept_stay_bounded() {
        let now = Instant::now();
        let old = now - ASK_EVERY;
        let mut asked: HashMap<(AgentId, NodeNumber), Instant> = (0..ASKS_KEPT as u32)
            .map(|agent| ((AgentId(agent), 2), old))
            .collect();
        trim_asks(&mut asked, now);
        assert_eq!(asked.len(), ASKS_KEPT, "within the bound, all kept");
        asked.insert((AgentId(u32::MAX), 2), now);
        trim_asks(&mut asked, now);
        assert_eq!(asked.len(), 1);
        assert!(asked.contains_key(&(AgentId(u32::MAX), 2)));
    }
}
