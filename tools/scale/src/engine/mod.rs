//! `drive-local`: one driver's share of the load model, open loop. A
//! planning thread draws the operations in time order and signs each ahead
//! of its scheduled send; the sending thread sends each at its time, one
//! attempt, over at most the plan's connections a node, and counts every
//! refusal by its kind. A user's calls go one at a time in its session, in
//! order: one scheduled while the last is unanswered waits for it, its
//! latency still timed from its schedule. Every interval a line a kind goes
//! to the record, and a line for the mix with the driver's own counts: its
//! CPU, the waits for a connection and the most in use.

mod pool;
mod session;
mod stats;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::AtomicI64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use smol::{LocalExecutor, Timer};
use vos_node::client::{Target, signed_workflow_read, workflow_read_not_after};
use vos_wire::Encode;
use vos_wire::ids::{AgentId, InstanceId, WorkflowId};
use vos_wire::ingress::{Consistency, Response, WorkflowStatus};
use vos_wire::result::Outcome;

use crate::agents::{Mix, Placed};
use crate::drive::{LATE_US, Plan};
use crate::load::{self, Kind, Readers, Users};
use crate::nodes::target;
use pool::{Pool, PoolStats};
use session::{Agent, Body, Fate, Methods, Op, ShardCounts, Shared, fate, wall_ms};
use stats::{KindStats, REPORTED, Stats, cpu_seconds, mix_line, refusal, thread_seconds};

/// The most connections a driver keeps to one node, unless its plan says
/// otherwise.
pub const MAX_CONNECTIONS: usize = 512;
/// How far ahead of its schedule an operation is signed.
const LOOKAHEAD: Duration = Duration::from_millis(500);
/// How early an operation may go rather than wait for a timer. It is timed
/// from its schedule, or from its send when that came first: never from a
/// later instant than it went.
const EARLY: Duration = Duration::from_micros(200);
/// The least the planning thread sleeps once far enough ahead.
const PLAN_NAP: Duration = Duration::from_millis(50);
/// How long one request may take before the driver counts it failed:
/// past it, a reaper that wakes every [`REAP`] closes its connection. A
/// timer a request would cost as much as the request, at the driver's
/// rates.
const ANSWER: Duration = Duration::from_secs(30);
const REAP: Duration = Duration::from_secs(1);
/// How long a node that failed a request is left out of the routes.
const BACKOFF: Duration = Duration::from_secs(2);
/// Connections opened to each node before the load starts.
const WARM: usize = 64;
/// How long a read of a workflow waits for it to end.
const WORKFLOW_WAIT_MS: u64 = 2_000;
/// A read at a cut, once its window closed: a jitter before the first
/// read, so a window's readers do not ask at one instant; the first read's
/// wait; the pause between the reads after; and how long it keeps asking.
/// The latency is resolved to the jitter and the pause, half a second
/// each.
const CUT_JITTER_MS: u64 = 500;
const CUT_WAIT_MS: u64 = 10_000;
const CUT_POLL: Duration = Duration::from_millis(500);
const CUT_GIVE_UP_MS: u64 = 60_000;

/// Where each agent's calls and queries go: calls to its leader as last
/// learned, queries to a follower; a node that failed a request left out
/// for [`BACKOFF`], the leader's place moving to the next replica.
struct Routes {
    leaders: Vec<usize>,
    down: Vec<Option<Instant>>,
}

impl Routes {
    fn up(&self, node: usize, now: Instant) -> bool {
        self.down[node].is_none_or(|until| until <= now)
    }

    fn call(&self, agent: usize) -> usize {
        self.leaders[agent]
    }

    /// A follower of `replicas` up now, by `user`; else the leader.
    fn query(&self, agent: usize, replicas: &[usize], user: u64, now: Instant) -> usize {
        let leader = self.leaders[agent];
        let followers: Vec<usize> = replicas
            .iter()
            .copied()
            .filter(|node| *node != leader && self.up(*node, now))
            .collect();
        match followers.len() {
            0 => leader,
            n => followers[(user % n as u64) as usize],
        }
    }

    /// `node` failed a request to `agent`: out for a while, and if it was
    /// the leader's place, the next replica up takes it.
    fn failed(&mut self, agent: usize, replicas: &[usize], node: usize, now: Instant) {
        self.down[node] = Some(now + BACKOFF);
        if self.leaders[agent] != node {
            return;
        }
        let at = replicas
            .iter()
            .position(|replica| *replica == node)
            .unwrap_or(0);
        let next = (1..=replicas.len())
            .map(|step| replicas[(at + step) % replicas.len()])
            .find(|replica| self.up(*replica, now))
            .unwrap_or(replicas[(at + 1) % replicas.len()]);
        self.leaders[agent] = next;
    }
}

/// Whether an answer says the node could not serve: no answer, or one that
/// names no leader.
fn unserved(answer: &Result<Response, String>) -> bool {
    matches!(
        answer,
        Err(_) | Ok(Response::Unavailable | Response::NotLeader { leader: None })
    )
}

/// The sending thread's state.
struct Engine {
    shared: Arc<Shared>,
    pools: Vec<Pool>,
    routes: RefCell<Routes>,
    stats: RefCell<Stats>,
    whole: RefCell<Stats>,
    pooled: RefCell<PoolStats>,
    /// Operations whose last request is unanswered, reads at a cut
    /// waiting for their window's close among them.
    inflight: Cell<u64>,
    ex: &'static LocalExecutor<'static>,
    /// The space's window clock: its origin and length, in ms; and `D`,
    /// how long after a window's boundary its close comes.
    window: (u64, u64, u64),
    /// Every request to a node that does not replicate its agent:
    /// [`Plan::probe`].
    probe: bool,
    /// The last interval's end, and the CPU used by then.
    flushed: Cell<(Instant, f64)>,
    /// The first and last sends, in ms since the epoch.
    sends: Cell<Option<(u64, u64)>>,
    jitter: Cell<Mix>,
}

impl Engine {
    /// A node that does not replicate `agent`: a probe's target, checked
    /// to exist before the load.
    fn elsewhere(&self, agent: usize) -> usize {
        let replicas = &self.shared.agents[agent].replicas;
        (0..self.pools.len())
            .find(|node| !replicas.contains(node))
            .expect("a node outside the replicas, checked before the load")
    }

    fn record(&self, kind: &'static str, update: impl FnOnce(&mut KindStats)) {
        update(self.stats.borrow_mut().kind(kind));
    }

    fn done(&self, kind: &'static str, due: Instant, answer: &Result<Response, String>) {
        let ok = matches!(
            answer,
            Ok(Response::Ran {
                outcome: Outcome::Done(_) | Outcome::Started(_),
                ..
            }) | Ok(Response::Workflow {
                status: WorkflowStatus::Ended(Outcome::Done(_)),
                ..
            })
        );
        let took = Instant::now().saturating_duration_since(due).as_micros() as u64;
        self.record(kind, |stats| {
            if ok {
                stats.ok += 1;
                stats.latency.record(took);
            } else {
                *stats.errors.entry(refusal(answer)).or_default() += 1;
                stats.refused.record(took);
            }
        });
    }

    /// Take `op` at its time: send it, or queue it behind its user's
    /// unanswered call.
    fn dispatch(self: &Rc<Self>, mut op: Op) {
        let now = Instant::now();
        let late = now.saturating_duration_since(op.due).as_micros() as u64;
        // Timed from its schedule, or from its send if that came first.
        op.due = op.due.min(now);
        let at = wall_ms();
        self.sends.set(Some(
            self.sends.get().map_or((at, at), |(first, _)| (first, at)),
        ));
        self.record(op.kind.name(), |stats| {
            stats.sent += 1;
            stats.cross += u64::from(op.cross);
            stats.late_us = stats.late_us.max(late);
            stats.late_sends += u64::from(late > LATE_US);
        });
        self.inflight.set(self.inflight.get() + 1);
        let kind = op.kind.name();
        if matches!(op.body, Body::Query(_)) {
            let this = Rc::clone(self);
            self.ex.spawn(async move { this.query(op).await }).detach();
            return;
        }
        let ready = {
            let mut sessions = self.shared.sessions.lock().expect("sessions");
            let session = sessions
                .get_mut(&op.user)
                .expect("a planned user's session");
            if session.busy {
                session.queue.push_back(op);
                None
            } else {
                session.busy = true;
                Some(self.prepare(session, op))
            }
        };
        match ready {
            Some(op) => {
                let this = Rc::clone(self);
                self.ex.spawn(async move { this.call(op).await }).detach();
            }
            None => self.record(kind, |stats| stats.queued += 1),
        }
    }

    /// `op` ready to send in `session`: signed again, here, unless it was
    /// signed at the session's next sequence.
    fn prepare(&self, session: &mut session::UserSession, mut op: Op) -> Op {
        let agent = op.agent;
        let mut again = false;
        if let Body::Call {
            method,
            arguments,
            generation,
            sequence,
            signed,
        } = &mut op.body
        {
            let (at, resign) = session.turn(*generation, *sequence);
            if resign {
                *signed = self
                    .shared
                    .call_body(agent, session, at, *method, arguments);
                *generation = session.generation;
                *sequence = at;
                again = true;
            }
        }
        if again {
            self.record(op.kind.name(), |stats| stats.signed += 1);
        }
        op
    }

    async fn query(self: Rc<Self>, op: Op) {
        let Body::Query(body) = &op.body else {
            unreachable!("a query")
        };
        let agent = &self.shared.agents[op.agent];
        let node = match self.probe {
            true => self.elsewhere(op.agent),
            false => self
                .routes
                .borrow()
                .query(op.agent, &agent.replicas, op.user, Instant::now()),
        };
        let answer = self.pools[node].post(&agent.paths[1], body, ANSWER).await;
        if !self.probe && unserved(&answer) {
            self.routes
                .borrow_mut()
                .failed(op.agent, &agent.replicas, node, Instant::now());
        }
        self.done(op.kind.name(), op.due, &answer);
        self.inflight.set(self.inflight.get() - 1);
    }

    async fn call(self: Rc<Self>, op: Op) {
        let Body::Call {
            signed, sequence, ..
        } = &op.body
        else {
            unreachable!("a call")
        };
        let agent = &self.shared.agents[op.agent];
        let node = match self.probe {
            true => self.elsewhere(op.agent),
            false => self.routes.borrow().call(op.agent),
        };
        let answer = self.pools[node].post(&agent.paths[0], signed, ANSWER).await;
        // A probe's calls are refused before they reach a session: its
        // sequences go on as if each ran, as they would at the leader.
        let fate = match self.probe {
            true => Fate::Ran(0),
            false => fate(&answer),
        };
        if !self.probe {
            self.learn(op.agent, node, &answer);
        }
        // The session goes on before any read of a workflow: the user's
        // next call need not wait for it.
        let next = {
            let mut sessions = self.shared.sessions.lock().expect("sessions");
            let session = sessions
                .get_mut(&op.user)
                .expect("a sending user's session");
            let generation = session.generation + 1;
            session.settle(&fate, *sequence, || {
                self.shared.fresh(op.user, op.agent, generation)
            });
            session.busy = false;
            match session.queue.pop_front() {
                Some(next) => {
                    session.busy = true;
                    Some(self.prepare(session, next))
                }
                None => None,
            }
        };
        if let Some(next) = next {
            let this = Rc::clone(&self);
            self.ex.spawn(async move { this.call(next).await }).detach();
        }
        let started = match &answer {
            Ok(Response::Ran {
                outcome: Outcome::Started(workflow),
                ..
            }) => Some(*workflow),
            _ => None,
        };
        match (op.kind, started) {
            (Kind::Workflow, Some(workflow)) => {
                let read = self.read_workflow(&op, workflow, WORKFLOW_WAIT_MS).await;
                self.done("workflow", op.due, &read);
            }
            (Kind::Cut, Some(workflow)) => {
                self.done("cut", op.due, &answer);
                self.read_at_cut(&op, workflow, "cut_read").await;
            }
            (Kind::Reader, Some(workflow)) => {
                self.done("reader", op.due, &answer);
                self.read_at_cut(&op, workflow, "reader_read").await;
            }
            (kind, _) => self.done(kind.name(), op.due, &answer),
        }
        self.inflight.set(self.inflight.get() - 1);
    }

    /// What an answer from `node` says of `agent`'s leader, and of the
    /// agents' time.
    fn learn(&self, agent: usize, node: usize, answer: &Result<Response, String>) {
        let replicas = &self.shared.agents[agent].replicas;
        match answer {
            Ok(Response::NotLeader {
                leader: Some(contact),
            }) => {
                let named = contact
                    .address
                    .rsplit("//")
                    .next()
                    .unwrap_or(&contact.address);
                if let Some(leader) = replicas
                    .iter()
                    .find(|replica| self.pools[**replica].authority == named)
                {
                    self.routes.borrow_mut().leaders[agent] = *leader;
                }
            }
            Ok(Response::Rejected(vos_wire::ingress::Rejection::StaleSession { now })) => {
                self.shared.learn_time(*now);
            }
            answer if unserved(answer) => {
                self.routes
                    .borrow_mut()
                    .failed(agent, replicas, node, Instant::now());
            }
            _ => {}
        }
    }

    /// A signed read of `workflow`, waiting up to `wait_ms` for it to end,
    /// at its agent's leader as last learned: signed here, on the sending
    /// thread, and counted so.
    async fn read_workflow(
        &self,
        op: &Op,
        workflow: WorkflowId,
        wait_ms: u64,
    ) -> Result<Response, String> {
        let (key, floor) = {
            let sessions = self.shared.sessions.lock().expect("sessions");
            let session = &sessions[&op.user];
            (session.key.clone(), session.floor)
        };
        let agent = &self.shared.agents[op.agent];
        let read = signed_workflow_read(
            &agent.identity,
            &key,
            workflow_read_not_after(self.shared.agent_now(), wait_ms),
            Consistency::Applied { at: floor },
            workflow,
            wait_ms,
        )
        .encode();
        self.record(op.kind.name(), |stats| stats.signed += 1);
        let node = match self.probe {
            true => self.elsewhere(op.agent),
            false => self.routes.borrow().call(op.agent),
        };
        let answer = self.pools[node]
            .post(
                &agent.paths[2],
                &read,
                ANSWER + Duration::from_millis(wait_ms),
            )
            .await;
        if !self.probe && unserved(&answer) {
            self.routes
                .borrow_mut()
                .failed(op.agent, &agent.replicas, node, Instant::now());
        }
        answer
    }

    /// A read at a cut, once started: read once to learn its window, then
    /// again from its close, `B_w + D`, until it ends, as `kind`. Its
    /// latency is from the close: whether every read is served within 10 s
    /// of it.
    async fn read_at_cut(&self, op: &Op, workflow: WorkflowId, kind: &'static str) {
        let first = self.read_workflow(op, workflow, 0).await;
        let (origin, length, delay) = self.window;
        let close = match &first {
            Ok(Response::Workflow {
                status: WorkflowStatus::Attesting { window, deadline },
                ..
            }) => match length {
                0 => *deadline,
                length => origin + (window + 1) * length + delay,
            },
            other => {
                // Ended already, or refused: no wait for a close.
                return self.done(kind, Instant::now(), other);
            }
        };
        let now = self.shared.agent_now();
        let closed = Instant::now() + Duration::from_millis(close.saturating_sub(now));
        let jitter = {
            let mut mix = self.jitter.get();
            let jitter = mix.next() % CUT_JITTER_MS;
            self.jitter.set(mix);
            jitter
        };
        Timer::at(closed + Duration::from_millis(jitter)).await;
        let last = loop {
            let asked = Instant::now();
            let read = self.read_workflow(op, workflow, CUT_WAIT_MS).await;
            let ended = matches!(
                read,
                Ok(Response::Workflow {
                    status: WorkflowStatus::Ended(_),
                    ..
                })
            );
            if ended || closed.elapsed() > Duration::from_millis(CUT_GIVE_UP_MS) {
                break read;
            }
            if asked.elapsed() < CUT_POLL {
                Timer::after(CUT_POLL - asked.elapsed()).await;
            }
        };
        self.done(kind, closed, &last);
    }

    /// The interval's lines: a line a kind, then one for the mix with the
    /// driver's own counts.
    fn flush(&self, file: &mut std::fs::File) {
        let (since, cpu_then) = self.flushed.get();
        let seconds = since.elapsed().as_secs_f64();
        let cpu = cpu_seconds();
        self.flushed.set((Instant::now(), cpu));
        let taken = std::mem::take(&mut *self.stats.borrow_mut());
        let mut pooled = PoolStats::default();
        for pool in &self.pools {
            pooled.absorb(&pool.take_stats());
        }
        let t_ms = wall_ms();
        for name in REPORTED {
            if let Some(stats) = taken.kinds.get(name) {
                let _ = writeln!(file, "{}", stats.line(t_ms, seconds, name, false));
            }
        }
        let mut line = taken.mix().line(t_ms, seconds, "all", false);
        line["cpu_s"] = (cpu - cpu_then).into();
        pool_fields(&mut line, &pooled);
        let _ = writeln!(file, "{line}");
        self.pooled.borrow_mut().absorb(&pooled);
        let mut whole = self.whole.borrow_mut();
        for (name, stats) in taken.kinds {
            whole.kind(name).absorb(&stats);
        }
        self.shared.forget();
    }
}

/// A line's counts of the driver's connections.
fn pool_fields(line: &mut serde_json::Value, pooled: &PoolStats) {
    line["conn_waits"] = pooled.waits.into();
    line["conn_wait_p99_us"] = pooled.wait.quantile(0.99).into();
    line["in_use_max"] = pooled.in_use_max.into();
}

/// What the plan's agents are, read from the nodes, a few at once: the
/// shards, the idle agents (only when readers read them), then the
/// identity agent.
fn agents(placed: &[&Placed], targets: &[Target]) -> Result<Vec<Agent>, String> {
    let one = |placed: &Placed| -> Result<Agent, String> {
        let agent = AgentId(placed.agent);
        let mut last = String::from("no replica answered");
        for replica in &placed.replicas {
            match vos_node::client::agent_info(&targets[usize::from(*replica) - 1], agent) {
                Ok(Some(info)) => {
                    return Ok(Agent {
                        id: agent,
                        identity: vos_node::identity(&info.record),
                        replicas: placed
                            .replicas
                            .iter()
                            .map(|node| usize::from(*node) - 1)
                            .collect(),
                        paths: ["calls", "queries", "workflows"]
                            .map(|kind| format!("/agents/{}/{kind}", agent.0)),
                    });
                }
                Ok(None) => last = format!("agent {}: unknown to node {replica}", agent.0),
                Err(error) => last = format!("agent {}: {error}", agent.0),
            }
        }
        Err(last)
    };
    let readers = 16.min(placed.len()).max(1);
    let read: Vec<Vec<(usize, Result<Agent, String>)>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..readers)
            .map(|reader| {
                scope.spawn(move || {
                    (reader..placed.len())
                        .step_by(readers)
                        .map(|at| (at, one(placed[at])))
                        .collect()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("an agents' reader"))
            .collect()
    });
    let mut read: Vec<(usize, Result<Agent, String>)> = read.into_iter().flatten().collect();
    read.sort_by_key(|(at, _)| *at);
    read.into_iter().map(|(_, agent)| agent).collect()
}

fn methods(plan: &Plan, targets: &[Target]) -> Result<Methods, String> {
    let first = plan.shards.first().ok_or("no ledger shards")?;
    let schema = vos_node::client::schema(
        &targets[usize::from(first.replicas[0]) - 1],
        AgentId(first.agent),
        InstanceId(first.instance),
    )
    .map_err(|error| error.to_string())?
    .ok_or("nothing installed in the first shard")?;
    let id = |name: &str| {
        schema
            .method_id(name)
            .ok_or_else(|| format!("the shard actor has no method {name}"))
    };
    Ok(Methods {
        transfer: id("transfer")?,
        balance: id("balance")?,
        tally: id("tally")?,
        holds_at_cut: id("holds_at_cut")?,
        set_identity: id("set_identity")?,
    })
}

/// Run this driver's share of `plan`, writing its lines to `out`: a line
/// a kind every interval, then the totals and the mix as sent.
pub fn run_local(plan: &Plan, out: &Path) -> Result<(), String> {
    plan.model.validate(plan.shards.len())?;
    let targets = plan
        .nodes
        .iter()
        .map(target)
        .collect::<Result<Vec<_>, _>>()?;
    let reading = plan.model.readers > 0.0;
    let idle: &[Placed] = if reading { &plan.idle } else { &[] };
    let identity = plan.identity.as_ref().filter(|_| !plan.probe);
    let placed: Vec<&Placed> = plan.shards.iter().chain(idle).chain(identity).collect();
    if plan.probe
        && let Some(covered) = placed
            .iter()
            .find(|placed| placed.replicas.len() >= plan.nodes.len())
    {
        return Err(format!(
            "the probe needs a node outside every agent's replicas: agent {} is on all {}",
            covered.agent,
            plan.nodes.len()
        ));
    }
    let agents = agents(&placed, &targets)?;
    let methods = methods(plan, &targets)?;
    let leaders: Vec<usize> = placed
        .iter()
        .map(|placed| usize::from(placed.leader.unwrap_or(placed.replicas[0])) - 1)
        .collect();
    let users = Users::new(plan.model.seed, plan.model.users, plan.shards.len());
    let shards = plan.shards.len();
    let shared = Arc::new(Shared {
        identity_agent: identity.map(|_| shards + idle.len()),
        shards,
        agents,
        instance: InstanceId(plan.shards[0].instance),
        methods,
        seed: plan.model.seed,
        sessions: Mutex::new(HashMap::new()),
        counts: Mutex::new(ShardCounts {
            users: vec![0; shards],
            sessions: vec![0; shards],
        }),
        offset_ms: AtomicI64::new(0),
    });
    let mut model = plan.model.clone();
    if identity.is_none() {
        model.identity_hz = 0.0;
    }
    let pools = targets
        .iter()
        .map(|target| Pool::new(target, plan.connections))
        .collect::<Result<Vec<_>, _>>()?;
    let mut file =
        std::fs::File::create(out).map_err(|error| format!("{}: {error}", out.display()))?;
    let secs = plan.secs as f64;
    let (sender, receiver) = smol::channel::unbounded::<Op>();
    // The load starts once the sending thread opened its first connections:
    // its start, and its start in ms since the epoch.
    let (started, starting) = std::sync::mpsc::channel::<(Instant, u64)>();
    let (ready, planned_ready) = std::sync::mpsc::channel::<()>();
    std::thread::scope(|scope| {
        let planner = {
            let shared = Arc::clone(&shared);
            let (users, model) = (&users, &model);
            let (driver, drivers) = (plan.driver, plan.drivers);
            let reader_agents = shards + idle.len();
            let (origin_ms, length_ms, _) = plan.window;
            std::thread::Builder::new()
                .name("plan".into())
                .spawn_scoped(scope, move || {
                    // The users active at the start, their keys derived
                    // before it.
                    let mut planned = load::Plan::new(model, users, driver, drivers);
                    for user in planned.fill() {
                        shared.open(user, users.shard(user));
                    }
                    let _ = ready.send(());
                    let Ok((start, start_ms)) = starting.recv() else {
                        return;
                    };
                    let planned = planned.with_readers(Readers {
                        agents: reader_agents,
                        origin_ms,
                        length_ms,
                        start_ms,
                    });
                    for planned in planned {
                        if planned.t >= secs {
                            break;
                        }
                        let due = start + Duration::from_secs_f64(planned.t);
                        let ahead = due.saturating_duration_since(Instant::now());
                        // Asleep in stretches, not before every operation.
                        if ahead > LOOKAHEAD + PLAN_NAP {
                            std::thread::sleep(ahead - LOOKAHEAD);
                        }
                        let op = shared.operation(&planned, users, due);
                        if sender.send_blocking(op).is_err() {
                            break;
                        }
                    }
                })
                .expect("the planning thread")
        };
        let ex: &'static LocalExecutor<'static> = Box::leak(Box::new(LocalExecutor::new()));
        let nodes = pools.len();
        let engine = Rc::new(Engine {
            shared: Arc::clone(&shared),
            pools,
            routes: RefCell::new(Routes {
                leaders,
                down: vec![None; nodes],
            }),
            stats: RefCell::new(Stats::default()),
            whole: RefCell::new(Stats::default()),
            pooled: RefCell::new(PoolStats::default()),
            inflight: Cell::new(0),
            ex,
            window: plan.window,
            probe: plan.probe,
            flushed: Cell::new((Instant::now(), cpu_seconds())),
            sends: Cell::new(None),
            jitter: Cell::new(Mix(plan.model.seed ^ plan.driver ^ 0x7177)),
        });
        let every = Duration::from_secs(plan.every_s.max(1));
        let drain = Duration::from_millis(plan.drain_ms());
        let mut load_cpu = 0.0;
        smol::block_on(ex.run(async {
            let warming: Vec<_> = (0..engine.pools.len())
                .flat_map(|node| (0..WARM.min(plan.connections)).map(move |_| node))
                .map(|node| {
                    let engine = Rc::clone(&engine);
                    ex.spawn(async move { engine.pools[node].warm().await })
                })
                .collect();
            for warm in warming {
                warm.await;
            }
            let _ = planned_ready.recv();
            // Signed ahead from now: the first operations a little later.
            let _ = started.send((
                Instant::now() + LOOKAHEAD,
                wall_ms() + LOOKAHEAD.as_millis() as u64,
            ));
            let cpu_before = cpu_seconds();
            engine.flushed.set((Instant::now(), cpu_before));
            let reporter = {
                let engine = Rc::clone(&engine);
                let file = &mut file;
                async move {
                    loop {
                        Timer::after(every).await;
                        engine.flush(file);
                    }
                }
            };
            let reaper = {
                let engine = Rc::clone(&engine);
                async move {
                    loop {
                        Timer::after(REAP).await;
                        for pool in &engine.pools {
                            pool.reap();
                        }
                    }
                }
            };
            let reporter = smol::future::or(reporter, reaper);
            let load = async {
                while let Ok(op) = receiver.recv().await {
                    if op.due > Instant::now() + EARLY {
                        Timer::at(op.due).await;
                    }
                    engine.dispatch(op);
                }
                load_cpu = cpu_seconds() - cpu_before;
                // The load is sent: its answers, and the reads waiting for
                // a cut's close, within the drain.
                let ended = Instant::now();
                while engine.inflight.get() > 0 && ended.elapsed() < drain {
                    Timer::after(Duration::from_millis(100)).await;
                }
            };
            smol::future::or(load, reporter).await;
        }));
        let _ = planner.join();
        engine.flush(&mut file);
        let whole = std::mem::take(&mut *engine.whole.borrow_mut());
        let t_ms = wall_ms();
        let (from_ms, to_ms) = engine.sends.get().unwrap_or((t_ms, t_ms));
        let span = ((to_ms - from_ms) as f64 / 1e3).max(1.0);
        for name in REPORTED {
            if let Some(stats) = whole.kinds.get(name) {
                let _ = writeln!(file, "{}", stats.line(t_ms, span, name, true));
            }
        }
        let mut total = whole.mix().line(t_ms, span, "all", true);
        // The load's span, from its first send to its last: a report's
        // window, the drain left out.
        total["load_from_ms"] = from_ms.into();
        total["load_to_ms"] = to_ms.into();
        // The CPU of the load's span, in cores: the driver's cost at its
        // rate.
        total["load_cores"] = (load_cpu / span).into();
        total["threads_cpu_s"] = serde_json::json!(thread_seconds());
        total["unanswered"] = engine.inflight.get().into();
        total["active_users"] = load::Plan::new(&model, &users, plan.driver, plan.drivers)
            .slots()
            .into();
        total["connections"] = plan.connections.into();
        pool_fields(&mut total, &engine.pooled.borrow());
        {
            let counts = shared.counts.lock().expect("counts");
            total["shard_users"] = serde_json::json!(counts.users);
            total["shard_sessions"] = serde_json::json!(counts.sessions);
        }
        total["mix"] = mix_line(plan, &whole.kinds);
        writeln!(file, "{total}").map_err(|error| error.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::{Routes, unserved};
    use std::time::{Duration, Instant};
    use vos_wire::ingress::Response;

    /// A leader that fails is left for the next replica up; queries skip a
    /// follower that failed until its backoff ends.
    #[test]
    fn a_dead_node_loses_its_routes_for_a_while() {
        let replicas = [0, 2, 3];
        let mut routes = Routes {
            leaders: vec![2],
            down: vec![None; 4],
        };
        let now = Instant::now();
        assert!(unserved(&Err("connection refused".into())));
        assert!(unserved(&Ok(Response::NotLeader { leader: None })));
        assert!(!unserved(&Ok(Response::Busy)));
        routes.failed(0, &replicas, 2, now);
        assert_eq!(routes.call(0), 3);
        // Queries go to the followers up, the new leader excepted.
        for user in 0..4 {
            assert_eq!(routes.query(0, &replicas, user, now), 0);
        }
        routes.failed(0, &replicas, 0, now);
        assert_eq!(routes.query(0, &replicas, 1, now), 3, "none up: the leader");
        let later = now + Duration::from_secs(3);
        assert_eq!(routes.query(0, &replicas, 1, later), [0, 2][1]);
        // The leader failing too: its place goes on, to a node up first.
        routes.failed(0, &replicas, 3, later);
        assert_eq!(routes.call(0), 0);
    }
}
