//! Clients' calls, from this node's ingress or forwarded by another
//! replica: run in their lanes at the agent's leader, or forwarded to it.
//!
//! Per (agent, session), at the leader, a call at or below the agent's
//! applied mark is a duplicate answered from its reply window; one in
//! flight waits for that answer; the next after those queued is queued;
//! any other is refused.
//!
//! The leader pushes a call to its group in its lane's order: nothing
//! awaits between the call's turn and its push, and the node's tasks share
//! one thread, so no other call of the lane comes between them. Should a
//! push have to wait for a leader, a later call may go first; refine
//! refuses that one as a gap, consuming nothing, and its client sends it
//! again.
//!
//! A replica that does not lead runs no lane: its marks may lag. It checks
//! the call's signature, forwards the call to the leader, again through
//! leader changes, and answers once it has applied the call itself.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, Principal, Session};
use vos_wire::ingress::{Call, Rejection, Response};
use vos_wire::peer::{NodeNumber, PeerMessage};
use vos_wire::result::Outcome;
use vos_wire::{defaults, keys};

use crate::asking::{PAUSE, REASK, Waits, pause};
use crate::fault::{Fault, read, session_mark};
use crate::node::{Answered, CallError, Inner, Reply, Run};
use crate::signature::signed;
use crate::{lock, timeout};

/// How long a forwarded call may take: its re-forwards, and the wait for
/// this replica's own apply.
const FORWARDING: Duration = Duration::from_secs(30);
/// Forwarded calls the leader runs at once for one forwarding replica.
const FORWARDED: usize = 1024;

/// One (agent, session)'s calls the leader has queued.
#[derive(Default)]
struct Lane {
    /// The highest sequence queued or applied.
    queued: u64,
    /// The calls in flight, each with the duplicates waiting on it.
    inflight: HashMap<u64, Vec<smol::channel::Sender<Response>>>,
}

#[derive(Default)]
pub(crate) struct Calls {
    lanes: Mutex<HashMap<(AgentId, Session), Lane>>,
    /// The calls this replica forwarded, each waiting for its answer and
    /// the term it came at.
    pub(crate) forwards: Waits<(u64, Response)>,
    /// The forwarded calls running here, by the replica that forwarded
    /// them, each by its token: a call forwarded again while it runs is
    /// answered once, when it ends.
    forwarded: Mutex<HashMap<NodeNumber, HashSet<u64>>>,
}

/// A forwarded call's place among those running, given back when it ends,
/// however it ends.
struct Running<'a> {
    calls: &'a Calls,
    from: NodeNumber,
    token: u64,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let mut forwarded = lock(&self.calls.forwarded);
        if let Some(running) = forwarded.get_mut(&self.from) {
            running.remove(&self.token);
            if running.is_empty() {
                forwarded.remove(&self.from);
            }
        }
    }
}

/// What the agent's applied state holds of a session.
struct Applied {
    /// The session's last sequence consumed, 0 for one the agent does not
    /// hold.
    mark: u64,
    /// The reply kept for the sequence asked about, at or below the mark.
    reply: Option<Outcome>,
    /// The agent's time, for a session it does not hold.
    time: Option<u64>,
    /// The applied index read at.
    at: u64,
}

impl Applied {
    /// The answer to a call at `sequence`, if the session consumed it: the
    /// reply kept for it, or `TooOld` once the window let it go.
    fn consumed(&mut self, sequence: u64) -> Option<Response> {
        (sequence <= self.mark).then(|| match self.reply.take() {
            Some(outcome) => Response::Ran {
                outcome,
                at: self.at,
            },
            None => Response::Rejected(Rejection::TooOld),
        })
    }
}

enum Next {
    Response(Response),
    Wait(smol::channel::Receiver<Response>),
    Queue,
}

/// What a client is answered for the node's reply.
pub(crate) fn answer_of(reply: Result<Answered, CallError>) -> Response {
    match reply {
        Err(error) => error.into(),
        Ok(Answered {
            reply: Reply::Ran(outcome),
            at,
        }) => Response::Ran { outcome, at },
        Ok(Answered {
            reply: Reply::Refused(code),
            ..
        }) => Response::Refused(code),
        Ok(Answered {
            reply: Reply::Failed,
            ..
        }) => Response::NotConsumed,
        Ok(Answered {
            reply: Reply::TooOld,
            ..
        }) => Response::Rejected(Rejection::TooOld),
    }
}

/// What a client is answered when its call has no reply.
impl From<CallError> for Response {
    fn from(error: CallError) -> Self {
        match error {
            CallError::Failed(_) => Response::Unavailable,
            CallError::Busy => Response::Busy,
            CallError::NoAgent => Response::NoAgent,
            CallError::Stopped => Response::Stopped,
            CallError::NotLeader(leader) => Response::NotLeader { leader },
            CallError::Elsewhere(replicas) => Response::Elsewhere { replicas },
            CallError::Unconfirmed(agent) => Response::Unconfirmed(agent),
            CallError::TimedOut => Response::TimedOut,
        }
    }
}

impl Inner {
    /// A client's call, as ingress takes it: its signature checked on an
    /// executor, then run here if this replica leads the agent, else
    /// forwarded to the leader.
    pub(crate) async fn client_call(self: &Arc<Self>, agent: AgentId, call: Call) -> Response {
        let run = match self.present(agent) {
            Ok(run) => run,
            Err(error) => return error.into(),
        };
        let identity = run.shared.identity;
        let stats = Arc::clone(&self.stats);
        let checked = self
            .offload(move || {
                let started = Instant::now();
                let signed = signed(&identity, &call);
                stats.verify.took(started.elapsed());
                (signed, call)
            })
            .await;
        let call = match checked {
            Some((true, call)) => call,
            Some((false, _)) => return Response::Rejected(Rejection::BadSignature),
            None => return Response::Unavailable,
        };
        if let Err(error) = self.settled(agent).await {
            return error.into();
        }
        if run.agent.leading() {
            self.lane_call(agent, call).await
        } else {
            self.forward(&run, agent, call).await
        }
    }

    /// Run a call whose signature was checked in its lane: this replica
    /// must lead the agent, else the answer says where the leader is.
    async fn lane_call(self: &Arc<Self>, agent: AgentId, call: Call) -> Response {
        if let Err(error) = self.leading(agent).await {
            return error.into();
        }
        let mut confirmed = false;
        let next = loop {
            match self.next(agent, &call) {
                // A refusal for a mark too low, or a session missing, holds
                // only while this replica leads: a deposed leader that has
                // not heard so reads state its successor moved past.
                Next::Response(Response::Rejected(
                    Rejection::Gap { .. } | Rejection::Ahead | Rejection::StaleSession { .. },
                )) if !confirmed => {
                    if let Err(error) = self.read_index(agent).await {
                        return error.into();
                    }
                    confirmed = true;
                }
                next => break next,
            }
        };
        match next {
            Next::Response(answer) => answer,
            Next::Wait(wait) => self.answered(wait).await,
            Next::Queue => {
                let (session, sequence) = (call.session, call.sequence);
                let request = Request {
                    session,
                    sequence,
                    caller: Principal::Client(session.key),
                    instance: call.instance,
                    method: call.method,
                    arguments: call.arguments,
                };
                // Pushed now, in the lane's order (see the module doc), and
                // run to its end in a task that settles the lane.
                let running = self.call(agent, request);
                let (answered, answer) = smol::channel::bounded(1);
                let inner = Arc::clone(self);
                self.spawn(async move {
                    let settled = inner.queued_call(agent, session, sequence, running).await;
                    let _ = answered.try_send(settled);
                });
                self.answered(answer).await
            }
        }
    }

    /// The answer `answer` gives, within the node's deadline.
    async fn answered(&self, answer: smol::channel::Receiver<Response>) -> Response {
        timeout(self.settings.answered, answer.recv())
            .await
            .map_or(Response::TimedOut, |answer| {
                answer.unwrap_or(Response::Stopped)
            })
    }

    /// The answer to a call its lane queued, once `running` ends; then
    /// every resend waiting on it is answered too.
    async fn queued_call(
        self: Arc<Self>,
        agent: AgentId,
        session: Session,
        sequence: u64,
        running: impl Future<Output = Result<Answered, CallError>>,
    ) -> Response {
        let lane_key = (agent, session);
        let answer = match answer_of(running.await) {
            // The program failed on it alone, here: on state a
            // deposed leader may hold. Once this replica is known to
            // lead, its state says whether the call ran after all.
            Response::NotConsumed => match self.read_index(agent).await {
                Ok(_) => match self.applied_session(agent, &session, sequence) {
                    Ok(mut applied) => applied.consumed(sequence).unwrap_or(Response::NotConsumed),
                    Err(answer) => answer,
                },
                Err(error) => error.into(),
            },
            answer => answer,
        };
        let waiting = {
            let mut lanes = lock(&self.calls.lanes);
            let lane = lanes.entry(lane_key).or_default();
            let waiting = lane.inflight.remove(&sequence).unwrap_or_default();
            // Not consumed, the mark stays: the client resends it.
            if !matches!(answer, Response::Ran { .. }) {
                lane.queued = lane.queued.min(sequence - 1);
            }
            if lane.inflight.is_empty() {
                lanes.remove(&lane_key);
            }
            waiting
        };
        for waiter in waiting {
            let _ = waiter.try_send(answer.clone());
        }
        answer
    }

    /// What a call's lane does with it now.
    fn next(&self, agent: AgentId, call: &Call) -> Next {
        let sequence = call.sequence;
        let mut lanes = lock(&self.calls.lanes);
        // Read under the lock: an answered call's commit is durable before
        // its lane changes, so the mark read here includes it.
        let mut applied = match self.applied_session(agent, &call.session, sequence) {
            Ok(applied) => applied,
            Err(answer) => return Next::Response(answer),
        };
        let mark = applied.mark;
        let key = (agent, call.session);
        let lane = lanes.entry(key).or_default();
        lane.queued = lane.queued.max(mark);
        // A new session's time must be near the agent's, as refine will
        // check: the client learns the time it should use. Only for a
        // session this leader holds nothing of: a call already queued was
        // timed when its batch formed, and a resend of it joins it.
        if let Some(time) = applied
            .time
            .filter(|_| lane.queued == 0 && lane.inflight.is_empty())
        {
            let now = (self.clock)().max(time);
            if call.session.t0.abs_diff(now) > defaults::SESSION_SKEW_MS {
                lanes.remove(&key);
                return Next::Response(Response::Rejected(Rejection::StaleSession { now }));
            }
        }
        let next = if sequence == 0 {
            Next::Response(Response::Rejected(Rejection::Gap { expected: mark + 1 }))
        } else if let Some(answer) = applied.consumed(sequence) {
            Next::Response(answer)
        } else if sequence > mark + defaults::REPLY_WINDOW {
            Next::Response(Response::Rejected(Rejection::Ahead))
        } else if let Some(waiting) = lane.inflight.get_mut(&sequence) {
            // The original's answer is this one's too. When that is a
            // refusal (a gap behind a call that failed) the resend may
            // already have moved past it; nothing was consumed, and the
            // client's next resend goes through.
            let (answer, wait) = smol::channel::bounded(1);
            waiting.push(answer);
            Next::Wait(wait)
        } else if sequence == lane.queued + 1 {
            lane.queued = sequence;
            lane.inflight.insert(sequence, Vec::new());
            Next::Queue
        } else {
            Next::Response(Response::Rejected(Rejection::Gap {
                expected: lane.queued + 1,
            }))
        };
        // A lane with nothing in flight holds nothing the mark does not.
        if lane.inflight.is_empty() {
            lanes.remove(&key);
        }
        next
    }

    /// What the agent's applied state holds of `session`, with the reply
    /// it kept for `sequence` when that is at or below its mark.
    fn applied_session(
        &self,
        agent: AgentId,
        session: &Session,
        sequence: u64,
    ) -> Result<Applied, Response> {
        let unavailable = |_: Fault| Response::Unavailable;
        let snapshot = self.store.snapshot();
        let at = snapshot
            .applied(agent)
            .map_err(|_| Response::Unavailable)?
            .unwrap_or(0);
        let Some((id, mark)) = session_mark(&snapshot, agent, session).map_err(unavailable)? else {
            let time = read::<u64>(&snapshot, agent, &keys::batch_time())
                .map_err(unavailable)?
                .unwrap_or(0);
            return Ok(Applied {
                mark: 0,
                reply: None,
                time: Some(time),
                at,
            });
        };
        let mark = mark.map_or(0, |mark| mark.sequence);
        let reply = if sequence <= mark {
            read::<Outcome>(&snapshot, agent, &keys::reply(id, sequence)).map_err(unavailable)?
        } else {
            None
        };
        Ok(Applied {
            mark,
            reply,
            time: None,
            at,
        })
    }

    /// Forward a checked call to the agent's leader until it is answered,
    /// then answer once this replica has applied it.
    async fn forward(self: &Arc<Self>, run: &Arc<Run>, agent: AgentId, call: Call) -> Response {
        let until = Instant::now() + FORWARDING;
        let wait = self.calls.forwards.register(agent);
        // How many times the call went: once it went before, nothing the
        // leader answers short of running it says it never ran.
        let mut sent = 0;
        // A leader at a later term than this replica knows of, as a node
        // that does not lead named it.
        let mut named: Option<(NodeNumber, u64)> = None;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Response::TimedOut;
            }
            let state = run.shared.state();
            if state.stopped {
                return Response::Stopped;
            }
            // This replica leads now: the call runs in its own lane.
            if run.agent.leading() {
                return self.lane_call(agent, call).await;
            }
            // The leader this replica follows, or one named at a later term
            // until this replica's own core reaches it.
            let (leader, term) = match named {
                Some((named, at)) if at > state.term => (Some(named), at),
                _ => (state.leader, state.term),
            };
            let changed = |state: &crate::group::State| {
                state.stopped || state.term > term || (state.term == term && state.leader != leader)
            };
            let Some(to) = leader.filter(|leader| *leader != self.number) else {
                // No leader known, or this replica leading before its loop
                // takes calls: wait for either to change.
                timeout(
                    left,
                    run.shared
                        .wait(|state| changed(state) || self.knows_leader(run, state)),
                )
                .await;
                continue;
            };
            sent += 1;
            self.send(
                to,
                &PeerMessage::Forward {
                    agent,
                    token: wait.token,
                    term,
                    call: call.clone(),
                },
            );
            match wait.within(REASK.min(left), run.shared.wait(changed)).await {
                // A node that leads at a later term than this replica
                // knows, or knows who does: there, at once. One at an
                // earlier term is behind: this replica waits for its own
                // core to name a leader, else the two would send the call
                // back and forth.
                Some((
                    answered_at,
                    Response::NotLeader {
                        leader: Some(contact),
                    },
                )) if answered_at > term => {
                    // Never this replica: its own core names itself.
                    named = self
                        .number_of(&contact)
                        .filter(|leader| *leader != self.number)
                        .map(|leader| (leader, answered_at));
                    if named.is_none() {
                        pause(run, PAUSE, until, changed).await;
                    }
                }
                Some((_, Response::Ran { outcome, at })) => {
                    // No reply before its apply here.
                    let left = until.saturating_duration_since(Instant::now());
                    let applied = timeout(
                        left,
                        run.shared
                            .wait(|state| state.stopped || state.applied >= at),
                    )
                    .await;
                    return match applied {
                        Some(state) if state.applied >= at => Response::Ran { outcome, at },
                        Some(_) => Response::Stopped,
                        None => Response::TimedOut,
                    };
                }
                // The node it went to does not lead, or could not take it
                // now: again, once this replica follows another leader, or
                // after a pause.
                Some((
                    _,
                    Response::NotLeader { .. }
                    | Response::Elsewhere { .. }
                    | Response::Stopped
                    | Response::Unavailable,
                )) => pause(run, PAUSE, until, changed).await,
                // The leader is full: at the first send nothing ran, and
                // the client may wait and send again. After that, an
                // earlier send may be running elsewhere: wait here.
                Some((_, Response::Busy)) if sent == 1 => return Response::Busy,
                Some((_, Response::Busy)) => pause(run, REASK, until, changed).await,
                // Answers that say the call did not run, about one send of
                // several: another may still run it.
                Some((
                    _,
                    Response::Rejected(Rejection::StaleSession { .. }) | Response::NotConsumed,
                )) if sent > 1 => {
                    return Response::TimedOut;
                }
                Some((_, Response::TimedOut)) | None => {}
                Some((_, answer)) => return answer,
            }
        }
    }

    /// A call forwarded by `from`, a replica of `agent`, to this replica
    /// as its leader at `term`: run in its lane, in a task of its own, and
    /// answered to `from`. A replica not leading at that term, whether it
    /// leads at another or leads nothing, answers who it knows leads, and
    /// at what term: a copy the network held across a redial runs no
    /// later than its sender meant.
    pub(crate) fn on_forward(
        self: &Arc<Self>,
        from: NodeNumber,
        agent: AgentId,
        token: u64,
        term: u64,
        call: Call,
    ) {
        if !self.admit(agent, from) {
            return;
        }
        let Some(run) = self.run(agent) else {
            // No group here: the forwarder goes again soon, to whoever its
            // own core names.
            self.answer_forward(from, agent, token, 0, Response::NotLeader { leader: None });
            return;
        };
        let state = run.shared.state();
        if state.term != term || state.role != vos_raft::Role::Leader {
            let leader = state.leader.and_then(|leader| self.contact(leader));
            self.answer_forward(
                from,
                agent,
                token,
                state.term,
                Response::NotLeader { leader },
            );
            return;
        }
        let admitted = {
            let mut forwarded = lock(&self.calls.forwarded);
            let running = forwarded.entry(from).or_default();
            if running.contains(&token) {
                // It runs already, and is answered when it ends.
                return;
            }
            running.len() < FORWARDED && running.insert(token)
        };
        if !admitted {
            self.answer_forward(from, agent, token, term, Response::Busy);
            return;
        }
        let inner = Arc::clone(self);
        self.spawn(async move {
            let running = Running {
                calls: &inner.calls,
                from,
                token,
            };
            let answer = inner.lane_call(agent, call).await;
            drop(running);
            let term = inner.run(agent).map_or(term, |run| run.shared.state().term);
            inner.answer_forward(from, agent, token, term, answer);
        });
    }

    /// Answer node `from`'s call forwarded under `token`, as of `term`.
    fn answer_forward(
        &self,
        from: NodeNumber,
        agent: AgentId,
        token: u64,
        term: u64,
        answer: Response,
    ) {
        self.send(
            from,
            &PeerMessage::Forwarded {
                agent,
                token,
                term,
                answer,
            },
        );
    }
}
