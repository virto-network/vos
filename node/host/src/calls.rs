//! Clients' calls, from this node's ingress or forwarded by another
//! replica: run in their lanes at the agent's leader, or forwarded to it.
//!
//! Per (agent, session), at the leader, a call at or below the agent's
//! applied mark is a duplicate answered from its reply window; one in
//! flight waits for that answer; the next after those queued is queued;
//! any other is refused.
//!
//! A replica that does not lead runs no lane: its marks may lag. It checks
//! the call's signature, forwards the call to the leader, again through
//! leader changes, and answers once it has applied the call itself.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use smol::future::FutureExt;
use vos_net::Class;
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, Principal, Session, SessionId};
use vos_wire::ingress::{Answer, Call, Rejection, call_message};
use vos_wire::peer::{NodeNumber, PeerMessage};
use vos_wire::records::{SessionMark, unstored};
use vos_wire::result::Outcome;
use vos_wire::{Decode, defaults, keys};

use crate::node::{Answered, CallError, Inner, Reply, Run};
use crate::peer::{self, Refusal};
use crate::store::{Store, View};

/// How long a forwarded call may take: its re-forwards, and the wait for
/// this replica's own apply.
const FORWARDING: Duration = Duration::from_secs(30);
/// How long a forward waits for its answer before it goes again.
const REFORWARD: Duration = Duration::from_secs(2);
/// How long a forwarder waits, for a change of leader, before it forwards
/// again to a leader that could not take the call.
const PAUSE: Duration = Duration::from_millis(100);
/// Forwarded calls the leader runs at once for one forwarding replica.
const FORWARDED: usize = 1024;

/// One (agent, session)'s calls the leader has queued.
#[derive(Default)]
struct Lane {
    /// The highest sequence queued or applied.
    queued: u64,
    /// The calls in flight, each with the duplicates waiting on it.
    inflight: HashMap<u64, Vec<smol::channel::Sender<Answer>>>,
}

#[derive(Default)]
pub(crate) struct Calls {
    lanes: Mutex<HashMap<(AgentId, Session), Lane>>,
    /// The calls this replica forwarded, by token, each waiting for its
    /// answer.
    forwards: Mutex<HashMap<u64, smol::channel::Sender<Answer>>>,
    /// The forwarded calls running here, by the replica that forwarded
    /// them, each by its token: a call forwarded again while it runs is
    /// answered once, when it ends.
    forwarded: Mutex<HashMap<NodeNumber, std::collections::HashSet<u64>>>,
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
        let mut forwarded = self.calls.forwarded.lock().expect("the forwarded");
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

enum Next {
    Answer(Answer),
    Wait(smol::channel::Receiver<Answer>),
    Queue,
}

/// What a client is answered for the node's reply.
pub(crate) fn answer_of(reply: Result<Answered, CallError>) -> Answer {
    match reply {
        Ok(Answered {
            reply: Reply::Ran(outcome),
            at,
        }) => Answer::Ran { outcome, at },
        Ok(Answered { reply, .. }) => match reply {
            Reply::Ran(_) => unreachable!("matched above"),
            Reply::Refused(code) => Answer::Refused(code),
            Reply::Failed => Answer::NotConsumed,
            Reply::TooOld => Answer::Rejected(Rejection::TooOld),
        },
        Err(CallError::Failed(_)) => Answer::Unavailable,
        Err(CallError::Busy) => Answer::Busy,
        Err(CallError::NoAgent) => Answer::NoAgent,
        Err(CallError::Stopped) => Answer::Stopped,
        Err(CallError::NotLeader(leader)) => Answer::NotLeader { leader },
        Err(CallError::Elsewhere(replicas)) => Answer::Elsewhere { replicas },
        Err(CallError::Unconfirmed(agent)) => Answer::Unconfirmed(agent),
    }
}

pub(crate) fn verify(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|key| {
        key.verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    })
}

/// Whether `call` is signed by its session's key, for the agent whose
/// identity is `identity`.
fn signed(identity: &[u8; 32], call: &Call) -> bool {
    let message = call_message(
        identity,
        &call.session,
        call.sequence,
        call.instance,
        call.method,
        &call.arguments,
    );
    verify(&call.session.key, &message, &call.signature)
}

impl Inner {
    /// A client's call, as ingress takes it: its signature checked on an
    /// executor, then run here if this replica leads the agent, else
    /// forwarded to the leader.
    pub(crate) async fn client_call(self: &Arc<Self>, agent: AgentId, call: Call) -> Answer {
        let Some(run) = self.run(agent) else {
            return answer_of(Err(self.absent(agent)));
        };
        let identity = run.shared.identity;
        let checked = self
            .offload(move || {
                let signed = signed(&identity, &call);
                (signed, call)
            })
            .await;
        let call = match checked {
            Some((true, call)) => call,
            Some((false, _)) => return Answer::Rejected(Rejection::BadSignature),
            None => return Answer::Unavailable,
        };
        if let Err(error) = self.settled(agent).await {
            return answer_of(Err(error));
        }
        if run.agent.queue.lock().expect("the queue").leading {
            self.lane_call(agent, call).await
        } else {
            self.forward(&run, agent, call).await
        }
    }

    /// Run a call whose signature was checked in its lane: this replica
    /// must lead the agent, else the answer says where the leader is.
    pub(crate) async fn lane_call(self: &Arc<Self>, agent: AgentId, call: Call) -> Answer {
        if let Err(error) = self.leading(agent).await {
            return answer_of(Err(error));
        }
        let mut confirmed = false;
        let next = loop {
            match self.next(agent, &call) {
                // A refusal for a mark too low, or a session missing, holds
                // only while this replica leads: a deposed leader that has
                // not heard so reads state its successor moved past.
                Next::Answer(Answer::Rejected(
                    Rejection::Gap { .. } | Rejection::Ahead | Rejection::StaleSession { .. },
                )) if !confirmed => {
                    if let Err(error) = self.read_index(agent).await {
                        return answer_of(Err(error));
                    }
                    confirmed = true;
                }
                next => break next,
            }
        };
        let sequence = call.sequence;
        let lane_key = (agent, call.session);
        match next {
            Next::Answer(answer) => answer,
            Next::Wait(wait) => wait.recv().await.unwrap_or(Answer::Stopped),
            Next::Queue => {
                let request = Request {
                    session: call.session,
                    sequence,
                    caller: Principal::Client(call.session.key),
                    instance: call.instance,
                    method: call.method,
                    arguments: call.arguments,
                };
                let answer = match answer_of(self.call(agent, request).await) {
                    // The program failed on it alone, here: on state a
                    // deposed leader may hold. Once this replica is known to
                    // lead, its state says whether the call ran after all.
                    Answer::NotConsumed => match self.read_index(agent).await {
                        Ok(_) => match self.applied_session(agent, &call.session, sequence) {
                            Ok(Applied {
                                mark,
                                reply: Some(outcome),
                                at,
                                ..
                            }) if sequence <= mark => Answer::Ran { outcome, at },
                            Ok(Applied { mark, .. }) if sequence <= mark => {
                                Answer::Rejected(Rejection::TooOld)
                            }
                            Ok(_) => Answer::NotConsumed,
                            Err(answer) => answer,
                        },
                        Err(error) => answer_of(Err(error)),
                    },
                    answer => answer,
                };
                let waiting = {
                    let mut lanes = self.calls.lanes.lock().expect("the lanes");
                    let lane = lanes.entry(lane_key).or_default();
                    let waiting = lane.inflight.remove(&sequence).unwrap_or_default();
                    // Not consumed, the mark stays: the client resends it.
                    if !matches!(answer, Answer::Ran { .. }) {
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
        }
    }

    /// What a call's lane does with it now.
    fn next(&self, agent: AgentId, call: &Call) -> Next {
        let sequence = call.sequence;
        let mut lanes = self.calls.lanes.lock().expect("the lanes");
        // Read under the lock: an answered call's commit is durable before
        // its lane changes, so the mark read here includes it.
        let Applied {
            mark,
            reply,
            time,
            at,
        } = match self.applied_session(agent, &call.session, sequence) {
            Ok(applied) => applied,
            Err(answer) => return Next::Answer(answer),
        };
        let key = (agent, call.session);
        let lane = lanes.entry(key).or_default();
        lane.queued = lane.queued.max(mark);
        // A new session's time must be near the agent's, as refine will
        // check: the client learns the time it should use. Only for a
        // session this leader holds nothing of: a call already queued was
        // timed when its batch formed, and a resend of it joins it.
        if let Some(time) = time.filter(|_| lane.queued == 0 && lane.inflight.is_empty()) {
            let now = (self.clock)().max(time);
            if call.session.t0.abs_diff(now) > defaults::SESSION_SKEW_MS {
                lanes.remove(&key);
                return Next::Answer(Answer::Rejected(Rejection::StaleSession { now }));
            }
        }
        let next = if sequence == 0 {
            Next::Answer(Answer::Rejected(Rejection::Gap { expected: mark + 1 }))
        } else if sequence <= mark {
            Next::Answer(match reply {
                Some(outcome) => Answer::Ran { outcome, at },
                None => Answer::Rejected(Rejection::TooOld),
            })
        } else if sequence > mark + defaults::REPLY_WINDOW {
            Next::Answer(Answer::Rejected(Rejection::Ahead))
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
            Next::Answer(Answer::Rejected(Rejection::Gap {
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
    ) -> Result<Applied, Answer> {
        let snapshot = self.store.snapshot();
        let at = snapshot
            .applied(agent)
            .map_err(|_| Answer::Unavailable)?
            .unwrap_or(0);
        let stored = |key: &[u8]| -> Result<Option<Vec<u8>>, Answer> {
            let bytes = snapshot.get(agent, key).map_err(|_| Answer::Unavailable)?;
            Ok(bytes.and_then(|bytes| unstored(&bytes).map(<[u8]>::to_vec)))
        };
        let Some(id) = stored(&keys::session_index(session))?
            .and_then(|bytes| SessionId::decode(&bytes).ok())
            .map(|(id, _)| id)
        else {
            let time = stored(&keys::batch_time())?
                .and_then(|bytes| u64::decode(&bytes).ok())
                .map_or(0, |(time, _)| time);
            return Ok(Applied {
                mark: 0,
                reply: None,
                time: Some(time),
                at,
            });
        };
        let mark = stored(&keys::session(id))?
            .and_then(|bytes| SessionMark::decode(&bytes).ok())
            .map_or(0, |(mark, _)| mark.sequence);
        let reply = if sequence <= mark {
            stored(&keys::reply(id, sequence))?
                .and_then(|bytes| Outcome::decode(&bytes).ok())
                .map(|(outcome, _)| outcome)
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
    async fn forward(self: &Arc<Self>, run: &Arc<Run>, agent: AgentId, call: Call) -> Answer {
        let until = Instant::now() + FORWARDING;
        let token = u64::from_le_bytes(crate::node::seed()[..8].try_into().expect("8 bytes"));
        let (answer, answered) = smol::channel::unbounded();
        self.calls
            .forwards
            .lock()
            .expect("the forwards")
            .insert(token, answer);
        let answer = self
            .forwarding(run, agent, &call, token, &answered, until)
            .await;
        self.calls
            .forwards
            .lock()
            .expect("the forwards")
            .remove(&token);
        answer
    }

    async fn forwarding(
        self: &Arc<Self>,
        run: &Arc<Run>,
        agent: AgentId,
        call: &Call,
        token: u64,
        answered: &smol::channel::Receiver<Answer>,
        until: Instant,
    ) -> Answer {
        // How many times the call went: once it went before, nothing the
        // leader answers short of running it says it never ran.
        let mut sent = 0;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Answer::TimedOut;
            }
            let state = run.shared.state();
            if state.stopped {
                return Answer::Stopped;
            }
            // This replica leads now: the call runs in its own lane.
            if run.agent.queue.lock().expect("the queue").leading {
                return self.lane_call(agent, call.clone()).await;
            }
            let (leader, term) = (state.leader, state.term);
            let changed = |state: &crate::group::State| {
                state.stopped || state.leader != leader || state.term != term
            };
            let Some(to) = leader.filter(|leader| *leader != self.number) else {
                // No leader known, or this replica leading before its loop
                // takes calls: wait for either to change.
                within(
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
                Class::Requests,
                &PeerMessage::Forward {
                    agent,
                    token,
                    call: call.clone(),
                },
            );
            let answer = async { answered.recv().await.ok() };
            let moved = async {
                run.shared.wait(changed).await;
                None
            };
            let quiet = async {
                smol::Timer::after(REFORWARD.min(left)).await;
                None
            };
            match answer.or(moved).or(quiet).await {
                Some(Answer::Ran { outcome, at }) => {
                    // No reply before its apply here.
                    let left = until.saturating_duration_since(Instant::now());
                    let applied = within(
                        left,
                        run.shared
                            .wait(|state| state.stopped || state.applied >= at),
                    )
                    .await;
                    return match applied {
                        Some(state) if state.applied >= at => Answer::Ran { outcome, at },
                        Some(_) => Answer::Stopped,
                        None => Answer::TimedOut,
                    };
                }
                // The node it went to does not lead, or could not take it
                // now: again, once this replica follows another leader, or
                // after a pause.
                Some(
                    Answer::NotLeader { .. }
                    | Answer::Elsewhere { .. }
                    | Answer::Stopped
                    | Answer::Unavailable,
                ) => {
                    let left = until.saturating_duration_since(Instant::now());
                    within(PAUSE.min(left), run.shared.wait(changed)).await;
                }
                // The leader is full: at the first send nothing ran, and
                // the client may wait and send again. After that, an
                // earlier send may be running elsewhere: wait here.
                Some(Answer::Busy) if sent == 1 => return Answer::Busy,
                Some(Answer::Busy) => {
                    let left = until.saturating_duration_since(Instant::now());
                    within(REFORWARD.min(left), run.shared.wait(changed)).await;
                }
                // Answers that say the call did not run, about one send of
                // several: another may still run it.
                Some(Answer::Rejected(Rejection::StaleSession { .. }) | Answer::NotConsumed)
                    if sent > 1 =>
                {
                    return Answer::TimedOut;
                }
                Some(Answer::TimedOut) | None => {}
                Some(answer) => return answer,
            }
        }
    }

    /// A call forwarded by `from`, a replica of `agent`: run in its lane,
    /// in a task of its own, and answered to `from`.
    pub(crate) fn on_forward(
        self: &Arc<Self>,
        from: NodeNumber,
        agent: AgentId,
        token: u64,
        call: Call,
    ) {
        let replicas = self
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .map(|record| record.replicas.clone());
        if let Err(refusal) = peer::check_replica(replicas.as_deref(), from) {
            self.drops.count(refusal);
            return;
        }
        let admitted = {
            let mut forwarded = self.calls.forwarded.lock().expect("the forwarded");
            let running = forwarded.entry(from).or_default();
            if running.contains(&token) {
                // It runs already, and is answered when it ends.
                return;
            }
            running.len() < FORWARDED && running.insert(token)
        };
        if !admitted {
            self.send(
                from,
                Class::Requests,
                &PeerMessage::Forwarded {
                    agent,
                    token,
                    answer: Answer::Busy,
                },
            );
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
            inner.send(
                from,
                Class::Requests,
                &PeerMessage::Forwarded {
                    agent,
                    token,
                    answer,
                },
            );
        });
    }

    /// The leader's answer to a call this replica forwarded, from a replica
    /// of `agent`.
    pub(crate) fn on_forwarded(
        &self,
        from: NodeNumber,
        agent: AgentId,
        token: u64,
        answer: Answer,
    ) {
        let replicas = self
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .map(|record| record.replicas.clone());
        if let Err(refusal) = peer::check_replica(replicas.as_deref(), from) {
            self.drops.count(refusal);
            return;
        }
        let waiting = self
            .calls
            .forwards
            .lock()
            .expect("the forwards")
            .get(&token)
            .cloned();
        match waiting {
            Some(waiting) => {
                let _ = waiting.try_send(answer);
            }
            None => self.drops.count(Refusal::Unmatched),
        }
    }
}

/// `work`, if it ends within `left`.
async fn within<T>(left: Duration, work: impl std::future::Future<Output = T>) -> Option<T> {
    let work = async { Some(work.await) };
    work.or(async {
        smol::Timer::after(left).await;
        None
    })
    .await
}
