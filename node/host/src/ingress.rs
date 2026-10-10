//! The node's HTTP ingress: signed calls in their sessions' sequences,
//! signed queries, and the operator's commands.
//!
//! A client names its sessions; the agent keeps them. Only the agent's
//! leader takes a call. Per (agent, session), a call at or below the
//! agent's applied mark is a duplicate answered from its reply window; one
//! in flight waits for that answer; the next after those queued is queued;
//! any other is refused.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::{Signature, VerifyingKey};
use smol::net::TcpListener;
use subtle::ConstantTimeEq;
use vos_wire::abi::{cap, refusal};
use vos_wire::batch::{Admin, Request};
use vos_wire::ids::{AgentId, InstanceId, Principal, Session, SessionId};
use vos_wire::ingress::{
    Answer, Call, Create, Grant, Install, QueryCall, Rejection, call_message, query_message,
};
use vos_wire::records::{Installed, SessionMark, unstored};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, defaults, keys};

use crate::http::{self, Handler, Limits, Response};
use crate::node::{CallError, Inner, Reply};
use crate::store::{Store, View};

/// How far ahead a query's `not_after` may be.
const QUERY_HORIZON_MS: u64 = 300_000;
/// The most a body may hold beyond a request's cap: its envelope.
const ENVELOPE: usize = 4096;
/// The most an install's body may hold: a package's programs.
const MAX_INSTALL: usize = 64 << 20;

/// One (agent, session)'s requests that ingress has queued.
#[derive(Default)]
struct Lane {
    /// The highest sequence queued or applied.
    queued: u64,
    /// The requests in flight, each with the duplicates waiting on it.
    inflight: HashMap<u64, Vec<smol::channel::Sender<Answer>>>,
}

pub(crate) struct Ingress {
    inner: Arc<Inner>,
    token: [u8; 32],
    lanes: Mutex<HashMap<(AgentId, Session), Lane>>,
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
}

enum Next {
    Answer(Answer),
    Wait(smol::channel::Receiver<Answer>),
    Queue,
}

fn reply_answer(reply: Result<Reply, CallError>) -> Answer {
    match reply {
        Ok(Reply::Ran(outcome)) => Answer::Ran(outcome),
        Ok(Reply::Refused(code)) => Answer::Refused(code),
        Ok(Reply::Failed) => Answer::NotConsumed,
        Ok(Reply::TooOld) => Answer::Rejected(Rejection::TooOld),
        Err(CallError::Failed(_)) => Answer::Unavailable,
        Err(CallError::Busy) => Answer::Busy,
        Err(CallError::NoAgent) => Answer::NoAgent,
        Err(CallError::Stopped) => Answer::Stopped,
        Err(CallError::NotLeader(leader)) => Answer::NotLeader { leader },
        Err(CallError::Elsewhere(replicas)) => Answer::Elsewhere { replicas },
        Err(CallError::Unconfirmed(agent)) => Answer::Unconfirmed(agent),
    }
}

fn status(answer: &Answer) -> u16 {
    match answer {
        Answer::Ran(_) | Answer::Created(_) => 200,
        Answer::Unconfirmed(_) => 202,
        // The session is done with: the client starts another.
        Answer::Refused(refusal::EXPIRED | refusal::STALE_SESSION) => 410,
        Answer::Refused(_) => 409,
        Answer::Rejected(rejection) => match rejection {
            Rejection::TooOld | Rejection::StaleSession { .. } => 410,
            Rejection::BadSignature | Rejection::Unauthorized => 401,
            Rejection::Gap { .. } | Rejection::Ahead => 409,
            Rejection::StaleQuery | Rejection::Malformed => 400,
        },
        Answer::NotConsumed => 500,
        Answer::NoAgent => 404,
        Answer::Busy | Answer::Stopped | Answer::Unavailable => 503,
        // Another node serves it: the answer says which.
        Answer::NotLeader { .. } | Answer::Elsewhere { .. } => 421,
    }
}

fn respond(answer: Answer) -> Response {
    Response::new(status(&answer), answer.encode())
}

fn verify(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|key| {
        key.verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    })
}

fn decode<T: Decode>(body: &[u8]) -> Result<T, Answer> {
    match T::decode(body) {
        Ok((value, used)) if used == body.len() => Ok(value),
        _ => Err(Answer::Rejected(Rejection::Malformed)),
    }
}

fn parse_hex(text: &[u8]) -> Option<[u8; 32]> {
    let text = std::str::from_utf8(text).ok()?.trim();
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16).ok()?;
    }
    Some(out)
}

impl Ingress {
    pub(crate) fn new(inner: Arc<Inner>, token: [u8; 32]) -> Self {
        Self {
            inner,
            token,
            lanes: Mutex::new(HashMap::new()),
        }
    }

    /// Serve until `stop` resolves, then end every connection.
    pub(crate) async fn serve(
        self,
        listener: TcpListener,
        tls: Option<Arc<rustls::ServerConfig>>,
        stop: smol::channel::Receiver<()>,
    ) {
        let this = Arc::new(self);
        let runtime = Arc::clone(&this.inner.runtime);
        let handler: Handler = {
            let this = Arc::clone(&this);
            Arc::new(move |request| {
                let this = Arc::clone(&this);
                Box::pin(async move { this.handle(request).await })
            })
        };
        let limits = Limits {
            body: Arc::new(|method, path| {
                if method == "POST" && path.ends_with("/install") {
                    MAX_INSTALL
                } else {
                    cap::REQUEST + ENVELOPE
                }
            }),
            idle: Duration::from_secs(30),
            connections: 1024,
        };
        let stopped = async {
            let _ = stop.recv().await;
        };
        http::serve(
            listener,
            tls,
            handler,
            limits,
            move |connection| runtime.spawn(connection),
            stopped,
        )
        .await;
    }

    async fn handle(&self, request: http::Request) -> Response {
        let path = request
            .path
            .split('?')
            .next()
            .unwrap_or_default()
            .to_string();
        let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        let agent = |text: &str| text.parse::<u32>().ok().map(AgentId);
        match (request.method.as_str(), segments.as_slice()) {
            ("GET", []) => Response::new(200, self.inner.node_id.encode()),
            ("GET", ["agents", id]) => match agent(id).and_then(|agent| self.record(agent)) {
                Some(record) => Response::new(200, record.encode()),
                None => Response::new(404, Vec::new()),
            },
            ("POST", ["agents", id, "calls"]) => match (agent(id), decode::<Call>(&request.body)) {
                (Some(agent), Ok(call)) => respond(self.call(agent, call).await),
                (None, _) => respond(Answer::NoAgent),
                (_, Err(answer)) => respond(answer),
            },
            ("POST", ["agents", id, "queries"]) => {
                match (agent(id), decode::<QueryCall>(&request.body)) {
                    (Some(agent), Ok(query)) => respond(self.query(agent, query).await),
                    (None, _) => respond(Answer::NoAgent),
                    (_, Err(answer)) => respond(answer),
                }
            }
            ("GET", ["agents", id, "instances", instance, "schema"]) => {
                match (agent(id), instance.parse::<u32>()) {
                    (Some(agent), Ok(instance)) => self.schema(agent, InstanceId(instance)),
                    _ => Response::new(404, Vec::new()),
                }
            }
            ("POST", ["agents"] | ["agents", _, "install" | "roles"])
                if !self.admitted(&request) =>
            {
                respond(Answer::Rejected(Rejection::Unauthorized))
            }
            ("POST", ["agents"]) => {
                let create = if request.body.is_empty() {
                    Ok(Create::default())
                } else {
                    decode::<Create>(&request.body)
                };
                match create {
                    Ok(create) => respond(match self.inner.create_agent(create.replicas).await {
                        Ok(agent) => Answer::Created(agent),
                        Err(error) => reply_answer(Err(error)),
                    }),
                    Err(answer) => respond(answer),
                }
            }
            ("POST", ["agents", id, "install"]) => {
                let Some(agent) = agent(id) else {
                    return respond(Answer::NoAgent);
                };
                // A package may be large: decode it off the leaders' thread.
                let body = request.body;
                let decoded = self.inner.offload(move || decode::<Install>(&body)).await;
                match decoded {
                    Some(Ok(install)) => {
                        let reply = self
                            .inner
                            .install(
                                agent,
                                install.instance,
                                install.program,
                                install.attestables,
                                install.roles,
                            )
                            .await;
                        respond(reply_answer(reply))
                    }
                    Some(Err(answer)) => respond(answer),
                    None => respond(Answer::Unavailable),
                }
            }
            ("POST", ["agents", id, "roles"]) => {
                match (agent(id), decode::<Grant>(&request.body)) {
                    (Some(agent), Ok(grant)) => {
                        let admin = Admin::SetRole {
                            principal: grant.principal,
                            role: grant.role,
                        };
                        respond(reply_answer(self.inner.admin(agent, admin).await))
                    }
                    (None, _) => respond(Answer::NoAgent),
                    (_, Err(answer)) => respond(answer),
                }
            }
            _ => Response::new(404, Vec::new()),
        }
    }

    /// Whether the request carries the operator's token.
    fn admitted(&self, request: &http::Request) -> bool {
        request
            .header("authorization")
            .and_then(|value| value.strip_prefix(b"Bearer "))
            .and_then(parse_hex)
            .is_some_and(|token| bool::from(token.ct_eq(&self.token)))
    }

    /// Agent `agent`'s creation record, when this node knows of it.
    fn record(&self, agent: AgentId) -> Option<vos_wire::peer::CreationRecord> {
        self.inner
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .cloned()
    }

    /// What the agent's applied state holds of `session`, with the reply
    /// it kept for `sequence` when that is at or below its mark.
    fn applied(&self, agent: AgentId, session: &Session, sequence: u64) -> Result<Applied, Answer> {
        let snapshot = self.inner.store.snapshot();
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
        })
    }

    async fn call(&self, agent: AgentId, call: Call) -> Answer {
        // A follower answers where the leader is, before anything else.
        let run = match self.inner.leading(agent).await {
            Ok(run) => run,
            Err(error) => return reply_answer(Err(error)),
        };
        let message = call_message(
            &run.shared.identity,
            &call.session,
            call.sequence,
            call.instance,
            call.method,
            &call.arguments,
        );
        if !verify(&call.session.key, &message, &call.signature) {
            return Answer::Rejected(Rejection::BadSignature);
        }
        let sequence = call.sequence;
        let lane_key = (agent, call.session);
        let next = {
            let mut lanes = self.lanes.lock().expect("the lanes");
            // Read under the lock: an answered request's commit is durable
            // before its lane changes, so the mark read here includes it.
            let Applied { mark, reply, time } = match self.applied(agent, &call.session, sequence) {
                Ok(applied) => applied,
                Err(answer) => return answer,
            };
            // A new session's time must be near the agent's, as refine will
            // check: the client learns the time it should use.
            if let Some(time) = time {
                let now = (self.inner.clock)().max(time);
                if call.session.t0.abs_diff(now) > defaults::SESSION_SKEW_MS {
                    return Answer::Rejected(Rejection::StaleSession { now });
                }
            }
            let lane = lanes.entry(lane_key).or_default();
            lane.queued = lane.queued.max(mark);
            if sequence == 0 {
                Next::Answer(Answer::Rejected(Rejection::Gap { expected: mark + 1 }))
            } else if sequence <= mark {
                Next::Answer(match reply {
                    Some(outcome) => Answer::Ran(outcome),
                    None => Answer::Rejected(Rejection::TooOld),
                })
            } else if sequence > mark + defaults::REPLY_WINDOW {
                Next::Answer(Answer::Rejected(Rejection::Ahead))
            } else if let Some(waiting) = lane.inflight.get_mut(&sequence) {
                // The original's answer is this one's too. When that is a
                // refusal (a gap behind a request that failed) the resend
                // may already have moved past it; nothing was consumed, and
                // the client's next resend goes through.
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
            }
        };
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
                let answer = reply_answer(self.inner.call(agent, request).await);
                let waiting = {
                    let mut lanes = self.lanes.lock().expect("the lanes");
                    let lane = lanes.entry(lane_key).or_default();
                    let waiting = lane.inflight.remove(&sequence).unwrap_or_default();
                    // Not consumed, the mark stays: the client resends it.
                    if !matches!(answer, Answer::Ran(_)) {
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

    async fn query(&self, agent: AgentId, query: QueryCall) -> Answer {
        let Some(run) = self.inner.run(agent) else {
            return reply_answer(Err(self.inner.absent(agent)));
        };
        let message = query_message(
            &run.shared.identity,
            &query.key,
            query.not_after,
            query.instance,
            query.method,
            &query.arguments,
        );
        if !verify(&query.key, &message, &query.signature) {
            return Answer::Rejected(Rejection::BadSignature);
        }
        let now = (self.inner.clock)();
        if query.not_after < now || query.not_after > now + QUERY_HORIZON_MS {
            return Answer::Rejected(Rejection::StaleQuery);
        }
        let outcome = self
            .inner
            .query(
                agent,
                Principal::Client(query.key),
                query.instance,
                query.method,
                query.arguments,
            )
            .await;
        match outcome {
            Ok(outcome) => Answer::Ran(outcome),
            Err(error) => reply_answer(Err(error)),
        }
    }

    /// An installed instance's schema, so clients call methods by name.
    fn schema(&self, agent: AgentId, instance: InstanceId) -> Response {
        let snapshot = self.inner.store.snapshot();
        let installed = snapshot
            .get(agent, &keys::installed(instance))
            .ok()
            .flatten()
            .and_then(|bytes| Installed::decode(unstored(&bytes)?).ok());
        match installed {
            Some((installed, _)) => Response::new(200, installed.schema.encode()),
            None => Response::new(404, Vec::new()),
        }
    }
}
