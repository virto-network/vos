//! The node's HTTP ingress: client sessions, signed calls and queries in
//! their sequences, and the operator's commands.
//!
//! Per (session, agent), a call at or below the agent's applied mark is a
//! duplicate answered from its reply window; one in flight waits for that
//! answer; the next after those queued is queued; any other is refused.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use ed25519_dalek::{Signature, VerifyingKey};
use smol::net::TcpListener;
use subtle::ConstantTimeEq;
use vos_wire::abi::{cap, refusal};
use vos_wire::batch::{Admin, Request};
use vos_wire::ids::{AgentId, InstanceId, Principal, SessionId};
use vos_wire::ingress::{
    Answer, Call, Grant, Install, Open, Opened, QueryCall, Rejection, call_message, open_message,
    query_message,
};
use vos_wire::records::{Installed, SessionMark, unstored};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, defaults, keys};

use crate::http::{self, Handler, Limits, Response};
use crate::node::{CallError, Inner, Reply};
use crate::storage::Change;
use crate::store::{Store, View};

/// The most sessions one key holds: opening another forgets its oldest.
pub const SESSIONS_PER_KEY: usize = 16;
/// How far an open's time may be from the node's clock.
const OPEN_SKEW_MS: u64 = 60_000;
/// How far ahead a query's `not_after` may be.
const QUERY_HORIZON_MS: u64 = 300_000;
/// The most a body may hold beyond a request's cap: its envelope.
const ENVELOPE: usize = 4096;
/// The most an install's body may hold: a package's programs.
const MAX_INSTALL: usize = 64 << 20;

struct Opening {
    next: u64,
    per_key: HashMap<[u8; 32], BTreeSet<SessionId>>,
    opened: HashMap<[u8; 32], u64>,
}

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
    sessions: RwLock<HashMap<SessionId, [u8; 32]>>,
    opening: smol::lock::Mutex<Opening>,
    lanes: Mutex<HashMap<(AgentId, SessionId), Lane>>,
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
        Err(CallError::Failed(_)) => Answer::Unavailable,
        Err(CallError::Busy) => Answer::Busy,
        Err(CallError::NoAgent) => Answer::NoAgent,
        Err(CallError::Stopped) => Answer::Stopped,
    }
}

fn status(answer: &Answer) -> u16 {
    match answer {
        Answer::Ran(_) | Answer::Created(_) => 200,
        // Like an unknown session, an expired one means opening another.
        Answer::Refused(refusal::EXPIRED) => 410,
        Answer::Refused(_) => 409,
        Answer::Rejected(rejection) => match rejection {
            Rejection::UnknownSession | Rejection::TooOld => 410,
            Rejection::BadSignature | Rejection::Unauthorized => 401,
            Rejection::Gap { .. } | Rejection::Ahead => 409,
            Rejection::StaleQuery | Rejection::StaleOpen | Rejection::Malformed => 400,
        },
        Answer::NotConsumed => 500,
        Answer::NoAgent => 404,
        Answer::Busy | Answer::Stopped | Answer::Unavailable => 503,
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
    pub(crate) fn open(inner: Arc<Inner>, token: [u8; 32]) -> Result<Self, fjall::Error> {
        let mut sessions = HashMap::new();
        let mut per_key: HashMap<[u8; 32], BTreeSet<SessionId>> = HashMap::new();
        for (session, key) in inner.store.sessions()? {
            sessions.insert(session, key);
            per_key.entry(key).or_default().insert(session);
        }
        let next = inner.store.next_session()?;
        Ok(Self {
            inner,
            token,
            sessions: RwLock::new(sessions),
            opening: smol::lock::Mutex::new(Opening {
                next,
                per_key,
                opened: HashMap::new(),
            }),
            lanes: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) async fn serve(self, listener: TcpListener) {
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
        http::serve(listener, handler, limits, move |connection| {
            runtime.spawn(connection).detach();
        })
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
            ("POST", ["sessions"]) => match decode::<Open>(&request.body) {
                Ok(open) => match self.open_session(open).await {
                    Ok(opened) => Response::new(200, opened.encode()),
                    Err(answer) => respond(answer),
                },
                Err(answer) => respond(answer),
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
            ("POST", ["agents"]) => respond(match self.inner.create_agent().await {
                Ok(agent) => Answer::Created(agent),
                Err(error) => reply_answer(Err(error)),
            }),
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

    async fn open_session(&self, open: Open) -> Result<Opened, Answer> {
        let node = self.inner.node_id;
        let now = (self.inner.clock)();
        if open.time.abs_diff(now) > OPEN_SKEW_MS {
            return Err(Answer::Rejected(Rejection::StaleOpen));
        }
        if !verify(
            &open.key,
            &open_message(&node, &open.key, open.time),
            &open.signature,
        ) {
            return Err(Answer::Rejected(Rejection::BadSignature));
        }
        let mut opening = self.opening.lock().await;
        let last = match opening.opened.get(&open.key) {
            Some(last) => Some(*last),
            None => self
                .inner
                .store
                .key_opened(&open.key)
                .map_err(|_| Answer::Unavailable)?,
        };
        if last.is_some_and(|last| open.time <= last) {
            return Err(Answer::Rejected(Rejection::StaleOpen));
        }
        let session = SessionId(opening.next);
        let held = opening.per_key.entry(open.key).or_default();
        let forgotten: Vec<SessionId> = held
            .iter()
            .copied()
            .take((held.len() + 1).saturating_sub(SESSIONS_PER_KEY))
            .collect();
        let mut changes = vec![Change::Session {
            id: session,
            key: open.key,
            time: open.time,
        }];
        changes.extend(forgotten.iter().map(|old| Change::ForgetSession(*old)));
        self.inner
            .commit(changes)
            .await
            .map_err(|_| Answer::Unavailable)?;
        opening.next += 1;
        opening.opened.insert(open.key, open.time);
        let held = opening.per_key.entry(open.key).or_default();
        held.insert(session);
        let mut sessions = self.sessions.write().expect("the sessions");
        for old in forgotten {
            held.remove(&old);
            sessions.remove(&old);
        }
        sessions.insert(session, open.key);
        Ok(Opened { node, session })
    }

    fn key(&self, session: SessionId) -> Option<[u8; 32]> {
        self.sessions
            .read()
            .expect("the sessions")
            .get(&session)
            .copied()
    }

    /// The agent's applied mark for `session`, and the reply it kept for
    /// `sequence` when that is at or below it.
    fn applied(
        &self,
        agent: AgentId,
        session: SessionId,
        sequence: u64,
    ) -> Result<(u64, Option<Outcome>), Answer> {
        let snapshot = self.inner.store.snapshot();
        let stored = |key: &[u8]| -> Result<Option<Vec<u8>>, Answer> {
            let bytes = snapshot.get(agent, key).map_err(|_| Answer::Unavailable)?;
            Ok(bytes.and_then(|bytes| unstored(&bytes).map(<[u8]>::to_vec)))
        };
        let mark = stored(&keys::session(session))?
            .and_then(|bytes| SessionMark::decode(&bytes).ok())
            .map_or(0, |(mark, _)| mark.sequence);
        let reply = if sequence <= mark {
            stored(&keys::reply(session, sequence))?
                .and_then(|bytes| Outcome::decode(&bytes).ok())
                .map(|(outcome, _)| outcome)
        } else {
            None
        };
        Ok((mark, reply))
    }

    async fn call(&self, agent: AgentId, call: Call) -> Answer {
        let Some(key) = self.key(call.session) else {
            return Answer::Rejected(Rejection::UnknownSession);
        };
        let message = call_message(
            &self.inner.node_id,
            agent,
            call.session,
            call.sequence,
            call.instance,
            call.method,
            &call.arguments,
        );
        if !verify(&key, &message, &call.signature) {
            return Answer::Rejected(Rejection::BadSignature);
        }
        let sequence = call.sequence;
        let lane_key = (agent, call.session);
        let next = {
            let mut lanes = self.lanes.lock().expect("the lanes");
            // Read under the lock: an answered request's commit is durable
            // before its lane changes, so the mark read here includes it.
            let (mark, reply) = match self.applied(agent, call.session, sequence) {
                Ok(applied) => applied,
                Err(answer) => return answer,
            };
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
                    caller: Principal::Client(key),
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
        let Some(key) = self.key(query.session) else {
            return Answer::Rejected(Rejection::UnknownSession);
        };
        let message = query_message(
            &self.inner.node_id,
            agent,
            query.session,
            query.not_after,
            query.instance,
            query.method,
            &query.arguments,
        );
        if !verify(&key, &message, &query.signature) {
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
                Principal::Client(key),
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
