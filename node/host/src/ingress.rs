//! The node's HTTP ingress: signed calls in their sessions' sequences
//! (run as `calls` says), signed queries, owners' reads of their
//! workflows, and the operator's commands.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use smol::net::TcpListener;
use subtle::ConstantTimeEq;
use vos_wire::abi::{Refusal, cap};
use vos_wire::batch::Admin;
use vos_wire::ids::{AgentId, InstanceId, Principal};
use vos_wire::ingress::{
    AgentInfo, Call, Create, Grant, Install, QueryCall, Rejection, Replace, Response, WorkflowRead,
    query_message, workflow_message, workflow_read_horizon,
};
use vos_wire::records::{Installed, unstored};
use vos_wire::{Decode, Encode, keys};

use crate::calls::answer_of;
use crate::http::{self, Handler, Limits};
use crate::node::{Inner, ReplaceError};
use crate::signature::verify;

/// How far ahead a query's `not_after` may be.
const QUERY_HORIZON_MS: u64 = 300_000;
/// The most a body may hold beyond a request's cap: its envelope.
const ENVELOPE: usize = 4096;
/// The most an install's body may hold: a package's ELF, at the most a
/// derivation reads, and its envelope.
const MAX_INSTALL: usize = vos_pvm_compiler::MAX_ELF + ENVELOPE;

pub(crate) struct Ingress {
    inner: Arc<Inner>,
    token: [u8; 32],
    /// Owners' reads of workflows waiting now.
    waiting: AtomicUsize,
}

/// A read's place among those waiting, given back when it ends, however it
/// ends: a client that hangs up mid-wait goes unnoticed, so its read holds
/// its place until its wait ends.
struct Waiting<'a>(&'a AtomicUsize);

impl<'a> Waiting<'a> {
    /// A place among `waiting`, if fewer than `most` hold one.
    fn take(waiting: &'a AtomicUsize, most: usize) -> Option<Self> {
        waiting
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                (held < most).then_some(held + 1)
            })
            .ok()
            .map(|_| Waiting(waiting))
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn status(answer: &Response) -> u16 {
    match answer {
        Response::Ran { .. }
        | Response::Created(_)
        | Response::Placed(_)
        | Response::Status(_)
        | Response::Stats(_)
        | Response::Workflow { .. } => 200,
        Response::Unplaced(_) => 409,
        Response::Unconfirmed(_) => 202,
        // The session is done with: the client starts another.
        Response::Refused(Refusal::Expired | Refusal::StaleSession) => 410,
        // No new session until some are collected.
        Response::Refused(Refusal::SessionsFull) => 503,
        Response::Refused(Refusal::KeySessionsFull) => 429,
        Response::Refused(_) => 409,
        Response::Rejected(rejection) => match rejection {
            Rejection::TooOld | Rejection::StaleSession { .. } => 410,
            Rejection::BadSignature | Rejection::Unauthorized => 401,
            Rejection::Gap { .. } | Rejection::Ahead => 409,
            Rejection::StaleQuery { .. } | Rejection::Malformed => 400,
            // Another replica may be further along.
            Rejection::Behind => 503,
        },
        Response::NotConsumed => 500,
        Response::NoAgent => 404,
        Response::Busy | Response::Stopped | Response::Unavailable => 503,
        Response::TimedOut => 504,
        // Another node serves it: the answer says which.
        Response::NotLeader { .. } | Response::Elsewhere { .. } => 421,
    }
}

fn respond(answer: Response) -> http::Response {
    http::Response::new(status(&answer), answer.encode())
}

fn decode<T: Decode>(body: &[u8]) -> Result<T, Response> {
    match T::decode(body) {
        Ok((value, used)) if used == body.len() => Ok(value),
        _ => Err(Response::Rejected(Rejection::Malformed)),
    }
}

impl Ingress {
    pub(crate) fn new(inner: Arc<Inner>, token: [u8; 32]) -> Self {
        Self {
            inner,
            token,
            waiting: AtomicUsize::new(0),
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
            body: cap::REQUEST + ENVELOPE,
            install: MAX_INSTALL,
            idle: Duration::from_secs(30),
            connections: this.inner.settings.ingress_connections,
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

    async fn handle(&self, request: http::Request) -> http::Response {
        let path = request
            .path
            .split('?')
            .next()
            .unwrap_or_default()
            .to_string();
        let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        let agent = |text: &str| text.parse::<u32>().ok().map(AgentId);
        match (request.method.as_str(), segments.as_slice()) {
            ("GET", []) => http::Response::new(200, self.inner.node_id.encode()),
            ("GET", ["agents", id]) => match agent(id).and_then(|agent| self.agent_info(agent)) {
                Some(info) => http::Response::new(200, info.encode()),
                None => http::Response::new(404, Vec::new()),
            },
            ("POST", ["agents", id, "calls"]) => match (agent(id), decode::<Call>(&request.body)) {
                (Some(agent), Ok(call)) => respond(self.inner.client_call(agent, call).await),
                (None, _) => respond(Response::NoAgent),
                (_, Err(answer)) => respond(answer),
            },
            ("POST", ["agents", id, "queries"]) => {
                match (agent(id), decode::<QueryCall>(&request.body)) {
                    (Some(agent), Ok(query)) => respond(self.query(agent, query).await),
                    (None, _) => respond(Response::NoAgent),
                    (_, Err(answer)) => respond(answer),
                }
            }
            ("POST", ["agents", id, "workflows"]) => {
                match (agent(id), decode::<WorkflowRead>(&request.body)) {
                    (Some(agent), Ok(read)) => respond(self.workflow(agent, read).await),
                    (None, _) => respond(Response::NoAgent),
                    (_, Err(answer)) => respond(answer),
                }
            }
            ("GET", ["agents", id, "instances", instance, "schema"]) => {
                match (agent(id), instance.parse::<u32>()) {
                    (Some(agent), Ok(instance)) => self.schema(agent, InstanceId(instance)),
                    _ => http::Response::new(404, Vec::new()),
                }
            }
            ("POST", ["agents"] | ["agents", _, "install" | "roles" | "replicas"])
            | ("GET", ["agents", _, "status"] | ["stats"])
                if !self.admitted(&request) =>
            {
                respond(Response::Rejected(Rejection::Unauthorized))
            }
            ("GET", ["stats"]) => respond(Response::Stats(self.inner.stats())),
            ("GET", ["agents", id, "status"]) => respond(match agent(id) {
                Some(agent) => self.inner.replica_status(agent),
                None => Response::NoAgent,
            }),
            ("POST", ["agents"]) => {
                let create = if request.body.is_empty() {
                    Ok(Create::default())
                } else {
                    decode::<Create>(&request.body)
                };
                match create {
                    Ok(create) => respond(match self.inner.create_agent(create.replicas).await {
                        Ok(agent) => Response::Created(agent),
                        Err(error) => answer_of(Err(error)),
                    }),
                    Err(answer) => respond(answer),
                }
            }
            ("POST", ["agents", id, "install"]) => {
                let Some(agent) = agent(id) else {
                    return respond(Response::NoAgent);
                };
                // A package may be large: decode it off the leaders' thread.
                let body = request.body;
                let decoded = self.inner.offload(move || decode::<Install>(&body)).await;
                match decoded {
                    Some(Ok(install)) => {
                        let reply = self
                            .inner
                            .install(agent, install.instance, install.elf, install.roles)
                            .await;
                        respond(answer_of(reply))
                    }
                    Some(Err(answer)) => respond(answer),
                    None => respond(Response::Unavailable),
                }
            }
            ("POST", ["agents", id, "replicas"]) => {
                match (agent(id), decode::<Replace>(&request.body)) {
                    (Some(agent), Ok(replace)) => {
                        let replaced = self.inner.replace(agent, replace.remove, replace.add).await;
                        respond(match replaced {
                            Ok(replicas) => Response::Placed(replicas),
                            Err(ReplaceError::Unplaced(why)) => Response::Unplaced(why),
                            Err(ReplaceError::TimedOut) => Response::TimedOut,
                            Err(ReplaceError::Call(error)) => answer_of(Err(error)),
                        })
                    }
                    (None, _) => respond(Response::NoAgent),
                    (_, Err(answer)) => respond(answer),
                }
            }
            ("POST", ["agents", id, "roles"]) => {
                match (agent(id), decode::<Grant>(&request.body)) {
                    (Some(agent), Ok(grant)) => {
                        let admin = Admin::SetRole(grant);
                        respond(answer_of(self.inner.admin(agent, admin).await))
                    }
                    (None, _) => respond(Response::NoAgent),
                    (_, Err(answer)) => respond(answer),
                }
            }
            _ => http::Response::new(404, Vec::new()),
        }
    }

    /// Whether the request carries the operator's token.
    fn admitted(&self, request: &http::Request) -> bool {
        request
            .header("authorization")
            .and_then(|value| value.strip_prefix(b"Bearer "))
            .and_then(|token| std::str::from_utf8(token).ok())
            .and_then(|token| crate::hex32(token.trim()))
            .is_some_and(|token| bool::from(token.ct_eq(&self.token)))
    }

    /// Agent `agent`'s creation record and replicas, when this node knows
    /// of it.
    fn agent_info(&self, agent: AgentId) -> Option<AgentInfo> {
        let known = self.inner.directory.get(agent)?;
        let replicas = known
            .placement
            .replicas
            .iter()
            .filter_map(|replica| self.inner.contact(*replica))
            .collect();
        Some(AgentInfo {
            record: known.record.clone(),
            replicas,
        })
    }

    async fn query(&self, agent: AgentId, query: QueryCall) -> Response {
        let Some(run) = self.inner.run(agent) else {
            return answer_of(Err(self.inner.absent(agent)));
        };
        let message = query_message(
            &run.shared.identity,
            &query.key,
            query.not_after,
            query.consistency,
            query.instance,
            query.method,
            &query.arguments,
        );
        if let Err(answer) = self
            .signed(
                query.key,
                message,
                query.signature,
                query.not_after,
                QUERY_HORIZON_MS,
            )
            .await
        {
            return answer;
        }
        self.inner
            .client_query(
                agent,
                Principal::Client(query.key),
                query.instance,
                query.method,
                query.arguments,
                query.consistency,
            )
            .await
    }

    /// An owner's read of a workflow's status, waiting for it to end, as
    /// long as it asks and the node allows, and only while fewer reads than
    /// the node allows wait: past them, it answers at once.
    async fn workflow(&self, agent: AgentId, read: WorkflowRead) -> Response {
        let Some(run) = self.inner.run(agent) else {
            return answer_of(Err(self.inner.absent(agent)));
        };
        let message = workflow_message(
            &run.shared.identity,
            &read.key,
            read.not_after,
            read.consistency,
            read.workflow,
            read.wait_ms,
        );
        let horizon = workflow_read_horizon(read.wait_ms);
        if let Err(answer) = self
            .signed(read.key, message, read.signature, read.not_after, horizon)
            .await
        {
            return answer;
        }
        let settings = &self.inner.settings;
        let place = (read.wait_ms > 0)
            .then(|| Waiting::take(&self.waiting, settings.workflow_waits))
            .flatten();
        let wait = match place {
            Some(_) => Duration::from_millis(read.wait_ms).min(settings.workflow_wait),
            None => Duration::ZERO,
        };
        let answer = self
            .inner
            .client_workflow(agent, read.key, read.workflow, read.consistency, wait)
            .await;
        drop(place);
        answer
    }

    /// That `key` signed `message`, good until `not_after`, at most
    /// `horizon` ms past the node's time: checked off the leaders' thread,
    /// then against the node's clock.
    async fn signed(
        &self,
        key: [u8; 32],
        message: Vec<u8>,
        signature: [u8; 64],
        not_after: u64,
        horizon: u64,
    ) -> Result<(), Response> {
        let signed = self
            .inner
            .offload({
                let stats = Arc::clone(&self.inner.stats);
                move || {
                    let started = Instant::now();
                    let signed = verify(&key, &message, &signature);
                    stats.verify.took(started.elapsed());
                    signed
                }
            })
            .await;
        match signed {
            Some(true) => {}
            Some(false) => return Err(Response::Rejected(Rejection::BadSignature)),
            None => return Err(Response::Unavailable),
        }
        let now = (self.inner.clock)();
        if not_after < now || not_after > now.saturating_add(horizon) {
            return Err(Response::Rejected(Rejection::StaleQuery { now }));
        }
        Ok(())
    }

    /// An installed instance's schema, so clients call methods by name.
    fn schema(&self, agent: AgentId, instance: InstanceId) -> http::Response {
        let snapshot = self.inner.store.snapshot();
        let installed = snapshot
            .get(agent, &keys::installed(instance))
            .ok()
            .flatten()
            .and_then(|bytes| Installed::decode(unstored(&bytes)?).ok());
        match installed {
            Some((installed, _)) => http::Response::new(200, installed.schema.encode()),
            None => http::Response::new(404, Vec::new()),
        }
    }
}
