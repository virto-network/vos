//! The node's HTTP ingress: signed calls in their sessions' sequences
//! (run as `calls` says), signed queries, and the operator's commands.

use std::sync::Arc;
use std::time::Duration;

use smol::net::TcpListener;
use subtle::ConstantTimeEq;
use vos_wire::abi::{cap, refusal};
use vos_wire::batch::Admin;
use vos_wire::ids::{AgentId, InstanceId, Principal};
use vos_wire::ingress::{
    AgentInfo, Answer, Call, Create, Grant, Install, QueryCall, Rejection, query_message,
};
use vos_wire::records::{Installed, unstored};
use vos_wire::{Decode, Encode, keys};

use crate::calls::{answer_of, verify};
use crate::http::{self, Handler, Limits, Response};
use crate::node::Inner;
use crate::store::{Store, View};

/// How far ahead a query's `not_after` may be.
const QUERY_HORIZON_MS: u64 = 300_000;
/// The most a body may hold beyond a request's cap: its envelope.
const ENVELOPE: usize = 4096;
/// The most an install's body may hold: a package's programs.
const MAX_INSTALL: usize = 64 << 20;

pub(crate) struct Ingress {
    inner: Arc<Inner>,
    token: [u8; 32],
}

fn status(answer: &Answer) -> u16 {
    match answer {
        Answer::Ran { .. } | Answer::Created(_) => 200,
        Answer::Unconfirmed(_) => 202,
        // The session is done with: the client starts another.
        Answer::Refused(refusal::EXPIRED | refusal::STALE_SESSION) => 410,
        Answer::Refused(_) => 409,
        Answer::Rejected(rejection) => match rejection {
            Rejection::TooOld | Rejection::StaleSession { .. } => 410,
            Rejection::BadSignature | Rejection::Unauthorized => 401,
            Rejection::Gap { .. } | Rejection::Ahead => 409,
            Rejection::StaleQuery | Rejection::Malformed => 400,
            // Another replica may be further along.
            Rejection::Behind => 503,
        },
        Answer::NotConsumed => 500,
        Answer::NoAgent => 404,
        Answer::Busy | Answer::Stopped | Answer::Unavailable => 503,
        Answer::TimedOut => 504,
        // Another node serves it: the answer says which.
        Answer::NotLeader { .. } | Answer::Elsewhere { .. } => 421,
    }
}

fn respond(answer: Answer) -> Response {
    Response::new(status(&answer), answer.encode())
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
        Self { inner, token }
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
            ("GET", ["agents", id]) => match agent(id).and_then(|agent| self.agent_info(agent)) {
                Some(info) => Response::new(200, info.encode()),
                None => Response::new(404, Vec::new()),
            },
            ("POST", ["agents", id, "calls"]) => match (agent(id), decode::<Call>(&request.body)) {
                (Some(agent), Ok(call)) => respond(self.inner.client_call(agent, call).await),
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
                        Err(error) => answer_of(Err(error)),
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
                        respond(answer_of(reply))
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
                        respond(answer_of(self.inner.admin(agent, admin).await))
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

    /// Agent `agent`'s creation record and replicas, when this node knows
    /// of it.
    fn agent_info(&self, agent: AgentId) -> Option<AgentInfo> {
        let record = self
            .inner
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .cloned()?;
        let replicas = record
            .replicas
            .iter()
            .filter_map(|replica| self.inner.contact(*replica))
            .collect();
        Some(AgentInfo { record, replicas })
    }

    async fn query(&self, agent: AgentId, query: QueryCall) -> Answer {
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
        let (key, signature) = (query.key, query.signature);
        let signed = self
            .inner
            .offload(move || verify(&key, &message, &signature))
            .await;
        match signed {
            Some(true) => {}
            Some(false) => return Answer::Rejected(Rejection::BadSignature),
            None => return Answer::Unavailable,
        }
        let now = (self.inner.clock)();
        if query.not_after < now || query.not_after > now + QUERY_HORIZON_MS {
            return Answer::Rejected(Rejection::StaleQuery);
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
