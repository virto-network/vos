//! The node API (`docs/design/node-api.md`): one handler for every kind,
//! whichever transport brought it. Signed calls run in their sessions'
//! sequences (as `calls` says), signed queries and owners' reads of their
//! workflows are checked here, and operator kinds run the operator's
//! commands.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use vos_api::Kind;
use vos_wire::batch::Admin;
use vos_wire::ids::{AgentId, InstanceId, Principal};
use vos_wire::ingress::{
    AgentInfo, Create, Grant, Install, QueryCall, Rejection, Replace, Response, WorkflowRead,
    workflow_read_horizon,
};
use vos_wire::records::{Installed, unstored};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode, keys};

use crate::calls::answer_of;
use crate::node::{Inner, ReplaceError};
use crate::queries::Asked;
use crate::signature::verify;

pub(crate) mod socket;

/// How far ahead a query's `not_after` may be.
const QUERY_HORIZON_MS: u64 = 300_000;

/// The transport a request came by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Via {
    /// The unix socket: its file mode is the access.
    Socket,
    /// The node's own HTTP: an operator's bare body, once the node's
    /// bearer token admitted it.
    Http,
}

pub(crate) struct Api {
    pub(crate) inner: Arc<Inner>,
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

fn decode<T: Decode>(body: &[u8]) -> Result<T, Response> {
    T::decode_exact(body).ok_or(Response::Rejected(Rejection::Malformed))
}

/// A `Create` from an operator's body: an empty one is the default.
fn create(body: &[u8]) -> Result<Create, Response> {
    if body.is_empty() {
        Ok(Create::default())
    } else {
        decode(body)
    }
}

impl Api {
    pub(crate) fn new(inner: Arc<Inner>) -> Self {
        Self {
            inner,
            waiting: AtomicUsize::new(0),
        }
    }

    /// The answer to a request of `kind` holding `body`, which came `via`
    /// a transport, in SCALE.
    pub(crate) async fn handle(&self, kind: Kind, body: Vec<u8>, via: Via) -> Vec<u8> {
        match kind {
            Kind::NodeKey => self.inner.node_id.encode(),
            Kind::Time => (self.inner.clock)().encode(),
            Kind::AgentInfo => AgentId::decode_exact(&body)
                .and_then(|agent| self.agent_info(agent))
                .encode(),
            Kind::Schema => <(AgentId, InstanceId)>::decode_exact(&body)
                .and_then(|(agent, instance)| self.schema(agent, instance))
                .encode(),
            _ => self.respond(kind, body, via).await.encode(),
        }
    }

    /// The answer to a kind answering a [`Response`].
    async fn respond(&self, kind: Kind, body: Vec<u8>, via: Via) -> Response {
        if kind.operator() {
            return match via {
                Via::Socket | Via::Http => self.operate(kind, body).await,
            };
        }
        match kind {
            Kind::Call => match decode(&body) {
                Ok((agent, call)) => self.inner.client_call(agent, call).await,
                Err(answer) => answer,
            },
            Kind::Query => match decode(&body) {
                Ok((agent, query)) => self.query(agent, query).await,
                Err(answer) => answer,
            },
            Kind::Workflow => match decode(&body) {
                Ok((agent, read)) => self.workflow(agent, read).await,
                Err(answer) => answer,
            },
            _ => Response::Rejected(Rejection::Malformed),
        }
    }

    /// An operator's command, its body bare: its authority checked by the
    /// transport.
    async fn operate(&self, kind: Kind, body: Vec<u8>) -> Response {
        let inner = &self.inner;
        let answer = match kind {
            Kind::Stats => decode::<()>(&body).map(|()| Response::Stats(inner.stats())),
            Kind::Status => decode(&body).map(|agent| inner.replica_status(agent)),
            Kind::CreateAgent => match create(&body) {
                Ok(create) => Ok(match inner.create_agent(create.replicas).await {
                    Ok(agent) => Response::Created(agent),
                    Err(error) => error.into(),
                }),
                Err(answer) => Err(answer),
            },
            Kind::CreateRepresentative => match create(&body) {
                Ok(create) => Ok(match inner.create_representative(create.replicas).await {
                    Ok(agent) => Response::Created(agent),
                    Err(error) => error.into(),
                }),
                Err(answer) => Err(answer),
            },
            Kind::Install => {
                // A package may be large: decode it off the leaders' thread.
                let decoded = inner
                    .offload(move || decode::<(AgentId, Install)>(&body))
                    .await;
                match decoded {
                    Some(Ok((agent, install))) => {
                        let reply = inner
                            .install(agent, install.instance, install.elf, install.roles)
                            .await;
                        Ok(answer_of(reply))
                    }
                    Some(Err(answer)) => Err(answer),
                    None => Ok(Response::Unavailable),
                }
            }
            Kind::Replace => match decode(&body) {
                Ok((agent, Replace { remove, add })) => {
                    Ok(match inner.replace(agent, remove, add).await {
                        Ok(replicas) => Response::Placed(replicas),
                        Err(ReplaceError::Unplaced(why)) => Response::Unplaced(why),
                        Err(ReplaceError::TimedOut) => Response::TimedOut,
                        Err(ReplaceError::Call(error)) => error.into(),
                    })
                }
                Err(answer) => Err(answer),
            },
            Kind::Grant => match decode::<(AgentId, Grant)>(&body) {
                Ok((agent, grant)) => {
                    Ok(answer_of(inner.admin(agent, Admin::SetRole(grant)).await))
                }
                Err(answer) => Err(answer),
            },
            Kind::Reports => match decode::<(AgentId, bool)>(&body) {
                Ok((agent, every)) => Ok(answer_of(
                    inner.admin(agent, Admin::ReportEveryWindow(every)).await,
                )),
                Err(answer) => Err(answer),
            },
            _ => Err(Response::Rejected(Rejection::Malformed)),
        };
        answer.unwrap_or_else(|answer| answer)
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
        let run = match self.inner.present(agent) {
            Ok(run) => run,
            Err(error) => return error.into(),
        };
        let message = query.message(&run.shared.identity);
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
        let asked = Asked {
            caller: Principal::Client(query.key),
            instance: query.instance,
            method: query.method,
            arguments: query.arguments,
        };
        self.inner
            .client_query(agent, asked, query.consistency)
            .await
    }

    /// An owner's read of a workflow's status, waiting for it to end, as
    /// long as it asks and the node allows, and only while fewer reads than
    /// the node allows wait: past them, it answers at once.
    async fn workflow(&self, agent: AgentId, read: WorkflowRead) -> Response {
        let run = match self.inner.present(agent) {
            Ok(run) => run,
            Err(error) => return error.into(),
        };
        let message = read.message(&run.shared.identity);
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
    fn schema(&self, agent: AgentId, instance: InstanceId) -> Option<Schema> {
        let snapshot = self.inner.store.snapshot();
        let installed = snapshot
            .get(agent, &keys::installed(instance))
            .ok()
            .flatten()
            .and_then(|bytes| Installed::decode(unstored(&bytes)?).ok());
        installed.map(|(installed, _)| installed.schema)
    }
}
