//! The node API (`docs/design/node-api.md`): one handler for every kind,
//! whichever transport brought it. Signed calls run in their sessions'
//! sequences (as `calls` says), signed queries and owners' reads of their
//! workflows are checked here, and operator kinds run the operator's
//! commands.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use vos_api::Kind;
use vos_wire::ids::{AgentId, InstanceId, Principal};
use vos_wire::ingress::{
    AgentInfo, QueryCall, Rejection, Response, WorkflowRead, workflow_read_horizon,
};
use vos_wire::records::{Installed, unstored};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode, keys};

use crate::node::Inner;
use crate::queries::Asked;
use crate::signature::verify;

mod operator;
pub(crate) mod quic;
pub(crate) mod socket;

pub(crate) use operator::{Nonces, listed};
pub use operator::{OPERATOR_KEY, OPERATOR_PUB};

/// How far ahead a query's `not_after` may be.
const QUERY_HORIZON_MS: u64 = 300_000;
/// Large bodies ([`vos_api::LARGE`], an install's) held at once, from the
/// socket and QUIC together: past them, the socket reads a large frame's
/// body only as one ends, and QUIC answers `Unavailable`.
const LARGE_BODIES: usize = 4;

/// The transport a request came by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Via {
    /// The unix socket: its file mode is the access.
    Socket,
    /// QUIC, from a key the node lists in `gateways`.
    Quic,
    /// The node's own HTTP, an operator's envelope in its header.
    Http,
    /// The node's own HTTP: an operator's bare body, once the node's
    /// bearer token admitted it.
    Token,
}

pub(crate) struct Api {
    pub(crate) inner: Arc<Inner>,
    /// Owners' reads of workflows waiting now.
    waiting: AtomicUsize,
    /// The operator keys the node lists.
    operators: HashSet<[u8; 32]>,
    /// The operators' commands' nonces, until their expiries.
    nonces: Nonces,
    /// Requests the API's transports brought, the node's HTTP's aside.
    pub(crate) frames: AtomicU64,
    /// The large bodies' places: installs', and credentialed calls'.
    pub(crate) large: Arc<smol::lock::Semaphore>,
    pub(crate) credentialed: Arc<smol::lock::Semaphore>,
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

/// Credentialed calls' bodies past a call's limit held at once, from the
/// socket and QUIC together, apart from the installs' large bodies. A
/// credentialed call gives its place back once its proof is verified, so
/// they bound proofs held and verified, not calls waiting to apply.
const CREDENTIALED_BODIES: usize = vos_http::CREDENTIALED_LARGE;

/// A large body's place among those its kind's pool holds, given back when
/// dropped: by the transport once the answer is out, or by a credentialed
/// call once its proof is verified.
pub(crate) type LargePlace = Box<dyn Send>;

/// Which large bodies' pool a request of `kind` with a body of `body`
/// bytes takes a place in, if any: an install's past
/// [`vos_api::LARGE`], a credentialed call's past a call's limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Large {
    Install,
    Credentialed,
}

fn large(kind: Kind, body: u32) -> Option<Large> {
    match kind {
        Kind::Install if body > vos_api::LARGE => Some(Large::Install),
        Kind::Credentialed if body > Kind::Call.limit() => Some(Large::Credentialed),
        _ => None,
    }
}

impl Api {
    /// The places the frame `reader` has part read takes one of, if its
    /// body is large.
    fn large_places(
        &self,
        reader: &vos_api::Reader,
        framing: vos_api::Framing,
    ) -> Option<&Arc<smol::lock::Semaphore>> {
        let header = reader.header()?;
        let body = header.body(framing)?;
        match large(Kind::from_u16(header.kind)?, body)? {
            Large::Install => Some(&self.large),
            Large::Credentialed => Some(&self.credentialed),
        }
    }

    /// The credentialed calls' places free now.
    pub(crate) fn credentialed_free(&self) -> usize {
        std::iter::from_fn(|| self.credentialed.try_acquire())
            .collect::<Vec<_>>()
            .len()
    }
}

fn decode<T: Decode>(body: &[u8]) -> Result<T, Response> {
    T::decode_exact(body).ok_or(Response::Rejected(Rejection::Malformed))
}

impl Api {
    pub(crate) fn new(inner: Arc<Inner>, operators: HashSet<[u8; 32]>, nonces: Nonces) -> Self {
        Self {
            inner,
            waiting: AtomicUsize::new(0),
            operators,
            nonces,
            frames: AtomicU64::new(0),
            large: Arc::new(smol::lock::Semaphore::new(LARGE_BODIES)),
            credentialed: Arc::new(smol::lock::Semaphore::new(CREDENTIALED_BODIES)),
        }
    }

    /// The answer to a request of `kind` holding `body`, which came `via`
    /// a transport holding `large`, its body's place if it is large, in
    /// SCALE.
    pub(crate) async fn handle(
        &self,
        kind: Kind,
        body: Vec<u8>,
        via: Via,
        large: Option<LargePlace>,
    ) -> Vec<u8> {
        if matches!(via, Via::Socket | Via::Quic) {
            self.frames.fetch_add(1, Ordering::Relaxed);
        }
        match kind {
            Kind::NodeKey => self.inner.node_id.encode(),
            Kind::Time => (self.inner.clock)().encode(),
            Kind::AgentInfo => AgentId::decode_exact(&body)
                .and_then(|agent| self.agent_info(agent))
                .encode(),
            Kind::Schema => <(AgentId, InstanceId)>::decode_exact(&body)
                .and_then(|(agent, instance)| self.schema(agent, instance))
                .encode(),
            _ => self.respond(kind, body, via, large).await.encode(),
        }
    }

    /// The answer to a kind answering a [`Response`].
    async fn respond(
        &self,
        kind: Kind,
        body: Vec<u8>,
        via: Via,
        large: Option<LargePlace>,
    ) -> Response {
        if kind.operator() {
            return match via {
                Via::Token => match operator::parse(&self.inner, kind, body).await {
                    Ok(command) => operator::run(&self.inner, command).await,
                    Err(answer) => answer,
                },
                Via::Socket | Via::Quic | Via::Http => self.operated(kind, body).await,
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
            // The body goes once decoded; the proof and the place go once
            // the proof is verified.
            Kind::Credentialed => match decode(&body) {
                Ok((agent, call)) => {
                    drop(body);
                    self.inner.credentialed(agent, call, large).await
                }
                Err(answer) => answer,
            },
            _ => Response::Rejected(Rejection::Malformed),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// An install takes an install's place past [`vos_api::LARGE`], a
    /// credentialed call a credentialed call's past a call's limit, and no
    /// other kind takes one at any size.
    #[test]
    fn large_bodies_take_their_kinds_places() {
        let call = Kind::Call.limit();
        assert_eq!(large(Kind::Install, vos_api::LARGE), None);
        assert_eq!(
            large(Kind::Install, vos_api::LARGE + 1),
            Some(Large::Install)
        );
        assert_eq!(large(Kind::Credentialed, call), None);
        assert_eq!(
            large(Kind::Credentialed, call + 1),
            Some(Large::Credentialed)
        );
        assert_eq!(
            large(Kind::Credentialed, Kind::Credentialed.limit()),
            Some(Large::Credentialed)
        );
        for kind in [Kind::Call, Kind::Query, Kind::Workflow, Kind::Grant] {
            assert_eq!(large(kind, kind.limit()), None, "{kind:?}");
            assert_eq!(large(kind, u32::MAX), None, "{kind:?}");
        }
    }
}
