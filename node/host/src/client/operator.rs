//! The node's operator: commands signed by an operator key for one node,
//! or, over the node's own HTTP, its admin token.

use std::sync::Mutex;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_http::routes::{self, Routed, operated_header};
use vos_wire::Encode;
use vos_wire::ids::{AgentId, Principal};
use vos_wire::ingress::{
    Create, Grant, Install, NodeId, OperatorRefusal, Rejection, Replace, Response,
};

use super::{ClientError, Target, Transport, decode_answer, signed_operated};
use crate::lock;

/// How long a signed request is good, past the node's time as the operator
/// knows it: within the node's horizon by half of it, so a clock off by as
/// much either way takes it.
const GOOD_FOR_MS: u64 = 60_000;

/// What an operator's requests carry.
enum Authority {
    /// The node's admin token, over its own HTTP.
    Token(String),
    /// An operator key the node lists, signing each request for the node
    /// `node`.
    Key { key: Box<SigningKey>, node: NodeId },
}

/// The node's operator.
pub struct Operator {
    authority: Authority,
    transport: Transport,
    /// How far the node's time is ahead of this client's clock, as the node
    /// last reported it.
    offset: Mutex<i64>,
}

impl Operator {
    /// The operator by the node's admin token, over its HTTP.
    pub fn new(target: &Target, token: &str) -> Self {
        Self::with(
            Transport::new(target),
            Authority::Token(token.trim().to_string()),
        )
    }

    /// One whose commands' answers are read within `answer`, each read
    /// and write of them: for a caller that tries another node when one
    /// is slow.
    pub fn within(target: &Target, token: &str, answer: Duration) -> Self {
        Self::with(
            Transport::within(target, answer),
            Authority::Token(token.trim().to_string()),
        )
    }

    /// The operator by `key`, which node `node` lists, signing each
    /// request for that node alone: over the node API, or over HTTP, the
    /// node's or a gateway's, in the `Authorization` header.
    pub fn signing(target: &Target, key: SigningKey, node: NodeId) -> Self {
        Self::with(
            Transport::new(target),
            Authority::Key {
                key: Box::new(key),
                node,
            },
        )
    }

    /// [`Operator::signing`], answered within `answer`.
    pub fn signing_within(
        target: &Target,
        key: SigningKey,
        node: NodeId,
        answer: Duration,
    ) -> Self {
        Self::with(
            Transport::within(target, answer),
            Authority::Key {
                key: Box::new(key),
                node,
            },
        )
    }

    fn with(transport: Transport, authority: Authority) -> Self {
        Self {
            authority,
            transport,
            offset: Mutex::new(0),
        }
    }

    /// The `Authorization` header's value for a request of `method` to
    /// `path` holding `body`: the token, or the envelope signed over the
    /// route's kind and inner body.
    fn authorization(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        nonce: [u8; 16],
    ) -> Option<String> {
        match &self.authority {
            Authority::Token(token) => Some(format!("Bearer {token}")),
            Authority::Key { key, node } => {
                let request = vos_http::Request {
                    method: method.to_string(),
                    path: path.to_string(),
                    headers: Vec::new(),
                    body: body.to_vec(),
                    peer: None,
                    large: None,
                };
                let Routed::Operator {
                    kind,
                    inner: Ok(inner),
                    ..
                } = routes::route(&request)
                else {
                    return None;
                };
                let now = crate::wall_clock().saturating_add_signed(*lock(&self.offset));
                let operated = signed_operated(
                    *node,
                    key,
                    kind,
                    nonce,
                    now.saturating_add(GOOD_FOR_MS),
                    inner,
                );
                Some(operated_header(&operated))
            }
        }
    }

    /// A request, signed again once at the node's time if the node says
    /// its expiry was off: with the same nonce, so the two copies run once
    /// between them, whoever holds the first.
    ///
    /// A signed command sent on a kept connection that fails is sent once
    /// more on a fresh one, under its nonce. If the first copy ran before
    /// the connection failed, the answer is `Replayed` (409), not the
    /// command's outcome: it ran once, and what it did is the node's to
    /// read (its status, the agent's record). The one `Replayed` whose
    /// command never ran follows an `Unavailable`, the node's store having
    /// failed to record the nonce; each `send` signs a fresh nonce.
    fn send(&self, method: &str, path: &str, body: &[u8]) -> Result<Response, ClientError> {
        let nonce = crate::random();
        let mut answer = self.once(method, path, body, nonce)?;
        if let Response::Rejected(Rejection::Operator(OperatorRefusal::Expiry { now })) = answer {
            let offset = i128::from(now) - i128::from(crate::wall_clock());
            *lock(&self.offset) = offset.clamp(i64::MIN.into(), i64::MAX.into()) as i64;
            answer = self.once(method, path, body, nonce)?;
        }
        Ok(answer)
    }

    fn once(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        nonce: [u8; 16],
    ) -> Result<Response, ClientError> {
        let authorization = self.authorization(method, path, body, nonce);
        // A signed command runs once by its nonce: it may go again on a
        // fresh connection when a kept one failed. A token's command may
        // not be idempotent: never sent twice.
        let repeatable = matches!(self.authority, Authority::Key { .. });
        let (status, answer) = match method {
            "GET" => self.transport.get(path, authorization.as_deref())?,
            _ => self
                .transport
                .post(path, authorization.as_deref(), body, repeatable)?,
        };
        decode_answer(status, &answer)
    }

    fn post(&self, path: &str, body: &[u8]) -> Result<Response, ClientError> {
        self.send("POST", path, body)
    }

    fn get(&self, path: &str) -> Result<Response, ClientError> {
        self.send("GET", path, &[])
    }

    /// Create an agent replicated on `replicas` (the node alone when
    /// empty).
    pub fn create_agent(&self, replicas: Vec<u8>) -> Result<Response, ClientError> {
        if replicas.is_empty() {
            return self.post("/agents", &[]);
        }
        self.post("/agents", &Create { replicas }.encode())
    }

    /// Create the space's representative replicated on `replicas` (the
    /// node alone when empty): at the space's first founding node, once.
    pub fn create_representative(&self, replicas: Vec<u8>) -> Result<Response, ClientError> {
        if replicas.is_empty() {
            return self.post("/representative", &[]);
        }
        self.post("/representative", &Create { replicas }.encode())
    }

    pub fn install(&self, agent: AgentId, install: &Install) -> Result<Response, ClientError> {
        self.post(&format!("/agents/{}/install", agent.0), &install.encode())
    }

    pub fn grant(
        &self,
        agent: AgentId,
        principal: Principal,
        role: Option<u8>,
    ) -> Result<Response, ClientError> {
        let grant = Grant { principal, role };
        self.post(&format!("/agents/{}/roles", agent.0), &grant.encode())
    }

    /// Have `agent` cut and report its root at every window (`true`), as
    /// an issuer's agent does, or only at the windows a read waits on.
    pub fn report_every_window(
        &self,
        agent: AgentId,
        every: bool,
    ) -> Result<Response, ClientError> {
        self.post(&format!("/agents/{}/reports", agent.0), &every.encode())
    }

    /// Replace `agent`'s replica `remove` by node `add`, at its leader.
    pub fn replace(&self, agent: AgentId, remove: u8, add: u8) -> Result<Response, ClientError> {
        let replace = Replace { remove, add };
        self.post(&format!("/agents/{}/replicas", agent.0), &replace.encode())
    }

    /// How long the node's stages took since it started.
    pub fn stats(&self) -> Result<Response, ClientError> {
        self.get("/stats")
    }

    /// The node's replica of `agent`: its term, role, commit, applied
    /// index and log.
    pub fn status(&self, agent: AgentId) -> Result<Response, ClientError> {
        self.get(&format!("/agents/{}/status", agent.0))
    }
}
