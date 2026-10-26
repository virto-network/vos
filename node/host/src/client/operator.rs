//! The node's operator: commands by its admin token.

use std::time::Duration;

use vos_wire::Encode;
use vos_wire::ids::{AgentId, Principal};
use vos_wire::ingress::{Create, Grant, Install, Replace, Response};

use super::{ClientError, Http, Target, decode_answer};

/// The node's operator, by its admin token.
pub struct Operator {
    token: String,
    http: Http,
}

impl Operator {
    pub fn new(target: &Target, token: &str) -> Self {
        Self {
            token: token.trim().to_string(),
            http: Http::new(target),
        }
    }

    /// One whose commands' answers are read within `answer`, each read
    /// and write of them: for a caller that tries another node when one
    /// is slow.
    pub fn within(target: &Target, token: &str, answer: Duration) -> Self {
        Self {
            token: token.trim().to_string(),
            http: Http::within(target, answer),
        }
    }

    fn post(&self, path: &str, body: &[u8]) -> Result<Response, ClientError> {
        // An operator's command may not be idempotent: never sent twice.
        let (status, body) = self.http.post_once(path, Some(&self.token), body)?;
        decode_answer(status, &body)
    }

    fn get(&self, path: &str) -> Result<Response, ClientError> {
        let (status, body) = self.http.get(path, Some(&self.token))?;
        decode_answer(status, &body)
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
