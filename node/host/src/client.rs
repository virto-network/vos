//! A blocking client of a node's ingress: a client key's session, signed
//! calls and queries, and the operator's commands.

use std::collections::HashMap;

use ed25519_dalek::{Signer, SigningKey};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, SessionId};
use vos_wire::ingress::{
    Answer, Call, Grant, Install, NodeId, Open, Opened, QueryCall, call_message, open_message,
    query_message,
};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode};

#[derive(Debug)]
pub enum ClientError {
    Http(String),
    /// The node answered something this client cannot read.
    Undecodable(u16),
    /// The node did not open the session.
    Refused(Answer),
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .new_agent()
}

fn post(
    agent: &ureq::Agent,
    url: &str,
    token: Option<&str>,
    body: &[u8],
) -> Result<(u16, Vec<u8>), ClientError> {
    let mut request = agent.post(url);
    if let Some(token) = token {
        request = request.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = request
        .send(body)
        .map_err(|error| ClientError::Http(error.to_string()))?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .read_to_vec()
        .map_err(|error| ClientError::Http(error.to_string()))?;
    Ok((status, body))
}

fn get(agent: &ureq::Agent, url: &str) -> Result<(u16, Vec<u8>), ClientError> {
    let mut response = agent
        .get(url)
        .call()
        .map_err(|error| ClientError::Http(error.to_string()))?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .read_to_vec()
        .map_err(|error| ClientError::Http(error.to_string()))?;
    Ok((status, body))
}

fn answer(status: u16, body: &[u8]) -> Result<Answer, ClientError> {
    Answer::decode(body)
        .map(|(answer, _)| answer)
        .map_err(|_| ClientError::Undecodable(status))
}

/// The node's identity, which its clients sign for.
pub fn node_id(base: &str) -> Result<NodeId, ClientError> {
    let (status, body) = get(&agent(), &format!("{base}/"))?;
    NodeId::decode(&body)
        .map(|(id, _)| id)
        .map_err(|_| ClientError::Undecodable(status))
}

/// A client key's session on one node.
pub struct Client {
    base: String,
    http: ureq::Agent,
    key: SigningKey,
    node: NodeId,
    session: SessionId,
    next: HashMap<AgentId, u64>,
}

impl Client {
    /// Open a session for `key` on the node at `base`, signed at `time`
    /// (milliseconds since the Unix epoch, near the node's clock).
    pub fn open(base: &str, key: SigningKey, time: u64) -> Result<Self, ClientError> {
        let http = agent();
        let node = node_id(base)?;
        let public = key.verifying_key().to_bytes();
        let open = Open {
            key: public,
            time,
            signature: key.sign(&open_message(&node, &public, time)).to_bytes(),
        };
        let (status, body) = post(&http, &format!("{base}/sessions"), None, &open.encode())?;
        let opened = match Opened::decode(&body) {
            Ok((opened, used)) if status == 200 && used == body.len() => opened,
            _ => return Err(ClientError::Refused(answer(status, &body)?)),
        };
        Ok(Self {
            base: base.to_string(),
            http,
            key,
            node,
            session: opened.session,
            next: HashMap::new(),
        })
    }

    /// Go on with a session opened before: its node, id, and each agent's
    /// next sequence.
    pub fn resume(
        base: &str,
        key: SigningKey,
        node: NodeId,
        session: SessionId,
        next: HashMap<AgentId, u64>,
    ) -> Self {
        Self {
            base: base.to_string(),
            http: agent(),
            key,
            node,
            session,
            next,
        }
    }

    pub fn session(&self) -> SessionId {
        self.session
    }

    pub fn node(&self) -> NodeId {
        self.node
    }

    /// Each agent's next sequence in this session.
    pub fn next(&self) -> &HashMap<AgentId, u64> {
        &self.next
    }

    pub fn principal(&self) -> Principal {
        Principal::Client(self.key.verifying_key().to_bytes())
    }

    /// Call `method` on `agent`'s `instance` with the session's next
    /// sequence for that agent, which moves on only once consumed.
    pub fn call(
        &mut self,
        agent: AgentId,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Answer, ClientError> {
        let sequence = self.next.get(&agent).copied().unwrap_or(1);
        let answer = self.call_at(agent, sequence, instance, method, arguments)?;
        if matches!(answer, Answer::Ran(_)) {
            self.next.insert(agent, sequence + 1);
        }
        Ok(answer)
    }

    /// Call with an explicit `sequence`: to resend one, or to test.
    pub fn call_at(
        &self,
        agent: AgentId,
        sequence: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Answer, ClientError> {
        let body = self.call_body(agent, sequence, instance, method, arguments);
        let url = format!("{}/agents/{}/calls", self.base, agent.0);
        let (status, body) = post(&self.http, &url, None, &body)?;
        answer(status, &body)
    }

    /// A signed call's body, to send by other means.
    pub fn call_body(
        &self,
        agent: AgentId,
        sequence: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Vec<u8> {
        let message = call_message(
            &self.node,
            agent,
            self.session,
            sequence,
            instance,
            method,
            arguments,
        );
        Call {
            session: self.session,
            sequence,
            instance,
            method,
            arguments: arguments.to_vec(),
            signature: self.key.sign(&message).to_bytes(),
        }
        .encode()
    }

    /// Run query `method` on `agent`'s `instance`, good until `not_after`.
    pub fn query(
        &self,
        agent: AgentId,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
        not_after: u64,
    ) -> Result<Answer, ClientError> {
        let message = query_message(
            &self.node,
            agent,
            self.session,
            not_after,
            instance,
            method,
            arguments,
        );
        let query = QueryCall {
            session: self.session,
            not_after,
            instance,
            method,
            arguments: arguments.to_vec(),
            signature: self.key.sign(&message).to_bytes(),
        };
        let url = format!("{}/agents/{}/queries", self.base, agent.0);
        let (status, body) = post(&self.http, &url, None, &query.encode())?;
        answer(status, &body)
    }

    /// The schema installed as `agent`'s `instance`.
    pub fn schema(
        &self,
        agent: AgentId,
        instance: InstanceId,
    ) -> Result<Option<Schema>, ClientError> {
        schema(&self.base, agent, instance)
    }
}

/// The schema installed as `agent`'s `instance`, if any.
pub fn schema(
    base: &str,
    agent: AgentId,
    instance: InstanceId,
) -> Result<Option<Schema>, ClientError> {
    let url = format!("{base}/agents/{}/instances/{}/schema", agent.0, instance.0);
    let (status, body) = get(&agent_http(), &url)?;
    if status == 404 {
        return Ok(None);
    }
    Schema::decode(&body)
        .map(|(schema, _)| Some(schema))
        .map_err(|_| ClientError::Undecodable(status))
}

fn agent_http() -> ureq::Agent {
    agent()
}

/// The node's operator, by its admin token.
pub struct Operator {
    base: String,
    token: String,
    http: ureq::Agent,
}

impl Operator {
    pub fn new(base: &str, token: &str) -> Self {
        Self {
            base: base.to_string(),
            token: token.trim().to_string(),
            http: agent(),
        }
    }

    fn post(&self, path: &str, body: &[u8]) -> Result<Answer, ClientError> {
        let url = format!("{}{path}", self.base);
        let (status, body) = post(&self.http, &url, Some(&self.token), body)?;
        answer(status, &body)
    }

    pub fn create_agent(&self) -> Result<Answer, ClientError> {
        self.post("/agents", &[])
    }

    pub fn install(&self, agent: AgentId, install: &Install) -> Result<Answer, ClientError> {
        self.post(&format!("/agents/{}/install", agent.0), &install.encode())
    }

    pub fn grant(
        &self,
        agent: AgentId,
        principal: Principal,
        role: Option<u8>,
    ) -> Result<Answer, ClientError> {
        let grant = Grant { principal, role };
        self.post(&format!("/agents/{}/roles", agent.0), &grant.encode())
    }
}
