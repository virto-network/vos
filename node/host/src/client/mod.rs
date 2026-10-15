//! A blocking client of a node's ingress: a client key's sessions, signed
//! calls and queries, its workflows' results, and the operator's commands.

mod call;
mod http;
mod operator;
mod read;
mod target;

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_wire::Decode;
use vos_wire::ids::{AgentId, Principal, Session};
use vos_wire::ingress::{AgentInfo, Contact, NodeId, Response};

use crate::lock;
use crate::tls::Trust;
use http::Http;
pub use operator::Operator;
pub use read::schema;
pub use target::Target;
use target::authority;

#[derive(Debug)]
pub enum ClientError {
    Http(String),
    /// The node answered something this client cannot read.
    Undecodable(u16),
    /// The node knows no agent of that id.
    NoAgent,
    /// The node's record of the agent is not the one this client kept.
    OtherAgent,
    /// The node names itself by a key other than the one its TLS showed.
    NotTheNode,
    /// A call whose fate was unknown met its session gone: it may have
    /// run, and nothing can say. Its session was collected, or may have
    /// been.
    Lost,
}

fn answer(status: u16, body: &[u8]) -> Result<Response, ClientError> {
    Response::decode(body)
        .map(|(answer, _)| answer)
        .map_err(|_| ClientError::Undecodable(status))
}

/// POST `body` to `path`: the status and body answered. For requests this
/// client does not otherwise make, as a test of the ingress does.
pub fn post(target: &Target, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), ClientError> {
    Http::new(target).post(path, None, body, false)
}

/// POST `body` to `path` on a connection of its own: the answer. Each
/// read and write, the connection's included, must be done within
/// `within`, a positive deadline. For a caller that keeps its own
/// deadlines and tries another node when one is slow, as a checker
/// does.
pub fn post_within(
    target: &Target,
    path: &str,
    body: &[u8],
    within: Duration,
) -> Result<Response, ClientError> {
    let (status, body) = Http::within(target, within).post(path, None, body, false)?;
    answer(status, &body)
}

/// The node's identity, its key, which its TLS presents. A pinned node
/// must name itself by the key it was pinned by.
pub fn node_id(target: &Target) -> Result<NodeId, ClientError> {
    fetch_node_id(&Http::new(target))
}

fn fetch_node_id(http: &Http) -> Result<NodeId, ClientError> {
    let (status, body) = http.get("/")?;
    let id = NodeId::decode(&body)
        .map(|(id, _)| id)
        .map_err(|_| ClientError::Undecodable(status))?;
    match http.target.key {
        Some(key) if key != id.0 => Err(ClientError::NotTheNode),
        _ => Ok(id),
    }
}

/// Agent `agent`'s creation record and replicas, as the node knows them:
/// `None` when it knows no such agent.
pub fn agent_info(target: &Target, agent: AgentId) -> Result<Option<AgentInfo>, ClientError> {
    agent_info_from(&Http::new(target), agent)
}

fn agent_info_from(http: &Http, agent: AgentId) -> Result<Option<AgentInfo>, ClientError> {
    let (status, body) = http.get(&format!("/agents/{}", agent.0))?;
    if status == 404 {
        return Ok(None);
    }
    match AgentInfo::decode(&body) {
        Ok((info, _)) if info.record.agent == agent => Ok(Some(info)),
        _ => Err(ClientError::Undecodable(status)),
    }
}

/// One agent's session as its client keeps it: the session's name and
/// creation time, and the next sequence to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kept {
    pub name: [u8; 16],
    pub t0: u64,
    pub next: u64,
}

/// A client key, calling each agent in a session of its own.
///
/// A session goes on until the agent refuses it for good (expired, or
/// started too far from the agent's time): only then does the client start
/// another. After an error the call may have run or not: call again with
/// the same request, which goes with the same sequence, and the agent runs
/// it once. A process that calls again later, as the CLI does, says so
/// with [`Client::repeats_unknown`]; once the agent has collected the
/// session, such a call ends [`ClientError::Lost`].
pub struct Client {
    http: Http,
    key: SigningKey,
    sessions: Mutex<HashMap<AgentId, Kept>>,
    identities: Mutex<HashMap<AgentId, [u8; 32]>>,
    /// Each agent's replicas, learned with its identity.
    replicas: Mutex<HashMap<AgentId, Vec<Contact>>>,
    /// Agents whose next call repeats one whose fate is unknown.
    unknown: Mutex<HashSet<AgentId>>,
    /// Each agent's floor: the highest applied index an answer reflected.
    floors: Mutex<HashMap<AgentId, u64>>,
    /// How far the agents' time is ahead of this client's clock, as a
    /// node last reported it: a new session starts at that time.
    offset: Mutex<i64>,
}

impl Client {
    /// A client for `key` calling the node at `target`.
    pub fn new(target: &Target, key: SigningKey) -> Self {
        Self::resume(target, key, HashMap::new(), HashMap::new())
    }

    /// A client going on with the sessions it kept, and the agents'
    /// identities it learned.
    pub fn resume(
        target: &Target,
        key: SigningKey,
        sessions: HashMap<AgentId, Kept>,
        identities: HashMap<AgentId, [u8; 32]>,
    ) -> Self {
        Self {
            http: Http::new(target),
            key,
            sessions: Mutex::new(sessions),
            identities: Mutex::new(identities),
            replicas: Mutex::new(HashMap::new()),
            unknown: Mutex::new(HashSet::new()),
            floors: Mutex::new(HashMap::new()),
            offset: Mutex::new(0),
        }
    }

    /// Each agent's session, to keep.
    pub fn sessions(&self) -> HashMap<AgentId, Kept> {
        lock(&self.sessions).clone()
    }

    /// Each agent's identity learned, to keep.
    pub fn identities(&self) -> HashMap<AgentId, [u8; 32]> {
        lock(&self.identities).clone()
    }

    /// Say that the next call to `agent` repeats one whose fate is unknown,
    /// as a process that kept it pending can, however long ago: a refusal
    /// of its session then proves nothing while copies of the earlier one
    /// may be on their way, and once the session may be collected, the
    /// call ends [`ClientError::Lost`].
    pub fn repeats_unknown(&self, agent: AgentId) {
        lock(&self.unknown).insert(agent);
    }

    /// The node this client calls: the one it was given, or the last a
    /// redirect named.
    pub fn target(&self) -> &Target {
        &self.http.target
    }

    pub fn principal(&self) -> Principal {
        Principal::Client(self.key.verifying_key().to_bytes())
    }

    /// The session this client calls `agent` in, started if there is none.
    pub fn session(&self, agent: AgentId) -> Session {
        let kept = *lock(&self.sessions)
            .entry(agent)
            .or_insert_with(|| self.start());
        self.whole(kept)
    }

    /// Start another session for `agent`: the one before is done with.
    pub fn renew(&self, agent: AgentId) {
        let kept = self.start();
        lock(&self.sessions).insert(agent, kept);
    }

    fn start(&self) -> Kept {
        let mut name = [0u8; 16];
        getrandom::getrandom(&mut name).expect("the operating system's randomness");
        let offset = *lock(&self.offset);
        let t0 = crate::wall_clock().saturating_add_signed(offset);
        Kept { name, t0, next: 1 }
    }

    fn whole(&self, kept: Kept) -> Session {
        Session {
            key: self.key.verifying_key().to_bytes(),
            name: kept.name,
            t0: kept.t0,
        }
    }

    /// The identity of `agent`, which calls to it are signed for: the hash
    /// of its creation record, fetched from the node once, with the agent's
    /// replicas.
    pub fn identity(&self, agent: AgentId) -> Result<[u8; 32], ClientError> {
        if let Some(identity) = lock(&self.identities).get(&agent) {
            return Ok(*identity);
        }
        self.learn(agent)
    }

    /// Fetch `agent`'s record and replicas from the node. An identity kept
    /// from before stands: a node that names another is refused.
    fn learn(&self, agent: AgentId) -> Result<[u8; 32], ClientError> {
        let info = agent_info_from(&self.http, agent)?.ok_or(ClientError::NoAgent)?;
        let identity = crate::identity(&info.record);
        let kept = *lock(&self.identities).entry(agent).or_insert(identity);
        if kept != identity {
            return Err(ClientError::OtherAgent);
        }
        lock(&self.replicas).insert(agent, info.replicas);
        Ok(identity)
    }

    /// Learn `agent`'s replicas, unless this client knows them: an
    /// identity kept from before comes without them.
    fn ensure_replicas(&self, agent: AgentId) {
        if !lock(&self.replicas).contains_key(&agent) {
            let _ = self.learn(agent);
        }
    }

    /// `agent`'s replicas other than the one this client calls, learned
    /// first if need be: from the one after it on, in turn.
    fn other_replicas(&self, agent: AgentId) -> Vec<Contact> {
        self.ensure_replicas(agent);
        let replicas = lock(&self.replicas)
            .get(&agent)
            .cloned()
            .unwrap_or_default();
        let current = Some(self.http.target.authority.clone());
        match replicas
            .iter()
            .position(|replica| authority(&replica.address) == current)
        {
            Some(at) => [&replicas[at + 1..], &replicas[..at]].concat(),
            None => replicas,
        }
    }

    /// Take the agent's time `now`, as a node reported it, as the offset
    /// from this client's clock.
    fn learn_time(&self, now: u64) {
        let offset = i128::from(now) - i128::from(crate::wall_clock());
        *lock(&self.offset) = offset.clamp(i64::MIN.into(), i64::MAX.into()) as i64;
    }

    /// The node `contact` names, trusted as this client trusts nodes.
    fn target_for(&self, contact: &Contact) -> Result<Target, ClientError> {
        let trust = match &self.http.target.trust {
            Trust::Ca(roots) => Trust::Ca(roots.clone()),
            Trust::NodeKey(_) | Trust::Loopback if contact.address.starts_with("https://") => {
                Trust::NodeKey(contact.node.0)
            }
            Trust::NodeKey(_) | Trust::Loopback => Trust::Loopback,
        };
        Target::new(&contact.address, trust)
    }
}
