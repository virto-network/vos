//! A blocking client of a node's ingress: a client key's sessions, signed
//! calls and queries, its workflows' results, and the operator's commands.

mod call;
mod http;
mod operator;
mod read;
mod signed;
mod target;

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard};
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
pub use signed::{
    signed_call, signed_operated, signed_query, signed_workflow_read, workflow_read_not_after,
};
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

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(why) => write!(f, "{why}"),
            Self::Undecodable(status) => write!(f, "an answer it cannot read (status {status})"),
            Self::NoAgent => write!(f, "the node knows no such agent"),
            Self::OtherAgent => write!(f, "the node's record of the agent is another"),
            Self::NotTheNode => write!(f, "the node names itself by another key"),
            Self::Lost => write!(f, "the call may have run, and nothing can say"),
        }
    }
}

impl std::error::Error for ClientError {}

/// The answer in a body the node sent with `status`.
fn decode_answer(status: u16, body: &[u8]) -> Result<Response, ClientError> {
    Response::decode(body)
        .map(|(answer, _)| answer)
        .map_err(|_| ClientError::Undecodable(status))
}

/// POST `body` to `path`: the status and body answered. For requests this
/// client does not otherwise make, as a test of the ingress does.
pub fn post(target: &Target, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), ClientError> {
    Http::new(target).post_once(path, None, body)
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
    let (status, body) = Http::within(target, within).post_once(path, None, body)?;
    decode_answer(status, &body)
}

/// The node's identity, its key, which its TLS presents. A pinned node
/// must name itself by the key it was pinned by.
pub fn node_id(target: &Target) -> Result<NodeId, ClientError> {
    Http::new(target).node_id()
}

/// Agent `agent`'s creation record and replicas, as the node knows them:
/// `None` when it knows no such agent.
pub fn agent_info(target: &Target, agent: AgentId) -> Result<Option<AgentInfo>, ClientError> {
    Http::new(target).agent_info(agent)
}

impl Http {
    fn node_id(&self) -> Result<NodeId, ClientError> {
        let (status, body) = self.get("/", None)?;
        let id = NodeId::decode(&body)
            .map(|(id, _)| id)
            .map_err(|_| ClientError::Undecodable(status))?;
        match self.target.trust {
            Trust::NodeKey(key) if key != id.0 => Err(ClientError::NotTheNode),
            _ => Ok(id),
        }
    }

    fn agent_info(&self, agent: AgentId) -> Result<Option<AgentInfo>, ClientError> {
        let (status, body) = self.get(&format!("/agents/{}", agent.0), None)?;
        if status == 404 {
            return Ok(None);
        }
        match AgentInfo::decode(&body) {
            Ok((info, _)) if info.record.agent == agent => Ok(Some(info)),
            _ => Err(ClientError::Undecodable(status)),
        }
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
    state: Mutex<State>,
}

/// What a client keeps of the agents it calls.
#[derive(Default)]
struct State {
    sessions: HashMap<AgentId, Kept>,
    identities: HashMap<AgentId, [u8; 32]>,
    /// Each agent's replicas, learned with its identity.
    replicas: HashMap<AgentId, Vec<Contact>>,
    /// Agents whose next call repeats one whose fate is unknown.
    unknown: HashSet<AgentId>,
    /// Each agent's floor: the highest applied index an answer reflected.
    floors: HashMap<AgentId, u64>,
    /// How far the agents' time is ahead of this client's clock, as a
    /// node last reported it: a new session starts at that time.
    offset: i64,
}

/// A new session, started at the agents' time as `offset` from this
/// client's clock puts it.
fn start(offset: i64) -> Kept {
    let t0 = crate::wall_clock().saturating_add_signed(offset);
    Kept {
        name: crate::random(),
        t0,
        next: 1,
    }
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
        let state = State {
            sessions,
            identities,
            ..State::default()
        };
        Self {
            http: Http::new(target),
            key,
            state: Mutex::new(state),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    /// Each agent's session, to keep.
    pub fn sessions(&self) -> HashMap<AgentId, Kept> {
        self.state().sessions.clone()
    }

    /// Each agent's identity learned, to keep.
    pub fn identities(&self) -> HashMap<AgentId, [u8; 32]> {
        self.state().identities.clone()
    }

    /// Say that the next call to `agent` repeats one whose fate is unknown,
    /// as a process that kept it pending can, however long ago: a refusal
    /// of its session then proves nothing while copies of the earlier one
    /// may be on their way, and once the session may be collected, the
    /// call ends [`ClientError::Lost`].
    pub fn repeats_unknown(&self, agent: AgentId) {
        self.state().unknown.insert(agent);
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
        self.session_of(self.kept(agent))
    }

    /// `agent`'s session as this client keeps it, started if there is
    /// none.
    fn kept(&self, agent: AgentId) -> Kept {
        let mut state = self.state();
        let offset = state.offset;
        *state.sessions.entry(agent).or_insert_with(|| start(offset))
    }

    /// Start another session for `agent`: the one before is done with.
    pub fn renew(&self, agent: AgentId) {
        let mut state = self.state();
        let kept = start(state.offset);
        state.sessions.insert(agent, kept);
    }

    /// The session `kept` names, this client's key's.
    fn session_of(&self, kept: Kept) -> Session {
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
        let learned = self.state().identities.get(&agent).copied();
        match learned {
            Some(identity) => Ok(identity),
            None => self.learn(agent),
        }
    }

    /// Fetch `agent`'s record and replicas from the node. An identity kept
    /// from before stands: a node that names another is refused.
    fn learn(&self, agent: AgentId) -> Result<[u8; 32], ClientError> {
        let info = self.http.agent_info(agent)?.ok_or(ClientError::NoAgent)?;
        let identity = crate::identity(&info.record);
        let mut state = self.state();
        if *state.identities.entry(agent).or_insert(identity) != identity {
            return Err(ClientError::OtherAgent);
        }
        state.replicas.insert(agent, info.replicas);
        Ok(identity)
    }

    /// Learn `agent`'s replicas, unless this client knows them: an
    /// identity kept from before comes without them.
    fn ensure_replicas(&self, agent: AgentId) {
        let known = self.state().replicas.contains_key(&agent);
        if !known {
            let _ = self.learn(agent);
        }
    }

    /// `agent`'s replicas other than the one this client calls, learned
    /// first if need be: from the one after it on, in turn.
    fn other_replicas(&self, agent: AgentId) -> Vec<Contact> {
        self.ensure_replicas(agent);
        let replicas = self
            .state()
            .replicas
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
        self.state().offset = offset.clamp(i64::MIN.into(), i64::MAX.into()) as i64;
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
