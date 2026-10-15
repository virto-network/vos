//! A blocking client of a node's ingress: a client key's sessions, signed
//! calls and queries, its workflows' results, and the operator's commands.

mod http;
mod target;

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use vos_wire::abi::Refusal;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session, WorkflowId};
use vos_wire::ingress::{
    AgentInfo, Call, Consistency, Contact, Create, Grant, Install, NodeId, QueryCall, Rejection,
    Replace, Response, WORKFLOW_READ_HORIZON_MS, WorkflowRead, call_message, query_message,
    workflow_message, workflow_read_horizon,
};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode, defaults};

use crate::lock;
use crate::tls::Trust;
use http::Http;
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

/// What became of a call whose fate was unknown, once its session was
/// refused.
enum Fate {
    /// Copies of it may still run.
    InTransit,
    /// It never ran, and never can: it may go again in a new session.
    NeverRan,
    /// It may have run, and nothing can say.
    Lost,
}

/// Redirects a call follows before it answers what the last node said.
const REDIRECTS: usize = 4;
/// Times a call goes to another replica, after a failure, before it
/// answers the last.
const FAILOVERS: usize = 6;
/// The first wait after `Busy`, doubled each time up to [`MAX_BUSY`].
const BUSY: Duration = Duration::from_millis(50);
const MAX_BUSY: Duration = Duration::from_secs(1);
/// New sessions a call starts before it answers the refusal: one when the
/// agent refuses a session for good, and one more when the client's clock
/// is off the agent's time.
const RENEWALS: usize = 2;

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

    /// Call the replica of `agent` after the one this client calls: false
    /// when it knows no other.
    fn fail_over(&mut self, agent: AgentId) -> Result<bool, ClientError> {
        let Some(next) = self.other_replicas(agent).into_iter().next() else {
            return Ok(false);
        };
        self.follow(&next)?;
        Ok(true)
    }

    /// Call `method` on `agent`'s `instance`, at the session's next
    /// sequence for that agent, which moves on only once consumed.
    ///
    /// Any replica takes the call. On a failure, or an answer that leaves
    /// it unknown whether the call ran, the call goes to the next replica
    /// with the same sequence; on `Busy`, again after a wait. Redirects are
    /// followed, and a new session is started when the agent refuses this
    /// one for good.
    pub fn call(
        &mut self,
        agent: AgentId,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Response, ClientError> {
        // Learn the replicas first: the node may be gone when a failover
        // needs them.
        self.ensure_replicas(agent);
        let mut redirects = 0;
        let mut renewals = 0;
        let mut failovers = 0;
        let mut busy = BUSY;
        // An attempt that may have run, or may yet: later refusals that
        // say it never ran no longer prove it for the call.
        let mut inconclusive = lock(&self.unknown).remove(&agent);
        loop {
            self.session(agent);
            let sequence = lock(&self.sessions)[&agent].next;
            let answer = match self.call_at(agent, sequence, instance, method, arguments) {
                Ok(answer) => answer,
                Err(error) => {
                    inconclusive = true;
                    if failovers < FAILOVERS && self.fail_over(agent).unwrap_or(false) {
                        failovers += 1;
                        continue;
                    }
                    return Err(error);
                }
            };
            match &answer {
                Response::Ran { at, .. } => {
                    if let Some(kept) = lock(&self.sessions).get_mut(&agent) {
                        kept.next = sequence + 1;
                    }
                    self.raise_floor(agent, *at);
                    return Ok(answer);
                }
                Response::NotLeader {
                    leader: Some(leader),
                } if redirects < REDIRECTS => {
                    redirects += 1;
                    self.follow(leader)?;
                }
                Response::Elsewhere { replicas }
                    if redirects < REDIRECTS && !replicas.is_empty() =>
                {
                    redirects += 1;
                    self.follow(&replicas[(redirects - 1) % replicas.len()])?;
                }
                // An earlier attempt may have run, or may yet.
                Response::Rejected(Rejection::StaleSession { now }) if inconclusive => {
                    match self.unknown_fate(agent, *now) {
                        Fate::Lost => {
                            self.renew(agent);
                            return Err(ClientError::Lost);
                        }
                        Fate::InTransit => return Ok(Response::TimedOut),
                        Fate::NeverRan if renewals < RENEWALS => {
                            renewals += 1;
                            inconclusive = false;
                            self.learn_time(*now);
                            self.renew(agent);
                        }
                        Fate::NeverRan => return Ok(answer),
                    }
                }
                // Not consumed: the same request goes again in a new session.
                Response::Rejected(Rejection::StaleSession { now }) if renewals < RENEWALS => {
                    renewals += 1;
                    self.learn_time(*now);
                    self.renew(agent);
                }
                // Timed by refine, past the lane: the next attempt meets the
                // lane's refusal, with the agent's time.
                Response::Refused(Refusal::StaleSession) if inconclusive => {
                    return Ok(Response::TimedOut);
                }
                // An expired session's calls that ran are answered from its
                // window: refused, this one never ran, and never will.
                Response::Refused(Refusal::Expired | Refusal::StaleSession)
                    if renewals < RENEWALS =>
                {
                    renewals += 1;
                    inconclusive = false;
                    self.renew(agent);
                }
                // The earlier attempt may still create the session.
                Response::Refused(Refusal::SessionsFull | Refusal::KeySessionsFull)
                    if inconclusive =>
                {
                    return Ok(Response::TimedOut);
                }
                Response::Stopped
                | Response::Unavailable
                | Response::TimedOut
                | Response::NotLeader { leader: None }
                    if failovers < FAILOVERS =>
                {
                    inconclusive = true;
                    failovers += 1;
                    let _ = self.fail_over(agent);
                }
                // Every replica forwards to the same leader: wait.
                Response::Busy if failovers < FAILOVERS => {
                    failovers += 1;
                    std::thread::sleep(busy);
                    busy = (busy * 2).min(MAX_BUSY);
                }
                // Busy, or a failure of this attempt, says nothing of an
                // earlier one.
                Response::Busy | Response::NotConsumed if inconclusive => {
                    return Ok(Response::TimedOut);
                }
                _ => return Ok(answer),
            }
        }
    }

    /// What a call whose fate is unknown can be, its session refused as one
    /// the agent does not hold at the agent's time `now`.
    fn unknown_fate(&self, agent: AgentId, now: u64) -> Fate {
        let Some(kept) = lock(&self.sessions).get(&agent).copied() else {
            return Fate::InTransit;
        };
        // Answered in, the session was created, and is gone.
        if kept.next > 1 {
            return Fate::Lost;
        }
        let skew = defaults::SESSION_SKEW_MS;
        // A leader may still create it, or will once time reaches a t0
        // ahead.
        if now <= kept.t0.saturating_add(2 * skew) {
            return Fate::InTransit;
        }
        // Never created: collecting it would need the agent's time past
        // its t0 less the skew plus the expiry. And no leader's clock is
        // now near enough its t0 to create it.
        if now <= kept.t0.saturating_add(defaults::SESSION_EXPIRY_MS) - skew {
            return Fate::NeverRan;
        }
        Fate::Lost
    }

    /// Take the agent's time `now`, as a node reported it, as the offset
    /// from this client's clock.
    fn learn_time(&self, now: u64) {
        let offset = i128::from(now) - i128::from(crate::wall_clock());
        *lock(&self.offset) = offset.clamp(i64::MIN.into(), i64::MAX.into()) as i64;
    }

    /// Call the node `contact` names from now on, trusted as this client
    /// trusts nodes: by the same CAs, or pinned by the key the redirecting
    /// node gave, as this client already trusts what that node says.
    fn follow(&mut self, contact: &Contact) -> Result<(), ClientError> {
        self.http = Http::new(&self.target_for(contact)?);
        Ok(())
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

    /// Call with an explicit `sequence` in the agent's session: to resend
    /// one, or to test.
    pub fn call_at(
        &self,
        agent: AgentId,
        sequence: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Response, ClientError> {
        let body = self.call_body(agent, sequence, instance, method, arguments)?;
        let path = format!("/agents/{}/calls", agent.0);
        let (status, body) = self.http.post(&path, None, &body, true)?;
        answer(status, &body)
    }

    /// A signed call's body in the agent's session, to send by other means.
    pub fn call_body(
        &self,
        agent: AgentId,
        sequence: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let identity = self.identity(agent)?;
        let session = self.session(agent);
        let message = call_message(&identity, &session, sequence, instance, method, arguments);
        Ok(Call {
            session,
            sequence,
            instance,
            method,
            arguments: arguments.to_vec(),
            signature: self.key.sign(&message).to_bytes(),
        }
        .encode())
    }

    /// Run query `method` on `agent`'s `instance`, good until `not_after`,
    /// on state that holds every answer this client was given for the
    /// agent: it reads its own writes, and never reads back.
    pub fn query(
        &self,
        agent: AgentId,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
        not_after: u64,
    ) -> Result<Response, ClientError> {
        let consistency = Consistency::Applied {
            at: self.floor(agent),
        };
        self.query_with(agent, instance, method, arguments, not_after, consistency)
    }

    /// Run a query on the state `consistency` asks for. `not_after` is by
    /// this client's clock: it goes moved to the agents' time, as a node
    /// last reported it, and once more after a node says it is stale.
    pub fn query_with(
        &self,
        agent: AgentId,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
        not_after: u64,
        consistency: Consistency,
    ) -> Result<Response, ClientError> {
        let identity = self.identity(agent)?;
        let offset = || *lock(&self.offset);
        let used = offset();
        let answer = self.query_until(
            agent,
            &identity,
            (instance, method, arguments),
            not_after.saturating_add_signed(used),
            consistency,
        )?;
        let Response::Rejected(Rejection::StaleQuery { now }) = answer else {
            return Ok(answer);
        };
        self.learn_time(now);
        self.query_until(
            agent,
            &identity,
            (instance, method, arguments),
            not_after.saturating_add_signed(offset()),
            consistency,
        )
    }

    /// A query good until `not_after`, by the agents' time.
    fn query_until(
        &self,
        agent: AgentId,
        identity: &[u8; 32],
        (instance, method, arguments): (InstanceId, MethodId, &[u8]),
        not_after: u64,
        consistency: Consistency,
    ) -> Result<Response, ClientError> {
        let key = self.key.verifying_key().to_bytes();
        let message = query_message(
            identity,
            &key,
            not_after,
            consistency,
            instance,
            method,
            arguments,
        );
        let query = QueryCall {
            key,
            not_after,
            consistency,
            instance,
            method,
            arguments: arguments.to_vec(),
            signature: self.key.sign(&message).to_bytes(),
        };
        self.read(
            agent,
            &format!("/agents/{}/queries", agent.0),
            &query.encode(),
        )
    }

    /// Read workflow `workflow` of `agent`, which this client's key
    /// started, on state that holds every answer this client was given for
    /// the agent, waiting up to `wait` for it to end, as long as the node
    /// allows: its status, as [`Response::Workflow`]. Only the workflow's
    /// owner learns of it: to any other key it is unknown, as it is to its
    /// owner once collected, about an hour after it ended
    /// ([`defaults::WORKFLOW_KEPT_MS`]).
    pub fn workflow(
        &self,
        agent: AgentId,
        workflow: WorkflowId,
        wait: Duration,
    ) -> Result<Response, ClientError> {
        let consistency = Consistency::Applied {
            at: self.floor(agent),
        };
        self.workflow_with(agent, workflow, wait, consistency)
    }

    /// [`Client::workflow`] on the state `consistency` asks for.
    pub fn workflow_with(
        &self,
        agent: AgentId,
        workflow: WorkflowId,
        wait: Duration,
        consistency: Consistency,
    ) -> Result<Response, ClientError> {
        let identity = self.identity(agent)?;
        let wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        let key = self.key.verifying_key().to_bytes();
        let path = format!("/agents/{}/workflows", agent.0);
        let read_until = |not_after: u64| {
            let message =
                workflow_message(&identity, &key, not_after, consistency, workflow, wait_ms);
            let read = WorkflowRead {
                key,
                not_after,
                consistency,
                workflow,
                wait_ms,
                signature: self.key.sign(&message).to_bytes(),
            };
            self.read(agent, &path, &read.encode())
        };
        // Good past the wait, by the agents' time, within half the horizon
        // a node allows: room for clocks off by as much either way.
        let not_after = || {
            crate::wall_clock()
                .saturating_add(workflow_read_horizon(wait_ms) - WORKFLOW_READ_HORIZON_MS / 2)
                .saturating_add_signed(*lock(&self.offset))
        };
        let answer = read_until(not_after())?;
        let Response::Rejected(Rejection::StaleQuery { now }) = answer else {
            return Ok(answer);
        };
        self.learn_time(now);
        read_until(not_after())
    }

    /// A signed read, `body` posted to `path`: it changes nothing, so one
    /// this replica cannot answer now goes to the others in turn, the
    /// client still calling this one. An answer raises the agent's floor.
    fn read(&self, agent: AgentId, path: &str, body: &[u8]) -> Result<Response, ClientError> {
        let ask = |http: &Http| -> Result<Response, ClientError> {
            let (status, answered) = http.post(path, None, body, true)?;
            answer(status, &answered)
        };
        let unanswered = |answer: &Result<Response, ClientError>| {
            matches!(
                answer,
                Err(_)
                    | Ok(Response::Rejected(Rejection::Behind)
                        | Response::TimedOut
                        | Response::Unavailable
                        | Response::Stopped
                        | Response::NotLeader { .. }
                        | Response::Elsewhere { .. })
            )
        };
        let mut answer = ask(&self.http);
        if unanswered(&answer) {
            for replica in self.other_replicas(agent) {
                let Ok(target) = self.target_for(&replica) else {
                    continue;
                };
                answer = ask(&Http::new(&target));
                if !unanswered(&answer) {
                    break;
                }
            }
        }
        let answer = answer?;
        if let Response::Ran { at, .. } | Response::Workflow { at, .. } = answer {
            self.raise_floor(agent, at);
        }
        Ok(answer)
    }

    /// The highest applied index an answer for `agent` reflected: the
    /// floor its queries ask a replica to have reached.
    pub fn floor(&self, agent: AgentId) -> u64 {
        lock(&self.floors).get(&agent).copied().unwrap_or(0)
    }

    /// Each agent's floor, to keep.
    pub fn floors(&self) -> HashMap<AgentId, u64> {
        lock(&self.floors).clone()
    }

    /// Raise `agent`'s floor to `at`, as an answer, or one kept from
    /// before, reflected.
    pub fn raise_floor(&self, agent: AgentId, at: u64) {
        let mut floors = lock(&self.floors);
        let floor = floors.entry(agent).or_insert(0);
        *floor = (*floor).max(at);
    }

    /// The schema installed as `agent`'s `instance`.
    pub fn schema(
        &self,
        agent: AgentId,
        instance: InstanceId,
    ) -> Result<Option<Schema>, ClientError> {
        schema_from(&self.http, agent, instance)
    }
}

/// The schema installed as `agent`'s `instance`, if any.
pub fn schema(
    target: &Target,
    agent: AgentId,
    instance: InstanceId,
) -> Result<Option<Schema>, ClientError> {
    schema_from(&Http::new(target), agent, instance)
}

fn schema_from(
    http: &Http,
    agent: AgentId,
    instance: InstanceId,
) -> Result<Option<Schema>, ClientError> {
    let path = format!("/agents/{}/instances/{}/schema", agent.0, instance.0);
    let (status, body) = http.get(&path)?;
    if status == 404 {
        return Ok(None);
    }
    Schema::decode(&body)
        .map(|(schema, _)| Some(schema))
        .map_err(|_| ClientError::Undecodable(status))
}

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
        let (status, body) = self.http.post(path, Some(&self.token), body, false)?;
        answer(status, &body)
    }

    /// Create an agent replicated on `replicas` (the node alone when
    /// empty).
    pub fn create_agent(&self, replicas: Vec<u8>) -> Result<Response, ClientError> {
        if replicas.is_empty() {
            return self.post("/agents", &[]);
        }
        self.post("/agents", &Create { replicas }.encode())
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

    /// Replace `agent`'s replica `remove` by node `add`, at its leader.
    pub fn replace(&self, agent: AgentId, remove: u8, add: u8) -> Result<Response, ClientError> {
        let replace = Replace { remove, add };
        self.post(&format!("/agents/{}/replicas", agent.0), &replace.encode())
    }

    /// How long the node's stages took since it started.
    pub fn stats(&self) -> Result<Response, ClientError> {
        let (status, body) = self
            .http
            .request("GET", "/stats", Some(&self.token), &[], true)?;
        answer(status, &body)
    }

    /// The node's replica of `agent`: its term, role, commit, applied
    /// index and log.
    pub fn status(&self, agent: AgentId) -> Result<Response, ClientError> {
        let (status, body) = self.http.request(
            "GET",
            &format!("/agents/{}/status", agent.0),
            Some(&self.token),
            &[],
            true,
        )?;
        answer(status, &body)
    }
}
