//! A device's requests to its personal agent, as a gateway relays what its
//! onion service received: over each node's API as the driver key, every
//! frame marked `Onion`. A call goes to the agent's leader as last
//! learned and follows a redirect; a query goes to the replica asked.

use std::cell::Cell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use smol::LocalExecutor;
use vos_abi::abi::Failure;
use vos_abi::ids::{AgentId, InstanceId, MethodId, Session};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode};
use vos_api::{Kind, Mark};
use vos_node::client::{signed_call, signed_query};
use vos_wire::ingress::{Consistency, Response};
use vos_wire::personal::PersonalError;

use super::{INSTANCE, Member, device_keys, method};
use crate::deploy::DeployedNode;
use crate::engine::pool::Pool;

/// How long one request may take.
pub const ANSWER: Duration = Duration::from_secs(30);
/// How long past the node's clock a query is good.
const QUERY_GOOD_MS: u64 = 30_000;
/// The most times a call is sent again after a refusal before it ran.
const RETRIES: usize = 4;

/// Each node's API, and the nodes by key, where a redirect points.
pub struct Nodes {
    pub pools: Vec<Pool>,
    by_key: HashMap<[u8; 32], usize>,
    /// How far the nodes' clock runs ahead of this host's.
    offset_ms: Cell<i64>,
}

impl Nodes {
    pub fn new(nodes: &[DeployedNode], client: [u8; 32]) -> Result<Self, String> {
        let mut pools = Vec::new();
        let mut by_key = HashMap::new();
        for (at, node) in nodes.iter().enumerate() {
            let key = crate::keys::hex32(&node.key)?;
            pools.push(Pool::quic(&node.api, key, client)?);
            by_key.insert(key, at);
        }
        Ok(Self {
            pools,
            by_key,
            offset_ms: Cell::new(0),
        })
    }

    /// The nodes' time now, as the first node last said.
    pub fn now(&self) -> u64 {
        crate::now_ms().saturating_add_signed(self.offset_ms.get())
    }

    /// Learn the nodes' clock from the first that answers.
    pub async fn learn_time(&self) -> Result<(), String> {
        let mut last = String::from("no node");
        for pool in &self.pools {
            let asked = crate::now_ms();
            match pool.time(ANSWER).await {
                Ok(now) => {
                    let mid = asked + (crate::now_ms() - asked) / 2;
                    self.offset_ms
                        .set((i128::from(now) - i128::from(mid)) as i64);
                    return Ok(());
                }
                Err(error) => last = error,
            }
        }
        Err(format!("the nodes' time: {last}"))
    }

    /// `call` at `agent`'s leader as `leader` holds it (a node index),
    /// following a redirect and trying the next replica when a node does
    /// not serve: the answer, once one ran or could not have.
    pub async fn call(
        &self,
        agent: AgentId,
        replicas: &[usize],
        leader: &Cell<usize>,
        call: &[u8],
    ) -> Result<Response, String> {
        let mut answer = Err("not sent".to_string());
        for _ in 0..=RETRIES {
            let node = leader.get();
            answer = self.pools[node]
                .post_marked(Kind::Call, Mark::Onion, agent, call, ANSWER)
                .await;
            match &answer {
                Ok(Response::NotLeader {
                    leader: Some(contact),
                }) => match self.by_key.get(&contact.node.0) {
                    Some(next) => leader.set(*next),
                    None => return answer,
                },
                Ok(Response::NotLeader { leader: None } | Response::Unavailable)
                | Ok(Response::Elsewhere { .. }) => {
                    let at = replicas.iter().position(|r| *r == node).unwrap_or(0);
                    leader.set(replicas[(at + 1) % replicas.len()]);
                    smol::Timer::after(Duration::from_millis(100)).await;
                }
                // No answer: the next call tries the next replica, this
                // one's fate unknown.
                Err(_) => {
                    let at = replicas.iter().position(|r| *r == node).unwrap_or(0);
                    leader.set(replicas[(at + 1) % replicas.len()]);
                    return answer;
                }
                _ => return answer,
            }
        }
        answer
    }

    /// `query` at node `node`.
    pub async fn query(
        &self,
        node: usize,
        agent: AgentId,
        query: &[u8],
    ) -> Result<Response, String> {
        self.pools[node]
            .post_marked(Kind::Query, Mark::Onion, agent, query, ANSWER)
            .await
    }
}

/// A device's key and its agent, signing its requests.
pub struct Device {
    pub key: SigningKey,
    pub agent: AgentId,
    pub identity: [u8; 32],
    pub replicas: Vec<usize>,
    pub leader: Cell<usize>,
}

impl Device {
    /// Member `member`'s device, by its sync key.
    pub fn sync(seed: u64, member: &Member) -> Self {
        let replicas: Vec<usize> = member
            .replicas
            .iter()
            .map(|node| usize::from(*node) - 1)
            .collect();
        Self {
            key: device_keys(seed, member.index).0,
            agent: AgentId(member.agent),
            identity: member.identity(),
            leader: Cell::new(replicas[0]),
            replicas,
        }
    }

    /// A new session at the nodes' time `now`, named `name`.
    pub fn session(&self, name: [u8; 16], now: u64) -> Session {
        Session {
            key: self.key.verifying_key().to_bytes(),
            name,
            t0: now,
        }
    }

    /// The call of `name` with `arguments` at `sequence` of `session`.
    pub fn call(&self, session: Session, sequence: u64, name: &str, arguments: Vec<u8>) -> Vec<u8> {
        signed_call(
            &self.identity,
            &self.key,
            session,
            sequence,
            InstanceId(INSTANCE),
            method(name),
            arguments,
        )
        .encode()
    }

    /// The query of `name` with `arguments`, good until `now` and a margin.
    pub fn query(&self, now: u64, name: &str, arguments: Vec<u8>) -> Vec<u8> {
        query_of(&self.key, &self.identity, now, method(name), arguments)
    }
}

fn query_of(
    key: &SigningKey,
    identity: &[u8; 32],
    now: u64,
    method: MethodId,
    arguments: Vec<u8>,
) -> Vec<u8> {
    signed_query(
        identity,
        key,
        now + QUERY_GOOD_MS,
        Consistency::Applied { at: 0 },
        InstanceId(INSTANCE),
        method,
        arguments,
    )
    .encode()
}

/// What `Personal` answered: its reply, its error, or the node's refusal.
pub enum Answer<T> {
    Reply(T),
    Error(PersonalError),
    Other(String),
}

impl<T: Decode> Answer<T> {
    pub fn of(answer: &Result<Response, String>) -> Self {
        match answer {
            Ok(Response::Ran {
                outcome: Outcome::Done(bytes),
                ..
            }) => match T::decode_exact(bytes) {
                Some(reply) => Answer::Reply(reply),
                None => Answer::Other("a reply it cannot read".into()),
            },
            Ok(Response::Ran {
                outcome:
                    Outcome::Failed {
                        code: Failure::Handler,
                        detail,
                    },
                ..
            }) => match PersonalError::decode_exact(detail) {
                Some(error) => Answer::Error(error),
                None => Answer::Other("Failed(Handler)".into()),
            },
            other => Answer::Other(crate::engine::stats::refusal(other)),
        }
    }

    /// Its name, as a record counts it: the reply's is "ok".
    pub fn name(&self) -> String {
        match self {
            Answer::Reply(_) => "ok".into(),
            Answer::Error(error) => format!("{error:?}")
                .split(|c: char| !c.is_alphanumeric())
                .next()
                .unwrap_or("?")
                .to_string(),
            Answer::Other(other) => other.clone(),
        }
    }
}

/// How many of `members` admit their device: each read's `overview` by its
/// sync key, through the onion, until it answers or `within` passes.
pub fn admitted<'a>(
    nodes: &[DeployedNode],
    client: [u8; 32],
    seed: u64,
    members: impl Iterator<Item = &'a Member>,
    within: Duration,
) -> Result<u64, String> {
    let members: Vec<&Member> = members.collect();
    let executor = LocalExecutor::new();
    let nodes = Rc::new(Nodes::new(nodes, client)?);
    smol::block_on(executor.run(async {
        nodes.learn_time().await?;
        let until = Instant::now() + within;
        let mut waiting: Vec<&Member> = members;
        let mut admitted = 0;
        while !waiting.is_empty() {
            let mut left = Vec::new();
            for batch in waiting.chunks(64) {
                let tasks: Vec<_> = batch
                    .iter()
                    .map(|member| {
                        let nodes = nodes.clone();
                        let device = Device::sync(seed, member);
                        executor.spawn(async move {
                            let node = device.replicas[0];
                            let query = device.query(nodes.now(), "overview", Vec::new());
                            let answer = nodes.query(node, device.agent, &query).await;
                            matches!(
                                Answer::<vos_wire::personal::Overview>::of(&answer),
                                Answer::Reply(_)
                            )
                        })
                    })
                    .collect();
                for (member, task) in batch.iter().zip(tasks) {
                    if task.await {
                        admitted += 1;
                    } else {
                        left.push(*member);
                    }
                }
            }
            waiting = left;
            if waiting.is_empty() || Instant::now() >= until || crate::hosts::interrupted() {
                break;
            }
            smol::Timer::after(Duration::from_secs(1)).await;
        }
        if !waiting.is_empty() {
            eprintln!(
                "{} personal agents not admitting their device within {} s, agent {} among them",
                waiting.len(),
                within.as_secs(),
                waiting[0].agent
            );
        }
        Ok(admitted)
    }))
}
