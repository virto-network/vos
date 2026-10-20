//! Calls and queries as the tests make them: what an answer carries (the
//! counter's total, whether it ran), an operator's install and one sent
//! to the leader, a query at one node and a signed one, a method's id
//! once its schema is served, and a call sent again until answered.

use std::fmt::Debug;
use std::ops::Deref;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use vos_node::client::{Client, Target};
use vos_node::{CallError, Node, Reply};
use vos_wire::ids::{AgentId, InstanceId, MethodId};
use vos_wire::ingress::{Consistency, Install, Response};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

use crate::processes::PROCESS_WAIT;
use crate::wait_until;

/// A call's answer, which carries the counter's total once the call ran
/// to completion: a node's reply, or its ingress's answer.
pub trait Total: Debug {
    /// The counter's total, if the call ran to completion.
    fn total(&self) -> Option<u64>;
}

impl Total for Result<Reply, CallError> {
    fn total(&self) -> Option<u64> {
        match self {
            Ok(Reply::Ran(Outcome::Done(bytes))) => Some(u64::decode(bytes).unwrap().0),
            _ => None,
        }
    }
}

impl Total for Response {
    fn total(&self) -> Option<u64> {
        match self {
            Response::Ran {
                outcome: Outcome::Done(bytes),
                ..
            } => Some(u64::decode(bytes).unwrap().0),
            _ => None,
        }
    }
}

/// An answer that says whether its call ran to completion: a node's
/// reply, or its ingress's answer.
pub trait Ran: Debug {
    fn ran(&self) -> bool;
}

impl Ran for Result<Reply, CallError> {
    fn ran(&self) -> bool {
        matches!(self, Ok(Reply::Ran(Outcome::Done(_))))
    }
}

impl Ran for Response {
    fn ran(&self) -> bool {
        matches!(
            self,
            Response::Ran {
                outcome: Outcome::Done(_),
                ..
            }
        )
    }
}

/// `answer`'s install must have run to completion.
#[track_caller]
pub fn installed(answer: impl Ran) {
    assert!(answer.ran(), "the install: {answer:?}");
}

/// The counter's total `answer` carries: its call must have run to
/// completion.
#[track_caller]
pub fn done(answer: impl Total) -> u64 {
    match answer.total() {
        Some(total) => total,
        None => panic!("not done: {answer:?}"),
    }
}

/// An operator's install of package `elf` as `instance`, granting no
/// roles.
pub fn install_of(instance: InstanceId, elf: &[u8]) -> Install {
    Install {
        instance,
        elf: elf.to_vec(),
        roles: Vec::new(),
    }
}

/// Package `elf` installed as `instance` of `agent` at the node `leader`
/// names on each try: sent again while the node it reached no longer
/// leads, as a client follows its leader, or once it answered that it may
/// have run, its node's deadline passed while a loaded host derived the
/// programs. An install sent again overwrites. It must run.
#[track_caller]
pub fn install_at_leader<N: Deref<Target = Node>>(
    leader: impl Fn() -> N,
    agent: AgentId,
    instance: InstanceId,
    elf: &[u8],
) {
    // Past one try's whole deadline, for the next.
    let until = Instant::now() + 2 * crate::spaces::IN_PROCESS_WAIT;
    loop {
        match smol::block_on(leader().install(agent, instance, elf, Vec::new())) {
            Err(CallError::NotLeader(_) | CallError::TimedOut) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(10));
            }
            answer => return installed(answer),
        }
    }
}

/// A query of `agent`'s `instance`'s `method`, without arguments, at the
/// node `target` reaches and nowhere else: by `key`, at the agent whose
/// identity is `identity`, good for a minute. Its answer, if it gave one.
pub fn query_at(
    target: &Target,
    agent: AgentId,
    identity: &[u8; 32],
    key: &SigningKey,
    consistency: Consistency,
    instance: InstanceId,
    method: MethodId,
) -> Option<Response> {
    let not_after = vos_node::wall_clock() + 60_000;
    let query = signed_query(identity, key, not_after, consistency, instance, method);
    let path = format!("/agents/{}/queries", agent.0);
    let (_, body) = vos_node::client::post(target, &path, &query).ok()?;
    Response::decode(&body).ok().map(|(answer, _)| answer)
}

/// A query of `instance`'s `method`, without arguments, at the agent
/// whose identity is `identity`: signed by `key`, good until `not_after`.
pub fn signed_query(
    identity: &[u8; 32],
    key: &SigningKey,
    not_after: u64,
    consistency: Consistency,
    instance: InstanceId,
    method: MethodId,
) -> Vec<u8> {
    let arguments = Vec::new();
    vos_node::client::signed_query(
        identity,
        key,
        not_after,
        consistency,
        instance,
        method,
        arguments,
    )
    .encode()
}

/// The method `name` of `agent`'s `instance`, read once its schema is
/// served.
pub fn served_method(
    client: &mut Client,
    agent: AgentId,
    instance: InstanceId,
    name: &str,
) -> MethodId {
    let mut schema = None;
    wait_until("the schema is served", PROCESS_WAIT, || {
        schema = client.schema(agent, instance).ok().flatten();
        schema.is_some()
    });
    schema
        .unwrap()
        .method_id(name)
        .unwrap_or_else(|| panic!("no method {name}"))
}

/// Call `method` of `agent`'s `instance` with `arguments` through
/// `client`, sending again with the same sequence until it is answered:
/// the counter's total it answers with.
pub fn call(
    client: &mut Client,
    agent: AgentId,
    instance: InstanceId,
    method: MethodId,
    arguments: &[u8],
) -> u64 {
    let mut answered = None;
    wait_until("a call is answered", PROCESS_WAIT, || {
        answered = client
            .call(agent, instance, method, arguments)
            .ok()
            .and_then(|answer| answer.total());
        answered.is_some()
    });
    answered.unwrap()
}

/// Call `method` of `agent`'s `instance` with `by` through `client`, as
/// [`call`] does.
pub fn increment(
    client: &mut Client,
    agent: AgentId,
    instance: InstanceId,
    method: MethodId,
    by: u64,
) -> u64 {
    call(client, agent, instance, method, &by.encode())
}
