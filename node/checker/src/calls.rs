//! Calls and queries as the tests make them: a call's total, an install
//! at the leader, and a signed query.

use std::fmt::Debug;
use std::ops::Deref;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use vos_node::client::Client;
use vos_node::{CallError, Node, Reply};
use vos_wire::ids::{AgentId, InstanceId, MethodId};
use vos_wire::ingress::{Consistency, QueryCall, Response, query_message};
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

/// The counter's total `answer` carries: its call must have run to
/// completion.
#[track_caller]
pub fn done(answer: impl Total) -> u64 {
    match answer.total() {
        Some(total) => total,
        None => panic!("not done: {answer:?}"),
    }
}

/// Package `elf` installed as `instance` of `agent` at the node `leader`
/// names on each try: sent again while the node it reached no longer
/// leads, as a client follows its leader. An install sent again
/// overwrites. It must run.
#[track_caller]
pub fn install_at_leader<N: Deref<Target = Node>>(
    leader: impl Fn() -> N,
    agent: AgentId,
    instance: InstanceId,
    elf: &[u8],
) {
    let until = Instant::now() + crate::spaces::IN_PROCESS_WAIT;
    loop {
        match smol::block_on(leader().install(agent, instance, elf, Vec::new())) {
            Ok(Reply::Ran(Outcome::Done(_))) => return,
            Err(CallError::NotLeader(_)) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(10));
            }
            other => panic!("the install: {other:?}"),
        }
    }
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
    let public = key.verifying_key().to_bytes();
    let message = query_message(
        identity,
        &public,
        not_after,
        consistency,
        instance,
        method,
        &[],
    );
    QueryCall {
        key: public,
        not_after,
        consistency,
        instance,
        method,
        arguments: Vec::new(),
        signature: key.sign(&message).to_bytes(),
    }
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
