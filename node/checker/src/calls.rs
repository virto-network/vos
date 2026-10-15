//! Calls and queries as the tests make them: a call's total, and a signed
//! query.

use std::fmt::Debug;

use ed25519_dalek::{Signer, SigningKey};
use vos_node::{CallError, Reply};
use vos_wire::ids::{InstanceId, MethodId};
use vos_wire::ingress::{Consistency, QueryCall, Response, query_message};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

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
