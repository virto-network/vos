//! Signed requests as a client builds them: a call in its session, a
//! query, and a read of a workflow, each signed by its key for the agent
//! whose identity it names; and an operator's request, signed for one
//! node.

use ed25519_dalek::{Signer, SigningKey};
use vos_api::{Kind, Operated};
use vos_wire::ids::{InstanceId, MethodId, Session, WorkflowId};
use vos_wire::ingress::{
    Call, Consistency, NodeId, QueryCall, WORKFLOW_READ_HORIZON_MS, WorkflowRead,
    workflow_read_horizon,
};

/// A call at `sequence` of `session`, whose key is `key`, to the agent
/// whose identity is `identity`.
pub fn signed_call(
    identity: &[u8; 32],
    key: &SigningKey,
    session: Session,
    sequence: u64,
    instance: InstanceId,
    method: MethodId,
    arguments: Vec<u8>,
) -> Call {
    let mut call = Call {
        session,
        sequence,
        instance,
        method,
        arguments,
        signature: [0; 64],
    };
    call.signature = key.sign(&call.message(identity)).to_bytes();
    call
}

/// A query by `key` to the agent whose identity is `identity`, good until
/// `not_after` by the node's clock.
pub fn signed_query(
    identity: &[u8; 32],
    key: &SigningKey,
    not_after: u64,
    consistency: Consistency,
    instance: InstanceId,
    method: MethodId,
    arguments: Vec<u8>,
) -> QueryCall {
    let mut query = QueryCall {
        key: key.verifying_key().to_bytes(),
        not_after,
        consistency,
        instance,
        method,
        arguments,
        signature: [0; 64],
    };
    query.signature = key.sign(&query.message(identity)).to_bytes();
    query
}

/// A read of `workflow` by `key`, its owner, at the agent whose identity
/// is `identity`, good until `not_after` by the node's clock, waiting up
/// to `wait_ms` for it to end.
pub fn signed_workflow_read(
    identity: &[u8; 32],
    key: &SigningKey,
    not_after: u64,
    consistency: Consistency,
    workflow: WorkflowId,
    wait_ms: u64,
) -> WorkflowRead {
    let mut read = WorkflowRead {
        key: key.verifying_key().to_bytes(),
        not_after,
        consistency,
        workflow,
        wait_ms,
        signature: [0; 64],
    };
    read.signature = key.sign(&read.message(identity)).to_bytes();
    read
}

/// How long a read of a workflow waiting `wait_ms`, signed when the
/// agents' time is `now`, is good: past its wait, within half the horizon
/// a node allows, so a node whose clock is off by as much either way takes
/// it.
pub fn workflow_read_not_after(now: u64, wait_ms: u64) -> u64 {
    now.saturating_add(workflow_read_horizon(wait_ms) - WORKFLOW_READ_HORIZON_MS / 2)
}

/// An operator request of `kind` holding `body`, signed by `key` for node
/// `node`, good until `expires_ms` by the node's clock, its command run
/// once by `nonce`.
pub fn signed_operated(
    node: NodeId,
    key: &SigningKey,
    kind: Kind,
    nonce: [u8; 16],
    expires_ms: u64,
    body: Vec<u8>,
) -> Operated {
    let mut operated = Operated {
        node,
        key: key.verifying_key().to_bytes(),
        nonce,
        expires_ms,
        body,
        signature: [0; 64],
    };
    operated.signature = key.sign(&operated.message(kind)).to_bytes();
    operated
}
