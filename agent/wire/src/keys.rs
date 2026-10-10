//! The layout of an agent's state, as keys relative to the agent.
//!
//! The node stores each agent's keys under its own prefix. Integers are
//! big-endian, so a prefix scan returns them in order.

use alloc::vec::Vec;

use crate::Encode;
use crate::ids::{AgentId, InstanceId, Principal, SessionId};

const SYSTEM: u8 = 0x00;
const INSTANCE: u8 = 0x01;

const INSTANCE_STRUCT: u8 = 0x00;
const INSTANCE_TABLE: u8 = 0x01;

const INSTALLED: u8 = 0x01;
const MEMBER: u8 = 0x02;
const SESSION: u8 = 0x03;
const REPLY: u8 = 0x04;
const PAIR_IN: u8 = 0x05;
const OUTBOX: u8 = 0x06;
const PAIR_OUT: u8 = 0x07;
const ACKED: u8 = 0x08;
const VERSION: u8 = 0x09;

fn key(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// An instance's struct state.
pub fn instance_struct(instance: InstanceId) -> Vec<u8> {
    key(&[&[INSTANCE], &instance.0.to_be_bytes(), &[INSTANCE_STRUCT]])
}

/// The prefix of every row of one of an instance's tables. `tag` is derived
/// from the table field's name.
pub fn table_prefix(instance: InstanceId, tag: u32) -> Vec<u8> {
    key(&[
        &[INSTANCE],
        &instance.0.to_be_bytes(),
        &[INSTANCE_TABLE],
        &tag.to_be_bytes(),
    ])
}

/// The prefix of everything an instance owns; its ABI reaches nothing else.
pub fn instance_prefix(instance: InstanceId) -> Vec<u8> {
    key(&[&[INSTANCE], &instance.0.to_be_bytes()])
}

/// The program an instance runs.
pub fn installed(instance: InstanceId) -> Vec<u8> {
    key(&[&[SYSTEM, INSTALLED], &instance.0.to_be_bytes()])
}

/// The prefix of every instance's [`installed`] row.
pub fn installed_prefix() -> Vec<u8> {
    key(&[&[SYSTEM, INSTALLED]])
}

/// A principal's role byte in this agent.
pub fn member(principal: &Principal) -> Vec<u8> {
    key(&[&[SYSTEM, MEMBER], &principal.encode()])
}

/// A session's high-water mark and last activity, for this agent.
pub fn session(session: SessionId) -> Vec<u8> {
    key(&[&[SYSTEM, SESSION], &session.0.to_be_bytes()])
}

/// A kept reply, by session and sequence; the window keeps the last
/// [`crate::defaults::REPLY_WINDOW`].
pub fn reply(session: SessionId, sequence: u64) -> Vec<u8> {
    key(&[
        &[SYSTEM, REPLY],
        &session.0.to_be_bytes(),
        &sequence.to_be_bytes(),
    ])
}

/// The high-water mark of messages received from an agent.
pub fn pair_in(from: AgentId) -> Vec<u8> {
    key(&[&[SYSTEM, PAIR_IN], &from.0.to_be_bytes()])
}

/// A message waiting in the outbox until acknowledged.
pub fn outbox(to: AgentId, sequence: u64) -> Vec<u8> {
    key(&[
        &[SYSTEM, OUTBOX],
        &to.0.to_be_bytes(),
        &sequence.to_be_bytes(),
    ])
}

/// The prefix of the outbox, for the node to send after apply.
pub fn outbox_prefix() -> Vec<u8> {
    key(&[&[SYSTEM, OUTBOX]])
}

/// The next sequence number for messages to an agent.
pub fn pair_out(to: AgentId) -> Vec<u8> {
    key(&[&[SYSTEM, PAIR_OUT], &to.0.to_be_bytes()])
}

/// The highest sequence an agent acknowledged.
pub fn acked(to: AgentId) -> Vec<u8> {
    key(&[&[SYSTEM, ACKED], &to.0.to_be_bytes()])
}

/// The agent's state version: applied, non-skipped work results.
pub fn version() -> Vec<u8> {
    key(&[&[SYSTEM, VERSION]])
}

/// Whether `key` lies inside `instance`'s own state.
pub fn owned_by(key: &[u8], instance: InstanceId) -> bool {
    key.starts_with(&instance_prefix(instance))
}
