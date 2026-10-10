//! The layout of an agent's state, as keys relative to the agent.
//!
//! The node stores each agent's keys under its own prefix. Integers are
//! big-endian, so a prefix scan returns them in order.

use alloc::vec::Vec;

use crate::Encode;
use crate::ids::{AgentId, InstanceId, Principal, Session, SessionId};

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
const SESSION_INDEX: u8 = 0x0a;
const NEXT_SESSION: u8 = 0x0b;
const LIVE_SESSIONS: u8 = 0x0c;
const BATCH_TIME: u8 = 0x0d;
const SESSION_OF: u8 = 0x0e;

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

/// The length of a [`session_index`] key.
pub const SESSION_INDEX_LEN: usize = 2 + 32 + 16 + 8;

/// A session's compact id, by its triple: key, name, then t0 big-endian,
/// so one key's sessions sit together.
pub fn session_index(session: &Session) -> Vec<u8> {
    session_index_key(session).to_vec()
}

/// [`session_index`] with no allocation.
pub fn session_index_key(session: &Session) -> [u8; SESSION_INDEX_LEN] {
    let mut key = [0u8; SESSION_INDEX_LEN];
    key[..2].copy_from_slice(&[SYSTEM, SESSION_INDEX]);
    key[2..34].copy_from_slice(&session.key);
    key[34..50].copy_from_slice(&session.name);
    key[50..].copy_from_slice(&session.t0.to_be_bytes());
    key
}

/// The session a compact id stands for, whole: written once, when
/// accumulate creates it.
pub fn session_of(session: SessionId) -> Vec<u8> {
    key(&[&[SYSTEM, SESSION_OF], &session.0.to_be_bytes()])
}

/// The id the next session gets: ids are never reused.
pub fn next_session() -> Vec<u8> {
    key(&[&[SYSTEM, NEXT_SESSION]])
}

/// How many sessions the agent holds.
pub fn live_sessions() -> Vec<u8> {
    key(&[&[SYSTEM, LIVE_SESSIONS]])
}

/// The high-water mark of work-result time: it never goes back.
pub fn batch_time() -> Vec<u8> {
    key(&[&[SYSTEM, BATCH_TIME]])
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
