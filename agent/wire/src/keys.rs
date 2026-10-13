//! The layout of an agent's state, as keys relative to the agent.
//!
//! The node stores each agent's keys under its own prefix. Integers are
//! big-endian, so a prefix scan returns them in order.

use alloc::vec::Vec;

use crate::Encode;
use crate::ids::{AgentId, InstanceId, Principal, Session, SessionId};

/// Who owns a row, its key's first byte: the agent itself, or one of its
/// instances.
#[derive(Clone, Copy)]
#[repr(u8)]
enum Owner {
    System = 0x00,
    Instance = 0x01,
}

/// An instance's row, after its id: its struct state, or a table's row.
#[derive(Clone, Copy)]
#[repr(u8)]
enum Part {
    Struct = 0x00,
    Table = 0x01,
}

/// The agent's own rows, each tagged after [`Owner::System`].
#[derive(Clone, Copy)]
#[repr(u8)]
enum Row {
    Installed = 0x01,
    Member = 0x02,
    Session = 0x03,
    Reply = 0x04,
    PairIn = 0x05,
    Outbox = 0x06,
    PairOut = 0x07,
    Acked = 0x08,
    Version = 0x09,
    SessionIndex = 0x0a,
    NextSession = 0x0b,
    LiveSessions = 0x0c,
    BatchTime = 0x0d,
    SessionOf = 0x0e,
    Expiry = 0x0f,
    KeySessions = 0x10,
}

impl Row {
    /// The two bytes every key of this row starts with.
    const fn prefix(self) -> [u8; 2] {
        [Owner::System as u8, self as u8]
    }
}

fn key(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// An instance's struct state.
pub fn instance_struct(instance: InstanceId) -> Vec<u8> {
    key(&[
        &[Owner::Instance as u8],
        &instance.0.to_be_bytes(),
        &[Part::Struct as u8],
    ])
}

/// The prefix of every row of one of an instance's tables. `tag` is derived
/// from the table field's name.
pub fn table_prefix(instance: InstanceId, tag: u32) -> Vec<u8> {
    key(&[
        &[Owner::Instance as u8],
        &instance.0.to_be_bytes(),
        &[Part::Table as u8],
        &tag.to_be_bytes(),
    ])
}

/// The prefix of everything an instance owns; its ABI reaches nothing else.
pub fn instance_prefix(instance: InstanceId) -> Vec<u8> {
    key(&[&[Owner::Instance as u8], &instance.0.to_be_bytes()])
}

/// The program an instance runs.
pub fn installed(instance: InstanceId) -> Vec<u8> {
    key(&[&Row::Installed.prefix(), &instance.0.to_be_bytes()])
}

/// The prefix of every instance's [`installed`] row.
pub fn installed_prefix() -> Vec<u8> {
    Row::Installed.prefix().to_vec()
}

/// A principal's role byte in this agent.
pub fn member(principal: &Principal) -> Vec<u8> {
    key(&[&Row::Member.prefix(), &principal.encode()])
}

/// A session's high-water mark and last activity, for this agent.
pub fn session(session: SessionId) -> Vec<u8> {
    key(&[&Row::Session.prefix(), &session.0.to_be_bytes()])
}

/// The length of a [`session_index`] key.
const SESSION_INDEX_LEN: usize = 2 + 32 + 16 + 8;

/// A session's compact id, by its triple: key, name, then t0 big-endian,
/// so one key's sessions sit together.
pub fn session_index(session: &Session) -> Vec<u8> {
    session_index_key(session).to_vec()
}

/// [`session_index`] with no allocation.
pub fn session_index_key(session: &Session) -> [u8; SESSION_INDEX_LEN] {
    let mut key = [0u8; SESSION_INDEX_LEN];
    key[..2].copy_from_slice(&Row::SessionIndex.prefix());
    key[2..34].copy_from_slice(&session.key);
    key[34..50].copy_from_slice(&session.name);
    key[50..].copy_from_slice(&session.t0.to_be_bytes());
    key
}

/// The session a compact id stands for, whole: written once, when
/// accumulate creates it.
pub fn session_of(session: SessionId) -> Vec<u8> {
    key(&[&Row::SessionOf.prefix(), &session.0.to_be_bytes()])
}

/// A session's row in the expiry index: its bucket (a time divided by
/// [`crate::defaults::SESSION_BUCKET_MS`]), then its id, big-endian, so
/// a scan meets the oldest first. A session's row lies at or before its
/// mark's bucket.
pub fn expiry(bucket: u64, session: SessionId) -> Vec<u8> {
    key(&[
        &Row::Expiry.prefix(),
        &bucket.to_be_bytes(),
        &session.0.to_be_bytes(),
    ])
}

/// The length of an [`expiry`] key.
const EXPIRY_LEN: usize = 2 + 8 + 8;

/// The prefix of the expiry index.
pub fn expiry_prefix() -> Vec<u8> {
    Row::Expiry.prefix().to_vec()
}

/// The bucket and session an [`expiry`] key names; `None` for any other
/// key.
pub fn expiry_entry(key: &[u8]) -> Option<(u64, SessionId)> {
    if key.len() != EXPIRY_LEN || key[..2] != Row::Expiry.prefix() {
        return None;
    }
    let bucket = u64::from_be_bytes(key[2..10].try_into().ok()?);
    let session = u64::from_be_bytes(key[10..].try_into().ok()?);
    Some((bucket, SessionId(session)))
}

/// How many sessions a key holds at this agent.
pub fn key_sessions(client: &[u8; 32]) -> Vec<u8> {
    key(&[&Row::KeySessions.prefix(), client])
}

/// The id the next session gets: ids are never reused.
pub fn next_session() -> Vec<u8> {
    Row::NextSession.prefix().to_vec()
}

/// How many sessions the agent holds.
pub fn live_sessions() -> Vec<u8> {
    Row::LiveSessions.prefix().to_vec()
}

/// The high-water mark of work-result time: it never goes back.
pub fn batch_time() -> Vec<u8> {
    Row::BatchTime.prefix().to_vec()
}

/// A kept reply, by session and sequence; the window keeps the last
/// [`crate::defaults::REPLY_WINDOW`].
pub fn reply(session: SessionId, sequence: u64) -> Vec<u8> {
    key(&[
        &Row::Reply.prefix(),
        &session.0.to_be_bytes(),
        &sequence.to_be_bytes(),
    ])
}

/// The high-water mark of messages received from an agent.
pub fn pair_in(from: AgentId) -> Vec<u8> {
    key(&[&Row::PairIn.prefix(), &from.0.to_be_bytes()])
}

/// A message waiting in the outbox until acknowledged.
pub fn outbox(to: AgentId, sequence: u64) -> Vec<u8> {
    key(&[
        &Row::Outbox.prefix(),
        &to.0.to_be_bytes(),
        &sequence.to_be_bytes(),
    ])
}

/// The prefix of the outbox, for the node to send after apply.
pub fn outbox_prefix() -> Vec<u8> {
    Row::Outbox.prefix().to_vec()
}

/// The next sequence number for messages to an agent.
pub fn pair_out(to: AgentId) -> Vec<u8> {
    key(&[&Row::PairOut.prefix(), &to.0.to_be_bytes()])
}

/// The highest sequence an agent acknowledged.
pub fn acked(to: AgentId) -> Vec<u8> {
    key(&[&Row::Acked.prefix(), &to.0.to_be_bytes()])
}

/// The agent's state version: applied, non-skipped work results.
pub fn version() -> Vec<u8> {
    Row::Version.prefix().to_vec()
}

/// Whether `key` lies inside `instance`'s own state.
pub fn owned_by(key: &[u8], instance: InstanceId) -> bool {
    key.starts_with(&instance_prefix(instance))
}
