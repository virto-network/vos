//! The store's key layout, and the codecs of the rows it keeps for each
//! agent and for the node.

use fjall::Slice;
use vos_wire::ids::AgentId;

use super::{BlobRef, HardState, LogEntry, Membership, NodeNumber};

/// The first byte of an agent-relative system key ([`vos_wire::keys`]).
pub(super) const SYSTEM: u8 = 0x00;
/// After an agent id, the node's own rows for the agent: above every
/// epoch (`0..=0xfe`), so no agent row reaches them.
pub(super) const NODE: u8 = 0xff;

/// The epoch after `epoch`, in the cycle `0..=0xfe`.
pub fn next_epoch(epoch: u8) -> u8 {
    if epoch >= NODE - 1 { 0 } else { epoch + 1 }
}
/// The id no agent gets: node-wide records live under its node rows.
pub const NODE_AGENT: AgentId = AgentId(u32::MAX);

/// The node's rows, under an agent's id (or [`NODE_AGENT`]'s).
#[derive(Clone, Copy)]
#[repr(u8)]
pub(super) enum NodeRow {
    Applied = 0x00,
    Agent = 0x01,
    // 0x02 to 0x05 are unused.
    Hard = 0x06,
    LogStart = 0x07,
    Membership = 0x08,
    Epoch = 0x09,
    Secret = 0x0a,
    LastResult = 0x0b,
    Placement = 0x0c,
    Incarnation = 0x0d,
    VoteFloor = 0x0e,
    AnchorKey = 0x0f,
}

pub(super) fn agent_key(agent: AgentId, epoch: u8, key: &[u8]) -> Vec<u8> {
    [&agent.0.to_be_bytes()[..], &[epoch], key].concat()
}

/// The bytes before an agent's relative keys.
pub(super) const AGENT_KEY_PREFIX: usize = 5;

pub(super) fn node_row(agent: AgentId, row: NodeRow) -> Vec<u8> {
    [&agent.0.to_be_bytes()[..], &[NODE, row as u8]].concat()
}

pub(super) fn registry_prefix() -> Vec<u8> {
    node_row(NODE_AGENT, NodeRow::Agent)
}

/// A node-wide record: under the node's reserved agent id.
pub(super) fn node_record(row: NodeRow, rest: &[u8]) -> Vec<u8> {
    [node_row(NODE_AGENT, row), rest.to_vec()].concat()
}

pub(super) fn be_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

pub(super) fn log_key(agent: AgentId, index: u64) -> Vec<u8> {
    [&agent.0.to_be_bytes()[..], &index.to_be_bytes()].concat()
}

pub(super) fn log_index(key: &[u8]) -> Option<u64> {
    be_u64(key.get(4..)?)
}

pub(super) fn encode_entry(entry: &LogEntry) -> Vec<u8> {
    [&entry.term.to_be_bytes()[..], &entry.payload()].concat()
}

pub(super) fn decode_entry(bytes: &[u8]) -> Option<LogEntry> {
    let (term, payload) = bytes.split_first_chunk::<8>()?;
    LogEntry::from_payload(u64::from_be_bytes(*term), payload)
}

/// The blobs a stored entry names, its body unread.
pub(super) fn entry_blobs(bytes: &[u8]) -> Option<Vec<BlobRef>> {
    let (_, payload) = bytes.split_first_chunk::<8>()?;
    LogEntry::blob_refs(payload)
}

/// An agent's epoch, from its row: the first when it has none.
pub(super) fn epoch(row: Option<Slice>) -> u8 {
    row.and_then(|bytes| bytes.first().copied()).unwrap_or(0)
}

/// An agent's applied index, from its row.
pub(super) fn applied(row: Option<Slice>) -> Option<u64> {
    row.and_then(|bytes| be_u64(&bytes))
}

/// A log position, its index and term, as the log start's and the vote
/// floor's rows begin.
pub(super) fn encode_position(index: u64, term: u64) -> [u8; 16] {
    let mut out = [0; 16];
    out[..8].copy_from_slice(&index.to_be_bytes());
    out[8..].copy_from_slice(&term.to_be_bytes());
    out
}

pub(super) fn decode_position(bytes: &[u8]) -> Option<(u64, u64)> {
    Some((be_u64(bytes.get(..8)?)?, be_u64(bytes.get(8..16)?)?))
}

/// The time and seed of an agent's last work result.
pub(super) fn encode_last_result(time: u64, seed: &[u8; 32]) -> Vec<u8> {
    [&time.to_be_bytes()[..], seed].concat()
}

pub(super) fn decode_last_result(bytes: &[u8]) -> Option<(u64, [u8; 32])> {
    let time = be_u64(bytes.get(..8)?)?;
    let seed = bytes.get(8..40)?.try_into().ok()?;
    Some((time, seed))
}

pub(super) fn encode_hard(hard: &HardState) -> Vec<u8> {
    let mut out = hard.term.to_be_bytes().to_vec();
    match hard.vote {
        Some(vote) => out.extend_from_slice(&[1, vote]),
        None => out.extend_from_slice(&[0, 0]),
    }
    out.extend_from_slice(&hard.commit.to_be_bytes());
    out
}

pub(super) fn decode_hard(bytes: &[u8]) -> Option<HardState> {
    let (term, rest) = bytes.split_first_chunk::<8>()?;
    let (vote, rest) = rest.split_first_chunk::<2>()?;
    Some(HardState {
        term: u64::from_be_bytes(*term),
        vote: (vote[0] == 1).then_some(vote[1]),
        commit: be_u64(rest)?,
    })
}

fn encode_nodes(out: &mut Vec<u8>, nodes: &[NodeNumber]) {
    out.push(u8::try_from(nodes.len()).expect("at most 255 replicas"));
    out.extend_from_slice(nodes);
}

fn decode_nodes(bytes: &[u8]) -> Option<(Vec<NodeNumber>, &[u8])> {
    let (&count, rest) = bytes.split_first()?;
    let (nodes, rest) = rest.split_at_checked(usize::from(count))?;
    Some((nodes.to_vec(), rest))
}

/// A replica set as a replica adopted it: the index that established it,
/// when known, then its configuration.
pub(super) fn encode_membership(membership: &Membership) -> Vec<u8> {
    let index = match membership.index {
        Some(index) => [&[1][..], &index.to_be_bytes()].concat(),
        None => vec![0],
    };
    let configuration = encode_configuration(&membership.members, membership.joint_old.as_deref());
    [index, configuration].concat()
}

pub(super) fn decode_membership(bytes: &[u8]) -> Option<Membership> {
    let (&has_index, mut rest) = bytes.split_first()?;
    let index = if has_index == 1 {
        let (index, after) = rest.split_first_chunk::<8>()?;
        rest = after;
        Some(u64::from_be_bytes(*index))
    } else {
        None
    };
    let (members, joint_old) = decode_configuration(rest)?;
    Some(Membership {
        index,
        members,
        joint_old,
    })
}

/// A configuration entry's body: the replica set, and the old one while
/// joint.
pub fn encode_configuration(members: &[NodeNumber], joint_old: Option<&[NodeNumber]>) -> Vec<u8> {
    let mut out = Vec::new();
    encode_nodes(&mut out, members);
    match joint_old {
        Some(old) => {
            out.push(1);
            encode_nodes(&mut out, old);
        }
        None => out.push(0),
    }
    out
}

/// The replica set, and the old one while joint, from a configuration
/// entry's body.
pub fn decode_configuration(body: &[u8]) -> Option<(Vec<NodeNumber>, Option<Vec<NodeNumber>>)> {
    let (members, rest) = decode_nodes(body)?;
    let (&has_old, rest) = rest.split_first()?;
    let joint_old = if has_old == 1 {
        Some(decode_nodes(rest)?.0)
    } else {
        None
    };
    Some((members, joint_old))
}
