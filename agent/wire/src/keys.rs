//! The layout of an agent's state, as keys relative to the agent.
//!
//! The node stores each agent's keys under its own prefix. Integers are
//! big-endian, so a prefix scan returns them in order.
//!
//! Every key is prefix-free, as a tree over the whole keyspace needs: each
//! kind of row starts with its own tag, its fixed parts have fixed widths,
//! and a variable part comes last, escaped or hashed by its
//! [`Transform`] ([`vos_tree::keys`]).

use alloc::vec::Vec;

use scale::{Decode, Encode};
use vos_tree::Blake2b;

use crate::abi::{Failure, Rows, cap};
use crate::ids::{
    AgentId, InstanceId, MapId, Principal, ProgramHash, Session, SessionId, WorkflowId,
};

/// Who owns a row, its key's first byte: the agent itself, one of its
/// instances, or the node's root builder.
#[derive(Clone, Copy)]
#[repr(u8)]
enum Owner {
    System = 0x00,
    Instance = 0x01,
    Tree = 0x02,
}

/// An instance's row, after its id: its struct state, a table's row, or a
/// committed map's.
#[derive(Clone, Copy)]
#[repr(u8)]
enum Part {
    Struct = 0x00,
    Table = 0x01,
    Committed = 0x02,
}

/// How a table's keys become its row keys, as a Substrate map's hasher
/// does. The transform's tag follows the table's tag in its rows' prefix,
/// so tables of different transforms never share a subtree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub enum Transform {
    /// `H128(key) ‖ escape(key)`: rows iterate in hash order, and the tree's
    /// paths stay about log₂ n deep whatever keys clients choose.
    #[codec(index = 0)]
    Hashed,
    /// `escape(key)`: rows iterate in key order. Keys are at most
    /// [`crate::abi::cap::ORDERED_KEY`] bytes, which bounds a path's depth.
    #[codec(index = 1)]
    Ordered,
}

impl Transform {
    /// The transform's tag in a row key, as its encoding's.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Hashed => 0x00,
            Self::Ordered => 0x01,
        }
    }

    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x00 => Some(Self::Hashed),
            0x01 => Some(Self::Ordered),
            _ => None,
        }
    }

    /// `key` transformed: prefix-free, whatever its bytes.
    pub fn apply(self, key: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.room(key));
        self.append(key, &mut out);
        out
    }

    /// Append `key` transformed to `out`.
    pub fn append(self, key: &[u8], out: &mut Vec<u8>) {
        match self {
            Self::Hashed => vos_tree::keys::hashed_into(&Blake2b, key, out),
            Self::Ordered => vos_tree::keys::escape_into(key, out),
        }
    }

    /// The bytes `key` takes transformed, unless it holds a zero byte.
    fn room(self, key: &[u8]) -> usize {
        let hash = match self {
            Self::Hashed => 16,
            Self::Ordered => 0,
        };
        hash + key.len() + 2
    }

    /// The raw key a transformed one carries, if `transformed` is one whole.
    pub fn raw(self, transformed: &[u8]) -> Option<Vec<u8>> {
        let escaped = match self {
            Self::Hashed => transformed.get(16..)?,
            Self::Ordered => transformed,
        };
        match vos_tree::keys::unescape(escaped)? {
            (key, used) if used == escaped.len() => Some(key),
            _ => None,
        }
    }
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
    Due = 0x0f,
    KeySessions = 0x10,
    Dirty = 0x11,
    Seed = 0x12,
    Workflow = 0x13,
    Page = 0x14,
    NextWorkflow = 0x15,
    LiveWorkflows = 0x16,
    WorkflowPins = 0x17,
}

/// The root builder's rows, each tagged after [`Owner::Tree`]: a committed
/// map's, then the map's id, and the agent's own.
#[derive(Clone, Copy)]
#[repr(u8)]
enum TreeRow {
    Node = 0x00,
    Leaf = 0x01,
    Root = 0x02,
    Built = 0x03,
}

impl TreeRow {
    fn key(self, map: &MapId, rest: &[u8]) -> Vec<u8> {
        key(&[&[Owner::Tree as u8, self as u8], &map_key(map), rest])
    }
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

/// The prefix of every row of one of an instance's tables, of either
/// transform. `tag` is derived from the table field's name.
pub fn table_prefix(instance: InstanceId, tag: u32) -> Vec<u8> {
    key(&[
        &[Owner::Instance as u8],
        &instance.0.to_be_bytes(),
        &[Part::Table as u8],
        &tag.to_be_bytes(),
    ])
}

/// The prefix of a table's rows: each row's key follows it, transformed.
pub fn table_rows(instance: InstanceId, tag: u32, transform: Transform) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(TABLE_PREFIX);
    prefix_into(Part::Table, instance, tag, transform, &mut prefix);
    prefix
}

/// The length of a table's or committed map's prefix.
pub const TABLE_PREFIX: usize = 1 + 4 + 1 + 4 + 1;

/// Append the prefix of a table's or committed map's rows to `out`.
fn prefix_into(
    part: Part,
    instance: InstanceId,
    tag: u32,
    transform: Transform,
    out: &mut Vec<u8>,
) {
    out.push(Owner::Instance as u8);
    out.extend_from_slice(&instance.0.to_be_bytes());
    out.push(part as u8);
    out.extend_from_slice(&tag.to_be_bytes());
    out.push(transform.tag());
}

/// The part, tag and transform of the rows `rows` names; `None` for the
/// struct.
fn table_of(rows: Rows) -> Option<(Part, u32, Transform)> {
    match rows {
        Rows::Struct => None,
        Rows::Table { tag, transform } => Some((Part::Table, tag, transform)),
        Rows::Committed { tag, transform } => Some((Part::Committed, tag, transform)),
    }
}

/// The prefix of the rows `rows` names in `instance`'s state, and their
/// transform; `None` for the struct, which is one row.
pub fn rows_prefix(instance: InstanceId, rows: Rows) -> Option<(Vec<u8>, Transform)> {
    let (part, tag, transform) = table_of(rows)?;
    let mut prefix = Vec::with_capacity(TABLE_PREFIX);
    prefix_into(part, instance, tag, transform, &mut prefix);
    Some((prefix, transform))
}

/// The row of the raw key `key` in `rows`: the struct row under the empty
/// key, or the key transformed after its table's prefix. A struct key that
/// is not empty fails the invocation ([`Failure::Trapped`]); an ordered key
/// past [`cap::ORDERED_KEY`] exceeds a cap ([`Failure::Cap`]).
pub fn row(instance: InstanceId, rows: Rows, key: &[u8]) -> Result<Vec<u8>, Failure> {
    let Some((part, tag, transform)) = table_of(rows) else {
        return match key.is_empty() {
            true => Ok(instance_struct(instance)),
            false => Err(Failure::Trapped),
        };
    };
    if transform == Transform::Ordered && key.len() > cap::ORDERED_KEY {
        return Err(Failure::Cap);
    }
    let mut row = Vec::with_capacity(TABLE_PREFIX + transform.room(key));
    prefix_into(part, instance, tag, transform, &mut row);
    transform.append(key, &mut row);
    Ok(row)
}

/// The length of a committed map's id in its rows' keys.
const MAP_LEN: usize = 4 + 4 + 1;

/// A committed map's id as its rows' keys carry it: the instance, the tag,
/// then the transform.
fn map_key(map: &MapId) -> [u8; MAP_LEN] {
    let mut bytes = [0u8; MAP_LEN];
    bytes[..4].copy_from_slice(&map.instance.0.to_be_bytes());
    bytes[4..8].copy_from_slice(&map.tag.to_be_bytes());
    bytes[8] = map.transform.tag();
    bytes
}

fn map_of(bytes: &[u8]) -> Option<MapId> {
    let bytes: &[u8; MAP_LEN] = bytes.get(..MAP_LEN)?.try_into().ok()?;
    Some(MapId {
        instance: InstanceId(u32::from_be_bytes(bytes[..4].try_into().ok()?)),
        tag: u32::from_be_bytes(bytes[4..8].try_into().ok()?),
        transform: Transform::from_tag(bytes[8])?,
    })
}

/// The prefix of a committed map's value rows.
pub fn committed_rows(map: &MapId) -> Vec<u8> {
    committed(map, &[])
}

/// A committed map's value row, by its key already transformed (`key'`):
/// the value with the state version that wrote it
/// ([`crate::records::versioned`]).
pub fn committed(map: &MapId, transformed: &[u8]) -> Vec<u8> {
    let mut row = Vec::with_capacity(TABLE_PREFIX + transformed.len());
    prefix_into(
        Part::Committed,
        map.instance,
        map.tag,
        map.transform,
        &mut row,
    );
    row.extend_from_slice(transformed);
    row
}

/// Whether `key` is a committed map's value row, whose value carries the
/// version that wrote it.
pub fn is_committed(key: &[u8]) -> bool {
    key.len() > TABLE_PREFIX && key[0] == Owner::Instance as u8 && key[5] == Part::Committed as u8
}

/// The map and transformed key a value row's key names; `None` for any
/// other key.
pub fn committed_entry(key: &[u8]) -> Option<(MapId, &[u8])> {
    let (prefix, key) = key.split_first_chunk::<TABLE_PREFIX>()?;
    if prefix[0] != Owner::Instance as u8 || prefix[5] != Part::Committed as u8 {
        return None;
    }
    let map = MapId {
        instance: InstanceId(u32::from_be_bytes(prefix[1..5].try_into().ok()?)),
        tag: u32::from_be_bytes(prefix[6..10].try_into().ok()?),
        transform: Transform::from_tag(prefix[10])?,
    };
    Some((map, key))
}

/// A committed key accumulate wrote at `version`, for the root builder:
/// one row per write, so later writes never share a row with earlier ones.
/// The version comes first: the rows a build consumed, whose deletions an
/// LSM keeps a while, all lie before the versions it has yet to build.
pub fn dirty(version: u64, map: &MapId, key: &[u8]) -> Vec<u8> {
    let mut row = Vec::with_capacity(2 + 8 + MAP_LEN + key.len());
    row.extend_from_slice(&Row::Dirty.prefix());
    row.extend_from_slice(&version.to_be_bytes());
    row.extend_from_slice(&map_key(map));
    row.extend_from_slice(key);
    row
}

/// Where the dirty rows of `version` and later start.
pub fn dirty_from(version: u64) -> Vec<u8> {
    key(&[&Row::Dirty.prefix(), &version.to_be_bytes()])
}

/// The prefix of every dirty row, in version order.
pub fn dirty_prefix() -> Vec<u8> {
    Row::Dirty.prefix().to_vec()
}

/// The version, map and transformed key a dirty row's key names; `None`
/// for any other key.
pub fn dirty_entry(key: &[u8]) -> Option<(u64, MapId, &[u8])> {
    let rest = key.strip_prefix(&Row::Dirty.prefix())?;
    let version = u64::from_be_bytes(rest.get(..8)?.try_into().ok()?);
    let map = map_of(&rest[8..])?;
    Some((version, map, &rest[8 + MAP_LEN..]))
}

/// The seed of the work result that made `version`, kept while a committed
/// write of that version waits for the root builder: its leaves' salts
/// derive from it.
pub fn seed(version: u64) -> Vec<u8> {
    key(&[&Row::Seed.prefix(), &version.to_be_bytes()])
}

/// The prefix of the seed rows, in version order.
pub fn seed_prefix() -> Vec<u8> {
    Row::Seed.prefix().to_vec()
}

/// A branch of a committed map's tree, by its level and prefix
/// ([`vos_tree::NodeStore`]): the prefix's length follows from the level.
pub fn tree_node(map: &MapId, level: u16, prefix: &[u8]) -> Vec<u8> {
    TreeRow::Node.key(map, &[&level.to_be_bytes()[..], prefix].concat())
}

/// The prefix of a committed map's branch rows.
pub fn tree_nodes(map: &MapId) -> Vec<u8> {
    TreeRow::Node.key(map, &[])
}

/// A leaf of a committed map's tree, by its transformed key.
pub fn tree_leaf(map: &MapId, key: &[u8]) -> Vec<u8> {
    TreeRow::Leaf.key(map, key)
}

/// The prefix of a committed map's leaf rows.
pub fn tree_leaves(map: &MapId) -> Vec<u8> {
    TreeRow::Leaf.key(map, &[])
}

/// A committed map's tree's top, and its root as its last complete build
/// left it.
pub fn tree_root(map: &MapId) -> Vec<u8> {
    TreeRow::Root.key(map, &[])
}

/// The prefix of every committed map's root row.
pub fn tree_roots() -> Vec<u8> {
    [Owner::Tree as u8, TreeRow::Root as u8].to_vec()
}

/// The map a root row's key names; `None` for any other key.
pub fn tree_root_entry(key: &[u8]) -> Option<MapId> {
    let rest = key.strip_prefix(&[Owner::Tree as u8, TreeRow::Root as u8])?;
    (rest.len() == MAP_LEN).then(|| map_of(rest)).flatten()
}

/// The version through which every committed map's tree is built: no dirty
/// or seed row is left through it.
pub fn built() -> Vec<u8> {
    [Owner::Tree as u8, TreeRow::Built as u8].to_vec()
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

/// What a row of the due index brings: a session to collect once it has
/// expired, or a workflow's step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub enum Due {
    #[codec(index = 0)]
    Session(SessionId),
    /// Its first step, its deadline or timer, or its collection once ended.
    #[codec(index = 1)]
    Workflow(WorkflowId),
}

impl Due {
    fn tag(self) -> (u8, u64) {
        match self {
            Due::Session(id) => (0, id.0),
            Due::Workflow(id) => (1, id.0),
        }
    }
}

/// A row of the due index, which the leader reads to time its sweeps and
/// lists in them: the batch time it is due at, then its entry's kind and
/// id, big-endian, so a scan meets the earliest first. A session's row is
/// due once it may have expired ([`crate::expiry::due`]), and lies at or
/// before that.
pub fn due(at: u64, entry: Due) -> Vec<u8> {
    let (kind, id) = entry.tag();
    key(&[
        &Row::Due.prefix(),
        &at.to_be_bytes(),
        &[kind],
        &id.to_be_bytes(),
    ])
}

/// The length of a [`due`] key.
const DUE_LEN: usize = 2 + 8 + 1 + 8;

/// The prefix of the due index.
pub fn due_prefix() -> Vec<u8> {
    Row::Due.prefix().to_vec()
}

/// The time and entry a [`due`] key names; `None` for any other key.
pub fn due_entry(key: &[u8]) -> Option<(u64, Due)> {
    if key.len() != DUE_LEN || key[..2] != Row::Due.prefix() {
        return None;
    }
    let at = u64::from_be_bytes(key[2..10].try_into().ok()?);
    let id = u64::from_be_bytes(key[11..].try_into().ok()?);
    let entry = match key[10] {
        0 => Due::Session(SessionId(id)),
        1 => Due::Workflow(WorkflowId(id)),
        _ => return None,
    };
    Some((at, entry))
}

/// A workflow's record ([`crate::records::Workflow`]).
pub fn workflow(id: WorkflowId) -> Vec<u8> {
    key(&[&Row::Workflow.prefix(), &id.0.to_be_bytes()])
}

/// A page a workflow's snapshot stores, LZ4-compressed, by its index.
pub fn page(id: WorkflowId, index: u32) -> Vec<u8> {
    key(&[
        &Row::Page.prefix(),
        &id.0.to_be_bytes(),
        &index.to_be_bytes(),
    ])
}

/// The id the next workflow gets: ids are never reused.
pub fn next_workflow() -> Vec<u8> {
    Row::NextWorkflow.prefix().to_vec()
}

/// How many workflows the agent holds that have not ended.
pub fn live_workflows() -> Vec<u8> {
    Row::LiveWorkflows.prefix().to_vec()
}

/// How many workflows that have not ended run `program`: each pins it, as
/// an installed instance pins its programs.
pub fn workflow_pins(program: &ProgramHash) -> Vec<u8> {
    key(&[&Row::WorkflowPins.prefix(), &program.0])
}

/// The prefix of the workflows' pins.
pub fn workflow_pins_prefix() -> Vec<u8> {
    Row::WorkflowPins.prefix().to_vec()
}

/// The program a [`workflow_pins`] key names; `None` for any other key.
pub fn workflow_pins_entry(key: &[u8]) -> Option<ProgramHash> {
    let rest = key.strip_prefix(&Row::WorkflowPins.prefix())?;
    Some(ProgramHash(rest.try_into().ok()?))
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
