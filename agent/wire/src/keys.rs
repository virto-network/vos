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

use crate::abi::{Failure, MergeRows, Rows, cap};
use crate::ids::{
    AgentId, InstanceId, MapId, Principal, ProgramHash, Session, SessionId, WorkflowId,
};

mod cuts;

pub use cuts::*;

/// Who owns a row, its key's first byte: the agent itself, one of its
/// instances, the node's root builder, or an instance's committed maps.
///
/// Committed rows have an owner byte of their own, so the agent's
/// committed rows are exactly the keys under `0x03`: in a tree over the
/// whole keyspace, the node at that prefix is the tree over them alone,
/// the agent's root, and the node at a map's prefix is the map's root.
#[derive(Clone, Copy)]
#[repr(u8)]
enum Owner {
    System = 0x00,
    Instance = 0x01,
    Tree = 0x02,
    Committed = 0x03,
}

/// An instance's row, after its id: its struct state or a table's row.
#[derive(Clone, Copy)]
#[repr(u8)]
enum Part {
    Struct = 0x00,
    Table = 0x01,
    Merge = 0x02,
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
    Target = 0x18,
    Space = 0x19,
    Clock = 0x1a,
    Cut = 0x1b,
    Request = 0x1c,
    Reported = 0x1d,
    Closed = 0x1e,
    CutMark = 0x1f,
    CloseMark = 0x20,
    Reports = 0x21,
    Proven = 0x22,
    Reading = 0x23,
    EveryWindow = 0x24,
    Quarantined = 0x25,
    Credentials = 0x26,
    Binding = 0x27,
    Once = 0x28,
    Admission = 0x29,
    Cutoff = 0x2a,
    Lamport = 0x2b,
    Held = 0x2c,
    BindingDue = 0x2d,
    Release = 0x2e,
    QuarantinedOp = 0x2f,
}

/// The root builder's rows, each tagged after [`Owner::Tree`]: the rows of
/// the agent's one tree over its committed rows.
#[derive(Clone, Copy)]
#[repr(u8)]
enum TreeRow {
    Node = 0x00,
    Leaf = 0x01,
    Root = 0x02,
    Built = 0x03,
    Undo = 0x04,
    CutRoot = 0x05,
    CutProof = 0x06,
    Closing = 0x07,
    Anchor = 0x08,
    Attested = 0x09,
}

impl TreeRow {
    const fn prefix(self) -> [u8; 2] {
        [Owner::Tree as u8, self as u8]
    }

    fn key(self, rest: &[u8]) -> Vec<u8> {
        key(&[&self.prefix(), rest])
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
    prefix_into(Kind::Table, instance, tag, transform, &mut prefix);
    prefix
}

/// The length of a table's prefix, the longest a table's or committed
/// map's rows have.
pub const TABLE_PREFIX: usize = 1 + 4 + 1 + 4 + 1;

/// The length of a committed map's prefix: its owner byte, `0x03`, then the
/// map's id.
pub const COMMITTED_PREFIX: usize = 1 + MAP_LEN;

/// Which keyed rows of an instance: a table's, or a committed map's.
#[derive(Clone, Copy)]
enum Kind {
    Table,
    Committed,
}

/// Append the prefix of a table's or committed map's rows to `out`: a
/// table's under its instance, `0x01 ‖ instance ‖ 0x01 ‖ tag ‖ transform`;
/// a committed map's under its own owner, `0x03 ‖ instance ‖ tag ‖
/// transform`.
fn prefix_into(
    kind: Kind,
    instance: InstanceId,
    tag: u32,
    transform: Transform,
    out: &mut Vec<u8>,
) {
    match kind {
        Kind::Table => {
            out.push(Owner::Instance as u8);
            out.extend_from_slice(&instance.0.to_be_bytes());
            out.push(Part::Table as u8);
        }
        Kind::Committed => {
            out.push(Owner::Committed as u8);
            out.extend_from_slice(&instance.0.to_be_bytes());
        }
    }
    out.extend_from_slice(&tag.to_be_bytes());
    out.push(transform.tag());
}

/// The kind, tag and transform of the keyed rows `rows` names; `None` for
/// the struct.
fn table_of(rows: Rows) -> Option<(Kind, u32, Transform)> {
    match rows {
        Rows::Struct => None,
        Rows::Table { tag, transform } => Some((Kind::Table, tag, transform)),
        Rows::Committed { tag, transform } => Some((Kind::Committed, tag, transform)),
    }
}

/// The prefix of the rows `rows` names in `instance`'s state, and their
/// transform; `None` for the struct, which is one row.
pub fn rows_prefix(instance: InstanceId, rows: Rows) -> Option<(Vec<u8>, Transform)> {
    let (kind, tag, transform) = table_of(rows)?;
    let mut prefix = Vec::with_capacity(TABLE_PREFIX);
    prefix_into(kind, instance, tag, transform, &mut prefix);
    Some((prefix, transform))
}

/// The row of the raw key `key` in `rows`: the struct row under the empty
/// key, or the key transformed after its table's prefix. A struct key that
/// is not empty fails the invocation ([`Failure::Trapped`]); an ordered key
/// past [`cap::ORDERED_KEY`] exceeds a cap ([`Failure::Cap`]).
pub fn row(instance: InstanceId, rows: Rows, key: &[u8]) -> Result<Vec<u8>, Failure> {
    let Some((kind, tag, transform)) = table_of(rows) else {
        return if key.is_empty() {
            Ok(instance_struct(instance))
        } else {
            Err(Failure::Trapped)
        };
    };
    if transform == Transform::Ordered && key.len() > cap::ORDERED_KEY {
        return Err(Failure::Cap);
    }
    let mut row = Vec::with_capacity(TABLE_PREFIX + transform.room(key));
    prefix_into(kind, instance, tag, transform, &mut row);
    transform.append(key, &mut row);
    Ok(row)
}

/// The length of a committed map's id in its rows' keys: the instance, the
/// tag, then the transform.
const MAP_LEN: usize = 4 + 4 + 1;

/// The map a committed row's key names after its owner byte.
fn map_of(bytes: &[u8]) -> Option<MapId> {
    let bytes: &[u8; MAP_LEN] = bytes.get(..MAP_LEN)?.try_into().ok()?;
    Some(MapId {
        instance: InstanceId(u32::from_be_bytes(bytes[..4].try_into().ok()?)),
        tag: u32::from_be_bytes(bytes[4..8].try_into().ok()?),
        transform: Transform::from_tag(bytes[8])?,
    })
}

/// The prefix of every committed row of the agent: the keys its root is
/// over.
pub fn committed_all() -> Vec<u8> {
    [Owner::Committed as u8].to_vec()
}

/// The prefix of a committed map's value rows: the place of its root in
/// the agent's tree.
pub fn committed_rows(map: &MapId) -> Vec<u8> {
    committed(map, &[])
}

/// A committed map's value row, by its key already transformed (`key'`):
/// `0x03 ‖ instance ‖ tag ‖ transform ‖ key'`, its value the value with
/// the state version that wrote it ([`crate::records::versioned`]).
pub fn committed(map: &MapId, transformed: &[u8]) -> Vec<u8> {
    let mut row = Vec::with_capacity(COMMITTED_PREFIX + transformed.len());
    prefix_into(
        Kind::Committed,
        map.instance,
        map.tag,
        map.transform,
        &mut row,
    );
    row.extend_from_slice(transformed);
    row
}

/// Whether `key` is a committed map's value row, whose value carries the
/// version that wrote it: decided by its first byte alone. Every key under
/// `0x03` is one; anything else stored there is corrupt, and reading it as
/// a value row fails ([`crate::records::leaf_value`]).
pub fn is_committed(key: &[u8]) -> bool {
    key.first() == Some(&(Owner::Committed as u8))
}

/// The map and transformed key a value row's key names; `None` for any
/// other key.
pub fn committed_entry(key: &[u8]) -> Option<(MapId, &[u8])> {
    let (prefix, key) = key.split_first_chunk::<COMMITTED_PREFIX>()?;
    if prefix[0] != Owner::Committed as u8 || key.is_empty() {
        return None;
    }
    Some((map_of(&prefix[1..])?, key))
}

/// A committed row accumulate wrote at `version`, by its key `row`
/// ([`committed`]), for the root builder: one row per write, so later
/// writes never share a row with earlier ones. The version comes first:
/// the rows a build consumed, whose deletions an LSM keeps a while, all
/// lie before the versions it has yet to build.
pub fn dirty(version: u64, row: &[u8]) -> Vec<u8> {
    let mut dirty = Vec::with_capacity(2 + 8 + row.len());
    dirty.extend_from_slice(&Row::Dirty.prefix());
    dirty.extend_from_slice(&version.to_be_bytes());
    dirty.extend_from_slice(row);
    dirty
}

/// Where the dirty rows of `version` and later start.
pub fn dirty_from(version: u64) -> Vec<u8> {
    key(&[&Row::Dirty.prefix(), &version.to_be_bytes()])
}

/// The prefix of every dirty row, in version order.
pub fn dirty_prefix() -> Vec<u8> {
    Row::Dirty.prefix().to_vec()
}

/// The version and committed row a dirty row's key names; `None` for any
/// other key.
pub fn dirty_entry(key: &[u8]) -> Option<(u64, &[u8])> {
    let rest = key.strip_prefix(&Row::Dirty.prefix())?;
    let (version, row) = rest.split_first_chunk::<8>()?;
    is_committed(row).then(|| (u64::from_be_bytes(*version), row))
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

/// A branch of the agent's tree, by its level and prefix
/// ([`vos_tree::NodeStore`]): the prefix's length follows from the level.
pub fn tree_node(level: u16, prefix: &[u8]) -> Vec<u8> {
    TreeRow::Node.key(&[&level.to_be_bytes()[..], prefix].concat())
}

/// The prefix of the tree's branch rows.
pub fn tree_nodes() -> Vec<u8> {
    TreeRow::Node.prefix().to_vec()
}

/// A leaf of the agent's tree, by its committed row's key.
pub fn tree_leaf(key: &[u8]) -> Vec<u8> {
    TreeRow::Leaf.key(key)
}

/// The prefix of the tree's leaf rows.
pub fn tree_leaves() -> Vec<u8> {
    TreeRow::Leaf.prefix().to_vec()
}

/// The tree's top, and the agent's root as the last complete build left
/// it.
pub fn tree_root() -> Vec<u8> {
    TreeRow::Root.prefix().to_vec()
}

/// The version through which the agent's tree is built: no dirty or seed
/// row is left through it.
pub fn built() -> Vec<u8> {
    TreeRow::Built.prefix().to_vec()
}

/// The prefix of an instance's struct and table rows.
pub fn instance_rows(instance: InstanceId) -> Vec<u8> {
    key(&[&[Owner::Instance as u8], &instance.0.to_be_bytes()])
}

/// The prefix of an instance's committed maps' rows.
pub fn instance_committed(instance: InstanceId) -> Vec<u8> {
    key(&[&[Owner::Committed as u8], &instance.0.to_be_bytes()])
}

/// The prefixes of everything an instance owns, [`instance_rows`] and
/// [`instance_committed`]; its ABI reaches nothing else.
pub fn instance_prefixes(instance: InstanceId) -> [Vec<u8>; 2] {
    [instance_rows(instance), instance_committed(instance)]
}

/// The program an instance runs.
pub fn installed(instance: InstanceId) -> Vec<u8> {
    key(&[&Row::Installed.prefix(), &instance.0.to_be_bytes()])
}

/// The prefix of every instance's [`installed`] row.
pub fn installed_prefix() -> Vec<u8> {
    Row::Installed.prefix().to_vec()
}

/// The agent's target, which its first install names and every later one
/// must ([`crate::abi::cap::Target`]).
pub fn target() -> Vec<u8> {
    Row::Target.prefix().to_vec()
}

/// The space the agent belongs to ([`crate::SpaceId`]), which its first
/// install names and every later one must.
pub fn space() -> Vec<u8> {
    Row::Space.prefix().to_vec()
}

/// The clock that numbers the agent's windows ([`crate::WindowClock`]), its
/// space's, which its first install names and every later one must.
pub fn clock() -> Vec<u8> {
    Row::Clock.prefix().to_vec()
}

/// A principal's role byte in this agent.
pub fn member(principal: &Principal) -> Vec<u8> {
    key(&[&Row::Member.prefix(), &principal.encode()])
}

/// The instance of the agent's credential actor, whose ring its auth
/// guards read: written by the actor's install, once.
pub fn credentials() -> Vec<u8> {
    Row::Credentials.prefix().to_vec()
}

/// What the agent's ingress asks of its requests
/// ([`crate::records::Admitting`]): written by the install of the actor
/// that declares it.
pub fn admission() -> Vec<u8> {
    Row::Admission.prefix().to_vec()
}

/// The row of `key` in the [`crate::schema::ADMITTED`] table of the actor
/// at `instance`, hashed: present when the agent admits the key to create
/// a session.
pub fn admitted(instance: InstanceId, key: &[u8; 32]) -> Vec<u8> {
    let rows = Rows::Table {
        tag: crate::ids::derive_id("vos/table/", crate::schema::ADMITTED),
        transform: Transform::Hashed,
    };
    row(instance, rows, key).expect("a hashed row's key")
}

/// The prefix of a merge field's rows in `instance`'s state, `0x01 ‖
/// instance ‖ 0x02 ‖ tag ‖ transform`, as a table's after its own part.
pub fn merge_rows(instance: InstanceId, field: MergeRows) -> Vec<u8> {
    key(&[
        &[Owner::Instance as u8],
        &instance.0.to_be_bytes(),
        &[Part::Merge as u8],
        &field.tag.to_be_bytes(),
        &[field.transform.tag()],
    ])
}

/// The row of the raw key `key` in a merge field, the prefix of its
/// entries, one an author ([`merge_entry`]): the key transformed after the
/// field's prefix. An ordered key past [`cap::ORDERED_KEY`] exceeds a cap
/// ([`Failure::Cap`]).
pub fn merge_element(
    instance: InstanceId,
    field: MergeRows,
    key: &[u8],
) -> Result<Vec<u8>, Failure> {
    if field.transform == Transform::Ordered && key.len() > cap::ORDERED_KEY {
        return Err(Failure::Cap);
    }
    let mut row = merge_rows(instance, field);
    field.transform.append(key, &mut row);
    Ok(row)
}

/// The entry of `author` for one element or key of a merge field, after
/// its row ([`merge_element`]): the author's 32 bytes last, so one key's
/// entries lie together and the keys stay prefix-free.
pub fn merge_entry(row: &[u8], author: &[u8; 32]) -> Vec<u8> {
    key(&[row, author])
}

/// The length of the author's part of a merge field's entry.
pub const AUTHOR: usize = 32;

/// An author's cutoff in `instance`'s scope ([`crate::merge::Cutoff`]): its
/// operations at this sequence number and later are filtered when a merge
/// field is read. A device writes it, never an actor.
pub fn cutoff(instance: InstanceId, author: &[u8; 32]) -> Vec<u8> {
    key(&[&Row::Cutoff.prefix(), &instance.0.to_be_bytes(), author])
}

/// A device's DAG node's Lamport clock, by its CID: one more than its
/// parents' greatest, the order a merge field's latest entry is chosen in.
pub fn lamport(cid: &[u8; 32]) -> Vec<u8> {
    key(&[&Row::Lamport.prefix(), cid])
}

/// An operation of a kind, or of a release of its actor, the device does
/// not run yet, or whose run faulted there, kept until it runs, with its
/// origin: in `instance`'s scope, by its node's CID and its index there, so
/// two equivocating nodes' never share a row.
pub fn held(instance: InstanceId, cid: &[u8; 32], index: u32) -> Vec<u8> {
    key(&[
        &Row::Held.prefix(),
        &instance.0.to_be_bytes(),
        cid,
        &index.to_be_bytes(),
    ])
}

/// The prefix of the operations held in `instance`'s scope.
pub fn held_prefix(instance: InstanceId) -> Vec<u8> {
    key(&[&Row::Held.prefix(), &instance.0.to_be_bytes()])
}

/// An operation of `instance`'s scope the device found invalid, or whose
/// author was cut off at or before its number: never applied, kept with
/// its origin and why, by its node's CID and its index there, as a held
/// one is ([`held`]).
pub fn quarantined_op(instance: InstanceId, cid: &[u8; 32], index: u32) -> Vec<u8> {
    key(&[
        &Row::QuarantinedOp.prefix(),
        &instance.0.to_be_bytes(),
        cid,
        &index.to_be_bytes(),
    ])
}

/// The prefix of the operations quarantined in `instance`'s scope.
pub fn quarantined_op_prefix(instance: InstanceId) -> Vec<u8> {
    key(&[&Row::QuarantinedOp.prefix(), &instance.0.to_be_bytes()])
}

/// The release version of the local actor installed at `instance` on a
/// device, which its operations carry: a device holds an operation of a
/// later one until it installs it. A device writes it, never an actor.
pub fn release(instance: InstanceId) -> Vec<u8> {
    key(&[&Row::Release.prefix(), &instance.0.to_be_bytes()])
}

/// A credentialed call's binding digest `b`, recorded at its apply with its
/// `expires_ms`: a second call of it is refused, at every replica, until
/// the sweep forgets it ([`Due::Binding`]).
pub fn binding(binding: &[u8; 32]) -> Vec<u8> {
    key(&[&Row::Binding.prefix(), binding])
}

/// A `once` guard's admission of `nullifier` in `scope`, with the batch
/// time of its admission: kept for good.
pub fn once(scope: &[u8; 32], nullifier: &[u8; 32]) -> Vec<u8> {
    key(&[&Row::Once.prefix(), scope, nullifier])
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
/// expired, a workflow's step, or a credentialed call's binding digest to
/// forget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub enum Due {
    #[codec(index = 0)]
    Session(SessionId),
    /// Its first step, its deadline or timer, or its collection once ended.
    #[codec(index = 1)]
    Workflow(WorkflowId),
    /// A binding digest's row ([`binding`]), forgotten at its row's time.
    #[codec(index = 2)]
    Binding([u8; 32]),
}

/// The kind byte of a session's or a workflow's [`Due`] in its row's key.
#[derive(Clone, Copy)]
#[repr(u8)]
enum DueKind {
    Session = 0,
    Workflow = 1,
}

/// The two indexes of due rows, each scanned from its own start: the
/// sessions' and workflows' rows, and the bindings' beside them, so a
/// backlog of either never holds the other back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DueIndex {
    Rows = 0,
    Bindings = 1,
}

impl DueIndex {
    /// Both, in the order a sweep lists them.
    pub const ALL: [Self; 2] = [Self::Rows, Self::Bindings];

    /// The index `entry`'s row is in.
    pub const fn of(entry: &Due) -> Self {
        match entry {
            Due::Session(_) | Due::Workflow(_) => Self::Rows,
            Due::Binding(_) => Self::Bindings,
        }
    }

    /// Its keys' prefix.
    pub const fn prefix(self) -> &'static [u8] {
        const ROWS: [u8; 2] = Row::Due.prefix();
        const BINDINGS: [u8; 2] = Row::BindingDue.prefix();
        match self {
            Self::Rows => &ROWS,
            Self::Bindings => &BINDINGS,
        }
    }

    /// A key past every row it holds: its last row's at the last time.
    pub fn past_every_row(self) -> Vec<u8> {
        match self {
            Self::Rows => due(u64::MAX, Due::Workflow(WorkflowId(u64::MAX))),
            Self::Bindings => due(u64::MAX, Due::Binding([0xff; 32])),
        }
    }

    /// The most of its rows one sweep lists, `limit` the sessions' and
    /// workflows'.
    pub const fn most(self, limit: usize) -> usize {
        match self {
            Self::Rows => limit,
            Self::Bindings => crate::defaults::SWEEP_BINDINGS,
        }
    }
}

/// A row of the due index, which the leader reads to time its sweeps and
/// lists in them: the batch time it is due at, then, for a session or a
/// workflow, its kind and id, big-endian, so a scan meets the earliest
/// first. A session's row is due once it may have expired
/// ([`crate::expiry::due`]), and lies at or before that. A binding's row is
/// in its own index ([`DueIndex::Bindings`]): its time, then its 32 bytes.
pub fn due(at: u64, entry: Due) -> Vec<u8> {
    let (kind, number) = match &entry {
        Due::Session(id) => (DueKind::Session, id.0),
        Due::Workflow(id) => (DueKind::Workflow, id.0),
        Due::Binding(binding) => {
            return key(&[&Row::BindingDue.prefix(), &at.to_be_bytes(), binding]);
        }
    };
    key(&[
        &Row::Due.prefix(),
        &at.to_be_bytes(),
        &[kind as u8],
        &number.to_be_bytes(),
    ])
}

/// The length of a [`due`] key of a session or a workflow.
const DUE_LEN: usize = 2 + 8 + 1 + 8;

/// The length of a [`due`] key of a binding.
const BINDING_DUE_LEN: usize = 2 + 8 + 32;

/// The prefix of the sessions' and workflows' due index.
pub fn due_prefix() -> Vec<u8> {
    DueIndex::Rows.prefix().to_vec()
}

/// The time and entry a [`due`] key names; `None` for any other key.
pub fn due_entry(key: &[u8]) -> Option<(u64, Due)> {
    if key.len() < 10 {
        return None;
    }
    let at = u64::from_be_bytes(key[2..10].try_into().ok()?);
    if key[..2] == Row::BindingDue.prefix() {
        return (key.len() == BINDING_DUE_LEN)
            .then(|| Some((at, Due::Binding(key[10..].try_into().ok()?))))
            .flatten();
    }
    if key.len() != DUE_LEN || key[..2] != Row::Due.prefix() {
        return None;
    }
    let number = u64::from_be_bytes(key[11..].try_into().ok()?);
    let entry = match key[10] {
        kind if kind == DueKind::Session as u8 => Due::Session(SessionId(number)),
        kind if kind == DueKind::Workflow as u8 => Due::Workflow(WorkflowId(number)),
        _ => return None,
    };
    Some((at, entry))
}

/// What one sweep lists of the due rows: at most `limit` sessions' and
/// workflows' rows, and at most [`crate::defaults::SWEEP_BINDINGS`]
/// binding digests' beside them.
#[derive(Clone, Copy, Debug)]
pub struct SweepBudget {
    limit: usize,
    taken: [usize; 2],
}

impl SweepBudget {
    pub const fn new(limit: usize) -> Self {
        Self {
            limit,
            taken: [0; 2],
        }
    }

    /// Whether a sweep lists `entry` after those it took: false once its
    /// index's count is full.
    pub fn take(&mut self, entry: &Due) -> bool {
        let index = DueIndex::of(entry);
        let count = &mut self.taken[index as usize];
        if *count == index.most(self.limit) {
            return false;
        }
        *count += 1;
        true
    }

    /// The most rows a sweep lists: both counts' worth.
    pub const fn rows(&self) -> usize {
        self.limit + crate::defaults::SWEEP_BINDINGS
    }
}

/// Of one due index's keys in order, from its start, the rows due at
/// `time`, earliest first, at most `most` of them: a key under the index
/// that names no row of it is passed over, and the keys end at the first
/// past the index or not yet due.
pub fn due_rows<K: AsRef<[u8]>, E>(
    index: DueIndex,
    keys: impl IntoIterator<Item = Result<K, E>>,
    time: u64,
    most: usize,
) -> Result<Vec<(u64, Due)>, E> {
    let prefix = index.prefix();
    let mut due = Vec::new();
    for key in keys {
        if due.len() == most {
            break;
        }
        let key = key?;
        if !key.as_ref().starts_with(prefix) {
            break;
        }
        let Some((at, entry)) = due_entry(key.as_ref()) else {
            continue;
        };
        if at > time {
            break;
        }
        due.push((at, entry));
    }
    Ok(due)
}

/// The rows a sweep at `time` lists, each due index's keys in order as
/// `scan` gives them from the index's prefix: the sessions' and workflows'
/// rows, at most `limit`, then the bindings'.
pub fn sweep_rows<I, K, E>(
    mut scan: impl FnMut(DueIndex) -> I,
    time: u64,
    limit: usize,
) -> Result<Vec<(u64, Due)>, E>
where
    I: IntoIterator<Item = Result<K, E>>,
    K: AsRef<[u8]>,
{
    let mut due = Vec::new();
    for index in DueIndex::ALL {
        due.extend(due_rows(index, scan(index), time, index.most(limit))?);
    }
    Ok(due)
}

/// A workflow's record ([`crate::records::Workflow`]).
pub fn workflow(id: WorkflowId) -> Vec<u8> {
    key(&[&Row::Workflow.prefix(), &id.0.to_be_bytes()])
}

/// A page a workflow's snapshot stores, by its index: on a VOS node its
/// LZ4 bytes, on JAM its hash, the page a segment.
pub fn page(id: WorkflowId, index: u32) -> Vec<u8> {
    key(&[
        &Row::Page.prefix(),
        &id.0.to_be_bytes(),
        &index.to_be_bytes(),
    ])
}

/// The workflow and page index a [`page`] key names; `None` for any other
/// key.
pub fn page_entry(key: &[u8]) -> Option<(WorkflowId, u32)> {
    let rest = key.strip_prefix(&Row::Page.prefix())?;
    let (id, index) = rest.split_first_chunk::<8>()?;
    let index: [u8; 4] = index.try_into().ok()?;
    Some((
        WorkflowId(u64::from_be_bytes(*id)),
        u32::from_be_bytes(index),
    ))
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

/// The prefix of the outbox's messages to `to`.
pub fn outbox_to(to: AgentId) -> Vec<u8> {
    key(&[&Row::Outbox.prefix(), &to.0.to_be_bytes()])
}

/// The target and sequence an [`outbox`] key names; `None` for any other
/// key.
pub fn outbox_entry(key: &[u8]) -> Option<(AgentId, u64)> {
    let rest = key.strip_prefix(&Row::Outbox.prefix())?;
    if rest.len() != 12 {
        return None;
    }
    let to = u32::from_be_bytes(rest[..4].try_into().ok()?);
    let sequence = u64::from_be_bytes(rest[4..].try_into().ok()?);
    Some((AgentId(to), sequence))
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

/// Whether `key` is a replicated row, the same on every replica at one
/// applied version: the agent's own rows but the dirty and seed rows its
/// root builder consumes at its own pace, its instances' rows and its
/// committed rows; never the root builder's node-local rows under
/// `0x02`.
pub fn is_replicated(key: &[u8]) -> bool {
    match key.first() {
        Some(&owner) if owner == Owner::System as u8 => {
            !key.starts_with(&Row::Dirty.prefix()) && !key.starts_with(&Row::Seed.prefix())
        }
        Some(&owner) => owner == Owner::Instance as u8 || owner == Owner::Committed as u8,
        None => false,
    }
}

/// Whether `key` lies inside `instance`'s own state: under
/// `0x01 ‖ instance` or `0x03 ‖ instance`.
pub fn owned_by(key: &[u8], instance: InstanceId) -> bool {
    match key.split_first() {
        Some((&owner, rest)) => {
            (owner == Owner::Instance as u8 || owner == Owner::Committed as u8)
                && rest.starts_with(&instance.0.to_be_bytes())
        }
        None => false,
    }
}
