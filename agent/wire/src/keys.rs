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
    AgentId, InstanceId, MapId, Principal, ProgramHash, RequestId, Session, SessionId, WorkflowId,
};

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
    Moved = 0x1f,
    Serving = 0x20,
    CloseMark = 0x21,
    Reports = 0x22,
    Proven = 0x23,
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

/// The state version of the window `window`'s cut: the version before the
/// first work result applied with a time at or past the window's boundary
/// ([`crate::WindowClock::boundary`]). Apply writes it, for every window
/// that result's time crosses, in an agent of a space; it is replicated,
/// and never rewritten.
pub fn cut(window: u64) -> Vec<u8> {
    key(&[&Row::Cut.prefix(), &window.to_be_bytes()])
}

/// The prefix of the cuts, in window order.
pub fn cuts() -> Vec<u8> {
    Row::Cut.prefix().to_vec()
}

/// The window a [`cut`] key names; `None` for any other key.
pub fn cut_entry(key: &[u8]) -> Option<u64> {
    let rest = key.strip_prefix(&Row::Cut.prefix())?;
    Some(u64::from_be_bytes(rest.try_into().ok()?))
}

/// A pending request of the window `window` ([`crate::records::PendingRead`]):
/// replicated, written by the workflow step that asks.
pub fn request(window: u64, id: RequestId) -> Vec<u8> {
    key(&[
        &Row::Request.prefix(),
        &window.to_be_bytes(),
        &id.workflow.0.to_be_bytes(),
        &id.awaits.to_be_bytes(),
    ])
}

/// The prefix of every pending request, in window order.
pub fn request_prefix() -> Vec<u8> {
    Row::Request.prefix().to_vec()
}

/// The prefix of the window `window`'s pending requests.
pub fn requests(window: u64) -> Vec<u8> {
    key(&[&Row::Request.prefix(), &window.to_be_bytes()])
}

/// The window and request a [`request`] key names; `None` for any other
/// key.
pub fn request_entry(key: &[u8]) -> Option<(u64, RequestId)> {
    let rest = key.strip_prefix(&Row::Request.prefix())?;
    let rest: &[u8; 24] = rest.try_into().ok()?;
    let word = |at: usize| u64::from_be_bytes(rest[at..at + 8].try_into().unwrap_or_default());
    Some((
        word(0),
        RequestId {
            workflow: WorkflowId(word(8)),
            awaits: word(16),
        },
    ))
}

/// The value the committed row `row` held at the window `window`'s cut,
/// its stored bytes, kept by the node while that cut's build is pending
/// and a later write overwrites the row. Node-local: the node's apply
/// writes it beside the agent's writes, and the cut's build deletes it.
pub fn undo(window: u64, row: &[u8]) -> Vec<u8> {
    TreeRow::Undo.key(&[&window.to_be_bytes()[..], row].concat())
}

/// The prefix of the window `window`'s [`undo`] rows.
pub fn undos(window: u64) -> Vec<u8> {
    TreeRow::Undo.key(&window.to_be_bytes())
}

/// The prefix of every [`undo`] row.
pub fn undo_prefix() -> Vec<u8> {
    TreeRow::Undo.prefix().to_vec()
}

/// The window and committed row an [`undo`] key names; `None` for any
/// other key.
pub fn undo_entry(key: &[u8]) -> Option<(u64, &[u8])> {
    let rest = key.strip_prefix(&TreeRow::Undo.prefix())?;
    let (window, row) = rest.split_first_chunk::<8>()?;
    is_committed(row).then(|| (u64::from_be_bytes(*window), row))
}

/// The agent's root at the window `window`'s cut, and the cut's version,
/// once the cut's build is done: node-local, kept for the two latest cuts.
pub fn cut_root(window: u64) -> Vec<u8> {
    TreeRow::CutRoot.key(&window.to_be_bytes())
}

/// The prefix of every [`cut_root`] row.
pub fn cut_roots() -> Vec<u8> {
    TreeRow::CutRoot.prefix().to_vec()
}

/// The window a [`cut_root`] key names; `None` for any other key.
pub fn cut_root_entry(key: &[u8]) -> Option<u64> {
    let rest = key.strip_prefix(&TreeRow::CutRoot.prefix())?;
    Some(u64::from_be_bytes(rest.try_into().ok()?))
}

/// A pending request's rows and their proof at window `window`'s cut,
/// node-local, written in the commit that marks the cut built: one for the
/// window it was asked in, and one for each window a re-cut moved it to.
pub fn cut_proof(id: RequestId, window: u64) -> Vec<u8> {
    TreeRow::CutProof.key(
        &[
            &id.workflow.0.to_be_bytes()[..],
            &id.awaits.to_be_bytes(),
            &window.to_be_bytes(),
        ]
        .concat(),
    )
}

/// The prefix of the [`cut_proof`] rows of request `id`, in window order.
pub fn cut_proofs_of(id: RequestId) -> Vec<u8> {
    TreeRow::CutProof.key(&[&id.workflow.0.to_be_bytes()[..], &id.awaits.to_be_bytes()].concat())
}

/// The prefix of every [`cut_proof`] row.
pub fn cut_proofs() -> Vec<u8> {
    TreeRow::CutProof.prefix().to_vec()
}

/// The request and window a [`cut_proof`] key names; `None` for any other
/// key.
pub fn cut_proof_entry(key: &[u8]) -> Option<(RequestId, u64)> {
    let rest = key.strip_prefix(&TreeRow::CutProof.prefix())?;
    let rest: &[u8; 24] = rest.try_into().ok()?;
    let word = |at: usize| u64::from_be_bytes(rest[at..at + 8].try_into().unwrap_or_default());
    Some((
        RequestId {
            workflow: WorkflowId(word(0)),
            awaits: word(8),
        },
        word(16),
    ))
}

/// The last window whose root at its cut the agent reported to its
/// space's representative, and the representative's id
/// ([`crate::batch::Input::Report`]): replicated, written by the report's
/// step. A report of that window or an earlier one sends nothing, and a
/// `Closed` comes only from that agent.
pub fn reported() -> Vec<u8> {
    Row::Reported.prefix().to_vec()
}

/// The representative's close of the window `window` as the agent holds
/// it ([`crate::served::ClosedRow`]): the representative's root at its cut
/// of the window, and the agent's row's salt and path there. Replicated,
/// written by the step of the representative's `Closed`; a second one for
/// the window is ignored.
pub fn closed(window: u64) -> Vec<u8> {
    key(&[&Row::Closed.prefix(), &window.to_be_bytes()])
}

/// The prefix of every [`closed`] row, in window order.
pub fn closed_prefix() -> Vec<u8> {
    Row::Closed.prefix().to_vec()
}

/// The window whose cut serves the pending requests the window `window`'s
/// cut served, once that window went unclosed: its requests' re-cut. Apply
/// writes it with the next cut recorded after `window`'s, when the
/// representative's `Closed` of `window` has not been applied by then
/// ([`crate::apply`]). Replicated.
pub fn moved(window: u64) -> Vec<u8> {
    key(&[&Row::Moved.prefix(), &window.to_be_bytes()])
}

/// The window of the latest cut recorded whose requests it serves: the
/// first of the windows the latest recording cut. Replicated, written by
/// apply with the cuts.
pub fn serving() -> Vec<u8> {
    Row::Serving.prefix().to_vec()
}

/// The representative's mark of the closes it has sent
/// ([`crate::batch::Input::Close`]): the window, and the last agent sent
/// its path for it. Replicated.
pub fn close_mark() -> Vec<u8> {
    Row::CloseMark.prefix().to_vec()
}

/// The last window whose root agent `agent` reported to this agent, its
/// space's representative ([`crate::batch::Body::Report`]): replicated,
/// written by the report's step. A report of that window or an earlier
/// one stores nothing.
pub fn reports(agent: AgentId) -> Vec<u8> {
    key(&[&Row::Reports.prefix(), &agent.0.to_be_bytes()])
}

/// The final proof of the agent's statement `id` (a
/// `vos_statement::StatementId`), as its prover recorded it
/// ([`crate::batch::Input::Proven`]): the proof's BLAKE2b-256, a blob in
/// the prover's store. Replicated, written by the step of the first
/// `Proven` of the id; a later one is ignored. Every replica learns from it
/// that the statement is proved, so a new leader proves it again only when
/// no replica holds the proof.
pub fn proven(id: &[u8; 32]) -> Vec<u8> {
    key(&[&Row::Proven.prefix(), id])
}

/// The representative's close of the window `window`, node-local, written
/// by the commit that finishes its cut's build: its root there, and the
/// path of each agent that asked for one ([`crate::served::Closing`]).
pub fn closing(window: u64) -> Vec<u8> {
    TreeRow::Closing.key(&window.to_be_bytes())
}

/// The prefix of every [`closing`] row, in window order.
pub fn closings() -> Vec<u8> {
    TreeRow::Closing.prefix().to_vec()
}

/// The window a [`closing`] key names; `None` for any other key.
pub fn closing_entry(key: &[u8]) -> Option<u64> {
    let rest = key.strip_prefix(&TreeRow::Closing.prefix())?;
    Some(u64::from_be_bytes(rest.try_into().ok()?))
}

/// The window a [`closed`] key names; `None` for any other key.
pub fn closed_entry(key: &[u8]) -> Option<u64> {
    let rest = key.strip_prefix(&Row::Closed.prefix())?;
    Some(u64::from_be_bytes(rest.try_into().ok()?))
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

/// Of the due index's keys in order, from its start, the rows due at
/// `time`, earliest first, at most `limit`: a key under the index that
/// names no row of it is passed over, and the keys end at the first past
/// the index.
pub fn due_rows<K: AsRef<[u8]>, E>(
    keys: impl IntoIterator<Item = Result<K, E>>,
    time: u64,
    limit: usize,
) -> Result<Vec<(u64, Due)>, E> {
    let prefix = Row::Due.prefix();
    let mut due = Vec::new();
    for key in keys {
        let key = key?;
        if !key.as_ref().starts_with(&prefix) {
            break;
        }
        let Some((at, entry)) = due_entry(key.as_ref()) else {
            continue;
        };
        if at > time || due.len() == limit {
            break;
        }
        due.push((at, entry));
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
