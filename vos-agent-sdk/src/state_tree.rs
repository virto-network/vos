//! Experimental copy-on-write radix tree over fixed 32-byte keys.
//!
//! Only the traversed path is fetched. Blocks authenticate under a pinned
//! scope/root; an unavailable child is never an absent key. The caller must
//! obtain the root from an authoritative revision, not arbitrary input. Roots
//! built here preserve canonical structure; imported roots require an audit.
//!
//! Updates return candidate immutable blocks and a candidate root, NOT a durable
//! commit. Persist/replicate the blocks before publishing the root with result
//! and retry metadata. No host I/O, root admission or reclamation lives here.

use crate::{
    Hash,
    state_blocks::{BlockError, BlockRef, BlockScope, MAX_STATE_BLOCK_BYTES, ReadBudget},
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};

const MAGIC: &[u8; 4] = b"VST1";
const LEAF_HEADER: usize = 4 + 1 + 32 + 4;
const BRANCH_BYTES: usize = 4 + 1 + 2 + 32 + 36 + 36;
pub const MAX_INLINE_TREE_VALUE_BYTES: usize = MAX_STATE_BLOCK_BYTES - LEAF_HEADER;
/// Candidate per-value ceiling, independently bounded from total retained state.
/// Signed actor limits must still be enforced by the runtime adapter.
pub const MAX_TREE_VALUE_BYTES: usize = 1024 * 1024;
pub type TreeKey = [u8; 32];

/// Public storage graph roles. Payload bytes must not be guessed to be nodes:
/// a value chunk may legitimately start with the tree-node magic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateBlockKind {
    TreeNode,
    ValueChunk,
}

/// Public storage metadata only; actor/runtime value encodings stay opaque.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateBlockShape {
    Branch {
        bit: u16,
        prefix: TreeKey,
        left: BlockRef,
        right: BlockRef,
    },
    Value {
        key: TreeKey,
        bytes: u32,
        chunks: Vec<BlockRef>,
    },
    Chunk {
        bytes: u32,
    },
}

/// Authenticate and inspect a block for backup/import/availability work. This
/// does not establish revision authority or durability. Branch-child placement
/// must additionally be checked against the parent (see `StateTree::audit`).
pub fn inspect_state_block(
    scope: BlockScope,
    kind: StateBlockKind,
    reference: BlockRef,
    bytes: &[u8],
) -> Result<StateBlockShape, TreeError> {
    if scope.reference(bytes)? != reference {
        return Err(BlockError::HashMismatch.into());
    }
    if kind == StateBlockKind::ValueChunk {
        return Ok(StateBlockShape::Chunk {
            bytes: reference.byte_len(),
        });
    }
    Ok(match Node::decode(bytes)? {
        Node::Branch(branch) => StateBlockShape::Branch {
            bit: branch.bit,
            prefix: branch.prefix,
            left: branch.left,
            right: branch.right,
        },
        Node::Leaf(key, value) => StateBlockShape::Value {
            key,
            bytes: value.len() as u32,
            chunks: Vec::new(),
        },
        Node::Chunked(key, bytes, chunks) => StateBlockShape::Value { key, bytes, chunks },
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TreeAudit {
    pub rows: u64,
    /// Encoded value bytes, not actor-specific logical accounting.
    pub value_bytes: u64,
    /// Physical visits, including repeated references to deduplicated chunks.
    pub block_visits: u64,
}

/// Work on a candidate graph, not a certificate of authority or durability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChangeReachability {
    pub candidate_visits: u32,
    pub reused_subtrees: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeError {
    Block(BlockError),
    InvalidNode,
    InvalidValue,
    InvalidKey,
    PreconditionFailed,
    WriteBudgetExceeded,
    Storage,
}

impl From<BlockError> for TreeError {
    fn from(value: BlockError) -> Self {
        Self::Block(value)
    }
}

/// Fill the exact pre-budgeted buffer, returning false for unavailable data.
/// The runtime verifies the bytes independently; no provider assertion grants
/// authenticity or absence. I/O failure remains distinct from absence.
pub trait BlockReader {
    fn read(&mut self, reference: BlockRef, output: &mut [u8]) -> Result<bool, TreeError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateTree {
    scope: BlockScope,
    root: Option<BlockRef>,
}

#[derive(Debug)]
#[must_use]
pub struct TreeUpdate {
    pub tree: StateTree,
    /// Uncommitted, bounded candidate data. Single updates emit children before
    /// parents; batches emit hash order after pruning superseded candidates.
    pub blocks: Vec<(BlockRef, Vec<u8>)>,
}

/// Private copy-on-write workspace. All intermediate emissions consume the
/// caller's write budget, even when a later update makes them unreachable.
/// The backing reader is never written and budgets are never refunded on error.
pub(crate) struct TreeBatch<'a, R> {
    base: StateTree,
    tree: StateTree,
    reader: &'a mut R,
    blocks: BTreeMap<[u8; 32], (BlockRef, Vec<u8>)>,
}

struct OverlayReader<'a, R> {
    reader: &'a mut R,
    blocks: &'a BTreeMap<[u8; 32], (BlockRef, Vec<u8>)>,
}

impl<R: BlockReader> BlockReader for OverlayReader<'_, R> {
    fn read(&mut self, reference: BlockRef, output: &mut [u8]) -> Result<bool, TreeError> {
        match self.blocks.get(&reference.hash().0) {
            Some((stored, bytes)) => {
                if *stored != reference || bytes.len() != output.len() {
                    return Err(BlockError::InvalidReference.into());
                }
                output.copy_from_slice(bytes);
                Ok(true)
            }
            None => self.reader.read(reference, output),
        }
    }
}

impl<'a, R: BlockReader> TreeBatch<'a, R> {
    pub(crate) fn new(tree: StateTree, reader: &'a mut R) -> Self {
        Self {
            base: tree,
            tree,
            reader,
            blocks: BTreeMap::new(),
        }
    }

    pub(crate) fn update_checked(
        &mut self,
        key: TreeKey,
        value: Option<&[u8]>,
        reads: &mut ReadBudget,
        writes: &mut WriteBudget,
        check: impl FnOnce(Option<&[u8]>) -> Result<(), TreeError>,
    ) -> Result<(), TreeError> {
        let update = self.tree.update_checked(
            key,
            value,
            &mut OverlayReader {
                reader: self.reader,
                blocks: &self.blocks,
            },
            (reads, writes),
            check,
        )?;
        for (reference, bytes) in update.blocks {
            if let Some((prior, data)) = self.blocks.get(&reference.hash().0) {
                if *prior != reference || *data != bytes {
                    return Err(TreeError::InvalidNode);
                }
            } else {
                self.blocks.insert(reference.hash().0, (reference, bytes));
            }
        }
        self.tree = update.tree;
        Ok(())
    }

    pub(crate) fn get(
        &mut self,
        key: &TreeKey,
        reads: &mut ReadBudget,
    ) -> Result<Option<Vec<u8>>, TreeError> {
        self.tree.get(
            key,
            &mut OverlayReader {
                reader: self.reader,
                blocks: &self.blocks,
            },
            reads,
        )
    }

    /// Retain only final candidate links; stop at reused immutable subtrees.
    /// This visits bounded candidate memory, never walks the retained tree.
    /// A payload can legitimately serve as both a value chunk and a tree node,
    /// so traversal tracks roles separately while emitting each hash once.
    pub(crate) fn finish(mut self) -> Result<TreeUpdate, TreeError> {
        if self.tree.root == self.base.root {
            return Ok(TreeUpdate {
                tree: self.tree,
                blocks: Vec::new(),
            });
        }
        let mut pending = self
            .tree
            .root
            .into_iter()
            .map(|root| (root, StateBlockKind::TreeNode))
            .collect::<Vec<_>>();
        let mut visited = BTreeSet::new();
        let mut retained = BTreeSet::new();
        while let Some((reference, kind)) = pending.pop() {
            let Some((stored, bytes)) = self.blocks.get(&reference.hash().0) else {
                continue;
            };
            if *stored != reference {
                return Err(BlockError::InvalidReference.into());
            }
            let role = match kind {
                StateBlockKind::TreeNode => 0,
                StateBlockKind::ValueChunk => 1,
            };
            if !visited.insert((reference.hash().0, role)) {
                continue;
            }
            retained.insert(reference.hash().0);
            match inspect_state_block(self.tree.scope, kind, reference, bytes)? {
                StateBlockShape::Branch { left, right, .. } => {
                    pending.push((right, StateBlockKind::TreeNode));
                    pending.push((left, StateBlockKind::TreeNode));
                }
                StateBlockShape::Value { chunks, .. } => pending.extend(
                    chunks
                        .into_iter()
                        .map(|chunk| (chunk, StateBlockKind::ValueChunk)),
                ),
                StateBlockShape::Chunk { .. } => {}
            }
        }
        self.blocks.retain(|hash, _| retained.contains(hash));
        Ok(TreeUpdate {
            tree: self.tree,
            blocks: self.blocks.into_values().collect(),
        })
    }
}

#[derive(Debug)]
pub struct WriteBudget {
    blocks: u32,
    bytes: u64,
}

impl WriteBudget {
    pub const fn new(blocks: u32, bytes: u64) -> Self {
        Self { blocks, bytes }
    }
    pub const fn remaining(&self) -> (u32, u64) {
        (self.blocks, self.bytes)
    }
    fn charge(&mut self, bytes: usize) -> Result<(), TreeError> {
        if self.blocks == 0 || self.bytes < bytes as u64 {
            return Err(TreeError::WriteBudgetExceeded);
        }
        self.blocks -= 1;
        self.bytes -= bytes as u64;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct Branch {
    bit: u16,
    prefix: TreeKey,
    left: BlockRef,
    right: BlockRef,
}

#[derive(Debug)]
enum Node {
    Leaf(TreeKey, Vec<u8>),
    Chunked(TreeKey, u32, Vec<BlockRef>),
    Branch(Branch),
}

impl Node {
    fn key(&self) -> &TreeKey {
        match self {
            Self::Leaf(key, _) | Self::Chunked(key, ..) => key,
            Self::Branch(branch) => &branch.prefix,
        }
    }
    fn depth(&self) -> u16 {
        match self {
            Self::Leaf(..) | Self::Chunked(..) => 256,
            Self::Branch(branch) => branch.bit,
        }
    }
    fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
        if bytes.len() < 5 || &bytes[..4] != MAGIC {
            return Err(TreeError::InvalidNode);
        }
        match bytes[4] {
            0 if bytes.len() >= LEAF_HEADER => {
                let key = bytes[5..37]
                    .try_into()
                    .map_err(|_| TreeError::InvalidNode)?;
                let len = u32::from_le_bytes(
                    bytes[37..41]
                        .try_into()
                        .map_err(|_| TreeError::InvalidNode)?,
                ) as usize;
                if len > MAX_INLINE_TREE_VALUE_BYTES || bytes.len() - LEAF_HEADER != len {
                    return Err(TreeError::InvalidNode);
                }
                Ok(Self::Leaf(key, bytes[41..].to_vec()))
            }
            2 if bytes.len() >= LEAF_HEADER => {
                let key = bytes[5..37]
                    .try_into()
                    .map_err(|_| TreeError::InvalidNode)?;
                let len = u32::from_le_bytes(
                    bytes[37..41]
                        .try_into()
                        .map_err(|_| TreeError::InvalidNode)?,
                );
                let size = len as usize;
                if size <= MAX_INLINE_TREE_VALUE_BYTES || size > MAX_TREE_VALUE_BYTES {
                    return Err(TreeError::InvalidNode);
                }
                let count = size.div_ceil(MAX_STATE_BLOCK_BYTES);
                if bytes.len() != LEAF_HEADER + 36 * count {
                    return Err(TreeError::InvalidNode);
                }
                let mut references = Vec::with_capacity(count);
                for index in 0..count {
                    let start = LEAF_HEADER + index * 36;
                    let hash = Hash(
                        bytes[start..start + 32]
                            .try_into()
                            .map_err(|_| TreeError::InvalidNode)?,
                    );
                    let length = u32::from_le_bytes(
                        bytes[start + 32..start + 36]
                            .try_into()
                            .map_err(|_| TreeError::InvalidNode)?,
                    );
                    if length as usize
                        != (size - index * MAX_STATE_BLOCK_BYTES).min(MAX_STATE_BLOCK_BYTES)
                    {
                        return Err(TreeError::InvalidNode);
                    }
                    references.push(BlockRef::new(hash, length)?);
                }
                Ok(Self::Chunked(key, len, references))
            }
            1 if bytes.len() == BRANCH_BYTES => {
                let bit = u16::from_le_bytes([bytes[5], bytes[6]]);
                let prefix: TreeKey = bytes[7..39]
                    .try_into()
                    .map_err(|_| TreeError::InvalidNode)?;
                if bit >= 256 || prefix_at(&prefix, bit) != prefix {
                    return Err(TreeError::InvalidNode);
                }
                let reference = |start: usize| -> Result<BlockRef, TreeError> {
                    let hash = Hash(
                        bytes[start..start + 32]
                            .try_into()
                            .map_err(|_| TreeError::InvalidNode)?,
                    );
                    let len = u32::from_le_bytes(
                        bytes[start + 32..start + 36]
                            .try_into()
                            .map_err(|_| TreeError::InvalidNode)?,
                    );
                    Ok(BlockRef::new(hash, len)?)
                };
                let left = reference(39)?;
                let right = reference(75)?;
                if left == right {
                    return Err(TreeError::InvalidNode);
                }
                Ok(Self::Branch(Branch {
                    bit,
                    prefix,
                    left,
                    right,
                }))
            }
            _ => Err(TreeError::InvalidNode),
        }
    }
    fn encoded_len(&self) -> usize {
        match self {
            Self::Leaf(_, value) => LEAF_HEADER + value.len(),
            Self::Chunked(_, _, references) => LEAF_HEADER + 36 * references.len(),
            Self::Branch(_) => BRANCH_BYTES,
        }
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(MAGIC);
        match self {
            Self::Leaf(key, value) => {
                bytes.push(0);
                bytes.extend_from_slice(key);
                bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
                bytes.extend_from_slice(value);
            }
            Self::Chunked(key, len, references) => {
                bytes.push(2);
                bytes.extend_from_slice(key);
                bytes.extend_from_slice(&len.to_le_bytes());
                for reference in references {
                    bytes.extend_from_slice(reference.hash().as_bytes());
                    bytes.extend_from_slice(&reference.byte_len().to_le_bytes());
                }
            }
            Self::Branch(branch) => {
                bytes.push(1);
                bytes.extend_from_slice(&branch.bit.to_le_bytes());
                bytes.extend_from_slice(&branch.prefix);
                for reference in [branch.left, branch.right] {
                    bytes.extend_from_slice(reference.hash().as_bytes());
                    bytes.extend_from_slice(&reference.byte_len().to_le_bytes());
                }
            }
        }
        bytes
    }

    fn value(
        &self,
        scope: BlockScope,
        reader: &mut impl BlockReader,
        reads: &mut ReadBudget,
    ) -> Result<Vec<u8>, TreeError> {
        match self {
            Self::Leaf(_, value) => Ok(value.clone()),
            Self::Chunked(_, _, references) => {
                // Grow only after each fetch is admitted and authenticated. Do
                // not allocate the declared value size before charging reads.
                let mut value = Vec::new();
                for reference in references {
                    let permit = reads.begin_fetch(scope, *reference)?;
                    let mut chunk = vec![0; reference.byte_len() as usize];
                    let available = reader.read(*reference, &mut chunk)?;
                    value.extend_from_slice(permit.verify(available.then_some(chunk.as_slice()))?);
                }
                Ok(value)
            }
            Self::Branch(_) => Err(TreeError::InvalidNode),
        }
    }
}

fn stage_node(
    scope: BlockScope,
    node: Node,
    writes: &mut WriteBudget,
    blocks: &mut Vec<(BlockRef, Vec<u8>)>,
) -> Result<BlockRef, TreeError> {
    writes.charge(node.encoded_len())?;
    let bytes = node.encode();
    let reference = scope.reference(&bytes)?;
    blocks.push((reference, bytes));
    Ok(reference)
}

fn stage_value(
    scope: BlockScope,
    key: TreeKey,
    value: &[u8],
    writes: &mut WriteBudget,
    blocks: &mut Vec<(BlockRef, Vec<u8>)>,
) -> Result<BlockRef, TreeError> {
    let node = if value.len() <= MAX_INLINE_TREE_VALUE_BYTES {
        Node::Leaf(key, value.to_vec())
    } else {
        let mut references = Vec::new();
        for chunk in value.chunks(MAX_STATE_BLOCK_BYTES) {
            writes.charge(chunk.len())?;
            let reference = scope.reference(chunk)?;
            blocks.push((reference, chunk.to_vec()));
            references.push(reference);
        }
        Node::Chunked(key, value.len() as u32, references)
    };
    stage_node(scope, node, writes, blocks)
}

fn bit(key: &TreeKey, position: u16) -> bool {
    key[position as usize / 8] & (0x80 >> (position % 8)) != 0
}

fn prefix_at(key: &TreeKey, depth: u16) -> TreeKey {
    let mut prefix = *key;
    if depth < 256 {
        let byte = depth as usize / 8;
        prefix[byte] &= !(0xff >> (depth % 8));
        prefix[byte + 1..].fill(0);
    }
    prefix
}

fn difference(a: &TreeKey, b: &TreeKey) -> u16 {
    for (index, (a, b)) in a.iter().zip(b).enumerate() {
        let xor = a ^ b;
        if xor != 0 {
            return index as u16 * 8 + xor.leading_zeros() as u16;
        }
    }
    256
}

type Path = Vec<(Branch, bool)>;
type Terminal = Option<(BlockRef, Node)>;

impl StateTree {
    pub const fn scope(self) -> BlockScope {
        self.scope
    }

    /// Verify new links using candidate bytes and membership paths under this
    /// base, without enumerating reused subtrees. The caller must independently
    /// establish and retain the base's complete availability (e.g. at recovery).
    /// Missing old descendants are NOT detected by this incremental check.
    /// New chunked leaves carry all chunks, even when a chunk already exists.
    /// This avoids treating arbitrary stored bytes as certified subtree data.
    pub(crate) fn verify_candidate(
        &self,
        root: Option<BlockRef>,
        blocks: &[(BlockRef, Vec<u8>)],
        reader: &mut impl BlockReader,
        budget: &mut ReadBudget,
    ) -> Result<ChangeReachability, TreeError> {
        type Parent = Option<(u16, TreeKey, bool)>;
        let mut pending: Vec<(BlockRef, StateBlockKind, Parent)> = Vec::new();
        if let Some(root) = root {
            pending.push((root, StateBlockKind::TreeNode, None));
        }
        let mut used = BTreeSet::new();
        let mut result = ChangeReachability::default();
        while let Some((reference, kind, parent)) = pending.pop() {
            let supplied = blocks
                .binary_search_by_key(&reference.hash().0, |(r, _)| r.hash().0)
                .ok();
            if supplied.is_none()
                && parent.is_none()
                && kind == StateBlockKind::TreeNode
                && Some(reference) == self.root
            {
                result.reused_subtrees += 1;
                continue;
            }
            let permit = budget.begin_fetch(self.scope, reference)?;
            let stored;
            let bytes = match supplied {
                Some(index) => {
                    let (actual, bytes) = &blocks[index];
                    if *actual != reference {
                        return Err(TreeError::InvalidNode);
                    }
                    used.insert(index);
                    result.candidate_visits = result
                        .candidate_visits
                        .checked_add(1)
                        .ok_or(TreeError::InvalidNode)?;
                    bytes.as_slice()
                }
                None => {
                    if kind == StateBlockKind::ValueChunk {
                        return Err(TreeError::PreconditionFailed);
                    }
                    stored = {
                        let mut bytes = vec![0; reference.byte_len() as usize];
                        if !reader.read(reference, &mut bytes)? {
                            return Err(BlockError::Unavailable.into());
                        }
                        bytes
                    };
                    stored.as_slice()
                }
            };
            permit.verify(Some(bytes))?;
            if kind == StateBlockKind::ValueChunk {
                continue;
            }
            let node = Node::decode(bytes)?;
            if let Some((depth, prefix, right)) = parent {
                if node.depth() <= depth
                    || prefix_at(node.key(), depth) != prefix
                    || bit(node.key(), depth) != right
                {
                    return Err(TreeError::InvalidNode);
                }
            }
            if supplied.is_none() {
                if !self.contains_node(reference, node.key(), reader, budget)? {
                    return Err(TreeError::PreconditionFailed);
                }
                result.reused_subtrees = result
                    .reused_subtrees
                    .checked_add(1)
                    .ok_or(TreeError::InvalidNode)?;
                continue;
            }
            match node {
                Node::Branch(branch) => {
                    pending.push((
                        branch.right,
                        StateBlockKind::TreeNode,
                        Some((branch.bit, branch.prefix, true)),
                    ));
                    pending.push((
                        branch.left,
                        StateBlockKind::TreeNode,
                        Some((branch.bit, branch.prefix, false)),
                    ));
                }
                Node::Chunked(_, _, chunks) => pending.extend(
                    chunks
                        .into_iter()
                        .map(|r| (r, StateBlockKind::ValueChunk, None)),
                ),
                Node::Leaf(..) => {}
            }
            if pending.len() > 256 + MAX_TREE_VALUE_BYTES.div_ceil(MAX_STATE_BLOCK_BYTES) {
                return Err(TreeError::InvalidNode);
            }
        }
        if used.len() != blocks.len() {
            return Err(TreeError::PreconditionFailed);
        }
        Ok(result)
    }

    /// Authenticate only the membership path; never fetch descendants of the
    /// target subtree. Its complete availability is an independent precondition.
    fn contains_node(
        &self,
        target: BlockRef,
        key: &TreeKey,
        reader: &mut impl BlockReader,
        budget: &mut ReadBudget,
    ) -> Result<bool, TreeError> {
        let mut current = self.root;
        let mut parent: Option<(Branch, bool)> = None;
        while let Some(reference) = current {
            if reference == target {
                return Ok(true);
            }
            let permit = budget.begin_fetch(self.scope, reference)?;
            let mut bytes = vec![0; reference.byte_len() as usize];
            let found = reader.read(reference, &mut bytes)?;
            let node = Node::decode(permit.verify(found.then_some(bytes.as_slice()))?)?;
            if let Some((branch, right)) = &parent {
                if node.depth() <= branch.bit
                    || prefix_at(node.key(), branch.bit) != branch.prefix
                    || bit(node.key(), branch.bit) != *right
                {
                    return Err(TreeError::InvalidNode);
                }
            }
            let Node::Branch(branch) = node else {
                return Ok(false);
            };
            if prefix_at(key, branch.bit) != branch.prefix {
                return Ok(false);
            }
            let right = bit(key, branch.bit);
            current = Some(if right { branch.right } else { branch.left });
            parent = Some((branch, right));
        }
        Ok(false)
    }

    /// Full bounded-memory recovery/import audit, NOT a request/publication
    /// fast path. Normal publication must validate only changed links against
    /// previously established durable availability. This checks all reachable
    /// blocks and branch placement without decoding private value layouts.
    /// Read budgets cap total work, and failure returns no partial success.
    pub fn audit(
        &self,
        reader: &mut impl BlockReader,
        budget: &mut ReadBudget,
    ) -> Result<TreeAudit, TreeError> {
        type Parent = Option<(u16, TreeKey, bool)>;
        let mut pending: Vec<(BlockRef, StateBlockKind, Parent)> = Vec::new();
        if let Some(root) = self.root {
            pending.push((root, StateBlockKind::TreeNode, None));
        }
        let mut audit = TreeAudit::default();
        while let Some((reference, kind, parent)) = pending.pop() {
            let _permit = budget.begin_fetch(self.scope, reference)?;
            let mut bytes = vec![0; reference.byte_len() as usize];
            if !reader.read(reference, &mut bytes)? {
                return Err(BlockError::Unavailable.into());
            }
            // `inspect_state_block` performs the scoped verification. Do not
            // hash twice merely because audit also shares the fetch budget.
            let shape = inspect_state_block(self.scope, kind, reference, &bytes)?;
            audit.block_visits = audit
                .block_visits
                .checked_add(1)
                .ok_or(TreeError::InvalidNode)?;
            if let Some((parent_bit, prefix, right)) = parent {
                let (key, depth) = match &shape {
                    StateBlockShape::Branch { bit, prefix, .. } => (prefix, *bit),
                    StateBlockShape::Value { key, .. } => (key, 256),
                    StateBlockShape::Chunk { .. } => return Err(TreeError::InvalidNode),
                };
                if depth <= parent_bit
                    || prefix_at(key, parent_bit) != prefix
                    || bit(key, parent_bit) != right
                {
                    return Err(TreeError::InvalidNode);
                }
            }
            match shape {
                StateBlockShape::Branch {
                    bit,
                    prefix,
                    left,
                    right,
                } => {
                    pending.push((right, StateBlockKind::TreeNode, Some((bit, prefix, true))));
                    pending.push((left, StateBlockKind::TreeNode, Some((bit, prefix, false))));
                }
                StateBlockShape::Value { bytes, chunks, .. } => {
                    audit.rows = audit.rows.checked_add(1).ok_or(TreeError::InvalidNode)?;
                    audit.value_bytes = audit
                        .value_bytes
                        .checked_add(u64::from(bytes))
                        .ok_or(TreeError::InvalidNode)?;
                    pending.extend(
                        chunks
                            .into_iter()
                            .map(|reference| (reference, StateBlockKind::ValueChunk, None)),
                    );
                }
                StateBlockShape::Chunk { .. } => {}
            }
            // At most 256 pending sibling branches plus one value's chunks.
            // Keep this explicit so later graph-format changes cannot silently
            // turn recovery into an unbounded traversal allocation.
            if pending.len() > 256 + MAX_TREE_VALUE_BYTES.div_ceil(MAX_STATE_BLOCK_BYTES) {
                return Err(TreeError::InvalidNode);
            }
        }
        Ok(audit)
    }
    pub const fn empty(scope: BlockScope) -> Self {
        Self { scope, root: None }
    }

    /// Binding only, NOT verification of revision authority or full-tree shape.
    /// Caller must admit/audit an imported root before allowing authoritative use.
    pub const fn from_root(scope: BlockScope, root: Option<BlockRef>) -> Self {
        Self { scope, root }
    }
    pub const fn root(self) -> Option<BlockRef> {
        self.root
    }

    fn walk(
        &self,
        key: &TreeKey,
        reader: &mut impl BlockReader,
        budget: &mut ReadBudget,
    ) -> Result<(Path, Terminal), TreeError> {
        let mut path: Path = Vec::new();
        let mut next = self.root;
        while let Some(reference) = next {
            let permit = budget.begin_fetch(self.scope, reference)?;
            let mut bytes = vec![0; reference.byte_len() as usize];
            let available = reader.read(reference, &mut bytes)?;
            let bytes = permit.verify(available.then_some(bytes.as_slice()))?;
            let node = Node::decode(bytes)?;
            if let Some((parent, right)) = path.last() {
                if node.depth() <= parent.bit
                    || prefix_at(node.key(), parent.bit) != parent.prefix
                    || bit(node.key(), parent.bit) != *right
                {
                    return Err(TreeError::InvalidNode);
                }
            }
            match &node {
                Node::Leaf(..) | Node::Chunked(..) => return Ok((path, Some((reference, node)))),
                Node::Branch(branch) => {
                    if prefix_at(key, branch.bit) != branch.prefix {
                        return Ok((path, Some((reference, node))));
                    }
                    let right = bit(key, branch.bit);
                    next = Some(if right { branch.right } else { branch.left });
                    path.push((branch.clone(), right));
                }
            }
        }
        Ok((path, None))
    }

    pub fn get(
        &self,
        key: &TreeKey,
        reader: &mut impl BlockReader,
        budget: &mut ReadBudget,
    ) -> Result<Option<Vec<u8>>, TreeError> {
        match self.walk(key, reader, budget)?.1 {
            Some((_, node)) if node.depth() == 256 && node.key() == key => {
                Ok(Some(node.value(self.scope, reader, budget)?))
            }
            _ => Ok(None),
        }
    }

    /// Stage one insertion/replacement/deletion. Failure leaves this root and
    /// the provider untouched. Charged work is not refunded on later failure.
    pub fn update(
        &self,
        key: TreeKey,
        value: Option<&[u8]>,
        reader: &mut impl BlockReader,
        reads: &mut ReadBudget,
        writes: &mut WriteBudget,
    ) -> Result<TreeUpdate, TreeError> {
        self.update_checked(key, value, reader, (reads, writes), |_| Ok(()))
    }

    /// Runtime adapters may validate the existing authenticated value before
    /// replacement, without a second tree traversal or any emitted blocks.
    pub(crate) fn update_checked(
        &self,
        key: TreeKey,
        value: Option<&[u8]>,
        reader: &mut impl BlockReader,
        budgets: (&mut ReadBudget, &mut WriteBudget),
        check: impl FnOnce(Option<&[u8]>) -> Result<(), TreeError>,
    ) -> Result<TreeUpdate, TreeError> {
        let (reads, writes) = budgets;
        if value.is_some_and(|value| value.len() > MAX_TREE_VALUE_BYTES) {
            return Err(TreeError::InvalidValue);
        }
        let (path, terminal) = self.walk(&key, reader, reads)?;
        let existing = match &terminal {
            Some((_, node)) if node.depth() == 256 && node.key() == &key => {
                Some(node.value(self.scope, reader, reads)?)
            }
            _ => None,
        };
        check(existing.as_deref())?;
        if existing.as_deref() == value {
            return Ok(TreeUpdate {
                tree: *self,
                blocks: Vec::new(),
            });
        }
        let mut blocks = Vec::new();
        let mut replacement = match value {
            None => None,
            Some(value) => {
                let leaf = stage_value(self.scope, key, value, writes, &mut blocks)?;
                match terminal {
                    Some((old, node)) if existing.is_none() => {
                        let split = difference(&key, node.key());
                        // A branch terminal was reached only for prefix mismatch;
                        // a distinct leaf differs before the end of its key.
                        if split >= node.depth() {
                            return Err(TreeError::InvalidNode);
                        }
                        let (left, right) = if bit(&key, split) {
                            (old, leaf)
                        } else {
                            (leaf, old)
                        };
                        Some(stage_node(
                            self.scope,
                            Node::Branch(Branch {
                                bit: split,
                                prefix: prefix_at(&key, split),
                                left,
                                right,
                            }),
                            writes,
                            &mut blocks,
                        )?)
                    }
                    _ => Some(leaf),
                }
            }
        };
        for (mut branch, right) in path.into_iter().rev() {
            replacement = Some(match replacement {
                None => {
                    if right {
                        branch.left
                    } else {
                        branch.right
                    }
                }
                Some(child) => {
                    if right {
                        branch.right = child;
                    } else {
                        branch.left = child;
                    }
                    stage_node(self.scope, Node::Branch(branch), writes, &mut blocks)?
                }
            });
        }
        Ok(TreeUpdate {
            tree: Self {
                scope: self.scope,
                root: replacement,
            },
            blocks,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{AgentId, SpaceId, StateLane};
    use alloc::collections::BTreeMap;

    #[derive(Default)]
    struct Store {
        blocks: BTreeMap<[u8; 32], Vec<u8>>,
        fetches: u32,
        bytes: u64,
    }
    impl BlockReader for Store {
        fn read(&mut self, reference: BlockRef, output: &mut [u8]) -> Result<bool, TreeError> {
            self.fetches += 1;
            self.bytes += output.len() as u64;
            let Some(bytes) = self.blocks.get(&reference.hash().0) else {
                return Ok(false);
            };
            if bytes.len() != output.len() {
                return Err(TreeError::Storage);
            }
            output.copy_from_slice(bytes);
            Ok(true)
        }
    }
    impl Store {
        fn install(&mut self, update: TreeUpdate) -> StateTree {
            for (reference, bytes) in update.blocks {
                assert_eq!(update.tree.scope.reference(&bytes).unwrap(), reference);
                self.blocks.insert(reference.hash().0, bytes);
            }
            update.tree
        }
    }
    fn scope() -> BlockScope {
        BlockScope::new(
            SpaceId([1; 32]),
            AgentId([2; 32]),
            Hash([3; 32]),
            StateLane::Linear,
        )
        .unwrap()
    }
    fn key(number: u32) -> TreeKey {
        Hash::digest(b"tree-test-key", &[&number.to_le_bytes()]).0
    }
    fn reads() -> ReadBudget {
        ReadBudget::new(257, 257 * MAX_STATE_BLOCK_BYTES as u64)
    }
    fn writes() -> WriteBudget {
        WriteBudget::new(274, 2 * 1024 * 1024)
    }
    fn put(tree: StateTree, store: &mut Store, key: TreeKey, value: Option<&[u8]>) -> StateTree {
        let update = tree
            .update(key, value, store, &mut reads(), &mut writes())
            .unwrap();
        store.install(update)
    }
    fn get(tree: StateTree, store: &mut Store, key: TreeKey) -> Option<Vec<u8>> {
        tree.get(&key, store, &mut reads()).unwrap()
    }

    fn change(
        tree: StateTree,
        update: TreeUpdate,
    ) -> (
        crate::state_root::StateRootDescriptor,
        crate::state_change::StateChange,
    ) {
        use crate::state_root::{RootContext, StateRootDescriptor};
        let before = RootContext::new(tree.scope(), Hash([4; 32]), Hash([5; 32])).unwrap();
        let after = RootContext::new(tree.scope(), Hash([4; 32]), Hash([6; 32])).unwrap();
        let base = StateRootDescriptor::new(before, tree.root());
        (
            base,
            crate::state_change::StateChange::from_update(base.commitment(), after, update)
                .unwrap(),
        )
    }

    #[test]
    fn incremental_reuse_checks_insert_replace_delete_and_noop_without_full_scan() {
        for count in [16, 256, 4096] {
            let mut store = Store::default();
            let mut tree = StateTree::empty(scope());
            for n in 0..count {
                tree = put(tree, &mut store, key(n), Some(b"value"));
            }
            for (key, value) in [
                (key(5), Some(b"new".as_slice())),
                (key(count), Some(b"inserted".as_slice())),
                (key(2), None),
                (key(8), Some(b"value".as_slice())),
            ] {
                let update = tree
                    .update(key, value, &mut store, &mut reads(), &mut writes())
                    .unwrap();
                let next = update.tree;
                let (base, candidate) = change(tree, update);
                let before = (store.fetches, store.bytes);
                let result = candidate
                    .verify_reuse(
                        base,
                        candidate.next().context(),
                        &mut store,
                        &mut ReadBudget::new(1024, 1000000),
                    )
                    .unwrap();
                assert!(store.fetches - before.0 < 512);
                assert!(store.bytes - before.1 < 64000);
                assert!(result.reused_subtrees > 0);
                tree = store.install(TreeUpdate {
                    tree: next,
                    blocks: candidate.blocks().to_vec(),
                });
                assert_eq!(get(tree, &mut store, key).as_deref(), value);
            }
        }
    }

    #[test]
    fn incremental_reuse_requires_membership_not_just_stored_bytes() {
        let mut store = Store::default();
        let tree = put(StateTree::empty(scope()), &mut store, key(1), Some(b"base"));
        let orphan = put(
            StateTree::empty(scope()),
            &mut store,
            key(9),
            Some(b"orphan"),
        );
        let (base, candidate) = change(
            tree,
            TreeUpdate {
                tree: orphan,
                blocks: Vec::new(),
            },
        );
        assert_eq!(
            candidate.verify_reuse(base, candidate.next().context(), &mut store, &mut reads()),
            Err(TreeError::PreconditionFailed)
        );
        let update = tree
            .update(
                key(1),
                Some(b"new"),
                &mut store,
                &mut reads(),
                &mut writes(),
            )
            .unwrap();
        let (base, candidate) = change(tree, update);
        let before = store.fetches;
        assert_eq!(
            candidate.verify_reuse(
                base,
                candidate.next().context(),
                &mut store,
                &mut ReadBudget::new(0, 0)
            ),
            Err(TreeError::Block(BlockError::BudgetExceeded))
        );
        assert_eq!(store.fetches, before);
        assert_eq!(
            candidate.verify_reuse(base, base.context(), &mut store, &mut reads()),
            Err(TreeError::PreconditionFailed)
        );
        assert_eq!(store.fetches, before);
        let unused = Node::Leaf(key(3), vec![7]).encode();
        let update = TreeUpdate {
            tree,
            blocks: vec![(scope().reference(&unused).unwrap(), unused)],
        };
        let (base, candidate) = change(tree, update);
        assert_eq!(
            candidate.verify_reuse(base, candidate.next().context(), &mut store, &mut reads()),
            Err(TreeError::PreconditionFailed)
        );
    }

    #[test]
    fn incremental_new_chunked_leaves_require_complete_candidate_payloads() {
        let mut store = Store::default();
        let tree = StateTree::empty(scope());
        let update = tree
            .update(
                key(1),
                Some(&vec![9; 65536]),
                &mut store,
                &mut reads(),
                &mut writes(),
            )
            .unwrap();
        let next = update.tree;
        let (base, complete) = change(tree, update);
        assert!(
            complete
                .verify_reuse(base, complete.next().context(), &mut store, &mut reads())
                .is_ok()
        );
        let missing_payload = TreeUpdate {
            tree: next,
            blocks: complete
                .blocks()
                .iter()
                .filter(|(r, _)| Some(*r) == next.root())
                .cloned()
                .collect(),
        };
        store.install(TreeUpdate {
            tree: next,
            blocks: complete.blocks().to_vec(),
        });
        let (base, partial) = change(tree, missing_payload);
        assert_eq!(
            partial.verify_reuse(base, partial.next().context(), &mut store, &mut reads()),
            Err(TreeError::PreconditionFailed),
            "preexisting bytes alone cannot establish chunk reuse"
        );
        // Deleting the sole key needs no data reads or new blocks.
        let (base, deletion) = change(
            next,
            TreeUpdate {
                tree,
                blocks: Vec::new(),
            },
        );
        assert!(
            deletion
                .verify_reuse(
                    base,
                    deletion.next().context(),
                    &mut store,
                    &mut ReadBudget::new(0, 0)
                )
                .is_ok()
        );
    }

    #[test]
    fn incremental_reuse_rejects_misplaced_children_and_corrupt_membership_paths() {
        let mut store = Store::default();
        let tree = put(
            StateTree::empty(scope()),
            &mut store,
            [0; 32],
            Some(b"left"),
        );
        let wrong = Node::Leaf([0; 32], b"wrong right".to_vec()).encode();
        let wrong_ref = scope().reference(&wrong).unwrap();
        let root = Node::Branch(Branch {
            bit: 0,
            prefix: [0; 32],
            left: tree.root().unwrap(),
            right: wrong_ref,
        })
        .encode();
        let root_ref = scope().reference(&root).unwrap();
        let (base, candidate) = change(
            tree,
            TreeUpdate {
                tree: StateTree::from_root(scope(), Some(root_ref)),
                blocks: vec![(wrong_ref, wrong), (root_ref, root)],
            },
        );
        assert_eq!(
            candidate.verify_reuse(base, candidate.next().context(), &mut store, &mut reads()),
            Err(TreeError::InvalidNode)
        );
        let tree = put(tree, &mut store, [255; 32], Some(b"right"));
        let update = tree
            .update(
                [0; 32],
                Some(b"new left"),
                &mut store,
                &mut reads(),
                &mut writes(),
            )
            .unwrap();
        let (base, candidate) = change(tree, update);
        let root = tree.root().unwrap();
        store.blocks.get_mut(&root.hash().0).unwrap()[0] ^= 1;
        assert_eq!(
            candidate.verify_reuse(base, candidate.next().context(), &mut store, &mut reads()),
            Err(TreeError::Block(BlockError::HashMismatch))
        );
        store.blocks.remove(&root.hash().0);
        assert_eq!(
            candidate.verify_reuse(base, candidate.next().context(), &mut store, &mut reads()),
            Err(TreeError::Block(BlockError::Unavailable))
        );
    }

    #[test]
    fn insert_replace_delete_preserve_old_roots_and_distinguish_empty_values() {
        let mut store = Store::default();
        let empty = StateTree::empty(scope());
        let first = put(empty, &mut store, key(1), Some(b"old"));
        let second = put(first, &mut store, key(2), Some(b""));
        let third = put(second, &mut store, key(1), Some(b"new"));
        let fourth = put(third, &mut store, key(2), None);
        assert_eq!(get(first, &mut store, key(1)), Some(b"old".to_vec()));
        assert_eq!(get(second, &mut store, key(2)), Some(vec![]));
        assert_eq!(get(third, &mut store, key(1)), Some(b"new".to_vec()));
        assert_eq!(get(fourth, &mut store, key(2)), None);
        assert_eq!(put(fourth, &mut store, key(1), None), empty);
        assert_eq!(get(empty, &mut store, key(1)), None);
    }

    #[test]
    fn canonical_roots_are_independent_of_insertion_order_and_deleted_history() {
        let mut store = Store::default();
        let mut forward = StateTree::empty(scope());
        let mut reverse = forward;
        for i in 0u32..128 {
            forward = put(forward, &mut store, key(i), Some(&i.to_le_bytes()));
        }
        for i in (0u32..128).rev() {
            reverse = put(reverse, &mut store, key(i), Some(&i.to_le_bytes()));
        }
        assert_eq!(forward, reverse);
        let extra = put(forward, &mut store, key(200), Some(b"extra"));
        assert_eq!(put(extra, &mut store, key(200), None), forward);
        for i in 0u32..128 {
            assert_eq!(
                get(forward, &mut store, key(i)),
                Some(i.to_le_bytes().to_vec())
            );
        }
    }

    #[test]
    fn deterministic_mixed_operations_match_reference_map() {
        let mut store = Store::default();
        let mut tree = StateTree::empty(scope());
        let mut expected = BTreeMap::new();
        let mut seed = 17u32;
        for step in 0u32..2048 {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            let selected = key((seed >> 16) % 97);
            let bytes = step.to_le_bytes();
            let value = if seed & 3 == 0 {
                None
            } else {
                Some(bytes.as_slice())
            };
            tree = put(tree, &mut store, selected, value);
            if let Some(value) = value {
                expected.insert(selected, value.to_vec());
            } else {
                expected.remove(&selected);
            }
            assert_eq!(
                get(tree, &mut store, selected),
                expected.get(&selected).cloned()
            );
        }
        for i in 0..100 {
            assert_eq!(
                get(tree, &mut store, key(i)),
                expected.get(&key(i)).cloned()
            );
        }
    }

    #[test]
    fn identical_writes_and_absent_deletes_emit_no_blocks() {
        let mut store = Store::default();
        let tree = put(StateTree::empty(scope()), &mut store, key(1), Some(b"data"));
        for (key, value) in [(key(1), Some(&b"data"[..])), (key(2), None)] {
            let update = tree
                .update(
                    key,
                    value,
                    &mut store,
                    &mut reads(),
                    &mut WriteBudget::new(0, 0),
                )
                .unwrap();
            assert_eq!(update.tree, tree);
            assert!(update.blocks.is_empty());
        }
    }

    #[test]
    fn unavailable_corrupt_and_cross_scope_blocks_never_become_absence() {
        let mut store = Store::default();
        let tree = put(StateTree::empty(scope()), &mut store, key(1), Some(b"data"));
        let root = tree.root().unwrap();
        let bytes = store.blocks.remove(&root.hash().0).unwrap();
        assert_eq!(
            tree.get(&key(2), &mut store, &mut reads()),
            Err(TreeError::Block(BlockError::Unavailable))
        );
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        store.blocks.insert(root.hash().0, corrupt);
        assert_eq!(
            tree.get(&key(2), &mut store, &mut reads()),
            Err(TreeError::Block(BlockError::HashMismatch))
        );
        store.blocks.insert(root.hash().0, bytes);
        let foreign = BlockScope::new(
            SpaceId([1; 32]),
            AgentId([8; 32]),
            Hash([3; 32]),
            StateLane::Linear,
        )
        .unwrap();
        assert_eq!(
            StateTree::from_root(foreign, Some(root)).get(&key(1), &mut store, &mut reads()),
            Err(TreeError::Block(BlockError::HashMismatch))
        );
        assert_eq!(get(tree, &mut store, key(2)), None);
    }

    #[test]
    fn budget_failures_never_write_provider_or_publish_candidate() {
        let mut store = Store::default();
        let tree = put(StateTree::empty(scope()), &mut store, key(1), Some(b"data"));
        let before = store.blocks.clone();
        let fetches = store.fetches;
        assert_eq!(
            tree.get(&key(1), &mut store, &mut ReadBudget::new(0, 0)),
            Err(TreeError::Block(BlockError::BudgetExceeded))
        );
        assert_eq!(store.fetches, fetches);
        // New leaf fits, but its parent does not: no partial update escapes.
        let mut budget = WriteBudget::new(1, 1024);
        assert!(matches!(
            tree.update(key(2), Some(b"next"), &mut store, &mut reads(), &mut budget),
            Err(TreeError::WriteBudgetExceeded)
        ));
        assert_eq!(budget.remaining().0, 0);
        assert_eq!(store.blocks, before);
        assert_eq!(get(tree, &mut store, key(1)), Some(b"data".to_vec()));
        assert_eq!(get(tree, &mut store, key(2)), None);
    }

    #[test]
    fn deepest_radix_path_is_iterative_and_bounded() {
        let mut store = Store::default();
        let zero = [0; 32];
        let mut tree = put(StateTree::empty(scope()), &mut store, zero, Some(b"zero"));
        for depth in 0..256 {
            let mut key = zero;
            key[depth / 8] = 0x80 >> (depth % 8);
            tree = put(tree, &mut store, key, Some(b"sibling"));
        }
        let before = store.fetches;
        assert_eq!(get(tree, &mut store, zero), Some(b"zero".to_vec()));
        assert_eq!(store.fetches - before, 257);
        let update = tree
            .update(
                zero,
                Some(b"replacement"),
                &mut store,
                &mut reads(),
                &mut writes(),
            )
            .unwrap();
        assert_eq!(update.blocks.len(), 257);
        let updated = store.install(update);
        assert_eq!(
            get(updated, &mut store, zero),
            Some(b"replacement".to_vec())
        );
        // Exercise the maximum audit frontier: all 256 right siblings
        // pending while the deepest left leaf contributes 16 value chunks.
        let updated = put(
            updated,
            &mut store,
            zero,
            Some(&vec![8; MAX_TREE_VALUE_BYTES]),
        );
        assert_eq!(
            updated.audit(&mut store, &mut ReadBudget::new(529, 2 * 1024 * 1024)),
            Ok(TreeAudit {
                rows: 257,
                value_bytes: (MAX_TREE_VALUE_BYTES + 256 * b"sibling".len()) as u64,
                block_visits: 529,
            })
        );
    }

    #[test]
    fn codec_rejects_truncation_trailing_bytes_and_noncanonical_prefixes() {
        let leaf = Node::Leaf(key(1), vec![1, 2, 3]).encode();
        for end in 0..leaf.len() {
            assert!(Node::decode(&leaf[..end]).is_err());
        }
        let mut trailing = leaf.clone();
        trailing.push(0);
        assert!(Node::decode(&trailing).is_err());
        let left = scope().reference(&leaf).unwrap();
        let right = scope()
            .reference(&Node::Leaf(key(2), vec![4]).encode())
            .unwrap();
        let canonical = Node::Branch(Branch {
            bit: 0,
            prefix: [0; 32],
            left,
            right,
        })
        .encode();
        assert!(Node::decode(&canonical).is_ok());
        let mut bad = canonical.clone();
        bad[7] = 1;
        assert!(Node::decode(&bad).is_err());
        let mut bad = canonical.clone();
        bad[5..7].copy_from_slice(&256u16.to_le_bytes());
        assert!(Node::decode(&bad).is_err());
        let mut bad = canonical;
        bad.copy_within(39..75, 75);
        assert!(Node::decode(&bad).is_err());
    }

    #[test]
    fn authenticated_but_misplaced_child_is_rejected() {
        let mut store = Store::default();
        let left_bytes = Node::Leaf([0; 32], vec![1]).encode();
        let right_bytes = Node::Leaf([0; 32], vec![2]).encode();
        let left = scope().reference(&left_bytes).unwrap();
        let right = scope().reference(&right_bytes).unwrap();
        let root_bytes = Node::Branch(Branch {
            bit: 0,
            prefix: [0; 32],
            left,
            right,
        })
        .encode();
        let root = scope().reference(&root_bytes).unwrap();
        for (reference, bytes) in [(left, left_bytes), (right, right_bytes), (root, root_bytes)] {
            store.blocks.insert(reference.hash().0, bytes);
        }
        let tree = StateTree::from_root(scope(), Some(root));
        assert_eq!(
            tree.get(&[255; 32], &mut store, &mut reads()),
            Err(TreeError::InvalidNode)
        );
        assert_eq!(
            tree.audit(&mut store, &mut reads()),
            Err(TreeError::InvalidNode)
        );
    }

    #[test]
    fn recovery_audit_counts_reachable_rows_and_repeated_chunk_visits() {
        let mut store = Store::default();
        let empty = StateTree::empty(scope());
        assert_eq!(
            empty.audit(&mut store, &mut ReadBudget::new(0, 0)),
            Ok(TreeAudit::default())
        );
        // Identical chunks share storage, but each authenticated reference is
        // visited. Chunk contents are opaque, even with tree-node magic.
        let mut chunk = vec![0; MAX_STATE_BLOCK_BYTES];
        chunk[..4].copy_from_slice(MAGIC);
        let value = [chunk.as_slice(), chunk.as_slice()].concat();
        let tree = put(empty, &mut store, key(1), Some(&value));
        let tree = put(tree, &mut store, key(2), Some(b""));
        // Retain an unreachable old value: it must not affect the audit.
        let tree = put(tree, &mut store, key(3), Some(b"old"));
        let tree = put(tree, &mut store, key(3), None);
        let before = store.fetches;
        assert_eq!(
            tree.audit(&mut store, &mut reads()),
            Ok(TreeAudit {
                rows: 2,
                value_bytes: value.len() as u64,
                block_visits: 5,
            })
        );
        assert_eq!(store.fetches - before, 5);
    }

    #[test]
    fn recovery_audit_rejects_missing_unrelated_data_and_corruption() {
        let mut store = Store::default();
        let value = vec![7; MAX_STATE_BLOCK_BYTES + 1];
        let tree = put(StateTree::empty(scope()), &mut store, key(1), Some(&value));
        let Node::Chunked(_, _, chunks) =
            Node::decode(&store.blocks[&tree.root().unwrap().hash().0]).unwrap()
        else {
            panic!("expected chunked value");
        };
        let tree = put(tree, &mut store, key(2), Some(b"available"));
        let missing = chunks[0];
        let original = store.blocks.remove(&missing.hash().0).unwrap();
        assert_eq!(get(tree, &mut store, key(2)), Some(b"available".to_vec()));
        assert_eq!(
            tree.audit(&mut store, &mut reads()),
            Err(TreeError::Block(BlockError::Unavailable))
        );
        let mut corrupt = original.clone();
        corrupt[0] ^= 1;
        store.blocks.insert(missing.hash().0, corrupt);
        assert_eq!(
            tree.audit(&mut store, &mut reads()),
            Err(TreeError::Block(BlockError::HashMismatch))
        );
        store.blocks.insert(missing.hash().0, original);
        assert_eq!(tree.audit(&mut store, &mut reads()).unwrap().rows, 2);
    }

    #[test]
    fn recovery_audit_charges_before_provider_io() {
        let mut store = Store::default();
        let tree = put(StateTree::empty(scope()), &mut store, key(1), Some(b"one"));
        let tree = put(tree, &mut store, key(2), Some(b"two"));
        for (mut budget, expected_reads) in [
            (ReadBudget::new(0, u64::MAX), 0),
            (
                ReadBudget::new(10, u64::from(tree.root().unwrap().byte_len()) - 1),
                0,
            ),
            (ReadBudget::new(1, u64::MAX), 1),
        ] {
            let before = store.fetches;
            assert_eq!(
                tree.audit(&mut store, &mut budget),
                Err(TreeError::Block(BlockError::BudgetExceeded))
            );
            assert_eq!(store.fetches - before, expected_reads);
        }
    }

    #[test]
    fn public_inspection_authenticates_scope_and_respects_block_role() {
        let bytes = Node::Leaf(key(1), vec![9]).encode();
        let reference = scope().reference(&bytes).unwrap();
        assert_eq!(
            inspect_state_block(scope(), StateBlockKind::TreeNode, reference, &bytes),
            Ok(StateBlockShape::Value {
                key: key(1),
                bytes: 1,
                chunks: Vec::new()
            })
        );
        assert_eq!(
            inspect_state_block(scope(), StateBlockKind::ValueChunk, reference, &bytes),
            Ok(StateBlockShape::Chunk {
                bytes: bytes.len() as u32
            })
        );
        let foreign = BlockScope::new(
            SpaceId([1; 32]),
            AgentId([9; 32]),
            Hash([3; 32]),
            StateLane::Linear,
        )
        .unwrap();
        assert_eq!(
            inspect_state_block(foreign, StateBlockKind::TreeNode, reference, &bytes),
            Err(TreeError::Block(BlockError::HashMismatch))
        );
        let malformed = b"VST1not a node";
        let reference = scope().reference(malformed).unwrap();
        assert_eq!(
            inspect_state_block(scope(), StateBlockKind::TreeNode, reference, malformed),
            Err(TreeError::InvalidNode)
        );
        assert!(
            inspect_state_block(scope(), StateBlockKind::ValueChunk, reference, malformed).is_ok()
        );
    }

    #[test]
    fn maximum_value_roundtrips_and_oversize_is_rejected_before_reads() {
        let mut store = Store::default();
        let value = vec![7; MAX_TREE_VALUE_BYTES];
        let tree = put(StateTree::empty(scope()), &mut store, key(1), Some(&value));
        assert_eq!(get(tree, &mut store, key(1)), Some(value));
        let before = store.fetches;
        assert!(matches!(
            tree.update(
                key(1),
                Some(&vec![7; MAX_TREE_VALUE_BYTES + 1]),
                &mut store,
                &mut reads(),
                &mut writes()
            ),
            Err(TreeError::InvalidValue)
        ));
        assert_eq!(store.fetches, before);
    }

    #[test]
    fn chunk_boundaries_roundtrip_and_old_values_survive_replacement() {
        let mut store = Store::default();
        for size in [
            MAX_INLINE_TREE_VALUE_BYTES,
            MAX_INLINE_TREE_VALUE_BYTES + 1,
            MAX_STATE_BLOCK_BYTES,
            MAX_STATE_BLOCK_BYTES + 1,
            2 * MAX_STATE_BLOCK_BYTES,
        ] {
            let value: Vec<u8> = (0..size)
                .map(|i| (i / MAX_STATE_BLOCK_BYTES + i % 251) as u8)
                .collect();
            let original = put(StateTree::empty(scope()), &mut store, key(1), Some(&value));
            assert_eq!(get(original, &mut store, key(1)), Some(value.clone()));
            let root_bytes = &store.blocks[&original.root().unwrap().hash().0];
            assert_eq!(
                root_bytes[4],
                if size <= MAX_INLINE_TREE_VALUE_BYTES {
                    0
                } else {
                    2
                }
            );
            let unchanged = original
                .update(
                    key(1),
                    Some(&value),
                    &mut store,
                    &mut reads(),
                    &mut WriteBudget::new(0, 0),
                )
                .unwrap();
            assert!(unchanged.blocks.is_empty());
            assert_eq!(unchanged.tree, original);
            let replaced = put(original, &mut store, key(1), Some(b"small"));
            assert_eq!(get(replaced, &mut store, key(1)), Some(b"small".to_vec()));
            assert_eq!(get(original, &mut store, key(1)), Some(value));
            assert_eq!(
                put(original, &mut store, key(1), None),
                StateTree::empty(scope())
            );
        }
    }

    #[test]
    fn missing_or_corrupt_value_chunks_are_not_empty_or_partial_values() {
        let mut store = Store::default();
        let value: Vec<u8> = (0..MAX_STATE_BLOCK_BYTES + 1)
            .map(|i| (i / MAX_STATE_BLOCK_BYTES) as u8)
            .collect();
        let tree = put(StateTree::empty(scope()), &mut store, key(1), Some(&value));
        let root = tree.root().unwrap();
        let Node::Chunked(_, _, chunks) = Node::decode(&store.blocks[&root.hash().0]).unwrap()
        else {
            panic!("expected chunks");
        };
        let last = *chunks.last().unwrap();
        let original = store.blocks.remove(&last.hash().0).unwrap();
        assert_eq!(
            tree.get(&key(1), &mut store, &mut reads()),
            Err(TreeError::Block(BlockError::Unavailable))
        );
        // The authenticated key mismatch proves absence without reading an
        // unrelated value, even if that value is currently unavailable.
        assert_eq!(get(tree, &mut store, key(2)), None);
        assert!(matches!(
            tree.update(
                key(1),
                Some(b"replacement"),
                &mut store,
                &mut reads(),
                &mut writes()
            ),
            Err(TreeError::Block(BlockError::Unavailable))
        ));
        store.blocks.insert(last.hash().0, vec![original[0] ^ 1]);
        assert_eq!(
            tree.get(&key(1), &mut store, &mut reads()),
            Err(TreeError::Block(BlockError::HashMismatch))
        );
        store.blocks.insert(last.hash().0, original);
        assert_eq!(get(tree, &mut store, key(1)), Some(value));
    }

    #[test]
    fn chunk_fetches_and_staged_payloads_consume_budgets() {
        let mut store = Store::default();
        let value = vec![7; MAX_STATE_BLOCK_BYTES + 1];
        let tree = put(StateTree::empty(scope()), &mut store, key(1), Some(&value));
        let before = store.fetches;
        let mut budget = ReadBudget::new(1, u64::MAX);
        assert_eq!(
            tree.get(&key(1), &mut store, &mut budget),
            Err(TreeError::Block(BlockError::BudgetExceeded))
        );
        assert_eq!(store.fetches - before, 1, "no unbudgeted chunk read");
        let before = store.blocks.clone();
        let mut budget = WriteBudget::new(2, value.len() as u64);
        assert!(matches!(
            StateTree::empty(scope()).update(
                key(2),
                Some(&value),
                &mut store,
                &mut reads(),
                &mut budget
            ),
            Err(TreeError::WriteBudgetExceeded)
        ));
        assert_eq!(budget.remaining(), (0, 0));
        assert_eq!(
            store.blocks, before,
            "failed manifest staging must not publish chunks"
        );
    }

    #[test]
    fn chunk_descriptor_rejects_wrong_counts_lengths_and_inline_aliases() {
        let first = scope().reference(&vec![0; MAX_STATE_BLOCK_BYTES]).unwrap();
        let last = scope().reference(&[1]).unwrap();
        let bytes = Node::Chunked(
            key(1),
            (MAX_STATE_BLOCK_BYTES + 1) as u32,
            vec![first, last],
        )
        .encode();
        assert!(Node::decode(&bytes).is_ok());
        for length in [0, LEAF_HEADER, bytes.len() - 1] {
            assert!(Node::decode(&bytes[..length]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Node::decode(&extra).is_err());
        let mut wrong_tail = bytes.clone();
        wrong_tail[LEAF_HEADER + 36 + 32..].copy_from_slice(&2u32.to_le_bytes());
        assert!(Node::decode(&wrong_tail).is_err());
        for size in [0, MAX_INLINE_TREE_VALUE_BYTES as u32, u32::MAX] {
            let mut bad = bytes.clone();
            bad[37..41].copy_from_slice(&size.to_le_bytes());
            assert!(Node::decode(&bad).is_err());
        }
        let mut reordered = bytes;
        reordered[LEAF_HEADER..LEAF_HEADER + 36]
            .copy_from_slice(&Node::Chunked(key(1), 1, vec![last]).encode()[LEAF_HEADER..]);
        assert!(Node::decode(&reordered).is_err());
    }

    fn growth_probe(entries: u32) {
        let mut store = Store::default();
        let mut tree = StateTree::empty(scope());
        for i in 0..entries {
            tree = put(tree, &mut store, key(i), Some(&i.to_le_bytes()));
        }
        let before = (store.fetches, store.bytes);
        assert_eq!(
            get(tree, &mut store, key(0)),
            Some(0u32.to_le_bytes().to_vec())
        );
        let fetched = store.fetches - before.0;
        let bytes = store.bytes - before.1;
        let update = tree
            .update(
                key(0),
                Some(b"changed"),
                &mut store,
                &mut reads(),
                &mut writes(),
            )
            .unwrap();
        let written: usize = update.blocks.iter().map(|(_, bytes)| bytes.len()).sum();
        // Fixture-specific ceilings, not a universal logarithmic worst-case
        // claim: adversarial keys can need 257 nodes (tested separately).
        assert!(fetched <= 32, "{fetched}");
        assert!(bytes <= 4096, "{bytes}");
        assert!(update.blocks.len() <= 32);
        assert!(written <= 4096);
        std::println!(
            "rows={entries} read_blocks={fetched} read_bytes={bytes} write_blocks={} write_bytes={written}",
            update.blocks.len()
        );
        let updated = store.install(update);
        assert_eq!(get(updated, &mut store, key(0)), Some(b"changed".to_vec()));
        assert_eq!(
            get(tree, &mut store, key(0)),
            Some(0u32.to_le_bytes().to_vec())
        );
    }

    #[test]
    fn fixed_work_does_not_materialize_growing_tree() {
        for entries in [16, 256, 4096] {
            growth_probe(entries);
        }
    }

    #[test]
    #[ignore = "explicit release-mode 100k primitive probe; not Clerk/PVM qualification"]
    fn hundred_thousand_row_growth_probe() {
        growth_probe(100_000);
    }
}
