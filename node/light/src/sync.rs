//! Sync (`light-node.md` §3.2): each local actor instance is one scope, a
//! merkle-crdt DAG whose nodes the light node's author key signs, each a
//! batch of operations. An operation is a merge handler's call with the
//! time and seed of the device that issued it, so every device that
//! applies the node runs the handler again and writes the same entries
//! (`vos_wire::merge`).
//!
//! Applying a node ([`apply_node`]) writes beside its operations' runs:
//! its Lamport clock, which orders the merge fields' entries; its author's
//! cutoff where it equivocates, from which the merge fields' reads filter
//! the author; and each operation of a kind this build does not know,
//! kept in its scope's rows, never refused.

use std::collections::BTreeMap;

use blake2::Blake2b;
use blake2::digest::Digest;
use blake2::digest::consts::{U16, U32};
use fjall::{Keyspace, OwnedWriteBatch};
use merkle_crdt::{
    Author, Changes, Decode, Encode, Event, FjallError, FjallStore, Loaded, Rows, Scope, Store,
};
use vos_wire::ids::{InstanceId, MethodId};
use vos_wire::keys;
use vos_wire::merge::{Cutoff, Origin};
use vos_wire::records::{stored, unstored};

/// The hash a scope's nodes are named by: BLAKE2b-256.
pub struct Blake2b256;

impl merkle_crdt::Hasher for Blake2b256 {
    type Output = [u8; 32];
    fn hash(data: &[u8]) -> [u8; 32] {
        Blake2b::<U32>::digest(data).into()
    }
}

/// A node's CID.
pub type Cid = merkle_crdt::Cid<Blake2b256>;

/// A merge handler's call: the operation a device issues, with its time
/// and seed, which every device that applies it runs on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub method: MethodId,
    pub arguments: Vec<u8>,
    pub time: u64,
    pub seed: [u8; 32],
}

/// An operation's kind, its encoding's first byte.
#[repr(u8)]
enum Kind {
    Call = 0,
}

/// One operation of a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Call(Call),
    /// An operation of a kind this build does not know, as it came: kept,
    /// for a build that knows it.
    Unknown {
        kind: u8,
        body: Vec<u8>,
    },
}

/// A node's operations.
pub type Ops = Vec<Op>;

impl Encode for Call {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.method.0.encode_to(buf);
        self.arguments.encode_to(buf);
        self.time.encode_to(buf);
        self.seed.encode_to(buf);
    }
}

impl Decode for Call {
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
        Some(Call {
            method: MethodId(u32::decode_from(buf, pos)?),
            arguments: Vec::decode_from(buf, pos)?,
            time: u64::decode_from(buf, pos)?,
            seed: <[u8; 32]>::decode_from(buf, pos)?,
        })
    }
}

/// An operation is its kind's byte, then its body's bytes, length-prefixed,
/// so a build that does not know the kind still reads where it ends.
impl Encode for Op {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        match self {
            Op::Call(call) => {
                buf.push(Kind::Call as u8);
                call.encode().encode_to(buf);
            }
            Op::Unknown { kind, body } => {
                buf.push(*kind);
                body.encode_to(buf);
            }
        }
    }
}

/// A known kind's body that is not that kind's is no operation, and its
/// node is malformed.
impl Decode for Op {
    fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
        let kind = u8::decode_from(buf, pos)?;
        let body = Vec::<u8>::decode_from(buf, pos)?;
        Some(match kind {
            0 => Op::Call(Call::decode(&body)?),
            kind => Op::Unknown { kind, body },
        })
    }
}

/// The scope of local instance `instance` among the devices that share
/// `realm`: the first 16 bytes of BLAKE2b over its domain, the realm and
/// the instance.
pub fn scope(realm: &[u8; 32], instance: InstanceId) -> Scope {
    let mut hasher = Blake2b::<U16>::new();
    hasher.update(b"vos/light/scope\0");
    hasher.update(realm);
    hasher.update(instance.0.to_be_bytes());
    Scope(hasher.finalize().into())
}

/// A row the light node wrote that does not read as written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorruptRow;

/// The value of a stored row of a light node's, as it wrote it.
fn read<T: vos_wire::Decode>(rows: &mut dyn Rows, key: &[u8]) -> Result<Option<T>, CorruptRow> {
    rows.read(key)
        .map(|bytes| unstored(&bytes).and_then(T::decode_exact).ok_or(CorruptRow))
        .transpose()
}

fn write(rows: &mut dyn Rows, key: &[u8], value: &impl vos_wire::Encode) {
    rows.write(key, Some(&stored(&value.encode())));
}

/// Hold `op`, the operation `origin` names in the node `cid` of
/// `instance`'s scope, in the scope's rows: its origin and its bytes, for
/// a build that runs it.
pub fn hold(instance: InstanceId, cid: &Cid, origin: &Origin, op: &Op, rows: &mut dyn Rows) {
    let key = keys::held(instance, &cid.0, origin.index);
    write(rows, &key, &(*origin, op.encode()));
}

/// Apply `event`, a node of `instance`'s scope, through `rows`: its Lamport
/// clock, one more than its parents' greatest; its author's cutoff from its
/// sequence number where it equivocates; then each operation in order, a
/// call by `run` with its node's CID and its origin, and one of a kind not
/// known held ([`hold`]).
pub fn apply_node<E: From<CorruptRow>>(
    instance: InstanceId,
    event: &Event<'_, Blake2b256, Ops>,
    rows: &mut dyn Rows,
    mut run: impl FnMut(&Cid, &Origin, &Call, &mut dyn Rows) -> Result<(), E>,
) -> Result<(), E> {
    let mut lamport = 0;
    for parent in event.parents {
        let clock = read::<u64>(rows, &keys::lamport(&parent.0))?.ok_or(CorruptRow)?;
        lamport = lamport.max(clock);
    }
    let lamport = lamport + 1;
    write(rows, &keys::lamport(&event.cid.0), &lamport);
    let author = event.author.0;
    if event.equivocation {
        let key = keys::cutoff(instance, &author);
        let cutoff = read::<Cutoff>(rows, &key)?;
        if cutoff.is_none_or(|cutoff| event.seq < cutoff.0) {
            write(rows, &key, &Cutoff(event.seq));
        }
    }
    for (index, op) in event.ops.iter().enumerate() {
        let origin = Origin {
            author,
            seq: event.seq,
            lamport,
            index: u32::try_from(index).map_err(|_| CorruptRow)?,
        };
        match op {
            Op::Call(call) => run(event.cid, &origin, call, rows)?,
            Op::Unknown { .. } => hold(instance, event.cid, &origin, op, rows),
        }
    }
    Ok(())
}

/// A scope's store: its keyspaces in the light node's database, its rows
/// the local agent's, and the light node's own writes an operation stages
/// ([`ScopeStore::stage`]), which the scope's next commit carries in its
/// batch.
pub(crate) struct ScopeStore {
    inner: FjallStore,
    staged: Vec<(Keyspace, Vec<u8>, Vec<u8>)>,
}

impl ScopeStore {
    pub(crate) fn new(inner: FjallStore) -> Self {
        Self {
            inner,
            staged: Vec::new(),
        }
    }

    /// Stage `value` under `key` in `keyspace` for the next commit.
    pub(crate) fn stage(&mut self, keyspace: &Keyspace, key: &[u8], value: Vec<u8>) {
        self.staged.push((keyspace.clone(), key.to_vec(), value));
    }

    /// Drop what is staged: the operation it was for wrote nothing.
    pub(crate) fn unstage(&mut self) {
        self.staged.clear();
    }
}

impl Store<Blake2b256> for ScopeStore {
    type Error = FjallError;

    fn node(&self, cid: &Cid) -> Result<Option<Vec<u8>>, FjallError> {
        self.inner.node(cid)
    }

    fn contains(&self, cid: &Cid) -> Result<bool, FjallError> {
        Store::<Blake2b256>::contains(&self.inner, cid)
    }

    fn nodes(&self) -> Result<Vec<Cid>, FjallError> {
        self.inner.nodes()
    }

    fn held(&self, cid: &Cid) -> Result<Option<Vec<u8>>, FjallError> {
        self.inner.held(cid)
    }

    fn authored(&self, author: &Author, seq: u64) -> Result<Vec<Cid>, FjallError> {
        self.inner.authored(author, seq)
    }

    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, FjallError> {
        Store::<Blake2b256>::row(&self.inner, key)
    }

    fn load(&self) -> Result<Loaded<Blake2b256>, FjallError> {
        self.inner.load()
    }

    fn commit(&mut self, changes: Changes<Blake2b256>) -> Result<(), FjallError> {
        let staged = std::mem::take(&mut self.staged);
        self.inner
            .commit_with(changes, |batch: &mut OwnedWriteBatch| {
                for (keyspace, key, value) in staged {
                    batch.insert(&keyspace, key, value);
                }
            })
    }
}

/// Rows under a batch's writes, each write also kept in `written`: the
/// writes the agent program's later runs in the batch read above the
/// store.
pub(crate) struct Mirrored<'a> {
    pub(crate) rows: &'a mut dyn Rows,
    pub(crate) written: &'a mut BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl Rows for Mirrored<'_> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.rows.read(key)
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        self.rows.write(key, value);
        self.written.insert(key.to_vec(), value.map(<[u8]>::to_vec));
    }
}
